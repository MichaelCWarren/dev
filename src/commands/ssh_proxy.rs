use anyhow::{Context, bail};

use std::time::Duration;

use crate::commands::exec::{ExitSignals, SignalSource, resolve_exec_secrets};
use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::devcontainer::secrets::{ProviderRegistry, SecretValue};
use crate::runtime::{
    ContainerInfo, ContainerRuntime, PipedStdio, detect_runtime, find_running_container,
};
use crate::session::{self, SessionKind};
use crate::ssh_server::sshd_config::{render_sshd_config, session_dir_name, session_env};
use crate::ssh_server::{SSHD_PATH, WorkspaceRecord, public_half, read_workspace_record_in};
use crate::util::paths::DevHome;

const ENV_CONFIG: &str = "DEV_SSHD_CONFIG";
const ENV_HOST_KEY: &str = "DEV_SSHD_HOST_KEY";
const ENV_AUTHORIZED_KEYS: &str = "DEV_SSHD_AUTHORIZED_KEYS";

/// How one proxied connection ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProxyOutcome {
    /// Nothing was started. Carries the line for stderr.
    NotRunning(String),
    /// The session exec ran and ended with this status.
    Finished(i32),
}

impl ProxyOutcome {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            ProxyOutcome::NotRunning(_) => 255,
            ProxyOutcome::Finished(code) => *code,
        }
    }
}

/// Every message goes to stderr: a byte on stdout ahead of sshd's banner
/// breaks the handshake.
pub async fn run(workspace_hash: &str, runtime_override: Option<&str>) -> anyhow::Result<()> {
    let dev_home = DevHome::current();
    let record = load_record(&dev_home, workspace_hash)?;
    let runtime = detect_runtime(runtime_choice(&record, runtime_override)).await?;
    let registry = ProviderRegistry::with_builtins(&record.workspace);
    let client = PipedStdio {
        stdin: Box::new(tokio::io::stdin()),
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
    };
    let outcome = run_with_runtime(
        &record,
        workspace_hash,
        runtime.as_ref(),
        &registry,
        &dev_home,
        client,
    )
    .await?;
    if let ProxyOutcome::NotRunning(message) = &outcome {
        eprintln!("{message}");
    }
    match outcome.exit_code() {
        0 => Ok(()),
        code => std::process::exit(code),
    }
}

/// The runtime `dev up` recorded, unless the command line names one. A record
/// from before the runtime was kept leaves the choice to detection, as before.
fn runtime_choice<'a>(
    record: &'a WorkspaceRecord,
    runtime_override: Option<&'a str>,
) -> Option<&'a str> {
    runtime_override.or(record.runtime.as_deref())
}

/// The hash is joined into paths, so anything but the 16 lowercase hex
/// characters `workspace_hash` produces is refused before the first join.
fn validate_hash(hash: &str) -> anyhow::Result<()> {
    let well_formed =
        hash.len() == 16 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !well_formed {
        bail!("dev ssh-proxy: invalid workspace hash");
    }
    Ok(())
}

fn load_record(dev_home: &DevHome, hash: &str) -> anyhow::Result<WorkspaceRecord> {
    validate_hash(hash)?;
    read_workspace_record_in(dev_home, hash).ok_or_else(|| {
        anyhow::anyhow!(
            "dev ssh-proxy: no workspace recorded for {hash} (run dev up in the project)"
        )
    })
}

/// `hash` is the one [`load_record`] accepted for `record`.
pub(crate) async fn run_with_runtime(
    record: &WorkspaceRecord,
    hash: &str,
    runtime: &dyn ContainerRuntime,
    registry: &ProviderRegistry,
    dev_home: &DevHome,
    client: PipedStdio,
) -> anyhow::Result<ProxyOutcome> {
    let Some(container) = find_running_container(runtime, &record.workspace).await? else {
        return Ok(ProxyOutcome::NotRunning(format!(
            "{}: container is not running (run dev up in {})",
            record.alias,
            record.workspace.display()
        )));
    };
    let prepared = build_session(record, hash, runtime, registry, dev_home, &container).await?;
    // Watching starts before the session exec, so a signal hangs sshd up
    // through `release` as well as through the stdin the runtime closes.
    let mut signals = ExitSignals::watch()?;
    let connection = Connection {
        record,
        runtime,
        container_id: &container.id,
        session: &prepared,
    };
    serve(&connection, client, &mut signals).await
}

/// One connection's session: the files the session exec writes into its
/// directory, and the `dev` process sshd is recorded as belonging to.
struct Session {
    dir: String,
    config: SecretValue,
    host_key: SecretValue,
    authorized_keys: SecretValue,
    host: session::HostIdentity,
}

/// The host key and the client's public key, both written by `dev up`.
fn read_keys(
    record: &WorkspaceRecord,
    hash: &str,
    dev_home: &DevHome,
) -> anyhow::Result<(String, String)> {
    let no_keys = |_| {
        anyhow::anyhow!(
            "{}: no ssh keys for this workspace (run dev up in {})",
            record.alias,
            record.workspace.display()
        )
    };
    let host_key = std::fs::read_to_string(dev_home.ssh_host_key(hash)).map_err(no_keys)?;
    let client_key = dev_home.ssh_client_key(hash);
    let public_key = std::fs::read_to_string(public_half(&client_key)).map_err(no_keys)?;
    std::fs::metadata(&client_key).map_err(no_keys)?;
    Ok((host_key, public_key))
}

async fn build_session(
    record: &WorkspaceRecord,
    hash: &str,
    runtime: &dyn ContainerRuntime,
    registry: &ProviderRegistry,
    dev_home: &DevHome,
    container: &ContainerInfo,
) -> anyhow::Result<Session> {
    let (host_key, public_key) = read_keys(record, hash, dev_home)?;
    let (config_path, config) =
        load_workspace_config_or_warn(&record.workspace, runtime.runtime_name()).unzip();
    let remote_user = config.as_ref().and_then(|c| c.remote_user.as_deref());
    let (secrets, container_env, host) = tokio::join!(
        resolve_exec_secrets(
            config_path.as_deref(),
            &record.workspace,
            remote_user,
            registry,
            dev_home,
        ),
        runtime.container_env(&container.id),
        session::host_identity(),
    );
    let secrets = secrets?;
    let container_env = parse_env(&container_env?);

    let (env, warnings) = session_env(&container_env, &secrets);
    for warning in warnings {
        eprintln!("{warning}");
    }
    let dir = session_dir_name().context("could not read random bytes for a session directory")?;
    Ok(Session {
        config: render_sshd_config(&dir, &env),
        dir,
        host_key: SecretValue::new(host_key),
        authorized_keys: SecretValue::new(format!("{}\n", public_key.trim_end())),
        host,
    })
}

fn parse_env(entries: &[String]) -> Vec<(String, String)> {
    entries
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The one exec a connection runs. `$1` is the session directory; `$2` and
/// `$3` stand in for sshd and the mount table, and `$4` names a point to
/// pause at, for tests run on the host.
///
/// The container owns removing the directory, because only its side can
/// order the removal after the `mkdir`. The traps go in before the `mkdir`,
/// since dash and busybox ash die of a signal that lands before them without
/// running the EXIT trap; `made` keeps a directory this shell did not make
/// from being removed. When ssh-proxy goes away the runtime closes the exec's
/// stdin, sshd reads EOF and exits, and the trap runs. sshd runs in the
/// background with the original stdin handed to it, because a trapped signal
/// waits out a foreground child but interrupts `wait`. `stop` kills `$!`, which
/// the shell sets as it forks, so a signal right after the fork still reaches
/// sshd; nothing else here runs in the background.
fn session_script() -> String {
    format!(
        r#"dir=$1 sshd=${{2:-{SSHD_PATH}}} mounts=${{3:-/proc/mounts}} pause_at=${{4-}} made=
hold() {{ [ "$pause_at" != "$1" ] || {{ : > "$dir.held"; sleep 1; }}; }}
[ -x "$sshd" ] || {{ echo 'sshd is not installed in this container (the ssh-server feature is baked in at build: run dev up --rebuild)' >&2; exit 1; }}
grep -q ' /dev/shm tmpfs ' "$mounts" || {{ echo '/dev/shm is not a tmpfs in this container; refusing to write keys and secrets there' >&2; exit 1; }}
trap '[ -z "$made" ] || rm -rf "$dir"' EXIT
stop() {{ [ -z "$!" ] || kill "$!" 2>/dev/null; exit "$1"; }}
trap 'stop 129' HUP
trap 'stop 130' INT
trap 'stop 143' TERM
mkdir -m 700 "$dir" || {{ echo "refusing to reuse the ssh session directory $dir: it already exists or could not be made" >&2; exit 1; }}
made=1
hold made
umask 077
{{ printf '%s' "${ENV_CONFIG}" > "$dir/sshd_config" &&
printf '%s' "${ENV_HOST_KEY}" > "$dir/ssh_host_ed25519_key" &&
printf '%s' "${ENV_AUTHORIZED_KEYS}" > "$dir/authorized_keys"; }} || exit 1
unset {ENV_CONFIG} {ENV_HOST_KEY} {ENV_AUTHORIZED_KEYS}
exec 3<&0
"$sshd" -i -e -f "$dir/sshd_config" <&3 3<&- &
hold forked
exec 3<&-
wait "$!""#
    )
}

/// Bounds hanging up the session on a signal, against a daemon that stopped
/// answering. The container removes the directory either way.
pub(crate) const RELEASE_BUDGET: Duration = Duration::from_secs(5);

/// One connection's session in its running container.
struct Connection<'a> {
    record: &'a WorkspaceRecord,
    runtime: &'a dyn ContainerRuntime,
    container_id: &'a str,
    session: &'a Session,
}

impl Connection<'_> {
    fn user(&self) -> Option<&str> {
        Some(self.record.user.as_str())
    }

    /// Runs as the container user so every file is theirs. File contents
    /// travel only in this exec's env, the channel `dev exec` already trusts
    /// with secrets.
    async fn run_session(&self, client: PipedStdio) -> anyhow::Result<i32> {
        let session = self.session;
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            session::recorded_script(&session_script(), SessionKind::Ssh, &session.host),
            "dev-ssh".to_string(),
            session.dir.clone(),
        ];
        let env = vec![
            (ENV_CONFIG.to_string(), session.config.clone()),
            (ENV_HOST_KEY.to_string(), session.host_key.clone()),
            (
                ENV_AUTHORIZED_KEYS.to_string(),
                session.authorized_keys.clone(),
            ),
        ];
        Ok(self
            .runtime
            .exec_piped(self.container_id, &cmd, self.user(), &env, client)
            .await?)
    }

    /// Hangs up sshd sooner than the closed stdin would. Failure is not worth
    /// reporting: the process is on its way out.
    async fn release(&self) {
        let release = session::release_own_sessions(
            self.runtime,
            self.container_id,
            self.user(),
            self.session.host.pid,
        );
        let _ = tokio::time::timeout(RELEASE_BUDGET, release).await;
    }
}

/// Relays the session exec until it ends or a signal arrives.
async fn serve(
    connection: &Connection<'_>,
    client: PipedStdio,
    signals: &mut impl SignalSource,
) -> anyhow::Result<ProxyOutcome> {
    let signal = tokio::select! {
        ran = connection.run_session(client) => return Ok(ProxyOutcome::Finished(ran?)),
        signal = signals.next() => signal,
    };
    // A second signal means the user is done waiting, and the release is
    // only a courtesy: the container removes the session either way.
    tokio::select! {
        _ = connection.release() => {}
        _ = signals.next() => {}
    }
    Ok(ProxyOutcome::Finished(128 + signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::exec::ScriptedSignals;
    use crate::devcontainer::secrets::provider::{FakeProvider, PluginPath};
    use crate::error::DevError;
    use crate::runtime::fake_daemon::{capture, read_captured};
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerState, ExecResult, ImageMetadata,
    };
    use crate::ssh_server::write_workspace_record;
    use crate::util::workspace_labels;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, DuplexStream};

    const HASH: &str = "0123456789abcdef";
    const HOST_KEY: &str = "HOSTKEY-DUMMY";
    const CLIENT_KEY: &str = "CLIENTKEY-DUMMY";
    const PUBLIC_KEY: &str = "ssh-ed25519 PUBKEY-DUMMY dev";

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("unused fake runtime method".into())) })
    }

    type ExecCall = (Vec<String>, Option<String>, Vec<(String, String)>);

    /// How the fake answers the plain execs `release_own_sessions` runs.
    #[derive(Clone)]
    enum ReleaseReply {
        /// Every exec prints this.
        Prints(String),
        /// Never answers.
        Hangs,
    }

    struct ProxyFakeRuntime {
        containers: Vec<ContainerInfo>,
        container_env: Vec<String>,
        sshd_stdout: Vec<u8>,
        sshd_stderr: Vec<u8>,
        sshd_exit: i32,
        fail_piped: bool,
        sshd_hangs: bool,
        release: ReleaseReply,
        calls: Arc<Mutex<Vec<&'static str>>>,
        execs: Arc<Mutex<Vec<ExecCall>>>,
        piped: Arc<Mutex<Vec<ExecCall>>>,
        sshd_stdin: Arc<Mutex<Vec<u8>>>,
    }

    impl ProxyFakeRuntime {
        fn with_state(workspace: &Path, state: ContainerState) -> Self {
            Self {
                containers: vec![ContainerInfo {
                    id: "container-id".to_string(),
                    name: "container".to_string(),
                    state,
                    labels: workspace_labels(workspace, None).into_iter().collect(),
                    image: "ubuntu:24.04".to_string(),
                }],
                container_env: Vec::new(),
                sshd_stdout: Vec::new(),
                sshd_stderr: Vec::new(),
                sshd_exit: 0,
                fail_piped: false,
                sshd_hangs: false,
                release: ReleaseReply::Prints(String::new()),
                calls: Arc::default(),
                execs: Arc::default(),
                piped: Arc::default(),
                sshd_stdin: Arc::default(),
            }
        }

        fn running(workspace: &Path) -> Self {
            Self::with_state(workspace, ContainerState::Running)
        }

        fn none_at_all(workspace: &Path) -> Self {
            let mut runtime = Self::running(workspace);
            runtime.containers.clear();
            runtime
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }

        fn note(&self, method: &'static str) {
            self.calls.lock().unwrap().push(method);
        }

        fn execs(&self) -> Vec<ExecCall> {
            self.execs.lock().unwrap().clone()
        }

        fn piped(&self) -> Vec<ExecCall> {
            self.piped.lock().unwrap().clone()
        }
    }

    fn expose(env: &[(String, SecretValue)]) -> Vec<(String, String)> {
        // Exposing inside a test double is the only way to prove the value arrived.
        env.iter()
            .map(|(key, value)| (key.clone(), value.expose().to_string()))
            .collect()
    }

    impl ContainerRuntime for ProxyFakeRuntime {
        fn runtime_name(&self) -> &'static str {
            "docker"
        }

        fn pull_image(&self, _image: &str) -> BoxFut<'_, ()> {
            unused()
        }

        fn build_image(
            &self,
            _dockerfile: &str,
            _context: &Path,
            _tag: &str,
            _build_args: &HashMap<String, String>,
            _no_cache: bool,
            _verbose: bool,
        ) -> BoxFut<'_, ()> {
            unused()
        }

        fn create_container(&self, _config: &ContainerConfig) -> BoxFut<'_, String> {
            self.note("create_container");
            unused()
        }

        fn start_container(&self, _id: &str) -> BoxFut<'_, ()> {
            self.note("start_container");
            unused()
        }

        fn stop_container(&self, _id: &str) -> BoxFut<'_, ()> {
            unused()
        }

        fn remove_container(&self, _id: &str) -> BoxFut<'_, ()> {
            unused()
        }

        fn exec(
            &self,
            _id: &str,
            cmd: &[String],
            user: Option<&str>,
            _workdir: Option<&str>,
            env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            self.note("exec");
            self.execs
                .lock()
                .unwrap()
                .push((cmd.to_vec(), user.map(str::to_string), expose(env)));
            let reply = self.release.clone();
            Box::pin(async move {
                let stdout = match reply {
                    ReleaseReply::Prints(stdout) => stdout,
                    ReleaseReply::Hangs => std::future::pending().await,
                };
                Ok(ExecResult {
                    exit_code: 0,
                    stdout,
                    stderr: String::new(),
                })
            })
        }

        fn exec_interactive(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
            _workdir: Option<&str>,
            _env: &[(String, SecretValue)],
        ) -> BoxFut<'_, i32> {
            unused()
        }

        fn inspect_container(&self, _id: &str) -> BoxFut<'_, ContainerInfo> {
            unused()
        }

        fn list_containers(&self, label_filters: &[String]) -> BoxFut<'_, Vec<ContainerInfo>> {
            self.note("list_containers");
            let filters: Vec<(String, String)> = label_filters
                .iter()
                .map(|filter| {
                    let (key, value) = filter.split_once('=').unwrap_or((filter, ""));
                    (key.to_string(), value.to_string())
                })
                .collect();
            let containers = self.containers.clone();
            Box::pin(async move {
                Ok(containers
                    .into_iter()
                    .filter(|c| {
                        filters
                            .iter()
                            .all(|(key, value)| c.labels.get(key).is_some_and(|got| got == value))
                    })
                    .collect())
            })
        }

        fn image_exists(&self, _image: &str) -> BoxFut<'_, bool> {
            unused()
        }

        fn inspect_image_metadata(&self, _image: &str) -> BoxFut<'_, ImageMetadata> {
            Box::pin(async { Ok(ImageMetadata::default()) })
        }

        fn exec_attached(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
        ) -> BoxFut<'_, AttachedExec> {
            unused()
        }

        fn exec_piped(
            &self,
            _id: &str,
            cmd: &[String],
            user: Option<&str>,
            env: &[(String, SecretValue)],
            mut stdio: PipedStdio,
        ) -> BoxFut<'_, i32> {
            self.note("exec_piped");
            self.piped
                .lock()
                .unwrap()
                .push((cmd.to_vec(), user.map(str::to_string), expose(env)));
            let fail = self.fail_piped;
            let hangs = self.sshd_hangs;
            let (out, err, exit) = (
                self.sshd_stdout.clone(),
                self.sshd_stderr.clone(),
                self.sshd_exit,
            );
            let stdin_seen = self.sshd_stdin.clone();
            Box::pin(async move {
                use tokio::io::AsyncWriteExt;
                if fail {
                    return Err(DevError::Runtime("exec refused".into()));
                }
                if hangs {
                    std::future::pending::<()>().await;
                }
                let mut input = Vec::new();
                stdio.stdin.read_to_end(&mut input).await.unwrap();
                *stdin_seen.lock().unwrap() = input;
                stdio.stdout.write_all(&out).await.unwrap();
                stdio.stderr.write_all(&err).await.unwrap();
                Ok(exit)
            })
        }

        fn container_env(&self, _id: &str) -> BoxFut<'_, Vec<String>> {
            self.note("container_env");
            let env = self.container_env.clone();
            Box::pin(async move { Ok(env) })
        }
    }

    struct Fixture {
        _tmp: TempDir,
        workspace: PathBuf,
        dev_home: DevHome,
        record: WorkspaceRecord,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let workspace = tmp.path().join("ws");
        let devcontainer_dir = workspace.join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).unwrap();
        std::fs::write(
            devcontainer_dir.join("devcontainer.json"),
            r#"{"image": "ubuntu:24.04"}"#,
        )
        .unwrap();
        std::fs::write(
            devcontainer_dir.join("secrets.json"),
            r#"{"version":1,"secrets":{"TOKEN":"fake://token"}}"#,
        )
        .unwrap();
        let dev_home = DevHome::at(tmp.path().join("dev-home"));
        std::fs::create_dir_all(dev_home.ssh_workspace_dir(HASH)).unwrap();
        std::fs::write(dev_home.ssh_host_key(HASH), HOST_KEY).unwrap();
        std::fs::write(dev_home.ssh_client_key(HASH), CLIENT_KEY).unwrap();
        std::fs::write(
            public_half(&dev_home.ssh_client_key(HASH)),
            format!("{PUBLIC_KEY}\n"),
        )
        .unwrap();
        let record = WorkspaceRecord {
            alias: "dev-proj".to_string(),
            workspace: workspace.clone(),
            user: "node".to_string(),
            runtime: None,
        };
        write_workspace_record(&dev_home, HASH, &record).unwrap();
        Fixture {
            _tmp: tmp,
            workspace,
            dev_home,
            record,
        }
    }

    fn registry_with(workspace: &Path, provider: FakeProvider) -> ProviderRegistry {
        let mut registry =
            ProviderRegistry::empty(workspace, PluginPath::from_os_str(OsStr::new("")));
        registry.register(Box::new(provider));
        registry
    }

    /// What the ssh client was sent, readable once the run has dropped its
    /// end.
    struct Client {
        stdout: DuplexStream,
        stderr: DuplexStream,
    }

    fn client(stdin: &[u8]) -> (PipedStdio, Client) {
        let (stdout, stdout_seen) = capture();
        let (stderr, stderr_seen) = capture();
        let stdio = PipedStdio {
            stdin: Box::new(std::io::Cursor::new(stdin.to_vec())),
            stdout,
            stderr,
        };
        let seen = Client {
            stdout: stdout_seen,
            stderr: stderr_seen,
        };
        (stdio, seen)
    }

    async fn text(seen: DuplexStream) -> String {
        String::from_utf8(read_captured(seen).await).unwrap()
    }

    async fn proxy(
        fx: &Fixture,
        runtime: &ProxyFakeRuntime,
        provider: FakeProvider,
        stdin: &[u8],
    ) -> (anyhow::Result<ProxyOutcome>, Client) {
        let (stdio, client) = client(stdin);
        let result = run_with_runtime(
            &fx.record,
            HASH,
            runtime,
            &registry_with(&fx.workspace, provider),
            &fx.dev_home,
            stdio,
        )
        .await;
        (result, client)
    }

    fn token_provider() -> FakeProvider {
        FakeProvider::answering(&[("TOKEN", "hunter2")])
    }

    fn running_with_env(fx: &Fixture) -> ProxyFakeRuntime {
        let mut runtime = ProxyFakeRuntime::running(&fx.workspace);
        runtime.container_env = vec!["PATH=/usr/bin".to_string(), "HOME=/root".to_string()];
        runtime
    }

    async fn assert_nothing_but_the_lookup_ran(runtime: ProxyFakeRuntime, fx: &Fixture) {
        let provider = FakeProvider::recording();
        let (result, client) = proxy(fx, &runtime, provider.clone(), b"").await;

        let expected = format!(
            "dev-proj: container is not running (run dev up in {})",
            fx.workspace.display()
        );
        assert_eq!(result.unwrap(), ProxyOutcome::NotRunning(expected));
        assert_eq!(runtime.calls(), ["list_containers"]);
        assert_eq!(provider.calls(), 0);
        assert!(text(client.stdout).await.is_empty());
    }

    #[tokio::test]
    async fn a_stopped_container_is_not_started() {
        let fx = fixture();
        let runtime = ProxyFakeRuntime::with_state(&fx.workspace, ContainerState::Stopped);
        assert_nothing_but_the_lookup_ran(runtime, &fx).await;
    }

    #[tokio::test]
    async fn a_missing_container_is_not_created() {
        let fx = fixture();
        let runtime = ProxyFakeRuntime::none_at_all(&fx.workspace);
        assert_nothing_but_the_lookup_ran(runtime, &fx).await;
    }

    #[test]
    fn not_running_exits_255() {
        assert_eq!(ProxyOutcome::NotRunning("x".into()).exit_code(), 255);
        assert_eq!(ProxyOutcome::Finished(3).exit_code(), 3);
    }

    #[tokio::test]
    async fn the_session_is_one_recorded_exec_as_the_recorded_user_with_the_files_in_env() {
        let fx = fixture();
        let runtime = running_with_env(&fx);

        let (result, _) = proxy(&fx, &runtime, token_provider(), b"").await;
        assert_eq!(result.unwrap(), ProxyOutcome::Finished(0));

        assert!(runtime.execs().is_empty(), "{:?}", runtime.execs());
        let piped = runtime.piped();
        assert_eq!(piped.len(), 1);
        let (cmd, user, env) = &piped[0];
        assert_eq!(user.as_deref(), Some("node"));
        assert_eq!(cmd[..2], ["/bin/sh", "-c"]);
        assert!(cmd[2].contains("'ssh'"), "recorded as an ssh session");
        assert!(cmd[2].contains(&session_script()));
        assert_eq!(cmd.len(), 5, "no sshd or mount table override: {cmd:?}");
        assert!(cmd[4].starts_with("/dev/shm/dev-sshd-"), "{}", cmd[4]);

        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, [ENV_CONFIG, ENV_HOST_KEY, ENV_AUTHORIZED_KEYS]);
        let config = &env[0].1;
        assert!(config.contains("SetEnv"));
        assert!(config.contains("TOKEN=hunter2"));
        assert!(config.contains("PATH=/usr/bin"));
        assert!(!config.contains("HOME="));
        assert!(config.contains(&cmd[4]), "the config names its own dir");
        assert_eq!(env[1].1, HOST_KEY);
        assert_eq!(env[2].1, format!("{PUBLIC_KEY}\n"));
    }

    #[tokio::test]
    async fn no_secret_reaches_any_argv() {
        let fx = fixture();
        let runtime = running_with_env(&fx);

        let (result, _) = proxy(&fx, &runtime, token_provider(), b"").await;
        result.unwrap();

        let all: Vec<ExecCall> = runtime.execs().into_iter().chain(runtime.piped()).collect();
        assert_eq!(all.len(), 1);
        let (cmd, _, env) = &all[0];
        let carried: String = env.iter().map(|(_, value)| value.as_str()).collect();
        for secret in ["hunter2", HOST_KEY, "PUBKEY-DUMMY"] {
            assert!(carried.contains(secret), "{secret} is carried in env");
            for word in cmd {
                assert!(!word.contains(secret), "{secret} in argv word {word}");
            }
        }
        for word in cmd {
            assert!(
                !word.contains(CLIENT_KEY),
                "the client key never leaves the host"
            );
        }
    }

    #[tokio::test]
    async fn a_refused_session_exec_is_an_error_and_nothing_follows_it() {
        let fx = fixture();
        let mut runtime = running_with_env(&fx);
        runtime.fail_piped = true;

        let (result, _) = proxy(&fx, &runtime, token_provider(), b"").await;

        assert!(result.is_err());
        assert_eq!(runtime.calls().last(), Some(&"exec_piped"));
        assert!(runtime.execs().is_empty());
    }

    const SIGNAL_AT: Duration = Duration::from_millis(10);
    const TEST_DIR: &str = "/dev/shm/dev-sshd-test";
    const HOST_PID: u32 = 4242;

    struct Ended {
        outcome: anyhow::Result<ProxyOutcome>,
        elapsed: Duration,
    }

    /// Runs one connection against `runtime` with `script` as its signals.
    /// Everything it awaits is a timer or a fake that answers at once, so a
    /// paused clock only moves when the run is truly idle.
    async fn run_signalled(
        fx: &Fixture,
        runtime: &ProxyFakeRuntime,
        script: &[(Duration, i32)],
    ) -> Ended {
        let session = Session {
            dir: TEST_DIR.to_string(),
            config: SecretValue::new(String::new()),
            host_key: SecretValue::new(String::new()),
            authorized_keys: SecretValue::new(String::new()),
            host: session::HostIdentity {
                pid: HOST_PID,
                start: "start".to_string(),
                tty: "?".to_string(),
            },
        };
        let connection = Connection {
            record: &fx.record,
            runtime,
            container_id: "container-id",
            session: &session,
        };
        let (stdio, _client) = client(b"");
        let mut signals = ScriptedSignals::after(script);
        let started = tokio::time::Instant::now();
        // A guard far past every bound, so a deleted bound fails the test
        // instead of hanging it.
        let outcome = tokio::time::timeout(
            Duration::from_secs(600),
            serve(&connection, stdio, &mut signals),
        )
        .await
        .expect("the connection never ended");
        Ended {
            outcome,
            elapsed: started.elapsed(),
        }
    }

    /// A session marker for this connection's own sshd, so the release has
    /// something to hang up.
    fn own_marker() -> ReleaseReply {
        ReleaseReply::Prints(format!("720 720 {HOST_PID} start ssh ?\n"))
    }

    #[tokio::test(start_paused = true)]
    async fn a_signal_hangs_up_the_session_and_exits_128_plus_the_signal() {
        let fx = fixture();
        let mut runtime = running_with_env(&fx);
        runtime.sshd_hangs = true;
        runtime.release = own_marker();

        let ended = run_signalled(&fx, &runtime, &[(SIGNAL_AT, libc::SIGHUP)]).await;

        assert_eq!(
            ended.outcome.unwrap(),
            ProxyOutcome::Finished(128 + libc::SIGHUP)
        );
        assert_eq!(runtime.calls(), ["exec_piped", "exec", "exec"]);
        let execs = runtime.execs();
        let kill = &execs[1].0;
        assert!(kill.iter().any(|word| word == "s:720:720"), "{kill:?}");
        assert_eq!(execs[1].1.as_deref(), Some("node"));
        assert_eq!(ended.elapsed, SIGNAL_AT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_signal_ends_the_release_at_once_with_the_first_signal() {
        let fx = fixture();
        let mut runtime = running_with_env(&fx);
        runtime.sshd_hangs = true;
        runtime.release = ReleaseReply::Hangs;
        let second_at = SIGNAL_AT * 2;

        let ended = run_signalled(
            &fx,
            &runtime,
            &[(SIGNAL_AT, libc::SIGTERM), (second_at, libc::SIGINT)],
        )
        .await;

        assert_eq!(
            ended.outcome.unwrap(),
            ProxyOutcome::Finished(128 + libc::SIGTERM)
        );
        assert_eq!(ended.elapsed, second_at);
    }

    #[tokio::test(start_paused = true)]
    async fn a_release_that_hangs_is_given_up_after_its_bound() {
        let fx = fixture();
        let mut runtime = running_with_env(&fx);
        runtime.sshd_hangs = true;
        runtime.release = ReleaseReply::Hangs;

        let ended = run_signalled(&fx, &runtime, &[(SIGNAL_AT, libc::SIGTERM)]).await;

        assert_eq!(
            ended.outcome.unwrap(),
            ProxyOutcome::Finished(128 + libc::SIGTERM)
        );
        assert_eq!(runtime.calls(), ["exec_piped", "exec"]);
        assert_eq!(ended.elapsed, SIGNAL_AT + RELEASE_BUDGET);
    }

    /// The session dir is the container's to remove: the only `rm -rf` is in
    /// the session exec's own trap, and nothing the host runs names the dir.
    #[tokio::test(start_paused = true)]
    async fn no_exec_from_the_host_removes_the_session_dir() {
        let fx = fixture();
        let mut finished = running_with_env(&fx);
        finished.release = own_marker();
        let mut signalled = running_with_env(&fx);
        signalled.sshd_hangs = true;
        signalled.release = own_marker();

        run_signalled(&fx, &finished, &[]).await.outcome.unwrap();
        run_signalled(&fx, &signalled, &[(SIGNAL_AT, libc::SIGINT)])
            .await
            .outcome
            .unwrap();

        assert!(!signalled.execs().is_empty(), "the release ran");
        for runtime in [&finished, &signalled] {
            for (cmd, ..) in runtime.execs() {
                for word in &cmd {
                    assert!(!word.contains("rm -rf"), "{word}");
                    assert!(!word.contains(TEST_DIR), "{word}");
                }
            }
            let piped = runtime.piped();
            assert_eq!(piped.len(), 1);
            assert!(piped[0].0[2].contains(r#"|| rm -rf "$dir"' EXIT"#));
        }
    }

    #[test]
    fn the_recorded_runtime_is_used_unless_the_command_line_names_one() {
        let fx = fixture();
        let mut record = fx.record.clone();
        assert_eq!(runtime_choice(&record, None), None);

        record.runtime = Some("podman".to_string());
        assert_eq!(runtime_choice(&record, None), Some("podman"));
        assert_eq!(runtime_choice(&record, Some("docker")), Some("docker"));
    }

    #[tokio::test]
    async fn sshd_stderr_never_enters_the_ssh_stream() {
        let fx = fixture();
        let mut runtime = running_with_env(&fx);
        runtime.sshd_stdout = b"SSH-2.0-x".to_vec();
        runtime.sshd_stderr = b"sshd: error".to_vec();
        runtime.sshd_exit = 7;

        let (result, client) = proxy(&fx, &runtime, token_provider(), b"").await;

        assert_eq!(result.unwrap(), ProxyOutcome::Finished(7));
        assert_eq!(text(client.stdout).await, "SSH-2.0-x");
        assert_eq!(text(client.stderr).await, "sshd: error");
    }

    #[tokio::test]
    async fn client_stdin_reaches_sshd() {
        let fx = fixture();
        let runtime = running_with_env(&fx);

        let (result, _) = proxy(&fx, &runtime, token_provider(), b"SSH-2.0-client").await;
        result.unwrap();

        assert_eq!(*runtime.sshd_stdin.lock().unwrap(), b"SSH-2.0-client");
    }

    #[test]
    fn a_malformed_hash_is_refused() {
        let fx = fixture();
        // Joined into a path, "../../x" would land here, outside `~/.dev/ssh/`.
        write_workspace_record(&fx.dev_home, "../../x", &fx.record).unwrap();

        for bad in ["../../x", "0123456789abcde", "0123456789ABCDEF"] {
            let err = load_record(&fx.dev_home, bad).unwrap_err();
            assert_eq!(err.to_string(), "dev ssh-proxy: invalid workspace hash");
        }
        assert!(load_record(&fx.dev_home, HASH).is_ok());
    }
}

/// The session script itself, run by the host's shells against a temp dir
/// standing in for `/dev/shm`. Every process started here is killed on drop.
#[cfg(test)]
mod session_script_tests {
    use super::*;
    use crate::util::process::{is_process_alive, wait_bounded};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::Instant;
    use tempfile::TempDir;

    const PATIENCE: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(10);

    /// Debian's and Ubuntu's `/bin/sh` is dash and Alpine's is busybox ash,
    /// so each runs whenever the host has it, alongside the host's own `sh`.
    fn shells() -> Vec<&'static str> {
        let mut shells: Vec<_> = ["sh", "/bin/dash", "/bin/bash"]
            .into_iter()
            .filter(|shell| !shell.starts_with('/') || Path::new(shell).exists())
            .collect();
        if on_path("busybox") {
            shells.push("busybox sh");
        }
        shells
    }

    fn on_path(program: &str) -> bool {
        std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
    }

    /// Starts every fake sshd: it notes its pid beside the session dir,
    /// which it finds from the `-f <dir>/sshd_config` it is handed as `$4`.
    const FAKE_SSHD_PRELUDE: &str = "#!/bin/sh\nd=${4%/*}\necho $$ > \"$d.pid\"\n";

    struct Stage {
        tmp: TempDir,
        dir: PathBuf,
        mounts: PathBuf,
        child: Option<Child>,
    }

    impl Stage {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let shm = tmp.path().join("shm");
            std::fs::create_dir(&shm).unwrap();
            let mounts = tmp.path().join("mounts");
            std::fs::write(&mounts, "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n").unwrap();
            Self {
                dir: shm.join("dev-sshd-test"),
                mounts,
                tmp,
                child: None,
            }
        }

        fn fake_sshd(&self, body: &str) -> PathBuf {
            let path = self.tmp.path().join("fake-sshd");
            std::fs::write(&path, format!("{FAKE_SSHD_PRELUDE}{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        fn spawn(&mut self, shell: &str, sshd: &Path) {
            self.spawn_pausing_at(shell, sshd, "");
        }

        /// `pause_at` names the script's `hold` point to stop at for a moment,
        /// after noting it in `<dir>.held`.
        fn spawn_pausing_at(&mut self, shell: &str, sshd: &Path, pause_at: &str) {
            let stderr = std::fs::File::create(self.tmp.path().join("stderr")).unwrap();
            let mut words = shell.split(' ');
            let child = Command::new(words.next().unwrap())
                .args(words)
                .arg("-c")
                .arg(session_script())
                .arg("dev-ssh")
                .arg(&self.dir)
                .arg(sshd)
                .arg(&self.mounts)
                .arg(pause_at)
                .env(ENV_CONFIG, "config-text")
                .env(ENV_HOST_KEY, "host-key-text")
                .env(ENV_AUTHORIZED_KEYS, "authorized-text")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(stderr)
                .spawn()
                .unwrap();
            self.child = Some(child);
        }

        fn child(&mut self) -> &mut Child {
            self.child.as_mut().expect("spawned")
        }

        fn shell_pid(&mut self) -> i32 {
            self.child().id() as i32
        }

        /// A file the fake sshd left beside the session dir.
        fn beside(&self, suffix: &str) -> PathBuf {
            let mut name = self.dir.as_os_str().to_owned();
            name.push(suffix);
            PathBuf::from(name)
        }

        fn seen(&self, suffix: &str) -> String {
            std::fs::read_to_string(self.beside(suffix)).unwrap_or_default()
        }

        fn sshd_pid(&self) -> Option<i32> {
            self.seen(".pid").trim().parse().ok()
        }

        fn wait_until_held(&self) {
            let deadline = Instant::now() + PATIENCE;
            while !self.beside(".held").exists() {
                assert!(Instant::now() < deadline, "the script never paused");
                std::thread::sleep(POLL);
            }
        }

        fn wait_for_sshd(&self) -> i32 {
            let deadline = Instant::now() + PATIENCE;
            loop {
                if let Some(pid) = self.sshd_pid() {
                    return pid;
                }
                assert!(Instant::now() < deadline, "the fake sshd never started");
                std::thread::sleep(POLL);
            }
        }

        fn finish(&mut self) -> (ExitStatus, String) {
            let status = wait_bounded(self.child(), PATIENCE, POLL).expect("the session ended");
            let stderr = std::fs::read_to_string(self.tmp.path().join("stderr")).unwrap();
            (status, stderr)
        }
    }

    impl Drop for Stage {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            if let Some(pid) = self.sshd_pid() {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    fn gone_within(pid: i32, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        while is_process_alive(pid as u32) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(POLL);
        }
        true
    }

    #[test]
    fn a_session_whose_sshd_exits_removes_its_dir_and_reports_sshd_status() {
        for shell in shells() {
            let mut stage = Stage::new();
            let sshd = stage.fake_sshd(
                r#"cat "$4" > "$d.config"
cat "$d/ssh_host_ed25519_key" > "$d.host_key"
cat "$d/authorized_keys" > "$d.authorized_keys"
ls -ld "$d" | cut -c1-10 > "$d.modes"
ls -l "$d" | grep -v '^total' | cut -c1-10 >> "$d.modes"
echo "${DEV_SSHD_CONFIG-unset} ${DEV_SSHD_HOST_KEY-unset} ${DEV_SSHD_AUTHORIZED_KEYS-unset}" > "$d.env"
exit 7"#,
            );
            stage.spawn(shell, &sshd);

            let (status, stderr) = stage.finish();

            assert_eq!(status.code(), Some(7), "{shell}: {stderr}");
            assert!(!stage.dir.exists(), "{shell}: the dir outlived sshd");
            assert_eq!(stage.seen(".config"), "config-text", "{shell}");
            assert_eq!(stage.seen(".host_key"), "host-key-text", "{shell}");
            assert_eq!(stage.seen(".authorized_keys"), "authorized-text", "{shell}");
            assert_eq!(
                stage.seen(".modes"),
                "drwx------\n-rw-------\n-rw-------\n-rw-------\n",
                "{shell}"
            );
            assert_eq!(stage.seen(".env"), "unset unset unset\n", "{shell}");
        }
    }

    #[test]
    fn a_signalled_session_stops_sshd_and_removes_its_dir() {
        for shell in shells() {
            for (signal, code) in [
                (libc::SIGTERM, 143),
                (libc::SIGHUP, 129),
                (libc::SIGINT, 130),
            ] {
                let mut stage = Stage::new();
                let sshd = stage.fake_sshd("exec sleep 30");
                stage.spawn(shell, &sshd);
                let sshd_pid = stage.wait_for_sshd();

                unsafe { libc::kill(stage.shell_pid(), signal) };
                let (status, stderr) = stage.finish();

                assert_eq!(status.code(), Some(code), "{shell} {signal}: {stderr}");
                assert!(!stage.dir.exists(), "{shell} {signal}: the dir was left");
                assert!(
                    gone_within(sshd_pid, PATIENCE),
                    "{shell} {signal}: sshd outlived the session"
                );
            }
        }
    }

    /// dash and busybox ash die of a signal that lands before any trap is
    /// set without running the EXIT trap, so the traps go in before `mkdir`.
    #[test]
    fn a_signal_right_after_mkdir_still_removes_the_dir() {
        for shell in shells() {
            let mut stage = Stage::new();
            let sshd = stage.fake_sshd("exec sleep 30");
            stage.spawn_pausing_at(shell, &sshd, "made");
            stage.wait_until_held();
            assert!(stage.dir.exists(), "{shell}");

            unsafe { libc::kill(stage.shell_pid(), libc::SIGTERM) };
            let (status, stderr) = stage.finish();

            assert_eq!(status.code(), Some(143), "{shell}: {stderr}");
            assert!(!stage.dir.exists(), "{shell}: the dir was left");
            assert_eq!(stage.sshd_pid(), None, "{shell}: sshd ran");
        }
    }

    /// The window between the fork and anything the script could assign
    /// afterwards: `stop` has to find sshd through `$!`.
    #[test]
    fn a_signal_right_after_the_fork_still_stops_sshd() {
        for shell in shells() {
            let mut stage = Stage::new();
            let sshd = stage.fake_sshd("exec sleep 30");
            stage.spawn_pausing_at(shell, &sshd, "forked");
            stage.wait_until_held();
            let sshd_pid = stage.wait_for_sshd();

            unsafe { libc::kill(stage.shell_pid(), libc::SIGTERM) };
            let (status, stderr) = stage.finish();

            assert_eq!(status.code(), Some(143), "{shell}: {stderr}");
            assert!(!stage.dir.exists(), "{shell}: the dir was left");
            assert!(
                gone_within(sshd_pid, PATIENCE),
                "{shell}: sshd outlived the session"
            );
        }
    }

    #[test]
    fn a_killed_sshd_ends_the_session_and_removes_its_dir() {
        for shell in shells() {
            let mut stage = Stage::new();
            let sshd = stage.fake_sshd("exec sleep 30");
            stage.spawn(shell, &sshd);
            let sshd_pid = stage.wait_for_sshd();

            unsafe { libc::kill(sshd_pid, libc::SIGKILL) };
            let (status, stderr) = stage.finish();

            assert_eq!(
                status.code(),
                Some(128 + libc::SIGKILL),
                "{shell}: {stderr}"
            );
            assert!(!stage.dir.exists(), "{shell}: the dir was left");
        }
    }

    /// The runtime closing the exec's stdin is all a vanished ssh-proxy does,
    /// so that alone has to end sshd and the session.
    #[test]
    fn a_closed_stdin_ends_sshd_and_the_session_removes_its_dir() {
        use std::io::Write;
        for shell in shells() {
            let mut stage = Stage::new();
            let sshd = stage.fake_sshd(r#"cat > "$d.stdin""#);
            stage.spawn(shell, &sshd);
            stage.wait_for_sshd();
            let mut stdin = stage.child().stdin.take().unwrap();
            stdin.write_all(b"SSH-2.0-client").unwrap();
            std::thread::sleep(Duration::from_millis(200));
            assert!(stage.child().try_wait().unwrap().is_none(), "{shell}");
            assert!(stage.dir.exists(), "{shell}");

            drop(stdin);
            let (status, stderr) = stage.finish();

            assert_eq!(status.code(), Some(0), "{shell}: {stderr}");
            assert!(!stage.dir.exists(), "{shell}: the dir was left");
            assert_eq!(stage.seen(".stdin"), "SSH-2.0-client", "{shell}");
        }
    }

    #[test]
    fn an_existing_dir_is_never_adopted_or_removed() {
        for shell in shells() {
            let mut stage = Stage::new();
            std::fs::create_dir(&stage.dir).unwrap();
            std::fs::write(stage.dir.join("keep"), "mine").unwrap();
            let sshd = stage.fake_sshd("exit 0");
            stage.spawn(shell, &sshd);

            let (status, stderr) = stage.finish();

            assert_eq!(status.code(), Some(1), "{shell}: {stderr}");
            assert!(
                stderr.contains("refusing to reuse the ssh session directory"),
                "{shell}: {stderr}"
            );
            assert_eq!(
                std::fs::read_to_string(stage.dir.join("keep")).unwrap(),
                "mine",
                "{shell}"
            );
            assert_eq!(stage.sshd_pid(), None, "{shell}: sshd ran");
        }
    }

    #[test]
    fn a_missing_sshd_or_a_disk_backed_shm_fails_before_making_anything() {
        for shell in shells() {
            let mut stage = Stage::new();
            let missing = stage.tmp.path().join("no-such-sshd");
            assert_refused_before_mkdir(shell, &mut stage, &missing, "sshd is not installed");

            let mut stage = Stage::new();
            std::fs::write(&stage.mounts, "/dev/sda1 /dev/shm ext4 rw 0 0\n").unwrap();
            let sshd = stage.fake_sshd("exit 0");
            assert_refused_before_mkdir(shell, &mut stage, &sshd, "/dev/shm is not a tmpfs");
        }
    }

    /// The stand-in `/dev/shm` is read-only for the run, so a `mkdir` ahead
    /// of the check would fail with its own message instead of `expected`,
    /// which tells "never made" from "made, then removed by the trap".
    fn assert_refused_before_mkdir(shell: &str, stage: &mut Stage, sshd: &Path, expected: &str) {
        let shm = stage.dir.parent().unwrap().to_path_buf();
        let mode = |bits| std::fs::set_permissions(&shm, std::fs::Permissions::from_mode(bits));
        mode(0o555).unwrap();
        stage.spawn(shell, sshd);
        let (status, stderr) = stage.finish();
        mode(0o755).unwrap();

        assert_eq!(status.code(), Some(1), "{shell}: {stderr}");
        assert!(stderr.contains(expected), "{shell}: {stderr}");
        assert!(!stderr.contains("refusing to reuse"), "{shell}: {stderr}");
        assert!(!stage.dir.exists(), "{shell}");
    }
}
