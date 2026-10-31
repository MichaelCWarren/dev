use std::path::Path;

use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::devcontainer::config::DevcontainerConfig;
use crate::devcontainer::secrets::up_store::read_up_store;
use crate::devcontainer::secrets::validate::validate_secrets_for_config;
use crate::devcontainer::secrets::{
    ProviderRegistry, ResolveTime, SecretRef, SecretValue, ValidatedSecrets,
};
use crate::error::DevError;
use crate::runtime::{
    ContainerRuntime, ExecResult, detect_runtime, find_running_container, resolve_remote_user,
};
use crate::session::{self, SessionKind};
use crate::util::naming::workspace_hash;
use crate::util::paths::DevHome;
use crate::util::workspace_folder_name;

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    user: Option<&str>,
    cmd: &[String],
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    let registry = ProviderRegistry::with_builtins(workspace);
    run_with_runtime(
        workspace,
        runtime.as_ref(),
        user,
        cmd,
        &registry,
        &DevHome::current(),
    )
    .await
}

pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn crate::runtime::ContainerRuntime,
    user: Option<&str>,
    cmd: &[String],
    registry: &ProviderRegistry,
    dev_home: &DevHome,
) -> anyhow::Result<()> {
    let container = find_running_container(runtime, workspace)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("No running container found for this workspace. Run `dev up` first.")
        })?;

    // Use explicit --user flag, falling back to remoteUser from config or image metadata
    let (config_path, config) =
        load_workspace_config_or_warn(dev_home, workspace, runtime.runtime_name()).unzip();

    let resolved_user = if user.is_some() {
        user.map(|u| u.to_string())
    } else {
        let config_user = config
            .as_ref()
            .and_then(|config| config.remote_user.clone());
        resolve_remote_user(runtime, &container.image, config_user.as_deref()).await?
    };
    let effective_user = resolved_user.as_deref();

    let workdir = match config.as_ref() {
        Some(config) => config.workspace_folder_path(workspace, effective_user)?,
        None => format!("/workspaces/{}", workspace_folder_name(workspace)),
    };

    // Before the sweep, so a bad reference leaves the container exactly as it
    // was found, and after the container lookup, so a workspace with nothing
    // running never costs a provider prompt.
    let secrets = session_secrets(
        runtime,
        &container.id,
        config_path.as_deref(),
        config.as_ref(),
        workspace,
        registry,
        dev_home,
    )
    .await?;

    // Collected here as well as in `dev shell`, so a container is tidied by
    // whichever command reaches it first. The cost is one round trip when
    // there is nothing to collect.
    match session::sweep(runtime, &container.id, effective_user).await {
        Ok(0) => {}
        Ok(reaped) => eprintln!("dev: reaped {reaped} orphaned container session(s)"),
        Err(e) => eprintln!("Warning: could not check for orphaned sessions: {e}"),
    }

    let host = session::host_identity().await;
    let outcome = attend_command(
        runtime,
        &container.id,
        cmd,
        effective_user,
        &workdir,
        &host,
        &secrets,
    )
    .await?;

    let result = match outcome {
        Outcome::Finished(result) => result,
        // Nothing ran to completion, so there is no output and no status of the
        // command's own to report — only the signal this process took.
        Outcome::Signalled(signal) => std::process::exit(128 + signal),
    };

    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }

    if result.exit_code != 0 {
        std::process::exit(result.exit_code);
    }

    Ok(())
}

/// The secrets one exec, shell or ssh session carries, by when they resolve.
///
/// `exec` values go through their providers every time, so a rotated secret
/// reaches the next command without a recreate. `up` values are read from the
/// in-container store the latest `dev up` wrote, with no provider call.
/// `create` values are already in the container env and are not touched.
/// Values live for the length of this command and are dropped.
pub(crate) async fn session_secrets(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    config_path: Option<&Path>,
    config: Option<&DevcontainerConfig>,
    workspace: &Path,
    registry: &ProviderRegistry,
    dev_home: &DevHome,
) -> Result<Vec<(String, SecretValue)>, DevError> {
    let (Some(config_path), Some(config)) = (config_path, config) else {
        return Ok(Vec::new());
    };
    let secrets = validate_secrets_for_config(
        dev_home,
        config_path,
        workspace,
        config.remote_user.as_deref(),
        config.is_compose(),
        registry,
    )?;
    // The store is checked first so a missing `up` key costs no provider prompt.
    let store_key = workspace_hash(workspace);
    let up = read_up_values(runtime, container_id, &store_key, &secrets).await?;
    crate::commands::print_warnings(&mut std::io::stderr(), up.warning);
    let mut values = up.values;
    values.extend(resolve_exec_values(registry, &secrets).await?);
    Ok(values)
}

/// The `up` values a session read, and the warning it owes the user, if any.
struct UpValues {
    values: Vec<(String, SecretValue)>,
    warning: Option<String>,
}

/// A store that cannot be read at all only fails the command when a required
/// key was wanted from it; optional keys are left out with a warning for the
/// caller to print.
async fn read_up_values(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    store_key: &str,
    secrets: &ValidatedSecrets,
) -> Result<UpValues, DevError> {
    let keys: Vec<String> = secrets
        .entries_at(ResolveTime::Up)
        .map(|r| r.key().to_string())
        .collect();
    let read = match read_up_store(runtime, container_id, store_key, &keys).await {
        Ok(read) => read,
        Err(e) if secrets.entries_at(ResolveTime::Up).all(|r| r.optional()) => {
            return Ok(UpValues {
                values: Vec::new(),
                warning: Some(unreadable_store_warning(&keys, &e)),
            });
        }
        Err(e) => return Err(e),
    };
    let required_missing: Vec<&str> = secrets
        .entries_at(ResolveTime::Up)
        .filter(|r| !r.optional() && read.missing.iter().any(|m| m == r.key()))
        .map(|r| r.key())
        .collect();
    if !required_missing.is_empty() {
        return Err(DevError::UpSecretsNotStored(format!(
            "secret(s) {} resolve at `dev up` but are not stored in this container; \
             run `dev up` to store them",
            required_missing.join(", ")
        )));
    }
    Ok(UpValues {
        values: read.found,
        warning: None,
    })
}

fn unreadable_store_warning(keys: &[String], error: &DevError) -> String {
    format!(
        "Warning: could not read the `up` secret store, so optional secret(s) {} are left out: {error}",
        keys.join(", ")
    )
}

async fn resolve_exec_values(
    registry: &ProviderRegistry,
    secrets: &ValidatedSecrets,
) -> Result<Vec<(String, SecretValue)>, DevError> {
    let entries: Vec<SecretRef> = secrets.entries_at(ResolveTime::Exec).cloned().collect();
    registry.resolve_all(&entries).await
}

/// How a `dev exec` ended.
enum Outcome {
    /// The command ran and reported a status of its own.
    Finished(ExecResult),
    /// This process was told to go away first, carrying the signal.
    Signalled(i32),
}

/// Run the command, and end it if this process is told to go away first.
///
/// A `dev exec` that is interrupted — the common way a long one ends, since
/// unlike `dev shell` there is no raw terminal to swallow Ctrl-C — leaves the
/// container running it with nothing attached: the daemon keeps the exec alive
/// whether or not a client is reading. So the command is recorded, and hung up
/// explicitly when this process is the one that stops.
async fn attend_command(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    cmd: &[String],
    user: Option<&str>,
    workdir: &str,
    host: &session::HostIdentity,
    secrets: &[(String, SecretValue)],
) -> anyhow::Result<Outcome> {
    let running = run_recorded(runtime, container_id, cmd, user, workdir, host, secrets);
    match until_signalled(running, runtime, container_id, user, host.pid).await? {
        Ok(finished) => Ok(Outcome::Finished(finished?)),
        Err(signal) => Ok(Outcome::Signalled(signal)),
    }
}

/// Where the exit signals a command watches for come from.
pub(crate) trait SignalSource {
    /// The number of the next signal to arrive. Dropping the future before it
    /// resolves loses no signal.
    fn next(&mut self) -> impl std::future::Future<Output = i32> + Send;
}

/// Signals that arrive at fixed instants. A `next` dropped before its
/// instant keeps the signal for the following call, as tokio's own signal
/// streams do.
#[cfg(test)]
pub(crate) struct ScriptedSignals(std::collections::VecDeque<(tokio::time::Instant, i32)>);

#[cfg(test)]
impl ScriptedSignals {
    pub(crate) fn after(script: &[(std::time::Duration, i32)]) -> Self {
        let start = tokio::time::Instant::now();
        Self(script.iter().map(|&(at, sig)| (start + at, sig)).collect())
    }
}

#[cfg(test)]
impl SignalSource for ScriptedSignals {
    async fn next(&mut self) -> i32 {
        let Some(&(at, signal)) = self.0.front() else {
            return std::future::pending().await;
        };
        tokio::time::sleep_until(at).await;
        self.0.pop_front();
        signal
    }
}

/// SIGINT, SIGTERM and SIGHUP, caught from the moment this is made. Tokio
/// keeps a handler installed for the rest of the process once there is one,
/// so a signal that lands before anything waits on these is held, not fatal.
pub(crate) struct ExitSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

impl ExitSignals {
    pub(crate) fn watch() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        let watch = |kind: SignalKind, name: &str| {
            signal(kind).map_err(|e| anyhow::anyhow!("watch {name}: {e}"))
        };
        Ok(Self {
            interrupt: watch(SignalKind::interrupt(), "SIGINT")?,
            terminate: watch(SignalKind::terminate(), "SIGTERM")?,
            hangup: watch(SignalKind::hangup(), "SIGHUP")?,
        })
    }
}

impl SignalSource for ExitSignals {
    async fn next(&mut self) -> i32 {
        tokio::select! {
            _ = self.interrupt.recv() => libc::SIGINT,
            _ = self.terminate.recv() => libc::SIGTERM,
            _ = self.hangup.recv() => libc::SIGHUP,
        }
    }
}

/// Run `work`, giving it up for the signal number if this process is told to
/// go away first. On a signal, `work` is dropped and then the sessions this
/// process recorded in the container are hung up, since the daemon would
/// otherwise keep them running with nothing attached.
pub(crate) async fn until_signalled<F: std::future::Future>(
    work: F,
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    host_pid: u32,
) -> anyhow::Result<Result<F::Output, i32>> {
    let mut signals = ExitSignals::watch()?;
    let mut work = Box::pin(work);
    let signalled = tokio::select! {
        output = &mut work => return Ok(Ok(output)),
        signal = signals.next() => signal,
    };
    drop(work);
    session::release_own_sessions(runtime, container_id, user, host_pid).await;
    Ok(Err(signalled))
}

/// Run the command so that it can be found again, falling back to running it
/// plainly in an image that has no shell to record it with.
///
/// A missing `/bin/sh` reaches this in either of two shapes, and both have to
/// be caught or an image without a shell would stop being able to run anything
/// at all: the daemon can decline the exec outright, which arrives as an API
/// error, or it can accept it and report the start failure as status 127 with
/// its own message in the output stream.
async fn run_recorded(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    cmd: &[String],
    user: Option<&str>,
    workdir: &str,
    host: &session::HostIdentity,
    secrets: &[(String, SecretValue)],
) -> Result<ExecResult, DevError> {
    let recorded = session::registered_command(cmd, SessionKind::Exec, host);
    match runtime
        .exec(container_id, &recorded, user, Some(workdir), secrets)
        .await
    {
        Err(e) if runtime.exec_reports_missing_command(&e) => {
            runtime
                .exec(container_id, cmd, user, Some(workdir), secrets)
                .await
        }
        Ok(result) if reports_missing_shell(&result) => {
            runtime
                .exec(container_id, cmd, user, Some(workdir), secrets)
                .await
        }
        other => other,
    }
}

/// Whether a completed exec means the recording shell never started.
///
/// Falling back runs the command a second time, so this has to be sure the
/// first attempt ran nothing. Three things have to agree before it is: the
/// status a runtime uses for a command it could not start, a message that is
/// the *runtime* announcing that failure rather than a shell reporting
/// anything, and that message being the whole of the output — a command that
/// ran would have said something of its own first.
///
/// The message arrives on stdout, not stderr: the daemon writes it into the
/// exec's output stream rather than answering the API call with it, so which
/// stream it lands on says nothing about what it means.
///
/// A command the user misspelled looks nothing like this — the shell starts,
/// and reports the miss itself, naming the command it was given.
fn reports_missing_shell(result: &ExecResult) -> bool {
    if result.exit_code != 127 {
        return false;
    }
    let output = format!("{}{}", result.stdout, result.stderr);
    let output = output.trim_start();
    [
        "OCI runtime exec failed",
        "exec failed",
        "unable to start container process",
    ]
    .iter()
    .any(|announcement| output.starts_with(announcement))
        && output.contains("/bin/sh")
}

#[cfg(test)]
mod tests {
    use super::run_with_runtime;
    use crate::devcontainer::secrets::provider::{FakeProvider, PluginPath, ProviderRegistry};
    use crate::devcontainer::secrets::up_store::{FakeUpStore, is_up_store_exec, up_store_key};
    use crate::devcontainer::secrets::validate::with_base;
    use crate::devcontainer::secrets::{SecretValue, expose, secrets_json};
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ContainerState,
        ExecResult, ImageMetadata,
    };
    use crate::util::paths::DevHome;
    use crate::util::workspace_labels;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("unused fake runtime method".into())) })
    }

    type ExecCall = (
        Vec<String>,
        Option<String>,
        Option<String>,
        Vec<(String, String)>,
    );

    struct ExecFakeRuntime {
        containers: Vec<ContainerInfo>,
        execs: Arc<Mutex<Vec<ExecCall>>>,
        /// Stands in for an image with no `/bin/sh`.
        without_a_shell: bool,
        /// Which of the two shapes that takes: an API error, or an accepted
        /// exec reporting the start failure as status 127.
        shell_missing_as_status: bool,
        store: FakeUpStore,
    }

    impl ExecFakeRuntime {
        fn running_for(workspace: &Path, config_path: &Path) -> Self {
            Self {
                containers: vec![ContainerInfo {
                    id: "container-id".to_string(),
                    name: "container".to_string(),
                    state: ContainerState::Running,
                    labels: workspace_labels(workspace, Some(config_path))
                        .into_iter()
                        .collect(),
                    image: "ubuntu:24.04".to_string(),
                }],
                execs: Arc::new(Mutex::new(Vec::new())),
                without_a_shell: false,
                shell_missing_as_status: false,
                store: FakeUpStore::default(),
            }
        }

        fn storing(mut self, pairs: &[(&str, &str)]) -> Self {
            self.store = FakeUpStore::storing(pairs);
            self
        }

        fn with_an_unreadable_store(mut self) -> Self {
            self.store = FakeUpStore::unreadable();
            self
        }

        fn without_a_shell(mut self) -> Self {
            self.without_a_shell = true;
            self
        }

        fn reporting_that_as_a_status(mut self) -> Self {
            self.shell_missing_as_status = true;
            self
        }

        /// The commands somebody asked for, without `dev`'s own bookkeeping.
        fn execs(&self) -> Vec<ExecCall> {
            self.execs
                .lock()
                .unwrap()
                .iter()
                .filter(|(cmd, ..)| {
                    !crate::session::is_session_machinery(cmd) && !is_up_store_exec(cmd)
                })
                .cloned()
                .collect()
        }

        /// Reads of the in-container up store, which are not the user's command.
        fn store_reads(&self) -> Vec<ExecCall> {
            FakeUpStore::reads(&self.execs.lock().unwrap(), |call| &call.0)
        }

        /// `dev`'s own bookkeeping execs, which must carry no secret.
        fn session_execs(&self) -> Vec<ExecCall> {
            self.execs
                .lock()
                .unwrap()
                .iter()
                .filter(|(cmd, ..)| crate::session::is_session_machinery(cmd))
                .cloned()
                .collect()
        }

        /// Whether this container was swept for orphaned sessions.
        fn was_swept(&self) -> bool {
            self.execs
                .lock()
                .unwrap()
                .iter()
                .any(|(cmd, ..)| crate::session::is_session_machinery(cmd))
        }
    }

    impl ContainerRuntime for ExecFakeRuntime {
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
            unused()
        }

        fn start_container(&self, _id: &str) -> BoxFut<'_, ()> {
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
            workdir: Option<&str>,
            env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            self.execs.lock().unwrap().push((
                cmd.to_vec(),
                user.map(str::to_string),
                workdir.map(str::to_string),
                expose(env),
            ));
            if let Some(reply) = self.store.answer(cmd) {
                return Box::pin(async move { Ok(reply) });
            }
            let no_shell = self.without_a_shell && cmd.first().is_some_and(|arg| arg == "/bin/sh");
            let as_status = self.shell_missing_as_status;
            Box::pin(async move {
                match (no_shell, as_status) {
                    // The daemon declining the exec outright.
                    (true, false) => Err(DevError::Runtime(
                        r#"exec: "/bin/sh": no such file or directory"#.into(),
                    )),
                    // The daemon accepting it and reporting the start failure
                    // as a status, which is what Docker Desktop does in
                    // practice — verbatim, down to the wording and the stream
                    // it arrives on, which is stdout rather than stderr.
                    (true, true) => Ok(ExecResult {
                        exit_code: 127,
                        stdout: "OCI runtime exec failed: exec failed: unable to start \
                                 container process: exec: \"/bin/sh\": stat /bin/sh: no such \
                                 file or directory"
                            .to_string(),
                        stderr: String::new(),
                    }),
                    _ => Ok(ExecResult {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                }
            })
        }

        fn exec_reports_missing_command(&self, error: &DevError) -> bool {
            matches!(error, DevError::Runtime(message) if message.contains("no such file"))
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
                    .filter(|container| {
                        filters.iter().all(|(key, value)| {
                            container.labels.get(key).is_some_and(|got| got == value)
                        })
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
    }

    /// A workspace whose config resolves to a non-default `workspaceFolder`.
    fn workspace_with_config() -> (TempDir, std::path::PathBuf) {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).unwrap();
        let config_path = devcontainer_dir.join("devcontainer.json");
        std::fs::write(
            &config_path,
            r#"{
                "image": "ubuntu:24.04",
                "workspaceMount": "source=${localWorkspaceFolder},target=/srv/app,type=bind",
                "workspaceFolder": "/srv/app/packages/api"
            }"#,
        )
        .unwrap();
        (workspace, config_path)
    }

    /// [`workspace_with_config`] with a `secrets.json` beside the config, so the
    /// sidecar is found through the real discovery rule rather than a stub.
    fn workspace_with_secrets(file_contents: &str) -> (TempDir, std::path::PathBuf) {
        let (workspace, config_path) = workspace_with_config();
        std::fs::write(
            config_path.parent().unwrap().join("secrets.json"),
            file_contents,
        )
        .unwrap();
        (workspace, config_path)
    }

    /// A registry holding only `provider`, with the plugin search path pointed
    /// at nothing so no `dev-secret-*` on the real `PATH` can answer.
    fn registry_with(workspace: &Path, provider: FakeProvider) -> ProviderRegistry {
        let mut registry =
            ProviderRegistry::empty(workspace, PluginPath::from_os_str(OsStr::new("")));
        registry.register(Box::new(provider));
        registry
    }

    /// A registry whose provider must never be asked anything.
    fn silent_registry(workspace: &Path) -> ProviderRegistry {
        registry_with(workspace, FakeProvider::recording())
    }

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[tokio::test]
    async fn one_off_exec_runs_in_the_resolved_workspace_folder() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &silent_registry(workspace.path()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        let execs = runtime.execs();
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].2.as_deref(), Some("/srv/app/packages/api"));
    }

    /// Every `dev exec` collects this container's abandoned sessions, so a
    /// container stays tidy for whoever reaches it first.
    #[tokio::test]
    async fn a_one_off_command_sweeps_before_it_runs() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &silent_registry(workspace.path()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        assert!(runtime.was_swept());
    }

    /// The command is recorded so that a `dev exec` whose client dies can be
    /// found and ended, rather than running on in the container forever.
    #[tokio::test]
    async fn a_one_off_command_records_itself_and_clears_the_record() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &silent_registry(workspace.path()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        let cmd = &runtime.execs()[0].0;
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("> /tmp/.dev-session-$$"));
        assert!(cmd[2].contains("'exec'"), "recorded as an exec session");
        // The record is cleared on the way out rather than left for whatever
        // reads this container next, and the command's status still reports.
        assert!(cmd[2].contains("\n\"$@\"\n"));
        assert!(cmd[2].contains("rm -f /tmp/.dev-session-$$"));
        assert!(cmd[2].ends_with("exit $__dev_rc"));
    }

    /// The caller's words reach the command as arguments, never as script text,
    /// so nothing in them can be read as syntax by the shell that records it.
    #[tokio::test]
    async fn a_commands_words_are_passed_through_untouched() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);
        let hostile = words(&[
            "python3",
            "-c",
            "print('hi; rm -rf /')",
            "a b c",
            "$(id)",
            "`id`",
            "it's",
            "*",
        ]);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &hostile,
            &silent_registry(workspace.path()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        let cmd = &runtime.execs()[0].0;
        // $0 names the session, and the caller's words follow it verbatim.
        assert_eq!(cmd[3], "dev-exec");
        assert_eq!(&cmd[4..], hostile.as_slice());
        assert!(!cmd[2].contains("rm -rf"), "no word reached the script");
    }

    /// An image with no shell has nothing to record a session with, and running
    /// the command still matters more than being able to find it later.
    #[tokio::test]
    async fn a_command_still_runs_in_an_image_without_a_shell() {
        let (workspace, config_path) = workspace_with_config();
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).without_a_shell();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &silent_registry(workspace.path()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should fall back to the bare command");

        let execs = runtime.execs();
        assert_eq!(
            execs.len(),
            2,
            "the wrapper is tried first, then the command"
        );
        assert_eq!(execs[0].0[0], "/bin/sh");
        assert_eq!(execs[1].0, words(&["cargo", "test"]));
        assert_eq!(execs[1].2.as_deref(), Some("/srv/app/packages/api"));
    }

    /// The same thing, in the shape Docker Desktop actually answers with: the
    /// exec is accepted, and the start failure comes back as a status. Nothing
    /// ran, so the fallback still has to happen — read only from the error, it
    /// would not, and an image without a shell could run nothing at all.
    #[tokio::test]
    async fn a_missing_shell_reported_as_a_status_also_falls_back() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .without_a_shell()
            .reporting_that_as_a_status();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &silent_registry(workspace.path()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should fall back to the bare command");

        let execs = runtime.execs();
        assert_eq!(execs.len(), 2);
        assert_eq!(execs[1].0, words(&["cargo", "test"]));
    }

    const TWO_SECRETS: &str = r#"{"version":1,"secrets":{
        "TOKEN":{"provider":"fake","ref":"token","resolve":"exec"},
        "API_KEY":{"provider":"fake","ref":"api","resolve":"exec"}
    }}"#;

    fn answers() -> FakeProvider {
        FakeProvider::answering(&[("TOKEN", "hunter2"), ("API_KEY", "s3cret")])
    }

    /// The whole point of exec-time injection: the command sees values fetched
    /// for this invocation, not whatever was baked in at create.
    #[tokio::test]
    async fn a_one_off_command_carries_the_workspaces_resolved_secrets() {
        let (workspace, config_path) = workspace_with_secrets(TWO_SECRETS);
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);
        let provider = answers();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), provider.clone()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        assert_eq!(
            runtime.execs()[0].3,
            vec![
                ("TOKEN".to_string(), "hunter2".to_string()),
                ("API_KEY".to_string(), "s3cret".to_string()),
            ]
        );
    }

    /// The missing-shell fallback runs the command twice. Paying for a second
    /// biometric prompt to do it would be indefensible.
    #[tokio::test]
    async fn secrets_are_resolved_once_per_invocation_not_once_per_exec() {
        let (workspace, config_path) = workspace_with_secrets(TWO_SECRETS);
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).without_a_shell();
        let provider = answers();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), provider.clone()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should fall back to the bare command");

        let execs = runtime.execs();
        assert_eq!(execs.len(), 2);
        assert_eq!(execs[0].3, execs[1].3);
        assert_eq!(provider.calls(), 1);
    }

    /// Legacy `createTime: false` means `exec`: fetched for each command, which
    /// is how it stays out of `docker inspect`.
    #[tokio::test]
    async fn a_secret_marked_create_time_false_resolves_at_exec() {
        let (workspace, config_path) = workspace_with_secrets(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"fake","ref":"token","createTime":false}}}"#,
        );
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), answers()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        assert_eq!(
            runtime.execs()[0].3,
            vec![("TOKEN".to_string(), "hunter2".to_string())]
        );
    }

    #[tokio::test]
    async fn a_workspace_without_secrets_calls_no_provider() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);
        let provider = FakeProvider::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), provider.clone()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        assert!(runtime.execs()[0].3.is_empty());
        assert_eq!(provider.calls(), 0);
    }

    /// A command that would run without the secret it asked for is worse than
    /// one that does not run, so nothing touches the container first.
    #[tokio::test]
    async fn a_failed_required_secret_stops_the_command_from_running() {
        let (workspace, config_path) = workspace_with_secrets(TWO_SECRETS);
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        let err = run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), FakeProvider::failing_for("TOKEN")),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect_err("a required secret that cannot resolve fails the command");

        assert!(err.to_string().contains("TOKEN"), "{err}");
        assert!(runtime.execs().is_empty());
        assert!(!runtime.was_swept());
    }

    #[tokio::test]
    async fn an_optional_secret_that_fails_is_omitted() {
        let (workspace, config_path) = workspace_with_secrets(
            r#"{"version":1,"secrets":{
                "TOKEN":{"provider":"fake","ref":"token","optional":true,"resolve":"exec"},
                "API_KEY":{"provider":"fake","ref":"api","resolve":"exec"}
            }}"#,
        );
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);
        let provider = answers().also_failing_for("TOKEN");

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), provider),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("an optional secret that fails is not fatal");

        assert_eq!(
            runtime.execs()[0].3,
            vec![("API_KEY".to_string(), "s3cret".to_string())]
        );
    }

    /// Values travel as env, outside the argv the recording shell is handed, so
    /// nothing in the container's process table shows them.
    #[tokio::test]
    async fn no_secret_value_reaches_the_recorded_script() {
        let (workspace, config_path) = workspace_with_secrets(TWO_SECRETS);
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), answers()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        let cmd = &runtime.execs()[0].0;
        assert!(cmd[2].contains("dev-session"), "the recording script");
        for word in cmd {
            assert!(!word.contains("hunter2"), "{word}");
            assert!(!word.contains("s3cret"), "{word}");
        }
    }

    /// Sweeping and releasing are dev's own bookkeeping. They need no secret,
    /// so they carry none.
    #[tokio::test]
    async fn dev_s_own_session_commands_carry_no_secrets() {
        let (workspace, config_path) = workspace_with_secrets(TWO_SECRETS);
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace.path(), answers()),
            &DevHome::at(workspace.path().join("dev-home")),
        )
        .await
        .expect("dev exec should run the command");

        let sessions = runtime.session_execs();
        assert!(!sessions.is_empty(), "the sweep ran");
        for session in sessions {
            assert!(session.3.is_empty());
        }
    }

    /// Dev keeps no cache of its own for `exec` secrets, which is what lets a
    /// rotated one reach the next command without a recreate.
    #[tokio::test]
    async fn nothing_is_remembered_between_invocations() {
        let (workspace, config_path) = workspace_with_secrets(TWO_SECRETS);
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);
        let provider = answers();
        let registry = registry_with(workspace.path(), provider.clone());

        for _ in 0..2 {
            run_with_runtime(
                workspace.path(),
                &runtime,
                None,
                &words(&["cargo", "test"]),
                &registry,
                &DevHome::at(workspace.path().join("dev-home")),
            )
            .await
            .expect("dev exec should run the command");
        }

        assert_eq!(provider.calls(), 2);
    }

    async fn run_command(
        workspace: &Path,
        runtime: &ExecFakeRuntime,
        provider: &FakeProvider,
    ) -> anyhow::Result<()> {
        run_with_runtime(
            workspace,
            runtime,
            None,
            &words(&["cargo", "test"]),
            &registry_with(workspace, provider.clone()),
            &DevHome::at(workspace.join("dev-home")),
        )
        .await
    }

    fn from_provider() -> FakeProvider {
        FakeProvider::answering(&[("TOKEN", "from-provider")])
    }

    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_string(), value.to_string())
    }

    #[tokio::test]
    async fn a_create_secret_is_neither_resolved_nor_read() {
        let (workspace, config_path) =
            workspace_with_secrets(&secrets_json(&[("TOKEN", "create")]));
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).storing(&[("TOKEN", "x")]);
        let provider = from_provider();

        run_command(workspace.path(), &runtime, &provider)
            .await
            .expect("dev exec should run the command");

        assert_eq!(provider.calls(), 0);
        assert!(runtime.store_reads().is_empty());
        assert!(runtime.execs()[0].3.is_empty());
    }

    #[tokio::test]
    async fn an_up_secret_is_read_from_the_store_not_resolved() {
        let (workspace, config_path) = workspace_with_secrets(&secrets_json(&[("TOKEN", "up")]));
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .storing(&[("TOKEN", "from-store")]);
        let provider = from_provider();

        run_command(workspace.path(), &runtime, &provider)
            .await
            .expect("dev exec should run the command");

        assert_eq!(provider.calls(), 0);
        let reads = runtime.store_reads();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].1.as_deref(), Some("root"));
        assert!(reads[0].3.is_empty());
        assert_eq!(runtime.execs()[0].3, vec![pair("TOKEN", "from-store")]);
    }

    #[tokio::test]
    async fn an_exec_secret_is_resolved_for_this_command() {
        let (workspace, config_path) = workspace_with_secrets(&secrets_json(&[("TOKEN", "exec")]));
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).storing(&[("TOKEN", "x")]);
        let provider = from_provider();

        run_command(workspace.path(), &runtime, &provider)
            .await
            .expect("dev exec should run the command");

        assert_eq!(provider.calls(), 1);
        assert!(runtime.store_reads().is_empty());
        assert_eq!(runtime.execs()[0].3, vec![pair("TOKEN", "from-provider")]);
    }

    #[tokio::test]
    async fn one_workspace_with_all_three_times_resolves_only_the_exec_key() {
        let (workspace, config_path) = workspace_with_secrets(&secrets_json(&[
            ("C", "create"),
            ("U", "up"),
            ("E", "exec"),
        ]));
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .storing(&[("U", "from-store")]);
        let provider = FakeProvider::answering(&[
            ("C", "c-provider"),
            ("U", "u-provider"),
            ("E", "e-provider"),
        ]);

        run_command(workspace.path(), &runtime, &provider)
            .await
            .expect("dev exec should run the command");

        assert_eq!(provider.batch_keys(), vec![vec!["E".to_string()]]);
        assert_eq!(runtime.store_reads().len(), 1);
        assert_eq!(
            runtime.execs()[0].3,
            vec![pair("U", "from-store"), pair("E", "e-provider")]
        );
    }

    #[tokio::test]
    async fn a_required_up_secret_missing_from_the_store_stops_the_command() {
        let (workspace, config_path) = workspace_with_secrets(&secrets_json(&[
            ("TOKEN", "up"),
            ("API_KEY", "up"),
            ("E", "exec"),
        ]));
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path).storing(&[]);
        let provider = FakeProvider::answering(&[("E", "e-provider")]);

        let err = run_command(workspace.path(), &runtime, &provider)
            .await
            .expect_err("a required up secret that is not stored fails the command");

        let message = err.to_string();
        assert!(message.contains("TOKEN, API_KEY"), "{message}");
        assert!(message.contains("dev up"), "{message}");
        assert_eq!(provider.calls(), 0);
        assert!(runtime.execs().is_empty());
        assert!(!runtime.was_swept());
    }

    #[tokio::test]
    async fn an_optional_up_secret_missing_from_the_store_is_omitted() {
        let (workspace, config_path) = workspace_with_secrets(
            r#"{"version":1,"secrets":{
                "TOKEN":{"provider":"fake","ref":"token","resolve":"up","optional":true},
                "API_KEY":{"provider":"fake","ref":"api_key","resolve":"up"}
            }}"#,
        );
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .storing(&[("API_KEY", "from-store")]);

        run_command(workspace.path(), &runtime, &from_provider())
            .await
            .expect("an optional up secret that is not stored is not fatal");

        assert_eq!(runtime.execs()[0].3, vec![pair("API_KEY", "from-store")]);
    }

    #[tokio::test]
    async fn a_stored_key_the_config_does_not_declare_as_up_is_not_injected() {
        let (workspace, config_path) = workspace_with_secrets(&secrets_json(&[("TOKEN", "up")]));
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .storing(&[("TOKEN", "from-store"), ("OTHER", "leaked")]);

        run_command(workspace.path(), &runtime, &from_provider())
            .await
            .expect("dev exec should run the command");

        assert_eq!(runtime.execs()[0].3, vec![pair("TOKEN", "from-store")]);
    }

    #[tokio::test]
    async fn the_store_is_read_under_the_workspaces_own_key() {
        let (workspace, config_path) = workspace_with_secrets(&secrets_json(&[("TOKEN", "up")]));
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .storing(&[("TOKEN", "from-store")]);

        run_command(workspace.path(), &runtime, &from_provider())
            .await
            .expect("dev exec should run the command");

        let reads = runtime.store_reads();
        let expected = crate::util::naming::workspace_hash(workspace.path());
        assert_eq!(up_store_key(&reads[0].0), Some(expected));
    }

    #[tokio::test]
    async fn an_unreadable_store_leaves_out_optional_up_keys() {
        let (workspace, config_path) = workspace_with_secrets(
            r#"{"version":1,"secrets":{
                "TOKEN":{"provider":"fake","ref":"token","resolve":"up","optional":true},
                "E":{"provider":"fake","ref":"e","resolve":"exec"}
            }}"#,
        );
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).with_an_unreadable_store();
        let provider = FakeProvider::answering(&[("E", "e-provider")]);

        run_command(workspace.path(), &runtime, &provider)
            .await
            .expect("an unreadable store costs only optional up keys");

        assert_eq!(runtime.store_reads().len(), 1);
        assert_eq!(runtime.execs()[0].3, vec![pair("E", "e-provider")]);
    }

    #[tokio::test]
    async fn the_unreadable_store_warning_carries_the_read_error() {
        let (workspace, config_path) = workspace_with_secrets(
            r#"{"version":1,"secrets":{
                "TOKEN":{"provider":"fake","ref":"token","resolve":"up","optional":true}
            }}"#,
        );
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).with_an_unreadable_store();
        let secrets = crate::devcontainer::secrets::validate::validate_secrets_for_config(
            &DevHome::at(workspace.path().join("dev-home")),
            &config_path,
            workspace.path(),
            None,
            false,
            &registry_with(workspace.path(), from_provider()),
        )
        .unwrap();

        let up = super::read_up_values(&runtime, "container-id", "ab12", &secrets)
            .await
            .expect("only an optional key was wanted");

        assert!(up.values.is_empty());
        let warning = up.warning.expect("a warning");
        assert!(
            warning.starts_with("Warning: could not read the `up` secret store"),
            "{warning}"
        );
        assert!(warning.contains("TOKEN"), "{warning}");
        assert!(
            warning.contains("(exit 1): od is missing in this container"),
            "the read's own error, verbatim: {warning}"
        );
    }

    #[tokio::test]
    async fn an_unreadable_store_fails_a_required_up_key() {
        let (workspace, config_path) = workspace_with_secrets(
            r#"{"version":1,"secrets":{
                "TOKEN":{"provider":"fake","ref":"token","resolve":"up","optional":true},
                "API_KEY":{"provider":"fake","ref":"api_key","resolve":"up"}
            }}"#,
        );
        let runtime =
            ExecFakeRuntime::running_for(workspace.path(), &config_path).with_an_unreadable_store();

        let err = run_command(workspace.path(), &runtime, &from_provider())
            .await
            .expect_err("a required up key needs a readable store");

        assert!(err.to_string().contains("od is missing"), "{err}");
        assert!(runtime.execs().is_empty());
    }

    /// A Compose workspace with no `secrets.json` of its own, under a base file
    /// declaring `TOKEN` at `create`.
    fn compose_workspace_with_base_create_token() -> (TempDir, std::path::PathBuf) {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).unwrap();
        let config_path = devcontainer_dir.join("devcontainer.json");
        std::fs::write(
            &config_path,
            r#"{"dockerComposeFile":"compose.yml","service":"app","workspaceFolder":"/app"}"#,
        )
        .unwrap();
        with_base(workspace.path(), &secrets_json(&[("TOKEN", "create")]));
        (workspace, config_path)
    }

    /// `dev up` stores a base `create` key for Compose, so the reader has to
    /// look for it there too and not in an env Compose never set.
    #[tokio::test]
    async fn a_compose_base_create_secret_is_read_from_the_store() {
        let (workspace, config_path) = compose_workspace_with_base_create_token();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path)
            .storing(&[("TOKEN", "from-store")]);
        let provider = from_provider();

        run_command(workspace.path(), &runtime, &provider)
            .await
            .expect("dev exec should run the command");

        assert_eq!(provider.calls(), 0);
        assert_eq!(runtime.store_reads().len(), 1);
        assert_eq!(runtime.execs()[0].3, vec![pair("TOKEN", "from-store")]);
    }

    /// Falling back runs the command again, so the only thing that may trigger
    /// it is the runtime saying it could not start the shell. A command of the
    /// user's that merely exits 127 has already run.
    #[test]
    fn a_command_that_ran_is_never_run_a_second_time() {
        use super::reports_missing_shell;

        let ran = |exit_code, stdout: &str, stderr: &str| ExecResult {
            exit_code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        };

        // The daemon's own announcement, on the stream it really uses.
        let announcement = "OCI runtime exec failed: exec failed: unable to start container \
                            process: exec: \"/bin/sh\": stat /bin/sh: no such file or directory";
        assert!(reports_missing_shell(&ran(127, announcement, "")));

        // The shell started and reported the miss itself.
        assert!(!reports_missing_shell(&ran(
            127,
            "",
            "dev-exec: 1: exec: definitely-not-a-command: not found"
        )));
        // A command of the user's that exits 127 for its own reasons.
        assert!(!reports_missing_shell(&ran(127, "", "usage: ...")));
        // A command that ran, said something, and only then failed — even if
        // what it said quotes the daemon.
        assert!(!reports_missing_shell(&ran(
            127,
            &format!("partial output\n{announcement}"),
            ""
        )));
        // The announcement naming some other missing executable is the
        // command's problem, not the wrapper's.
        assert!(!reports_missing_shell(&ran(
            127,
            "OCI runtime exec failed: exec failed: unable to start container process: \
             exec: \"cargo\": executable file not found in $PATH",
            ""
        )));
        assert!(!reports_missing_shell(&ran(0, "", "")));
    }
}
