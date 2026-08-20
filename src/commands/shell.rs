use std::path::Path;

use crate::commands::exec::resolve_exec_secrets;
use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::devcontainer::secrets::{ProviderRegistry, SecretValue};
use crate::runtime::{
    ContainerInfo, ContainerRuntime, ContainerState, detect_runtime, resolve_remote_user,
};
use crate::session::{self, HostIdentity, SessionKind};
use crate::util::{workspace_folder_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    shell: Option<&str>,
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    let registry = ProviderRegistry::with_builtins(workspace);
    let exit_code = run_with_runtime(workspace, runtime.as_ref(), shell, &registry).await?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    shell: Option<&str>,
    registry: &ProviderRegistry,
) -> anyhow::Result<i32> {
    let container = running_container(runtime, workspace).await?;

    // Resolve remoteUser and workspaceFolder from config or image metadata
    let loaded = load_workspace_config_or_warn(workspace, runtime.runtime_name());
    let config_path = loaded.as_ref().map(|(path, _)| path.as_path());
    let config = loaded.as_ref().map(|(_, config)| config);
    let config_user = config.and_then(|c| c.remote_user.as_deref());
    let user = resolve_remote_user(runtime, &container.image, config_user).await?;

    let shell_cmd = resolve_shell(runtime, &container.id, user.as_deref(), shell).await?;

    // Resolve workspaceFolder the same way `dev up` does, so the shell starts
    // where lifecycle hooks ran.
    let workdir = match config {
        Some(config) => config.workspace_folder_path(workspace, user.as_deref())?,
        None => format!("/workspaces/{}", workspace_folder_name(workspace)),
    };

    // Fresh every session, so a secret rotated since `dev up` reaches this shell
    // without a recreate. A compose container is not re-checked: `dev up`
    // rejects a compose project that declares secrets, and refusing a shell too
    // would leave a running container with no way in.
    let secrets = resolve_exec_secrets(config_path, workspace, config_user, registry).await?;

    sweep_orphans(runtime, &container.id, user.as_deref()).await;

    let host = session::host_identity().await;
    let cmd = session_command(&shell_cmd, &workdir, &host);
    attend_session(
        runtime,
        &container.id,
        &cmd,
        user.as_deref(),
        &workdir,
        host.pid,
        &secrets,
    )
    .await
}

/// Before starting one more, collect the sessions whose clients are gone: this
/// is the moment the user is about to look at the container anyway, and an
/// orphaned `claude` burns a core until something ends it.
async fn sweep_orphans(runtime: &dyn ContainerRuntime, container_id: &str, user: Option<&str>) {
    match session::sweep(runtime, container_id, user).await {
        Ok(0) => {}
        Ok(reaped) => eprintln!("dev: reaped {reaped} orphaned container session(s)"),
        Err(e) => eprintln!("Warning: could not check for orphaned sessions: {e}"),
    }
}

/// This workspace's running container, or the advice to start one.
async fn running_container(
    runtime: &dyn ContainerRuntime,
    workspace: &Path,
) -> anyhow::Result<ContainerInfo> {
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    runtime
        .list_containers(&filters)
        .await?
        .into_iter()
        .find(|c| c.state == ContainerState::Running)
        .ok_or_else(|| {
            anyhow::anyhow!("No running container found for this workspace. Run `dev up` first.")
        })
}

/// The shell to open: the one `--shell` named, else the best of the usual three
/// the image actually has.
///
/// The probes carry no env. Asking whether `/bin/zsh` exists needs no secret,
/// and a provider prompt per candidate would be absurd.
async fn resolve_shell(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    shell: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(shell) = shell {
        return Ok(shell.to_string());
    }
    for candidate in ["/bin/zsh", "/bin/bash", "/bin/sh"] {
        let probe = vec!["test".to_string(), "-x".to_string(), candidate.to_string()];
        let result = runtime.exec(container_id, &probe, user, None, &[]).await?;
        if result.exit_code == 0 {
            return Ok(candidate.to_string());
        }
    }
    Ok("/bin/sh".to_string())
}

/// The command the container runs for an interactive session.
///
/// It records the session before entering the workspace so that a client dying
/// early still leaves something to collect, and `exec`s the login shell so the
/// user's shell is the process, not a child of a wrapper.
fn session_command(shell_cmd: &str, workdir: &str, host: &HostIdentity) -> Vec<String> {
    let quoted_workdir = single_quoted(workdir);
    let quoted_shell = single_quoted(shell_cmd);
    let register = session::register_script(SessionKind::Shell, host);
    vec![
        shell_cmd.to_string(),
        "-c".to_string(),
        format!(
            "{register}cd {quoted_workdir} || \
             {{ printf 'dev: could not enter %s\\n' {quoted_workdir} >&2; exit 1; }}; \
             exec {quoted_shell} -l"
        ),
    ]
}

/// Run the session, and end it if this process is told to go away first.
///
/// An exec carries no disconnect: were `dev` to exit on a signal without saying
/// anything, the daemon would keep the pty open and the container's shell —
/// with whatever it is running — would survive with nothing left to read it.
/// Dropping the interactive future restores the terminal, and the container
/// side is then hung up explicitly.
///
/// The Podman runtime replaces this process with `podman exec`, so none of this
/// runs there; its orphans are collected by the sweep instead.
async fn attend_session(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    cmd: &[String],
    user: Option<&str>,
    workdir: &str,
    host_pid: u32,
    secrets: &[(String, SecretValue)],
) -> anyhow::Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};

    let watch = |kind: SignalKind, name: &str| {
        signal(kind).map_err(|e| anyhow::anyhow!("watch {name}: {e}"))
    };
    let mut hangup = watch(SignalKind::hangup(), "SIGHUP")?;
    let mut terminate = watch(SignalKind::terminate(), "SIGTERM")?;
    let mut interrupt = watch(SignalKind::interrupt(), "SIGINT")?;

    let mut exec = runtime.exec_interactive(container_id, cmd, user, Some(workdir), secrets);
    let signalled = tokio::select! {
        // A session that ended on its own has nothing left to hang up, but its
        // record outlives it: the login shell `exec`s, so nothing of `dev`'s is
        // left in the container to clear it. Doing that here rather than
        // leaving it for the next read keeps a closed shell from showing up as
        // an abandoned one in the meantime.
        exited = &mut exec => {
            let code = exited?;
            session::release_own_sessions(runtime, container_id, user, host_pid).await;
            return Ok(code);
        }
        // Closing the terminal is the common case, and the one that leaves no
        // other trace: the tty's foreground group is hung up, `dev` included.
        _ = hangup.recv() => libc::SIGHUP,
        _ = terminate.recv() => libc::SIGTERM,
        // A raw terminal delivers Ctrl-C to the container as a byte, so this is
        // only ever an explicit signal — which must still end the session.
        _ = interrupt.recv() => libc::SIGINT,
    };

    drop(exec);
    session::release_own_sessions(runtime, container_id, user, host_pid).await;
    // The status a shell reports for a signalled process.
    Ok(128 + signalled)
}

/// Wrap a value the caller supplied so the guest's shell reads it as one word.
///
/// Both values interpolated into the `-c` script come from outside this
/// process: the working directory is resolved from `workspaceFolder` or from
/// the `target=` segment of `workspaceMount`, and the shell can be named
/// outright with `--shell`. A path holding a space would otherwise be split
/// (`cd /workspaces/My Projects/repo` enters `/workspaces/My`), and one holding
/// `;` or a backtick would run as a command. Single quotes suppress every
/// expansion the shell performs, so only the quote itself needs escaping — by
/// closing the run, emitting a literal quote, and reopening.
fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::{HostIdentity, run_with_runtime, session_command, single_quoted};
    use crate::devcontainer::secrets::SecretValue;
    use crate::devcontainer::secrets::provider::{FakeProvider, PluginPath, ProviderRegistry};
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ContainerState,
        ExecResult, ImageMetadata,
    };
    use crate::util::workspace_labels;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("unused fake runtime method".into())) })
    }

    type SessionCall = (
        Vec<String>,
        Option<String>,
        Option<String>,
        Vec<(String, String)>,
    );

    struct ShellFakeRuntime {
        containers: Vec<ContainerInfo>,
        sessions: Arc<Mutex<Vec<SessionCall>>>,
    }

    impl ShellFakeRuntime {
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
                sessions: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sessions(&self) -> Vec<SessionCall> {
            self.sessions.lock().unwrap().clone()
        }
    }

    impl ContainerRuntime for ShellFakeRuntime {
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

        /// Answers the shell probe and the sweep, both of which want status 0
        /// and no output.
        fn exec(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
            _workdir: Option<&str>,
            _env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            Box::pin(async {
                Ok(ExecResult {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }

        fn exec_interactive(
            &self,
            _id: &str,
            cmd: &[String],
            user: Option<&str>,
            workdir: Option<&str>,
            env: &[(String, SecretValue)],
        ) -> BoxFut<'_, i32> {
            self.sessions.lock().unwrap().push((
                cmd.to_vec(),
                user.map(str::to_string),
                workdir.map(str::to_string),
                // Exposing inside a test double is the only way to prove the
                // value arrived. Production code never does this.
                env.iter()
                    .map(|(key, value)| (key.clone(), value.expose().to_string()))
                    .collect(),
            ));
            Box::pin(async { Ok(0) })
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

    /// A workspace with a `.devcontainer/devcontainer.json`, and a
    /// `secrets.json` beside it when one is given.
    fn workspace_with(secrets: Option<&str>) -> (TempDir, std::path::PathBuf) {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).unwrap();
        let config_path = devcontainer_dir.join("devcontainer.json");
        std::fs::write(&config_path, r#"{"image": "ubuntu:24.04"}"#).unwrap();
        if let Some(secrets) = secrets {
            std::fs::write(devcontainer_dir.join("secrets.json"), secrets).unwrap();
        }
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

    const ONE_SECRET: &str = r#"{"version":1,"secrets":{"TOKEN":"fake://token"}}"#;
    const VALUE: &str = "hunter2-DO-NOT-INTERPOLATE";

    fn answers() -> FakeProvider {
        FakeProvider::answering(&[("TOKEN", VALUE)])
    }

    /// The point of the command: the shell the user lands in holds values
    /// fetched now, not whatever was baked in when the container was created.
    #[tokio::test]
    async fn a_session_carries_the_resolved_secrets_in_its_own_env() {
        let (workspace, config_path) = workspace_with(Some(ONE_SECRET));
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), answers()),
        )
        .await
        .expect("dev shell should open a session");

        assert_eq!(
            runtime.sessions()[0].3,
            vec![("TOKEN".to_string(), VALUE.to_string())]
        );
    }

    /// The `-c` script is assembled with `format!`, so a value that reached it
    /// would be one more string to quote and would sit in the container's
    /// process table for the life of the session. Values travel as env instead.
    #[tokio::test]
    async fn no_secret_value_reaches_the_shell_script() {
        let (workspace, config_path) = workspace_with(Some(ONE_SECRET));
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), answers()),
        )
        .await
        .expect("dev shell should open a session");

        let cmd = &runtime.sessions()[0].0;
        for word in cmd {
            assert!(!word.contains(VALUE), "{word}");
        }
        assert!(cmd[2].ends_with("exec '/bin/zsh' -l"));
    }

    #[tokio::test]
    async fn a_workspace_without_secrets_calls_no_provider() {
        let (workspace, config_path) = workspace_with(None);
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);
        let provider = FakeProvider::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), provider.clone()),
        )
        .await
        .expect("dev shell should open a session");

        assert!(runtime.sessions()[0].3.is_empty());
        assert_eq!(provider.calls(), 0);
    }

    /// A shell that silently lacks its secrets is worse than no shell.
    /// `optional: true` is the escape hatch, and the error names the key.
    #[tokio::test]
    async fn a_failed_secret_ends_the_session_before_it_starts() {
        let (workspace, config_path) = workspace_with(Some(ONE_SECRET));
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);

        let err = run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), FakeProvider::failing_for("TOKEN")),
        )
        .await
        .expect_err("a required secret that cannot resolve fails the command");

        assert!(err.to_string().contains("TOKEN"), "{err}");
        assert!(runtime.sessions().is_empty());
    }

    /// `createTime` governs the `dev up` create path only, so an exec-time-only
    /// secret still reaches the session.
    #[tokio::test]
    async fn create_time_false_still_reaches_the_session() {
        let (workspace, config_path) = workspace_with(Some(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"fake","ref":"token","createTime":false}}}"#,
        ));
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), answers()),
        )
        .await
        .expect("dev shell should open a session");

        assert_eq!(
            runtime.sessions()[0].3,
            vec![("TOKEN".to_string(), VALUE.to_string())]
        );
    }

    /// Dev builds no cache, which is what makes a rotated secret current in the
    /// next shell.
    #[tokio::test]
    async fn each_session_resolves_again() {
        let (workspace, config_path) = workspace_with(Some(ONE_SECRET));
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);
        let provider = answers();
        let registry = registry_with(workspace.path(), provider.clone());

        for _ in 0..2 {
            run_with_runtime(workspace.path(), &runtime, None, &registry)
                .await
                .expect("dev shell should open a session");
        }

        assert_eq!(provider.calls(), 2);
    }

    fn host() -> HostIdentity {
        HostIdentity {
            pid: 4131,
            start: "Tue Aug  5 08:56:01 2026".to_string(),
            tty: "ttys016".to_string(),
        }
    }

    /// A session that dies before it is recorded is a session nothing can
    /// collect, so the record is written before anything that can fail — the
    /// `cd` included.
    #[test]
    fn a_session_records_itself_before_it_can_fail() {
        let script = &session_command("/bin/zsh", "/workspaces/repo", &host())[2];
        let recorded = script.find("/tmp/.dev-session-").expect("marker written");
        let entered = script
            .find("cd '/workspaces/repo'")
            .expect("workdir entered");
        assert!(recorded < entered);
        assert!(script.ends_with("exec '/bin/zsh' -l"));
    }

    /// Registration prefixes the same script the workdir is interpolated into,
    /// so it must not become a way around the quoting.
    #[test]
    fn registration_does_not_loosen_the_workdir_quoting() {
        let script = &session_command("/bin/zsh", "/tmp; rm -rf /", &host())[2];
        assert!(script.contains("cd '/tmp; rm -rf /'"));
    }

    #[test]
    fn a_quoted_value_survives_the_guest_shell_as_one_word() {
        assert_eq!(single_quoted("/workspaces/repo"), "'/workspaces/repo'");
        assert_eq!(
            single_quoted("/workspaces/My Projects/repo"),
            "'/workspaces/My Projects/repo'"
        );
    }

    /// The shell script this builds is the only place a `workspaceFolder` or a
    /// `--shell` value reaches a command line, so metacharacters must arrive as
    /// text rather than as syntax.
    #[test]
    fn quoting_leaves_no_metacharacter_live() {
        for hostile in [
            "/tmp; rm -rf /",
            "/tmp && whoami",
            "/tmp`id`",
            "/tmp$(id)",
            "/tmp\nid",
            "/tmp|id",
        ] {
            let quoted = single_quoted(hostile);
            assert_eq!(quoted, format!("'{hostile}'"));
        }

        // A quote of its own is the one character single quotes cannot carry,
        // so the run is closed, the quote emitted literally, and the run
        // reopened — never leaving the quoted state.
        assert_eq!(single_quoted("/tmp/it's"), r"'/tmp/it'\''s'");
        assert_eq!(single_quoted("';id;'"), r"''\'';id;'\'''");
    }
}
