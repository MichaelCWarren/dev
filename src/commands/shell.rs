use std::path::Path;

use crate::cmux::{Cmux, SESSION_PILL_STYLE, SHELL_KEY, StatusGuard};
use crate::commands::exec::resolve_exec_secrets;
use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::devcontainer::config::DevcontainerConfig;
use crate::devcontainer::secrets::{ProviderRegistry, SecretValue};
use crate::runtime::{
    ContainerInfo, ContainerRuntime, ContainerState, detect_runtime, resolve_remote_user,
};
use crate::session::{self, HostIdentity, SessionKind, SessionMarker};
use crate::util::{workspace_folder_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    shell: Option<&str>,
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    let registry = ProviderRegistry::with_builtins(workspace);
    let cmux = Cmux::detect(true);
    let exit_code = run_with_runtime(workspace, runtime.as_ref(), shell, &registry, &cmux).await?;

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
    cmux: &Cmux,
) -> anyhow::Result<i32> {
    let container = running_container(runtime, workspace).await?;

    // Resolve remoteUser and workspaceFolder from config or image metadata
    let loaded = load_workspace_config_or_warn(workspace, runtime.runtime_name());
    let config_path = loaded.as_ref().map(|(path, _)| path.as_path());
    let config = loaded.as_ref().map(|(_, config)| config);
    let config_user = config.and_then(|c| c.remote_user.as_deref());
    let pill_enabled =
        config.is_some_and(DevcontainerConfig::cmux_status_enabled) && cmux.available();
    let mut pill = cmux.guard(SHELL_KEY, pill_enabled);
    let user = resolve_remote_user(runtime, &container.image, config_user).await?;

    let shell_cmd = resolve_shell(runtime, &container.id, user.as_deref(), shell).await?;

    let workdir = resolve_workdir(config, workspace, user.as_deref())?;

    // Fresh every session, so a secret rotated since `dev up` reaches this shell
    // without a recreate. A compose container is not re-checked: `dev up`
    // rejects a compose project that declares secrets, and refusing a shell too
    // would leave a running container with no way in.
    let secrets = resolve_exec_secrets(config_path, workspace, config_user, registry).await?;

    sweep_orphans(runtime, &container.id, user.as_deref()).await;

    let host = session::host_identity().await;
    let pill_ctx =
        SessionPillContext::new(workspace, runtime, &container, user.as_deref(), host.pid);
    paint_session_pill(pill_enabled, &pill_ctx, true, &mut pill).await;
    let cmd = session_command(&shell_cmd, &workdir, &host);
    let exit_code = attend_session(
        runtime,
        &container.id,
        &cmd,
        user.as_deref(),
        &workdir,
        host.pid,
        &secrets,
    )
    .await;
    paint_session_pill(pill_enabled, &pill_ctx, false, &mut pill).await;
    exit_code
}

/// Where the shell starts: `workspaceFolder` resolved the same way `dev up`
/// resolves it, so a session lands where the lifecycle hooks ran.
fn resolve_workdir(
    config: Option<&DevcontainerConfig>,
    workspace: &Path,
    user: Option<&str>,
) -> anyhow::Result<String> {
    match config {
        Some(config) => Ok(config.workspace_folder_path(workspace, user)?),
        None => Ok(format!("/workspaces/{}", workspace_folder_name(workspace))),
    }
}

/// The pieces of a `dev shell` session that stay the same between painting
/// the pill on entry and again after `attend_session` returns.
struct SessionPillContext<'a> {
    workspace: &'a Path,
    runtime: &'a dyn ContainerRuntime,
    container: &'a ContainerInfo,
    user: Option<&'a str>,
    own_host_pid: u32,
}

impl<'a> SessionPillContext<'a> {
    fn new(
        workspace: &'a Path,
        runtime: &'a dyn ContainerRuntime,
        container: &'a ContainerInfo,
        user: Option<&'a str>,
        own_host_pid: u32,
    ) -> Self {
        Self {
            workspace,
            runtime,
            container,
            user,
            own_host_pid,
        }
    }
}

/// Recount live shells and update the pill: painted on entry (this session's
/// own marker not written yet) and again once `attend_session` returns
/// (this session's marker gone or going). `counting_self` is what tells the
/// two apart.
///
/// `enabled` is checked first, so a disabled pill never lists the session,
/// the same as before this feature existed. What each read means is
/// [`SessionPill`]'s to say.
async fn paint_session_pill(
    enabled: bool,
    ctx: &SessionPillContext<'_>,
    counting_self: bool,
    pill: &mut StatusGuard,
) {
    if !enabled {
        return;
    }
    let read = session::list_sessions(ctx.runtime, &ctx.container.id, ctx.user)
        .await
        .ok();
    match session_pill_action(
        read.as_deref(),
        ctx.own_host_pid,
        counting_self,
        &workspace_folder_name(ctx.workspace),
        ctx.runtime.runtime_name(),
    ) {
        SessionPill::Show(value) => pill.phase(&value, SESSION_PILL_STYLE),
        SessionPill::Clear => pill.clear(),
        SessionPill::Leave => {}
    }
    // The exit decision is carried out above, so the guard's `Drop` has
    // nothing left to do.
    if !counting_self {
        pill.disarm();
    }
}

/// What a read of the live session list tells a paint site to do.
///
/// The invariant every paint site shares: zero live shells is painted only
/// from evidence. A read that found none, and a workspace with no running
/// container, are both evidence of zero and clear the pill. A read that
/// failed is evidence of nothing, so the pill stays as it is and the next
/// read corrects it — a shell whose sibling's `docker exec` hiccuped keeps
/// its pill.
///
/// The second invariant, which `dev shell` is the only caller to need: a
/// session decides the pill's state at exactly two moments, entry and exit,
/// and each decision is carried out at the moment it is made. None is
/// deferred. The guard's `Drop` is the safety net for ending without ever
/// reaching the exit decision, and is never the mechanism for a decision that
/// was reached.
pub(crate) enum SessionPill {
    /// Paint this value.
    Show(String),
    /// Take the pill down.
    Clear,
    /// Leave whatever is up there alone.
    Leave,
}

/// Decide from one read of the session list: `None` is a read that failed.
///
/// Shared by both paint sites in this file and `dev status`'s repaint, so the
/// decision and the value's shape live in exactly one place.
pub(crate) fn session_pill_action(
    sessions: Option<&[(SessionMarker, bool)]>,
    own_host_pid: u32,
    counting_self: bool,
    workspace_name: &str,
    runtime_name: &str,
) -> SessionPill {
    let Some(sessions) = sessions else {
        return SessionPill::Leave;
    };
    let shells =
        session::count_other_live_shells(sessions, own_host_pid) + usize::from(counting_self);
    if shells == 0 {
        return SessionPill::Clear;
    }
    SessionPill::Show(pill_value(workspace_name, runtime_name, shells))
}

/// `<name> · <runtime>` for one shell, `<n> shells · <name> · <runtime>` for
/// more. The runtime stays in both forms so it does not vanish and reappear
/// as a second shell opens and closes.
fn pill_value(name: &str, runtime_name: &str, shells: usize) -> String {
    if shells > 1 {
        format!("{shells} shells · {name} · {runtime_name}")
    } else {
        format!("{name} · {runtime_name}")
    }
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
/// The Podman runtime runs `podman exec` as a child on a pty `dev` owns, so this
/// applies there too: dropping the future kills the podman client, and the
/// container-side exec it leaves behind is what the release by marker hangs up.
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
    use super::{
        HostIdentity, SessionPill, pill_value, run_with_runtime, session_command,
        session_pill_action, single_quoted,
    };
    use crate::cmux::Cmux;
    use crate::devcontainer::secrets::SecretValue;
    use crate::devcontainer::secrets::provider::{FakeProvider, PluginPath, ProviderRegistry};
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ContainerState,
        ExecResult, ImageMetadata,
    };
    use crate::util::{workspace_folder_name, workspace_labels};
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
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

    type ExecCall = (
        Vec<String>,
        Option<String>,
        Option<String>,
        Vec<(String, String)>,
    );

    struct ShellFakeRuntime {
        containers: Vec<ContainerInfo>,
        sessions: Arc<Mutex<Vec<SessionCall>>>,
        execs: Arc<Mutex<Vec<ExecCall>>>,
        /// Stdout `dev`'s own session-bookkeeping execs (the sweep's and the
        /// release's reads) receive, standing in for the live session list a
        /// real container would report. `None` keeps the default of no other
        /// session, which every existing test relies on.
        machinery_reply: Option<String>,
        /// Session reads fail once the interactive session has run, standing
        /// in for a daemon that hiccups while a shell is on its way out.
        machinery_fails_after_session: bool,
        /// The same hiccup, but before the session runs, so the entry paint
        /// reads nothing and the exit paint reads cleanly.
        machinery_fails_before_session: bool,
        session_started: Arc<AtomicBool>,
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
                execs: Arc::new(Mutex::new(Vec::new())),
                machinery_reply: None,
                machinery_fails_after_session: false,
                machinery_fails_before_session: false,
                session_started: Arc::new(AtomicBool::new(false)),
            }
        }

        fn answering_machinery_with(mut self, reply: &str) -> Self {
            self.machinery_reply = Some(reply.to_string());
            self
        }

        fn failing_machinery_after_the_session(mut self) -> Self {
            self.machinery_fails_after_session = true;
            self
        }

        fn failing_machinery_before_the_session(mut self) -> Self {
            self.machinery_fails_before_session = true;
            self
        }

        fn sessions(&self) -> Vec<SessionCall> {
            self.sessions.lock().unwrap().clone()
        }

        /// `dev`'s own bookkeeping execs: the sweep's and the release's reads,
        /// which must never be mistaken for a command the user asked for.
        fn session_execs(&self) -> Vec<ExecCall> {
            self.execs
                .lock()
                .unwrap()
                .iter()
                .filter(|(cmd, ..)| crate::session::is_session_machinery(cmd))
                .cloned()
                .collect()
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

        /// Answers the shell probe with status 0. Session-bookkeeping execs
        /// (the sweep's and the release's reads) get `machinery_reply`, so a
        /// test can stand in a sibling shell's marker without a real
        /// container; everything else gets no output, same as before this
        /// field existed.
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
                env.iter()
                    .map(|(key, value)| (key.clone(), value.expose().to_string()))
                    .collect(),
            ));
            let machinery = crate::session::is_session_machinery(cmd);
            let started = self.session_started.load(Ordering::SeqCst);
            if machinery
                && ((self.machinery_fails_after_session && started)
                    || (self.machinery_fails_before_session && !started))
            {
                return Box::pin(async { Err(DevError::Runtime("session read failed".into())) });
            }
            let stdout = if machinery {
                self.machinery_reply.clone().unwrap_or_default()
            } else {
                String::new()
            };
            Box::pin(async move {
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
            cmd: &[String],
            user: Option<&str>,
            workdir: Option<&str>,
            env: &[(String, SecretValue)],
        ) -> BoxFut<'_, i32> {
            self.session_started.store(true, Ordering::SeqCst);
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

    /// A workspace with the session pill turned on: `"cmux": {"status": true}`
    /// beside the fixture image `workspace_with` writes.
    fn workspace_with_pill_enabled() -> (TempDir, std::path::PathBuf) {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).unwrap();
        let config_path = devcontainer_dir.join("devcontainer.json");
        std::fs::write(
            &config_path,
            r#"{"image": "ubuntu:24.04", "cmux": {"status": true}}"#,
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
            &Cmux::recording().0,
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
            &Cmux::recording().0,
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
            &Cmux::recording().0,
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
            &Cmux::recording().0,
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
            &Cmux::recording().0,
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
            run_with_runtime(
                workspace.path(),
                &runtime,
                None,
                &registry,
                &Cmux::recording().0,
            )
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

    /// The runtime stays in both forms so it never vanishes and reappears as
    /// a second shell opens and closes; the count only shows once there is
    /// more than one to distinguish from a lone shell.
    #[test]
    fn pill_value_shows_a_count_only_above_one_shell() {
        assert_eq!(pill_value("myproject", "docker", 1), "myproject · docker");
        assert_eq!(
            pill_value("myproject", "docker", 3),
            "3 shells · myproject · docker"
        );
    }

    /// A config without the `cmux` key must cost nothing beyond what `dev
    /// shell` already does: no call into the handle, and no more session
    /// reads than the sweep's and the release's.
    #[tokio::test]
    async fn a_disabled_gate_makes_no_cmux_call_and_reads_no_extra_sessions() {
        let (workspace, config_path) = workspace_with(None);
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);
        let (cmux, recorder) = Cmux::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), FakeProvider::recording()),
            &cmux,
        )
        .await
        .expect("dev shell should open a session");

        assert!(recorder.calls().is_empty());
        assert_eq!(runtime.session_execs().len(), 2);
    }

    /// With nothing else running, the pill appears on entry and disappears on
    /// exit through the guard's own `Drop` — `paint_session_pill` makes no
    /// explicit clear call itself.
    #[tokio::test]
    async fn one_shell_paints_on_entry_and_clears_on_exit() {
        let (workspace, config_path) = workspace_with_pill_enabled();
        let name = workspace_folder_name(workspace.path());
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path);
        let (cmux, recorder) = Cmux::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), FakeProvider::recording()),
            &cmux,
        )
        .await
        .expect("dev shell should open a session");

        assert_eq!(
            recorder.calls(),
            vec![
                vec![
                    "set-status".to_string(),
                    "dev_shell".to_string(),
                    format!("{name} · docker"),
                    "--icon".to_string(),
                    "terminal".to_string(),
                    "--color".to_string(),
                    "#3B82F6".to_string(),
                ],
                vec!["clear-status".to_string(), "dev_shell".to_string()],
            ]
        );
    }

    /// A live sibling shell, owned by `host_pid`.
    fn live_shell(host_pid: u32) -> (crate::session::SessionMarker, bool) {
        (
            crate::session::SessionMarker {
                container_pid: 720,
                container_sid: 720,
                host_pid,
                host_start: "-".to_string(),
                kind: crate::session::SessionKind::Shell,
                host_tty: "ttys001".to_string(),
            },
            true,
        )
    }

    /// The half of the invariant that costs a live shell its pill when it is
    /// broken: a read that failed says nothing about how many shells are
    /// open, so nothing may be painted from it.
    #[test]
    fn a_failed_read_paints_nothing() {
        assert!(matches!(
            session_pill_action(None, 4131, false, "myproject", "docker"),
            SessionPill::Leave
        ));
        assert!(matches!(
            session_pill_action(None, 4131, true, "myproject", "docker"),
            SessionPill::Leave
        ));
    }

    /// The other half: a read that succeeded and found no live shell is
    /// evidence of zero, and takes the pill down.
    #[test]
    fn a_read_that_found_no_shell_clears() {
        assert!(matches!(
            session_pill_action(Some(&[]), 4131, false, "myproject", "docker"),
            SessionPill::Clear
        ));
        assert!(matches!(
            session_pill_action(
                Some(&[live_shell(4131)]),
                4131,
                false,
                "myproject",
                "docker"
            ),
            SessionPill::Clear
        ));
    }

    #[test]
    fn a_read_that_found_shells_paints_their_count() {
        let entering = session_pill_action(Some(&[]), 4131, true, "myproject", "docker");
        assert!(matches!(entering, SessionPill::Show(value) if value == "myproject · docker"));

        let two = session_pill_action(Some(&[live_shell(5000)]), 4131, true, "myproject", "docker");
        assert!(
            matches!(two, SessionPill::Show(value) if value == "2 shells · myproject · docker")
        );
    }

    /// The exit read failing is not evidence that this was the last shell, so
    /// the pill stays up for the next read to correct. Were it cleared here,
    /// a sibling shell would lose its pill to this one's daemon hiccup.
    #[tokio::test]
    async fn a_failed_exit_read_leaves_the_pill_up() {
        let (workspace, config_path) = workspace_with_pill_enabled();
        let name = workspace_folder_name(workspace.path());
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path)
            .failing_machinery_after_the_session();
        let (cmux, recorder) = Cmux::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), FakeProvider::recording()),
            &cmux,
        )
        .await
        .expect("dev shell should open a session");

        assert_eq!(
            recorder.calls(),
            vec![vec![
                "set-status".to_string(),
                "dev_shell".to_string(),
                format!("{name} · docker"),
                "--icon".to_string(),
                "terminal".to_string(),
                "--color".to_string(),
                "#3B82F6".to_string(),
            ]]
        );
    }

    /// An entry read that failed paints nothing, so the guard is never armed;
    /// the exit read then finding no shell must still take the pill down. The
    /// exit decision is the session's last word on the key, and leaving it to
    /// the guard's `Drop` strands the pill of the shell that wrote it.
    #[tokio::test]
    async fn an_unpainted_entry_still_clears_when_the_exit_read_finds_no_shell() {
        let (workspace, config_path) = workspace_with_pill_enabled();
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path)
            .failing_machinery_before_the_session();
        let (cmux, recorder) = Cmux::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), FakeProvider::recording()),
            &cmux,
        )
        .await
        .expect("dev shell should open a session");

        assert_eq!(
            recorder.calls(),
            vec![vec!["clear-status".to_string(), "dev_shell".to_string()]]
        );
    }

    /// A sibling's marker keeps the pill counting rather than clearing it,
    /// which is what lets the first of two shells to exit fall back to the
    /// other's count instead of blanking the sidebar.
    #[tokio::test]
    async fn a_sibling_shell_keeps_the_pill_and_recounts_on_exit() {
        let (workspace, config_path) = workspace_with_pill_enabled();
        let name = workspace_folder_name(workspace.path());
        let ppid = std::os::unix::process::parent_id();
        let runtime = ShellFakeRuntime::running_for(workspace.path(), &config_path)
            .answering_machinery_with(&format!("720 720 {ppid} - shell ttys001"));
        let (cmux, recorder) = Cmux::recording();

        run_with_runtime(
            workspace.path(),
            &runtime,
            None,
            &registry_with(workspace.path(), FakeProvider::recording()),
            &cmux,
        )
        .await
        .expect("dev shell should open a session");

        assert_eq!(
            recorder.calls(),
            vec![
                vec![
                    "set-status".to_string(),
                    "dev_shell".to_string(),
                    format!("2 shells · {name} · docker"),
                    "--icon".to_string(),
                    "terminal".to_string(),
                    "--color".to_string(),
                    "#3B82F6".to_string(),
                ],
                vec![
                    "set-status".to_string(),
                    "dev_shell".to_string(),
                    format!("{name} · docker"),
                    "--icon".to_string(),
                    "terminal".to_string(),
                    "--color".to_string(),
                    "#3B82F6".to_string(),
                ],
            ]
        );
    }
}
