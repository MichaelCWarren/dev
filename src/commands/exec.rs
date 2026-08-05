use std::path::Path;

use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::error::DevError;
use crate::runtime::{
    ContainerRuntime, ContainerState, ExecResult, detect_runtime, resolve_remote_user,
};
use crate::session::{self, SessionKind};
use crate::util::{workspace_folder_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    user: Option<&str>,
    cmd: &[String],
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    run_with_runtime(workspace, runtime.as_ref(), user, cmd).await
}

pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn crate::runtime::ContainerRuntime,
    user: Option<&str>,
    cmd: &[String],
) -> anyhow::Result<()> {
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let containers = runtime.list_containers(&filters).await?;

    let container = containers
        .iter()
        .find(|c| c.state == ContainerState::Running)
        .ok_or_else(|| {
            anyhow::anyhow!("No running container found for this workspace. Run `dev up` first.")
        })?;

    // Use explicit --user flag, falling back to remoteUser from config or image metadata
    let config =
        load_workspace_config_or_warn(workspace, runtime.runtime_name()).map(|(_, config)| config);

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

    let host = session::host_identity().await;
    let outcome =
        attend_command(runtime, &container.id, cmd, effective_user, &workdir, &host).await?;

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
) -> anyhow::Result<Outcome> {
    use tokio::signal::unix::{SignalKind, signal};

    let watch = |kind: SignalKind, name: &str| {
        signal(kind).map_err(|e| anyhow::anyhow!("watch {name}: {e}"))
    };
    let mut interrupt = watch(SignalKind::interrupt(), "SIGINT")?;
    let mut terminate = watch(SignalKind::terminate(), "SIGTERM")?;
    let mut hangup = watch(SignalKind::hangup(), "SIGHUP")?;

    let mut running = Box::pin(run_recorded(
        runtime,
        container_id,
        cmd,
        user,
        workdir,
        host,
    ));
    let signalled = tokio::select! {
        finished = &mut running => return Ok(Outcome::Finished(finished?)),
        _ = interrupt.recv() => libc::SIGINT,
        _ = terminate.recv() => libc::SIGTERM,
        _ = hangup.recv() => libc::SIGHUP,
    };

    drop(running);
    session::release_own_sessions(runtime, container_id, user, host.pid).await;
    Ok(Outcome::Signalled(signalled))
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
) -> Result<ExecResult, DevError> {
    let recorded = session::registered_command(cmd, SessionKind::Exec, host);
    match runtime
        .exec(container_id, &recorded, user, Some(workdir))
        .await
    {
        Err(e) if runtime.exec_reports_missing_command(&e) => {
            runtime.exec(container_id, cmd, user, Some(workdir)).await
        }
        Ok(result) if reports_missing_shell(&result) => {
            runtime.exec(container_id, cmd, user, Some(workdir)).await
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
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ContainerState,
        ExecResult, ImageMetadata,
    };
    use crate::util::workspace_labels;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("unused fake runtime method".into())) })
    }

    type ExecCall = (Vec<String>, Option<String>, Option<String>);

    struct ExecFakeRuntime {
        containers: Vec<ContainerInfo>,
        execs: Arc<Mutex<Vec<ExecCall>>>,
        /// Stands in for an image with no `/bin/sh`.
        without_a_shell: bool,
        /// Which of the two shapes that takes: an API error, or an accepted
        /// exec reporting the start failure as status 127.
        shell_missing_as_status: bool,
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
            }
        }

        fn without_a_shell(mut self) -> Self {
            self.without_a_shell = true;
            self
        }

        fn reporting_that_as_a_status(mut self) -> Self {
            self.shell_missing_as_status = true;
            self
        }

        fn execs(&self) -> Vec<ExecCall> {
            self.execs.lock().unwrap().clone()
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
        ) -> BoxFut<'_, ExecResult> {
            self.execs.lock().unwrap().push((
                cmd.to_vec(),
                user.map(str::to_string),
                workdir.map(str::to_string),
            ));
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

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[tokio::test]
    async fn one_off_exec_runs_in_the_resolved_workspace_folder() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(workspace.path(), &runtime, None, &words(&["cargo", "test"]))
            .await
            .expect("dev exec should run the command");

        let execs = runtime.execs();
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].2.as_deref(), Some("/srv/app/packages/api"));
    }

    /// The command is recorded so that a `dev exec` whose client dies can be
    /// found and ended, rather than running on in the container forever.
    #[tokio::test]
    async fn a_one_off_command_records_itself_before_becoming_the_command() {
        let (workspace, config_path) = workspace_with_config();
        let runtime = ExecFakeRuntime::running_for(workspace.path(), &config_path);

        run_with_runtime(workspace.path(), &runtime, None, &words(&["cargo", "test"]))
            .await
            .expect("dev exec should run the command");

        let cmd = &runtime.execs()[0].0;
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("/tmp/.dev-session-$$"));
        assert!(cmd[2].contains("'exec'"), "recorded as an exec session");
        // `exec` so the recorded pid stays the command's own, and the status,
        // signals and streams remain the command's.
        assert!(cmd[2].ends_with(r#"exec "$@""#));
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

        run_with_runtime(workspace.path(), &runtime, None, &hostile)
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

        run_with_runtime(workspace.path(), &runtime, None, &words(&["cargo", "test"]))
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

        run_with_runtime(workspace.path(), &runtime, None, &words(&["cargo", "test"]))
            .await
            .expect("dev exec should fall back to the bare command");

        let execs = runtime.execs();
        assert_eq!(execs.len(), 2);
        assert_eq!(execs[1].0, words(&["cargo", "test"]));
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
