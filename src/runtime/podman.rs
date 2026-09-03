use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};

use crate::devcontainer::secrets::SecretValue;
use crate::error::DevError;
use crate::runtime::docker::{BollardRuntime, EXEC_STATUS_BUDGET};
use crate::runtime::terminal_relay::{
    HostTerminal, Pty, PtyMaster, RawModeGuard, SessionPeer, StdinReader, UnitFut,
    drain_remaining_output, relay_terminal,
};
use crate::runtime::{
    AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ExecResult, ImageInfo,
    ImageMetadata, terminal_size,
};

/// Podman runtime backed by the same bollard client, connecting to the Podman socket.
pub struct PodmanRuntime(pub(crate) BollardRuntime);

impl PodmanRuntime {
    pub fn connect() -> Result<Self, DevError> {
        let socket = podman_socket_path()?;
        Ok(Self(BollardRuntime::connect_to_socket(&socket)?))
    }

    pub async fn ping(&self) -> Result<(), DevError> {
        self.0.ping().await
    }
}

fn podman_socket_path() -> Result<String, DevError> {
    // Prefer $XDG_RUNTIME_DIR/podman/podman.sock, fall back to common locations.
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let path = format!("{xdg}/podman/podman.sock");
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    // macOS via Homebrew podman machine
    if cfg!(target_os = "macos")
        && let Ok(home) = std::env::var("HOME")
    {
        let path = format!("{home}/.local/share/containers/podman/machine/podman.sock");
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    // Linux fallback
    let uid_path = format!("/run/user/{}/podman/podman.sock", unsafe { libc::getuid() });
    if std::path::Path::new(&uid_path).exists() {
        return Ok(uid_path);
    }

    Err(DevError::Runtime(
        "Could not find Podman socket".to_string(),
    ))
}

/// `env` carries names only, never `NAME=value`. `podman exec -e NAME` reads the
/// value out of the podman client's own environment, so a secret reaches the
/// container without ever appearing in argv. That matters because
/// `/proc/<pid>/cmdline` is world readable while `/proc/<pid>/environ` is not:
/// an assignment on the command line is legible to every user on the host, not
/// only to the one running `dev`.
fn podman_exec_args(
    id: &str,
    cmd: &[String],
    user: Option<&str>,
    workdir: Option<&str>,
    env: &[String],
) -> Vec<String> {
    let mut args = vec!["exec".to_string(), "-it".to_string()];
    if let Some(u) = user {
        args.push("--user".to_string());
        args.push(u.to_string());
    }
    if let Some(dir) = workdir {
        args.push("--workdir".to_string());
        args.push(dir.to_string());
    }
    for name in env {
        args.push("-e".to_string());
        args.push(name.clone());
    }
    args.push(id.to_string());
    args.extend(cmd.iter().cloned());
    args
}

impl PodmanRuntime {
    /// Runs `podman exec -it` as a child of `dev` on a pty `dev` owns, and
    /// relays the user's terminal against it the same way every other
    /// runtime's interactive session does.
    async fn exec_interactive_impl(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
        env: &[(String, String)],
    ) -> Result<i32, DevError> {
        let names: Vec<String> = env.iter().map(|(key, _)| key.clone()).collect();
        let args = podman_exec_args(id, cmd, user, workdir, &names);

        let mut pty = Pty::open()?;
        if let Some((cols, rows)) = terminal_size() {
            pty.resize(cols, rows)?;
        }

        // Raw mode goes on before the spawn so no keystroke reaches the child
        // cooked; it is a local here so it restores on every exit path.
        let _raw_guard = RawModeGuard::enter()?;

        let slave = pty
            .take_slave()
            .expect("a freshly opened Pty always holds its slave");
        // The `-e NAME` flags read their values out of the podman client's own
        // environment, not out of argv: `spawn_on_slave` puts them there via
        // `Command::envs`.
        let child = spawn_on_slave("podman", &args, env.to_vec(), &slave)
            .map_err(|e| DevError::Runtime(format!("Failed to exec into container: {e}")))?;
        drop(slave);

        let peer = PodmanSessionPeer {
            bollard: &self.0,
            container: id.to_string(),
            user: user.map(str::to_string),
            master: pty.master(),
        };

        let mut stdin = StdinReader::spawn()?;
        let host = HostTerminal::for_process(stdin.chunks())?;

        run_session(host, pty, child, peer).await

        // _raw_guard is dropped here, restoring the terminal.
    }
}

/// Spawns `program` with its three stdio fds set to clones of `slave`, making
/// it a session leader with the slave as its controlling terminal before
/// `exec`. `-it` on podman's own argv depends on this: podman checks `isatty`
/// on its stdin before raw-moding it and allocating the container-side tty,
/// and a pipe would fail that check.
fn spawn_on_slave(
    program: &str,
    args: &[String],
    env: Vec<(String, String)>,
    slave: &OwnedFd,
) -> std::io::Result<Child> {
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(env)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?))
        .kill_on_drop(true);
    // Safe: the closure captures nothing, so `FnMut + Send + Sync + 'static`
    // holds trivially. `setsid` and the `TIOCSCTTY` ioctl are both
    // async-signal-safe, and by the time this closure runs, std has already
    // `dup2`'d the slave onto fd 0, so making this forked, not-yet-`exec`'d
    // child a session leader gives it that slave as its controlling terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// Which side of the session ended first.
enum SessionEnd {
    /// Host stdin EOF, master EOF, or a write error.
    Relay,
    Child(std::process::ExitStatus),
}

/// Runs the relay against the child's own exit, then settles on an exit code
/// either way. Split out of `exec_interactive_impl` to keep that under the
/// project's line limit for a function.
async fn run_session(
    mut host: HostTerminal<'_, tokio::io::Stdout>,
    pty: Pty,
    mut child: Child,
    peer: PodmanSessionPeer<'_>,
) -> Result<i32, DevError> {
    let input = pty.master();
    let output = pty.master();

    let end = tokio::select! {
        result = relay_terminal(&mut host, input, output, &peer) => {
            result?;
            SessionEnd::Relay
        }
        status = child.wait() => {
            SessionEnd::Child(status.map_err(|e| DevError::Runtime(format!("wait for podman: {e}")))?)
        }
    };

    match end {
        SessionEnd::Child(status) => {
            // The relay's own master handles are already gone (select!
            // dropped the losing/winning branch's future above); drain what
            // podman had already written before its exit was recorded.
            drain_remaining_output(&mut pty.master()).await;
            exit_code_of(status)
        }
        SessionEnd::Relay => {
            // Dropping every remaining master handle is what hangs podman up:
            // the kernel delivers SIGHUP to the pty's foreground process
            // group once the last master fd closes.
            drop(peer);
            drop(pty);
            let status = tokio::time::timeout(EXEC_STATUS_BUDGET, child.wait())
                .await
                .map_err(|_| {
                    DevError::Runtime(format!(
                        "the podman client did not exit within {}s after the session ended",
                        EXEC_STATUS_BUDGET.as_secs()
                    ))
                })?
                .map_err(|e| DevError::Runtime(format!("wait for podman: {e}")))?;
            exit_code_of(status)
        }
    }
}

/// `Some(code)` is podman's own exit code. `(None, Some(signal))` is the shell
/// convention of `128 + signal`. `(None, None)` cannot happen for a waited
/// child on unix, but the match stays total so "no status" never passes for
/// success, mirroring `recorded_exec_status`'s refusal in docker.rs.
fn exit_code_of(status: std::process::ExitStatus) -> Result<i32, DevError> {
    match (status.code(), status.signal()) {
        (Some(code), _) => Ok(code),
        (None, Some(signal)) => Ok(128 + signal),
        (None, None) => Err(DevError::Runtime(
            "podman exited with neither a code nor a signal".to_string(),
        )),
    }
}

/// The [`SessionPeer`] for a podman exec: copy-in goes through the same
/// bollard-backed non-tty exec every other Podman write uses, but resize
/// never touches bollard — podman is the pty's foreground process and
/// forwards SIGWINCH to the container exec on its own.
pub(crate) struct PodmanSessionPeer<'a> {
    bollard: &'a BollardRuntime,
    container: String,
    user: Option<String>,
    master: PtyMaster,
}

impl SessionPeer for PodmanSessionPeer<'_> {
    fn resize(&self, cols: u16, rows: u16) -> UnitFut<'_> {
        // Best-effort, matching every other `SessionPeer::resize`: the ioctl this
        // reaches can fail if the pty has already gone away, and a resize failure
        // must not end the session.
        let _ = self.master.resize(cols, rows);
        Box::pin(async {})
    }

    fn copy_in<'a>(&'a self, bytes: Vec<u8>, target: &'a str) -> BoxFut<'a, ()> {
        Box::pin(async move {
            self.bollard
                .copy_into_container(&self.container, self.user.as_deref(), bytes, target)
                .await
        })
    }
}

impl ContainerRuntime for PodmanRuntime {
    fn runtime_name(&self) -> &'static str {
        "podman"
    }

    fn pull_image(&self, image: &str) -> BoxFut<'_, ()> {
        self.0.pull_image(image)
    }

    fn build_image(
        &self,
        dockerfile: &str,
        context: &Path,
        tag: &str,
        build_args: &std::collections::HashMap<String, String>,
        no_cache: bool,
        verbose: bool,
    ) -> BoxFut<'_, ()> {
        self.0
            .build_image(dockerfile, context, tag, build_args, no_cache, verbose)
    }

    fn create_container(&self, config: &ContainerConfig) -> BoxFut<'_, String> {
        self.0.create_container(config)
    }

    fn start_container(&self, id: &str) -> BoxFut<'_, ()> {
        self.0.start_container(id)
    }

    fn stop_container(&self, id: &str) -> BoxFut<'_, ()> {
        self.0.stop_container(id)
    }

    fn remove_container(&self, id: &str) -> BoxFut<'_, ()> {
        self.0.remove_container(id)
    }

    fn exec(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
        env: &[(String, SecretValue)],
    ) -> BoxFut<'_, ExecResult> {
        self.0.exec(id, cmd, user, workdir, env)
    }

    fn exec_reports_missing_command(&self, error: &DevError) -> bool {
        self.0.exec_reports_missing_command(error)
    }

    fn exec_interactive(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
        env: &[(String, SecretValue)],
    ) -> BoxFut<'_, i32> {
        // Podman's HTTP API doesn't reliably support interactive TTY exec via
        // bollard; run `podman exec -it` as a child on a pty `dev` owns instead.
        let id = id.to_string();
        let cmd = cmd.to_vec();
        let user = user.map(|u| u.to_string());
        let workdir = workdir.map(|d| d.to_string());
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(key, value)| (key.clone(), value.expose().to_string()))
            .collect();
        Box::pin(async move {
            self.exec_interactive_impl(&id, &cmd, user.as_deref(), workdir.as_deref(), &env)
                .await
        })
    }

    fn inspect_container(&self, id: &str) -> BoxFut<'_, ContainerInfo> {
        self.0.inspect_container(id)
    }

    fn list_containers(&self, label_filters: &[String]) -> BoxFut<'_, Vec<ContainerInfo>> {
        self.0.list_containers(label_filters)
    }

    fn image_exists(&self, image: &str) -> BoxFut<'_, bool> {
        self.0.image_exists(image)
    }

    fn container_logs(
        &self,
        id: &str,
        follow: bool,
        tail: Option<u32>,
    ) -> BoxFut<'_, Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
        self.0.container_logs(id, follow, tail)
    }

    fn list_images(&self) -> BoxFut<'_, Vec<ImageInfo>> {
        self.0.list_images()
    }

    fn remove_image(&self, image: &str) -> BoxFut<'_, ()> {
        self.0.remove_image(image)
    }

    fn inspect_image_metadata(&self, image: &str) -> BoxFut<'_, ImageMetadata> {
        self.0.inspect_image_metadata(image)
    }

    fn exec_attached(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
    ) -> BoxFut<'_, AttachedExec> {
        self.0.exec_attached(id, cmd, user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::fake_daemon::{read_http_request, request_json_body};
    use crate::runtime::test_peer::bounded;
    use crate::runtime::{ContainerRuntime, WorkspaceMount};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Podman create delegates through the same bollard-backed create path as
    /// Docker. This uses a fake Unix-socket daemon rather than a live Podman
    /// daemon, so it proves the request body Podman sends through
    /// `ContainerRuntime::create_container`, not Podman's daemon behavior.
    #[tokio::test]
    async fn podman_create_container_sends_the_shared_bollard_create_body() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 37\r\n\r\n{\"Id\":\"podman-created\",\"Warnings\":[]}",
                )
                .await
                .unwrap();
            request
        });

        let runtime = PodmanRuntime(
            BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
                .expect("building a podman client must not need a daemon"),
        );
        let mut config = ContainerConfig {
            image: "ubuntu:24.04".to_string(),
            name: "vsc-test".to_string(),
            labels: HashMap::new(),
            env: HashMap::from([("FROM_RUNARGS".to_string(), "1".to_string())]),
            mounts: vec![],
            volumes: vec![],
            tmpfs: vec![],
            ports: vec![],
            workspace_mount: Some(WorkspaceMount {
                source: std::path::PathBuf::from("/host/workspace"),
                target: "/workspace".to_string(),
            }),
            workspace_folder: Some("/workspace".to_string()),
            extra_args: vec![],
            entrypoint: None,
            init: true,
            privileged: true,
            cap_add: vec!["SYS_PTRACE".to_string()],
            security_opt: vec!["seccomp=unconfined".to_string()],
            userns_mode: Some("keep-id".to_string()),
        };
        config.labels.insert(
            "devcontainer.local_folder".to_string(),
            "/host/workspace".to_string(),
        );

        let id = (&runtime as &dyn ContainerRuntime)
            .create_container(&config)
            .await
            .expect("fake daemon should accept the create request");

        let request = server.await.unwrap();
        let body = request_json_body(&request);

        assert_eq!(id, "podman-created");
        assert!(
            request.starts_with("POST /containers/create"),
            "create must be sent through bollard's Docker-compatible create API, got: {request}"
        );
        assert!(
            request.contains("/containers/create?name=vsc-test"),
            "container name should be passed as create option, got: {request}"
        );
        assert_eq!(body["Image"], "ubuntu:24.04");
        assert_eq!(body["WorkingDir"], "/workspace");
        assert_eq!(body["Env"], serde_json::json!(["FROM_RUNARGS=1"]));
        assert_eq!(body["HostConfig"]["Init"], true);
        assert_eq!(body["HostConfig"]["Privileged"], true);
        assert_eq!(
            body["HostConfig"]["CapAdd"],
            serde_json::json!(["SYS_PTRACE"])
        );
        assert_eq!(
            body["HostConfig"]["SecurityOpt"],
            serde_json::json!(["seccomp=unconfined"])
        );
        assert_eq!(body["HostConfig"]["UsernsMode"], "keep-id");
    }

    #[test]
    fn interactive_exec_args_include_the_requested_workspace_folder() {
        let args = podman_exec_args(
            "container-id",
            &["bash".to_string()],
            Some("vscode"),
            Some("/srv/app/packages/api"),
            &[],
        );

        assert_eq!(
            args,
            vec![
                "exec",
                "-it",
                "--user",
                "vscode",
                "--workdir",
                "/srv/app/packages/api",
                "container-id",
                "bash",
            ]
        );
    }

    /// One `-e` per name, and the name only. A `NAME=value` here would put the
    /// value in `/proc/<pid>/cmdline`, which every user on the host can read.
    #[test]
    fn interactive_exec_args_name_env_entries_without_their_values() {
        let args = podman_exec_args(
            "container-id",
            &["bash".to_string()],
            None,
            None,
            &["A".to_string(), "B".to_string()],
        );

        assert_eq!(
            args,
            vec!["exec", "-it", "-e", "A", "-e", "B", "container-id", "bash"]
        );
    }

    /// The guard against someone reintroducing `env_assignments` here: an
    /// assignment reaching this function would be a value in argv.
    #[test]
    fn no_env_argument_carries_an_assignment() {
        let args = podman_exec_args(
            "container-id",
            &["bash".to_string()],
            Some("vscode"),
            Some("/workspaces/demo"),
            &["API_TOKEN".to_string()],
        );

        assert!(
            !args.iter().any(|arg| arg.contains('=')),
            "no argument may carry a `NAME=value` assignment: {args:?}"
        );
    }

    /// Reads from `master` until `wanted` shows up in the accumulated bytes or
    /// `budget` runs out, mirroring `apple.rs`'s fd-based `read_until` but over
    /// the tokio-backed master.
    async fn read_until(
        master: &mut PtyMaster,
        wanted: &str,
        budget: std::time::Duration,
    ) -> Vec<u8> {
        let deadline = std::time::Instant::now() + budget;
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, master.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    seen.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&seen).contains(wanted) {
                        break;
                    }
                }
            }
        }
        seen
    }

    /// `exit_code_of` returns the shell convention `128 + signal` for a
    /// signalled status and the plain code for a normal exit — not the bare
    /// signal number, and not `code().unwrap_or(-1)` for the signalled case.
    #[test]
    fn exit_code_of_a_signalled_child_is_128_plus_the_signal() {
        let signalled = std::process::ExitStatus::from_raw(libc::SIGKILL);
        assert_eq!(
            exit_code_of(signalled).expect("a signalled status must resolve to a code"),
            137,
            "SIGKILL (signal 9) must resolve to 128 + 9"
        );

        let exited = std::process::ExitStatus::from_raw(3 << 8);
        assert_eq!(
            exit_code_of(exited).expect("a normal exit must resolve to a code"),
            3,
            "a normal exit must resolve to its own code, not the shell convention"
        );
    }

    /// `setsid` + `TIOCSCTTY` in `spawn_on_slave`'s `pre_exec` give the child
    /// the slave as its controlling terminal: `/dev/tty` inside the child
    /// reports the slave's own size (set here before spawn), never the
    /// developer's own terminal — even though `cargo test` itself may be
    /// running under one.
    #[tokio::test]
    async fn a_child_on_the_slave_gets_it_as_its_controlling_terminal() {
        bounded(async {
            let mut pty = Pty::open().expect("open pty");
            pty.resize(97, 31).expect("resize must succeed");
            let slave = pty.take_slave().expect("slave present after open");

            let mut child = spawn_on_slave(
                "/bin/sh",
                &[
                    "-c".to_string(),
                    "stty size </dev/tty && exit 42; exit 1".to_string(),
                ],
                vec![],
                &slave,
            )
            .expect("spawn must succeed");
            drop(slave);

            let mut master = pty.master();
            let seen = read_until(&mut master, "31 97", std::time::Duration::from_secs(8)).await;
            assert!(
                String::from_utf8_lossy(&seen).contains("31 97"),
                "the child must report the slave's own resized size through /dev/tty, got: {seen:?}"
            );

            let status = child.wait().await.expect("wait must succeed");
            assert_eq!(
                exit_code_of(status).expect("status must resolve to a code"),
                42,
                "the child must exit 42 once stty size on /dev/tty succeeds"
            );
        })
        .await;
    }

    /// Proves all three stdio fds are the slave clones `spawn_on_slave`
    /// claims: `/bin/cat` reads fd 0 and writes fd 1, so bytes written to the
    /// master come back through the master only if both are wired through.
    /// Also pins the signal branch of `exit_code_of` against a real killed
    /// child, not a synthetic status.
    #[tokio::test]
    async fn bytes_written_to_the_master_come_back_through_the_child() {
        bounded(async {
            let mut pty = Pty::open().expect("open pty");
            let slave = pty.take_slave().expect("slave present after open");

            let mut child =
                spawn_on_slave("/bin/cat", &[], vec![], &slave).expect("spawn must succeed");
            drop(slave);

            let mut master = pty.master();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                master.write_all(b"ping\n"),
            )
            .await
            .expect("write must not hang")
            .expect("write to the master must succeed");

            let seen = read_until(&mut master, "ping\n", std::time::Duration::from_secs(8)).await;
            assert!(
                String::from_utf8_lossy(&seen).contains("ping\n"),
                "bytes written to the master must come back through cat's stdout, got: {seen:?}"
            );

            child.start_kill().expect("start_kill must succeed");
            let status = child.wait().await.expect("wait must succeed");
            assert_eq!(
                exit_code_of(status).expect("status must resolve to a code"),
                128 + libc::SIGKILL,
                "a signalled child must resolve through the 128 + signal branch"
            );
        })
        .await;
    }

    /// The property the whole resize design rests on: a size change on the
    /// master reaches the pty's foreground process group as SIGWINCH, which
    /// only exists because the child made the slave its controlling terminal.
    /// `PodmanSessionPeer::resize` never touches bollard to make this happen.
    #[tokio::test]
    async fn a_resize_reaches_the_child_as_sigwinch() {
        bounded(async {
            let mut pty = Pty::open().expect("open pty");
            let slave = pty.take_slave().expect("slave present after open");

            let mut child = spawn_on_slave(
                "/bin/sh",
                &[
                    "-c".to_string(),
                    "trap \"stty size; exit 0\" WINCH; echo ready; while :; do sleep 0.05; done"
                        .to_string(),
                ],
                vec![],
                &slave,
            )
            .expect("spawn must succeed");
            drop(slave);

            let mut master = pty.master();
            let ready = read_until(&mut master, "ready", std::time::Duration::from_secs(8)).await;
            assert!(
                String::from_utf8_lossy(&ready).contains("ready"),
                "the child must print ready before the resize is sent, got: {ready:?}"
            );

            // `connect_to_socket` only needs the path to exist, not a daemon
            // behind it — resize never sends it a request.
            let dir = tempfile::TempDir::new().unwrap();
            let socket_path = dir.path().join("podman-pty-test.sock");
            let _listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            let bollard = BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
                .expect("building a bollard client must not need a live daemon");
            let peer = PodmanSessionPeer {
                bollard: &bollard,
                container: "unused".to_string(),
                user: None,
                master: pty.master(),
            };
            peer.resize(97, 31).await;

            let seen = read_until(&mut master, "31 97", std::time::Duration::from_secs(8)).await;
            assert!(
                String::from_utf8_lossy(&seen).contains("31 97"),
                "SIGWINCH from the resize must reach the child's WINCH trap, got: {seen:?}"
            );

            let status = child.wait().await.expect("wait must succeed");
            assert_eq!(
                exit_code_of(status).expect("status must resolve to a code"),
                0,
                "the trap must exit 0 once it observes the resize"
            );
        })
        .await;
    }

    /// Pins the relay-first path in requirement 6: closing every master
    /// handle is what ends the podman client when the host side goes away
    /// first, delivered as SIGHUP because the child is the session leader on
    /// this pty.
    #[tokio::test]
    async fn closing_the_master_hangs_the_child_up() {
        bounded(async {
            let mut pty = Pty::open().expect("open pty");
            let slave = pty.take_slave().expect("slave present after open");

            let mut child =
                spawn_on_slave("/bin/cat", &[], vec![], &slave).expect("spawn must succeed");
            drop(slave);

            drop(pty);

            let status = child.wait().await.expect("wait must succeed");
            assert_eq!(
                exit_code_of(status).expect("status must resolve to a code"),
                128 + libc::SIGHUP,
                "closing every master handle must hang the child up with SIGHUP"
            );
        })
        .await;
    }

    /// `PtyMaster` is an `Arc` clone of one master fd, and the kernel only
    /// hangs the child up when the last of those clones closes. So a session
    /// that drops the `Pty` while another handle survives leaves the child
    /// running — which is why the relay-first arm has to drop the peer as
    /// well, and not rely on rust dropping it at the end of the function.
    #[tokio::test]
    async fn a_surviving_master_clone_keeps_the_child_from_hanging_up() {
        bounded(async {
            let mut pty = Pty::open().expect("open pty");
            let slave = pty.take_slave().expect("slave present after open");

            let mut child =
                spawn_on_slave("/bin/cat", &[], vec![], &slave).expect("spawn must succeed");
            drop(slave);

            let surviving = pty.master();
            drop(pty);

            let still_running = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                child.wait(),
            )
            .await;
            assert!(
                still_running.is_err(),
                "one surviving master clone must hold the pty open, so dropping the Pty alone cannot hang the child up: {still_running:?}"
            );

            drop(surviving);
            let status = child.wait().await.expect("wait must succeed");
            assert_eq!(
                exit_code_of(status).expect("status must resolve to a code"),
                128 + libc::SIGHUP,
                "the child must hang up as soon as the last master handle is gone"
            );
        })
        .await;
    }

    /// The relay-first arm of requirement 6, driven through `run_session`
    /// itself: host stdin EOF ends the relay, and the session must then close
    /// every master handle it still owns — the peer's clone included — so the
    /// child hangs up before the exit-status budget runs out.
    #[tokio::test]
    async fn a_relay_that_ends_first_hangs_the_child_up_and_reports_its_signal() {
        bounded(async {
            let mut pty = Pty::open().expect("open pty");
            let slave = pty.take_slave().expect("slave present after open");

            let child =
                spawn_on_slave("/bin/cat", &[], vec![], &slave).expect("spawn must succeed");
            drop(slave);

            // `connect_to_socket` only needs the path to exist, not a daemon
            // behind it — this session never copies anything in.
            let dir = tempfile::TempDir::new().unwrap();
            let socket_path = dir.path().join("podman-session-test.sock");
            let _listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            let bollard = BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
                .expect("building a bollard client must not need a live daemon");
            let peer = PodmanSessionPeer {
                bollard: &bollard,
                container: "unused".to_string(),
                user: None,
                master: pty.master(),
            };

            // A closed keys channel is host stdin EOF, the first of the three
            // ways the relay can be the side that ends.
            let (keys_tx, mut keys) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
            drop(keys_tx);
            let host = HostTerminal {
                keys: &mut keys,
                stdout: tokio::io::stdout(),
                winch:
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                        .expect("SIGWINCH registration must succeed in a test binary"),
                size: || None,
            };

            let code = run_session(host, pty, child, peer).await.expect(
                "the session must settle on an exit code, not time out waiting for the child",
            );
            assert_eq!(
                code,
                128 + libc::SIGHUP,
                "a relay that ends first must hang the child up and report its signal"
            );
        })
        .await;
    }
}
