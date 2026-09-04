//! Best-effort integration with cmux's sidebar: status pills and notifications.
//!
//! Every call here returns `()` and prints nothing on any failure. Outside a
//! live cmux terminal, or with the caller's config gate off, every function
//! is a no-op.
//!
//! A call is queued for one worker thread, which spawns `cmux` and waits on
//! it there, so painting a pill costs the command an enqueue. The liveness
//! ping runs on that worker too, ahead of the first call. See [`queue`].

use std::ffi::OsString;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::devcontainer::secrets::PluginPath;
use crate::devcontainer::secrets::provider::is_executable_file;
use crate::util::process::wait_bounded;

pub mod agent;

/// Status key for `dev up`'s build phases pill.
///
/// `cmux set-status` targets a workspace, not a surface, so a `dev up`
/// running in one surface would overwrite the session pill of a shell open in
/// another surface of the same workspace if both wrote the same key. Two
/// keys, two pills.
pub const BUILD_KEY: &str = "dev_build";

/// Status key for `dev shell`'s session pill. See [`BUILD_KEY`] for why this
/// is a separate key.
pub const SHELL_KEY: &str = "dev_shell";

/// Amber and a hammer for the `dev up`/`dev build`/`dev down` phase pill,
/// against the session pill's terminal icon and blue, so the two read apart
/// in the sidebar.
pub(crate) const BUILD_STYLE: StatusStyle<'static> = StatusStyle {
    icon: Some("hammer"),
    color: Some("#F59E0B"),
    priority: None,
};

/// Icon and color for `dev shell`'s session pill. See [`BUILD_STYLE`].
pub(crate) const SESSION_PILL_STYLE: StatusStyle<'static> = StatusStyle {
    icon: Some("terminal"),
    color: Some("#3B82F6"),
    priority: None,
};

/// Every cmux child is killed and reaped if it has not exited by this long,
/// so a wedged socket costs each call at most one second, and the liveness
/// ping at most one second once per process, all on the worker thread.
const CALL_TIMEOUT: Duration = Duration::from_secs(1);

/// Caddy's 100ms poll would add roughly a second across a `dev up` and a
/// visible delay on `dev shell` entry and exit, so this module polls faster.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The longest a command will wait at its exit for queued calls to land.
/// Past this the pill is left to whatever looks at the container next, which
/// is the trade [`flush_budget`] makes against a wedged cmux.
const FLUSH_CEILING: Duration = Duration::from_secs(4);

/// Spawn cost and one `POLL_INTERVAL` of granularity per call, so a budget
/// sized to the work is not missed by a hair.
const FLUSH_SLACK: Duration = Duration::from_millis(100);

/// Set on every child, the way cmux's own wrapper sets it for its ping, so
/// cmux gives up on its own socket before `CALL_TIMEOUT` fires.
const RESPONSE_TIMEOUT_ENV: (&str, &str) = ("CMUXTERM_CLI_RESPONSE_TIMEOUT_SEC", "0.75");

/// The process environment this module reads. Captured once so every other
/// function in the module takes values as data instead of touching `std::env`.
struct Env {
    surface_id: Option<OsString>,
    socket_path: Option<PathBuf>,
    bundled_cli: Option<PathBuf>,
    path: OsString,
}

impl Env {
    fn from_process() -> Env {
        Env {
            surface_id: std::env::var_os("CMUX_SURFACE_ID"),
            socket_path: std::env::var_os("CMUX_SOCKET_PATH").map(PathBuf::from),
            bundled_cli: std::env::var_os("CMUX_BUNDLED_CLI_PATH").map(PathBuf::from),
            path: std::env::var_os("PATH").unwrap_or_default(),
        }
    }
}

/// The spawn seam. Production uses [`LiveTarget`]; tests substitute
/// [`Recorder`], so the suite never spawns a real `cmux`.
trait Runner: Send + Sync {
    /// Whether calls can reach cmux at all. Answered without spawning
    /// anything: the ping that would settle it runs on the worker.
    fn available(&self) -> bool;

    /// `true` means the call was accepted. In production that is only that it
    /// was queued: the spawn, and whatever cmux makes of it, happen on the
    /// worker after this has returned.
    fn run(&self, args: &[String]) -> bool;
}

/// The production [`Runner`]. The surface, socket, and binary are resolved on
/// the first call rather than up front, so a command that never paints a pill
/// never touches the filesystem for one.
struct LiveTarget;

impl Runner for LiveTarget {
    fn available(&self) -> bool {
        live().is_some()
    }

    fn run(&self, args: &[String]) -> bool {
        live().is_some_and(|spawner| enqueue_call(spawner, args.to_vec()))
    }
}

/// The resolved `cmux` binary and the socket it is pointed at.
struct Spawner {
    binary: PathBuf,
    socket: PathBuf,
}

impl Spawner {
    /// The argv every caller shares. `--socket` must precede `args`, or cmux
    /// would read it as an argument to the verb rather than a global flag.
    ///
    /// Stdio and the response timeout are left to the caller, because the two
    /// callers want opposites: a status pill wants a fast give-up and no
    /// output, while [`agent`]'s relay is forwarding a hook that may be
    /// waiting on a person and whose answer it has to read back.
    fn base_command(&self, args: &[String]) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg("--socket").arg(&self.socket).args(args);
        command
    }

    /// A status call: bounded by [`RESPONSE_TIMEOUT_ENV`], with stdout and
    /// stderr nulled so cmux's own error text never reaches the user's
    /// terminal — that is what makes "prints nothing" hold.
    fn command_for(&self, args: &[String]) -> Command {
        let mut command = self.base_command(args);
        command
            .env(RESPONSE_TIMEOUT_ENV.0, RESPONSE_TIMEOUT_ENV.1)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// Spawn and wait for the child, killing it at `CALL_TIMEOUT`. `true`
    /// means it exited 0. Only the worker thread calls this, so no command
    /// waits on a spawn of its own.
    fn run_now(&self, args: &[String]) -> bool {
        let mut child = match self.command_for(args).spawn() {
            Ok(child) => child,
            Err(_) => return false,
        };
        match wait_bounded(&mut child, CALL_TIMEOUT, POLL_INTERVAL) {
            Some(status) => status.success(),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                false
            }
        }
    }
}

/// What the worker thread accepts.
enum Job {
    Call(Vec<String>),
    /// Acked once every job queued ahead of it has run.
    Fence(Sender<()>),
}

static QUEUE: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();

/// Calls queued and not yet run, so [`flush`] can size its wait to the work
/// the worker still has ahead of the fence.
static PENDING_CALLS: AtomicUsize = AtomicUsize::new(0);

/// The worker's queue, started on the first call.
///
/// One worker draining one queue keeps the pills in the order the command
/// submitted them; a thread per call could paint "building" after "done".
fn queue(spawner: &'static Spawner) -> &'static Mutex<Sender<Job>> {
    QUEUE.get_or_init(|| {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || drain(spawner, receiver));
        Mutex::new(sender)
    })
}

/// Run each job in turn until the queue is closed.
///
/// The liveness ping cmux's own wrapper does happens here, before the first
/// call and only if there is one, because every other thread that would have
/// waited for it is running the user's command. A target that fails the ping
/// stays failed for the rest of the process; a fence is acked either way, or
/// [`flush`] would wait out its whole timeout for an answer nothing will send.
fn drain(spawner: &Spawner, jobs: Receiver<Job>) {
    let mut reachable = None;
    for job in jobs {
        match job {
            Job::Call(args) => {
                if *reachable.get_or_insert_with(|| spawner.run_now(&["ping".to_string()])) {
                    spawner.run_now(&args);
                }
                PENDING_CALLS.fetch_sub(1, Ordering::SeqCst);
            }
            Job::Fence(ack) => {
                let _ = ack.send(());
            }
        }
    }
}

/// Queue one call, counted as outstanding until the worker has run it.
///
/// The count is raised before the send, or the worker could run the call and
/// lower it first.
fn enqueue_call(spawner: &'static Spawner, args: Vec<String>) -> bool {
    PENDING_CALLS.fetch_add(1, Ordering::SeqCst);
    let sent = queue(spawner)
        .lock()
        .is_ok_and(|sender| sender.send(Job::Call(args)).is_ok());
    if !sent {
        PENDING_CALLS.fetch_sub(1, Ordering::SeqCst);
    }
    sent
}

/// Wait, briefly, for the worker to run everything queued so far.
///
/// The worker dies with the process, so a command that exits with its pill
/// clear still queued would leave the pill up in the sidebar with nothing
/// left to remove it.
fn flush() {
    let Some(queue) = QUEUE.get() else {
        return;
    };
    let (ack, acked) = mpsc::channel();
    let sent = queue
        .lock()
        .is_ok_and(|sender| sender.send(Job::Fence(ack)).is_ok());
    if sent {
        let _ = acked.recv_timeout(flush_budget(PENDING_CALLS.load(Ordering::SeqCst)));
    }
}

/// How long [`flush`] waits: one `CALL_TIMEOUT` for each call still ahead of
/// the fence, plus one for the liveness ping that may still run before them,
/// plus a little for spawn cost and the poll granularity underneath them.
///
/// One call's worth is not enough. `dev status` queues a single call to
/// correct a stranded pill and flushes at once, so its fence waits out the
/// ping as well, and a cmux answering in 0.6s spends 1.2s on the pair.
///
/// [`FLUSH_CEILING`] is what stops the other end. `dev up` can reach its drop
/// with five calls queued against a cmux that answers `ping` and then wedges
/// on writes, and five seconds of dead terminal is worse than a sidebar pill
/// that stayed up.
fn flush_budget(pending_calls: usize) -> Duration {
    let calls = u32::try_from(pending_calls).unwrap_or(u32::MAX);
    CALL_TIMEOUT
        .saturating_mul(calls.saturating_add(1))
        .saturating_add(FLUSH_SLACK)
        .min(FLUSH_CEILING)
}

/// `$CMUX_BUNDLED_CLI_PATH` if it names an executable file, else the first
/// `cmux` on `PATH`. The wrapper's sibling-of-the-script fallback is dropped:
/// `dev` has no sibling cmux binary and the analogue is meaningless here.
fn resolve_binary(env: &Env) -> Option<PathBuf> {
    if let Some(bundled) = &env.bundled_cli
        && is_executable_file(bundled)
    {
        return Some(bundled.clone());
    }
    PluginPath::from_os_str(&env.path).find("cmux")
}

/// A plain file at `path` is not live; only an actual unix socket is.
fn is_unix_socket(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.file_type().is_socket())
        .unwrap_or(false)
}

/// `None` unless the surface, socket, and binary are all present. Touches the
/// filesystem but spawns nothing.
fn locate(env: &Env) -> Option<Spawner> {
    let surface_id = env.surface_id.as_ref()?;
    if surface_id.is_empty() {
        return None;
    }
    let socket = env.socket_path.as_ref()?;
    if !is_unix_socket(socket) {
        return None;
    }
    let binary = resolve_binary(env)?;
    Some(Spawner {
        binary,
        socket: socket.clone(),
    })
}

/// The resolved cmux target for this process, computed once.
///
/// The surface, socket, and binary cannot change during one `dev` invocation,
/// and a socket that dies mid-run yields silent failed calls, which is the
/// intended behavior anyway. Whether the target answers is settled by the
/// worker's ping, so this costs a few stats and no spawn.
fn live() -> Option<&'static Spawner> {
    static LIVE: OnceLock<Option<Spawner>> = OnceLock::new();
    LIVE.get_or_init(|| locate(&Env::from_process())).as_ref()
}

fn status_args(key: &str, value: &str, style: StatusStyle<'_>) -> Vec<String> {
    let mut args = vec!["set-status".to_string(), key.to_string(), value.to_string()];
    if let Some(icon) = style.icon {
        args.push("--icon".to_string());
        args.push(icon.to_string());
    }
    if let Some(color) = style.color {
        args.push("--color".to_string());
        args.push(color.to_string());
    }
    if let Some(priority) = style.priority {
        args.push("--priority".to_string());
        args.push(priority.to_string());
    }
    args
}

fn clear_args(key: &str) -> Vec<String> {
    vec!["clear-status".to_string(), key.to_string()]
}

fn notify_args(title: &str, body: &str) -> Vec<String> {
    vec![
        "notify".to_string(),
        "--title".to_string(),
        title.to_string(),
        "--body".to_string(),
        body.to_string(),
    ]
}

/// Optional `cmux set-status` styling. Fields are applied in declaration
/// order: `--icon`, `--color`, `--priority`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusStyle<'a> {
    pub icon: Option<&'a str>,
    pub color: Option<&'a str>,
    pub priority: Option<u32>,
}

/// A handle to cmux's sidebar for one command invocation. `None` runner is
/// inert: every method becomes a no-op.
#[derive(Clone)]
pub struct Cmux {
    runner: Option<Arc<dyn Runner>>,
}

impl Cmux {
    /// The cmux target for this command, or an inert handle.
    ///
    /// `enabled` is the caller's config gate where the caller already knows
    /// it; `true` only says nothing has ruled cmux out yet, since the target
    /// itself is resolved on the first call.
    pub fn detect(enabled: bool) -> Cmux {
        Cmux {
            runner: enabled.then(|| Arc::new(LiveTarget) as Arc<dyn Runner>),
        }
    }

    /// A handle that records every call instead of spawning cmux, and the
    /// [`Recorder`] a test reads them back from. Per-instance, so parallel
    /// tests never share state.
    #[cfg(test)]
    pub(crate) fn recording() -> (Cmux, Recorder) {
        let recorder = Recorder::default();
        let runner: Arc<dyn Runner> = Arc::new(recorder.clone());
        (
            Cmux {
                runner: Some(runner),
            },
            recorder,
        )
    }

    /// Whether this handle has a cmux target to try. Says the surface, socket
    /// and binary are all there, not that cmux answers: what a wedged socket
    /// costs is a queued call the worker drops.
    pub fn available(&self) -> bool {
        self.runner
            .as_ref()
            .is_some_and(|runner| runner.available())
    }

    /// Wait for the calls made through this handle to reach cmux. Callers
    /// that keep no [`StatusGuard`] need this before the process exits; see
    /// the module's [`flush`]. The wait itself goes to a blocking thread, so
    /// the caller's runtime keeps running while cmux is asked.
    pub async fn flush(&self) {
        if self.runner.is_some() {
            let _ = tokio::task::spawn_blocking(flush).await;
        }
    }

    pub fn set_status(&self, key: &str, value: &str, style: StatusStyle<'_>) {
        self.call(status_args(key, value, style));
    }

    pub fn clear_status(&self, key: &str) {
        self.call(clear_args(key));
    }

    pub fn notify(&self, title: &str, body: &str) {
        self.call(notify_args(title, body));
    }

    fn call(&self, args: Vec<String>) {
        if let Some(runner) = &self.runner {
            let _ = runner.run(&args);
        }
    }

    /// Build a status pill guard for `key`. `enabled` is the caller's config
    /// gate (e.g. `cmux.status`); this handle's own `available()` is the
    /// environment gate. Both must hold for the guard to do anything, which
    /// is why this is the one place the two gates meet.
    ///
    /// Bind the result to a named variable (`let mut pill = ...`); `let _ =
    /// cmux.guard(...)` drops it on the same line, and `#[must_use]` does not
    /// catch that form.
    pub fn guard(&self, key: &str, enabled: bool) -> StatusGuard {
        let cmux = if enabled {
            self.clone()
        } else {
            Cmux { runner: None }
        };
        StatusGuard {
            cmux,
            key: key.to_string(),
            set: false,
            outcome: None,
            notify: None,
            started: Instant::now(),
        }
    }
}

/// Clears its status key when dropped, and optionally notifies with the
/// recorded outcome once the guard has lived past `notify_after`'s threshold.
#[must_use]
pub struct StatusGuard {
    cmux: Cmux,
    key: String,
    set: bool,
    outcome: Option<String>,
    notify: Option<(String, Duration)>,
    started: Instant,
}

impl StatusGuard {
    /// Set the pill to `label`, styled with `style`.
    pub fn phase(&mut self, label: &str, style: StatusStyle<'_>) {
        self.cmux.set_status(&self.key, label, style);
        self.set = true;
    }

    /// Record the outcome a trailing notify should report. Runs nothing.
    pub fn succeeded(&mut self, summary: &str) {
        self.outcome = Some(summary.to_string());
    }

    /// Arm a notify on drop, once at least `min_elapsed` has passed since the
    /// guard was built. Runs nothing.
    pub fn notify_after(mut self, title: &str, min_elapsed: Duration) -> Self {
        self.notify = Some((title.to_string(), min_elapsed));
        self
    }

    /// Take the pill down now, and leave nothing for `Drop` to clear. An
    /// armed notify still fires on drop.
    pub fn clear(&mut self) {
        self.cmux.clear_status(&self.key);
        self.set = false;
    }

    /// Skip the clear on drop, for a caller that has already carried out its
    /// own decision about the key.
    pub fn disarm(&mut self) {
        self.set = false;
    }
}

impl Drop for StatusGuard {
    fn drop(&mut self) {
        if self.set {
            self.cmux.clear_status(&self.key);
        }
        if let Some((title, min_elapsed)) = &self.notify
            && self.started.elapsed() >= *min_elapsed
        {
            let body = self.outcome.as_deref().unwrap_or("failed");
            self.cmux.notify(title, body);
        }
        // The one place that blocks the caller: a `Drop` cannot await, and a
        // command that exits with its last clear still queued leaves the pill
        // up for good. The clear and the notify above are themselves queued,
        // so the wait covers them too, bounded by `FLUSH_CEILING` and taken as
        // the command ends, with nothing left to overlap it with.
        if self.cmux.runner.is_some() {
            flush();
        }
    }
}

/// Every argv a [`Cmux::recording`] handle received, in call order, verb
/// first, with no `--socket` prefix (that is prepended only by
/// [`Spawner::command_for`]). Records on the calling thread, so a test reads
/// back what it just did.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Recorder(Arc<Mutex<Vec<Vec<String>>>>);

#[cfg(test)]
impl Recorder {
    pub(crate) fn calls(&self) -> Vec<Vec<String>> {
        self.0.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Runner for Recorder {
    fn available(&self) -> bool {
        true
    }

    fn run(&self, args: &[String]) -> bool {
        self.0.lock().unwrap().push(args.to_vec());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::net::UnixListener;

    /// Writes a `#!/bin/sh` fixture at `dir/name` with the given mode. Copies
    /// the shape of `provider.rs`'s `plant`, local here because that one is
    /// private to its own module.
    fn plant(dir: &Path, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn env_with(
        surface: Option<&str>,
        socket: Option<&Path>,
        bundled: Option<&Path>,
        path: &Path,
    ) -> Env {
        Env {
            surface_id: surface.map(OsString::from),
            socket_path: socket.map(Path::to_path_buf),
            bundled_cli: bundled.map(Path::to_path_buf),
            path: path.as_os_str().to_os_string(),
        }
    }

    // --- status keys ---

    #[test]
    fn build_and_shell_keys_are_distinct_and_clear_independently() {
        assert_ne!(BUILD_KEY, SHELL_KEY);

        let (cmux, recorder) = Cmux::recording();
        let mut guard = cmux.guard(BUILD_KEY, true);
        guard.phase("Pulling", StatusStyle::default());
        drop(guard);

        let calls = recorder.calls();
        assert_eq!(
            calls.last(),
            Some(&vec!["clear-status".to_string(), BUILD_KEY.to_string()])
        );
        assert!(
            !calls.iter().flatten().any(|arg| arg == SHELL_KEY),
            "no call should name SHELL_KEY: {calls:?}"
        );
    }

    // --- argv builders ---

    #[test]
    fn status_args_has_no_flags_by_default() {
        assert_eq!(
            status_args("build", "Pulling", StatusStyle::default()),
            vec!["set-status", "build", "Pulling"]
        );
    }

    #[test]
    fn status_args_appends_each_style_flag_in_order() {
        let style = StatusStyle {
            icon: Some("arrow.down"),
            color: Some("#00ff00"),
            priority: Some(5),
        };
        assert_eq!(
            status_args("build", "Pulling", style),
            vec![
                "set-status",
                "build",
                "Pulling",
                "--icon",
                "arrow.down",
                "--color",
                "#00ff00",
                "--priority",
                "5",
            ]
        );
    }

    #[test]
    fn status_args_emits_only_the_flags_that_are_set() {
        let style = StatusStyle {
            color: Some("#abc"),
            ..Default::default()
        };
        assert_eq!(
            status_args("k", "v", style),
            vec!["set-status", "k", "v", "--color", "#abc"]
        );
    }

    #[test]
    fn clear_args_and_notify_args_shape() {
        assert_eq!(clear_args("build"), vec!["clear-status", "build"]);
        assert_eq!(
            notify_args("t", "b"),
            vec!["notify", "--title", "t", "--body", "b"]
        );
    }

    // --- locating cmux ---

    #[test]
    fn locate_needs_a_surface_id() {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path(), "cmux", 0o755);
        let socket_path = dir.path().join("s");
        let _listener = UnixListener::bind(&socket_path).unwrap();

        let none = env_with(None, Some(&socket_path), None, dir.path());
        assert!(locate(&none).is_none());

        let empty = env_with(Some(""), Some(&socket_path), None, dir.path());
        assert!(locate(&empty).is_none());
    }

    #[test]
    fn locate_needs_the_socket_to_be_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path(), "cmux", 0o755);
        let socket_path = dir.path().join("s");

        std::fs::write(&socket_path, "not a socket").unwrap();
        let plain_file = env_with(Some("surface"), Some(&socket_path), None, dir.path());
        assert!(locate(&plain_file).is_none());

        std::fs::remove_file(&socket_path).unwrap();
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let real_socket = env_with(Some("surface"), Some(&socket_path), None, dir.path());
        assert!(locate(&real_socket).is_some());
    }

    #[test]
    fn locate_prefers_an_executable_bundled_cli() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("s");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let bundled = plant(dir.path(), "bundled-cmux", 0o755);
        let path_dir = dir.path().join("bin");
        std::fs::create_dir_all(&path_dir).unwrap();
        plant(&path_dir, "cmux", 0o755);

        let env = env_with(
            Some("surface"),
            Some(&socket_path),
            Some(&bundled),
            &path_dir,
        );
        let spawner = locate(&env).expect("should locate a spawner");
        assert_eq!(spawner.binary, bundled);
    }

    #[test]
    fn locate_falls_through_a_non_executable_bundled_cli() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("s");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let bundled = plant(dir.path(), "bundled-cmux", 0o644);
        let path_dir = dir.path().join("bin");
        std::fs::create_dir_all(&path_dir).unwrap();
        let path_cmux = plant(&path_dir, "cmux", 0o755);

        let env = env_with(
            Some("surface"),
            Some(&socket_path),
            Some(&bundled),
            &path_dir,
        );
        let spawner = locate(&env).expect("should locate a spawner");
        assert_eq!(spawner.binary, path_cmux);
    }

    #[test]
    fn locate_is_none_without_any_binary() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("s");
        let _listener = UnixListener::bind(&socket_path).unwrap();

        let env = env_with(Some("surface"), Some(&socket_path), None, Path::new(""));
        assert!(locate(&env).is_none());
    }

    // --- the production runner ---

    #[test]
    fn command_for_targets_the_socket_and_nulls_output() {
        let spawner = Spawner {
            binary: PathBuf::from("/x/cmux"),
            socket: PathBuf::from("/y/s"),
        };
        let command = spawner.command_for(&["ping".to_string()]);

        assert_eq!(command.get_program(), OsStr::new("/x/cmux"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args,
            vec![
                OsStr::new("--socket"),
                OsStr::new("/y/s"),
                OsStr::new("ping")
            ]
        );
        let envs: Vec<_> = command.get_envs().collect();
        assert!(
            envs.contains(&(
                OsStr::new("CMUXTERM_CLI_RESPONSE_TIMEOUT_SEC"),
                Some(OsStr::new("0.75"))
            )),
            "missing response-timeout env: {envs:?}"
        );
    }

    #[test]
    fn spawner_reports_the_childs_exit() {
        let ok = Spawner {
            binary: PathBuf::from("true"),
            socket: PathBuf::from("/nonexistent/socket"),
        };
        assert!(ok.run_now(&["ping".to_string()]));

        let fails = Spawner {
            binary: PathBuf::from("false"),
            socket: PathBuf::from("/nonexistent/socket"),
        };
        assert!(!fails.run_now(&["ping".to_string()]));

        let dir = tempfile::tempdir().unwrap();
        let missing = Spawner {
            binary: dir.path().join("missing"),
            socket: PathBuf::from("/nonexistent/socket"),
        };
        assert!(!missing.run_now(&["ping".to_string()]));
    }

    /// A `#!/bin/sh` fixture that appends its whole argv to `log` as one
    /// line and exits `code`, so a test can read back what was spawned.
    fn plant_recorder(dir: &Path, log: &Path, code: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("recording-cmux");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexit {code}\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn spawned_lines(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// A queued call, counted the way `enqueue_call` counts it so a test
    /// driving `drain` by hand leaves `PENDING_CALLS` where it found it.
    fn call(args: &[&str]) -> Job {
        PENDING_CALLS.fetch_add(1, Ordering::SeqCst);
        Job::Call(args.iter().map(|arg| arg.to_string()).collect())
    }

    // --- the worker ---

    #[test]
    fn the_worker_pings_once_before_the_calls_it_drains() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv");
        let spawner = Spawner {
            binary: plant_recorder(dir.path(), &log, 0),
            socket: PathBuf::from("/y/s"),
        };
        let (sender, receiver) = mpsc::channel();
        sender.send(call(&["clear-status", "k"])).unwrap();
        sender.send(call(&["clear-status", "k"])).unwrap();
        drop(sender);

        drain(&spawner, receiver);

        let spawned = spawned_lines(&log);
        assert_eq!(spawned.len(), 3, "{spawned:?}");
        assert!(spawned[0].ends_with("ping"), "{spawned:?}");
        assert!(spawned[1].ends_with("clear-status k"), "{spawned:?}");
        assert!(spawned[2].ends_with("clear-status k"), "{spawned:?}");
    }

    /// A target that fails the ping is spawned once and never again, and a
    /// fence is still acked so a finishing command does not wait out
    /// `CALL_TIMEOUT` for it.
    #[test]
    fn a_target_that_fails_the_ping_gets_no_calls_but_still_acks() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv");
        let spawner = Spawner {
            binary: plant_recorder(dir.path(), &log, 1),
            socket: PathBuf::from("/y/s"),
        };
        let (sender, receiver) = mpsc::channel();
        let (ack, acked) = mpsc::channel();
        sender.send(call(&["set-status", "k", "v"])).unwrap();
        sender.send(Job::Fence(ack)).unwrap();
        sender.send(call(&["clear-status", "k"])).unwrap();
        drop(sender);

        drain(&spawner, receiver);

        let spawned = spawned_lines(&log);
        assert_eq!(spawned.len(), 1, "only the ping should spawn: {spawned:?}");
        assert!(spawned[0].ends_with("ping"), "{spawned:?}");
        assert!(acked.try_recv().is_ok(), "the fence must be acked anyway");
    }

    /// A fence sits behind the ping as well as behind the calls, so one
    /// call's worth of budget would give up on a write that is still
    /// runnable: the single call `dev status` queues to correct a stranded
    /// pill is exactly the case that loses.
    #[test]
    fn flush_budget_covers_the_ping_and_every_call_still_queued() {
        assert_eq!(flush_budget(0), CALL_TIMEOUT + FLUSH_SLACK);
        assert_eq!(flush_budget(1), CALL_TIMEOUT * 2 + FLUSH_SLACK);
        assert_eq!(flush_budget(3), FLUSH_CEILING);
    }

    #[test]
    fn flush_budget_stops_at_the_ceiling() {
        // A queue long enough to outlast a wedged cmux must not hold the
        // terminal open for it, and the count that says something is wrong
        // must not turn into a hang.
        assert_eq!(flush_budget(50), FLUSH_CEILING);
        assert_eq!(flush_budget(usize::MAX), FLUSH_CEILING);
    }

    // --- the handle ---

    #[test]
    fn inert_handle_runs_nothing() {
        let cmux = Cmux { runner: None };
        assert!(!cmux.available());

        cmux.set_status("k", "v", StatusStyle::default());
        cmux.clear_status("k");
        cmux.notify("t", "b");

        let mut guard = cmux.guard("k", true);
        guard.phase("p", StatusStyle::default());
        drop(guard);
    }

    #[test]
    fn handle_routes_each_verb_through_the_runner() {
        let (cmux, recorder) = Cmux::recording();
        cmux.set_status("k", "v", StatusStyle::default());
        cmux.clear_status("k");
        cmux.notify("t", "b");

        assert_eq!(
            recorder.calls(),
            vec![
                vec!["set-status", "k", "v"],
                vec!["clear-status", "k"],
                vec!["notify", "--title", "t", "--body", "b"],
            ]
        );
    }

    // --- the guard ---

    #[test]
    fn guard_clears_on_drop_after_a_phase() {
        let (cmux, recorder) = Cmux::recording();
        let mut guard = cmux.guard("build", true);
        guard.phase("Pulling", StatusStyle::default());
        drop(guard);

        assert_eq!(
            recorder.calls(),
            vec![
                vec!["set-status", "build", "Pulling"],
                vec!["clear-status", "build"],
            ]
        );
    }

    #[test]
    fn guard_without_a_phase_clears_nothing() {
        let (cmux, recorder) = Cmux::recording();
        let guard = cmux.guard("build", true);
        drop(guard);
        assert!(recorder.calls().is_empty());
    }

    #[test]
    fn guard_phase_reuses_its_key_and_style() {
        let (cmux, recorder) = Cmux::recording();
        let mut guard = cmux.guard("build", true);
        guard.phase("Pulling", StatusStyle::default());
        guard.phase(
            "Building",
            StatusStyle {
                icon: Some("hammer"),
                ..Default::default()
            },
        );
        drop(guard);

        let calls = recorder.calls();
        assert_eq!(
            calls[1],
            vec!["set-status", "build", "Building", "--icon", "hammer"]
        );
    }

    #[test]
    fn guard_disabled_by_config_is_inert() {
        let (cmux, recorder) = Cmux::recording();
        let mut guard = cmux.guard("build", false);
        assert!(!guard.cmux.available());

        guard.phase("Pulling", StatusStyle::default());
        drop(guard);
        assert!(recorder.calls().is_empty());
    }

    #[test]
    fn guard_disarm_skips_the_clear() {
        let (cmux, recorder) = Cmux::recording();
        let mut guard = cmux.guard("build", true);
        guard.phase("Pulling", StatusStyle::default());
        guard.disarm();
        drop(guard);

        assert_eq!(recorder.calls().len(), 1);
    }

    #[test]
    fn guard_notifies_after_the_threshold_with_the_outcome() {
        let (cmux, recorder) = Cmux::recording();
        let mut guard = cmux
            .guard("build", true)
            .notify_after("dev up", Duration::ZERO);
        guard.succeeded("ready in 3s");
        drop(guard);

        assert_eq!(
            recorder.calls().last(),
            Some(&vec![
                "notify".to_string(),
                "--title".to_string(),
                "dev up".to_string(),
                "--body".to_string(),
                "ready in 3s".to_string(),
            ])
        );
    }

    #[test]
    fn guard_notifies_failed_when_no_outcome_was_recorded() {
        let (cmux, recorder) = Cmux::recording();
        let guard = cmux
            .guard("build", true)
            .notify_after("dev up", Duration::ZERO);
        drop(guard);

        assert_eq!(
            recorder.calls().last(),
            Some(&vec![
                "notify".to_string(),
                "--title".to_string(),
                "dev up".to_string(),
                "--body".to_string(),
                "failed".to_string(),
            ])
        );
    }

    #[test]
    fn guard_stays_quiet_under_the_threshold() {
        let (cmux, recorder) = Cmux::recording();
        let guard = cmux
            .guard("build", true)
            .notify_after("dev up", Duration::from_secs(3600));
        drop(guard);

        assert!(recorder.calls().is_empty());
    }

    #[test]
    fn guard_is_send_and_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<StatusGuard>();
        assert::<Cmux>();
    }
}
