use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// How long a daemon gets to honor SIGTERM before [`kill_and_wait`] stops
/// asking.
const SHUTDOWN_POLLS: u32 = 20;
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);

/// Whether `pid` still names a live process, asked of the kernel rather than
/// of a pid file that may outlive it.
pub(crate) fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// SIGTERM, then SIGKILL if the process is still around two seconds later.
/// The shutdown every daemon `dev` spawns and tracks by pid file gets.
pub(crate) fn kill_and_wait(pid: u32) {
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    for _ in 0..SHUTDOWN_POLLS {
        if !is_process_alive(pid) {
            return;
        }
        std::thread::sleep(SHUTDOWN_POLL);
    }
    if is_process_alive(pid) {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
}

/// Ends this process the way `signal` would have, so a shell loop around
/// `dev` sees it as signalled. A handler for it has to be put back to the
/// default first, or the raise is only caught again. Exiting 128 plus the
/// signal covers a process that somehow outlives the raise.
pub(crate) fn exit_as_signalled(signal: i32) -> ! {
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    std::process::exit(128 + signal)
}

/// Wait for `child` to exit, giving up after `timeout`. `None` means it was
/// still running (or could not be polled) when the deadline passed.
pub(crate) fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
    poll: Duration,
) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(poll);
    }
}

/// How a run under [`output_within`] ended.
#[derive(Debug)]
pub(crate) enum Bounded {
    Exited(std::process::Output),
    /// The budget ran out, and the process group has been stopped.
    TimedOut,
    /// The interrupt arrived with this signal, and the group has been stopped.
    Interrupted(i32),
}

/// How long the output pipes get once the child has exited. A grandchild that
/// still holds one open must not hold the answer up.
const DRAIN_BOUND: Duration = Duration::from_millis(200);

const GROUP_POLL: Duration = Duration::from_millis(20);

/// Runs `command` in a process group of its own and collects its output,
/// unless `budget` runs out or `interrupt` resolves first. Then the whole
/// group is sent SIGTERM, given `grace`, sent SIGKILL if any of it is left,
/// and the child is reaped.
///
/// The group is what reaches ssh's `ProxyCommand` as well as ssh. Being its
/// own group also keeps the terminal's Ctrl-C from reaching it, which is why
/// the caller forwards one through `interrupt`. Dropped before the child is
/// reaped, by a panic or a cancelled caller, it SIGKILLs the group.
pub(crate) async fn output_within(
    mut command: tokio::process::Command,
    budget: Duration,
    grace: Duration,
    interrupt: impl std::future::Future<Output = i32>,
) -> std::io::Result<Bounded> {
    use std::process::Stdio;

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let mut guard = GroupGuard::new(child.id().expect("a child not yet waited on has a pid"));
    let stdout = Collector::start(child.stdout.take());
    let stderr = Collector::start(child.stderr.take());
    let stopped = tokio::select! {
        status = child.wait() => {
            guard.leader_reaped();
            let (stdout, stderr) = tokio::join!(stdout.drain(), stderr.drain());
            return Ok(Bounded::Exited(std::process::Output { status: status?, stdout, stderr }));
        }
        _ = tokio::time::sleep(budget) => Bounded::TimedOut,
        signal = interrupt => Bounded::Interrupted(signal),
    };
    stop_group(&mut child, &mut guard, grace).await;
    Ok(stopped)
}

/// SIGKILLs the group on drop while its leader, the child, is unreaped.
/// `kill_on_drop` reaches only the child, which leaves a `ProxyCommand`
/// running. Once the child is reaped its pid, and so the group id, is free
/// to name a stranger, so a reaped leader disarms this.
struct GroupGuard {
    group: libc::pid_t,
    leader_unreaped: bool,
}

impl GroupGuard {
    fn new(leader: u32) -> Self {
        Self {
            group: leader as libc::pid_t,
            leader_unreaped: true,
        }
    }

    fn leader_reaped(&mut self) {
        self.leader_unreaped = false;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if self.leader_unreaped {
            signal_group(self.group, libc::SIGKILL);
        }
    }
}

/// Reads one output pipe in the background, so whatever arrived can be
/// handed back without waiting for an EOF that may never come.
struct Collector {
    buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    reader: tokio::task::JoinHandle<()>,
}

impl Collector {
    fn start<R>(stream: Option<R>) -> Self
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt;

        let buffer = std::sync::Arc::default();
        let sink = std::sync::Arc::clone(&buffer);
        let reader = tokio::spawn(async move {
            let Some(mut stream) = stream else { return };
            let mut chunk = [0u8; 4096];
            // A read error ends the output the same way EOF does.
            while let Ok(read @ 1..) = stream.read(&mut chunk).await {
                lock(&sink).extend_from_slice(&chunk[..read]);
            }
        });
        Self { buffer, reader }
    }

    /// What arrived by EOF or by [`DRAIN_BOUND`], whichever is first.
    async fn drain(mut self) -> Vec<u8> {
        let _ = tokio::time::timeout(DRAIN_BOUND, &mut self.reader).await;
        std::mem::take(&mut *lock(&self.buffer))
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

fn lock(buffer: &std::sync::Mutex<Vec<u8>>) -> std::sync::MutexGuard<'_, Vec<u8>> {
    buffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The child's pid names the group, and a group's id is not reused while
/// any member is left, so the SIGKILL never reaches a stranger: it is sent
/// only while the child is unreaped or the group still has members.
///
/// The caller's outcome is the reason it stopped the group, so a child that
/// cannot be polled cuts the grace short and a failed reap is not an error.
async fn stop_group(child: &mut tokio::process::Child, guard: &mut GroupGuard, grace: Duration) {
    let group = guard.group;
    signal_group(group, libc::SIGTERM);
    let deadline = tokio::time::Instant::now() + grace;
    while tokio::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => {
                guard.leader_reaped();
                if !signal_group(group, 0) {
                    return;
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
        tokio::time::sleep(GROUP_POLL).await;
    }
    signal_group(group, libc::SIGKILL);
    let _ = child.wait().await;
    guard.leader_reaped();
}

/// Whether the group had a member to signal.
fn signal_group(group: libc::pid_t, signal: libc::c_int) -> bool {
    unsafe { libc::killpg(group, signal) == 0 }
}

/// What `pgrep` finds in process group `group`, for tests that a stopped
/// group left nothing behind.
#[cfg(test)]
pub(crate) fn group_members(group: i32) -> String {
    let found = std::process::Command::new("pgrep")
        .arg("-g")
        .arg(group.to_string())
        .output()
        .expect("pgrep runs");
    String::from_utf8_lossy(&found.stdout).trim().to_string()
}

/// The shells a container's `/bin/sh` may be, for running in-container
/// scripts on the host. Debian's and Ubuntu's `/bin/sh` is dash and Alpine's is
/// busybox ash, so each runs whenever the host has it, alongside the host's own
/// `sh`.
#[cfg(test)]
pub(crate) fn shells() -> Vec<&'static str> {
    let mut shells: Vec<_> = ["sh", "/bin/dash", "/bin/bash"]
        .into_iter()
        .filter(|shell| !shell.starts_with('/') || std::path::Path::new(shell).exists())
        .collect();
    if on_path("busybox") {
        shells.push("busybox sh");
    }
    shells
}

#[cfg(test)]
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Set in the copy of the test binary that is meant to die.
    const DIE_IN_CHILD: &str = "DEV_TEST_EXIT_AS_SIGNALLED";

    /// The raise would end the test process itself, so the test binary runs
    /// again as a child that installs tokio's handler, as `dev` does, and
    /// then calls it.
    #[test]
    fn exit_as_signalled_ends_the_process_by_that_signal_past_a_handler() {
        use std::os::unix::process::ExitStatusExt;
        if std::env::var_os(DIE_IN_CHILD).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _handler = runtime.block_on(async {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            });
            exit_as_signalled(libc::SIGTERM);
        }
        let module = module_path!().split_once("::").unwrap().1;
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "{module}::exit_as_signalled_ends_the_process_by_that_signal_past_a_handler"
            ))
            .env(DIE_IN_CHILD, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
    }

    #[test]
    fn wait_bounded_returns_status_when_child_exits() {
        let mut child = Command::new("true").spawn().expect("spawn true");
        let status = wait_bounded(
            &mut child,
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        assert!(status.expect("exited within timeout").success());
    }

    #[test]
    fn wait_bounded_gives_up_on_a_long_running_child() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let started = Instant::now();
        let status = wait_bounded(
            &mut child,
            Duration::from_millis(300),
            Duration::from_millis(10),
        );
        let _ = child.kill();
        let _ = child.wait();

        assert!(status.is_none(), "should not have waited for the child");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    const BUDGET: Duration = Duration::from_millis(300);
    const GRACE: Duration = Duration::from_millis(400);
    /// Room for scheduling on top of a bound a test applies.
    const SLACK: Duration = Duration::from_secs(2);
    /// Far past every bound a test here applies, so a deleted bound fails
    /// the test instead of hanging it.
    const GUARD: Duration = Duration::from_secs(20);

    /// `None` when the guard ran out. Tests kill the group before they look,
    /// so a guard that fires leaves none of it running.
    async fn guarded(
        run: impl std::future::Future<Output = std::io::Result<Bounded>>,
    ) -> Option<Bounded> {
        let ended = tokio::time::timeout(GUARD, run).await.ok()?;
        Some(ended.expect("output_within ran"))
    }

    fn read_pid(path: &std::path::Path) -> i32 {
        std::fs::read_to_string(path)
            .expect("the child wrote its pid")
            .trim()
            .parse()
            .unwrap()
    }

    fn script(body: &str, dir: &std::path::Path) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg(body).arg("sh").arg(dir);
        command
    }

    fn never() -> std::future::Pending<i32> {
        std::future::pending()
    }

    /// A child that notes each SIGTERM in `marker` and carries on, over two
    /// grandchildren in its group standing in for ssh's `ProxyCommand`.
    const IGNORES_TERM: &str = r#"trap 'echo term >> "$1/marker"' TERM
echo $$ > "$1/child.pid"
sleep 3017 &
sleep 3017 &
while :; do sleep 0.05; done"#;

    #[tokio::test]
    async fn a_group_that_outlasts_the_budget_gets_term_then_kill_and_nothing_is_left() {
        let tmp = tempfile::tempdir().unwrap();
        let started = Instant::now();

        let ended = guarded(output_within(
            script(IGNORES_TERM, tmp.path()),
            BUDGET,
            GRACE,
            never(),
        ))
        .await;

        let elapsed = started.elapsed();
        let group = read_pid(&tmp.path().join("child.pid"));
        let left = group_members(group);
        unsafe { libc::killpg(group, libc::SIGKILL) };
        let ended = ended.expect("output_within outlasted its bounds");
        assert!(matches!(ended, Bounded::TimedOut), "{ended:?}");
        let marker = std::fs::read_to_string(tmp.path().join("marker")).unwrap_or_default();
        assert_eq!(marker, "term\n", "SIGTERM came first, once");
        assert!(elapsed >= BUDGET + GRACE, "KILL waited out the grace");
        assert!(elapsed < BUDGET + GRACE + SLACK, "{elapsed:?}");
        assert_eq!(left, "", "the whole group is gone");
    }

    #[tokio::test]
    async fn a_group_that_honors_term_is_not_waited_on_for_the_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let body = r#"trap 'echo term > "$1/marker"; exit 0' TERM
echo $$ > "$1/child.pid"
sleep 3018 &
while :; do sleep 0.05; done"#;
        let started = Instant::now();

        let ended = guarded(output_within(
            script(body, tmp.path()),
            BUDGET,
            GRACE,
            never(),
        ))
        .await;

        let group = read_pid(&tmp.path().join("child.pid"));
        let left = group_members(group);
        unsafe { libc::killpg(group, libc::SIGKILL) };
        let ended = ended.expect("output_within outlasted its bounds");
        assert!(matches!(ended, Bounded::TimedOut), "{ended:?}");
        let marker = std::fs::read_to_string(tmp.path().join("marker")).unwrap_or_default();
        assert_eq!(marker, "term\n");
        assert!(started.elapsed() < BUDGET + GRACE);
        assert_eq!(left, "", "the grandchild got the TERM too");
    }

    #[tokio::test]
    async fn a_forwarded_interrupt_stops_the_group() {
        let tmp = tempfile::tempdir().unwrap();
        let body = r#"echo $$ > "$1/child.pid"
sleep 3019 &
sleep 3019 &
wait"#;
        let interrupt_at = Duration::from_millis(200);
        let interrupt = async move {
            tokio::time::sleep(interrupt_at).await;
            libc::SIGINT
        };
        let started = Instant::now();

        let ended = guarded(output_within(
            script(body, tmp.path()),
            Duration::from_secs(30),
            GRACE,
            interrupt,
        ))
        .await;

        let elapsed = started.elapsed();
        let group = read_pid(&tmp.path().join("child.pid"));
        let left = group_members(group);
        unsafe { libc::killpg(group, libc::SIGKILL) };
        let ended = ended.expect("output_within outlasted its bounds");
        assert!(
            matches!(ended, Bounded::Interrupted(libc::SIGINT)),
            "{ended:?}"
        );
        assert!(elapsed >= interrupt_at, "{elapsed:?}");
        assert!(elapsed < interrupt_at + GRACE + SLACK, "{elapsed:?}");
        assert_eq!(left, "", "the whole group is gone");
    }

    async fn until_exists(path: &std::path::Path) {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// `mv` so the pid file is never seen half written.
    const SPAWNS_GRANDCHILD: &str = r#"echo $$ > "$1/child.pid"
sleep 3021 &
echo $! > "$1/grandchild.tmp"
mv "$1/grandchild.tmp" "$1/grandchild.pid"
wait"#;

    /// Stands in for `dev status` panicking mid round trip.
    #[tokio::test]
    async fn a_run_dropped_before_the_child_is_reaped_kills_the_whole_group() {
        let tmp = tempfile::tempdir().unwrap();
        let mut run = Box::pin(output_within(
            script(SPAWNS_GRANDCHILD, tmp.path()),
            Duration::from_secs(30),
            GRACE,
            never(),
        ));
        let grandchild_pid = tmp.path().join("grandchild.pid");
        let ready = tokio::time::timeout(GUARD, async {
            tokio::select! {
                ended = &mut run => panic!("ended by itself: {ended:?}"),
                _ = until_exists(&grandchild_pid) => {}
            }
        })
        .await;

        drop(run);

        let group = read_pid(&tmp.path().join("child.pid"));
        let grandchild = read_pid(&grandchild_pid);
        let gone = gone_within(grandchild, SLACK).await;
        unsafe { libc::killpg(group, libc::SIGKILL) };
        unsafe { libc::kill(grandchild, libc::SIGKILL) };
        ready.expect("the grandchild started");
        assert!(gone, "the grandchild outlived the dropped run");
    }

    async fn gone_within(pid: i32, patience: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + patience;
        while is_process_alive(pid as u32) {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    /// A leader reaped behind tokio's back makes `try_wait` fail. The group
    /// still has a member that ignores SIGTERM, and it still gets SIGKILL.
    #[tokio::test]
    async fn a_child_that_cannot_be_polled_still_has_its_group_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let body = r#"trap '' TERM
sleep 3022 &
echo $! > "$1/grandchild.tmp"
mv "$1/grandchild.tmp" "$1/grandchild.pid"
exit 0"#;
        let mut child = script(body, tmp.path()).process_group(0).spawn().unwrap();
        let mut guard = GroupGuard::new(child.id().unwrap());
        let group = guard.group;
        unsafe { libc::waitpid(group, std::ptr::null_mut(), 0) };
        let grandchild = read_pid(&tmp.path().join("grandchild.pid"));
        assert!(
            child.try_wait().is_err(),
            "the reap behind tokio's back took"
        );

        let stopped = tokio::time::timeout(GUARD, stop_group(&mut child, &mut guard, GRACE)).await;

        let left = group_members(group);
        unsafe { libc::killpg(group, libc::SIGKILL) };
        stopped.expect("stop_group outlasted its bounds");
        assert_eq!(left, "", "the group got SIGKILL: {grandchild}");
    }

    #[tokio::test]
    async fn a_child_inside_the_budget_hands_back_its_output() {
        let tmp = tempfile::tempdir().unwrap();
        let command = script("echo out; echo err >&2; exit 3", tmp.path());

        let ended = guarded(output_within(
            command,
            Duration::from_secs(10),
            GRACE,
            never(),
        ))
        .await;

        let Some(Bounded::Exited(output)) = ended else {
            panic!("finished inside the budget: {ended:?}");
        };
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
    }

    /// ssh can exit while its `ProxyCommand` still holds stderr; the answer
    /// is ssh's own, not a timeout.
    #[tokio::test]
    async fn a_grandchild_holding_stderr_does_not_hold_up_the_childs_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let body = r#"echo out; echo err >&2
sleep 3020 &
echo $! > "$1/grandchild.pid"
exit 5"#;
        let budget = Duration::from_secs(10);
        let started = Instant::now();

        let ended = guarded(output_within(
            script(body, tmp.path()),
            budget,
            GRACE,
            never(),
        ))
        .await;

        let elapsed = started.elapsed();
        let grandchild = read_pid(&tmp.path().join("grandchild.pid"));
        let grandchild_alive = is_process_alive(grandchild as u32);
        unsafe { libc::kill(grandchild, libc::SIGKILL) };
        let Some(Bounded::Exited(output)) = ended else {
            panic!("the child exited: {ended:?}");
        };
        assert_eq!(output.status.code(), Some(5));
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
        assert!(grandchild_alive, "the pipe really was still held");
        assert!(elapsed < DRAIN_BOUND + SLACK, "{elapsed:?}");
    }
}
