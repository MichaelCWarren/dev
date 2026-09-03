use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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
}
