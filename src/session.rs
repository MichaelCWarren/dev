//! Tracking, and reaping, the container-side processes `dev` starts for a client.
//!
//! An exec has no client-disconnect signal. The daemon owns the pty master and
//! holds it open whether or not anything reads the other end, so when the
//! client's hijacked stream drops — a closed terminal, a `kill -9`, a VM
//! suspended with the Mac asleep — the container's shell sees a healthy pty
//! that simply never delivers input again, and runs forever. Nothing in the
//! interactive path can notice: every way that loop ends means the *container*
//! side finished.
//!
//! So each session records itself inside the container before handing over to
//! the real command, and a later `dev` invocation reads those records back,
//! asks the host which clients are still alive, and hangs up the rest. A marker
//! is one line at `/tmp/.dev-session-<pid>`:
//!
//! ```text
//! <container-pid> <container-sid> <host-pid> <host-start> <kind> <host-tty>
//! ```
//!
//! The host fields answer "is the client that owns this still running", and the
//! container fields say what to signal. Both are needed: a pid alone is
//! ambiguous once pids are reused, and a session leader alone cannot be found
//! from the host.

use std::collections::HashMap;

use crate::error::DevError;
use crate::runtime::ContainerRuntime;

/// Where a session's marker lives inside the container.
///
/// `/tmp` is world-writable on every image, so this needs no directory to be
/// created and no ownership arrangement between users sharing a container.
const MARKER_PREFIX: &str = "/tmp/.dev-session-";

/// What a marker's process is for, so a reap can be reported in the terms the
/// user recognises and `dev status` can separate a shell from plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// An interactive `dev shell`.
    Shell,
    /// A one-off command run by `dev exec`.
    Exec,
    /// One connection's netcat relay, started by `dev forward`.
    Forward,
}

impl SessionKind {
    fn as_str(self) -> &'static str {
        match self {
            SessionKind::Shell => "shell",
            SessionKind::Exec => "exec",
            SessionKind::Forward => "forward",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "shell" => Some(SessionKind::Shell),
            "exec" => Some(SessionKind::Exec),
            "forward" => Some(SessionKind::Forward),
            _ => None,
        }
    }
}

/// One recorded session, as read back out of the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMarker {
    /// The wrapper's pid inside the container. Survives its `exec`, so it is
    /// still the pid of whatever replaced it.
    pub container_pid: u32,
    /// The wrapper's session id, read from `/proc` rather than assumed: a TTY
    /// exec is a session leader (so this equals `container_pid`), but a
    /// plain one need not be, and mistaking PID 1's session for our own would
    /// turn a reap into killing the container.
    pub container_sid: u32,
    /// The `dev` process on this Mac that owns the session.
    pub host_pid: u32,
    /// An opaque token for when `host_pid` started, or `-` if it could not be
    /// read. Distinguishes the client from a later process wearing its pid.
    pub host_start: String,
    pub kind: SessionKind,
    /// The client's controlling terminal, or `-`. Purely for display: it is
    /// what lets someone tell their live shell from an abandoned one.
    pub host_tty: String,
}

impl SessionMarker {
    /// Whether signalling this session means signalling a whole session, or
    /// only a process tree.
    ///
    /// Killing a `dev shell` by session is the only thing that works: an
    /// interactive zsh puts each job in its own process group, so killing the
    /// leader alone reparents `claude` to PID 1 and leaves it running. But that
    /// is safe only because the leader *is* the session — for anything else,
    /// the session belongs to someone other than us.
    fn kill_mode(&self) -> char {
        if self.container_sid == self.container_pid && self.container_pid > 1 {
            's'
        } else {
            't'
        }
    }

    fn target(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kill_mode(),
            self.container_pid,
            self.container_sid
        )
    }
}

/// The `dev` process a session will belong to.
#[derive(Debug, Clone)]
pub struct HostIdentity {
    pub pid: u32,
    pub start: String,
    pub tty: String,
}

/// Describe this process for the marker it is about to write.
pub async fn host_identity() -> HostIdentity {
    let pid = std::process::id();
    let start = process_start_tokens(&[pid])
        .await
        .remove(&pid)
        .unwrap_or_else(|| UNKNOWN.to_string());
    HostIdentity {
        pid,
        start,
        tty: controlling_tty(),
    }
}

/// Shell prefixed to a session's command so it records itself before starting.
///
/// Every value interpolated here is either a number or has been through
/// [`sanitize`], so the guest shell has nothing to expand and the marker stays
/// one line of six fields. A container that cannot be written to — a read-only
/// `/tmp`, no `/proc` — silently records nothing rather than failing the
/// session the user asked for.
pub fn register_script(kind: SessionKind, host: &HostIdentity) -> String {
    format!(
        "__dev_sid=$(sed -n 's/.*) //p' /proc/$$/stat 2>/dev/null | cut -d' ' -f4); \
         printf '%s %s %s %s %s %s\\n' \"$$\" \"${{__dev_sid:-0}}\" \
         '{pid}' '{start}' '{kind}' '{tty}' > {MARKER_PREFIX}$$ 2>/dev/null || :; ",
        pid = host.pid,
        start = sanitize(&host.start),
        kind = kind.as_str(),
        tty = sanitize(&host.tty),
    )
}

/// Wrap a command so it records itself, then becomes that command.
///
/// The caller's words are passed to the shell as arguments and reached through
/// `"$@"`, never pasted into the script — so a command holding spaces, quotes
/// or `;` arrives exactly as it was written, with no quoting for this to get
/// wrong. `exec` then replaces the shell, which keeps the recorded pid the
/// command's own and leaves its exit status, signals and streams untouched.
///
/// Costs an image with `/bin/sh`. Callers that may run without one should be
/// ready to fall back to the bare command, recording nothing.
pub fn registered_command(cmd: &[String], kind: SessionKind, host: &HostIdentity) -> Vec<String> {
    let register = register_script(kind, host);
    let mut wrapped = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("{register}exec \"$@\""),
        format!("dev-{}", kind.as_str()),
    ];
    wrapped.extend_from_slice(cmd);
    wrapped
}

/// Remove a session's own marker on the way out.
///
/// A session that can run this is one that never `exec`s away, so it is the
/// only kind that can clean up after itself. Anything else leaves its marker
/// for a sweep to collect once its process is gone.
pub fn unregister_script() -> String {
    format!("rm -f {MARKER_PREFIX}$$ 2>/dev/null || :; ")
}

/// Read back the sessions this container still has processes for, discarding
/// the records of those it does not.
///
/// A record cannot remove itself: a `dev shell` `exec`s the user's login shell,
/// so once the session is under way there is nothing of `dev`'s left in the
/// container to clean up after it, and a session hung up on a signal is still
/// dying as its owner exits. Reading is therefore the moment the container can
/// be asked which records still mean something — which keeps `dev status` from
/// showing a shell the user closed themselves as abandoned, and keeps a sweep
/// from counting it as reaped.
pub async fn read_markers(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> Result<Vec<SessionMarker>, DevError> {
    let script = format!(
        "for f in {MARKER_PREFIX}*; do [ -f \"$f\" ] || continue; \
         if [ -d \"/proc/${{f#{MARKER_PREFIX}}}\" ]; then cat \"$f\"; else rm -f \"$f\"; fi; done"
    );
    let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), script];
    let result = runtime.exec(container_id, &cmd, user, None).await?;
    Ok(parse_markers(&result.stdout))
}

/// Split marker output into the sessions whose client is gone and those still
/// held by a running `dev`.
///
/// The failure direction matters more than the accuracy: a live client's pid
/// cannot be reused while it holds it, so a session can never be reaped out
/// from under someone. The start-token comparison only stops a *reused* pid —
/// after a reboot, say — from making an orphan look alive forever.
pub fn partition_by_liveness(
    markers: Vec<SessionMarker>,
    alive: impl Fn(u32, &str) -> bool,
) -> (Vec<SessionMarker>, Vec<SessionMarker>) {
    markers
        .into_iter()
        .partition(|marker| !alive(marker.host_pid, &marker.host_start))
}

/// Hang up the given sessions, and clear the markers of any already gone.
///
/// `escalate` follows the hangup with a wait and a kill for whatever ignored
/// it. A sweep wants that; a client tearing down its own session does not,
/// because it is the thing being waited on.
///
/// Answers how many sessions were still running to be signalled — which is not
/// the number asked about, since a marker can outlive its process and only the
/// container can tell the difference.
pub async fn kill_sessions(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    sessions: &[SessionMarker],
    escalate: bool,
) -> Result<usize, DevError> {
    if sessions.is_empty() {
        return Ok(0);
    }
    let mut cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        KILL_SCRIPT.to_string(),
        "dev-reap".to_string(),
        if escalate { "1" } else { "0" }.to_string(),
    ];
    cmd.extend(sessions.iter().map(SessionMarker::target));
    let result = runtime.exec(container_id, &cmd, user, None).await?;
    Ok(parse_reaped(&result.stdout))
}

/// How many sessions the reaper reported signalling.
///
/// Anything unreadable counts as none: over-reporting a reap invites someone to
/// go looking for processes that were never there.
fn parse_reaped(stdout: &str) -> usize {
    stdout
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("reaped="))
        .and_then(|count| count.parse().ok())
        .unwrap_or(0)
}

/// Reap every session in this container whose client is gone.
///
/// Returns how many were reaped, for the caller to report.
pub async fn sweep(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> Result<usize, DevError> {
    let markers = read_markers(runtime, container_id, user).await?;
    if markers.is_empty() {
        return Ok(0);
    }
    let starts = client_start_tokens(&markers).await;
    let (orphaned, _live) = partition_by_liveness(markers, |pid, recorded| {
        client_is_alive(pid, recorded, &starts)
    });
    kill_sessions(runtime, container_id, user, &orphaned, true).await
}

/// Give up the sessions this process owns: hang up any still running, and
/// clear the records of those already finished.
///
/// Both halves matter, and which one does the work depends on how `dev` is
/// leaving. On a signal the container's shell is still there, and would become
/// exactly the orphan this module exists to collect. On a clean exit it is
/// already gone, but its record cannot remove itself — the session `exec`s the
/// user's shell, so nothing of `dev`'s is left in the container to run — and a
/// record left behind would have `dev status` describing a shell the user
/// closed themselves as abandoned.
///
/// Failure is not worth reporting: the process is on its way out, and a sweep
/// collects whatever this missed.
pub async fn release_own_sessions(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    host_pid: u32,
) {
    let Ok(markers) = read_markers(runtime, container_id, user).await else {
        return;
    };
    let mine: Vec<SessionMarker> = markers
        .into_iter()
        .filter(|marker| marker.host_pid == host_pid)
        .collect();
    let _ = kill_sessions(runtime, container_id, user, &mine, false).await;
}

/// Pair every recorded session with whether its client is still running.
pub async fn list_sessions(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> Result<Vec<(SessionMarker, bool)>, DevError> {
    let markers = read_markers(runtime, container_id, user).await?;
    let starts = client_start_tokens(&markers).await;
    Ok(markers
        .into_iter()
        .map(|marker| {
            let live = client_is_alive(marker.host_pid, &marker.host_start, &starts);
            (marker, live)
        })
        .collect())
}

/// When each of the clients these markers name started.
///
/// Collected in one `ps` call so a sweep costs one child process rather than
/// one per session.
async fn client_start_tokens(markers: &[SessionMarker]) -> HashMap<u32, String> {
    let pids: Vec<u32> = markers.iter().map(|marker| marker.host_pid).collect();
    process_start_tokens(&pids).await
}

/// Whether the `dev` process that owns a session is still running.
fn client_is_alive(pid: u32, recorded: &str, starts: &HashMap<u32, String>) -> bool {
    if !pid_exists(pid) {
        return false;
    }
    match starts.get(&pid) {
        // Neither side knowing when it started leaves the pid itself as the
        // only evidence, and a running pid is the safe answer.
        Some(current) if current != UNKNOWN && recorded != UNKNOWN => current == recorded,
        _ => true,
    }
}

/// The value stood in for a start token or a terminal that could not be read.
const UNKNOWN: &str = "-";

/// Whether a pid is running, counting one owned by another user.
fn pid_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 performs the permission and existence checks without
    // delivering anything.
    let sent = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if sent == 0 {
        return true;
    }
    // Existing but not ours to signal still means existing.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// When each of these pids started, as an opaque comparable token.
async fn process_start_tokens(pids: &[u32]) -> HashMap<u32, String> {
    let mut tokens = HashMap::new();
    if pids.is_empty() {
        return tokens;
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let Ok(output) = tokio::process::Command::new("ps")
        .args(["-o", "pid=,lstart=", "-p", &list])
        .output()
        .await
    else {
        return tokens;
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let line = line.trim();
        let Some((pid, start)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        tokens.insert(pid, sanitize(start));
    }
    tokens
}

/// This process's controlling terminal, named the way `ps` names it.
fn controlling_tty() -> String {
    // SAFETY: `ttyname` returns a pointer to storage owned by libc, valid until
    // the next call from this thread; it is copied out before returning.
    let name = unsafe {
        let raw = libc::ttyname(libc::STDIN_FILENO);
        if raw.is_null() {
            return UNKNOWN.to_string();
        }
        std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned()
    };
    let name = name.strip_prefix("/dev/").unwrap_or(&name);
    sanitize(name)
}

/// Reduce a value to something that can be a marker field.
///
/// Marker fields are read back by splitting on whitespace, and are written by a
/// shell. Collapsing everything outside a known-inert set removes both problems
/// at once: no field can gain a space, and none can carry a quote or a
/// metacharacter into the script that writes it.
fn sanitize(value: &str) -> String {
    let mapped: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '+' | '-' | '_' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() {
        UNKNOWN.to_string()
    } else {
        mapped
    }
}

/// Parse marker lines, discarding any that are not a complete record.
///
/// A partial line is a session that was recorded while being read, or a file
/// truncated by a container that ran out of space. Guessing at one risks
/// signalling a pid that was never ours, so it is dropped and left for the next
/// sweep to read whole.
fn parse_markers(stdout: &str) -> Vec<SessionMarker> {
    stdout.lines().filter_map(parse_marker).collect()
}

fn parse_marker(line: &str) -> Option<SessionMarker> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [
        container_pid,
        container_sid,
        host_pid,
        host_start,
        kind,
        host_tty,
    ] = fields[..]
    else {
        return None;
    };
    let container_pid = container_pid.parse().ok()?;
    if container_pid <= 1 {
        return None;
    }
    Some(SessionMarker {
        container_pid,
        container_sid: container_sid.parse().ok()?,
        host_pid: host_pid.parse().ok()?,
        host_start: host_start.to_string(),
        kind: SessionKind::parse(kind)?,
        host_tty: host_tty.to_string(),
    })
}

/// Signal recorded sessions, from inside the container.
///
/// Written against `/proc` and POSIX `sh` alone: `pkill -s` is the natural way
/// to end a session, but busybox images have no such option and the images
/// `dev` runs are not its own to choose.
///
/// Each target is `<mode>:<pid>:<sid>`, and every one is re-checked against
/// `/proc` before anything is signalled — a recorded pid that has since been
/// reused inside the container no longer sits in the session it was recorded
/// with, and is skipped. PID 1 and session 1 are never signalled under any
/// reading of the arguments.
const KILL_SCRIPT: &str = r#"
esc=$1; shift
field() { sed -n 's/.*) //p' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f"$2"; }
sig() { [ "$1" -gt 1 ] 2>/dev/null && [ "$1" != "$$" ] && kill -"$2" "$1" 2>/dev/null; :; }
leaders=""
members=""
reaped=0
for t in "$@"; do
  mode=${t%%:*}; rest=${t#*:}; pid=${rest%%:*}; sid=${rest##*:}
  case $mode in s|t) ;; *) continue ;; esac
  [ "$pid" -gt 1 ] 2>/dev/null || continue
  # Listed before the session check, so a marker left by a session that is
  # already gone is still cleared rather than lingering to be re-counted.
  leaders="$leaders $pid"
  [ "$sid" = "$(field "$pid" 4)" ] || continue
  reaped=$((reaped+1))
  found=""
  if [ "$mode" = s ] && [ "$sid" -gt 1 ] 2>/dev/null; then
    for d in /proc/[0-9]*; do
      p=${d#/proc/}
      [ "$(field "$p" 4)" = "$sid" ] && found="$found $p"
    done
  else
    found="$pid"; frontier="$pid"; n=0
    while [ -n "$frontier" ] && [ "$n" -lt 16 ]; do
      n=$((n+1)); next=""
      for d in /proc/[0-9]*; do
        p=${d#/proc/}
        pp=$(field "$p" 2)
        for f in $frontier; do
          [ "$pp" = "$f" ] || continue
          case " $found " in *" $p "*) ;; *) found="$found $p"; next="$next $p" ;; esac
        done
      done
      frontier=$next
    done
  fi
  for p in $found; do sig "$p" HUP; done
  members="$members $found"
done
if [ "$esc" = 1 ] && [ -n "$members" ]; then
  sleep 2
  for p in $members; do [ -d "/proc/$p" ] && sig "$p" KILL; done
fi
for pid in $leaders; do [ -d "/proc/$pid" ] || rm -f "/tmp/.dev-session-$pid"; done
echo "reaped=$reaped"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(container_pid: u32, container_sid: u32, host_pid: u32) -> SessionMarker {
        SessionMarker {
            container_pid,
            container_sid,
            host_pid,
            host_start: "Tue_Aug__5_08:56:01_2026".to_string(),
            kind: SessionKind::Shell,
            host_tty: "ttys016".to_string(),
        }
    }

    #[test]
    fn a_recorded_session_round_trips_through_its_marker_line() {
        let line = "720 720 4131 Tue_Aug__5_08:56:01_2026 shell ttys016";
        assert_eq!(
            parse_marker(line),
            Some(SessionMarker {
                container_pid: 720,
                container_sid: 720,
                host_pid: 4131,
                host_start: "Tue_Aug__5_08:56:01_2026".to_string(),
                kind: SessionKind::Shell,
                host_tty: "ttys016".to_string(),
            })
        );
    }

    /// Anything short of a whole record names a pid this cannot vouch for.
    #[test]
    fn an_incomplete_or_unparseable_record_is_dropped() {
        for line in [
            "",
            "720",
            "720 720 4131 start shell",
            "720 720 4131 start shell ttys016 extra",
            "720 720 4131 start telnet ttys016",
            "seven 720 4131 start shell ttys016",
            "720 720 four start shell ttys016",
        ] {
            assert_eq!(parse_marker(line), None, "should not parse: {line:?}");
        }
    }

    /// PID 1 is the container. A marker naming it is corrupt by construction,
    /// and acting on one would end everything running in there.
    #[test]
    fn a_marker_naming_init_is_refused() {
        assert_eq!(parse_marker("1 1 4131 start shell ttys016"), None);
        assert_eq!(parse_marker("0 0 4131 start shell ttys016"), None);
    }

    #[test]
    fn only_a_session_leader_is_signalled_by_session() {
        // A TTY exec: the wrapper is its own session, so ending the session
        // ends the shell's jobs with it.
        assert_eq!(marker(720, 720, 4131).kill_mode(), 's');
        // A plain exec that never got its own session sits in someone else's —
        // PID 1's, typically. Only its own descendants are ours to end.
        assert_eq!(marker(9042, 1, 4131).kill_mode(), 't');
        assert_eq!(marker(9042, 0, 4131).kill_mode(), 't');
        assert_eq!(marker(9042, 8100, 4131).kill_mode(), 't');
    }

    #[test]
    fn a_session_is_orphaned_when_its_client_is_gone() {
        let markers = vec![marker(720, 720, 4131), marker(1738, 1738, 9002)];
        let (orphaned, live) = partition_by_liveness(markers, |pid, _| pid == 4131);
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].host_pid, 9002);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].host_pid, 4131);
    }

    /// The whole point of the start token: a client's pid outliving it, taken
    /// up by something unrelated, must not keep an orphan looking alive.
    #[test]
    fn a_reused_client_pid_does_not_keep_a_session_alive() {
        let mut stale = marker(720, 720, 4131);
        stale.host_start = "Mon_Aug__4_11:00:00_2026".to_string();
        let (orphaned, live) = partition_by_liveness(vec![stale], |_, recorded| {
            recorded == "Tue_Aug__5_08:56:01_2026"
        });
        assert_eq!(orphaned.len(), 1);
        assert!(live.is_empty());
    }

    #[test]
    fn a_registered_session_writes_one_inert_line() {
        let host = HostIdentity {
            pid: 4131,
            start: "Tue Aug  5 08:56:01 2026".to_string(),
            tty: "ttys016".to_string(),
        };
        let script = register_script(SessionKind::Shell, &host);
        assert!(script.contains("'4131' 'Tue_Aug__5_08:56:01_2026' 'shell' 'ttys016'"));
        assert!(script.contains("> /tmp/.dev-session-$$"));
        // A container that cannot record must still run what was asked of it.
        assert!(script.contains("|| :;"));
    }

    /// Marker fields reach the guest inside a shell script and come back split
    /// on whitespace, so a value carrying either must not survive as itself.
    #[test]
    fn a_hostile_identity_field_cannot_escape_its_marker() {
        for hostile in [
            "'; rm -rf /; '",
            "a b c",
            "`id`",
            "$(id)",
            "a\nb",
            "a|b",
            "a;b",
        ] {
            let clean = sanitize(hostile);
            assert!(
                clean
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric()
                        || matches!(c, '.' | ':' | '+' | '-' | '_' | '/')),
                "{hostile:?} sanitized to {clean:?}"
            );
            assert!(!clean.contains(char::is_whitespace));
        }
        assert_eq!(sanitize(""), "-");
    }

    #[test]
    fn a_kill_target_names_its_mode_pid_and_session() {
        assert_eq!(marker(720, 720, 4131).target(), "s:720:720");
        assert_eq!(marker(9042, 1, 4131).target(), "t:9042:1");
    }

    /// A marker can outlive the process that wrote it — a session hung up on
    /// the way out leaves one behind — so the count that gets reported is the
    /// container's, not the number of markers that looked stale.
    #[test]
    fn the_reap_count_comes_from_what_was_actually_signalled() {
        assert_eq!(parse_reaped("reaped=3\n"), 3);
        assert_eq!(parse_reaped("some noise\nreaped=0\n"), 0);
        assert_eq!(parse_reaped(""), 0);
        assert_eq!(parse_reaped("reaped=lots"), 0);
    }

    /// The reaper runs in whatever shell the image has, against whatever
    /// process table it finds. These are the invariants that keep a reap from
    /// becoming an outage.
    #[test]
    fn the_reaper_refuses_the_container_itself() {
        assert!(KILL_SCRIPT.contains(r#"[ "$1" -gt 1 ]"#));
        assert!(KILL_SCRIPT.contains(r#"[ "$sid" -gt 1 ]"#));
        // A target naming PID 1 would otherwise reach the tree walk, whose
        // descendants are every process in the container.
        assert!(KILL_SCRIPT.contains(r#"[ "$pid" -gt 1 ] 2>/dev/null || continue"#));
        // An unreadable mode is skipped rather than falling through to one.
        assert!(KILL_SCRIPT.contains(r#"case $mode in s|t) ;; *) continue ;; esac"#));
        // Its own pid is not a candidate either.
        assert!(KILL_SCRIPT.contains(r#"[ "$1" != "$$" ]"#));
        // A recorded pid is only signalled while it still sits in the session
        // it was recorded with.
        assert!(KILL_SCRIPT.contains(r#"[ "$sid" = "$(field "$pid" 4)" ] || continue"#));
        // `comm` can hold spaces and parentheses, so fields are taken after the
        // last `)` rather than counted from the left.
        assert!(KILL_SCRIPT.contains(r#"sed -n 's/.*) //p'"#));
    }
}
