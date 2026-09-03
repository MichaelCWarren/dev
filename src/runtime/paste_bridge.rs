//! Carries a pasted file from this host into the container so the path the
//! terminal pasted resolves on the far side.
//!
//! A terminal such as cmux turns a clipboard image into a temp file and
//! pastes its path. Inside a container that path names nothing, so Claude
//! Code cannot attach it. Each file the paste names is read here and handed
//! to the session peer, which delivers it however that runtime does exec;
//! the paste is then rewritten to point at the copy. Anything that is not
//! an existing file on this host is left exactly as it arrived.

use super::terminal_input::{container_paste_path, pasted_files, rewrite_paste};
use super::terminal_relay::SessionPeer;
use crate::error::DevError;

/// How long a single file's copy-in has to finish before this gives up on it. The
/// relay does not pump container output or answer SIGWINCH while a copy is in
/// flight, so an unbounded copy would freeze the whole session.
const COPY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct PasteBridge<'a> {
    peer: &'a dyn SessionPeer,
}

impl<'a> PasteBridge<'a> {
    pub fn new(peer: &'a dyn SessionPeer) -> Self {
        Self { peer }
    }

    /// The paste to forward, markers restored, with every host file it
    /// named now naming its copy in the container. A file that could not
    /// be copied, or that timed out, keeps its host path and the failure
    /// is reported on stderr.
    pub async fn translate(&self, paste: &[u8]) -> Vec<u8> {
        let mut replacements = Vec::new();
        for file in pasted_files(paste) {
            let target = container_paste_path(&file.host_path);
            match self.copy_file(&file.host_path, &target).await {
                Ok(()) => replacements.push((file.span, target)),
                // The terminal is in raw mode, so a bare newline would staircase.
                Err(e) => eprint!(
                    "\r\ndev: could not copy {} into the container: {e}\r\n",
                    file.host_path.display()
                ),
            }
        }
        rewrite_paste(paste, &replacements)
    }

    /// Reads the host file and hands it to the peer, bounded by [`COPY_TIMEOUT`] so a
    /// peer that never resolves cannot wedge `translate`.
    async fn copy_file(&self, host_path: &std::path::Path, target: &str) -> Result<(), String> {
        let bytes = std::fs::read(host_path).map_err(|e| {
            DevError::Runtime(format!("read {}: {e}", host_path.display())).to_string()
        })?;
        match tokio::time::timeout(COPY_TIMEOUT, self.peer.copy_in(bytes, target)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err(format!("timed out after {}s", COPY_TIMEOUT.as_secs())),
        }
    }
}

/// Writes stdin to `target`, creating its directory first. The path travels
/// as an argument, never through the shell text.
pub(crate) fn receive_file_command(target: &str) -> Vec<String> {
    [
        "sh",
        "-c",
        r#"mkdir -p "$(dirname "$1")" && cat > "$1""#,
        "sh",
        target,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::test_peer::{RecordingPeer, Reply};
    use std::time::Duration;
    use tempfile::TempDir;

    fn escaped(path: &std::path::Path) -> String {
        path.to_str().unwrap().replace(' ', "\\ ")
    }

    /// The argv `receive_file_command` builds must carry the target as its
    /// own argument, never formatted into the `-c` shell text — that is what
    /// lets it survive a shell-hostile target unescaped.
    #[test]
    fn receive_file_command_carries_the_target_as_an_argument() {
        let target = "/tmp/dev-paste/a b'c.png";
        let argv = receive_file_command(target);
        assert_eq!(
            argv,
            vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"mkdir -p "$(dirname "$1")" && cat > "$1""#.to_string(),
                "sh".to_string(),
                target.to_string(),
            ],
            "the argv shape must stay exactly five elements with target last"
        );
        assert!(
            !argv[2].contains(target),
            "the target must never be formatted into the -c shell text"
        );
    }

    /// A file this host can see is read whole, handed to the peer under the
    /// sanitised container target, and the paste is rewritten to name it.
    #[tokio::test]
    async fn an_existing_file_is_read_and_handed_to_the_peer() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a file.png");
        std::fs::write(&path, b"file bytes").unwrap();
        let body = escaped(&path);

        let peer = RecordingPeer::accepting();
        let out = PasteBridge::new(&peer).translate(body.as_bytes()).await;

        let target = container_paste_path(&path);
        assert_eq!(
            peer.copies.lock().unwrap().as_slice(),
            &[(target.clone(), b"file bytes".to_vec())],
            "the peer must receive exactly the file's bytes and the sanitised target"
        );
        assert_eq!(
            out,
            rewrite_paste(body.as_bytes(), &[(0..body.len(), target)]),
            "the forwarded paste must name the container target, not the host path"
        );
    }

    /// A path the location guard in `terminal_input.rs` rejects (here,
    /// simply one that does not exist) must never reach `copy_in`.
    #[tokio::test]
    async fn a_path_that_is_not_a_file_here_is_left_alone() {
        let peer = RecordingPeer::accepting();
        let body: &[u8] = b"/nowhere/at/all/shot.png";

        let out = PasteBridge::new(&peer).translate(body).await;

        assert!(
            peer.copies.lock().unwrap().is_empty(),
            "a path the finder rejected must never trigger a copy"
        );
        assert_eq!(
            out,
            rewrite_paste(body, &[]),
            "an untouched paste must still come back framed with both markers"
        );
    }

    /// A copy the peer refuses leaves the host path in the forwarded paste
    /// and never escapes `translate` as an error — `translate` is infallible.
    #[tokio::test]
    async fn a_refused_copy_keeps_the_host_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        std::fs::write(&path, b"PNG!").unwrap();
        let body = path.to_str().unwrap().to_string();

        let peer = RecordingPeer::refusing("disk full");
        let out = PasteBridge::new(&peer).translate(body.as_bytes()).await;

        assert_eq!(
            out,
            rewrite_paste(body.as_bytes(), &[]),
            "a refused copy must leave the paste framed but otherwise unchanged"
        );
        assert_eq!(
            peer.copies.lock().unwrap().len(),
            1,
            "the failure must come from the peer, not from skipping the call"
        );
    }

    /// `copy_file` must bound `copy_in` in `COPY_TIMEOUT` itself: a peer that
    /// never resolves must not wedge `translate` forever. The paused clock
    /// auto-advances through the 30 s bound while every task is idle, so
    /// this runs in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn a_copy_that_never_finishes_is_abandoned_at_the_timeout() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        std::fs::write(&path, b"PNG!").unwrap();
        let body = path.to_str().unwrap().to_string();

        let peer = RecordingPeer::stalling();
        let out = tokio::time::timeout(
            Duration::from_secs(600),
            PasteBridge::new(&peer).translate(body.as_bytes()),
        )
        .await
        .expect("the bridge must bound the copy itself instead of waiting on the peer");

        assert_eq!(
            out,
            rewrite_paste(body.as_bytes(), &[]),
            "a timed-out file must keep its host path, not a target that was never written"
        );
    }

    /// A failure on one file in a multi-file paste must not stop the loop:
    /// later files still get copied and their spans still land in order.
    #[tokio::test]
    async fn a_failure_on_one_file_does_not_stop_the_next() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.png");
        let b = dir.path().join("b.png");
        std::fs::write(&a, b"A").unwrap();
        std::fs::write(&b, b"B").unwrap();
        let body = format!("{} {}", a.to_str().unwrap(), b.to_str().unwrap());

        let peer = RecordingPeer::queued(vec![Reply::Fail("disk full".into()), Reply::Succeed]);
        let out = PasteBridge::new(&peer).translate(body.as_bytes()).await;

        assert_eq!(
            peer.copies.lock().unwrap().len(),
            2,
            "both files must be attempted even though the first was refused"
        );
        let found = pasted_files(body.as_bytes());
        let target_b = container_paste_path(&b);
        assert_eq!(
            out,
            rewrite_paste(body.as_bytes(), &[(found[1].span.clone(), target_b)]),
            "the first host path must survive and the second must be rewritten, in order"
        );
    }

    /// Pins the read-failure wording the executor restored while moving
    /// `copy_in`'s bollard-era logic out of this file: a host read failure
    /// must carry the `"read {path}: "` prefix, not the bare I/O error.
    #[tokio::test]
    async fn a_read_failure_names_the_host_path() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("gone.png");
        let peer = RecordingPeer::accepting();

        let err = PasteBridge::new(&peer)
            .copy_file(&missing, "/tmp/dev-paste/gone.png")
            .await
            .expect_err("reading a file that was never written must fail");

        assert!(
            err.contains(&format!("read {}: ", missing.display())),
            "the read failure must carry the `read {{path}}: ` prefix, got {err:?}"
        );
    }

    /// Pins the second bug fixed in the same move: the timeout wording must
    /// derive its seconds from `COPY_TIMEOUT` rather than a literal that
    /// could silently desync from the constant.
    #[tokio::test(start_paused = true)]
    async fn a_timed_out_copy_names_the_seconds_from_copy_timeout() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        std::fs::write(&path, b"PNG!").unwrap();
        let peer = RecordingPeer::stalling();

        let err = tokio::time::timeout(
            Duration::from_secs(600),
            PasteBridge::new(&peer).copy_file(&path, "/tmp/dev-paste/shot.png"),
        )
        .await
        .expect("the bridge must bound the copy itself instead of waiting on the peer")
        .expect_err("a stalled copy must time out as an error");

        assert_eq!(
            err,
            format!("timed out after {}s", COPY_TIMEOUT.as_secs()),
            "the timeout wording must be derived from COPY_TIMEOUT, not a hardcoded literal"
        );
    }
}
