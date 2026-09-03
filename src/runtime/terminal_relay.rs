//! The relay loop that sits between the user's terminal and a container session on
//! every runtime. It rewrites keystrokes and pasted host file paths on the way in and
//! pumps container output back out; every runtime plugs its own session into it.

use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::error::DevError;
use crate::runtime::paste_bridge::PasteBridge;
use crate::runtime::terminal_input::{Input, PasteFilter, translate_shift_enter};
use crate::runtime::{BoxFut, terminal_size};

/// RAII guard that puts the terminal into raw mode and restores it on drop.
pub struct RawModeGuard {
    original: libc::termios,
    fd: i32,
}

impl RawModeGuard {
    pub fn enter() -> Result<Self, DevError> {
        let fd = std::io::stdin().as_raw_fd();
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(DevError::Runtime(
                "Failed to get terminal attributes".into(),
            ));
        }
        let mut raw = original;
        // Safe: `raw` is a local, fully-initialized `termios` value; `cfmakeraw` only
        // edits it in place.
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(DevError::Runtime("Failed to set raw mode".into()));
        }
        Ok(Self { original, fd })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Safe: `self.fd` was validated by `enter`'s `tcgetattr`/`tcsetattr` and stdin
        // stays open for the process lifetime.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

/// Reads stdin on a blocking thread and delivers chunks to the async world.
///
/// `std::io::stdin()` has no async-cancellable read, so a dedicated thread parks in
/// `poll` over stdin and a self-pipe, and a drop of the writer end wakes it for
/// shutdown.
pub struct StdinReader {
    chunks: mpsc::Receiver<Vec<u8>>,
    cancel: Option<os_pipe::PipeWriter>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl StdinReader {
    /// Reads fd 0. The caller keeps stdin open for the reader's life.
    pub fn spawn() -> Result<Self, DevError> {
        Self::spawn_reading(std::io::stdin().as_raw_fd())
    }

    /// Split out of `spawn` so tests can feed a pipe instead of the real stdin. The
    /// caller keeps `fd` open for the reader's life.
    fn spawn_reading(fd: RawFd) -> Result<Self, DevError> {
        let (cancel_reader, cancel_writer) =
            os_pipe::pipe().map_err(|e| DevError::Runtime(format!("pipe: {e}")))?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>(32);
        let thread = std::thread::spawn(move || read_stdin_until_cancelled(fd, cancel_reader, tx));
        Ok(Self {
            chunks: rx,
            cancel: Some(cancel_writer),
            thread: Some(thread),
        })
    }

    pub fn chunks(&mut self) -> &mut mpsc::Receiver<Vec<u8>> {
        &mut self.chunks
    }
}

impl Drop for StdinReader {
    fn drop(&mut self) {
        // A thread parked in `blocking_send` on a full channel does not watch the
        // cancel pipe, so the channel must close before the cancel write can matter;
        // skipping either step leaves a thread blocked in `poll` on fd 0 forever.
        self.chunks.close();
        drop(self.cancel.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The blocking half of `StdinReader`: raw bytes only, no translation.
fn read_stdin_until_cancelled(fd: RawFd, cancel: os_pipe::PipeReader, tx: mpsc::Sender<Vec<u8>>) {
    let cancel_fd = cancel.as_raw_fd();
    // 64 KiB so a large paste costs a handful of read/send/filter round trips
    // instead of one per kilobyte; typing is one byte at a time either way.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let mut pfds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancel_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Safe: `pfds` is a valid, correctly-sized array of pollfds for the call's
        // duration.
        let ready = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            break;
        }
        // A pipe whose write end has closed is only ever reported as
        // POLLHUP on Linux, never POLLIN — macOS reports both, so a
        // POLLIN-only check passes there but spins at 100% CPU on Linux and
        // never lets `Drop`'s `join()` return. Every fd needs the same
        // "something happened" mask, not just "there is data".
        const READY_OR_DONE: i16 = libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;
        if pfds[1].revents & READY_OR_DONE != 0 {
            break;
        }
        if pfds[0].revents & READY_OR_DONE != 0 {
            // Safe: `buf` is a valid, writable buffer of `buf.len()` bytes.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            if tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                break;
            }
        }
    }
}

/// Turns a libc `-1` return into `DevError::Runtime` naming the failing call, keeping
/// the value on success so flag reads can chain into flag writes.
fn checked(call: &str, rc: i32) -> Result<i32, DevError> {
    if rc < 0 {
        Err(DevError::Runtime(format!(
            "{call}: {}",
            io::Error::last_os_error()
        )))
    } else {
        Ok(rc)
    }
}

fn set_cloexec(fd: &OwnedFd) -> Result<(), DevError> {
    // Safe: `fd` is owned by us and stays open for the duration of both calls.
    let flags = checked("fcntl F_GETFD", unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_GETFD)
    })?;
    checked("fcntl F_SETFD", unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC)
    })?;
    Ok(())
}

fn set_nonblocking(fd: &OwnedFd) -> Result<(), DevError> {
    // Safe: `fd` is owned by us and stays open for the duration of both calls.
    let flags = checked("fcntl F_GETFL", unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_GETFL)
    })?;
    checked("fcntl F_SETFL", unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
    })?;
    Ok(())
}

/// Puts `fd` into the same raw mode `RawModeGuard` puts the host terminal into, so
/// bytes cross the pty exactly as they cross the real raw terminal today: no echo, no
/// `ICRNL`/`ISIG`, and no `OPOST` (which would turn every `\n` from the container into
/// `\r\n` a second time).
fn make_raw(fd: RawFd) -> Result<(), DevError> {
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // Safe: `fd` is the pty slave we just opened and own exclusively.
    checked("tcgetattr", unsafe { libc::tcgetattr(fd, &mut termios) })?;
    // Safe: `termios` is a local, fully-initialized value; `cfmakeraw` only edits it.
    unsafe { libc::cfmakeraw(&mut termios) };
    // Safe: same fd as the `tcgetattr` above.
    checked("tcsetattr", unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, &termios)
    })?;
    Ok(())
}

/// A pty this process owns end-to-end: a raw slave handed to the container process,
/// and a non-blocking async master this process reads and writes.
pub struct Pty {
    master: PtyMaster,
    slave: Option<OwnedFd>,
}

impl Pty {
    /// `AsyncFd::new` needs a runtime, so this must be called from async context —
    /// true of every runtime's exec path.
    pub fn open() -> Result<Pty, DevError> {
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        // Safe: `openpty` fills exactly the two fd slots we pass; null name/termios/
        // winsize is an explicitly allowed form (see the man page).
        let rc = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        checked("openpty", rc)?;
        // Safe: `openpty` returned success, so both fds are open and not owned
        // elsewhere yet.
        let master = unsafe { OwnedFd::from_raw_fd(master_fd) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };

        set_cloexec(&master)?;
        set_cloexec(&slave)?;
        make_raw(slave.as_raw_fd())?;
        set_nonblocking(&master)?;

        Ok(Pty {
            master: PtyMaster(Arc::new(AsyncFd::new(master)?)),
            slave: Some(slave),
        })
    }

    pub fn master(&self) -> PtyMaster {
        self.master.clone()
    }

    /// Hands the slave to the caller once; `None` afterwards. The caller owns closing
    /// it. While `Pty` still holds the slave, the master can never read EOF.
    pub fn take_slave(&mut self) -> Option<OwnedFd> {
        self.slave.take()
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), DevError> {
        self.master.resize(cols, rows)
    }
}

/// The async, cloneable half of a [`Pty`]. `Send + Sync` via `Arc<AsyncFd<..>>`.
#[derive(Clone)]
pub struct PtyMaster(Arc<AsyncFd<OwnedFd>>);

impl PtyMaster {
    /// Argument order is `(cols, rows)` to match `terminal_size()`.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), DevError> {
        let winsize = libc::winsize {
            ws_col: cols,
            ws_row: rows,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // Safe: `self.0` owns a valid pty master fd for the life of this call.
        checked("ioctl TIOCSWINSZ", unsafe {
            libc::ioctl(self.0.as_raw_fd(), libc::TIOCSWINSZ, &winsize)
        })?;
        Ok(())
    }
}

impl AsyncRead for PtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.0.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|inner| {
                let unfilled = buf.initialize_unfilled();
                // Safe: `unfilled` is a valid buffer of its own length; `inner` is the
                // pty master fd this struct owns.
                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        unfilled.as_mut_ptr() as *mut libc::c_void,
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    // Linux reports the slave-closed hangup as EIO on the master;
                    // macOS reports it as a zero read. Both must come out as EOF.
                    if err.raw_os_error() == Some(libc::EIO) {
                        return Ok(0);
                    }
                    return Err(err);
                }
                Ok(n as usize)
            });
            match result {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for PtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.0.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|inner| {
                // Safe: `data` is a valid, initialized slice for the call's duration;
                // `inner` is the pty master fd this struct owns.
                let n = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            });
            match result {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// A pty has no half-close: the process on the far side sees EOF only when every
    /// master fd closes, so there is nothing to do here.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A future of `()`, for a `SessionPeer` method whose caller cannot observe failure.
pub type UnitFut<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A container-side session `relay_terminal` drives: resize and paste delivery. Every
/// other detail (spawning, exec plumbing) is the runtime's business, not the relay's.
///
/// `resize` failures are non-fatal — every impl swallows its own error, as the direct
/// call it replaces already did. `copy_in` is bounded by `PasteBridge`, not by the relay.
pub trait SessionPeer: Sync {
    fn resize(&self, cols: u16, rows: u16) -> UnitFut<'_>;
    fn copy_in<'a>(&'a self, bytes: Vec<u8>, target: &'a str) -> BoxFut<'a, ()>;
}

/// The host side of the relay, injectable so `relay_terminal` can be driven without a
/// real tty in tests.
pub struct HostTerminal<'a, W> {
    /// `StdinReader::chunks()` in production.
    pub keys: &'a mut mpsc::Receiver<Vec<u8>>,
    /// `tokio::io::stdout()` in production.
    pub stdout: W,
    pub winch: tokio::signal::unix::Signal,
    /// `runtime::terminal_size` in production.
    pub size: fn() -> Option<(u16, u16)>,
}

impl<'a> HostTerminal<'a, tokio::io::Stdout> {
    pub fn for_process(keys: &'a mut mpsc::Receiver<Vec<u8>>) -> Result<Self, DevError> {
        let winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(|e| DevError::Runtime(format!("SIGWINCH handler: {e}")))?;
        Ok(Self {
            keys,
            stdout: tokio::io::stdout(),
            winch,
            size: terminal_size,
        })
    }
}

/// Which side ended the relay loop.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayEnd {
    StdinClosed,
    OutputClosed,
}

/// How long a chunk that looks like the start of a bracketed-paste marker is
/// held before it is released as plain keys.
///
/// The conventional escape-timeout window: long enough that a terminal's
/// multi-byte marker reliably arrives within one more read, short enough that
/// a bare Escape (leaving vim insert mode, interrupting Claude Code) is not
/// perceptibly delayed.
const ESCAPE_HOLD_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(40);

/// Runs the relay loop until stdin or the container output closes, or a write fails.
///
/// `input` is dropped with the returned future: on the `StdinClosed` path that drop is
/// what gives the container's shell its own EOF, so callers must not keep a second
/// handle to it open past this call.
pub async fn relay_terminal<W, In, Out>(
    host: &mut HostTerminal<'_, W>,
    mut input: In,
    mut output: Out,
    peer: &dyn SessionPeer,
) -> Result<RelayEnd, DevError>
where
    W: AsyncWrite + Unpin,
    In: AsyncWrite + Unpin,
    Out: AsyncRead + Unpin,
{
    if let Some((cols, rows)) = (host.size)() {
        peer.resize(cols, rows).await;
    }

    let mut paste_filter = PasteFilter::default();
    let mut winch_open = true;
    // 64 KiB so a full-screen redraw is one write-and-flush pair, not sixteen.
    let mut buf = [0u8; 64 * 1024];
    // Disarmed until a chunk leaves the filter holding a marker prefix; the
    // `if` guard on its select! arm means an elapsed-but-unarmed timer is
    // never polled, so starting it already "expired" is harmless.
    let escape_timeout = tokio::time::sleep(ESCAPE_HOLD_TIMEOUT);
    tokio::pin!(escape_timeout);
    loop {
        tokio::select! {
            biased;

            signal = host.winch.recv(), if winch_open => {
                if signal.is_none() {
                    winch_open = false;
                    continue;
                }
                if let Some((cols, rows)) = (host.size)() {
                    peer.resize(cols, rows).await;
                }
            }

            chunk = host.keys.recv() => {
                match chunk {
                    None => return Ok(RelayEnd::StdinClosed),
                    Some(data) => {
                        forward_keys(&mut paste_filter, &data, &mut input, peer).await?;
                        if paste_filter.holding_marker_prefix() {
                            escape_timeout
                                .as_mut()
                                .reset(tokio::time::Instant::now() + ESCAPE_HOLD_TIMEOUT);
                        }
                    }
                }
            }

            () = &mut escape_timeout, if paste_filter.holding_marker_prefix() => {
                flush_held_prefix(&mut paste_filter, &mut input).await?;
            }

            read = output.read(&mut buf) => {
                let n = read.map_err(DevError::Io)?;
                if n == 0 {
                    return Ok(RelayEnd::OutputClosed);
                }
                host.stdout.write_all(&buf[..n]).await.map_err(DevError::Io)?;
                host.stdout.flush().await.map_err(DevError::Io)?;
            }
        }
    }
}

/// Rewrites one chunk of stdin (Shift+Enter, pasted files) and forwards it into
/// `input`. `paste_filter` carries state across calls so a paste can straddle chunks.
async fn forward_keys<In: AsyncWrite + Unpin>(
    paste_filter: &mut PasteFilter,
    data: &[u8],
    input: &mut In,
    peer: &dyn SessionPeer,
) -> Result<(), DevError> {
    for piece in paste_filter.feed(data) {
        let bytes = match piece {
            Input::Keys(keys) => translate_shift_enter(&keys),
            Input::Paste(paste) => PasteBridge::new(peer).translate(&paste).await,
        };
        input.write_all(&bytes).await.map_err(DevError::Io)?;
    }
    Ok(())
}

/// Releases bytes `paste_filter` is holding only because they could still
/// become the start of a bracketed-paste marker, once a timeout has decided
/// no more are coming. Goes through the same key translation as `forward_keys`,
/// not back through `feed`, since re-feeding bytes `take_keys` already gave up
/// on would just hold them again.
async fn flush_held_prefix<In: AsyncWrite + Unpin>(
    paste_filter: &mut PasteFilter,
    input: &mut In,
) -> Result<(), DevError> {
    let bytes = translate_shift_enter(&paste_filter.take_held_prefix());
    input.write_all(&bytes).await.map_err(DevError::Io)
}

/// Reads whatever is still buffered on `output` to stdout, stopping at EOF, a
/// read error, or a 1 s budget so a stray slave holder cannot park the shell.
///
/// A container's shell can write its last line and exit in the same poll as
/// the exit-wait future resolving, so `select!` picking the exit arm must not
/// be allowed to drop that output unread.
pub async fn drain_remaining_output<Out: AsyncRead + Unpin>(output: &mut Out) {
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            match output.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = stdout.flush().await;
                }
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::terminal_input::container_paste_path;
    use crate::runtime::test_peer::{RecordingPeer, bounded};
    use std::io::Write;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    // `RawModeGuard::enter` is not unit tested: under `cargo test` stdin may
    // or may not be a tty, so any assertion about it would be nondeterministic.

    /// A [`HostTerminal`] driven by an in-memory `keys` channel and a `Vec<u8>`
    /// stdout, registering a real SIGWINCH `Signal` (works in a test binary).
    fn test_host(
        keys: &mut mpsc::Receiver<Vec<u8>>,
        size: fn() -> Option<(u16, u16)>,
    ) -> HostTerminal<'_, Vec<u8>> {
        let winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .expect("SIGWINCH registration must succeed in a test binary");
        HostTerminal {
            keys,
            stdout: Vec::new(),
            winch,
            size,
        }
    }

    fn framed_paste(body: &[u8]) -> Vec<u8> {
        let mut out = b"\x1b[200~".to_vec();
        out.extend_from_slice(body);
        out.extend_from_slice(b"\x1b[201~");
        out
    }

    /// The forwarder step: keystrokes are translated (Shift+Enter -> plain CR)
    /// before they reach the container, not forwarded raw.
    #[tokio::test]
    async fn keys_are_translated_on_the_way_in() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        tx.send(b"ls\x1b[13;2u".to_vec()).await.unwrap();
        drop(tx);

        let end = bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");
        assert_eq!(
            end,
            RelayEnd::StdinClosed,
            "stdin EOF must end the loop as StdinClosed"
        );

        let mut got = Vec::new();
        bounded(input_far.read_to_end(&mut got))
            .await
            .expect("the far end of input must see what the relay forwarded");
        assert_eq!(
            got, b"ls\r",
            "Shift+Enter must be translated to a plain CR before reaching the container"
        );
    }

    /// A lone Escape (leaving vim insert mode, interrupting Claude Code)
    /// looks exactly like the start of a bracketed-paste marker until more
    /// bytes settle it, so it must reach the container once
    /// `ESCAPE_HOLD_TIMEOUT` decides no more are coming — with no further
    /// keys sent. `start_paused` lets the virtual clock fire the timeout
    /// without a real sleep.
    #[tokio::test(start_paused = true)]
    async fn a_lone_escape_reaches_the_container_after_the_hold_timeout() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        tx.send(b"\x1b".to_vec()).await.unwrap();

        let relay = relay_terminal(&mut host, input, output_far, &peer);
        tokio::pin!(relay);

        let mut buf = [0u8; 8];
        let n = tokio::select! {
            biased;
            _ = &mut relay => panic!("the relay must not end before the held escape is released"),
            read = input_far.read(&mut buf) => read.expect("read must succeed"),
        };
        assert_eq!(
            &buf[..n],
            b"\x1b",
            "a lone Escape must reach the container once the hold timeout releases it"
        );

        drop(tx);
        let end = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("must not hang")
            .expect("relay must not error");
        assert_eq!(end, RelayEnd::StdinClosed);
    }

    /// A real paste can have long gaps between chunks (a large image over a
    /// slow link), and `holding_marker_prefix` only ever answers true for an
    /// incomplete *marker*, never for a paste body: proves a gap far longer
    /// than `ESCAPE_HOLD_TIMEOUT` mid-paste does not tear the paste apart.
    /// This is the case that matters — getting it wrong corrupts pastes.
    #[tokio::test(start_paused = true)]
    async fn a_slow_paste_survives_a_gap_past_the_escape_hold_timeout() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        let body: &[u8] = b"/nowhere/at/all/shot.png";
        tx.send(b"\x1b[200~".to_vec()).await.unwrap();
        tx.send(body[..10].to_vec()).await.unwrap();

        async fn drip_the_rest(tx: mpsc::Sender<Vec<u8>>, rest: Vec<u8>) {
            // A gap far longer than ESCAPE_HOLD_TIMEOUT between paste
            // chunks — exactly what a slow paste transfer looks like.
            tokio::time::sleep(Duration::from_millis(500)).await;
            tx.send(rest).await.unwrap();
            tx.send(b"\x1b[201~".to_vec()).await.unwrap();
            drop(tx);
        }

        let (end, ()) = bounded(async {
            tokio::join!(
                relay_terminal(&mut host, input, output_far, &peer),
                drip_the_rest(tx, body[10..].to_vec()),
            )
        })
        .await;
        let end = end.expect("relay must not error");
        assert_eq!(end, RelayEnd::StdinClosed);

        let mut got = Vec::new();
        bounded(input_far.read_to_end(&mut got))
            .await
            .expect("the far end of input must see the whole, unsplit paste");
        assert_eq!(
            got,
            framed_paste(body),
            "a paste with a gap longer than the escape-hold timeout must still arrive whole, markers included"
        );
    }

    /// A pasted file this host can see is copied into the container and the
    /// paste is rewritten to name the copy, never the host path.
    #[tokio::test]
    async fn a_paste_naming_a_file_here_is_copied_in_and_rewritten() {
        let dir = TempDir::new().unwrap();
        let png = dir.path().join("shot.png");
        std::fs::write(&png, b"PNG!").unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        tx.send(framed_paste(png.to_str().unwrap().as_bytes()))
            .await
            .unwrap();
        drop(tx);

        let end = bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");
        assert_eq!(end, RelayEnd::StdinClosed);

        let target = container_paste_path(&png);
        assert_eq!(
            peer.copies.lock().unwrap().as_slice(),
            &[(target.clone(), b"PNG!".to_vec())],
            "the pasted file's bytes and container target must be recorded exactly once"
        );

        let mut got = Vec::new();
        bounded(input_far.read_to_end(&mut got))
            .await
            .expect("the far end of input must see the rewritten paste");
        assert_eq!(
            got,
            framed_paste(target.as_bytes()),
            "the forwarded paste must name the container path, not the host path"
        );
    }

    /// A pasted path this host cannot resolve to a file passes through byte
    /// for byte, markers included, and never triggers a copy.
    #[tokio::test]
    async fn a_paste_naming_a_missing_path_passes_through_untouched() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        let body: &[u8] = b"/nowhere/at/all/shot.png";
        tx.send(framed_paste(body)).await.unwrap();
        drop(tx);

        bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");

        assert!(
            peer.copies.lock().unwrap().is_empty(),
            "a path this host cannot see must never be copied"
        );

        let mut got = Vec::new();
        bounded(input_far.read_to_end(&mut got))
            .await
            .expect("the far end of input must see the untouched paste");
        assert_eq!(
            got,
            framed_paste(body),
            "an untouched paste must reach the container byte-for-byte, markers included"
        );
    }

    /// A copy that fails leaves the host path in the forwarded paste and does
    /// not end the relay: keys sent afterward still arrive.
    #[tokio::test]
    async fn a_failed_copy_keeps_the_host_path() {
        let dir = TempDir::new().unwrap();
        let png = dir.path().join("shot.png");
        std::fs::write(&png, b"PNG!").unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::refusing("copy failed");

        let paste_chunk = framed_paste(png.to_str().unwrap().as_bytes());
        tx.send(paste_chunk.clone()).await.unwrap();
        tx.send(b"ok".to_vec()).await.unwrap();
        drop(tx);

        let end = bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("a failed copy must not end the relay in error");
        assert_eq!(
            end,
            RelayEnd::StdinClosed,
            "the relay must keep running past a failed copy, ending only on stdin EOF"
        );

        let mut got = Vec::new();
        bounded(input_far.read_to_end(&mut got))
            .await
            .expect("the far end of input must see both the paste and the later keys");
        let mut want = paste_chunk;
        want.extend_from_slice(b"ok");
        assert_eq!(
            got, want,
            "a failed copy must keep the host path in the forwarded paste, and later keys must still arrive"
        );
    }

    /// `translate_paste` must bound `copy_in` in `COPY_TIMEOUT`: a copy that
    /// never resolves must not wedge the relay forever.
    ///
    /// `start_paused` lets the virtual clock auto-advance through the 30 s
    /// timeout while every task is idle, so this runs instantly in real time.
    #[tokio::test(start_paused = true)]
    async fn a_copy_that_hangs_is_abandoned_after_the_timeout() {
        let dir = TempDir::new().unwrap();
        let png = dir.path().join("shot.png");
        std::fs::write(&png, b"PNG!").unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::stalling();

        let paste_chunk = framed_paste(png.to_str().unwrap().as_bytes());
        tx.send(paste_chunk.clone()).await.unwrap();
        drop(tx);

        let end = tokio::time::timeout(
            Duration::from_secs(60),
            relay_terminal(&mut host, input, output_far, &peer),
        )
        .await
        .expect("translate_paste must bound copy_in with COPY_TIMEOUT instead of hanging")
        .expect("relay must not error");
        assert_eq!(end, RelayEnd::StdinClosed);

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), input_far.read_to_end(&mut got))
            .await
            .expect("must not hang")
            .expect("read must succeed");
        assert_eq!(
            got, paste_chunk,
            "a copy that times out must keep the host path in the forwarded paste"
        );
    }

    /// Container output is pumped to the host's stdout, flushed, and its EOF
    /// ends the loop as `OutputClosed`.
    #[tokio::test]
    async fn container_output_reaches_the_host_stdout() {
        let (_tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, _input_far) = tokio::io::duplex(4096);
        let (mut output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        output_near.write_all(b"hello\r\n").await.unwrap();
        drop(output_near);

        let end = bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");
        assert_eq!(
            end,
            RelayEnd::OutputClosed,
            "container output EOF must end the loop as OutputClosed"
        );
        assert_eq!(
            host.stdout, b"hello\r\n",
            "container output must be pumped to the host stdout, flushed, byte for byte"
        );
    }

    /// `input` is dropped when the relay returns, so the container's shell
    /// gets its own EOF on the `StdinClosed` path.
    #[tokio::test]
    async fn stdin_eof_closes_the_container_input() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, mut input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        drop(tx);

        bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");

        let mut buf = [0u8; 8];
        let n = bounded(input_far.read(&mut buf))
            .await
            .expect("the far end must not hang after the relay returns");
        assert_eq!(
            n, 0,
            "the relay must drop `input` on return so the container's stdin gets its own EOF"
        );
    }

    /// The host's terminal size, when there is one, is sent before the loop
    /// starts, not only on the first SIGWINCH.
    #[tokio::test]
    async fn the_initial_size_is_sent_before_the_loop() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || Some((80, 24)));
        let (input, _input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        drop(tx);

        bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");

        assert_eq!(
            peer.resizes.lock().unwrap().first(),
            Some(&(80, 24)),
            "the initial terminal size must be sent before the loop starts"
        );
    }

    /// Companion to the initial-resize test: a host with no terminal sends no
    /// resize at all.
    #[tokio::test]
    async fn no_resize_when_the_host_has_no_terminal() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || None);
        let (input, _input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        drop(tx);

        bounded(relay_terminal(&mut host, input, output_far, &peer))
            .await
            .expect("relay must not error");

        assert!(
            peer.resizes.lock().unwrap().is_empty(),
            "no terminal size must mean no initial resize"
        );
    }

    /// Polls until at least `want` resizes have been recorded, or `budget`
    /// elapses, then drops `tx` to let the relay end. Bounded so a missed
    /// SIGWINCH fails the test instead of hanging it.
    async fn wait_for_resizes_then_close(
        peer: &RecordingPeer,
        tx: mpsc::Sender<Vec<u8>>,
        want: usize,
        budget: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + budget;
        while peer.resizes.lock().unwrap().len() < want && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(tx);
    }

    /// A SIGWINCH re-reads the host's terminal size and resizes the session,
    /// on top of the resize the relay already sent before the loop started.
    /// `biased` in the select makes a pending signal win over a stdin close
    /// that only happens afterward.
    #[tokio::test]
    async fn a_window_change_resizes_the_session() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut host = test_host(&mut rx, || Some((120, 40)));
        let (input, _input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        // Safe: raising a signal this process already listens for.
        unsafe { libc::raise(libc::SIGWINCH) };

        let (end, ()) = bounded(async {
            tokio::join!(
                relay_terminal(&mut host, input, output_far, &peer),
                wait_for_resizes_then_close(&peer, tx, 2, Duration::from_secs(4)),
            )
        })
        .await;
        let end = end.expect("relay must not error");
        assert_eq!(end, RelayEnd::StdinClosed);

        let recorded = peer.resizes.lock().unwrap().clone();
        assert!(
            recorded.len() >= 2,
            "SIGWINCH must add at least one resize beyond the initial one: {recorded:?}"
        );
        assert!(
            recorded.iter().all(|&s| s == (120, 40)),
            "every resize in this test must report the same fixed size: {recorded:?}"
        );
    }

    /// The relay's future must be `Send` so every runtime can return it
    /// inside a `BoxFut`. Fails to compile, not at runtime, if `SessionPeer`
    /// loses `Sync` or a non-`Send` local enters the loop.
    #[tokio::test]
    async fn the_relay_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}

        let (_tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        let mut host =
            HostTerminal::for_process(&mut rx).expect("SIGWINCH registration must succeed");
        let (input, _input_far) = tokio::io::duplex(4096);
        let (_output_near, output_far) = tokio::io::duplex(4096);
        let peer = RecordingPeer::accepting();

        let fut = relay_terminal(&mut host, input, output_far, &peer);
        assert_send(&fut);
        drop(fut);
    }

    /// Polls `handle.is_finished()` for up to `budget`, as the fd-readiness
    /// helpers in `apple.rs` bound their own polling.
    async fn wait_finished(handle: &std::thread::JoinHandle<()>, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if handle.is_finished() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        handle.is_finished()
    }

    /// Raw bytes written to the fd `StdinReader` reads arrive as one chunk
    /// on its channel, untranslated.
    #[tokio::test]
    async fn stdin_bytes_arrive_as_chunks() {
        let (reader, mut writer) = os_pipe::pipe().unwrap();
        let mut stdin = StdinReader::spawn_reading(reader.as_raw_fd()).unwrap();

        writer.write_all(b"abc").unwrap();

        let got = bounded(stdin.chunks().recv())
            .await
            .expect("the channel must not close while the writer is open");
        assert_eq!(
            got, b"abc",
            "bytes written to the fd must arrive as an equal chunk, untranslated"
        );
    }

    /// Dropping `StdinReader` closes the cancel pipe, which wakes the thread
    /// parked in `poll` on the target fd even though nothing was ever written
    /// to it.
    #[tokio::test]
    async fn dropping_the_reader_wakes_a_thread_parked_in_poll() {
        let (reader, _writer) = os_pipe::pipe().unwrap();
        let stdin = StdinReader::spawn_reading(reader.as_raw_fd()).unwrap();

        let handle = std::thread::spawn(move || drop(stdin));

        assert!(
            wait_finished(&handle, Duration::from_secs(2)).await,
            "dropping the reader must close the cancel pipe and let the poll thread exit"
        );
        handle.join().unwrap();
    }

    /// `Drop` must close the channel before dropping the cancel writer: a
    /// thread parked in `blocking_send` on a full channel does not watch the
    /// cancel pipe, so skipping `close()` would deadlock the join.
    #[tokio::test]
    async fn dropping_the_reader_with_a_full_channel_does_not_deadlock() {
        let (reader, mut writer) = os_pipe::pipe().unwrap();
        let stdin = StdinReader::spawn_reading(reader.as_raw_fd()).unwrap();

        let writer_thread = std::thread::spawn(move || {
            let chunk = [0u8; 1024];
            for _ in 0..64 {
                let _ = writer.write_all(&chunk);
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let handle = std::thread::spawn(move || drop(stdin));
        assert!(
            wait_finished(&handle, Duration::from_secs(2)).await,
            "a full channel must not stop `Drop` from closing it and joining the thread"
        );
        handle.join().unwrap();
        let _ = writer_thread.join();
    }

    /// Reads until at least `want` bytes have arrived or `budget` elapses, as
    /// `apple.rs`'s `read_until` does for its own fd tests.
    fn read_at_least(fd: RawFd, want: usize, budget: Duration) -> Vec<u8> {
        let deadline = Instant::now() + budget;
        let mut seen = Vec::new();
        while seen.len() < want && Instant::now() < deadline {
            let mut watch = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // Safe: `watch` is a single valid pollfd for the call's duration.
            match unsafe { libc::poll(&mut watch, 1, 250) } {
                0 => continue,
                ready if ready < 0 => break,
                _ => {}
            }
            let mut buf = [0u8; 64];
            // Safe: `buf` is a valid, writable buffer of its own length.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n as usize]);
        }
        seen
    }

    /// A freshly opened pty has a non-blocking, close-on-exec master, a
    /// close-on-exec slave, and hands its slave out exactly once.
    #[tokio::test]
    async fn a_pty_opens_with_a_nonblocking_master() {
        let mut pty = Pty::open().expect("open pty");
        let master_fd = pty.master.0.as_raw_fd();
        let slave_fd = pty
            .slave
            .as_ref()
            .expect("slave present after open")
            .as_raw_fd();

        // Safe: `master_fd` is a valid fd owned by `pty` for this call.
        let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
        assert!(
            flags & libc::O_NONBLOCK != 0,
            "the master fd must be non-blocking"
        );

        // Safe: both fds are valid and owned by `pty` for these calls.
        let master_fdflags = unsafe { libc::fcntl(master_fd, libc::F_GETFD) };
        let slave_fdflags = unsafe { libc::fcntl(slave_fd, libc::F_GETFD) };
        assert!(
            master_fdflags & libc::FD_CLOEXEC != 0,
            "the master fd must be close-on-exec"
        );
        assert!(
            slave_fdflags & libc::FD_CLOEXEC != 0,
            "the slave fd must be close-on-exec"
        );

        assert!(
            pty.take_slave().is_some(),
            "the first take_slave must hand over the slave"
        );
        assert!(
            pty.take_slave().is_none(),
            "a second take_slave must return None"
        );
    }

    /// `Pty::resize` reaches the slave: `TIOCGWINSZ` there reports the size
    /// just set on the master, in the same (cols, rows) order.
    #[tokio::test]
    async fn resize_is_visible_on_the_slave() {
        let mut pty = Pty::open().expect("open pty");
        let slave = pty.take_slave().expect("slave present after open");

        pty.resize(132, 43).expect("resize must succeed");

        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // Safe: `slave` is a valid, open pty slave fd for this call.
        let rc = unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
        assert_eq!(rc, 0, "TIOCGWINSZ on the slave must succeed");
        assert_eq!(
            ws.ws_col, 132,
            "the slave must see the resized column count"
        );
        assert_eq!(ws.ws_row, 43, "the slave must see the resized row count");
    }

    /// Bytes cross the pty exactly as they cross a real raw terminal: no
    /// echo back to the master, and no `OPOST` turning `\n` into `\r\n` on
    /// the way from the slave.
    #[tokio::test]
    async fn bytes_cross_the_pty_unchanged_in_both_directions() {
        let mut pty = Pty::open().expect("open pty");
        let slave = pty.take_slave().expect("slave present after open");
        let mut master = pty.master();

        bounded(master.write_all(b"ls\r"))
            .await
            .expect("write to the master must succeed");
        let from_slave = read_at_least(slave.as_raw_fd(), 3, Duration::from_secs(2));
        assert_eq!(
            from_slave, b"ls\r",
            "the slave must see exactly what was written to the master, with no echo appended"
        );

        // Safe: `slave` is a valid, open pty slave fd for this call.
        let written = unsafe { libc::write(slave.as_raw_fd(), b"out\n".as_ptr().cast(), 4) };
        assert_eq!(written, 4, "the raw write to the slave must succeed");
        let mut buf = [0u8; 16];
        let n = bounded(master.read(&mut buf))
            .await
            .expect("read from the master must succeed");
        assert_eq!(
            &buf[..n],
            b"out\n",
            "the master must see exactly what the slave wrote, with no OPOST CR inserted"
        );
    }

    /// Closing every slave fd surfaces as a clean EOF on the master read,
    /// never as an `EIO` error, on both Linux (which reports the hangup as
    /// `EIO`) and macOS (which reports it as a zero read).
    #[tokio::test]
    async fn the_master_reads_eof_once_the_slave_closes() {
        let mut pty = Pty::open().expect("open pty");
        let slave = pty.take_slave().expect("slave present after open");
        drop(slave);
        let mut master = pty.master();

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), master.read(&mut buf))
            .await
            .expect("the master read must not hang once the slave is closed")
            .expect("the master read must not error once the slave is closed");
        assert_eq!(
            n, 0,
            "closing every slave fd must surface as EOF on the master, not EIO"
        );
    }
}
