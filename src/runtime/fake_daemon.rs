//! A fake Unix-socket daemon for tests that need to inspect the HTTP request bollard
//! sends without a live Docker or Podman daemon behind the socket.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub(crate) async fn read_http_request(stream: &mut tokio::net::UnixStream) -> String {
    read_http_request_or_eof(stream)
        .await
        .expect("client closed before sending the request")
}

/// Like [`read_http_request`], but a client that closes between requests is
/// `None`, which is how a keep-alive loop ends.
pub(crate) async fn read_http_request_or_eof(
    stream: &mut tokio::net::UnixStream,
) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            assert!(buf.is_empty(), "client closed in the middle of a request");
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if request_complete(&buf) {
            return Some(String::from_utf8(buf).unwrap());
        }
    }
}

pub(crate) fn request_complete(buf: &[u8]) -> bool {
    let Some(header_end) = find_header_end(buf) else {
        return false;
    };
    let headers = std::str::from_utf8(&buf[..header_end]).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    buf.len() >= header_end + 4 + content_length
}

pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

pub(crate) fn request_json_body(request: &str) -> serde_json::Value {
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

/// What the scripted exec daemon does once a client starts its exec.
#[derive(Clone, Default)]
pub(crate) struct ExecScript {
    /// Read the client's stdin to EOF before writing any frame.
    pub read_stdin_to_eof: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Keep the upgraded socket open after the frames, as docker can after
    /// the process has exited.
    pub hold_open: bool,
    /// One more stdout frame, written only after an inspect has answered
    /// `Running:false`.
    pub tail_after_stopped: Option<Vec<u8>>,
    pub exit_code: i32,
    /// Answer to `GET /containers/<id>/json`.
    pub container_body: String,
}

#[derive(Default)]
struct ExecState {
    create_bodies: Vec<serde_json::Value>,
    stdin_received: Vec<u8>,
    stdin_eof: bool,
    finished: bool,
    stopped_answered: bool,
}

/// A Unix-socket daemon speaking just enough of the docker exec API for the
/// piped-exec tests, shared by docker and podman.
pub(crate) struct ScriptedExecDaemon {
    socket: PathBuf,
    state: Arc<Mutex<ExecState>>,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ScriptedExecDaemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ScriptedExecDaemon {
    pub(crate) fn start(script: ExecScript) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let state = Arc::new(Mutex::new(ExecState::default()));
        let task = tokio::spawn(accept_loop(listener, script, state.clone()));
        Self {
            socket,
            state,
            _dir: dir,
            task,
        }
    }

    pub(crate) fn socket(&self) -> String {
        self.socket.to_string_lossy().into_owned()
    }

    pub(crate) fn create_body(&self) -> serde_json::Value {
        self.state.lock().unwrap().create_bodies[0].clone()
    }

    pub(crate) fn stdin_received(&self) -> Vec<u8> {
        self.state.lock().unwrap().stdin_received.clone()
    }

    pub(crate) fn stdin_reached_eof(&self) -> bool {
        self.state.lock().unwrap().stdin_eof
    }
}

async fn accept_loop(listener: UnixListener, script: ExecScript, state: Arc<Mutex<ExecState>>) {
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(serve_connection(stream, script.clone(), state.clone()));
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    script: ExecScript,
    state: Arc<Mutex<ExecState>>,
) {
    while let Some(request) = read_http_request_or_eof(&mut stream).await {
        let line = request.lines().next().unwrap_or_default();
        let mut parts = line.split(' ');
        let (method, target) = (parts.next().unwrap(), parts.next().unwrap());
        let path = target.split('?').next().unwrap();
        match (method, path) {
            ("POST", p) if p.starts_with("/containers/") && p.ends_with("/exec") => {
                state
                    .lock()
                    .unwrap()
                    .create_bodies
                    .push(request_json_body(&request));
                respond(&mut stream, "201 Created", r#"{"Id":"e1"}"#).await;
            }
            ("POST", "/exec/e1/start") => {
                run_script(stream, &script, &state).await;
                return;
            }
            ("GET", "/exec/e1/json") => answer_exec_inspect(&mut stream, &script, &state).await,
            ("GET", p) if p.starts_with("/containers/") && p.ends_with("/json") => {
                respond(&mut stream, "200 OK", &script.container_body).await;
            }
            _ => panic!("scripted exec daemon has no route for {line}"),
        }
    }
}

async fn respond(stream: &mut UnixStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

async fn answer_exec_inspect(
    stream: &mut UnixStream,
    script: &ExecScript,
    state: &Mutex<ExecState>,
) {
    let running = !state.lock().unwrap().finished;
    let body = format!(r#"{{"Running":{running},"ExitCode":{}}}"#, script.exit_code);
    respond(stream, "200 OK", &body).await;
    if !running {
        state.lock().unwrap().stopped_answered = true;
    }
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 0, 0, 0];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn run_script(mut stream: UnixStream, script: &ExecScript, state: &Arc<Mutex<ExecState>>) {
    stream
        .write_all(
            b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
        )
        .await
        .unwrap();
    if script.read_stdin_to_eof {
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        let mut state = state.lock().unwrap();
        state.stdin_received = received;
        state.stdin_eof = true;
    }
    let mut frames = frame(1, &script.stdout);
    frames.extend(frame(2, &script.stderr));
    stream.write_all(&frames).await.unwrap();
    state.lock().unwrap().finished = true;
    if let Some(tail) = &script.tail_after_stopped {
        while !state.lock().unwrap().stopped_answered {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stream.write_all(&frame(1, tail)).await.unwrap();
    }
    if script.hold_open {
        std::future::pending::<()>().await;
    }
    let _ = stream.shutdown().await;
}

/// A writer the test hands to the code under test, and a way to read back
/// everything it wrote once that code has dropped it.
pub(crate) fn capture() -> (
    Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    tokio::io::DuplexStream,
) {
    let (writer, reader) = tokio::io::duplex(1 << 16);
    (Box::new(writer), reader)
}

pub(crate) async fn read_captured(mut reader: tokio::io::DuplexStream) -> Vec<u8> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.unwrap();
    out
}

/// Run one piped exec against captured stdout and stderr, failing the test
/// instead of hanging if it outlasts `budget`. Returns what `exec` resolved to
/// and everything written to each stream.
pub(crate) async fn run_captured_piped<F>(
    budget: Duration,
    stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    exec: impl FnOnce(crate::runtime::PipedStdio) -> F,
) -> (F::Output, Vec<u8>, Vec<u8>)
where
    F: std::future::Future,
{
    let (stdout, stdout_back) = capture();
    let (stderr, stderr_back) = capture();
    let stdio = crate::runtime::PipedStdio {
        stdin,
        stdout,
        stderr,
    };
    let result = tokio::time::timeout(budget, exec(stdio))
        .await
        .unwrap_or_else(|_| {
            panic!("a piped exec must finish within {budget:?} instead of hanging")
        });
    (
        result,
        read_captured(stdout_back).await,
        read_captured(stderr_back).await,
    )
}
