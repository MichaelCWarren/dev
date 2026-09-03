//! A fake Unix-socket daemon for tests that need to inspect the HTTP request bollard
//! sends without a live Docker or Podman daemon behind the socket.

use tokio::io::AsyncReadExt;

pub(crate) async fn read_http_request(stream: &mut tokio::net::UnixStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0, "client closed before sending the request");
        buf.extend_from_slice(&chunk[..n]);
        if request_complete(&buf) {
            return String::from_utf8(buf).unwrap();
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
