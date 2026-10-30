use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// The caller's own byte streams for a non-TTY exec: what feeds the process's
/// stdin, and where its stdout and stderr go.
pub struct PipedStdio {
    pub stdin: Box<dyn AsyncRead + Send + Unpin>,
    pub stdout: Box<dyn AsyncWrite + Send + Unpin>,
    pub stderr: Box<dyn AsyncWrite + Send + Unpin>,
}

/// Copy `reader` into `writer` until the reader's EOF, then half-close the
/// writer so the process on the other end sees its own EOF.
pub(crate) async fn forward_stdin<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await
}
