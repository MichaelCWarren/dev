use std::io::Write;
use std::path::Path;

/// Written whole or not at all, readable by the owner only. The temp file
/// sits beside the target so the rename never crosses a filesystem.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let temp = dir.join(format!("{name}.{}.tmp", std::process::id()));
    let mut open = std::fs::OpenOptions::new();
    open.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let written = open
        .open(&temp)
        .and_then(|mut file| file.write_all(bytes))
        .and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// A file that is already gone counts as removed.
pub(crate) fn remove_if_present(path: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Whether [`lock_file`] waits for another holder or gives up at once.
pub(crate) enum LockWait {
    Block,
    NonBlocking,
}

/// Open `path` (created at 0600 when missing) and take an exclusive `flock`
/// on it, released when the file drops. `Ok(None)` only for
/// [`LockWait::NonBlocking`] when someone else holds the lock.
pub(crate) fn lock_file(path: &Path, wait: LockWait) -> anyhow::Result<Option<std::fs::File>> {
    use anyhow::Context;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let operation = match wait {
        LockWait::Block => libc::LOCK_EX,
        LockWait::NonBlocking => libc::LOCK_EX | libc::LOCK_NB,
    };
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        return Ok(Some(file));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error).with_context(|| format!("locking {}", path.display()))
}
