use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runtime::ExecResult;
use crate::util::naming::workspace_hash;
use crate::util::paths::DevHome;

/// Persisted record of one `dev up` run's lifecycle-hook output.
///
/// Hooks stream nothing to the terminal on success, so a failed `dev up` used
/// to leave no trace of what its hooks printed. Every hook's buffered output —
/// success and failure alike — is appended here, and `dev logs` replays it.
///
/// One log per workspace at `~/.dev/logs/<hash>/hooks.log`; the previous run
/// survives as `hooks.prev.log`. Logging must never fail a hook, so all IO
/// errors degrade to a single stderr warning.
pub struct HookLog {
    file: Mutex<File>,
    pub path: PathBuf,
}

impl HookLog {
    /// Rotate the previous run's log aside and start a fresh one with a run
    /// header. The caller downgrades an `Err` to a warning and logs nothing.
    pub fn begin(dev_home: &DevHome, workspace: &Path, run_kind: &str) -> anyhow::Result<HookLog> {
        let dir = dev_home.workspace_logs_dir(&workspace_hash(workspace));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("hooks.log");
        if path.exists() {
            std::fs::rename(&path, dir.join("hooks.prev.log"))?;
        }
        let mut open = OpenOptions::new();
        open.create_new(true).write(true);
        #[cfg(unix)]
        {
            // Hook output can carry secret material; keep it owner-only.
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let mut file = open.open(&path)?;
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        writeln!(
            file,
            "=== dev up ({run_kind}) at {epoch} workspace={} ===",
            workspace.display()
        )?;
        Ok(HookLog {
            file: Mutex::new(file),
            path,
        })
    }

    /// Append one hook's outcome and output. Never fails the hook.
    pub fn record(&self, name: &str, command: &str, result: &ExecResult) {
        let mut entry = format!("--- {name}: {command} (exit {}) ---\n", result.exit_code);
        for (label, output) in [("stdout", &result.stdout), ("stderr", &result.stderr)] {
            if !output.is_empty() {
                entry.push_str(&format!("[{label}]\n{output}"));
                if !output.ends_with('\n') {
                    entry.push('\n');
                }
            }
        }
        let mut file = match self.file.lock() {
            Ok(f) => f,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(e) = file.write_all(entry.as_bytes()) {
            eprintln!(
                "Warning: could not append to hook log {}: {e}",
                self.path.display()
            );
        }
    }
}

/// The workspace's current hook log path, if a run has written one.
pub fn hook_log_path(dev_home: &DevHome, workspace: &Path) -> PathBuf {
    dev_home
        .workspace_logs_dir(&workspace_hash(workspace))
        .join("hooks.log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn exec_result(exit_code: i32, stdout: &str, stderr: &str) -> ExecResult {
        ExecResult {
            exit_code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn begin_writes_header_and_rotates_previous_log() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());

        let log = HookLog::begin(&dev_home, workspace.path(), "create").unwrap();
        log.record(
            "postCreateCommand",
            "echo one",
            &exec_result(0, "one\n", ""),
        );
        drop(log);

        let log = HookLog::begin(&dev_home, workspace.path(), "start").unwrap();
        log.record("postStartCommand", "echo two", &exec_result(0, "two\n", ""));

        let current = std::fs::read_to_string(&log.path).unwrap();
        assert!(current.starts_with("=== dev up (start) at "));
        assert!(current.contains("echo two"));
        assert!(!current.contains("echo one"), "runs must not accumulate");

        let prev = std::fs::read_to_string(log.path.with_file_name("hooks.prev.log")).unwrap();
        assert!(prev.contains("echo one"), "the previous run survives once");
    }

    #[test]
    fn record_appends_name_command_exit_and_both_streams() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let log = HookLog::begin(&DevHome::at(home.path()), workspace.path(), "create").unwrap();

        log.record(
            "postCreateCommand [greeter]",
            "npm install",
            &exec_result(1, "added 12 packages\n", "npm WARN deprecated\n"),
        );

        let content = std::fs::read_to_string(&log.path).unwrap();
        assert!(content.contains("--- postCreateCommand [greeter]: npm install (exit 1) ---"));
        assert!(content.contains("[stdout]\nadded 12 packages\n"));
        assert!(content.contains("[stderr]\nnpm WARN deprecated\n"));
    }

    #[test]
    fn record_omits_empty_stream_sections() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let log = HookLog::begin(&DevHome::at(home.path()), workspace.path(), "create").unwrap();

        log.record("postStartCommand", "true", &exec_result(0, "", ""));

        let content = std::fs::read_to_string(&log.path).unwrap();
        assert!(content.contains("--- postStartCommand: true (exit 0) ---"));
        assert!(!content.contains("[stdout]"));
        assert!(!content.contains("[stderr]"));
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let log = HookLog::begin(&DevHome::at(home.path()), workspace.path(), "create").unwrap();

        let mode = std::fs::metadata(&log.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "hook output can carry secrets");
    }
}
