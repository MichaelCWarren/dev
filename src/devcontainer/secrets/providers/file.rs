//! The `file` provider: the reference names a path on the host and the file's
//! contents are the secret, with one trailing line ending removed.
//!
//! Relative paths resolve against the workspace folder, the same base
//! `run_args::resolve_env_file_path` uses and the same context
//! `${localWorkspaceFolder}` resolves to — not the `.devcontainer/` directory
//! that holds `secrets.json`. Variables are already substituted by the time a
//! ref arrives here; `~` is not, and nothing here expands it.
//!
//! The reads are `std::fs`, not `tokio::fs`, even though they sit inside an
//! async block. Nothing in the tree uses `tokio::fs`: `up.rs`, `exec.rs`,
//! `apple.rs`, `compose.rs`, and `run_args.rs` all read files with `std::fs`
//! from async call paths. A secrets reference points at a small local file, and
//! `tokio::fs` would answer it by handing the same blocking read to a
//! `spawn_blocking` thread. That costs more than the read it defers, and
//! `main.rs` documents why the blocking pool is something to stay out of: the
//! runtime's shutdown grace is `Duration::ZERO` because a parked blocking task
//! holds the process at exit with nothing printed. Providers that spawn
//! subprocesses are the other side of this line and should use `tokio::process`.
//!
//! There is no empty-reference check because `SecretRef` cannot carry one:
//! `new` and `from_json` reject an empty body and `substitute` returns `Err`
//! rather than hand over a body substitution emptied. If that ever weakened, an
//! empty reference would join onto the workspace folder and yield the workspace
//! folder itself, which the directory arm reports without reading anything.

use super::super::SecretValue;
use super::super::provider::{ResolvedBatch, SecretProvider};
use super::super::reference::SecretRef;
use super::trim_trailing_newline;
use crate::runtime::BoxFut;
use std::path::{Path, PathBuf};

/// Reads secrets out of files on the host.
// The allow comes off when the registry registers the built-ins (Group 5).
#[allow(dead_code)]
pub struct FileProvider {
    workspace: PathBuf,
}

#[allow(dead_code)]
impl FileProvider {
    /// `workspace` is the host workspace folder relative references resolve
    /// against. It is constructor state because `resolve` has nowhere to pass
    /// it, and the process working directory is never consulted.
    pub fn new(workspace: &Path) -> Self {
        FileProvider {
            workspace: workspace.to_path_buf(),
        }
    }

    /// `Err` carries a per-key reason, not a `DevError`: nothing a file read can
    /// hit is a whole-batch failure, and the type is what keeps that true.
    fn read_one(&self, secret: &SecretRef) -> Result<SecretValue, String> {
        if let Some(name) = secret.options().keys().next() {
            return Err(format!(
                "the `file` provider takes no options, but `{name}` was given"
            ));
        }
        let path = self.resolve_path(secret.reference());
        let shown = path.display();
        match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(format!("file `{shown}` does not exist"))
            }
            Err(e) => Err(format!("cannot read file `{shown}`: {e}")),
            Ok(md) if md.is_dir() => Err(format!("`{shown}` is a directory, not a file")),
            Ok(_) => {
                let bytes =
                    std::fs::read(&path).map_err(|e| format!("cannot read file `{shown}`: {e}"))?;
                // Never interpolate the bytes: they are the secret.
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| format!("file `{shown}` is not valid UTF-8"))?;
                Ok(SecretValue::new(trim_trailing_newline(text)))
            }
        }
    }

    /// Absolute paths as given, relative paths against the workspace folder.
    /// Same rule as `run_args::resolve_env_file_path`.
    fn resolve_path(&self, reference: &str) -> PathBuf {
        let path = PathBuf::from(reference);
        if path.is_absolute() {
            path
        } else {
            self.workspace.join(path)
        }
    }
}

impl SecretProvider for FileProvider {
    fn name(&self) -> &str {
        "file"
    }

    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        Box::pin(async move {
            let mut batch = ResolvedBatch::new();
            for secret in refs {
                match self.read_one(secret) {
                    Ok(value) => batch.push_value(secret.key(), value),
                    Err(reason) => batch.push_failure(secret.key(), reason),
                }
            }
            Ok(batch)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn secret_ref(key: &str, reference: &str) -> SecretRef {
        SecretRef::new(key, "file", reference).unwrap()
    }

    fn write(dir: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Resolve one ref against a provider rooted at `dir`.
    async fn resolve_one(dir: &TempDir, secret: SecretRef) -> ResolvedBatch {
        let refs = vec![secret];
        FileProvider::new(dir.path()).resolve(&refs).await.unwrap()
    }

    /// The single value of a batch expected to hold exactly one.
    fn only_value(batch: &ResolvedBatch) -> (&str, &str) {
        assert!(batch.failures().is_empty(), "{:?}", batch.failures());
        assert_eq!(batch.values().len(), 1);
        let (key, value) = &batch.values()[0];
        (key.as_str(), value.expose())
    }

    /// The single failure reason of a batch expected to hold exactly one.
    fn only_failure(batch: &ResolvedBatch) -> (&str, &str) {
        assert!(batch.values().is_empty(), "resolved a value it should not");
        assert_eq!(batch.failures().len(), 1);
        let failure = &batch.failures()[0];
        (failure.key.as_str(), failure.reason.as_str())
    }

    /// Write `contents` to `tmp/token` and return what the provider resolves.
    async fn value_of(dir: &TempDir, contents: &[u8]) -> String {
        write(dir, "token", contents);
        let batch = resolve_one(dir, secret_ref("TOKEN", "token")).await;
        only_value(&batch).1.to_string()
    }

    #[test]
    fn file_provider_name_is_file() {
        assert_eq!(FileProvider::new(Path::new("/w")).name(), "file");
    }

    #[tokio::test]
    async fn file_provider_reads_an_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let path = write(&tmp, "token", b"hunter2\n");
        let other = TempDir::new().unwrap();
        let batch = resolve_one(&other, secret_ref("TOKEN", &path.display().to_string())).await;
        assert_eq!(only_value(&batch), ("TOKEN", "hunter2"));
    }

    #[tokio::test]
    async fn file_provider_resolves_a_relative_path_against_the_workspace() {
        let tmp = TempDir::new().unwrap();
        write(&tmp, "sub/token", b"hunter2\n");
        let batch = resolve_one(&tmp, secret_ref("TOKEN", "sub/token")).await;
        assert_eq!(only_value(&batch), ("TOKEN", "hunter2"));

        let elsewhere = TempDir::new().unwrap();
        let batch = resolve_one(&elsewhere, secret_ref("TOKEN", "sub/token")).await;
        assert!(only_failure(&batch).1.contains("does not exist"));
    }

    #[tokio::test]
    async fn file_provider_trims_one_trailing_newline() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(value_of(&tmp, b"v\n").await, "v");
    }

    #[tokio::test]
    async fn file_provider_trims_a_trailing_crlf() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(value_of(&tmp, b"v\r\n").await, "v");
    }

    #[tokio::test]
    async fn file_provider_keeps_a_second_trailing_newline() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(value_of(&tmp, b"v\n\n").await, "v\n");
    }

    #[tokio::test]
    async fn file_provider_keeps_interior_and_leading_whitespace() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(value_of(&tmp, b"  a b\nc \n").await, "  a b\nc ");
    }

    #[tokio::test]
    async fn file_provider_reads_an_empty_file_as_an_empty_value() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(value_of(&tmp, b"").await, "");
    }

    #[tokio::test]
    async fn file_provider_reports_a_missing_path_as_a_key_failure() {
        let tmp = TempDir::new().unwrap();
        let batch = resolve_one(&tmp, secret_ref("TOKEN", "token")).await;
        let (key, reason) = only_failure(&batch);
        assert_eq!(key, "TOKEN");
        assert!(
            reason.contains(&tmp.path().join("token").display().to_string()),
            "names the path: {reason}"
        );
    }

    #[tokio::test]
    async fn file_provider_reports_a_directory_as_a_key_failure() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().display().to_string();
        let batch = resolve_one(&tmp, secret_ref("TOKEN", &dir)).await;
        let reason = only_failure(&batch).1;
        assert!(reason.contains(&dir), "names the path: {reason}");
        assert!(reason.contains("directory"), "says why: {reason}");
    }

    #[tokio::test]
    async fn file_provider_reports_a_dot_reference_as_a_directory() {
        let tmp = TempDir::new().unwrap();
        let batch = resolve_one(&tmp, secret_ref("TOKEN", ".")).await;
        assert!(only_failure(&batch).1.contains("directory"));
    }

    #[tokio::test]
    async fn file_provider_reports_non_utf8_without_printing_bytes() {
        let tmp = TempDir::new().unwrap();
        write(&tmp, "token", b"hunter2\xff\xfe");
        let batch = resolve_one(&tmp, secret_ref("TOKEN", "token")).await;
        let reason = only_failure(&batch).1;
        assert!(
            reason.contains(&tmp.path().join("token").display().to_string()),
            "names the path: {reason}"
        );
        assert!(!reason.contains("hunter2"), "leaked contents: {reason}");
    }

    #[tokio::test]
    async fn file_provider_keys_the_value_by_the_secrets_json_key() {
        let tmp = TempDir::new().unwrap();
        write(&tmp, "token", b"hunter2\n");
        let batch = resolve_one(&tmp, secret_ref("DB_PASSWORD", "token")).await;
        assert_eq!(only_value(&batch).0, "DB_PASSWORD");
    }

    #[tokio::test]
    async fn file_provider_failure_reason_does_not_repeat_the_key() {
        let tmp = TempDir::new().unwrap();
        let batch = resolve_one(&tmp, secret_ref("DB_PASSWORD", "token")).await;
        let reason = only_failure(&batch).1;
        assert!(!reason.contains("DB_PASSWORD"), "repeats the key: {reason}");
    }

    #[tokio::test]
    async fn file_provider_failure_reason_names_the_resolved_path() {
        let tmp = TempDir::new().unwrap();
        let batch = resolve_one(&tmp, secret_ref("TOKEN", "sub/token")).await;
        let reason = only_failure(&batch).1;
        assert!(
            reason.contains(&tmp.path().join("sub/token").display().to_string()),
            "names the joined path: {reason}"
        );
    }

    #[tokio::test]
    async fn file_provider_rejects_any_provider_option() {
        let tmp = TempDir::new().unwrap();
        write(&tmp, "token", b"hunter2\n");
        let secret = secret_ref("TOKEN", "token").with_option("account", "work".into());
        let batch = resolve_one(&tmp, secret).await;
        let reason = only_failure(&batch).1;
        assert!(reason.contains("account"), "names the option: {reason}");
    }

    #[tokio::test]
    async fn file_provider_resolves_the_rest_of_the_batch_around_a_failure() {
        let tmp = TempDir::new().unwrap();
        write(&tmp, "one", b"1\n");
        write(&tmp, "three", b"3\n");
        let refs = vec![
            secret_ref("ONE", "one"),
            secret_ref("TWO", "missing"),
            secret_ref("THREE", "three"),
        ];
        let batch = FileProvider::new(tmp.path()).resolve(&refs).await.unwrap();

        let keys: Vec<&str> = batch.values().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["ONE", "THREE"]);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "TWO");
    }

    #[tokio::test]
    async fn file_provider_ignores_the_optional_flag() {
        let tmp = TempDir::new().unwrap();
        let secret = secret_ref("TOKEN", "token").with_optional(true);
        let batch = resolve_one(&tmp, secret).await;
        assert_eq!(only_failure(&batch).0, "TOKEN");
    }
}
