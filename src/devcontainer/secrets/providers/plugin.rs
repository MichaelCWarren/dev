//! The `dev-secret-*` plugin protocol: how dev talks to a secret provider it
//! does not ship.
//!
//! A provider name no built-in answers to resolves to an executable
//! `dev-secret-<name>` on `PATH`, the same fallback git and the docker CLI use.
//! Dev runs it once per batch with one JSON request on stdin and reads one JSON
//! response from stdout.
//!
//! Request, all fields required except `secrets[].options`:
//!
//! ```json
//! {
//!   "version": 1,
//!   "provider": "vault",
//!   "workspaceFolder": "/Users/me/code/fsm",
//!   "secrets": [
//!     { "key": "VAULT_DB_PASSWORD", "ref": "kv/data/prod/db#password" },
//!     { "key": "VAULT_API_TOKEN", "ref": "kv/data/prod/api#token",
//!       "options": { "namespace": "team-a" } }
//!   ]
//! }
//! ```
//!
//! `provider` is the bare name from the reference, not the executable name, so
//! one binary linked under several names can tell which one it was invoked as.
//! `ref` has the `foo://` scheme already stripped. `options` carries the object
//! form's unrecognised keys verbatim, absent when empty; an option written as
//! `""` stays on the wire as `""` and stays distinguishable from one that is
//! not there. Dev never sends `optional` or `createTime`: what to do about a
//! failure is dev's policy, not the plugin's.
//!
//! Response, `version` required, `error` and `secrets` both optional:
//!
//! ```json
//! {
//!   "version": 1,
//!   "secrets": [
//!     { "key": "VAULT_DB_PASSWORD", "value": "s3cr3t" },
//!     { "key": "VAULT_API_TOKEN", "error": "no such path" }
//!   ]
//! }
//! ```
//!
//! Exactly one of `value` and `error` per entry. A top-level `error` fails the
//! whole batch. Unknown fields are ignored, so a plugin can add one without
//! breaking an older dev, and entries for keys dev did not ask for are ignored
//! too. Values are taken verbatim, newline and all.
//!
//! The rule plugin authors get wrong: **a plugin reporting a failure exits 0 and
//! sets `error`**. A non-zero exit means the plugin crashed, and dev reports the
//! exit code rather than trusting whatever landed on stdout.
//!
//! stderr is inherited and dev never reads or reprints it. It is the plugin's
//! own channel to the user's terminal, which is what lets a plugin prompt. That
//! also means `error` strings must not contain secret material: dev prints them
//! and dev cannot inspect them.
//!
//! Dev owns no clock here. It waits as long as the plugin takes and never kills
//! it, so a plugin may wait on a fingerprint, a hardware key, or a 2FA push. In
//! exchange a plugin owns the timeout on anything that can hang with nobody
//! present, network calls above all. After ten seconds dev prints one warning
//! naming the plugin, which is a notice to the user rather than a deadline.
//!
//! A plugin inherits dev's full environment, deliberately: `VAULT_ADDR`, `HOME`,
//! and session tokens all have to reach it. So a plugin on `PATH` runs with
//! whatever ambient credentials the user has. `postCreateCommand` already runs
//! arbitrary shell out of the same config, so this adds no trust that was not
//! there. Nothing here caches: the same refs are resolved again at exec time.

use crate::devcontainer::secrets::provider::PluginBinary;
use crate::devcontainer::secrets::{ResolvedBatch, SecretProvider, SecretRef, SecretValue};
use crate::error::DevError;
use crate::runtime::BoxFut;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// The protocol version dev speaks. A response carrying anything else is refused.
pub const PLUGIN_PROTOCOL_VERSION: u32 = 1;

/// How long dev waits before telling the user which plugin it is waiting on.
const WAITING_NOTICE_AFTER: Duration = Duration::from_secs(10);

/// What a `Debug` impl prints in place of a value.
const REDACTED: &str = "***";

/// One request object, written to the plugin's stdin followed by a newline.
///
/// `Debug` is derived and stays safe: a request holds keys, references, and
/// options, none of which is a value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginRequest {
    pub version: u32,
    pub provider: String,
    #[serde(rename = "workspaceFolder")]
    pub workspace_folder: String,
    pub secrets: Vec<PluginRequestSecret>,
}

/// One secret dev is asking the plugin to resolve.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginRequestSecret {
    pub key: String,
    #[serde(rename = "ref")]
    pub reference: String,
    /// `skip_serializing_if` applies to the map, never to a value inside it, so
    /// an option written as `""` survives as `""`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, serde_json::Value>,
}

/// One response object, read from the plugin's stdout.
///
/// No `derive(Debug)`: an entry's `value` is the secret. See the hand-written
/// impls below. No `Serialize` either, because dev never writes a response.
#[derive(Clone, Deserialize)]
pub struct PluginResponse {
    pub version: u32,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub secrets: Vec<PluginResponseSecret>,
}

/// What the plugin has to say about one key: a value, or why there is none.
#[derive(Clone, Deserialize)]
pub struct PluginResponseSecret {
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl std::fmt::Debug for PluginResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginResponse")
            .field("version", &self.version)
            .field("error", &self.error)
            .field("secrets", &self.secrets)
            .finish()
    }
}

impl std::fmt::Debug for PluginResponseSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginResponseSecret")
            .field("key", &self.key)
            .field("value", &self.value.as_ref().map(|_| REDACTED))
            .field("error", &self.error)
            .finish()
    }
}

/// What the plugin said about one key, once the protocol checks have passed.
type Answer = Result<SecretValue, String>;

/// Resolves one provider's batch by running its `dev-secret-<provider>` binary.
///
/// Built from the [`PluginBinary`] the registry already found, so the `PATH`
/// search happens once, at validation time, and a test can point straight at a
/// fixture script without touching the process environment.
pub struct PluginProvider {
    provider: String,
    program: PathBuf,
    workspace: PathBuf,
}

impl PluginProvider {
    pub fn new(binary: PluginBinary, workspace: impl Into<PathBuf>) -> Self {
        PluginProvider {
            provider: binary.provider,
            program: binary.path,
            workspace: workspace.into(),
        }
    }

    /// The executable name, which is what a user greps for and what every
    /// message here names.
    fn binary_name(&self) -> String {
        format!("dev-secret-{}", self.provider)
    }

    /// Every whole-batch failure this file reports. `reason` never carries
    /// stdout, stderr, or a `serde_json::Error`.
    fn failed(&self, reason: impl Into<String>) -> DevError {
        DevError::SecretProviderFailed {
            provider: self.provider.clone(),
            reason: reason.into(),
        }
    }

    fn build_request(&self, refs: &[SecretRef]) -> PluginRequest {
        PluginRequest {
            version: PLUGIN_PROTOCOL_VERSION,
            provider: self.provider.clone(),
            workspace_folder: self.workspace.to_string_lossy().into_owned(),
            secrets: refs
                .iter()
                .map(|secret| PluginRequestSecret {
                    key: secret.key().to_string(),
                    reference: secret.reference().to_string(),
                    options: secret.options().clone(),
                })
                .collect(),
        }
    }

    /// Spawn the plugin, hand it the request, and return its raw stdout.
    async fn run_plugin(&self, request: &PluginRequest) -> Result<Vec<u8>, DevError> {
        let mut body = serde_json::to_vec(request).map_err(|_| {
            self.failed(format!(
                "could not encode the request for plugin `{}`",
                self.binary_name()
            ))
        })?;
        body.push(b'\n');

        let mut child = tokio::process::Command::new(&self.program)
            .current_dir(&self.workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| self.spawn_error(err))?;

        if let Some(mut stdin) = child.stdin.take() {
            // A plugin may answer without draining stdin, which closes the pipe
            // under us. Its response is what matters, so a broken pipe here is
            // not a failure. Dropping the handle before awaiting the output is
            // what keeps such a plugin from deadlocking against dev.
            match stdin.write_all(&body).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(err) => {
                    return Err(self.failed(format!(
                        "could not send the request to plugin `{}`: {err}",
                        self.binary_name()
                    )));
                }
            }
        }

        let output = self.wait_with_notice(child).await?;
        if !output.status.success() {
            return Err(self.failed(self.exit_reason(output.status)));
        }
        Ok(output.stdout)
    }

    /// Wait for the plugin, warning once at [`WAITING_NOTICE_AFTER`] so a
    /// wedged plugin is visible without a legitimate prompt being killed.
    async fn wait_with_notice(
        &self,
        child: tokio::process::Child,
    ) -> Result<std::process::Output, DevError> {
        let finished = child.wait_with_output();
        tokio::pin!(finished);
        let output = tokio::select! {
            done = &mut finished => done,
            _ = tokio::time::sleep(WAITING_NOTICE_AFTER) => {
                eprintln!("Warning: {}", waiting_notice(&self.provider));
                finished.await
            }
        };
        output.map_err(|err| {
            self.failed(format!(
                "could not run plugin `{}` at {}: {err}",
                self.binary_name(),
                self.program.display()
            ))
        })
    }

    /// A file that lost its execute bit between validation and now, versus
    /// anything else. The spawn already tells us, so nothing stats the file.
    fn spawn_error(&self, err: std::io::Error) -> DevError {
        let path = self.program.display();
        let name = self.binary_name();
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            return self.failed(format!(
                "plugin `{name}` at {path} is not executable; run `chmod +x {path}`"
            ));
        }
        self.failed(format!("could not run plugin `{name}` at {path}: {err}"))
    }

    fn exit_reason(&self, status: std::process::ExitStatus) -> String {
        let name = self.binary_name();
        match status.code() {
            Some(code) => format!(
                "plugin `{name}` exited with code {code}; a plugin reporting a failure \
                 should exit 0 and set `error` in its response"
            ),
            None => format!("plugin `{name}` was killed by a signal"),
        }
    }

    /// Parse stdout. Neither the bytes nor serde's own message reaches the
    /// error: serde reports unexpected values inline, and a value is what this
    /// file must never print.
    fn parse_response(&self, stdout: &[u8]) -> Result<PluginResponse, DevError> {
        let response: PluginResponse = serde_json::from_slice(stdout).map_err(|_| {
            self.failed(format!(
                "plugin `{}` did not write a valid version {PLUGIN_PROTOCOL_VERSION} \
                 response on stdout",
                self.binary_name()
            ))
        })?;
        if response.version != PLUGIN_PROTOCOL_VERSION {
            return Err(self.failed(format!(
                "plugin `{}` replied with protocol version {}; this build of dev speaks \
                 version {PLUGIN_PROTOCOL_VERSION}",
                self.binary_name(),
                response.version
            )));
        }
        Ok(response)
    }

    /// Turn a parsed response into a batch. A key the plugin failed and a key it
    /// never mentioned both become a `KeyFailure`, so the registry can apply
    /// `optional` to them alike. Nothing here reads `optional` or drops a key.
    fn collect(
        &self,
        refs: &[SecretRef],
        response: PluginResponse,
    ) -> Result<ResolvedBatch, DevError> {
        if let Some(error) = response.error {
            return Err(self.failed(error));
        }
        let answers = self.answers(refs, response.secrets)?;

        let mut batch = ResolvedBatch::new();
        for secret in refs {
            match answers.get(secret.key()) {
                Some(Ok(value)) => batch.push_value(secret.key(), value.clone()),
                Some(Err(reason)) => batch.push_failure(secret.key(), reason.clone()),
                None => batch.push_failure(
                    secret.key(),
                    format!(
                        "plugin `{}` returned no entry for this key",
                        self.binary_name()
                    ),
                ),
            }
        }
        Ok(batch)
    }

    /// One answer per requested key the plugin mentioned. Entries for keys
    /// nobody asked for are dropped; a malformed entry fails the whole batch,
    /// because a plugin that cannot follow the schema cannot be trusted about
    /// the keys it did answer.
    fn answers(
        &self,
        refs: &[SecretRef],
        entries: Vec<PluginResponseSecret>,
    ) -> Result<BTreeMap<String, Answer>, DevError> {
        let name = self.binary_name();
        let mut answers: BTreeMap<String, Answer> = BTreeMap::new();
        for entry in entries {
            if !refs.iter().any(|secret| secret.key() == entry.key) {
                continue;
            }
            let key = entry.key;
            let answer = match (entry.value, entry.error) {
                (Some(value), None) => Ok(SecretValue::new(value)),
                (None, Some(error)) => Err(error),
                (Some(_), Some(_)) => {
                    return Err(self.failed(format!(
                        "plugin `{name}` returned an entry for `{key}` with both `value` and `error`"
                    )));
                }
                (None, None) => {
                    return Err(self.failed(format!(
                        "plugin `{name}` returned an entry for `{key}` with neither `value` nor `error`"
                    )));
                }
            };
            if answers.insert(key.clone(), answer).is_some() {
                return Err(
                    self.failed(format!("plugin `{name}` returned two entries for `{key}`"))
                );
            }
        }
        Ok(answers)
    }
}

impl SecretProvider for PluginProvider {
    fn name(&self) -> &str {
        &self.provider
    }

    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        Box::pin(async move {
            if refs.is_empty() {
                return Ok(ResolvedBatch::new());
            }
            let request = self.build_request(refs);
            let stdout = self.run_plugin(&request).await?;
            let response = self.parse_response(&stdout)?;
            self.collect(refs, response)
        })
    }
}

/// The line dev prints once it has waited [`WAITING_NOTICE_AFTER`]. Built here
/// so the text is testable without the clock.
fn waiting_notice(provider: &str) -> String {
    format!(
        "still waiting on the `dev-secret-{provider}` plugin; it may be waiting for you \
         to approve something"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::TempDir;

    const VALUE: &str = "hunter2";

    /// The response every fixture that only has to succeed writes back.
    const TWO_VALUES: &str =
        r#"{"version":1,"secrets":[{"key":"A","value":"alpha"},{"key":"B","value":"beta"}]}"#;

    fn secret_ref(key: &str, reference: &str) -> SecretRef {
        SecretRef::new(key, "vault", reference).unwrap()
    }

    fn binary(path: PathBuf) -> PluginBinary {
        PluginBinary {
            provider: "vault".to_string(),
            path,
        }
    }

    /// A provider whose program does not exist, for the tests that never spawn.
    fn offline(workspace: &str) -> PluginProvider {
        PluginProvider::new(
            binary(PathBuf::from("/nonexistent/dev-secret-vault")),
            workspace,
        )
    }

    /// A `/bin/sh` fixture in `dir`, run with `workspace` as its cwd.
    fn plugin_in(dir: &Path, workspace: &Path, body: &str) -> PluginProvider {
        let path = dir.join("dev-secret-vault");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        PluginProvider::new(binary(path), workspace)
    }

    fn plugin(dir: &TempDir, body: &str) -> PluginProvider {
        plugin_in(dir.path(), dir.path(), body)
    }

    /// A fixture that drains stdin and answers with `response`.
    fn responder(dir: &TempDir, response: &str) -> PluginProvider {
        plugin(dir, &format!("cat >/dev/null\necho '{response}'"))
    }

    fn parse(response: &str) -> PluginResponse {
        offline("/w").parse_response(response.as_bytes()).unwrap()
    }

    fn collect(refs: &[SecretRef], response: &str) -> Result<ResolvedBatch, DevError> {
        offline("/w").collect(refs, parse(response))
    }

    fn value_keys(batch: &ResolvedBatch) -> Vec<&str> {
        batch.values().iter().map(|(key, _)| key.as_str()).collect()
    }

    #[test]
    fn request_serializes_to_the_documented_shape() {
        let refs = vec![
            secret_ref("VAULT_DB_PASSWORD", "kv/data/prod/db#password"),
            secret_ref("VAULT_API_TOKEN", "kv/data/prod/api#token")
                .with_option("namespace", json!("team-a")),
        ];
        let request = offline("/Users/me/code/fsm").build_request(&refs);

        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "version": 1,
                "provider": "vault",
                "workspaceFolder": "/Users/me/code/fsm",
                "secrets": [
                    { "key": "VAULT_DB_PASSWORD", "ref": "kv/data/prod/db#password" },
                    {
                        "key": "VAULT_API_TOKEN",
                        "ref": "kv/data/prod/api#token",
                        "options": { "namespace": "team-a" }
                    }
                ]
            })
        );
    }

    #[test]
    fn request_round_trips() {
        let refs = vec![
            secret_ref("A", "kv/a").with_option("namespace", json!("team-a")),
            secret_ref("B", "kv/b"),
        ];
        let request = offline("/w").build_request(&refs);
        let text = serde_json::to_string(&request).unwrap();

        assert_eq!(
            serde_json::from_str::<PluginRequest>(&text).unwrap(),
            request
        );
    }

    #[test]
    fn request_omits_empty_options() {
        let request = offline("/w").build_request(&[secret_ref("A", "kv/a")]);
        let entry = &serde_json::to_value(&request).unwrap()["secrets"][0];

        assert!(
            entry.get("options").is_none(),
            "carried an empty map: {entry}"
        );
    }

    #[test]
    fn empty_option_value_survives_serialization() {
        let refs = vec![secret_ref("A", "kv/a").with_option("account", json!(""))];
        let request = offline("/w").build_request(&refs);
        let entry = &serde_json::to_value(&request).unwrap()["secrets"][0];

        assert_eq!(entry["options"], json!({ "account": "" }));
    }

    #[test]
    fn response_parses_mixed_value_and_error_entries() {
        let refs = vec![secret_ref("A", "kv/a"), secret_ref("B", "kv/b")];
        let batch = collect(
            &refs,
            r#"{"version":1,"secrets":[
                {"key":"A","value":"alpha"},
                {"key":"B","error":"no such path: kv/b"}
            ]}"#,
        )
        .unwrap();

        assert_eq!(value_keys(&batch), vec!["A"]);
        assert_eq!(batch.values()[0].1.expose(), "alpha");
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "B");
        assert_eq!(batch.failures()[0].reason, "no such path: kv/b");
    }

    #[test]
    fn response_ignores_unknown_fields() {
        let refs = vec![secret_ref("A", "kv/a")];
        let batch = collect(
            &refs,
            r#"{"version":1,"ttl":5,"secrets":[{"key":"A","value":"alpha","source":"cache"}]}"#,
        )
        .unwrap();

        assert_eq!(batch.values()[0].1.expose(), "alpha");
    }

    #[test]
    fn response_ignores_unrequested_keys() {
        let refs = vec![secret_ref("A", "kv/a")];
        let batch = collect(
            &refs,
            r#"{"version":1,"secrets":[
                {"key":"A","value":"alpha"},
                {"key":"UNASKED","value":"beta"},
                {"key":"ALSO_UNASKED","error":"whatever"}
            ]}"#,
        )
        .unwrap();

        assert_eq!(value_keys(&batch), vec!["A"]);
        assert!(batch.failures().is_empty());
    }

    #[test]
    fn response_debug_redacts_values() {
        let response = parse(&format!(
            r#"{{"version":1,"secrets":[{{"key":"A","value":"{VALUE}"}}]}}"#
        ));
        let out = format!("{response:?}");

        assert!(out.contains("A"), "keeps the key: {out}");
        assert!(out.contains("***"), "redacts: {out}");
        assert!(!out.contains(VALUE), "leaked the value: {out}");
    }

    #[test]
    fn entry_with_both_value_and_error_fails_the_batch() {
        let refs = vec![secret_ref("A", "kv/a")];
        let err = collect(
            &refs,
            r#"{"version":1,"secrets":[{"key":"A","value":"alpha","error":"nope"}]}"#,
        )
        .unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("both"), "says what is wrong: {msg}");
        assert!(!msg.contains("alpha"), "leaked the value: {msg}");
    }

    #[test]
    fn entry_with_neither_value_nor_error_fails_the_batch() {
        let refs = vec![secret_ref("A", "kv/a")];
        let err = collect(&refs, r#"{"version":1,"secrets":[{"key":"A"}]}"#).unwrap_err();

        assert!(format!("{err}").contains("neither"), "{err}");
    }

    #[test]
    fn two_entries_for_one_key_fail_the_batch() {
        let refs = vec![secret_ref("A", "kv/a")];
        let err = collect(
            &refs,
            r#"{"version":1,"secrets":[{"key":"A","value":"x"},{"key":"A","value":"y"}]}"#,
        )
        .unwrap_err();

        assert!(format!("{err}").contains("two entries"), "{err}");
    }

    #[tokio::test]
    async fn plugin_resolves_a_batch_in_one_invocation() {
        let dir = TempDir::new().unwrap();
        let provider = plugin(
            &dir,
            &format!("cat >/dev/null\necho x >> count\necho '{TWO_VALUES}'"),
        );
        let refs = vec![secret_ref("A", "kv/a"), secret_ref("B", "kv/b")];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(value_keys(&batch), vec!["A", "B"]);
        assert_eq!(batch.values()[1].1.expose(), "beta");
        let count = std::fs::read_to_string(dir.path().join("count")).unwrap();
        assert_eq!(count.lines().count(), 1, "one invocation for the batch");
    }

    #[tokio::test]
    async fn plugin_receives_the_request_on_stdin() {
        let dir = TempDir::new().unwrap();
        let provider = plugin(&dir, &format!("cat > request.json\necho '{TWO_VALUES}'"));
        let refs = vec![
            secret_ref("A", "kv/a").with_option("namespace", json!("team-a")),
            secret_ref("B", "kv/b"),
        ];
        provider.resolve(&refs).await.unwrap();

        let sent = std::fs::read_to_string(dir.path().join("request.json")).unwrap();
        assert_eq!(
            serde_json::from_str::<PluginRequest>(&sent).unwrap(),
            provider.build_request(&refs)
        );
    }

    #[tokio::test]
    async fn plugin_runs_in_the_workspace_folder() {
        let dir = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let provider = plugin_in(
            dir.path(),
            workspace.path(),
            &format!("cat >/dev/null\npwd -P > cwd.txt\necho '{TWO_VALUES}'"),
        );
        provider.resolve(&[secret_ref("A", "kv/a")]).await.unwrap();

        let recorded = std::fs::read_to_string(workspace.path().join("cwd.txt")).unwrap();
        let expected = std::fs::canonicalize(workspace.path()).unwrap();
        assert_eq!(recorded.trim(), expected.to_string_lossy());
    }

    #[tokio::test]
    async fn non_executable_plugin_names_the_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dev-secret-vault");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let provider = PluginProvider::new(binary(path.clone()), dir.path());

        let err = provider
            .resolve(&[secret_ref("A", "kv/a")])
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "names the path: {msg}"
        );
        assert!(msg.contains("chmod +x"), "says how to fix it: {msg}");
        assert!(!msg.contains("not found"), "wrong diagnosis: {msg}");
    }

    #[tokio::test]
    async fn missing_plugin_names_the_plugin_and_the_io_error() {
        let err = offline("/")
            .resolve(&[secret_ref("A", "kv/a")])
            .await
            .unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("dev-secret-vault"), "names the plugin: {msg}");
        assert!(msg.contains("/nonexistent/"), "names the path: {msg}");
    }

    #[tokio::test]
    async fn non_zero_exit_reports_the_code_and_ignores_stdout() {
        let dir = TempDir::new().unwrap();
        let provider = plugin(
            &dir,
            &format!(
                "cat >/dev/null\necho '{{\"version\":1,\"secrets\":[{{\"key\":\"A\",\"value\":\"{VALUE}\"}}]}}'\nexit 3"
            ),
        );

        let err = provider
            .resolve(&[secret_ref("A", "kv/a")])
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("code 3"), "names the exit code: {msg}");
        assert!(
            msg.contains("exit 0"),
            "says what a failure looks like: {msg}"
        );
        assert!(!msg.contains(VALUE), "leaked the value: {msg}");
    }

    #[tokio::test]
    async fn unparseable_stdout_names_the_plugin_not_the_bytes() {
        let dir = TempDir::new().unwrap();
        let provider = responder(&dir, &format!("not json at all {VALUE}"));

        let err = provider
            .resolve(&[secret_ref("A", "kv/a")])
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("dev-secret-vault"), "names the plugin: {msg}");
        assert!(!msg.contains(VALUE), "leaked stdout: {msg}");
        assert!(!msg.contains("column"), "leaked a serde position: {msg}");
    }

    #[tokio::test]
    async fn wrong_protocol_version_is_rejected() {
        let dir = TempDir::new().unwrap();
        let provider = responder(
            &dir,
            r#"{"version":2,"secrets":[{"key":"A","value":"alpha"}]}"#,
        );

        let err = provider
            .resolve(&[secret_ref("A", "kv/a")])
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("version 2"),
            "names the plugin's version: {msg}"
        );
        assert!(msg.contains("version 1"), "names dev's version: {msg}");
        assert!(!msg.contains("alpha"), "leaked the value: {msg}");
    }

    #[tokio::test]
    async fn top_level_error_fails_the_batch() {
        let dir = TempDir::new().unwrap();
        let provider = responder(
            &dir,
            r#"{"version":1,"error":"not signed in; run `vault login` first"}"#,
        );

        let err = provider
            .resolve(&[secret_ref("A", "kv/a")])
            .await
            .unwrap_err();
        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{err}"
        );
        assert!(format!("{err}").contains("not signed in"), "{err}");
    }

    #[test]
    fn waiting_notice_names_the_plugin() {
        assert!(waiting_notice("vault").contains("dev-secret-vault"));
    }

    #[tokio::test]
    async fn per_key_error_does_not_fail_the_batch() {
        let dir = TempDir::new().unwrap();
        let provider = responder(
            &dir,
            r#"{"version":1,"secrets":[
                {"key":"A","value":"alpha"},
                {"key":"B","error":"no such path: kv/b"}
            ]}"#,
        );
        let refs = vec![secret_ref("A", "kv/a"), secret_ref("B", "kv/b")];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(value_keys(&batch), vec!["A"]);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].reason, "no such path: kv/b");
    }

    #[tokio::test]
    async fn missing_entry_becomes_a_key_failure() {
        let dir = TempDir::new().unwrap();
        let provider = responder(
            &dir,
            r#"{"version":1,"secrets":[{"key":"A","value":"alpha"}]}"#,
        );
        let refs = vec![secret_ref("A", "kv/a"), secret_ref("B", "kv/b")];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(value_keys(&batch), vec!["A"]);
        assert_eq!(batch.failures()[0].key, "B");
        assert!(
            batch.failures()[0].reason.contains("no entry"),
            "{}",
            batch.failures()[0].reason
        );
    }

    #[tokio::test]
    async fn optional_is_not_read_here() {
        let dir = TempDir::new().unwrap();
        let response =
            r#"{"version":1,"secrets":[{"key":"A","value":"alpha"},{"key":"B","error":"nope"}]}"#;
        let provider = responder(&dir, response);
        let required = vec![secret_ref("A", "kv/a"), secret_ref("B", "kv/b")];
        let optional: Vec<SecretRef> = required
            .iter()
            .map(|secret| secret.clone().with_optional(true))
            .collect();

        let one = provider.resolve(&required).await.unwrap();
        let two = provider.resolve(&optional).await.unwrap();

        assert_eq!(value_keys(&one), value_keys(&two));
        assert_eq!(one.failures().len(), two.failures().len());
        assert_eq!(one.failures()[0].key, two.failures()[0].key);
    }

    #[tokio::test]
    async fn batch_failure_returns_err_not_key_failures() {
        let dir = TempDir::new().unwrap();
        let provider = plugin(&dir, "cat >/dev/null\nexit 3");
        let refs = vec![
            secret_ref("A", "kv/a").with_optional(true),
            secret_ref("B", "kv/b"),
        ];

        let err = provider.resolve(&refs).await.unwrap_err();
        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_empty_batch_never_spawns_the_plugin() {
        let batch = offline("/").resolve(&[]).await.unwrap();

        assert!(batch.values().is_empty());
        assert!(batch.failures().is_empty());
    }
}
