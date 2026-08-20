//! The `op` provider: resolve 1Password references through the `op` CLI.
//!
//! Every reference in a batch goes into one `op inject` run, so eight secrets
//! cost one authorization instead of eight. That is the whole reason the
//! provider trait is batch-shaped.
//!
//! **The stdin template is sentinel-delimited on purpose.** `op inject`
//! substitutes raw text with no escaping whatsoever, so a value carrying a
//! quote, an `=`, or a newline would corrupt a `KEY=VALUE`, JSON, or YAML
//! framing. Instead each ref gets a three-line block wrapped in a nonce-bearing
//! begin and end marker, and the parser slices between the markers. Values are
//! mapped back to keys by the marker's index into the input slice, never by
//! matching output text, so two refs sharing one reference string still resolve
//! to their own keys. Do not simplify this back into a line format.
//!
//! **stdout is secret-bearing, stderr is diagnostic.** `op`'s stdout carries
//! resolved values and must never reach an error, a `push_failure` reason, a
//! log, or a `Debug`. `op`'s stderr may be quoted. That split is what keeps the
//! catch-all failure branch safe.
//!
//! **The `op read` retry is load-bearing.** A failed `op inject` writes no
//! stdout and names at most one reference, so a batch call cannot say which key
//! failed. Without re-resolving the group one ref at a time, one bad vault path
//! in a group of eight would take the other seven down with it and `optional`
//! would never fire. The retry runs on the failure path only, and the inject
//! already unlocked the session, so it adds no authorization prompt.

use crate::devcontainer::secrets::{ResolvedBatch, SecretProvider, SecretRef, SecretValue};
use crate::error::DevError;
use crate::runtime::BoxFut;
use std::hash::{BuildHasher, Hasher};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// The provider name, and the name every error is attributed to.
const PROVIDER: &str = "op";

/// The bound on one `op` invocation, not on a whole batch. Far above any
/// legitimate interaction (a biometric prompt is seconds, a typed password tens
/// of seconds) and still short enough to bound a hang from a prompt nobody can
/// see, because stderr is piped.
const OP_TIMEOUT: Duration = Duration::from_secs(120);

/// Stderr fragments that mean `op` could not authorize. Checked before the
/// not-found table: `op read` wraps its own failure text around the client
/// error, so both tables can match one line and the authorization problem is
/// the real one.
const NOT_AUTHORIZED: [&str; 7] = [
    "account is not signed in",
    "not currently signed in",
    "error initializing client",
    "multiple accounts found",
    "found no accounts for filter",
    "authorization prompt dismissed",
    "session expired",
];

/// Stderr fragments that mean the reference does not name anything. Reported
/// against the one key it belongs to, so `optional` can do its job.
const NOT_FOUND: [&str; 8] = [
    "invalid secret reference",
    "could not resolve item",
    "could not find item",
    "isn't an item",
    "isn't a vault",
    "no item matching",
    "item not found",
    "could not read secret",
];

/// Stderr fragments that mean the account filter itself is the problem, so the
/// message can point at the `account` option rather than only at `op signin`.
const ACCOUNT_PROBLEM: [&str; 2] = ["multiple accounts found", "found no accounts for filter"];

/// Resolves 1Password references through the `op` CLI.
// The allow comes off when the registry registers the built-ins.
#[allow(dead_code)]
pub struct OpProvider {
    runner: Box<dyn OpRunner>,
}

#[allow(dead_code)]
impl OpProvider {
    /// The provider production uses: a real `op` on `PATH`.
    pub fn new() -> Self {
        OpProvider {
            runner: Box::new(RealOp),
        }
    }

    #[cfg(test)]
    fn with_runner(runner: Box<dyn OpRunner>) -> Self {
        OpProvider { runner }
    }

    /// Validate every ref, group the survivors by account, run one `op inject`
    /// per group. Every input ref leaves with exactly one outcome.
    async fn resolve_batch(&self, refs: &[SecretRef]) -> Result<ResolvedBatch, DevError> {
        let mut batch = ResolvedBatch::new();
        let mut valid: Vec<(usize, Option<&str>)> = Vec::new();
        for (index, secret) in refs.iter().enumerate() {
            match validate(secret) {
                Ok(account) => valid.push((index, account)),
                Err(reason) => batch.push_failure(secret.key(), reason),
            }
        }

        let nonce = nonce();
        for (account, indices) in group_by_account(&valid) {
            self.resolve_group(refs, &indices, account.as_deref(), &nonce, &mut batch)
                .await?;
        }
        Ok(batch)
    }

    /// One `op inject` for one account group.
    async fn resolve_group(
        &self,
        refs: &[SecretRef],
        indices: &[usize],
        account: Option<&str>,
        nonce: &str,
        batch: &mut ResolvedBatch,
    ) -> Result<(), DevError> {
        let template = build_template(refs, indices, nonce);
        let outcome = self
            .run_bounded(&inject_argv(account), Some(&template))
            .await?;

        if outcome.succeeded() {
            for (index, value) in parse_injected(&outcome.stdout, indices, nonce)? {
                batch.push_value(refs[index].key(), SecretValue::new(value));
            }
            return Ok(());
        }

        match classify(&outcome.stderr) {
            OpFailure::NotAuthorized => Err(not_authorized_error(&outcome.stderr)),
            OpFailure::Other => Err(unclassified_error(outcome.code, &outcome.stderr)),
            // One ref needs no retry: stderr is already unambiguous.
            OpFailure::NotFound if indices.len() == 1 => {
                let secret = &refs[indices[0]];
                batch.push_failure(
                    secret.key(),
                    not_found_reason(secret.reference(), &outcome.stderr),
                );
                Ok(())
            }
            OpFailure::NotFound => self.retry_individually(refs, indices, account, batch).await,
        }
    }

    /// Re-resolve a failed group one ref at a time, so each not-found lands on
    /// the key it belongs to. See the module header for why this is not
    /// redundant with the batch call.
    async fn retry_individually(
        &self,
        refs: &[SecretRef],
        indices: &[usize],
        account: Option<&str>,
        batch: &mut ResolvedBatch,
    ) -> Result<(), DevError> {
        for &index in indices {
            let secret = &refs[index];
            let uri = op_uri(secret.reference());
            let outcome = self.run_bounded(&read_argv(&uri, account), None).await?;
            if outcome.succeeded() {
                batch.push_value(secret.key(), SecretValue::new(outcome.stdout));
                continue;
            }
            match classify(&outcome.stderr) {
                // Authorization was lost mid-flight; the remaining reads would
                // each report the same thing.
                OpFailure::NotAuthorized => return Err(not_authorized_error(&outcome.stderr)),
                OpFailure::Other => return Err(unclassified_error(outcome.code, &outcome.stderr)),
                OpFailure::NotFound => batch.push_failure(
                    secret.key(),
                    not_found_reason(secret.reference(), &outcome.stderr),
                ),
            }
        }
        Ok(())
    }

    /// The only route to the runner, so neither the inject nor the retry can
    /// forget the timeout.
    async fn run_bounded(
        &self,
        args: &[String],
        stdin: Option<&str>,
    ) -> Result<OpOutcome, DevError> {
        match tokio::time::timeout(OP_TIMEOUT, self.runner.run(args, stdin)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(timed_out_error()),
        }
    }
}

#[allow(dead_code)]
impl Default for OpProvider {
    fn default() -> Self {
        OpProvider::new()
    }
}

impl SecretProvider for OpProvider {
    fn name(&self) -> &str {
        PROVIDER
    }

    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        Box::pin(self.resolve_batch(refs))
    }
}

/// Captured result of one `op` invocation. `stdout` is secret-bearing, so this
/// type deliberately has no `Debug`.
struct OpOutcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl OpOutcome {
    /// Every `op` failure exits non-zero, so the code separates success from
    /// failure and stderr does the rest.
    fn succeeded(&self) -> bool {
        self.code == Some(0)
    }
}

/// The spawn seam. Every test substitutes a fake, so the suite never invokes a
/// real `op` and never touches a vault. `Send + Sync` because `BoxFut` requires
/// `Send` and the registry is shared.
trait OpRunner: Send + Sync {
    fn run<'a>(&'a self, args: &'a [String], stdin: Option<&'a str>) -> BoxFut<'a, OpOutcome>;
}

/// Spawns the real `op`.
struct RealOp;

impl OpRunner for RealOp {
    fn run<'a>(&'a self, args: &'a [String], stdin: Option<&'a str>) -> BoxFut<'a, OpOutcome> {
        Box::pin(spawn_op(args, stdin))
    }
}

/// The child inherits dev's environment, so `OP_SERVICE_ACCOUNT_TOKEN`,
/// `OP_SESSION_*`, `OP_ACCOUNT`, `HOME`, and `PATH` keep working. No secret
/// value is ever put into the child's environment.
async fn spawn_op(args: &[String], stdin: Option<&str>) -> Result<OpOutcome, DevError> {
    let mut child = tokio::process::Command::new(PROVIDER)
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => not_installed_error(),
            _ => spawn_error(&e),
        })?;

    let template = stdin.unwrap_or_default().to_string();
    let mut pipe = child
        .stdin
        .take()
        .ok_or_else(|| provider_error("could not open a pipe to `op`'s standard input"))?;

    // Writing to completion before awaiting the child deadlocks as soon as both
    // pipes fill. The handle must also be closed or `op` waits on EOF forever.
    let (written, output) = tokio::join!(
        async move {
            pipe.write_all(template.as_bytes()).await?;
            pipe.shutdown().await
        },
        child.wait_with_output(),
    );

    let output = output.map_err(|e| spawn_error(&e))?;
    // A broken pipe here only means `op` gave up before reading the template.
    // Its stderr says why, and reporting the pipe error would hide that.
    if let Err(e) = written
        && output.status.success()
    {
        return Err(spawn_error(&e));
    }

    Ok(OpOutcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// How a non-zero `op` exit is read. Not-installed is deliberately absent: it
/// is a spawn error, not a classification of stderr, and keeping it out stops
/// anyone from matching it here.
#[derive(Debug, PartialEq, Eq)]
enum OpFailure {
    NotAuthorized,
    NotFound,
    Other,
}

/// The reference as `op` wants it. Both spellings reach this provider: the URI
/// shorthand arrives with the scheme stripped, the object form's `ref` arrives
/// verbatim and may still carry it.
fn op_uri(reference: &str) -> String {
    match reference.get(..5) {
        Some(scheme) if scheme.eq_ignore_ascii_case("op://") => reference.to_string(),
        _ => format!("op://{reference}"),
    }
}

/// The per-ref checks that run before any spawn, returning the ref's `account`.
///
/// `Err` is free text rather than a `DevError` because it becomes a
/// `push_failure` reason. That is deliberate for the account checks too: a
/// mistyped `account` belongs to one key, and failing the whole batch over it
/// would take down seven working secrets.
fn validate(secret: &SecretRef) -> Result<Option<&str>, String> {
    let reference = secret.reference();
    if let Some(hazard) = template_hazard(reference) {
        return Err(format!(
            "reference `{reference}` may not contain {hazard}, which would corrupt the `op inject` template"
        ));
    }
    match secret.option_str("account") {
        Err(e) => Err(e.to_string()),
        Ok(None) => Ok(None),
        // Reachable without anyone writing `"account": ""`: a
        // `${localEnv:OP_ACCOUNT}` with the variable unset substitutes to empty,
        // and `op` reads an empty filter as "use the default account". That
        // would bring the container up with a secret nobody chose.
        Ok(Some(account)) if account.trim().is_empty() => Err(
            "the `account` option is empty; omit `account` entirely to use the default 1Password account"
                .to_string(),
        ),
        Ok(Some(account)) => Ok(Some(account)),
    }
}

/// What in a reference would break the template, or `None`.
fn template_hazard(reference: &str) -> Option<&'static str> {
    if reference.contains("{{") || reference.contains("}}") {
        return Some("`{{` or `}}`");
    }
    if reference.contains('\n') || reference.contains('\r') {
        return Some("a line break");
    }
    None
}

/// Partition validated refs by account, first-seen order preserved, with "no
/// account" as its own group. One `op inject` runs per group.
fn group_by_account(valid: &[(usize, Option<&str>)]) -> Vec<(Option<String>, Vec<usize>)> {
    let mut groups: Vec<(Option<String>, Vec<usize>)> = Vec::new();
    for (index, account) in valid {
        let account = account.map(str::to_string);
        match groups.iter_mut().find(|(name, _)| *name == account) {
            Some((_, indices)) => indices.push(*index),
            None => groups.push((account, vec![*index])),
        }
    }
    groups
}

/// 16 lowercase hex characters, fresh per `resolve` call. Hex only, so the
/// nonce can never contain template syntax. `RandomState` is OS-seeded per
/// process and costs no new dependency.
fn nonce() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default(),
    );
    format!("{:016x}", hasher.finish())
}

/// One three-line block per ref, in ascending index order. The index is the
/// ref's position in the original slice, so one parser serves every group.
fn build_template(refs: &[SecretRef], indices: &[usize], nonce: &str) -> String {
    let mut template = String::new();
    for &index in indices {
        let uri = op_uri(refs[index].reference());
        template.push_str(&format!(
            "{nonce}#{index}#B\n{{{{ {uri} }}}}\n{nonce}#{index}#E\n"
        ));
    }
    template
}

/// Slice each value out from between its markers, verbatim. Values containing
/// newlines, interior whitespace, `=`, quotes, or a trailing newline of their
/// own all survive intact.
fn parse_injected(
    stdout: &str,
    indices: &[usize],
    nonce: &str,
) -> Result<Vec<(usize, String)>, DevError> {
    let mut values = Vec::new();
    for &index in indices {
        let begin = format!("{nonce}#{index}#B\n");
        let end = format!("\n{nonce}#{index}#E");
        let opens = marker_offset(stdout, &begin, index)?;
        let closes = marker_offset(stdout, &end, index)?;
        let start = opens + begin.len();
        if closes < start {
            return Err(marker_error(index));
        }
        values.push((index, stdout[start..closes].to_string()));
    }
    Ok(values)
}

/// The offset of a marker that must appear exactly once.
fn marker_offset(stdout: &str, marker: &str, index: usize) -> Result<usize, DevError> {
    let mut found = stdout.match_indices(marker);
    let first = found.next().ok_or_else(|| marker_error(index))?.0;
    if found.next().is_some() {
        return Err(marker_error(index));
    }
    Ok(first)
}

fn inject_argv(account: Option<&str>) -> Vec<String> {
    let mut argv = vec!["--no-color".to_string(), "inject".to_string()];
    push_account(&mut argv, account);
    argv
}

fn read_argv(uri: &str, account: Option<&str>) -> Vec<String> {
    let mut argv = vec![
        "--no-color".to_string(),
        "read".to_string(),
        "--no-newline".to_string(),
        uri.to_string(),
    ];
    push_account(&mut argv, account);
    argv
}

fn push_account(argv: &mut Vec<String>, account: Option<&str>) {
    if let Some(account) = account {
        argv.push("--account".to_string());
        argv.push(account.to_string());
    }
}

/// Read a non-zero exit off stderr. Authorization is checked first; see
/// [`NOT_AUTHORIZED`].
fn classify(stderr: &str) -> OpFailure {
    let text = stderr.to_lowercase();
    if NOT_AUTHORIZED.iter().any(|hint| text.contains(hint)) {
        OpFailure::NotAuthorized
    } else if NOT_FOUND.iter().any(|hint| text.contains(hint)) {
        OpFailure::NotFound
    } else {
        OpFailure::Other
    }
}

fn provider_error(reason: impl Into<String>) -> DevError {
    DevError::SecretProviderFailed {
        provider: PROVIDER.to_string(),
        reason: reason.into(),
    }
}

fn not_installed_error() -> DevError {
    provider_error(
        "the 1Password CLI (`op`) is not installed or is not on PATH; install it with \
         `brew install 1password-cli`, see https://developer.1password.com/docs/cli/get-started/",
    )
}

fn spawn_error(e: &std::io::Error) -> DevError {
    provider_error(format!("could not run `op`: {e}"))
}

fn timed_out_error() -> DevError {
    provider_error(format!(
        "`op` did not respond within {}s; run `op signin` in a terminal first, because an \
         interactive prompt from `op` is not visible from here",
        OP_TIMEOUT.as_secs()
    ))
}

fn not_authorized_error(stderr: &str) -> DevError {
    let mut reason = format!(
        "`op` is not authorized; run `op signin`: {}",
        detail(stderr)
    );
    if ACCOUNT_PROBLEM
        .iter()
        .any(|hint| stderr.to_lowercase().contains(hint))
    {
        reason.push_str(
            "; with more than one account configured, set `\"account\"` in the secret's object form",
        );
    }
    provider_error(reason)
}

fn unclassified_error(code: Option<i32>, stderr: &str) -> DevError {
    let exit = match code {
        Some(code) => format!("exit code {code}"),
        None => "a signal".to_string(),
    };
    provider_error(format!("`op` failed with {exit}: {}", detail(stderr)))
}

/// The `push_failure` reason for one reference `op` could not resolve. Names
/// the reference and quotes stderr; never the key, which `reconcile` adds, and
/// never stdout.
fn not_found_reason(reference: &str, stderr: &str) -> String {
    let uri = op_uri(reference);
    match detail(stderr) {
        "" => format!("1Password has no item for `{uri}`"),
        text => format!("1Password could not resolve `{uri}`: {text}"),
    }
}

/// The first non-empty line of `op`'s stderr, which is the part worth quoting.
fn detail(stderr: &str) -> &str {
    stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
}

/// A marker anomaly is a bug in dev, not a user error, so it fails the batch
/// rather than one key. Names the index only: the output bytes are the secrets.
fn marker_error(index: usize) -> DevError {
    provider_error(format!(
        "could not read `op inject` output for entry {index}: its markers were missing or \
         duplicated. This is a bug in dev, not in your configuration"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// One recorded `op` invocation.
    #[derive(Clone)]
    struct FakeCall {
        argv: Vec<String>,
        stdin: Option<String>,
    }

    /// What `FakeOp` answers one invocation with.
    enum FakeReply {
        /// Substitute the template's placeholders the way `op inject` does. A
        /// `None` omits that whole block, which is how a marker goes missing.
        Inject {
            values: Vec<Option<String>>,
            code: i32,
            stderr: String,
        },
        /// Verbatim stdout, for `op read` and for hand-built output.
        Fixed {
            stdout: String,
            code: Option<i32>,
            stderr: String,
        },
        /// A runner-level failure, the way a missing binary arrives.
        Error(DevError),
        /// A future that never resolves, for the timeout tests.
        Stall,
    }

    impl FakeReply {
        fn injected(values: &[&str]) -> Self {
            FakeReply::partly_injected(values.iter().map(|v| Some(v.to_string())).collect())
        }

        fn partly_injected(values: Vec<Option<String>>) -> Self {
            FakeReply::Inject {
                values,
                code: 0,
                stderr: String::new(),
            }
        }

        /// Values on stdout paired with a non-zero exit, so a test can prove
        /// stdout never joins an error message.
        fn leaky(values: &[&str], stderr: &str) -> Self {
            FakeReply::Inject {
                values: values.iter().map(|v| Some(v.to_string())).collect(),
                code: 1,
                stderr: stderr.to_string(),
            }
        }

        fn read(value: &str) -> Self {
            FakeReply::Fixed {
                stdout: value.to_string(),
                code: Some(0),
                stderr: String::new(),
            }
        }

        fn failed(stderr: &str) -> Self {
            FakeReply::Fixed {
                stdout: String::new(),
                code: Some(1),
                stderr: stderr.to_string(),
            }
        }
    }

    /// Records every `(argv, stdin)` pair and answers from a queue. Shared
    /// state is behind `Arc`, so a test keeps a clone and asserts against it
    /// after the boxed original has been handed to `OpProvider`.
    #[derive(Clone)]
    struct FakeOp {
        calls: Arc<Mutex<Vec<FakeCall>>>,
        replies: Arc<Mutex<VecDeque<FakeReply>>>,
    }

    impl FakeOp {
        fn answering(replies: Vec<FakeReply>) -> Self {
            FakeOp {
                calls: Arc::new(Mutex::new(Vec::new())),
                replies: Arc::new(Mutex::new(replies.into())),
            }
        }

        fn calls(&self) -> Vec<FakeCall> {
            self.calls.lock().unwrap().clone()
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl OpRunner for FakeOp {
        // Recording happens at call time, not first poll, so no `MutexGuard`
        // enters the future and the future stays `Send`.
        fn run<'a>(&'a self, args: &'a [String], stdin: Option<&'a str>) -> BoxFut<'a, OpOutcome> {
            self.calls.lock().unwrap().push(FakeCall {
                argv: args.to_vec(),
                stdin: stdin.map(str::to_string),
            });
            let reply = self.replies.lock().unwrap().pop_front();
            let template = stdin.unwrap_or_default().to_string();
            match reply {
                Some(FakeReply::Stall) => Box::pin(std::future::pending()),
                Some(FakeReply::Error(e)) => Box::pin(async move { Err(e) }),
                Some(reply) => Box::pin(async move { Ok(fake_outcome(reply, &template)) }),
                None => Box::pin(async move { Err(provider_error("the fake ran out of replies")) }),
            }
        }
    }

    /// `FakeReply::Error` is the one arm that is not an `OpOutcome`, so it is
    /// unwrapped before this point.
    fn fake_outcome(reply: FakeReply, template: &str) -> OpOutcome {
        match reply {
            FakeReply::Inject {
                values,
                code,
                stderr,
            } => OpOutcome {
                code: Some(code),
                stdout: substitute(template, &values),
                stderr,
            },
            FakeReply::Fixed {
                stdout,
                code,
                stderr,
            } => OpOutcome {
                code,
                stdout,
                stderr,
            },
            FakeReply::Error(_) | FakeReply::Stall => unreachable!("handled by the caller"),
        }
    }

    /// What `op inject` does to the template: replace each placeholder line
    /// with its value, leaving the markers alone.
    fn substitute(template: &str, values: &[Option<String>]) -> String {
        let lines: Vec<&str> = template.lines().collect();
        let mut out = String::new();
        for (block, value) in lines.chunks(3).zip(values) {
            let Some(value) = value else { continue };
            out.push_str(block[0]);
            out.push('\n');
            out.push_str(value);
            out.push('\n');
            out.push_str(block[2]);
            out.push('\n');
        }
        out
    }

    fn secret_ref(key: &str, reference: &str) -> SecretRef {
        SecretRef::new(key, PROVIDER, reference).unwrap()
    }

    fn with_account(key: &str, reference: &str, account: serde_json::Value) -> SecretRef {
        secret_ref(key, reference).with_option("account", account)
    }

    /// Resolve `refs` against a fake, handing back both the outcome and the
    /// fake so the test can assert on what was spawned.
    async fn resolve_with(
        refs: &[SecretRef],
        replies: Vec<FakeReply>,
    ) -> (Result<ResolvedBatch, DevError>, FakeOp) {
        let fake = FakeOp::answering(replies);
        let provider = OpProvider::with_runner(Box::new(fake.clone()));
        let batch = provider.resolve(refs).await;
        (batch, fake)
    }

    fn pairs(batch: &ResolvedBatch) -> Vec<(&str, &str)> {
        batch
            .values()
            .iter()
            .map(|(key, value)| (key.as_str(), value.expose()))
            .collect()
    }

    fn failure_keys(batch: &ResolvedBatch) -> Vec<&str> {
        batch.failures().iter().map(|f| f.key.as_str()).collect()
    }

    fn only_failure(batch: &ResolvedBatch) -> &str {
        assert_eq!(batch.failures().len(), 1, "expected one failure");
        &batch.failures()[0].reason
    }

    fn reason_of(secret: SecretRef) -> String {
        validate(&secret).expect_err("expected validation to reject this ref")
    }

    #[test]
    fn provider_name_is_op() {
        assert_eq!(OpProvider::new().name(), "op");
    }

    #[test]
    fn op_uri_prepends_the_scheme_only_when_it_is_missing() {
        assert_eq!(op_uri("Private/Item/field"), "op://Private/Item/field");
        assert_eq!(op_uri("op://Private/Item/field"), "op://Private/Item/field");
        assert_eq!(op_uri("OP://Private/Item/field"), "OP://Private/Item/field");
        assert_eq!(op_uri("o"), "op://o");
    }

    #[test]
    fn inject_argv_appends_the_account_when_there_is_one() {
        assert_eq!(inject_argv(None), vec!["--no-color", "inject"]);
        assert_eq!(
            inject_argv(Some("acme.1password.com")),
            vec!["--no-color", "inject", "--account", "acme.1password.com"]
        );
    }

    #[test]
    fn read_argv_carries_no_newline_and_the_uri() {
        assert_eq!(
            read_argv("op://a/b/c", None),
            vec!["--no-color", "read", "--no-newline", "op://a/b/c"]
        );
        assert_eq!(read_argv("op://a/b/c", Some("work")).len(), 6);
    }

    #[test]
    fn nonce_is_sixteen_lowercase_hex_characters() {
        let nonce = nonce();
        assert_eq!(nonce.len(), 16, "{nonce}");
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "{nonce}"
        );
    }

    #[test]
    fn build_template_writes_three_lines_per_ref() {
        let refs = vec![
            secret_ref("A", "v/i/a"),
            secret_ref("B", "v/i/b"),
            secret_ref("C", "op://v/i/c"),
        ];
        let template = build_template(&refs, &[0, 1, 2], "abc");
        let lines: Vec<&str> = template.lines().collect();

        assert_eq!(lines.len(), 9);
        assert_eq!(lines[0], "abc#0#B");
        assert_eq!(lines[1], "{{ op://v/i/a }}");
        assert_eq!(lines[2], "abc#0#E");
        assert_eq!(lines[7], "{{ op://v/i/c }}", "already-prefixed ref");
        assert!(template.ends_with('\n'));
    }

    #[test]
    fn build_template_numbers_blocks_by_input_index() {
        let refs = vec![secret_ref("A", "a"), secret_ref("B", "b")];
        let template = build_template(&refs, &[1], "abc");
        assert!(template.starts_with("abc#1#B\n"), "{template}");
    }

    #[test]
    fn validate_rejects_a_reference_with_template_syntax() {
        let reason = reason_of(secret_ref("TOKEN", "v/i/f}}"));
        assert!(reason.contains("v/i/f}}"), "names the reference: {reason}");
        assert!(reason.contains("{{"), "says what is wrong: {reason}");
    }

    #[test]
    fn validate_rejects_a_reference_with_a_line_break() {
        for reference in ["v/i\n/f", "v/i\r/f"] {
            let reason = reason_of(secret_ref("TOKEN", reference));
            assert!(reason.contains("line break"), "{reason}");
        }
    }

    #[test]
    fn empty_account_option_is_rejected_not_omitted() {
        let reason = reason_of(with_account("TOKEN", "v/i/f", "".into()));
        assert!(reason.contains("account"), "names the option: {reason}");
        assert!(reason.contains("omit"), "says what to do: {reason}");
    }

    #[test]
    fn validate_rejects_a_whitespace_only_account() {
        let reason = reason_of(with_account("TOKEN", "v/i/f", "   ".into()));
        assert!(reason.contains("account"), "{reason}");
    }

    #[test]
    fn validate_rejects_a_non_string_account() {
        let reason = reason_of(with_account("TOKEN", "v/i/f", serde_json::json!(7)));
        assert!(reason.contains("account"), "names the option: {reason}");
        assert!(reason.contains("string"), "says why: {reason}");
    }

    #[test]
    fn validate_accepts_an_account_and_ignores_other_options() {
        let secret = with_account("TOKEN", "v/i/f", "work".into())
            .with_option("vault", "Private".into())
            .with_option("createTime", serde_json::json!(true));
        assert_eq!(validate(&secret).unwrap(), Some("work"));
    }

    #[test]
    fn group_by_account_keeps_first_seen_order() {
        let groups = group_by_account(&[(0, Some("a")), (1, Some("b")), (2, Some("a")), (3, None)]);
        assert_eq!(
            groups,
            vec![
                (Some("a".to_string()), vec![0, 2]),
                (Some("b".to_string()), vec![1]),
                (None, vec![3]),
            ]
        );
    }

    #[test]
    fn classify_reads_authorization_failures() {
        for stderr in [
            "[ERROR] 2026/08/19 account is not signed in",
            "[ERROR] error initializing client: multiple accounts found. Use the --account flag",
            "[ERROR] error initializing client: found no accounts for filter \"x\"",
            "[ERROR] session expired",
        ] {
            assert_eq!(classify(stderr), OpFailure::NotAuthorized, "{stderr}");
        }
    }

    #[test]
    fn classify_reads_missing_references() {
        for stderr in [
            "[ERROR] could not resolve item UUID for item Nope: could not find item Nope in vault ntozoxj",
            "[ERROR] invalid secret reference 'op://onlyvault': too few '/'",
            "[ERROR] \"Nope\" isn't an item in the \"Private\" vault",
        ] {
            assert_eq!(classify(stderr), OpFailure::NotFound, "{stderr}");
        }
    }

    #[test]
    fn classify_prefers_authorization_over_not_found() {
        let stderr = "[ERROR] could not read secret 'op://a/b/c': error initializing client: found no accounts for filter \"x\"";
        assert_eq!(classify(stderr), OpFailure::NotAuthorized);
    }

    #[test]
    fn classify_falls_through_to_other() {
        assert_eq!(
            classify("[ERROR] something new and unrecognised"),
            OpFailure::Other
        );
    }

    #[test]
    fn not_installed_message_points_at_the_install_and_not_at_signin() {
        let msg = not_installed_error().to_string();
        assert!(msg.contains("brew install 1password-cli"), "{msg}");
        assert!(msg.contains("developer.1password.com"), "{msg}");
        assert!(!msg.contains("op signin"), "{msg}");
    }

    #[test]
    fn timed_out_message_points_at_signin_and_not_at_the_install() {
        let msg = timed_out_error().to_string();
        assert!(msg.contains("op signin"), "{msg}");
        assert!(!msg.contains("brew install"), "{msg}");
        assert!(msg.contains("120"), "names the bound: {msg}");
    }

    #[tokio::test]
    async fn empty_batch_spawns_nothing() {
        let (batch, fake) = resolve_with(&[], vec![]).await;
        let batch = batch.unwrap();

        assert!(batch.values().is_empty());
        assert!(batch.failures().is_empty());
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn three_refs_resolve_in_one_invocation() {
        let refs = vec![
            secret_ref("A", "v/i/a"),
            secret_ref("B", "v/i/b"),
            secret_ref("C", "v/i/c"),
        ];
        let (batch, fake) = resolve_with(&refs, vec![FakeReply::injected(&["a", "b", "c"])]).await;
        let batch = batch.unwrap();

        assert_eq!(pairs(&batch), vec![("A", "a"), ("B", "b"), ("C", "c")]);
        assert_eq!(fake.call_count(), 1, "one prompt, not three");
        assert_eq!(fake.calls()[0].argv, vec!["--no-color", "inject"]);
    }

    #[tokio::test]
    async fn a_value_with_an_embedded_newline_round_trips() {
        let refs = vec![secret_ref("KEY", "v/i/f")];
        let (batch, _) = resolve_with(
            &refs,
            vec![FakeReply::injected(&[
                "-----BEGIN-----\nabc\n-----END-----",
            ])],
        )
        .await;

        assert_eq!(
            pairs(&batch.unwrap()),
            vec![("KEY", "-----BEGIN-----\nabc\n-----END-----")]
        );
    }

    #[tokio::test]
    async fn a_value_keeps_its_own_trailing_newline() {
        let refs = vec![secret_ref("KEY", "v/i/f")];
        let (batch, _) = resolve_with(&refs, vec![FakeReply::injected(&["hunter2\n"])]).await;

        assert_eq!(pairs(&batch.unwrap()), vec![("KEY", "hunter2\n")]);
    }

    #[tokio::test]
    async fn an_empty_value_resolves_as_empty() {
        let refs = vec![secret_ref("KEY", "v/i/f")];
        let (batch, _) = resolve_with(&refs, vec![FakeReply::injected(&[""])]).await;

        assert_eq!(pairs(&batch.unwrap()), vec![("KEY", "")]);
    }

    #[tokio::test]
    async fn a_value_holding_quotes_and_equals_survives() {
        let refs = vec![secret_ref("KEY", "v/i/f")];
        let (batch, _) = resolve_with(&refs, vec![FakeReply::injected(&["a=\"b\" c='d'"])]).await;

        assert_eq!(pairs(&batch.unwrap()), vec![("KEY", "a=\"b\" c='d'")]);
    }

    #[tokio::test]
    async fn two_keys_sharing_one_reference_each_resolve() {
        let refs = vec![secret_ref("A", "v/i/f"), secret_ref("B", "v/i/f")];
        let (batch, fake) = resolve_with(&refs, vec![FakeReply::injected(&["one", "two"])]).await;

        assert_eq!(pairs(&batch.unwrap()), vec![("A", "one"), ("B", "two")]);
        assert_eq!(fake.call_count(), 1);
    }

    #[tokio::test]
    async fn a_missing_marker_block_fails_the_batch_without_leaking() {
        let refs = vec![
            secret_ref("A", "v/i/a"),
            secret_ref("B", "v/i/b"),
            secret_ref("C", "v/i/c"),
        ];
        let reply =
            FakeReply::partly_injected(vec![Some("alpha".into()), None, Some("gamma".into())]);
        let (batch, _) = resolve_with(&refs, vec![reply]).await;

        let msg = batch.unwrap_err().to_string();
        assert!(msg.contains('1'), "names the entry: {msg}");
        assert!(!msg.contains("alpha"), "leaked a value: {msg}");
        assert!(!msg.contains("gamma"), "leaked a value: {msg}");
    }

    #[tokio::test]
    async fn accounts_partition_into_one_invocation_each() {
        let refs = vec![
            with_account("A", "v/i/a", "one".into()),
            with_account("B", "v/i/b", "two".into()),
            with_account("C", "v/i/c", "one".into()),
        ];
        let (batch, fake) = resolve_with(
            &refs,
            vec![
                FakeReply::injected(&["a", "c"]),
                FakeReply::injected(&["b"]),
            ],
        )
        .await;
        let batch = batch.unwrap();

        assert_eq!(fake.call_count(), 2);
        assert_eq!(
            fake.calls()[0].argv,
            vec!["--no-color", "inject", "--account", "one"]
        );
        assert_eq!(
            fake.calls()[1].argv,
            vec!["--no-color", "inject", "--account", "two"]
        );
        let mut keys: Vec<&str> = batch.values().iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["A", "B", "C"]);
    }

    #[tokio::test]
    async fn refs_without_an_account_share_one_invocation_with_no_account_flag() {
        let refs = vec![secret_ref("A", "v/i/a"), secret_ref("B", "v/i/b")];
        let (batch, fake) = resolve_with(&refs, vec![FakeReply::injected(&["a", "b"])]).await;

        assert_eq!(batch.unwrap().values().len(), 2);
        assert_eq!(fake.call_count(), 1);
        assert!(!fake.calls()[0].argv.iter().any(|arg| arg == "--account"));
    }

    #[tokio::test]
    async fn an_invalid_ref_fails_its_key_while_the_group_still_runs() {
        let refs = vec![secret_ref("GOOD", "v/i/a"), secret_ref("BAD", "v/i/b}}")];
        let (batch, fake) = resolve_with(&refs, vec![FakeReply::injected(&["a"])]).await;
        let batch = batch.unwrap();

        assert_eq!(pairs(&batch), vec![("GOOD", "a")]);
        assert_eq!(failure_keys(&batch), vec!["BAD"]);
        assert_eq!(fake.call_count(), 1);
        let template = fake.calls()[0].stdin.clone().unwrap();
        assert_eq!(template.lines().count(), 3, "one block only");
    }

    #[tokio::test]
    async fn an_empty_account_costs_only_its_own_key() {
        let refs = vec![
            secret_ref("GOOD", "v/i/a"),
            with_account("BAD", "v/i/b", "".into()),
        ];
        let (batch, fake) = resolve_with(&refs, vec![FakeReply::injected(&["a"])]).await;
        let batch = batch.unwrap();

        assert_eq!(pairs(&batch), vec![("GOOD", "a")]);
        assert_eq!(failure_keys(&batch), vec!["BAD"]);
        assert_eq!(fake.call_count(), 1);
        assert!(!fake.calls()[0].argv.iter().any(|arg| arg == "--account"));
    }

    #[tokio::test]
    async fn a_group_whose_only_ref_is_invalid_spawns_nothing() {
        let refs = vec![secret_ref("BAD", "v/i/{{f")];
        let (batch, fake) = resolve_with(&refs, vec![]).await;

        assert_eq!(failure_keys(&batch.unwrap()), vec!["BAD"]);
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn a_not_found_batch_retries_one_ref_at_a_time() {
        let refs = vec![
            secret_ref("A", "v/i/a"),
            secret_ref("B", "v/i/b"),
            secret_ref("C", "v/i/c"),
        ];
        let (batch, fake) = resolve_with(
            &refs,
            vec![
                FakeReply::failed("[ERROR] could not find item b in vault ntozoxj"),
                FakeReply::read("alpha"),
                FakeReply::failed("[ERROR] could not find item b in vault ntozoxj"),
                FakeReply::read("gamma"),
            ],
        )
        .await;
        let batch = batch.unwrap();

        assert_eq!(fake.call_count(), 4, "one inject plus three reads");
        assert_eq!(pairs(&batch), vec![("A", "alpha"), ("C", "gamma")]);
        assert_eq!(failure_keys(&batch), vec!["B"]);
        let reason = &batch.failures()[0].reason;
        assert!(
            reason.contains("op://v/i/b"),
            "names the reference: {reason}"
        );
        assert!(!reason.contains("alpha"), "leaked a value: {reason}");
        assert_eq!(
            fake.calls()[1].argv,
            vec!["--no-color", "read", "--no-newline", "op://v/i/a"]
        );
    }

    #[tokio::test]
    async fn a_single_ref_not_found_skips_the_retry() {
        let refs = vec![secret_ref("A", "v/i/a")];
        let (batch, fake) = resolve_with(
            &refs,
            vec![FakeReply::failed(
                "[ERROR] invalid secret reference 'op://onlyvault': too few '/'",
            )],
        )
        .await;
        let batch = batch.unwrap();

        assert_eq!(fake.call_count(), 1, "stderr is already unambiguous");
        assert_eq!(failure_keys(&batch), vec!["A"]);
    }

    #[tokio::test]
    async fn a_retry_that_loses_authorization_stops_and_fails_the_batch() {
        let refs = vec![
            secret_ref("A", "v/i/a"),
            secret_ref("B", "v/i/b"),
            secret_ref("C", "v/i/c"),
        ];
        let (batch, fake) = resolve_with(
            &refs,
            vec![
                FakeReply::failed("[ERROR] could not find item b"),
                FakeReply::read("alpha"),
                FakeReply::failed("[ERROR] account is not signed in"),
                FakeReply::read("gamma"),
            ],
        )
        .await;

        let msg = batch.unwrap_err().to_string();
        assert!(msg.contains("op signin"), "{msg}");
        assert!(!msg.contains("alpha"), "leaked a value: {msg}");
        assert_eq!(fake.call_count(), 3, "stopped after the second read");
    }

    #[tokio::test]
    async fn not_signed_in_fails_the_whole_batch() {
        let refs = vec![secret_ref("A", "v/i/a"), secret_ref("B", "v/i/b")];
        let (batch, _) = resolve_with(
            &refs,
            vec![FakeReply::failed("[ERROR] account is not signed in")],
        )
        .await;

        let err = batch.unwrap_err();
        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("op signin"), "{msg}");
        assert!(!msg.contains("account\" in the secret"), "{msg}");
    }

    #[tokio::test]
    async fn an_account_problem_points_at_the_account_option() {
        for stderr in [
            "[ERROR] error initializing client: multiple accounts found. Use the --account flag",
            "[ERROR] error initializing client: found no accounts for filter \"nope\"",
        ] {
            let refs = vec![secret_ref("A", "v/i/a"), secret_ref("B", "v/i/b")];
            let (batch, _) = resolve_with(&refs, vec![FakeReply::failed(stderr)]).await;

            let msg = batch.unwrap_err().to_string();
            assert!(msg.contains("account"), "names the option: {msg}");
            assert!(msg.contains("op signin"), "{msg}");
        }
    }

    #[tokio::test]
    async fn an_unrecognised_stderr_carries_the_exit_code() {
        let refs = vec![secret_ref("A", "v/i/a")];
        let (batch, _) =
            resolve_with(&refs, vec![FakeReply::failed("[ERROR] brand new wording")]).await;

        let msg = batch.unwrap_err().to_string();
        assert!(msg.contains("code 1"), "names the exit code: {msg}");
        assert!(msg.contains("brand new wording"), "quotes stderr: {msg}");
    }

    #[tokio::test]
    async fn a_spawn_failure_reports_that_op_is_not_installed() {
        let refs = vec![secret_ref("A", "v/i/a")];
        let fake = FakeOp::answering(vec![FakeReply::Error(not_installed_error())]);
        let provider = OpProvider::with_runner(Box::new(fake));
        let msg = provider.resolve(&refs).await.unwrap_err().to_string();

        assert!(msg.contains("brew install 1password-cli"), "{msg}");
        assert!(!msg.contains("op signin"), "{msg}");
    }

    #[tokio::test]
    async fn stdout_never_reaches_an_error_message() {
        let refs = vec![secret_ref("A", "v/i/a")];
        let (batch, _) = resolve_with(
            &refs,
            vec![FakeReply::leaky(&["hunter2"], "[ERROR] brand new wording")],
        )
        .await;

        let msg = batch.unwrap_err().to_string();
        assert!(!msg.contains("hunter2"), "leaked the value: {msg}");
        assert!(msg.contains("brand new wording"), "kept stderr: {msg}");
    }

    #[tokio::test]
    async fn a_resolved_batch_debug_is_redacted() {
        let refs = vec![secret_ref("A", "v/i/a")];
        let (batch, _) = resolve_with(&refs, vec![FakeReply::injected(&["hunter2"])]).await;

        let out = format!("{:?}", batch.unwrap());
        assert!(out.contains("***"), "redacts: {out}");
        assert!(!out.contains("hunter2"), "leaked the value: {out}");
    }

    #[tokio::test]
    async fn every_ref_is_accounted_for() {
        let refs = vec![
            secret_ref("GOOD", "v/i/a"),
            secret_ref("BAD_REF", "v/i/b}}"),
            with_account("BAD_ACCOUNT", "v/i/c", serde_json::json!(7)),
            secret_ref("MISSING", "v/i/d"),
        ];
        let (batch, _) = resolve_with(
            &refs,
            vec![
                FakeReply::failed("[ERROR] could not find item d"),
                FakeReply::read("alpha"),
                FakeReply::failed("[ERROR] could not find item d"),
            ],
        )
        .await;
        let batch = batch.unwrap();

        assert_eq!(batch.values().len() + batch.failures().len(), refs.len());
        let mut answered: Vec<&str> = batch
            .values()
            .iter()
            .map(|(key, _)| key.as_str())
            .chain(failure_keys(&batch))
            .collect();
        answered.sort_unstable();
        assert_eq!(answered, vec!["BAD_ACCOUNT", "BAD_REF", "GOOD", "MISSING"]);
    }

    #[tokio::test]
    async fn an_optional_ref_is_reported_not_dropped() {
        let refs = vec![secret_ref("A", "v/i/a").with_optional(true)];
        let (batch, _) = resolve_with(
            &refs,
            vec![FakeReply::failed("[ERROR] could not find item a")],
        )
        .await;

        assert_eq!(
            failure_keys(&batch.unwrap()),
            vec!["A"],
            "the registry owns `optional`"
        );
    }

    #[tokio::test]
    async fn a_failure_reason_does_not_repeat_the_key() {
        let refs = vec![secret_ref("DB_PASSWORD", "v/i/a")];
        let (batch, _) = resolve_with(
            &refs,
            vec![FakeReply::failed("[ERROR] could not find item a")],
        )
        .await;

        let reason = only_failure(&batch.unwrap()).to_string();
        assert!(!reason.contains("DB_PASSWORD"), "repeats the key: {reason}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_op_times_out() {
        let refs = vec![secret_ref("A", "v/i/a")];
        let (batch, _) = resolve_with(&refs, vec![FakeReply::Stall]).await;

        let msg = batch.unwrap_err().to_string();
        assert!(msg.contains("did not respond"), "{msg}");
        assert!(msg.contains("op signin"), "{msg}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_timeout_covers_the_retry_path_too() {
        let refs = vec![
            secret_ref("A", "v/i/a"),
            secret_ref("B", "v/i/b"),
            secret_ref("C", "v/i/c"),
        ];
        let (batch, fake) = resolve_with(
            &refs,
            vec![
                FakeReply::failed("[ERROR] could not find item b"),
                FakeReply::read("alpha"),
                FakeReply::Stall,
            ],
        )
        .await;

        assert!(batch.unwrap_err().to_string().contains("did not respond"));
        assert_eq!(fake.call_count(), 3);
    }
}
