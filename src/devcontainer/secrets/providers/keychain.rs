//! The `keychain` provider: `"keychain://fsm-db"` resolves to the data of a
//! generic password item in the macOS keychain, read by shelling out to
//! `/usr/bin/security`.
//!
//! The binary rather than `security-framework`, because that crate is a C
//! binding and a transitive tree for one lookup, and the binary already exposes
//! everything this needs. The absolute path rather than a PATH lookup, because
//! nothing earlier on the user's PATH should be able to shadow the program that
//! reads their secrets.
//!
//! `-g` rather than `-w`. `-w` prints the item's data followed by a newline, but
//! only while every byte is printable ASCII; anything else comes back as a
//! lowercase hex string with no prefix, no warning and exit 0. Stored `café`
//! reads back as `636166c3a9`. The two cases cannot be told apart afterwards,
//! because a literal secret of `deadbeef` is both printable ASCII and valid hex.
//! `-g` marks the hex form with a `0x` prefix, so this provider can decode it.
//!
//! The rule that matters for review: `-g` writes the password line, and the
//! whole attribute dump, to **stderr**. So this module reads stderr, ignores
//! stdout, and no error or reason string it builds may ever quote stderr.
//!
//! The reference is the item's service name, and it is never passed through a
//! shell. It is also never empty: `SecretRef` rejects an empty body at every
//! entry point, which is load bearing here rather than merely tidy, because
//! `security find-generic-password` with no `-s` value matches the first item in
//! the keychain and exits 0. An empty service name would hand back an unrelated
//! secret rather than fail.
//!
//! `security` has no batch mode, so a batch of eight refs is eight invocations
//! and, on a machine that has not granted dev access to those items yet, eight
//! keychain dialogs. Nothing here can avoid that. Declining one stops the rest:
//! once the user has said no, prompting seven more times is user-hostile.

use crate::devcontainer::secrets::{ResolvedBatch, SecretProvider, SecretRef, SecretValue};
use crate::error::DevError;
use crate::runtime::BoxFut;

/// The only provider option `keychain` reads. It becomes `-a`.
const ACCOUNT_OPTION: &str = "account";

/// The line `security -g` writes the item's data on.
const PASSWORD_PREFIX: &str = "password: ";

/// Reads generic password items out of the macOS keychain.
// The allow comes off when the registry registers the built-ins.
#[allow(dead_code)]
pub struct KeychainProvider;

impl SecretProvider for KeychainProvider {
    fn name(&self) -> &str {
        "keychain"
    }

    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        Box::pin(async move {
            // Once for the batch, not per ref: what an unavailable provider means
            // for an `optional` key is the registry's rule, not this module's.
            keychain_unavailable()?;
            let runner = SecurityCommand;
            resolve_in(refs, &runner).await
        })
    }
}

/// Resolve a batch against an injected runner, so tests exercise every path
/// without spawning `security` or touching a real keychain.
///
/// `Err` is reserved for what took the whole batch down: a platform with no
/// keychain, or a `security` that would not start. Everything else is a per-key
/// entry, which is how `env` and `file` classify and what lets the registry
/// apply `optional` in one place.
async fn resolve_in(
    refs: &[SecretRef],
    runner: &dyn SecurityRunner,
) -> Result<ResolvedBatch, DevError> {
    let mut batch = ResolvedBatch::new();
    let mut declined: Option<String> = None;
    for secret in refs {
        if let Some(reason) = &declined {
            batch.push_failure(secret.key(), reason.clone());
            continue;
        }
        match resolve_one(secret, runner).await? {
            KeyOutcome::Value(value) => batch.push_value(secret.key(), value),
            KeyOutcome::Failed(reason) => batch.push_failure(secret.key(), reason),
            KeyOutcome::Declined(reason) => {
                batch.push_failure(secret.key(), reason.clone());
                declined = Some(reason);
            }
        }
    }
    Ok(batch)
}

/// What one ref resolved to. Exactly one of these is pushed per ref, so no key
/// is ever silently dropped.
enum KeyOutcome {
    Value(SecretValue),
    Failed(String),
    /// Failed, and the rest of the batch must not prompt again.
    Declined(String),
}

/// One lookup: validate the options, build the argv, run it, read the answer.
async fn resolve_one(
    secret: &SecretRef,
    runner: &dyn SecurityRunner,
) -> Result<KeyOutcome, DevError> {
    let account = match keychain_account(secret) {
        Ok(account) => account,
        Err(reason) => return Ok(KeyOutcome::Failed(reason)),
    };
    let service = secret.reference();
    let output = runner.run(&keychain_find_args(service, account)).await?;
    Ok(match classify_status(output.code) {
        KeychainStatus::Found => match password_from_stderr(&output.stderr, service) {
            Ok(value) => KeyOutcome::Value(value),
            Err(reason) => KeyOutcome::Failed(reason),
        },
        KeychainStatus::NotFound => KeyOutcome::Failed(not_found_reason(service)),
        KeychainStatus::Cancelled => KeyOutcome::Declined(declined_reason(service)),
        KeychainStatus::Other(code) => KeyOutcome::Failed(other_status_reason(service, code)),
    })
}

/// The argv for one lookup. Pure, no I/O, compiled on every target. `reference`
/// is the item's service name and is never empty; see the module header for what
/// an empty one would do.
fn keychain_find_args(reference: &str, account: Option<&str>) -> Vec<String> {
    let mut args = vec!["find-generic-password".to_string(), "-g".to_string()];
    if let Some(account) = account {
        args.push("-a".to_string());
        args.push(account.to_string());
    }
    args.push("-s".to_string());
    args.push(reference.to_string());
    args
}

/// Reject every option but `account`, then read `account` through `option_str`
/// so the parser's type check runs. Reading it off `options()` instead would let
/// `{"account": 7}` through as `None`, and a lookup with no `-a` returns the
/// first item matching the service name with exit 0 and no warning.
fn keychain_account(secret: &SecretRef) -> Result<Option<&str>, String> {
    if let Some(name) = secret
        .options()
        .keys()
        .find(|name| name.as_str() != ACCOUNT_OPTION)
    {
        return Err(unknown_option_reason(name));
    }
    secret.option_str(ACCOUNT_OPTION).map_err(reference_reason)
}

/// What an exit status means. All four codes measured against
/// `/usr/bin/security` on macOS 25.6.
#[derive(Debug, PartialEq, Eq)]
enum KeychainStatus {
    Found,
    NotFound,
    /// The prompt was declined, or could not be shown at all.
    Cancelled,
    /// `None` is a signal rather than an exit.
    Other(Option<i32>),
}

fn classify_status(code: Option<i32>) -> KeychainStatus {
    match code {
        Some(0) => KeychainStatus::Found,
        Some(44) => KeychainStatus::NotFound,
        Some(128) => KeychainStatus::Cancelled,
        other => KeychainStatus::Other(other),
    }
}

/// Pull the value out of `security -g`'s stderr, in either of the two forms it
/// writes:
///
/// ```text
/// password: "a-plain-value"
/// password: 0x6C696E65310A6C696E6532  "line1\012line2"
/// ```
///
/// `Err` is a per-key reason, never a `DevError`: typing it this way makes it
/// impossible to `?` a single unreadable item into a whole-batch failure.
fn password_from_stderr(stderr: &str, service: &str) -> Result<SecretValue, String> {
    let line = stderr
        .lines()
        .find_map(|line| line.strip_prefix(PASSWORD_PREFIX))
        .ok_or_else(|| unparseable_reason(service))?;
    match line.strip_prefix("0x") {
        Some(rest) => {
            let digits = rest.split(' ').next().unwrap_or_default();
            decode_hex_password(digits, service).map(SecretValue::new)
        }
        None => plain_password(line, service).map(SecretValue::new),
    }
}

/// The plain form is printable ASCII by construction, so nothing inside it is
/// escaped and only the last quote on the line can be the closing one: a stored
/// `a'b"c` prints as `password: "a'b"c"`.
fn plain_password<'a>(line: &'a str, service: &str) -> Result<&'a str, String> {
    let body = line
        .strip_prefix('"')
        .ok_or_else(|| unparseable_reason(service))?;
    let end = body.rfind('"').ok_or_else(|| unparseable_reason(service))?;
    Ok(&body[..end])
}

/// Decode the `0x...` form and gate it on UTF-8. Both errors are discarded
/// rather than rendered: `hex`'s carries the offending character and
/// `FromUtf8Error` carries the bytes, and either would be part of the secret.
fn decode_hex_password(digits: &str, service: &str) -> Result<String, String> {
    let bytes = hex::decode(digits).map_err(|_| undecodable_reason(service))?;
    String::from_utf8(bytes).map_err(|_| not_utf8_reason(service))
}

fn not_found_reason(service: &str) -> String {
    format!(
        "no generic password item for service `{service}`. Add one with \
         `security add-generic-password -s {service} -a <account> -w`."
    )
}

fn other_status_reason(service: &str, code: Option<i32>) -> String {
    let what = match code {
        Some(code) => format!("exit code {code}"),
        None => "terminated by a signal".to_string(),
    };
    format!("`security find-generic-password` failed for service `{service}` ({what}).")
}

fn not_utf8_reason(service: &str) -> String {
    format!(
        "the item for service `{service}` is not valid UTF-8 and cannot be an \
         environment variable."
    )
}

fn unparseable_reason(service: &str) -> String {
    format!(
        "`security find-generic-password` reported success for service `{service}` \
         but printed no password line."
    )
}

fn undecodable_reason(service: &str) -> String {
    format!(
        "`security find-generic-password` printed a hex-encoded item for service \
         `{service}` that could not be decoded."
    )
}

fn declined_reason(service: &str) -> String {
    format!(
        "the keychain prompt for service `{service}` was declined or could not be \
         shown. Later secrets in this batch were not looked up."
    )
}

fn unknown_option_reason(name: &str) -> String {
    format!("unknown provider option `{name}`. The `keychain` provider accepts `account`.")
}

/// The reason out of the parser's error, without its rendered prefix: the
/// registry names the key when it wraps a `KeyFailure`, so a reason that repeats
/// the key stutters.
fn reference_reason(err: DevError) -> String {
    match err {
        DevError::SecretReference { reason, .. } => reason,
        other => other.to_string(),
    }
}

fn provider_failed(reason: impl Into<String>) -> DevError {
    DevError::SecretProviderFailed {
        provider: "keychain".to_string(),
        reason: reason.into(),
    }
}

/// One `security` invocation. A trait rather than a function so the tests can
/// substitute a double: nothing in this file's suite spawns the real binary.
trait SecurityRunner: Sync {
    fn run<'a>(&'a self, args: &'a [String]) -> BoxFut<'a, SecurityOutput>;
}

/// What one invocation reported. `stderr` holds the password line, so it goes to
/// the parser and nowhere else.
struct SecurityOutput {
    code: Option<i32>,
    stderr: String,
}

struct SecurityCommand;

#[cfg(target_os = "macos")]
const SECURITY_BIN: &str = "/usr/bin/security";

#[cfg(target_os = "macos")]
impl SecurityRunner for SecurityCommand {
    fn run<'a>(&'a self, args: &'a [String]) -> BoxFut<'a, SecurityOutput> {
        Box::pin(async move {
            // `tokio::process`, not `std::process`: a keychain prompt can sit for
            // many seconds and a blocking call would park a worker for all of it.
            let output = tokio::process::Command::new(SECURITY_BIN)
                .args(args)
                .output()
                .await
                .map_err(|err| provider_failed(format!("cannot run `{SECURITY_BIN}`: {err}")))?;
            Ok(SecurityOutput {
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl SecurityRunner for SecurityCommand {
    /// Unreachable: `resolve` returns above it on any target without a keychain.
    /// It exists so the argv builder, the parser and the classifier stay under
    /// `cargo test` and `cargo clippy` on the Linux job.
    fn run<'a>(&'a self, _args: &'a [String]) -> BoxFut<'a, SecurityOutput> {
        Box::pin(async move { Err(keychain_unavailable_error()) })
    }
}

#[cfg(target_os = "macos")]
fn keychain_unavailable() -> Result<(), DevError> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn keychain_unavailable() -> Result<(), DevError> {
    Err(keychain_unavailable_error())
}

/// Compiled only where it is reachable, like
/// `configured_runtime_not_compiled_error` in `src/runtime/mod.rs`.
#[cfg(not(target_os = "macos"))]
fn keychain_unavailable_error() -> DevError {
    provider_failed(
        "the `keychain` provider requires macOS and this dev binary was built for \
         another platform. Use the `exec` provider or a `dev-secret-*` plugin for a \
         portable secret store.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const VALUE: &str = "hunter2";
    const SERVICE: &str = "fsm-db";

    /// Scripted `security` invocations. Records the argv it was handed and
    /// answers from a queue, so a batch test asserts one invocation per ref.
    struct FakeSecurity {
        answers: Mutex<VecDeque<Result<SecurityOutput, DevError>>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeSecurity {
        fn new(answers: Vec<Result<SecurityOutput, DevError>>) -> Self {
            FakeSecurity {
                answers: Mutex::new(answers.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn answering(answers: Vec<SecurityOutput>) -> Self {
            FakeSecurity::new(answers.into_iter().map(Ok).collect())
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl SecurityRunner for FakeSecurity {
        // Both locks are taken and released at call time, so no guard enters the
        // future and the future stays `Send`.
        fn run<'a>(&'a self, args: &'a [String]) -> BoxFut<'a, SecurityOutput> {
            self.calls.lock().unwrap().push(args.to_vec());
            let answer = self
                .answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("unscripted `security` invocation");
            Box::pin(async move { answer })
        }
    }

    fn found(stderr: &str) -> SecurityOutput {
        SecurityOutput {
            code: Some(0),
            stderr: stderr.to_string(),
        }
    }

    fn exited(code: i32) -> SecurityOutput {
        SecurityOutput {
            code: Some(code),
            stderr: String::new(),
        }
    }

    fn plain_line(value: &str) -> String {
        format!(
            "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"\npassword: \"{value}\"\n"
        )
    }

    fn secret_ref(key: &str, reference: &str) -> SecretRef {
        SecretRef::new(key, "keychain", reference).unwrap()
    }

    fn keys_of(batch: &ResolvedBatch) -> Vec<&str> {
        batch
            .values()
            .iter()
            .map(|(key, _)| key.as_str())
            .chain(batch.failures().iter().map(|f| f.key.as_str()))
            .collect()
    }

    /// Every ref handed in appears in exactly one of the two lists.
    fn assert_accounts_for(refs: &[SecretRef], batch: &ResolvedBatch) {
        assert_eq!(
            batch.values().len() + batch.failures().len(),
            refs.len(),
            "a key went unaccounted for"
        );
        let mut answered = keys_of(batch);
        answered.sort_unstable();
        let mut expected: Vec<&str> = refs.iter().map(SecretRef::key).collect();
        expected.sort_unstable();
        assert_eq!(answered, expected);
    }

    #[test]
    fn find_args_without_an_account() {
        assert_eq!(
            keychain_find_args(SERVICE, None),
            vec!["find-generic-password", "-g", "-s", "fsm-db"]
        );
    }

    #[test]
    fn find_args_with_an_account() {
        assert_eq!(
            keychain_find_args(SERVICE, Some("alice")),
            vec!["find-generic-password", "-g", "-a", "alice", "-s", "fsm-db"]
        );
    }

    #[test]
    fn a_shell_metacharacter_stays_one_verbatim_argument() {
        let reference = "db; rm -rf $HOME";
        let args = keychain_find_args(reference, None);
        assert_eq!(args.last().unwrap(), reference);
        assert_eq!(args.len(), 4);
    }

    #[test]
    fn exit_codes_classify() {
        assert_eq!(classify_status(Some(0)), KeychainStatus::Found);
        assert_eq!(classify_status(Some(44)), KeychainStatus::NotFound);
        assert_eq!(classify_status(Some(128)), KeychainStatus::Cancelled);
        assert_eq!(classify_status(Some(51)), KeychainStatus::Other(Some(51)));
        assert_eq!(classify_status(None), KeychainStatus::Other(None));
    }

    #[test]
    fn plain_form_round_trips() {
        let value = password_from_stderr(&plain_line(VALUE), SERVICE).unwrap();
        assert_eq!(value.expose(), VALUE);
    }

    #[test]
    fn hex_form_round_trips_a_newline() {
        let stderr = "password: 0x6C696E65310A6C696E6532  \"line1\\012line2\"\n";
        let value = password_from_stderr(stderr, SERVICE).unwrap();
        assert_eq!(value.expose(), "line1\nline2");
    }

    #[test]
    fn hex_form_round_trips_non_ascii() {
        let stderr = "password: 0x636166C3A9  \"caf\\303\\251\"\n";
        let value = password_from_stderr(stderr, SERVICE).unwrap();
        assert_eq!(value.expose(), "café");
    }

    #[test]
    fn hex_form_round_trips_a_tab() {
        let stderr = "password: 0x610962  \"a\\011b\"\n";
        let value = password_from_stderr(stderr, SERVICE).unwrap();
        assert_eq!(value.expose(), "a\tb");
    }

    #[test]
    fn plain_form_takes_the_last_quote_not_the_second() {
        let stderr = "password: \"a'b\"c\"\n";
        let value = password_from_stderr(stderr, SERVICE).unwrap();
        assert_eq!(value.expose(), "a'b\"c");
    }

    #[test]
    fn plain_form_keeps_an_empty_value() {
        let value = password_from_stderr("password: \"\"\n", SERVICE).unwrap();
        assert_eq!(value.expose(), "");
    }

    #[test]
    fn stderr_without_a_password_line_is_an_error_naming_the_service() {
        let reason =
            password_from_stderr("keychain: \"login.keychain-db\"\n", SERVICE).unwrap_err();
        assert!(reason.contains(SERVICE), "{reason}");
        assert!(reason.contains("no password line"), "{reason}");
    }

    #[test]
    fn a_hex_value_that_is_not_utf8_is_an_error_that_prints_no_bytes() {
        let reason = password_from_stderr("password: 0x80  \"\\200\"\n", SERVICE).unwrap_err();
        assert!(reason.contains("not valid UTF-8"), "{reason}");
        assert!(!reason.contains("80"), "rendered the bytes: {reason}");
    }

    #[test]
    fn a_hex_value_that_is_not_hex_is_an_error_that_prints_no_bytes() {
        let reason = password_from_stderr("password: 0xZZ\n", SERVICE).unwrap_err();
        assert!(reason.contains("could not be decoded"), "{reason}");
        assert!(!reason.contains("ZZ"), "rendered the bytes: {reason}");
    }

    #[test]
    fn account_option_is_read_as_a_string() {
        let secret = secret_ref("DB", SERVICE).with_option("account", "alice".into());
        assert_eq!(keychain_account(&secret).unwrap(), Some("alice"));
    }

    #[test]
    fn no_options_means_no_account() {
        assert_eq!(keychain_account(&secret_ref("DB", SERVICE)).unwrap(), None);
    }

    #[test]
    fn an_unknown_option_is_rejected_by_name() {
        let secret = secret_ref("DB", SERVICE).with_option("acount", "alice".into());
        let reason = keychain_account(&secret).unwrap_err();
        assert!(reason.contains("acount"), "{reason}");
        assert!(reason.contains("accepts `account`"), "{reason}");
    }

    #[test]
    fn a_non_string_account_propagates_the_parsers_error() {
        let secret = secret_ref("DB", SERVICE).with_option("account", 42.into());
        let reason = keychain_account(&secret).unwrap_err();
        assert!(reason.contains("must be a string"), "{reason}");
        assert!(!reason.contains("42"), "leaked the value: {reason}");
    }

    #[test]
    fn no_reason_leaks_a_value_or_quotes_stderr() {
        let reasons = vec![
            not_found_reason(SERVICE),
            other_status_reason(SERVICE, Some(51)),
            other_status_reason(SERVICE, None),
            not_utf8_reason(SERVICE),
            unparseable_reason(SERVICE),
            undecodable_reason(SERVICE),
            declined_reason(SERVICE),
            unknown_option_reason("acount"),
            reference_reason(provider_failed("`security` would not start")),
        ];
        for reason in reasons {
            assert!(!reason.contains(VALUE), "leaked a value: {reason}");
            assert!(!reason.contains(PASSWORD_PREFIX), "quotes stderr: {reason}");
        }
    }

    #[tokio::test]
    async fn a_found_item_resolves() {
        let runner = FakeSecurity::answering(vec![found(&plain_line(VALUE))]);
        let refs = vec![secret_ref("DB_PASSWORD", SERVICE)];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert_eq!(batch.values()[0].0, "DB_PASSWORD");
        assert_eq!(batch.values()[0].1.expose(), VALUE);
        assert!(batch.failures().is_empty());
        assert_eq!(
            runner.calls(),
            vec![keychain_find_args(SERVICE, None)],
            "one invocation, argv as built"
        );
    }

    #[tokio::test]
    async fn an_account_option_reaches_the_argv() {
        let runner = FakeSecurity::answering(vec![found(&plain_line(VALUE))]);
        let refs = vec![secret_ref("DB_PASSWORD", SERVICE).with_option("account", "alice".into())];
        resolve_in(&refs, &runner).await.unwrap();

        assert_eq!(
            runner.calls(),
            vec![keychain_find_args(SERVICE, Some("alice"))]
        );
    }

    #[tokio::test]
    async fn a_missing_item_is_a_key_failure_and_the_batch_continues() {
        let runner = FakeSecurity::answering(vec![exited(44)]);
        let refs = vec![secret_ref("DB_PASSWORD", SERVICE)];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert!(batch.values().is_empty());
        assert_eq!(batch.failures()[0].key, "DB_PASSWORD");
        assert!(batch.failures()[0].reason.contains(SERVICE));
        assert!(batch.failures()[0].reason.contains("add-generic-password"));
        assert_accounts_for(&refs, &batch);
    }

    #[tokio::test]
    async fn unreadable_answers_are_key_failures() {
        let answers = vec![
            found("password: 0x80  \"\\200\"\n"),
            found("keychain: \"login.keychain-db\"\n"),
            exited(51),
        ];
        let runner = FakeSecurity::answering(answers);
        let refs = vec![
            secret_ref("A", SERVICE),
            secret_ref("B", SERVICE),
            secret_ref("C", SERVICE),
        ];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert!(batch.values().is_empty());
        assert_eq!(keys_of(&batch), vec!["A", "B", "C"]);
        assert!(batch.failures()[2].reason.contains("exit code 51"));
        assert_accounts_for(&refs, &batch);
    }

    #[tokio::test]
    async fn a_bad_option_is_a_key_failure_and_never_runs_security() {
        let runner = FakeSecurity::answering(vec![found(&plain_line(VALUE))]);
        let refs = vec![
            secret_ref("BAD", SERVICE).with_option("service", "x".into()),
            secret_ref("GOOD", SERVICE),
        ];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert_eq!(batch.failures()[0].key, "BAD");
        assert!(batch.failures()[0].reason.contains("service"));
        assert_eq!(batch.values()[0].0, "GOOD");
        assert_eq!(runner.calls().len(), 1, "the bad ref was never looked up");
        assert_accounts_for(&refs, &batch);
    }

    #[tokio::test]
    async fn a_declined_prompt_fails_every_key_and_stops_prompting() {
        let runner = FakeSecurity::answering(vec![exited(128)]);
        let refs = vec![
            secret_ref("A", SERVICE),
            secret_ref("B", "other"),
            secret_ref("C", "third"),
        ];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert!(batch.values().is_empty());
        assert_eq!(keys_of(&batch), vec!["A", "B", "C"]);
        for failure in batch.failures() {
            assert!(failure.reason.contains("declined"), "{}", failure.reason);
        }
        assert_eq!(runner.calls().len(), 1, "prompted again after a decline");
        assert_accounts_for(&refs, &batch);
    }

    #[tokio::test]
    async fn a_failure_to_run_security_ends_the_batch() {
        let runner = FakeSecurity::new(vec![Err(provider_failed("cannot run it"))]);
        let refs = vec![secret_ref("A", SERVICE), secret_ref("B", SERVICE)];
        let err = resolve_in(&refs, &runner).await.unwrap_err();

        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_batch_of_three_runs_three_lookups_in_input_order() {
        let answers = vec![
            found(&plain_line("first")),
            exited(44),
            found(&plain_line("third")),
        ];
        let runner = FakeSecurity::answering(answers);
        let refs = vec![
            secret_ref("A", "one"),
            secret_ref("B", "two"),
            secret_ref("C", "three"),
        ];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert_eq!(runner.calls().len(), 3);
        let values: Vec<&str> = batch.values().iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(values, vec!["A", "C"]);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "B");
        assert_accounts_for(&refs, &batch);
    }

    #[tokio::test]
    async fn the_optional_flag_is_never_read() {
        let runner = FakeSecurity::answering(vec![exited(44)]);
        let refs = vec![secret_ref("A", SERVICE).with_optional(true)];
        let batch = resolve_in(&refs, &runner).await.unwrap();

        assert_eq!(batch.failures()[0].key, "A", "the registry owns `optional`");
    }

    #[test]
    fn provider_name_is_keychain_on_every_target() {
        assert_eq!(KeychainProvider.name(), "keychain");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_provider_is_available_on_macos() {
        assert!(keychain_unavailable().is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn resolve_fails_the_batch_before_spawning_on_another_platform() {
        let refs = vec![secret_ref("A", SERVICE)];
        let err = KeychainProvider.resolve(&refs).await.unwrap_err();

        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("macOS"), "{msg}");
        assert!(msg.contains("keychain"), "{msg}");
    }

    #[tokio::test]
    async fn an_empty_batch_resolves_to_nothing_and_runs_nothing() {
        let runner = FakeSecurity::answering(vec![]);
        let batch = resolve_in(&[], &runner).await.unwrap();

        assert!(batch.values().is_empty());
        assert!(batch.failures().is_empty());
        assert!(runner.calls().is_empty());
    }
}
