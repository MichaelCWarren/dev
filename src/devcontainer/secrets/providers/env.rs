//! The `env` provider: `"env://LINEAR_API_KEY"` resolves to the value of the
//! host environment variable `LINEAR_API_KEY` in dev's own process.
//!
//! A reference body is a bare variable name, nothing else. There is no path, no
//! interpolation and no trimming: a variable set to the empty string resolves to
//! an empty value rather than counting as unset.
//!
//! A failure reason names the variable and never the value. Not the string, not
//! the raw `OsString`, not a lossy rendering of bytes that are not UTF-8.
//!
//! `check_var_name` does not reject an empty name because `SecretRef` cannot
//! hold one. If that guarantee were ever dropped, `env` would report "is not
//! set" for an empty name, because `getenv("")` returns NULL, so `var_os("")` is
//! already `None`. That is a confusing message rather than a wrong value; the
//! providers whose backend reads an empty selector as a wildcard are the ones
//! that break first.

use crate::devcontainer::secrets::{ResolvedBatch, SecretProvider, SecretRef, SecretValue};
use crate::runtime::BoxFut;
use std::ffi::OsString;

/// Reads host environment variables. No state: the process environment is the
/// only thing it consults.
// The allow comes off when `providers/mod.rs` re-exports it and Group 5
// registers it into `ProviderRegistry::with_builtins`.
#[allow(dead_code)]
pub struct EnvProvider;

impl SecretProvider for EnvProvider {
    fn name(&self) -> &str {
        "env"
    }

    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        // `var_os`, not `var`: `var` folds "unset" and "set to bytes that are not
        // UTF-8" into two `VarError` arms that are easy to conflate, and the two
        // have to stay distinct failures here. It is wrapped in a closure because
        // it is generic over `AsRef<OsStr>`, which satisfies `Fn(&str)` for one
        // lifetime rather than the higher-ranked bound `resolve_with` asks for.
        Box::pin(async move { Ok(resolve_with(refs, |name: &str| std::env::var_os(name))) })
    }
}

/// Resolve a batch against an arbitrary name lookup. The [`SecretProvider`] impl
/// passes the process environment; tests pass a fixture map.
///
/// Returns a `ResolvedBatch` rather than a `Result`: `env` has no whole-batch
/// failure mode, so one unset variable must never take the other keys down with
/// it. Every ref gets exactly one value or one failure, in input order.
fn resolve_with<F>(refs: &[SecretRef], lookup: F) -> ResolvedBatch
where
    F: Fn(&str) -> Option<OsString>,
{
    let mut batch = ResolvedBatch::new();
    for secret in refs {
        match resolve_one(secret, &lookup) {
            Ok(value) => batch.push_value(secret.key(), value),
            Err(reason) => batch.push_failure(secret.key(), reason),
        }
    }
    batch
}

/// The outcome for a single ref: the value, or the text of its `KeyFailure`.
fn resolve_one<F>(secret: &SecretRef, lookup: &F) -> Result<SecretValue, String>
where
    F: Fn(&str) -> Option<OsString>,
{
    let name = secret.reference();
    check_var_name(name)?;
    check_no_options(secret)?;
    let raw =
        lookup(name).ok_or_else(|| format!("host environment variable `{name}` is not set"))?;
    raw.into_string()
        .map(SecretValue::new)
        .map_err(|_| format!("host environment variable `{name}` is not valid UTF-8"))
}

/// Reject a name containing whitespace or `=`, the rule `push_env_flag_token` in
/// `run_args.rs` applies to `--env` tokens. Emptiness is not checked; see the
/// module header.
fn check_var_name(name: &str) -> Result<(), String> {
    if name.chars().any(char::is_whitespace) {
        return Err(format!(
            "host environment variable name `{name}` may not contain whitespace"
        ));
    }
    if name.contains('=') {
        return Err(format!(
            "host environment variable name `{name}` may not contain `=`"
        ));
    }
    Ok(())
}

/// Reject any provider option. `env` takes none, so a typo is a message rather
/// than a setting that quietly does nothing. The first name in `BTreeMap` order
/// keeps the text identical run to run.
fn check_no_options(secret: &SecretRef) -> Result<(), String> {
    match secret.options().keys().next() {
        Some(name) => Err(format!(
            "the `env` provider takes no options, but `{name}` was given"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const VALUE: &str = "hunter2";

    fn fixture(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(*v)))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn empty_lookup() -> impl Fn(&str) -> Option<OsString> {
        fixture(&[])
    }

    fn secret_ref(key: &str, reference: &str) -> SecretRef {
        SecretRef::new(key, "env", reference).unwrap()
    }

    fn pairs(batch: &ResolvedBatch) -> Vec<(&str, &str)> {
        batch
            .values()
            .iter()
            .map(|(key, value)| (key.as_str(), value.expose()))
            .collect()
    }

    #[test]
    fn set_variable_resolves() {
        let refs = vec![secret_ref("LINEAR_API_KEY", "LINEAR_API_KEY")];
        let batch = resolve_with(&refs, fixture(&[("LINEAR_API_KEY", VALUE)]));

        assert_eq!(pairs(&batch), vec![("LINEAR_API_KEY", VALUE)]);
        assert!(batch.failures().is_empty());
    }

    #[test]
    fn batch_of_three_resolves_in_one_call() {
        let refs = vec![
            secret_ref("A", "A"),
            secret_ref("B", "B"),
            secret_ref("C", "C"),
        ];
        let batch = resolve_with(&refs, fixture(&[("A", "a"), ("B", "b"), ("C", "c")]));

        assert_eq!(pairs(&batch), vec![("A", "a"), ("B", "b"), ("C", "c")]);
    }

    #[test]
    fn key_and_reference_may_differ() {
        let refs = vec![secret_ref("DB_PASSWORD", "PGPASSWORD")];
        let batch = resolve_with(&refs, fixture(&[("PGPASSWORD", VALUE)]));

        assert_eq!(pairs(&batch), vec![("DB_PASSWORD", VALUE)]);
    }

    #[test]
    fn unset_variable_is_a_key_failure() {
        let refs = vec![secret_ref("DB_PASSWORD", "PGPASSWORD")];
        let batch = resolve_with(&refs, fixture(&[("OTHER", VALUE)]));

        assert!(batch.values().is_empty());
        assert_eq!(batch.failures().len(), 1);
        let failure = &batch.failures()[0];
        assert_eq!(failure.key, "DB_PASSWORD");
        assert!(failure.reason.contains("PGPASSWORD"), "{}", failure.reason);
        assert!(failure.reason.contains("is not set"), "{}", failure.reason);
        assert!(!failure.reason.contains(VALUE), "leaked a value");
    }

    #[test]
    fn unset_variable_does_not_fail_the_batch() {
        let refs = vec![secret_ref("GOOD", "GOOD"), secret_ref("BAD", "BAD")];
        let batch = resolve_with(&refs, fixture(&[("GOOD", "ok")]));

        assert_eq!(pairs(&batch), vec![("GOOD", "ok")]);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "BAD");
    }

    #[test]
    fn every_ref_is_accounted_for() {
        let refs = vec![
            secret_ref("GOOD", "GOOD"),
            secret_ref("UNSET", "UNSET"),
            secret_ref("BAD_NAME", "A B"),
            secret_ref("WITH_OPTION", "WITH_OPTION").with_option("account", "work".into()),
        ];
        let batch = resolve_with(&refs, fixture(&[("GOOD", "ok"), ("WITH_OPTION", "ok")]));

        assert_eq!(batch.values().len() + batch.failures().len(), refs.len());
        let mut answered: Vec<&str> = batch
            .values()
            .iter()
            .map(|(key, _)| key.as_str())
            .chain(batch.failures().iter().map(|f| f.key.as_str()))
            .collect();
        answered.sort_unstable();
        let mut expected: Vec<&str> = refs.iter().map(SecretRef::key).collect();
        expected.sort_unstable();
        assert_eq!(answered, expected);
    }

    #[test]
    fn empty_host_value_is_not_unset() {
        let refs = vec![secret_ref("EMPTY", "EMPTY")];
        let batch = resolve_with(&refs, fixture(&[("EMPTY", "")]));

        assert_eq!(pairs(&batch), vec![("EMPTY", "")]);
        assert!(batch.failures().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_value_is_a_key_failure() {
        use std::os::unix::ffi::OsStringExt;

        let refs = vec![secret_ref("RAW", "RAW")];
        let raw = OsString::from_vec(vec![0xff, 0xfe]);
        let batch = resolve_with(&refs, move |name| (name == "RAW").then(|| raw.clone()));

        assert!(batch.values().is_empty());
        let reason = &batch.failures()[0].reason;
        assert!(reason.contains("not valid UTF-8"), "{reason}");
        assert!(reason.contains("RAW"), "{reason}");
        assert!(!reason.contains('\u{fffd}'), "rendered the bytes: {reason}");
        assert!(!reason.contains("255"), "rendered the bytes: {reason}");
        assert!(!reason.contains("xff"), "rendered the bytes: {reason}");
    }

    #[test]
    fn a_malformed_name_is_a_key_failure() {
        for (reference, expected) in [
            ("A B", "may not contain whitespace"),
            ("A\tB", "may not contain whitespace"),
            ("A=B", "may not contain `=`"),
        ] {
            let refs = vec![secret_ref("KEY", reference)];
            let batch = resolve_with(&refs, fixture(&[(reference, VALUE)]));

            assert!(batch.values().is_empty(), "{reference} resolved");
            let failure = &batch.failures()[0];
            assert_eq!(failure.key, "KEY");
            assert!(failure.reason.contains(expected), "{}", failure.reason);
            assert!(!failure.reason.contains(VALUE), "leaked a value");
        }
    }

    #[test]
    fn provider_option_is_a_key_failure_naming_the_option() {
        let refs = vec![
            secret_ref("KEY", "KEY")
                .with_option("vault", "Private".into())
                .with_option("account", "work".into()),
        ];
        let batch = resolve_with(&refs, fixture(&[("KEY", VALUE)]));

        assert!(batch.values().is_empty());
        let reason = &batch.failures()[0].reason;
        assert!(reason.contains("takes no options"), "{reason}");
        assert!(reason.contains("`account`"), "first in order: {reason}");
        assert!(!reason.contains(VALUE), "leaked a value");
    }

    #[test]
    fn optional_ref_is_reported_not_dropped() {
        let refs = vec![secret_ref("KEY", "KEY").with_optional(true)];
        let batch = resolve_with(&refs, empty_lookup());

        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "KEY");
    }

    #[test]
    fn provider_name_is_env() {
        assert_eq!(EnvProvider.name(), "env");
    }

    #[tokio::test]
    async fn empty_batch_resolves_to_nothing() {
        let batch = EnvProvider.resolve(&[]).await.unwrap();

        assert!(batch.values().is_empty());
        assert!(batch.failures().is_empty());
    }
}
