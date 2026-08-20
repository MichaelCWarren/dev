//! Resolve secret values from pluggable providers and inject them into the
//! container.
//!
//! `secrets.json` holds references — a provider name and a key — never values.
//! A value only exists once a provider answers, and from that moment it lives in
//! a [`SecretValue`], whose `Debug` and `Display` both print `***`. The single
//! route to the bytes is [`SecretValue::expose`], so every place a secret leaves
//! this type is greppable. Error messages here name the key or the path, never
//! the value.
//!
//! The redacting `Display` is a trap that fails loudly on purpose: a caller who
//! writes `format!("{v}")` instead of `v.expose()` ships the literal `***` into
//! a container env var, which shows up as an application failing to
//! authenticate. If you are staring at `***` in `docker inspect`, that is the
//! bug.

pub mod discovery;
pub mod file;
pub mod provider;
pub mod providers;
pub mod reference;
pub mod validate;

#[allow(unused_imports)]
pub use discovery::{
    find_secrets_file, find_secrets_file_in, load_secrets_in, secrets_path_beside,
};
#[allow(unused_imports)]
pub use file::SecretsFile;
#[allow(unused_imports)]
pub use provider::{
    KeyFailure, PluginBinary, PluginPath, ProviderLookup, ProviderRegistry, ResolvedBatch,
    SecretProvider,
};
#[allow(unused_imports)]
pub use reference::SecretRef;
#[allow(unused_imports)]
pub use validate::{ValidatedSecrets, validate_secrets_at, validate_secrets_for_config};

/// The redaction both `Debug` and `Display` print in place of the value.
const REDACTED: &str = "***";

/// Why `name` cannot be an environment variable, or `None` when it can.
///
/// One rule for both ways a name reaches this feature: a `secrets.json` key and
/// a `--secrets-file` key. It returns the reason rather than an error because
/// the two build different errors around it — one names a reference, the other
/// names a flag — and the check itself must not drift between them.
///
/// `char::is_whitespace`, not `is_ascii_whitespace`: a key holding U+00A0 is
/// just as unusable and twice as hard to see.
pub fn env_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("the environment variable name is empty");
    }
    if name.chars().any(char::is_whitespace) {
        return Some("the environment variable name contains whitespace");
    }
    if name.contains('=') {
        return Some("the environment variable name contains `=`");
    }
    None
}

/// A resolved secret value.
///
/// `Debug` and `Display` both print `***`, so a stray `{:?}` in a log line or an
/// error cannot leak the value. `expose` is the only way to reach the string,
/// which makes every place a secret escapes this type greppable.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        SecretValue(value.into())
    }

    /// The wrapped value. The only accessor, deliberately.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "hunter2";

    #[test]
    fn debug_prints_the_redaction_and_not_the_value() {
        let out = format!("{:?}", SecretValue::new(VALUE));
        assert!(out.contains("***"));
        assert!(!out.contains(VALUE));
    }

    #[test]
    fn display_prints_the_redaction_and_not_the_value() {
        let out = format!("{}", SecretValue::new(VALUE));
        assert!(out.contains("***"));
        assert!(!out.contains(VALUE));
    }

    #[test]
    fn debug_of_a_vec_of_secrets_is_redacted() {
        let secrets = vec![SecretValue::new(VALUE), SecretValue::new(VALUE)];
        let out = format!("{secrets:?}");
        assert!(out.contains("***"));
        assert!(!out.contains(VALUE));
    }

    #[test]
    fn debug_of_an_option_of_a_secret_is_redacted() {
        let out = format!("{:?}", Some(SecretValue::new(VALUE)));
        assert!(out.contains("***"));
        assert!(!out.contains(VALUE));

        let none: Option<SecretValue> = None;
        let out = format!("{none:?}");
        assert!(!out.contains(VALUE));
    }

    #[test]
    fn debug_of_a_derived_struct_holding_a_secret_is_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            key: String,
            value: SecretValue,
        }

        let holder = Holder {
            key: "GITHUB_TOKEN".to_string(),
            value: SecretValue::new(VALUE),
        };
        let out = format!("{holder:?}");
        assert!(out.contains("GITHUB_TOKEN"));
        assert!(out.contains("***"));
        assert!(!out.contains(VALUE));
    }

    #[test]
    fn expose_returns_the_original_value() {
        assert_eq!(SecretValue::new(VALUE).expose(), VALUE);
    }
}
