//! Parse one entry of the `secrets` map in `secrets.json` into a validated
//! [`SecretRef`].
//!
//! Both spellings are accepted: the string shorthand
//! `"op://Private/Linear CLI/credential"`, whose scheme names the provider, and
//! the object form `{ "provider": "op", "ref": "...", "account": "..." }`, whose
//! unrecognised keys become provider options.
//!
//! Nothing here does I/O and nothing here resolves a value. The point of the
//! seam is that a typo in a vault path becomes an error naming the environment
//! variable before `dev up` has any side effect, rather than a container that
//! misbehaves after a five-minute build.
//!
//! A reference is a locator, never a value. Even so, a malformed reference is
//! exactly the case where a user may have pasted a literal secret where a
//! reference belongs, so every error goes through `reference_error` and names
//! the environment variable rather than the reference body.

use crate::error::DevError;
use std::collections::BTreeMap;

/// Keys the object form spells itself. Everything else is a provider option.
const RESERVED_KEYS: [&str; 4] = ["provider", "ref", "optional", "createTime"];

/// One entry of the `secrets` map in `secrets.json`, parsed and validated.
///
/// Every field is private and `substitute` is the only `&mut self` method, so
/// nothing outside this file can change which provider a reference resolves to.
// `#[allow(dead_code)]` goes when `up.rs` validation (Group 5) reaches this type
// from the bin target.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct SecretRef {
    key: String,
    provider: String,
    reference: String,
    options: BTreeMap<String, serde_json::Value>,
    optional: bool,
    create_time: bool,
}

#[allow(dead_code)]
impl SecretRef {
    /// Parse one `secrets` map entry, in either spelling.
    pub fn from_json(key: &str, value: &serde_json::Value) -> Result<SecretRef, DevError> {
        match value {
            serde_json::Value::String(text) => parse_shorthand(key, text),
            serde_json::Value::Object(map) => parse_object(key, map),
            other => Err(reference_error(
                key,
                format!(
                    "entry must be a string or an object, found {}",
                    value_type_name(other)
                ),
            )),
        }
    }

    /// Build a reference from its parts, applying the same rules `from_json` does.
    pub fn new(
        key: impl Into<String>,
        provider: impl Into<String>,
        reference: impl Into<String>,
    ) -> Result<SecretRef, DevError> {
        build(
            key.into(),
            provider.into(),
            reference.into(),
            BTreeMap::new(),
            false,
            true,
        )
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn options(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.options
    }

    pub fn optional(&self) -> bool {
        self.optional
    }

    pub fn create_time(&self) -> bool {
        self.create_time
    }

    /// One provider option, whatever its JSON type. For the plugin provider,
    /// which forwards options it does not interpret.
    pub fn option(&self, name: &str) -> Option<&serde_json::Value> {
        self.options.get(name)
    }

    /// One provider option that must be a string if it is there at all.
    ///
    /// A present-but-wrong-typed option is an error rather than a `None`, so
    /// `{"account": 7}` fails instead of quietly resolving against the default
    /// account, which would be a wrong secret rather than a failure.
    pub fn option_str(&self, name: &str) -> Result<Option<&str>, DevError> {
        match self.options.get(name) {
            None => Ok(None),
            Some(serde_json::Value::String(text)) => Ok(Some(text)),
            Some(other) => Err(reference_error(
                &self.key,
                format!(
                    "option `{name}` must be a string, found {}",
                    value_type_name(other)
                ),
            )),
        }
    }

    /// Apply `f` to the reference body and to every top-level string option.
    ///
    /// This is the only way to rewrite a parsed reference. It cannot reach
    /// `key`, `provider`, or the option keys, so no substitution can change
    /// which provider a reference resolves to.
    ///
    /// Strings nested inside an option array or object are NOT substituted,
    /// because a `dev-secret-*` plugin receives the whole options map as its
    /// wire payload and dev must not rewrite the inside of a payload it does not
    /// understand. If a built-in provider ever needs a nested option, flatten
    /// that option rather than deepening this walk.
    pub fn substitute(&mut self, f: impl Fn(&str) -> String) -> Result<(), DevError> {
        let body = f(&self.reference);
        if body.is_empty() {
            return Err(reference_error(
                &self.key,
                "reference body is empty after variable substitution",
            ));
        }
        self.reference = body;
        for value in self.options.values_mut() {
            if let serde_json::Value::String(text) = value {
                *text = f(text);
            }
        }
        Ok(())
    }
}

/// Test fixtures only. Private fields mean a test can no longer write a struct
/// literal to express "this ref, but with `optional` set", and building the
/// expected value with `from_json` would compare parse output against parse
/// output.
#[cfg(test)]
impl SecretRef {
    pub fn with_option(mut self, name: &str, value: serde_json::Value) -> Self {
        self.options.insert(name.to_string(), value);
        self
    }

    pub fn with_optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    pub fn with_create_time(mut self, create_time: bool) -> Self {
        self.create_time = create_time;
        self
    }
}

/// The one place a `SecretRef` comes into existence, so the invariants exist once.
fn build(
    key: String,
    provider: String,
    reference: String,
    options: BTreeMap<String, serde_json::Value>,
    optional: bool,
    create_time: bool,
) -> Result<SecretRef, DevError> {
    if key.is_empty() {
        return Err(reference_error(
            &key,
            "the environment variable name is empty",
        ));
    }
    validate_provider_name(&key, &provider)?;
    if reference.is_empty() {
        return Err(reference_error(&key, "reference body is empty"));
    }
    Ok(SecretRef {
        key,
        provider,
        reference,
        options,
        optional,
        create_time,
    })
}

/// `"op://Private/Linear CLI/credential"`, split on its first `://`.
fn parse_shorthand(key: &str, text: &str) -> Result<SecretRef, DevError> {
    let Some((scheme, body)) = text.split_once("://") else {
        return Err(reference_error(key, "reference has no `://` scheme"));
    };
    if scheme.is_empty() {
        return Err(reference_error(key, "scheme is empty"));
    }
    validate_provider_name(key, scheme)?;
    if body.is_empty() {
        return Err(reference_error(key, "reference body is empty"));
    }
    build(
        key.to_string(),
        scheme.to_string(),
        body.to_string(),
        BTreeMap::new(),
        false,
        true,
    )
}

/// `{ "provider": "op", "ref": "...", "account": "..." }`. `ref` is taken
/// literally and never re-parsed as a shorthand, even when it looks like one.
fn parse_object(
    key: &str,
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<SecretRef, DevError> {
    let provider = required_string(key, map, "provider")?;
    let reference = required_string(key, map, "ref")?;
    let optional = optional_bool(key, map, "optional", false)?;
    let create_time = optional_bool(key, map, "createTime", true)?;
    build(
        key.to_string(),
        provider,
        reference,
        collect_options(map),
        optional,
        create_time,
    )
}

fn validate_provider_name(key: &str, provider: &str) -> Result<(), DevError> {
    // The provider name becomes a filename: the registry's plugin fallback joins
    // `dev-secret-<provider>` onto each PATH entry. `../../../tmp/evil` would
    // walk out of the search directory, so reject it here rather than at lookup.
    if provider.is_empty() {
        return Err(reference_error(key, "provider name is empty"));
    }
    let allowed = provider
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !allowed {
        return Err(reference_error(
            key,
            format!("provider name `{provider}` may contain only letters, digits, `_` and `-`"),
        ));
    }
    Ok(())
}

fn required_string(
    key: &str,
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<String, DevError> {
    match map.get(field) {
        None => Err(reference_error(key, format!("field `{field}` is missing"))),
        Some(serde_json::Value::String(text)) if text.is_empty() => {
            Err(reference_error(key, format!("field `{field}` is empty")))
        }
        Some(serde_json::Value::String(text)) => Ok(text.clone()),
        Some(other) => Err(reference_error(
            key,
            format!(
                "field `{field}` must be a string, found {}",
                value_type_name(other)
            ),
        )),
    }
}

fn optional_bool(
    key: &str,
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    default: bool,
) -> Result<bool, DevError> {
    match map.get(field) {
        None => Ok(default),
        Some(serde_json::Value::Bool(flag)) => Ok(*flag),
        Some(other) => Err(reference_error(
            key,
            format!(
                "field `{field}` must be a boolean, found {}",
                value_type_name(other)
            ),
        )),
    }
}

fn collect_options(
    map: &serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    map.iter()
        .filter(|(name, _)| !RESERVED_KEYS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The JSON type of a value with its article, for "found a number" messages.
fn value_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Object(_) => "an object",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Null => "null",
    }
}

/// The single error constructor in this file, so requirement "no message
/// contains the reference body" holds by reading one function.
fn reference_error(key: &str, reason: impl std::fmt::Display) -> DevError {
    DevError::SecretReference {
        key: key.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    fn parse(key: &str, json: &str) -> SecretRef {
        SecretRef::from_json(key, &v(json)).unwrap()
    }

    fn err_msg(key: &str, json: &str) -> String {
        format!("{}", SecretRef::from_json(key, &v(json)).unwrap_err())
    }

    #[test]
    fn shorthand_scheme_names_the_provider() {
        for (json, provider, reference) in [
            (
                r#""op://Private/Linear CLI/credential""#,
                "op",
                "Private/Linear CLI/credential",
            ),
            (r#""env://LINEAR_API_KEY""#, "env", "LINEAR_API_KEY"),
            (r#""keychain://fsm-db""#, "keychain", "fsm-db"),
            (r#""file://./secrets/token""#, "file", "./secrets/token"),
            (r#""file:///etc/token""#, "file", "/etc/token"),
            (
                r#""exec://vault kv get -field=token secret/ci""#,
                "exec",
                "vault kv get -field=token secret/ci",
            ),
        ] {
            let r = parse("T", json);
            assert_eq!(r.provider(), provider, "provider of {json}");
            assert_eq!(r.reference(), reference, "reference of {json}");
            assert!(r.options().is_empty(), "options of {json}");
            assert_eq!(r, SecretRef::new("T", provider, reference).unwrap());
        }
    }

    #[test]
    fn shorthand_carries_the_env_var_key() {
        let r = parse("LINEAR_API_KEY", r#""op://Private/Linear CLI/credential""#);
        assert_eq!(r.key(), "LINEAR_API_KEY");
        assert!(!r.optional());
        assert!(r.create_time());
    }

    #[test]
    fn shorthand_reference_keeps_an_inner_scheme_separator() {
        let r = parse(
            "T",
            r#""exec://vault read -address=https://vault.example.com secret/ci""#,
        );
        assert_eq!(r.provider(), "exec");
        assert_eq!(
            r.reference(),
            "vault read -address=https://vault.example.com secret/ci"
        );
    }

    #[test]
    fn shorthand_reference_keeps_leading_slash_and_trailing_space() {
        assert_eq!(
            parse("T", r#""file:///etc/token""#).reference(),
            "/etc/token"
        );
        assert_eq!(parse("T", r#""op://a/b/c ""#).reference(), "a/b/c ");
    }

    #[test]
    fn unknown_shorthand_scheme_parses_and_defers_to_the_registry() {
        let r = parse("T", r#""acme-vault://team/app/token""#);
        assert_eq!(r.provider(), "acme-vault");
        assert_eq!(r.reference(), "team/app/token");
    }

    #[test]
    fn provider_name_charset_is_enforced_in_both_spellings() {
        for name in ["my provider", "../../../tmp/evil", "op.beta", "op/beta"] {
            let shorthand = serde_json::Value::String(format!("{name}://a/b/c"));
            let err = SecretRef::from_json("T", &shorthand).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("provider"), "shorthand names provider: {msg}");
            assert!(msg.contains(name), "shorthand names `{name}`: {msg}");
            assert!(!msg.contains("a/b/c"), "shorthand hides the body: {msg}");

            let object = serde_json::json!({ "provider": name, "ref": "a/b/c" });
            let err = SecretRef::from_json("T", &object).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("provider"), "object names provider: {msg}");
            assert!(msg.contains(name), "object names `{name}`: {msg}");
            assert!(!msg.contains("a/b/c"), "object hides the body: {msg}");
        }
    }

    #[test]
    fn shorthand_without_separator_errors_naming_the_key_not_the_body() {
        for json in [r#""plain-value""#, r#""op:/Private/Linear""#, r#""""#] {
            let msg = err_msg("LINEAR_API_KEY", json);
            assert!(msg.contains("LINEAR_API_KEY"), "names the key: {msg}");
            assert!(msg.contains("://"), "names the separator: {msg}");
        }
        assert!(!err_msg("K", r#""plain-value""#).contains("plain-value"));
        assert!(!err_msg("K", r#""op:/Private/Linear""#).contains("Private/Linear"));
    }

    #[test]
    fn shorthand_with_empty_scheme_errors_naming_the_key_not_the_body() {
        let msg = err_msg("T", r#""://Private/Linear CLI/credential""#);
        assert!(msg.contains("T"), "names the key: {msg}");
        assert!(msg.contains("scheme"), "names the scheme: {msg}");
        assert!(!msg.contains("Private/Linear CLI/credential"), "{msg}");
    }

    #[test]
    fn shorthand_with_empty_reference_errors_naming_the_key() {
        let msg = err_msg("T", r#""op://""#);
        assert!(msg.contains("T"), "names the key: {msg}");
        assert!(msg.contains("reference"), "names the reference: {msg}");
    }

    #[test]
    fn object_form_collects_unknown_keys_as_options() {
        let r = parse(
            "T",
            r#"{"provider":"op","ref":"Work/OpenAI/api key","account":"leafpass.1password.com"}"#,
        );
        assert_eq!(r.provider(), "op");
        assert_eq!(r.reference(), "Work/OpenAI/api key");
        assert_eq!(r.options().len(), 1);
        assert_eq!(
            r.option_str("account").unwrap(),
            Some("leafpass.1password.com")
        );
    }

    #[test]
    fn object_form_option_values_keep_their_json_types() {
        let r = parse(
            "T",
            r#"{"provider":"acme","ref":"x","retries":3,"tags":["a"],"nested":{"k":1}}"#,
        );
        assert_eq!(r.option("retries"), Some(&v("3")));
        assert_eq!(r.option("tags"), Some(&v(r#"["a"]"#)));
        assert_eq!(r.option("nested"), Some(&v(r#"{"k":1}"#)));
    }

    #[test]
    fn option_str_distinguishes_an_absent_option_from_a_wrong_typed_one() {
        let r = parse("T", r#"{"provider":"acme","ref":"x","retries":3}"#);
        assert_eq!(r.option_str("absent").unwrap(), None);
        let msg = format!("{}", r.option_str("retries").unwrap_err());
        assert!(msg.contains("T"), "names the key: {msg}");
        assert!(msg.contains("retries"), "names the option: {msg}");
        assert!(msg.contains("string"), "names the wanted type: {msg}");
    }

    #[test]
    fn object_form_flags_default_to_optional_false_and_create_time_true() {
        let plain = parse("T", r#"{"provider":"env","ref":"TOKEN"}"#);
        assert!(!plain.optional());
        assert!(plain.create_time());

        let optional = parse(
            "T",
            r#"{"provider":"keychain","ref":"fsm-db","optional":true}"#,
        );
        assert!(optional.optional());
        assert!(optional.create_time());

        let late = parse("T", r#"{"provider":"op","ref":"a/b/c","createTime":false}"#);
        assert!(!late.create_time());
        assert!(!late.optional());
    }

    #[test]
    fn object_form_reserved_keys_never_land_in_options() {
        let r = parse(
            "T",
            r#"{"provider":"op","ref":"a/b/c","optional":true,"createTime":false,"account":"x"}"#,
        );
        assert_eq!(
            r,
            SecretRef::new("T", "op", "a/b/c")
                .unwrap()
                .with_option("account", v(r#""x""#))
                .with_optional(true)
                .with_create_time(false)
        );
        for reserved in RESERVED_KEYS {
            assert!(r.option(reserved).is_none(), "{reserved} leaked to options");
        }
    }

    #[test]
    fn object_form_ref_is_not_reparsed_as_a_shorthand() {
        let r = parse("T", r#"{"provider":"op","ref":"op://a/b/c"}"#);
        assert_eq!(r.provider(), "op");
        assert_eq!(r.reference(), "op://a/b/c");
    }

    #[test]
    fn a_reference_containing_a_variable_placeholder_parses_unexpanded() {
        let r = parse("T", r#""op://${localEnv:VAULT}/item""#);
        assert_eq!(r.provider(), "op");
        assert_eq!(r.reference(), "${localEnv:VAULT}/item");
    }

    #[test]
    fn substitute_rewrites_the_body_and_every_top_level_string_option() {
        let mut r = parse(
            "T",
            r#"{"provider":"op","ref":"${X}/item","account":"${X}.example","retries":3}"#,
        );
        r.substitute(|s| s.replace("${X}", "vault")).unwrap();
        assert_eq!(r.reference(), "vault/item");
        assert_eq!(r.option_str("account").unwrap(), Some("vault.example"));
        assert_eq!(r.option("retries"), Some(&v("3")));
    }

    #[test]
    fn substitute_leaves_key_provider_option_keys_and_non_string_options_alone() {
        let mut r = parse(
            "T",
            r#"{"provider":"op","ref":"a/b/c","account":"x","retries":3}"#,
        );
        r.substitute(|s| format!("{s}!")).unwrap();
        assert_eq!(r.key(), "T");
        assert_eq!(r.provider(), "op");
        assert_eq!(r.reference(), "a/b/c!");
        assert_eq!(r.option_str("account").unwrap(), Some("x!"));
        assert_eq!(r.option("retries"), Some(&v("3")));
        let names: Vec<&str> = r.options().keys().map(String::as_str).collect();
        assert_eq!(names, vec!["account", "retries"]);
    }

    #[test]
    fn substitute_errors_when_it_empties_the_reference_body() {
        let mut r = parse("T", r#"{"provider":"op","ref":"${X}","account":"${X}"}"#);
        let err = r.substitute(|_| String::new()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("T"), "names the key: {msg}");
        assert!(msg.contains("substitution"), "says why: {msg}");

        // An option that empties is kept as an empty string, not an error.
        let mut r = parse("T", r#"{"provider":"op","ref":"a/b/c","account":"${X}"}"#);
        r.substitute(|s| s.replace("${X}", "")).unwrap();
        assert_eq!(r.option_str("account").unwrap(), Some(""));
    }

    #[test]
    fn substitute_does_not_recurse_into_nested_option_values() {
        let mut r = parse(
            "T",
            r#"{"provider":"acme","ref":"x","headers":{"X-Token":"${X}"},"tags":["${X}"]}"#,
        );
        r.substitute(|s| s.replace("${X}", "expanded")).unwrap();
        assert_eq!(r.option("headers"), Some(&v(r#"{"X-Token":"${X}"}"#)));
        assert_eq!(r.option("tags"), Some(&v(r#"["${X}"]"#)));
    }

    #[test]
    fn new_validates_the_provider_name_and_the_non_empty_rules() {
        assert!(SecretRef::new("K", "op", "a/b/c").is_ok());
        for (key, provider, reference) in [
            ("K", "../../../tmp/evil", "a/b/c"),
            ("K", "my provider", "a/b/c"),
            ("K", "", "a/b/c"),
            ("K", "op", ""),
            ("", "op", "a/b/c"),
        ] {
            let err = SecretRef::new(key, provider, reference).unwrap_err();
            assert!(
                matches!(err, DevError::SecretReference { .. }),
                "wrong variant for {provider}/{reference}"
            );
        }
    }

    #[test]
    fn object_form_missing_and_empty_required_fields_error_naming_the_field() {
        for (json, field) in [
            (r#"{}"#, "provider"),
            (r#"{"ref":"a/b/c"}"#, "provider"),
            (r#"{"provider":"op"}"#, "ref"),
            (r#"{"provider":"","ref":"a/b/c"}"#, "provider"),
            (r#"{"provider":"op","ref":""}"#, "ref"),
        ] {
            let msg = err_msg("T", json);
            assert!(msg.contains("T"), "names the key for {json}: {msg}");
            assert!(msg.contains(field), "names `{field}` for {json}: {msg}");
        }
    }

    #[test]
    fn object_form_wrong_field_types_error_naming_the_field_and_the_type() {
        for (json, field, wanted) in [
            (r#"{"provider":3,"ref":"a/b/c"}"#, "provider", "string"),
            (r#"{"provider":"op","ref":["a"]}"#, "ref", "string"),
            (
                r#"{"provider":"op","ref":"a/b/c","optional":"yes"}"#,
                "optional",
                "boolean",
            ),
            (
                r#"{"provider":"op","ref":"a/b/c","createTime":1}"#,
                "createTime",
                "boolean",
            ),
        ] {
            let msg = err_msg("T", json);
            assert!(msg.contains(field), "names `{field}` for {json}: {msg}");
            assert!(msg.contains(wanted), "names `{wanted}` for {json}: {msg}");
        }
    }

    #[test]
    fn entry_that_is_neither_string_nor_object_errors_naming_the_json_type() {
        for (json, kind) in [
            ("42", "number"),
            ("true", "boolean"),
            ("null", "null"),
            (r#"["op://a/b/c"]"#, "array"),
        ] {
            let msg = err_msg("T", json);
            assert!(msg.contains("T"), "names the key for {json}: {msg}");
            assert!(
                msg.contains("string or an object"),
                "says what is accepted for {json}: {msg}"
            );
            assert!(msg.contains(kind), "names `{kind}` for {json}: {msg}");
        }
    }

    #[test]
    fn no_error_message_contains_the_reference_body() {
        const SENTINEL: &str = "s3cret-sentinel";
        let bodies = [
            format!(r#""{SENTINEL}""#),
            format!(r#""op:/{SENTINEL}""#),
            format!(r#""://{SENTINEL}""#),
            format!(r#""my provider://{SENTINEL}""#),
            format!(r#""../../../tmp/evil://{SENTINEL}""#),
            format!(r#""op.beta://{SENTINEL}""#),
            format!(r#"{{"provider":"my provider","ref":"{SENTINEL}"}}"#),
            format!(r#"{{"provider":3,"ref":"{SENTINEL}"}}"#),
            format!(r#"{{"provider":"op","ref":"{SENTINEL}","optional":"yes"}}"#),
            format!(r#"{{"provider":"op","ref":"{SENTINEL}","createTime":1}}"#),
            format!(r#"["{SENTINEL}"]"#),
        ];
        for json in bodies {
            let err = SecretRef::from_json("T", &v(&json)).unwrap_err();
            assert!(matches!(err, DevError::SecretReference { .. }), "{json}");
            let msg = format!("{err}");
            assert!(msg.contains("T"), "names the key for {json}: {msg}");
            assert!(!msg.contains(SENTINEL), "leaked the body for {json}: {msg}");
        }
    }
}
