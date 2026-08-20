//! Read a `secrets.json` document into an ordered list of [`SecretRef`]s.
//!
//! This is the only reader of the format, so the rules that belong to the
//! document live here: the supported `version`, which environment variable
//! names are legal keys, the rejection of a repeated key, and document order.
//! Everything about a single reference, including the `optional` and
//! `createTime` flags, is [`SecretRef::from_json`]'s business.
//!
//! Failures split two ways. A problem attached to one key is a
//! [`DevError::SecretReference`] naming that key; a problem with the document as
//! a whole is a [`DevError::InvalidConfig`] naming the path. Nothing but key
//! names, the version, and the path ever reaches a message, so a reference body
//! that turns out to be a pasted secret cannot escape through an error.

use super::env_name_problem;
use super::reference::SecretRef;
use crate::devcontainer::jsonc::parse_jsonc;
use crate::error::DevError;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

/// The only `version` this reader accepts.
#[allow(dead_code)]
pub const SUPPORTED_VERSION: u32 = 1;

/// The marker the duplicate-key visitor writes into a `serde_json::Error` so
/// `parse` can lift it back onto the per-key error variant.
const DUPLICATE_PREFIX: &str = "duplicate secret key ";

/// A parsed `secrets.json`, in document order.
// The allows come off once Group 5 wires `up.rs` to these types.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SecretsFile {
    pub version: u32,
    pub secrets: Vec<SecretRef>,
}

/// Read and parse a `secrets.json`. A path that does not exist is an error
/// here; treating a missing sidecar as "no secrets" is the discovery layer's
/// rule.
#[allow(dead_code)]
pub fn load(path: &Path) -> Result<SecretsFile, DevError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| DevError::InvalidConfig(format!("Failed to read {}: {e}", path.display())))?;
    parse(&content, path)
}

/// Parse document text. Comments and trailing commas are accepted, matching the
/// `devcontainer.json` beside it.
#[allow(dead_code)]
pub fn parse(content: &str, path: &Path) -> Result<SecretsFile, DevError> {
    let raw: RawSecretsFile = parse_jsonc(content).map_err(|e| document_error(path, &e))?;
    check_version(raw.version, path)?;
    Ok(SecretsFile {
        version: raw.version,
        secrets: build_refs(raw.secrets.0)?,
    })
}

fn check_version(version: u32, path: &Path) -> Result<(), DevError> {
    if version == SUPPORTED_VERSION {
        return Ok(());
    }
    Err(DevError::InvalidConfig(format!(
        "{} declares secrets version {version}, but only version {SUPPORTED_VERSION} is supported",
        path.display()
    )))
}

/// No path argument: every error below here names a key, and one `dev up` reads
/// exactly one references file.
fn build_refs(raw: Vec<(String, Value)>) -> Result<Vec<SecretRef>, DevError> {
    raw.iter()
        .map(|(key, value)| {
            validate_env_name(key)?;
            SecretRef::from_json(key, value)
        })
        .collect()
}

/// [`env_name_problem`] as a per-key error. The rule itself is shared with
/// `--secrets-file`, which applies the same one to its literal keys.
fn validate_env_name(key: &str) -> Result<(), DevError> {
    match env_name_problem(key) {
        None => Ok(()),
        Some(reason) => Err(DevError::SecretReference {
            key: key.to_string(),
            reason: reason.to_string(),
        }),
    }
}

/// A repeated key is the one per-key problem serde detects, so lift it back off
/// the `serde_json::Error` and onto the variant it belongs on.
fn document_error(path: &Path, error: &serde_json::Error) -> DevError {
    let message = error.to_string();
    match duplicate_key(&message) {
        Some(key) => DevError::SecretReference {
            key: key.to_string(),
            reason: "declared more than once".to_string(),
        },
        None => DevError::InvalidConfig(format!("Failed to parse {}: {message}", path.display())),
    }
}

fn duplicate_key(message: &str) -> Option<&str> {
    let rest = message.split_once(DUPLICATE_PREFIX)?.1;
    rest.strip_prefix('`')?.split_once('`').map(|(key, _)| key)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretsFile {
    version: u32,
    secrets: OrderedSecrets,
}

/// Collects the `secrets` object in document order and rejects a repeated key.
/// `serde_json` keeps the last duplicate silently, so the check has to happen
/// while both occurrences are still visible.
const NOT_A_MAP: &str =
    "`secrets` must be an object mapping environment variable names to references";

struct OrderedSecrets(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for OrderedSecrets {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(OrderedSecretsVisitor)
    }
}

struct OrderedSecretsVisitor;

impl<'de> Visitor<'de> for OrderedSecretsVisitor {
    type Value = OrderedSecrets;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a map of environment variable names to secret references")
    }

    /// Serde's own `invalid type` message quotes the offending string, which for
    /// a misplaced reference would put the reference body in the error. Answer
    /// with a fixed message instead.
    fn visit_str<E: de::Error>(self, _value: &str) -> Result<Self::Value, E> {
        Err(E::custom(NOT_A_MAP))
    }

    fn visit_string<E: de::Error>(self, _value: String) -> Result<Self::Value, E> {
        Err(E::custom(NOT_A_MAP))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("{DUPLICATE_PREFIX}`{key}`")));
            }
            entries.push((key, value));
        }
        Ok(OrderedSecrets(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESIGN_DOC_EXAMPLE: &str = r#"{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/Linear CLI/credential",
    "OPENAI_API_KEY": {
      "provider": "op",
      "ref": "Work/OpenAI/api key",
      "account": "leafpass.1password.com"
    },
    "DB_PASSWORD": { "provider": "keychain", "ref": "fsm-db", "optional": true }
  }
}"#;

    fn path() -> &'static Path {
        Path::new("/ws/.devcontainer/secrets.json")
    }

    fn load_doc(content: &str) -> Result<SecretsFile, DevError> {
        parse(content, path())
    }

    fn ok(content: &str) -> SecretsFile {
        load_doc(content).unwrap()
    }

    fn err(content: &str) -> DevError {
        load_doc(content).unwrap_err()
    }

    fn keys(file: &SecretsFile) -> Vec<&str> {
        file.secrets.iter().map(SecretRef::key).collect()
    }

    fn one(reference: &str) -> SecretRef {
        let doc = format!(r#"{{"version":1,"secrets":{{"T":{reference}}}}}"#);
        ok(&doc).secrets.remove(0)
    }

    #[test]
    fn design_doc_example_parses() {
        let file = ok(DESIGN_DOC_EXAMPLE);
        assert_eq!(file.version, 1);
        assert_eq!(
            keys(&file),
            vec!["LINEAR_API_KEY", "OPENAI_API_KEY", "DB_PASSWORD"]
        );
        assert_eq!(file.secrets[0].provider(), "op");
        assert_eq!(
            file.secrets[1].option_str("account").unwrap(),
            Some("leafpass.1password.com")
        );
        assert!(file.secrets[2].optional());
    }

    #[test]
    fn order_is_document_order_not_sorted() {
        let doc = r#"{"version":1,"secrets":{"Z":"env://Z","A":"env://A","M":"env://M"}}"#;
        assert_eq!(keys(&ok(doc)), vec!["Z", "A", "M"]);
    }

    #[test]
    fn unknown_version_errors_naming_the_file() {
        let e = err(r#"{"version":2,"secrets":{}}"#);
        assert!(matches!(e, DevError::InvalidConfig(_)), "{e:?}");
        let msg = format!("{e}");
        assert!(msg.contains("secrets.json"), "names the file: {msg}");
        assert!(msg.contains('2'), "names the version: {msg}");
    }

    #[test]
    fn missing_secrets_object_errors() {
        let e = err(r#"{"version":1}"#);
        assert!(matches!(e, DevError::InvalidConfig(_)), "{e:?}");
        assert!(format!("{e}").contains("secrets.json"));
    }

    #[test]
    fn missing_version_errors() {
        let e = err(r#"{"secrets":{}}"#);
        assert!(matches!(e, DevError::InvalidConfig(_)), "{e:?}");
        assert!(format!("{e}").contains("version"));
    }

    #[test]
    fn unknown_top_level_key_errors_by_name() {
        let e = err(r#"{"version":1,"secret":{}}"#);
        assert!(matches!(e, DevError::InvalidConfig(_)), "{e:?}");
        assert!(format!("{e}").contains("secret"), "{e}");
    }

    #[test]
    fn empty_secrets_map_is_valid() {
        assert!(ok(r#"{"version":1,"secrets":{}}"#).secrets.is_empty());
    }

    #[test]
    fn malformed_key_errors_naming_the_key() {
        for (key, rule) in [
            (r"", "empty"),
            (r"A B", "whitespace"),
            (r"A\tB", "whitespace"),
            (r"A\nB", "whitespace"),
            (r"A=B", "`=`"),
        ] {
            let doc = format!(r#"{{"version":1,"secrets":{{"{key}":"env://X"}}}}"#);
            let e = err(&doc);
            assert!(
                matches!(e, DevError::SecretReference { .. }),
                "wrong variant for `{key}`: {e:?}"
            );
            let msg = format!("{e}");
            assert!(msg.contains(rule), "names the rule for `{key}`: {msg}");
            if !key.is_empty() {
                assert!(msg.contains('A'), "names the key for `{key}`: {msg}");
            }
        }
    }

    #[test]
    fn well_formed_keys_are_accepted() {
        for key in ["LINEAR_API_KEY", "a_b1", "1DIGIT", "with-dash"] {
            let doc = format!(r#"{{"version":1,"secrets":{{"{key}":"env://X"}}}}"#);
            assert_eq!(ok(&doc).secrets[0].key(), key);
        }
    }

    #[test]
    fn duplicate_key_errors_naming_the_key() {
        let doc = r#"{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/first",
    "LINEAR_API_KEY": "env://SECOND"
  }
}"#;
        let e = err(doc);
        assert!(matches!(e, DevError::SecretReference { .. }), "{e:?}");
        let msg = format!("{e}");
        assert!(msg.contains("LINEAR_API_KEY"), "names the key: {msg}");
        assert!(!msg.contains("SECOND"), "hides the body: {msg}");
    }

    #[test]
    fn flags_default_for_shorthand() {
        let r = one(r#""op://Private/Linear CLI/credential""#);
        assert!(!r.optional());
        assert!(r.create_time());
    }

    #[test]
    fn flags_default_for_object_form() {
        let r = one(r#"{"provider":"op","ref":"a/b/c"}"#);
        assert!(!r.optional());
        assert!(r.create_time());
    }

    #[test]
    fn flags_are_read_through() {
        let r = one(r#"{"provider":"op","ref":"a/b/c","optional":true,"createTime":false}"#);
        assert!(r.optional());
        assert!(!r.create_time());
    }

    #[test]
    fn reference_errors_propagate() {
        for reference in [
            r#""plain-value""#,
            r#"{"provider":"op"}"#,
            r#"{"provider":"../../../tmp/evil","ref":"a/b/c"}"#,
            "42",
        ] {
            let doc = format!(r#"{{"version":1,"secrets":{{"T":{reference}}}}}"#);
            let e = err(&doc);
            assert!(
                matches!(e, DevError::SecretReference { .. }),
                "wrong variant for {reference}: {e:?}"
            );
        }
    }

    #[test]
    fn comments_and_trailing_comma_parse() {
        let doc = r#"{
  // The version this reader supports.
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/Linear CLI/credential", // trailing comma below
    "OPENAI_API_KEY": "env://OPENAI_API_KEY",
  },
}"#;
        assert_eq!(keys(&ok(doc)), vec!["LINEAR_API_KEY", "OPENAI_API_KEY"]);
    }

    #[test]
    fn errors_never_contain_reference_bodies() {
        let doc = r#"{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/Linear CLI/credential",
    "BAD KEY": "op://Private/Linear CLI/credential"
  }
}"#;
        let msg = format!("{}", err(doc));
        assert!(msg.contains("BAD KEY"), "names the key: {msg}");
        assert!(!msg.contains("Linear CLI"), "hides the item: {msg}");
        assert!(!msg.contains("credential"), "hides the field: {msg}");
    }

    #[test]
    fn load_errors_on_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("secrets.json");
        let e = load(&missing).unwrap_err();
        assert!(matches!(e, DevError::InvalidConfig(_)), "{e:?}");
        assert!(format!("{e}").contains(&missing.display().to_string()));
    }

    #[test]
    fn load_reads_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secrets.json");
        std::fs::write(&file, DESIGN_DOC_EXAMPLE).unwrap();
        assert_eq!(load(&file).unwrap().secrets.len(), 3);
    }

    #[test]
    fn a_string_in_place_of_the_secrets_map_never_echoes_the_reference() {
        let body = "op://Private/Linear CLI/credential";
        let content = format!(r#"{{"version": 1, "secrets": "{body}"}}"#);
        let err = parse(&content, Path::new("/tmp/secrets.json")).unwrap_err();
        let message = err.to_string();
        assert!(
            !message.contains(body),
            "leaked the reference body: {message}"
        );
        assert!(message.contains("secrets"), "unhelpful message: {message}");
    }
}
