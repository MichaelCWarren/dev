//! Parse, provider-check, and variable-substitute `secrets.json` before `dev up`
//! has any side effect.
//!
//! A malformed reference or a provider name nothing answers to should cost a
//! second, not a multi-minute image build. So this runs at the same point in
//! `run_with_runtime` that validates `runArgs`: after config composition, before
//! `initializeCommand`, before any container lookup, before any build, before
//! the lockfile write, and before container creation.
//!
//! Nothing here resolves a secret. No provider's `resolve` is called, so this
//! costs no biometric prompt and no network round trip.
//!
//! Errors name the key, the provider, and the file path. Never a reference body
//! and never an option value: `${localEnv:...}` expands in both, so either can
//! hold something the user considers private.

use std::path::{Path, PathBuf};

use super::file;
use super::provider::ProviderRegistry;
use super::reference::SecretRef;
use crate::devcontainer::variables::substitute_variables_with_user;
use crate::error::DevError;

/// A `secrets.json` that has been found, parsed, checked against the provider
/// registry, and variable-substituted. Empty when the workspace declares no
/// secrets.
#[derive(Debug, Clone, Default)]
pub struct ValidatedSecrets {
    source: Option<PathBuf>,
    entries: Vec<SecretRef>,
}

impl ValidatedSecrets {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The file these entries came from, or `None` when there was no sidecar.
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    pub fn entries(&self) -> &[SecretRef] {
        &self.entries
    }

    /// The subset the create path injects. `createTime: false` means exec-time
    /// only, so those entries are skipped at create.
    pub fn create_time_entries(&self) -> impl Iterator<Item = &SecretRef> {
        self.entries.iter().filter(|r| r.create_time())
    }
}

/// Load, validate, and variable-substitute the `secrets.json` beside
/// `config_path`, if there is one.
///
/// `workspace` and `remote_user` exist only for substitution and are the same
/// two values the `runArgs` substitution passes, so one rule covers the whole
/// config.
///
/// Parsing, provider lookup, and substitution only. No provider is asked to
/// resolve anything, so this is safe to call before any side effect.
// `dev up` goes through `validate_secrets_at` so the sidecar-vs-override choice
// lives in one place. `dev exec` and `dev shell` discover from a config path.
pub fn validate_secrets_for_config(
    config_path: &Path,
    workspace: &Path,
    remote_user: Option<&str>,
    registry: &ProviderRegistry,
) -> Result<ValidatedSecrets, DevError> {
    validate_secrets_at(
        super::discovery::secrets_path_beside(config_path),
        workspace,
        remote_user,
        registry,
    )
}

/// [`validate_secrets_for_config`] against an explicit references file.
///
/// `--secrets` replaces the sidecar, never merges with it, so this takes the one
/// path the invocation settled on rather than a second source.
pub fn validate_secrets_at(
    path: Option<PathBuf>,
    workspace: &Path,
    remote_user: Option<&str>,
    registry: &ProviderRegistry,
) -> Result<ValidatedSecrets, DevError> {
    let Some(path) = path else {
        return Ok(ValidatedSecrets::default());
    };
    let mut entries = file::load(&path)?.secrets;
    check_providers(&entries, registry)?;
    substitute_entries(&mut entries, workspace, remote_user)?;
    Ok(ValidatedSecrets {
        source: Some(path),
        entries,
    })
}

/// One lookup per distinct provider name, in declaration order.
///
/// An unknown name is fatal even when every reference naming it is `optional`,
/// matching `ProviderRegistry::resolve_all`, which keeps its lookup outside the
/// whole-batch failure path for the same reason. The lookup result is thrown
/// away so `ValidatedSecrets` stays plain data; the create path looks providers
/// up again when it groups references for resolution.
fn check_providers(entries: &[SecretRef], registry: &ProviderRegistry) -> Result<(), DevError> {
    let mut checked: Vec<&str> = Vec::new();
    for entry in entries {
        if checked.contains(&entry.provider()) {
            continue;
        }
        registry.lookup(entry.key(), entry.provider())?;
        checked.push(entry.provider());
    }
    Ok(())
}

/// Expand devcontainer variables in every reference body and every top-level
/// string option.
///
/// After parsing, never over the raw document text: an expansion holding `"`,
/// `\`, `}`, or a newline would otherwise move where the JSON tokens end and
/// could add a key. Inside an already-delimited string it cannot escape.
///
/// After the provider check, so a file that is wrong in two ways reports the
/// unknown provider, which is the more useful of the two, and reports it
/// identically whether or not the body had variables in it.
fn substitute_entries(
    entries: &mut [SecretRef],
    workspace: &Path,
    remote_user: Option<&str>,
) -> Result<(), DevError> {
    for entry in entries.iter_mut() {
        // An option that expands to the empty string keeps its key with an empty
        // value; only an empty reference body is an error. The asymmetry is
        // deliberate: an empty `account` or `cwd` is coherent, an empty locator
        // is not.
        entry.substitute(|s| substitute_variables_with_user(s, workspace, remote_user))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::secrets::provider::{FakeProvider, PluginPath};
    use std::ffi::OsStr;
    use std::fs;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        workspace: PathBuf,
        config_path: PathBuf,
    }

    /// A workspace with a `.devcontainer/` holding a `devcontainer.json` and the
    /// `secrets.json` beside it.
    fn fixture(secrets: &str) -> Fixture {
        let dir = TempDir::new().unwrap();
        let workspace = dir.path().to_path_buf();
        let devcontainer = workspace.join(".devcontainer");
        fs::create_dir_all(&devcontainer).unwrap();
        let config_path = devcontainer.join("devcontainer.json");
        fs::write(&config_path, r#"{"image":"ubuntu:24.04"}"#).unwrap();
        fs::write(devcontainer.join("secrets.json"), secrets).unwrap();
        Fixture {
            _dir: dir,
            workspace,
            config_path,
        }
    }

    /// Built-ins plus a plugin search path pointed at nothing, so an unknown
    /// name cannot be rescued by a `dev-secret-*` that happens to sit on the
    /// developer's real `PATH`.
    fn registry(workspace: &Path) -> ProviderRegistry {
        ProviderRegistry::with_builtins_in(workspace, PluginPath::from_os_str(OsStr::new("")))
    }

    fn validate(f: &Fixture) -> Result<ValidatedSecrets, DevError> {
        let registry = registry(&f.workspace);
        validate_secrets_for_config(&f.config_path, &f.workspace, None, &registry)
    }

    fn only_entry(f: &Fixture) -> SecretRef {
        let validated = validate(f).expect("file should validate");
        assert_eq!(validated.entries().len(), 1);
        validated.entries()[0].clone()
    }

    #[test]
    fn no_secrets_file_yields_an_empty_set() {
        let dir = TempDir::new().unwrap();
        let devcontainer = dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer).unwrap();
        let config_path = devcontainer.join("devcontainer.json");
        fs::write(&config_path, r#"{"image":"ubuntu:24.04"}"#).unwrap();

        let registry = registry(dir.path());
        let validated =
            validate_secrets_for_config(&config_path, dir.path(), None, &registry).unwrap();
        assert!(validated.is_empty());
        assert!(validated.source().is_none());
    }

    #[test]
    fn a_valid_file_comes_back_with_its_source() {
        let f = fixture(r#"{"version":1,"secrets":{"TOKEN":"env://TOKEN"}}"#);
        let validated = validate(&f).unwrap();
        assert_eq!(validated.entries().len(), 1);
        assert_eq!(
            validated.source().unwrap(),
            f.config_path.parent().unwrap().join("secrets.json")
        );
    }

    #[test]
    fn a_bad_document_version_is_an_error() {
        let f = fixture(r#"{"version":9,"secrets":{"TOKEN":"env://TOKEN"}}"#);
        assert!(validate(&f).is_err());
    }

    #[test]
    fn a_malformed_reference_is_an_error() {
        let f = fixture(r#"{"version":1,"secrets":{"TOKEN":"no-scheme-here"}}"#);
        let err = validate(&f).unwrap_err();
        assert!(format!("{err}").contains("TOKEN"));
    }

    /// The check must not stop at the first entry when a later one is broken.
    #[test]
    fn a_broken_entry_after_a_good_one_still_fails() {
        let f = fixture(
            r#"{"version":1,"secrets":{"GOOD":"env://GOOD","BAD":{"provider":"nosuch","ref":"x"}}}"#,
        );
        let msg = format!("{}", validate(&f).unwrap_err());
        assert!(msg.contains("nosuch"), "{msg}");
        assert!(msg.contains("BAD"), "{msg}");
    }

    #[test]
    fn an_unknown_provider_names_the_provider_and_the_key() {
        let f = fixture(r#"{"version":1,"secrets":{"TOKEN":"nosuch://a/b"}}"#);
        let msg = format!("{}", validate(&f).unwrap_err());
        assert!(msg.contains("nosuch"), "{msg}");
        assert!(msg.contains("TOKEN"), "{msg}");
    }

    /// `optional` excuses a missing value, never a provider name nothing
    /// answers to. The registry treats it as fatal and validation agrees.
    #[test]
    fn an_unknown_provider_is_fatal_even_when_optional() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"nosuch","ref":"a","optional":true}}}"#,
        );
        assert!(validate(&f).is_err());
    }

    #[test]
    fn unknown_provider_is_rejected_before_substitution() {
        let f = fixture(r#"{"version":1,"secrets":{"TOKEN":"nosuch://${localWorkspaceFolder}"}}"#);
        let msg = format!("{}", validate(&f).unwrap_err());
        assert!(msg.contains("nosuch"), "{msg}");
        assert!(!msg.contains("localWorkspaceFolder"), "{msg}");
    }

    /// A registered provider is looked up once per distinct name, so a second
    /// reference to the same provider does not need a second registration.
    #[test]
    fn a_registered_provider_satisfies_every_reference_naming_it() {
        let f = fixture(r#"{"version":1,"secrets":{"A":"fake://a","B":"fake://b","C":"env://C"}}"#);
        let mut registry = registry(&f.workspace);
        registry.register(Box::new(FakeProvider::answers_everything()));
        let validated =
            validate_secrets_for_config(&f.config_path, &f.workspace, None, &registry).unwrap();
        assert_eq!(validated.entries().len(), 3);
    }

    #[test]
    fn substitutes_variables_in_the_reference_body() {
        let f =
            fixture(r#"{"version":1,"secrets":{"TOKEN":"file://${localWorkspaceFolder}/token"}}"#);
        let entry = only_entry(&f);
        assert_eq!(
            entry.reference(),
            format!("{}/token", f.workspace.display())
        );
        assert!(!entry.reference().contains("${"));
    }

    #[test]
    fn substitutes_variables_in_option_values() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"env","ref":"TOKEN","cwd":"${localWorkspaceFolder}"}}}"#,
        );
        let entry = only_entry(&f);
        assert_eq!(
            entry.option_str("cwd").unwrap(),
            Some(f.workspace.to_str().unwrap())
        );
    }

    #[test]
    fn leaves_non_string_option_values_alone() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"env","ref":"TOKEN","retries":3,"quiet":true,"cwd":"${localWorkspaceFolder}"}}}"#,
        );
        let entry = only_entry(&f);
        assert_eq!(entry.option("retries"), Some(&serde_json::json!(3)));
        assert_eq!(entry.option("quiet"), Some(&serde_json::json!(true)));
        assert!(!entry.option_str("cwd").unwrap().unwrap().contains("${"));
    }

    /// Rewriting strings inside a payload dev does not understand is a worse
    /// failure than leaving a placeholder alone: for a plugin provider the
    /// options map is a wire format, not dev's data.
    #[test]
    fn leaves_nested_option_strings_literal() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"env","ref":"TOKEN","headers":{"X":"${localWorkspaceFolder}"},"args":["${localWorkspaceFolder}"]}}}"#,
        );
        let entry = only_entry(&f);
        let nested = format!("{}", entry.option("headers").unwrap());
        assert!(nested.contains("${localWorkspaceFolder}"), "{nested}");
        let args = format!("{}", entry.option("args").unwrap());
        assert!(args.contains("${localWorkspaceFolder}"), "{args}");
    }

    #[test]
    fn empty_option_value_is_kept() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"env","ref":"TOKEN","account":"${localEnv:DEV_SECRETS_VALIDATE_UNSET_OPT}"}}}"#,
        );
        let entry = only_entry(&f);
        assert_eq!(entry.option_str("account").unwrap(), Some(""));
    }

    #[test]
    fn empty_reference_body_is_an_error() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":"env://${localEnv:DEV_SECRETS_VALIDATE_UNSET_BODY}"}}"#,
        );
        let msg = format!("{}", validate(&f).unwrap_err());
        assert!(msg.contains("TOKEN"), "{msg}");
    }

    /// dev cannot tell a deliberate absolute path from a blanked variable, so
    /// the provider reports this one later as a missing file.
    #[test]
    fn partial_expansion_of_reference_body_is_not_an_error() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":"file://${localEnv:DEV_SECRETS_VALIDATE_UNSET_PART}/token"}}"#,
        );
        assert_eq!(only_entry(&f).reference(), "/token");
    }

    #[test]
    fn unknown_variable_is_left_alone() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"file","ref":"${nope}/x","cwd":"${alsoNope}"}}}"#,
        );
        let entry = only_entry(&f);
        assert_eq!(entry.reference(), "${nope}/x");
        assert_eq!(entry.option_str("cwd").unwrap(), Some("${alsoNope}"));
    }

    /// `substitute` cannot reach `provider` or an option key, so this guards a
    /// future refactor rather than today's code.
    #[test]
    fn never_substitutes_the_provider_name_or_option_keys() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"env","ref":"TOKEN","${localWorkspaceFolder}":"${localWorkspaceFolder}"}}}"#,
        );
        let entry = only_entry(&f);
        assert_eq!(entry.provider(), "env");
        assert!(entry.options().contains_key("${localWorkspaceFolder}"));
        assert_eq!(
            entry.option_str("${localWorkspaceFolder}").unwrap(),
            Some(f.workspace.to_str().unwrap())
        );
    }

    /// Substitution runs on the parsed reference, never on the document text.
    /// An expansion carrying `"` must not be able to add a key.
    #[test]
    fn substitution_cannot_change_document_shape() {
        let var = "DEV_SECRETS_VALIDATE_SHAPE_VAR";
        unsafe { std::env::set_var(var, r#"", "INJECTED": "env://X"#) };
        let f = fixture(&format!(
            r#"{{"version":1,"secrets":{{"TOKEN":"env://${{localEnv:{var}}}"}}}}"#
        ));
        let validated = validate(&f).unwrap();
        unsafe { std::env::remove_var(var) };

        assert_eq!(validated.entries().len(), 1);
        assert_eq!(validated.entries()[0].key(), "TOKEN");
        assert!(validated.entries().iter().all(|r| r.key() != "INJECTED"));
    }

    #[test]
    fn create_time_entries_skip_exec_time_only_references() {
        let f = fixture(
            r#"{"version":1,"secrets":{"A":"env://A","B":{"provider":"env","ref":"B","createTime":false}}}"#,
        );
        let validated = validate(&f).unwrap();
        let keys: Vec<&str> = validated.create_time_entries().map(|r| r.key()).collect();
        assert_eq!(keys, vec!["A"]);
    }
}
