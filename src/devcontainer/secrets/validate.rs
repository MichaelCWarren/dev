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
use super::reference::{ResolveTime, SecretRef};
use crate::devcontainer::variables::substitute_variables_with_user;
use crate::error::DevError;
use crate::util::paths::DevHome;

/// Which layer declared an entry. A project key that replaces a base key is
/// `Project`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretOrigin {
    Base,
    Project,
}

/// The base and project `secrets.json` files, found, parsed, checked against
/// the provider registry, variable-substituted, and merged. Empty when neither
/// file exists.
#[derive(Debug, Clone, Default)]
pub struct ValidatedSecrets {
    sources: Vec<(PathBuf, SecretOrigin)>,
    entries: Vec<(SecretRef, SecretOrigin)>,
    downgraded: Vec<String>,
}

impl ValidatedSecrets {
    /// The files these entries came from, base first. Empty when there were none.
    #[cfg(test)]
    pub fn sources(&self) -> Vec<&Path> {
        self.sources.iter().map(|(p, _)| p.as_path()).collect()
    }

    /// The file the `origin` layer was read from, if that layer had one.
    pub fn source_from(&self, origin: SecretOrigin) -> Option<&Path> {
        self.sources
            .iter()
            .find(|(_, o)| *o == origin)
            .map(|(p, _)| p.as_path())
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<&SecretRef> {
        self.entries.iter().map(|(r, _)| r).collect()
    }

    pub fn entries_at(&self, time: ResolveTime) -> impl Iterator<Item = &SecretRef> {
        self.entries
            .iter()
            .map(|(r, _)| r)
            .filter(move |r| r.resolve_time() == time)
    }

    pub fn entries_with_origin(&self) -> impl Iterator<Item = (&SecretRef, SecretOrigin)> {
        self.entries.iter().map(|(r, o)| (r, *o))
    }

    pub fn entries_at_from(
        &self,
        time: ResolveTime,
        origin: SecretOrigin,
    ) -> impl Iterator<Item = &SecretRef> {
        self.entries_with_origin()
            .filter(move |(r, o)| r.resolve_time() == time && *o == origin)
            .map(|(r, _)| r)
    }

    /// The base-file `create` keys a Compose validation moved to `up`, in entry
    /// order. Only `dev up` reports them, so the warning prints once.
    pub fn downgraded_to_up(&self) -> &[String] {
        &self.downgraded
    }

    /// Compose cannot inject at create, so a base-file `create` entry is
    /// resolved at `up` instead. Returns the downgraded keys in entry order.
    fn downgrade_base_create_to_up(&mut self) -> Vec<String> {
        let mut keys = Vec::new();
        for (entry, origin) in &mut self.entries {
            if *origin == SecretOrigin::Base && entry.resolve_time() == ResolveTime::Create {
                keys.push(entry.key().to_string());
                entry.set_resolve_time(ResolveTime::Up);
            }
        }
        keys
    }
}

/// Load, validate, and variable-substitute the `secrets.json` beside
/// `config_path`, merged over `~/.dev/base/secrets.json`.
///
/// `workspace` and `remote_user` exist only for substitution and are the same
/// two values the `runArgs` substitution passes, so one rule covers the whole
/// config.
///
/// `compose` applies the Compose rule that a base-file `create` entry resolves
/// at `up`, here, so every reader of a Compose workspace agrees on it.
///
/// Parsing, provider lookup, and substitution only. No provider is asked to
/// resolve anything, so this is safe to call before any side effect.
// `dev up` goes through `validate_secrets_at` so the sidecar-vs-override choice
// lives in one place. `dev exec` and `dev shell` discover from a config path.
pub fn validate_secrets_for_config(
    dev_home: &DevHome,
    config_path: &Path,
    workspace: &Path,
    remote_user: Option<&str>,
    compose: bool,
    registry: &ProviderRegistry,
) -> Result<ValidatedSecrets, DevError> {
    validate_secrets_at(
        dev_home,
        super::discovery::secrets_path_beside(config_path),
        workspace,
        remote_user,
        compose,
        registry,
    )
}

/// [`validate_secrets_for_config`] against an explicit references file.
///
/// `--secrets` replaces the sidecar, never merges with it, so this takes the one
/// path the invocation settled on rather than a second source. The base file
/// sits under whichever one that is, and a project key replaces a base key of
/// the same name, the way a project's `remoteEnv` beats the base layer's.
pub fn validate_secrets_at(
    dev_home: &DevHome,
    path: Option<PathBuf>,
    workspace: &Path,
    remote_user: Option<&str>,
    compose: bool,
    registry: &ProviderRegistry,
) -> Result<ValidatedSecrets, DevError> {
    let base = dev_home.base_secrets();
    let layers: Vec<(PathBuf, SecretOrigin)> = base
        .is_file()
        .then_some((base, SecretOrigin::Base))
        .into_iter()
        .chain(path.map(|p| (p, SecretOrigin::Project)))
        .collect();
    let mut entries = merge_layers(&layers)?;
    check_providers(entries.iter().map(|(r, _)| r), registry)?;
    substitute_entries(entries.iter_mut().map(|(r, _)| r), workspace, remote_user)?;
    let mut validated = ValidatedSecrets {
        sources: layers,
        entries,
        downgraded: Vec::new(),
    };
    if compose {
        validated.downgraded = validated.downgrade_base_create_to_up();
    }
    Ok(validated)
}

fn merge_layers(
    layers: &[(PathBuf, SecretOrigin)],
) -> Result<Vec<(SecretRef, SecretOrigin)>, DevError> {
    let mut merged: Vec<(SecretRef, SecretOrigin)> = Vec::new();
    for (source, origin) in layers {
        for entry in file::load(source)?.secrets {
            merged.retain(|(e, _)| e.key() != entry.key());
            merged.push((entry, *origin));
        }
    }
    Ok(merged)
}

/// One lookup per distinct provider name, in declaration order.
///
/// An unknown name is fatal even when every reference naming it is `optional`,
/// matching `ProviderRegistry::resolve_all`, which keeps its lookup outside the
/// whole-batch failure path for the same reason. The lookup result is thrown
/// away so `ValidatedSecrets` stays plain data; the create path looks providers
/// up again when it groups references for resolution.
fn check_providers<'a>(
    entries: impl Iterator<Item = &'a SecretRef>,
    registry: &ProviderRegistry,
) -> Result<(), DevError> {
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
fn substitute_entries<'a>(
    entries: impl Iterator<Item = &'a mut SecretRef>,
    workspace: &Path,
    remote_user: Option<&str>,
) -> Result<(), DevError> {
    for entry in entries {
        // An option that expands to the empty string keeps its key with an empty
        // value; only an empty reference body is an error. The asymmetry is
        // deliberate: an empty `account` or `cwd` is coherent, an empty locator
        // is not.
        entry.substitute(|s| substitute_variables_with_user(s, workspace, remote_user))?;
    }
    Ok(())
}

/// A `~/.dev` under `workspace` whose `base/secrets.json` holds `secrets`.
#[cfg(test)]
pub(crate) fn with_base(workspace: &Path, secrets: &str) -> DevHome {
    let home = DevHome::at(workspace.join("dev-home"));
    write_base_secrets(&home, secrets);
    home
}

#[cfg(test)]
pub(crate) fn write_base_secrets(home: &DevHome, secrets: &str) {
    std::fs::create_dir_all(home.base_secrets().parent().unwrap()).unwrap();
    std::fs::write(home.base_secrets(), secrets).unwrap();
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

    /// A `~/.dev` with no base secrets, so no test reads the real one.
    fn no_base(workspace: &Path) -> DevHome {
        DevHome::at(workspace.join("dev-home"))
    }

    fn validate_with(home: &DevHome, f: &Fixture) -> Result<ValidatedSecrets, DevError> {
        let registry = registry(&f.workspace);
        validate_secrets_for_config(home, &f.config_path, &f.workspace, None, false, &registry)
    }

    #[test]
    fn base_secrets_reach_a_project_with_none_of_its_own() {
        let dir = TempDir::new().unwrap();
        let devcontainer = dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer).unwrap();
        let config_path = devcontainer.join("devcontainer.json");
        fs::write(&config_path, r#"{"image":"ubuntu:24.04"}"#).unwrap();
        let home = with_base(
            dir.path(),
            r#"{"version":1,"secrets":{"GH_TOKEN":"env://GH"}}"#,
        );

        let validated = validate_secrets_for_config(
            &home,
            &config_path,
            dir.path(),
            None,
            false,
            &registry(dir.path()),
        )
        .unwrap();
        let keys: Vec<&str> = validated.entries().iter().map(|e| e.key()).collect();
        assert_eq!(keys, ["GH_TOKEN"]);
        assert_eq!(validated.sources(), [home.base_secrets()]);
    }

    #[test]
    fn a_project_key_replaces_the_base_key_of_the_same_name() {
        let f =
            fixture(r#"{"version":1,"secrets":{"GH_TOKEN":"env://PROJECT","OWN":"env://OWN"}}"#);
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{"GH_TOKEN":"env://BASE","SHARED":"env://SHARED"}}"#,
        );

        let validated = validate_with(&home, &f).unwrap();
        let entries: Vec<(&str, &str)> = validated
            .entries()
            .iter()
            .map(|e| (e.key(), e.reference()))
            .collect();
        assert_eq!(
            entries,
            [
                ("SHARED", "SHARED"),
                ("GH_TOKEN", "PROJECT"),
                ("OWN", "OWN")
            ]
        );
        assert_eq!(validated.sources().len(), 2);
    }

    #[test]
    fn a_broken_base_file_fails_every_project() {
        let f = fixture(r#"{"version":1,"secrets":{"OWN":"env://OWN"}}"#);
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{"GH_TOKEN":"nosuch://x"}}"#,
        );
        let msg = format!("{}", validate_with(&home, &f).unwrap_err());
        assert!(msg.contains("GH_TOKEN"), "{msg}");
    }

    fn validate(f: &Fixture) -> Result<ValidatedSecrets, DevError> {
        let registry = registry(&f.workspace);
        validate_secrets_for_config(
            &no_base(&f.workspace),
            &f.config_path,
            &f.workspace,
            None,
            false,
            &registry,
        )
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
        let validated = validate_secrets_for_config(
            &no_base(dir.path()),
            &config_path,
            dir.path(),
            None,
            false,
            &registry,
        )
        .unwrap();
        assert!(validated.entries().is_empty());
        assert!(validated.sources().is_empty());
    }

    #[test]
    fn a_valid_file_comes_back_with_its_source() {
        let f = fixture(r#"{"version":1,"secrets":{"TOKEN":"env://TOKEN"}}"#);
        let validated = validate(&f).unwrap();
        assert_eq!(validated.entries().len(), 1);
        assert_eq!(
            validated
                .entries_with_origin()
                .map(|(_, o)| o)
                .collect::<Vec<_>>(),
            [SecretOrigin::Project]
        );
        assert_eq!(
            validated.sources(),
            [f.config_path.parent().unwrap().join("secrets.json")]
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
        let validated = validate_secrets_for_config(
            &no_base(&f.workspace),
            &f.config_path,
            &f.workspace,
            None,
            false,
            &registry,
        )
        .unwrap();
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

    fn keys<'a>(entries: impl Iterator<Item = &'a SecretRef>) -> Vec<&'a str> {
        entries.map(|r| r.key()).collect()
    }

    #[test]
    fn entries_at_filters_by_resolve_time() {
        let f = fixture(
            r#"{"version":1,"secrets":{
                "A":"env://A",
                "B":{"provider":"env","ref":"B","createTime":false},
                "C":{"provider":"env","ref":"C","resolve":"up"},
                "D":{"provider":"env","ref":"D","resolve":"exec"}}}"#,
        );
        let validated = validate(&f).unwrap();
        assert_eq!(keys(validated.entries_at(ResolveTime::Create)), ["A"]);
        assert_eq!(keys(validated.entries_at(ResolveTime::Up)), ["C"]);
        assert_eq!(keys(validated.entries_at(ResolveTime::Exec)), ["B", "D"]);
    }

    #[test]
    fn origins_track_the_declaring_layer() {
        let f =
            fixture(r#"{"version":1,"secrets":{"GH_TOKEN":"env://PROJECT","OWN":"env://OWN"}}"#);
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{"GH_TOKEN":"env://BASE","SHARED":"env://SHARED"}}"#,
        );

        let validated = validate_with(&home, &f).unwrap();
        let pairs: Vec<(&str, SecretOrigin)> = validated
            .entries_with_origin()
            .map(|(r, o)| (r.key(), o))
            .collect();
        assert_eq!(
            pairs,
            [
                ("SHARED", SecretOrigin::Base),
                ("GH_TOKEN", SecretOrigin::Project),
                ("OWN", SecretOrigin::Project)
            ]
        );
        let (gh, _) = validated
            .entries_with_origin()
            .find(|(r, _)| r.key() == "GH_TOKEN")
            .unwrap();
        assert_eq!(gh.reference(), "PROJECT");
    }

    #[test]
    fn entries_at_from_combines_time_and_origin() {
        let f = fixture(r#"{"version":1,"secrets":{"P_CREATE":"env://P"}}"#);
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{
                "B_UP":{"provider":"env","ref":"U","resolve":"up"},
                "B_CREATE":"env://B"}}"#,
        );
        let validated = validate_with(&home, &f).unwrap();
        use SecretOrigin::{Base, Project};
        let at = |t, o| keys(validated.entries_at_from(t, o));
        assert_eq!(at(ResolveTime::Create, Base), ["B_CREATE"]);
        assert_eq!(at(ResolveTime::Create, Project), ["P_CREATE"]);
        assert_eq!(at(ResolveTime::Up, Base), ["B_UP"]);
        assert!(at(ResolveTime::Up, Project).is_empty());
    }

    #[test]
    fn an_override_file_is_project_origin() {
        let f = fixture(r#"{"version":1,"secrets":{"SIDECAR":"env://S"}}"#);
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{"BASE_ONLY":"env://B"}}"#,
        );
        let override_file = f.workspace.join("elsewhere.json");
        fs::write(
            &override_file,
            r#"{"version":1,"secrets":{"FROM_OVERRIDE":"env://O"}}"#,
        )
        .unwrap();

        let validated = validate_secrets_at(
            &home,
            Some(override_file),
            &f.workspace,
            None,
            false,
            &registry(&f.workspace),
        )
        .unwrap();
        let pairs: Vec<(&str, SecretOrigin)> = validated
            .entries_with_origin()
            .map(|(r, o)| (r.key(), o))
            .collect();
        assert_eq!(
            pairs,
            [
                ("BASE_ONLY", SecretOrigin::Base),
                ("FROM_OVERRIDE", SecretOrigin::Project)
            ]
        );
    }

    #[test]
    fn downgrade_moves_base_create_to_up_and_reports_keys() {
        let f = fixture(r#"{"version":1,"secrets":{"C":"env://C"}}"#);
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{"A":"env://A","B":{"provider":"env","ref":"B","resolve":"exec"}}}"#,
        );
        let mut validated = validate_with(&home, &f).unwrap();

        let keys = validated.downgrade_base_create_to_up();

        assert_eq!(keys, ["A"]);
        let time = |k: &str| {
            validated
                .entries()
                .iter()
                .find(|e| e.key() == k)
                .unwrap()
                .resolve_time()
        };
        assert_eq!(time("A"), ResolveTime::Up);
        assert_eq!(time("B"), ResolveTime::Exec);
        assert_eq!(time("C"), ResolveTime::Create);
    }

    #[test]
    fn downgrade_skips_a_project_override_of_a_base_create_key() {
        let f = fixture(
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"env","ref":"T","resolve":"exec"}}}"#,
        );
        let home = with_base(
            &f.workspace,
            r#"{"version":1,"secrets":{"TOKEN":"env://T"}}"#,
        );
        let mut validated = validate_with(&home, &f).unwrap();

        assert!(validated.downgrade_base_create_to_up().is_empty());
        assert_eq!(validated.entries()[0].resolve_time(), ResolveTime::Exec);
    }

    #[test]
    fn only_a_compose_validation_downgrades_base_create_entries() {
        let f = fixture(r#"{"version":1,"secrets":{"C":"env://C"}}"#);
        let home = with_base(&f.workspace, r#"{"version":1,"secrets":{"A":"env://A"}}"#);
        let registry = registry(&f.workspace);
        let validate = |compose| {
            validate_secrets_for_config(
                &home,
                &f.config_path,
                &f.workspace,
                None,
                compose,
                &registry,
            )
            .unwrap()
        };

        let compose = validate(true);
        assert_eq!(compose.downgraded_to_up(), ["A"]);
        let up: Vec<&str> = compose
            .entries_at(ResolveTime::Up)
            .map(|r| r.key())
            .collect();
        assert_eq!(up, ["A"]);
        let create: Vec<&str> = compose
            .entries_at(ResolveTime::Create)
            .map(|r| r.key())
            .collect();
        assert_eq!(create, ["C"]);

        let plain = validate(false);
        assert!(plain.downgraded_to_up().is_empty());
        assert_eq!(plain.entries_at(ResolveTime::Up).count(), 0);
    }
}
