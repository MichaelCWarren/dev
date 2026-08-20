//! Find the `secrets.json` that governs a container.
//!
//! One rule covers every scope: the file sits beside the config that governs
//! the container, so the path is `config_path.parent().join("secrets.json")`.
//! For a recipe that parent is the recipe directory, which is also the parent of
//! the virtual `devcontainer.json` composition names, so discovery never has to
//! compose anything. A missing file is not an error; it means the project
//! declares no secrets.
//!
//! A `secrets.json` in a recipe directory survives `prepare_recipe_directory_in`
//! because planning walks only the template's source tree
//! (`plan_auxiliary_files`, `compose.rs:420`) and the write phase only creates
//! and writes planned files (`compose.rs:387-393`) — there is no deletion pass
//! and no destination enumeration. That holds only while no global template
//! ships its own `.devcontainer/secrets.json`. If one ever does, the file
//! becomes an ordinary auxiliary file: substituted, written, recorded in the
//! manifest, and subject to the "already exists" refusal on refresh.

use std::path::{Path, PathBuf};

use super::file::{self, SecretsFile};
use crate::error::DevError;
use crate::util::paths::DevHome;
use crate::util::workspace::{ConfigSource, find_config_source_in};

const SECRETS_FILE_NAME: &str = "secrets.json";

/// The `secrets.json` beside a config, if it exists.
#[allow(dead_code)]
pub fn secrets_path_beside(config_path: &Path) -> Option<PathBuf> {
    let path = config_path.parent()?.join(SECRETS_FILE_NAME);
    path.is_file().then_some(path)
}

/// Discover the `secrets.json` governing a workspace.
#[allow(dead_code)]
pub fn find_secrets_file(workspace: &Path) -> Result<Option<PathBuf>, DevError> {
    find_secrets_file_in(&DevHome::current(), workspace)
}

/// [`find_secrets_file`] against an explicit `~/.dev/` layout, so the user-scope
/// lookup stays inside an injected home rather than the real one.
#[allow(dead_code)]
pub fn find_secrets_file_in(
    dev_home: &DevHome,
    workspace: &Path,
) -> Result<Option<PathBuf>, DevError> {
    match find_config_source_in(dev_home, workspace) {
        Ok(ConfigSource::Direct(path) | ConfigSource::Recipe(path)) => {
            Ok(secrets_path_beside(&path))
        }
        Err(DevError::NoConfig(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The references file for this invocation: the explicit `--secrets` path when
/// given, otherwise whatever sits beside the config.
///
/// Replacement, never a merge, so exactly one references file is read per
/// `dev up` and there is no precedence order between two reference sources to
/// reason about. An explicitly named path must exist; a missing sidecar stays
/// what it has always been, which is simply no secrets.
///
/// The override is a `dev up` flag only. `dev exec` and `dev shell` rediscover
/// the sidecar per invocation, so a container created with `dev up --secrets`
/// in a repo with no sidecar gets create-time secrets and no exec-time refresh,
/// and in a repo *with* a sidecar gets exec-time values from a different file
/// than it was created with.
#[allow(dead_code)]
pub fn secrets_file_path(
    secrets_override: Option<&Path>,
    config_path: &Path,
) -> Result<Option<PathBuf>, DevError> {
    secrets_file_path_in(&DevHome::current(), secrets_override, config_path)
}

/// [`secrets_file_path`] against an explicit `~/.dev/` layout. The explicit-path
/// branch never touches `dev_home`.
pub fn secrets_file_path_in(
    _dev_home: &DevHome,
    secrets_override: Option<&Path>,
    config_path: &Path,
) -> Result<Option<PathBuf>, DevError> {
    let Some(path) = secrets_override else {
        return Ok(secrets_path_beside(config_path));
    };
    if !path.is_file() {
        return Err(DevError::InvalidConfig(format!(
            "`--secrets {}`: no such file",
            path.display()
        )));
    }
    Ok(Some(path.to_path_buf()))
}

/// Discover and parse the `secrets.json` governing a workspace.
#[allow(dead_code)]
pub fn load_secrets_in(
    dev_home: &DevHome,
    workspace: &Path,
) -> Result<Option<SecretsFile>, DevError> {
    find_secrets_file_in(dev_home, workspace)?
        .map(|path| file::load(&path))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::Recipe;
    use crate::devcontainer::compose::{AuxPolicy, prepare_recipe_directory_in};
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use tempfile::TempDir;

    const DOC: &str = r#"{"version":1,"secrets":{"LINEAR_API_KEY":"env://LINEAR_API_KEY"}}"#;

    /// A temp `~/.dev/` root with a workspace inside it, so a test that reaches
    /// the user scope still cannot escape the temp tree.
    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        workspace: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let workspace = root.join("projects/demo");
        fs::create_dir_all(&workspace).unwrap();
        Fixture {
            _dir: dir,
            root,
            workspace,
        }
    }

    impl Fixture {
        fn dev_home(&self) -> DevHome {
            DevHome::at(&self.root)
        }

        fn write(&self, relative: &str, content: &str) -> PathBuf {
            let path = self.workspace.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            path
        }

        fn write_user_scoped(&self, relative: &str, content: &str) -> PathBuf {
            let path = self
                .root
                .join("devcontainers/demo/.devcontainer")
                .join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            path
        }

        fn find(&self) -> Result<Option<PathBuf>, DevError> {
            find_secrets_file_in(&self.dev_home(), &self.workspace)
        }
    }

    #[test]
    fn finds_secrets_beside_a_workspace_devcontainer_json() {
        let env = fixture();
        env.write(".devcontainer/devcontainer.json", "{}");
        let secrets = env.write(".devcontainer/secrets.json", DOC);
        assert_eq!(env.find().unwrap(), Some(secrets));
    }

    #[test]
    fn finds_secrets_beside_a_workspace_recipe() {
        let env = fixture();
        env.write(".devcontainer/recipe.json", r#"{"globalTemplate":"rust"}"#);
        let secrets = env.write(".devcontainer/secrets.json", DOC);
        assert_eq!(env.find().unwrap(), Some(secrets));
    }

    #[test]
    fn finds_secrets_beside_a_user_scope_recipe() {
        let env = fixture();
        env.write_user_scoped("recipe.json", r#"{"globalTemplate":"rust"}"#);
        let secrets = env.write_user_scoped("secrets.json", DOC);

        let found = env.find().unwrap().unwrap();
        assert_eq!(found, secrets);
        assert!(
            found.starts_with(&env.root),
            "escaped the temp root: {found:?}"
        );
        assert!(!env.workspace.join(".devcontainer").exists());
    }

    #[test]
    fn a_missing_secrets_file_is_not_an_error() {
        let env = fixture();
        env.write(".devcontainer/devcontainer.json", "{}");
        assert_eq!(env.find().unwrap(), None);
    }

    #[test]
    fn a_directory_named_secrets_json_is_not_a_hit() {
        let env = fixture();
        env.write(".devcontainer/devcontainer.json", "{}");
        fs::create_dir(env.workspace.join(".devcontainer/secrets.json")).unwrap();
        assert_eq!(env.find().unwrap(), None);
    }

    #[test]
    fn a_workspace_with_no_config_yields_no_secrets() {
        assert_eq!(fixture().find().unwrap(), None);
    }

    #[test]
    fn a_config_error_other_than_no_config_propagates() {
        let env = fixture();
        env.write(".devcontainer/recipe.json", r#"{"globalTemplate":"rust"}"#);
        env.write(".devcontainer/devcontainer.json", "{}");
        let e = env.find().unwrap_err();
        assert!(matches!(e, DevError::InvalidConfig(_)), "{e:?}");
    }

    #[test]
    fn a_root_level_devcontainer_json_puts_secrets_at_the_workspace_root() {
        let env = fixture();
        env.write(".devcontainer.json", "{}");
        let secrets = env.write("secrets.json", DOC);
        assert_eq!(env.find().unwrap(), Some(secrets));
    }

    #[test]
    fn a_config_path_with_no_parent_yields_none() {
        assert_eq!(secrets_path_beside(Path::new("")), None);
    }

    #[test]
    fn load_secrets_parses_the_discovered_file() {
        let env = fixture();
        env.write(".devcontainer/devcontainer.json", "{}");
        env.write(".devcontainer/secrets.json", DOC);

        let loaded = load_secrets_in(&env.dev_home(), &env.workspace)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.secrets.len(), 1);
        assert!(
            load_secrets_in(&env.dev_home(), &env.root.join("projects/none"))
                .unwrap()
                .is_none()
        );
    }

    /// The whole point of the flag: a sidecar that exists is not consulted.
    #[test]
    fn secrets_file_path_prefers_explicit_override() {
        let env = fixture();
        let config = env.write(".devcontainer/devcontainer.json", "{}");
        let sidecar = env.write(".devcontainer/secrets.json", DOC);
        let explicit = env.write("elsewhere/other.json", DOC);
        assert_eq!(
            secrets_file_path_in(&env.dev_home(), Some(&explicit), &config).unwrap(),
            Some(explicit.clone())
        );
        assert!(sidecar.is_file(), "the sidecar is there and still ignored");
    }

    #[test]
    fn secrets_file_path_missing_explicit_errors() {
        let env = fixture();
        let config = env.write(".devcontainer/devcontainer.json", "{}");
        let explicit = env.workspace.join("never-created.json");
        let e = secrets_file_path_in(&env.dev_home(), Some(&explicit), &config).unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("never-created.json"), "{msg}");
        assert!(msg.contains("--secrets"), "{msg}");
    }

    /// `is_file()` is the test, so a directory fails the same way a missing
    /// path does.
    #[test]
    fn secrets_file_path_explicit_directory_errors() {
        let env = fixture();
        let config = env.write(".devcontainer/devcontainer.json", "{}");
        let explicit = env.workspace.join("a-directory");
        fs::create_dir_all(&explicit).unwrap();
        let e = secrets_file_path_in(&env.dev_home(), Some(&explicit), &config).unwrap_err();
        assert!(format!("{e}").contains("a-directory"), "{e}");
    }

    #[test]
    fn secrets_file_path_falls_back_to_sidecar() {
        let env = fixture();
        let config = env.write(".devcontainer/devcontainer.json", "{}");
        let sidecar = env.write(".devcontainer/secrets.json", DOC);
        assert_eq!(
            secrets_file_path_in(&env.dev_home(), None, &config).unwrap(),
            Some(sidecar)
        );
    }

    #[test]
    fn secrets_file_path_absent_sidecar_is_none() {
        let env = fixture();
        let config = env.write(".devcontainer/devcontainer.json", "{}");
        assert_eq!(
            secrets_file_path_in(&env.dev_home(), None, &config).unwrap(),
            None
        );
    }

    #[test]
    fn a_recipe_secrets_file_survives_prepare_recipe_directory() {
        let env = fixture();
        let template = env.root.join("global/test-lang/.devcontainer");
        fs::create_dir_all(&template).unwrap();
        fs::write(template.join("devcontainer.json"), r#"{"image":"rust"}"#).unwrap();
        fs::write(template.join("Dockerfile"), "FROM rust:latest\n").unwrap();

        let recipe_dir = env.workspace.join(".devcontainer");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::write(recipe_dir.join("secrets.json"), DOC).unwrap();

        let recipe = Recipe {
            global_template: "test-lang".to_string(),
            features: Vec::new(),
            options: HashMap::new(),
            customizations: serde_json::json!({}),
            generated: BTreeMap::new(),
        };
        let manifest = prepare_recipe_directory_in(
            &env.dev_home(),
            &recipe,
            &recipe_dir,
            AuxPolicy::Refresh { previous: None },
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(recipe_dir.join("Dockerfile")).unwrap(),
            "FROM rust:latest\n",
            "the call did no work, so the test proves nothing"
        );
        assert_eq!(
            fs::read_to_string(recipe_dir.join("secrets.json")).unwrap(),
            DOC
        );
        assert!(!manifest.contains_key("secrets.json"), "{manifest:?}");
    }
}
