//! The `usher.enabled` key, which adds usher's devcontainer feature to the build.
//!
//! Unlike `dev`'s own features, this one is not embedded. `usherd install` writes it to
//! `~/.usher/feature`, so it always matches the usher client the container mounts.

use std::path::PathBuf;

use crate::devcontainer::config::DevcontainerConfig;
use crate::error::DevError;
use crate::util::paths::DevHome;

/// The feature directory to build with, or `None` when the key is off.
///
/// A missing feature is an error rather than a skipped layer: a container that
/// silently came up without usher would run every job unqueued. `dev up` calls this
/// before any side effect so the error lands first.
pub(crate) fn feature_dir_in(
    config: &DevcontainerConfig,
    home: &DevHome,
) -> Result<Option<PathBuf>, DevError> {
    if !config.usher_enabled() {
        return Ok(None);
    }
    let dir = home.usher_feature_dir();
    if !dir.join("devcontainer-feature.json").is_file() {
        return Err(DevError::FeatureNotFound(format!(
            "usher.enabled is on, but there is no usher feature at {}. \
             Install usher with: usherd install --client <path-to-usher-linux-arm64>",
            dir.display()
        )));
    }
    Ok(Some(dir))
}

#[cfg(test)]
pub(crate) fn write_test_feature(home: &DevHome) -> PathBuf {
    let dir = home.usher_feature_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("devcontainer-feature.json"), r#"{"id": "usher"}"#).unwrap();
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> DevcontainerConfig {
        crate::devcontainer::jsonc::parse_jsonc(json).unwrap()
    }

    const ON: &str = r#"{"usher": {"enabled": true}}"#;

    #[test]
    fn on_with_the_feature_installed_names_its_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let dir = write_test_feature(&home);

        assert_eq!(feature_dir_in(&config(ON), &home).unwrap(), Some(dir));
    }

    #[test]
    fn on_without_the_feature_says_how_to_install_it() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        std::fs::create_dir_all(home.usher_feature_dir()).unwrap();

        let error = feature_dir_in(&config(ON), &home).unwrap_err().to_string();

        assert!(error.contains("usher.enabled is on"), "{error}");
        assert!(
            error.contains(&home.usher_feature_dir().display().to_string()),
            "{error}"
        );
        assert!(error.contains("usherd install --client"), "{error}");
    }

    #[test]
    fn off_never_looks_for_the_feature() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        for json in [r#"{}"#, r#"{"usher": {"enabled": false}}"#] {
            assert_eq!(
                feature_dir_in(&config(json), &home).unwrap(),
                None,
                "{json}"
            );
        }
    }
}
