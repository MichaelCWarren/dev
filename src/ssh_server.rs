//! The feature `dev` carries for `sshServer.enabled`, and the host-side files
//! that give each workspace an ssh alias.
//!
//! The feature is embedded because `dev` installs as a bare binary, so a
//! feature living only in the repository would be a feature nobody has.
//!
//! Layout under `~/.dev/ssh/` (dirs 0700, files 0600, all written by `dev`):
//!
//! - `<hash>/id_ed25519[.pub]`: client key. The public half goes into the
//!   container's `authorized_keys`.
//! - `<hash>/host_ed25519[.pub]`: sshd's host key.
//! - `<hash>/workspace.json`: `{"alias", "workspace", "user", "runtime"}`, read
//!   through [`read_workspace_record_in`]. `user` is the name the alias's `User`
//!   line carries, and sshd must run as that user: a non-root `sshd -i` can only
//!   log in its own user. `runtime` is the one `dev up` ran on, absent from
//!   records written before it was kept.
//! - `known_hosts`: one `<alias> <keytype> <base64>` line per alias.
//! - `config.d/<hash>`: the alias file, exactly
//!
//! ```text
//! # Managed by dev (sshServer). dev down --remove deletes it.
//! Host <alias>
//!   ProxyCommand '<dev exe>' ssh-proxy --workspace-hash <hash>
//!   User <user>
//!   IdentityFile "<client key>"
//!   IdentitiesOnly yes
//!   IdentityAgent none
//!   UserKnownHostsFile "<known_hosts>"
//!   HostKeyAlias <alias>
//!   StrictHostKeyChecking yes
//! ```
//!
//! - `hinted/<hash>`: the one-time T3 hint marker.
//!
//! `remove_alias_in` keeps `workspace.json` and the marker, so the alias name
//! stays stable and the hint is never shown twice.

mod alias;
mod keys;
pub(crate) mod sshd_config;

pub(crate) use keys::public_half;

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::error::DevError;
use crate::util::fs::{remove_if_present, write_private_file};
use crate::util::naming::workspace_hash;
use crate::util::paths::DevHome;

const FEATURE_FILES: [(&str, &str); 2] = [
    (
        "devcontainer-feature.json",
        include_str!("../features/ssh-server/devcontainer-feature.json"),
    ),
    (
        "install.sh",
        include_str!("../features/ssh-server/install.sh"),
    ),
];

/// Where the ssh-server feature installs sshd.
pub(crate) const SSHD_PATH: &str = "/usr/sbin/sshd";

const FEATURE_NAME: &str = "ssh-server";

/// Write the feature out and hand back the path a build can resolve it by.
pub(crate) fn stage_feature_in(home: &DevHome) -> Result<PathBuf, DevError> {
    crate::devcontainer::features::stage_embedded_feature(home, FEATURE_NAME, &FEATURE_FILES)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceRecord {
    pub(crate) alias: String,
    pub(crate) workspace: PathBuf,
    pub(crate) user: String,
    /// With docker and podman both up, auto-detection can land on the one
    /// that does not have the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime: Option<String>,
}

pub(crate) fn read_workspace_record_in(dev_home: &DevHome, hash: &str) -> Option<WorkspaceRecord> {
    let content = std::fs::read_to_string(dev_home.ssh_workspace_record(hash)).ok()?;
    serde_json::from_str(&content).ok()
}

/// The record of a workspace whose alias is in place. `Err` names the first
/// file that is missing or unreadable: the alias file, then the record.
pub(crate) fn registered_alias_in(
    dev_home: &DevHome,
    hash: &str,
) -> Result<WorkspaceRecord, PathBuf> {
    let alias_file = dev_home.ssh_alias_file(hash);
    if !alias_file.exists() {
        return Err(alias_file);
    }
    read_workspace_record_in(dev_home, hash).ok_or_else(|| dev_home.ssh_workspace_record(hash))
}

pub(crate) fn write_workspace_record(
    dev_home: &DevHome,
    hash: &str,
    record: &WorkspaceRecord,
) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(record)?;
    write_private_file(&dev_home.ssh_workspace_record(hash), json.as_bytes())
        .context("writing workspace.json")
}

fn write_alias_file(
    dev_home: &DevHome,
    hash: &str,
    record: &WorkspaceRecord,
    dev_exe: &Path,
) -> anyhow::Result<()> {
    let text = alias::render_alias_config(
        &record.alias,
        hash,
        &record.user,
        dev_exe,
        &dev_home.ssh_client_key(hash),
        &dev_home.ssh_known_hosts(),
    )?;
    keys::ensure_private_dir(&dev_home.ssh_alias_dir())?;
    write_private_file(&dev_home.ssh_alias_file(hash), text.as_bytes())
        .context("writing the alias file")
}

/// The hint is shown once per workspace, ever: the marker outlives a remove.
fn take_hint(dev_home: &DevHome, hash: &str, alias: &str) -> anyhow::Result<Option<String>> {
    let marker = dev_home.ssh_hint_marker(hash);
    if marker.exists() {
        return Ok(None);
    }
    if let Some(dir) = marker.parent() {
        keys::ensure_private_dir(dir)?;
    }
    write_private_file(&marker, b"").context("writing the hint marker")?;
    Ok(Some(format!(
        "T3 Code: add \"{alias}\" under Settings \u{2192} Environments \u{2192} SSH (once per project)"
    )))
}

/// Writes everything the alias needs and hands back the one-time hint.
/// `workspace` must already be canonical: it is recorded as given.
pub(crate) fn register_alias_in(
    dev_home: &DevHome,
    workspace: &Path,
    user: &str,
    runtime: &str,
    dev_exe: &Path,
) -> anyhow::Result<Option<String>> {
    alias::validate_user(user)?;
    let hash = workspace_hash(workspace);
    let record = WorkspaceRecord {
        alias: alias::choose_alias_in(dev_home, &hash, workspace),
        workspace: workspace.to_path_buf(),
        user: user.to_string(),
        runtime: Some(runtime.to_string()),
    };
    keys::ensure_keys_in(dev_home, &hash)?;
    write_workspace_record(dev_home, &hash, &record)?;
    keys::pin_host_key_in(dev_home, &hash, &record.alias)?;
    write_alias_file(dev_home, &hash, &record, dev_exe)?;
    take_hint(dev_home, &hash, &record.alias)
}

/// Removes whatever alias the workspace has, warning rather than failing the
/// command. Creates nothing, so a workspace that never had an alias is left
/// with no `~/.dev/ssh/`.
pub(crate) fn remove_alias_or_warn(dev_home: &DevHome, workspace: &Path) {
    if let Err(e) = remove_alias_in(dev_home, &workspace_hash(workspace)) {
        eprintln!("Warning: ssh alias cleanup failed: {e}");
    }
}

pub(crate) fn remove_alias_in(dev_home: &DevHome, hash: &str) -> anyhow::Result<()> {
    remove_if_present(&dev_home.ssh_alias_file(hash)).context("removing the alias file")?;
    if let Some(record) = read_workspace_record_in(dev_home, hash) {
        keys::unpin_alias_in(dev_home, &record.alias)?;
    }
    keys::remove_keys_in(dev_home, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedded(name: &str) -> &'static str {
        FEATURE_FILES
            .iter()
            .find(|(file, _)| *file == name)
            .map(|(_, contents)| *contents)
            .unwrap_or_else(|| panic!("{name} is not carried in the binary"))
    }

    #[test]
    fn the_binary_carries_the_ssh_server_feature_as_written() {
        for (name, contents) in FEATURE_FILES {
            let on_disk = std::fs::read_to_string(format!("features/ssh-server/{name}"))
                .unwrap_or_else(|e| panic!("reading features/ssh-server/{name}: {e}"));
            assert_eq!(on_disk, contents, "features/ssh-server/{name} drifted");
        }
    }

    #[test]
    fn every_file_in_the_feature_directory_is_carried() {
        for entry in std::fs::read_dir("features/ssh-server").unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            if name == "README.md" {
                continue;
            }
            assert!(
                FEATURE_FILES.iter().any(|(file, _)| *file == name),
                "features/ssh-server/{name} is not embedded"
            );
        }
    }

    #[test]
    fn staging_writes_the_whole_ssh_server_feature_out() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());

        let dir = stage_feature_in(&home).expect("staging writes the feature");

        assert_eq!(dir, tmp.path().join("features/ssh-server"));
        for (name, contents) in FEATURE_FILES {
            assert_eq!(std::fs::read_to_string(dir.join(name)).unwrap(), contents);
        }
    }

    /// No `installsAfter`: `order_features` matches exact resolved ids, so an
    /// entry could never match a project's versioned id.
    #[test]
    fn the_feature_id_is_the_directory_it_is_staged_under() {
        let json: serde_json::Value =
            serde_json::from_str(embedded("devcontainer-feature.json")).unwrap();
        assert_eq!(json["id"], FEATURE_NAME);
        assert!(json.get("installsAfter").is_none());
    }

    #[test]
    fn the_install_script_parses() {
        let status = std::process::Command::new("sh")
            .arg("-n")
            .arg("features/ssh-server/install.sh")
            .status()
            .expect("sh runs");
        assert!(status.success());
    }

    #[test]
    fn the_install_script_leaves_no_key_and_no_service() {
        let install = embedded("install.sh");
        for needle in [
            "/etc/ssh/ssh_host_",
            "sshd_not_to_be_run",
            "1:8.7",
            "/run/sshd",
            "policy-rc.d",
            "/usr/sbin/sshd",
        ] {
            assert!(install.contains(needle), "install.sh lost {needle}");
        }
    }

    use crate::util::process::wait_bounded;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    const SSH: &str = "/usr/bin/ssh";

    /// Temp dirs, each holding a folder named `name`, so the folder names
    /// match while the paths (and hashes) differ. Canonical, as `dev` hands
    /// them over.
    fn same_named_workspaces(name: &str, count: usize) -> (Vec<tempfile::TempDir>, Vec<PathBuf>) {
        let dirs: Vec<_> = (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
        let paths = dirs
            .iter()
            .map(|d| {
                let p = d.path().canonicalize().unwrap().join(name);
                std::fs::create_dir_all(&p).unwrap();
                p
            })
            .collect();
        (dirs, paths)
    }

    /// Registers and hands back the hint.
    fn register(home: &DevHome, workspace: &Path) -> Option<String> {
        register_alias_in(
            home,
            workspace,
            "root",
            "docker",
            Path::new("/usr/local/bin/dev"),
        )
        .unwrap()
    }

    /// Registers and hands back the alias as persisted in `workspace.json`.
    fn register_alias(home: &DevHome, workspace: &Path) -> String {
        register(home, workspace);
        read_workspace_record_in(home, &workspace_hash(workspace))
            .unwrap()
            .alias
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn first_workspace_keeps_the_short_name() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 2);

        let a = register_alias(&home, &ws[0]);
        let b = register_alias(&home, &ws[1]);

        assert_eq!(a, "dev-proj");
        assert_eq!(b, format!("dev-proj-{}", &workspace_hash(&ws[1])[..6]));
    }

    #[test]
    fn alias_is_stable_across_calls() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 2);

        let a = register_alias(&home, &ws[0]);
        let b = register_alias(&home, &ws[1]);

        assert_eq!(register_alias(&home, &ws[0]), a);
        assert_eq!(register_alias(&home, &ws[1]), b);
        assert_eq!(register_alias(&home, &ws[0]), a);
    }

    #[test]
    fn a_recorded_alias_is_kept_even_when_the_short_name_frees_up() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 2);
        register(&home, &ws[0]);
        let b = register_alias(&home, &ws[1]);
        std::fs::remove_file(home.ssh_workspace_record(&workspace_hash(&ws[0]))).unwrap();

        assert_eq!(register_alias(&home, &ws[1]), b);
    }

    #[test]
    fn alias_survives_remove() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 3);
        register(&home, &ws[0]);

        remove_alias_in(&home, &workspace_hash(&ws[0])).unwrap();
        let c = register_alias(&home, &ws[2]);

        assert_ne!(c, "dev-proj");
        assert_eq!(register_alias(&home, &ws[0]), "dev-proj");
    }

    #[test]
    fn empty_folder_name_falls_back_to_dev_workspace() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("___", 1);

        assert_eq!(register_alias(&home, &ws[0]), "dev-workspace");
    }

    #[test]
    fn remove_deletes_keys_alias_file_and_known_hosts_line_only() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 2);
        let a = register_alias(&home, &ws[0]);
        let b = register_alias(&home, &ws[1]);
        let hash = workspace_hash(&ws[0]);

        remove_alias_in(&home, &hash).unwrap();

        assert!(!home.ssh_alias_file(&hash).exists());
        for key in [home.ssh_client_key(&hash), home.ssh_host_key(&hash)] {
            assert!(!key.exists());
            assert!(!public_half(&key).exists());
        }
        let known = std::fs::read_to_string(home.ssh_known_hosts()).unwrap();
        assert!(!known.lines().any(|l| l.starts_with(&format!("{a} "))));
        assert!(known.lines().any(|l| l.starts_with(&format!("{b} "))));
        assert!(home.ssh_workspace_record(&hash).exists());
        assert!(home.ssh_hint_marker(&hash).exists());
        remove_alias_in(&home, &hash).expect("a second remove is fine");
    }

    #[test]
    fn a_registered_alias_needs_both_the_alias_file_and_the_record() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 1);
        let hash = workspace_hash(&ws[0]);
        assert_eq!(
            registered_alias_in(&home, &hash).unwrap_err(),
            home.ssh_alias_file(&hash)
        );

        register(&home, &ws[0]);
        assert_eq!(registered_alias_in(&home, &hash).unwrap().alias, "dev-proj");

        remove_alias_in(&home, &hash).unwrap();
        assert_eq!(
            registered_alias_in(&home, &hash).unwrap_err(),
            home.ssh_alias_file(&hash)
        );

        register(&home, &ws[0]);
        std::fs::remove_file(home.ssh_workspace_record(&hash)).unwrap();
        assert_eq!(
            registered_alias_in(&home, &hash).unwrap_err(),
            home.ssh_workspace_record(&hash)
        );
    }

    #[test]
    fn removing_an_alias_removes_it_and_never_creates_the_ssh_dir() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 1);

        remove_alias_or_warn(&home, &ws[0]);
        assert!(!home.ssh_dir().exists());

        register(&home, &ws[0]);
        remove_alias_or_warn(&home, &ws[0]);
        assert!(!home.ssh_alias_file(&workspace_hash(&ws[0])).exists());
    }

    #[test]
    fn hint_is_returned_once_and_survives_remove() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 1);

        let first = register(&home, &ws[0]);
        assert_eq!(
            first.as_deref(),
            Some(
                "T3 Code: add \"dev-proj\" under Settings \u{2192} Environments \u{2192} SSH (once per project)"
            )
        );
        assert!(register(&home, &ws[0]).is_none());
        remove_alias_in(&home, &workspace_hash(&ws[0])).unwrap();
        assert!(register(&home, &ws[0]).is_none());
    }

    #[test]
    fn register_writes_the_alias_file_and_record_privately() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 1);
        let hash = workspace_hash(&ws[0]);

        register_alias_in(
            &home,
            &ws[0],
            "vscode",
            "podman",
            Path::new("/usr/local/bin/dev"),
        )
        .unwrap();

        let expected = alias::render_alias_config(
            "dev-proj",
            &hash,
            "vscode",
            Path::new("/usr/local/bin/dev"),
            &home.ssh_client_key(&hash),
            &home.ssh_known_hosts(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(home.ssh_alias_file(&hash)).unwrap(),
            expected
        );
        assert_eq!(mode(&home.ssh_alias_file(&hash)), 0o600);
        assert_eq!(mode(&home.ssh_workspace_record(&hash)), 0o600);
        let record = read_workspace_record_in(&home, &hash).unwrap();
        assert_eq!(record.workspace, ws[0]);
        assert_eq!(record.user, "vscode");
        assert_eq!(record.runtime.as_deref(), Some("podman"));
    }

    #[test]
    fn a_record_written_before_the_runtime_was_kept_still_reads() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let hash = "0123456789abcdef";
        std::fs::create_dir_all(home.ssh_workspace_dir(hash)).unwrap();
        std::fs::write(
            home.ssh_workspace_record(hash),
            r#"{"alias":"dev-proj","workspace":"/ws","user":"root"}"#,
        )
        .unwrap();

        let record = read_workspace_record_in(&home, hash).unwrap();

        assert_eq!(record.alias, "dev-proj");
        assert_eq!(record.runtime, None);
    }

    #[test]
    fn register_rejects_a_bad_user_before_writing_anything() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = DevHome::at(home_dir.path());
        let (_keep, ws) = same_named_workspaces("proj", 1);

        assert!(register_alias_in(&home, &ws[0], "a b", "docker", Path::new("/bin/dev")).is_err());
        assert!(!home.ssh_dir().exists());
    }

    #[test]
    fn ssh_parses_the_alias_paths() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("dev home");
        let home = DevHome::at(&root);
        let (_keep, ws) = same_named_workspaces("proj", 1);
        let hash = workspace_hash(&ws[0]);
        register_alias_in(
            &home,
            &ws[0],
            "vscode",
            "docker",
            Path::new("/usr/local/bin/dev"),
        )
        .unwrap();

        let out = std::process::Command::new(SSH)
            .arg("-G")
            .arg("-F")
            .arg(home.ssh_alias_file(&hash))
            .arg("dev-proj")
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();

        let has = |line: String| assert!(text.lines().any(|l| l == line), "{line}\n{text}");
        has("user vscode".to_string());
        has(format!(
            "identityfile {}",
            home.ssh_client_key(&hash).display()
        ));
        has(format!(
            "userknownhostsfile {}",
            home.ssh_known_hosts().display()
        ));
        has("hostkeyalias dev-proj".to_string());
        has("identitiesonly yes".to_string());
        has("stricthostkeychecking true".to_string());
    }

    #[test]
    fn proxy_command_runs_a_path_with_space_quote_and_percent() {
        let base = tempfile::tempdir().unwrap();
        let bin_dir = base.path().join("it's 100% dev");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let exe = bin_dir.join("dev bin");
        let argv_file = base.path().join("argv");
        std::fs::write(
            &exe,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n",
                argv_file.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = DevHome::at(base.path().join("home"));
        let (_keep, ws) = same_named_workspaces("proj", 1);
        let hash = workspace_hash(&ws[0]);
        register_alias_in(&home, &ws[0], "root", "docker", &exe).unwrap();

        let mut child = std::process::Command::new(SSH)
            .arg("-F")
            .arg(home.ssh_alias_file(&hash))
            .args(["-o", "BatchMode=yes", "dev-proj", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let status = wait_bounded(
            &mut child,
            Duration::from_secs(10),
            Duration::from_millis(20),
        );
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }

        assert!(status.is_some(), "ssh did not exit");
        assert_eq!(
            std::fs::read_to_string(&argv_file).unwrap().trim(),
            format!("ssh-proxy --workspace-hash {hash}")
        );
    }
}
