use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::util::fs::{LockWait, lock_file, remove_if_present, write_private_file};
use crate::util::paths::DevHome;

const SSH_KEYGEN: &str = "ssh-keygen";

pub(crate) fn public_half(private: &Path) -> PathBuf {
    let mut name = private.as_os_str().to_os_string();
    name.push(".pub");
    PathBuf::from(name)
}

fn key_paths(dev_home: &DevHome, hash: &str) -> [PathBuf; 2] {
    [dev_home.ssh_client_key(hash), dev_home.ssh_host_key(hash)]
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

/// Created and chmodded every time, so a directory the umask made 0755 is
/// repaired rather than trusted.
pub(super) fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    set_mode(path, 0o700)
}

fn generate_key(private: &Path, hash: &str) -> Result<()> {
    let output = Command::new(SSH_KEYGEN)
        .args(["-q", "-t", "ed25519", "-N", "", "-C"])
        .arg(format!("dev:{hash}"))
        .arg("-f")
        .arg(private)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {SSH_KEYGEN}"))?;
    if !output.status.success() {
        bail!(
            "{SSH_KEYGEN} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Both halves of a pair or neither: ssh-keygen prompts before overwriting,
/// and with no stdin that prompt is a failure.
fn ensure_key_pair(private: &Path, hash: &str) -> Result<()> {
    let public = public_half(private);
    if private.exists() && public.exists() {
        return Ok(());
    }
    remove_if_present(private)?;
    remove_if_present(&public)?;
    generate_key(private, hash)
}

pub(crate) fn ensure_keys_in(dev_home: &DevHome, hash: &str) -> Result<()> {
    ensure_private_dir(&dev_home.ssh_dir())?;
    ensure_private_dir(&dev_home.ssh_workspace_dir(hash))?;
    for private in key_paths(dev_home, hash) {
        ensure_key_pair(&private, hash)?;
        set_mode(&private, 0o600)?;
        set_mode(&public_half(&private), 0o600)?;
    }
    Ok(())
}

pub(crate) fn remove_keys_in(dev_home: &DevHome, hash: &str) -> Result<()> {
    for private in key_paths(dev_home, hash) {
        remove_if_present(&public_half(&private))?;
        remove_if_present(&private)?;
    }
    Ok(())
}

/// Two `dev up`s in different workspaces rewrite the same file; without the
/// lock one of them loses its line. Released when the file drops.
fn lock_known_hosts(dev_home: &DevHome) -> Result<File> {
    ensure_private_dir(&dev_home.ssh_dir())?;
    let path = dev_home.ssh_known_hosts_lock();
    lock_file(&path, LockWait::Block)?.with_context(|| format!("locking {}", path.display()))
}

fn first_field(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

fn read_known_hosts(dev_home: &DevHome) -> Result<String> {
    match std::fs::read_to_string(dev_home.ssh_known_hosts()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        other => other.context("reading known_hosts"),
    }
}

fn without_alias(existing: &str, alias: &str) -> String {
    existing
        .lines()
        .filter(|line| first_field(line) != alias)
        .map(|line| format!("{line}\n"))
        .collect()
}

fn write_known_hosts(dev_home: &DevHome, content: &str) -> Result<()> {
    write_private_file(&dev_home.ssh_known_hosts(), content.as_bytes())
        .context("writing known_hosts")
}

fn host_key_line(dev_home: &DevHome, hash: &str, alias: &str) -> Result<String> {
    let path = public_half(&dev_home.ssh_host_key(hash));
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut fields = content.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(kind), Some(key)) => Ok(format!("{alias} {kind} {key}")),
        _ => bail!("{} is not a public key", path.display()),
    }
}

/// Drops `alias`'s line and appends `line` in its place, if one is given.
fn rewrite_known_hosts(dev_home: &DevHome, alias: &str, line: Option<&str>) -> Result<()> {
    let _lock = lock_known_hosts(dev_home)?;
    let existing = read_known_hosts(dev_home)?;
    let mut updated = without_alias(&existing, alias);
    if let Some(line) = line {
        updated.push_str(line);
        updated.push('\n');
    }
    if updated != existing {
        write_known_hosts(dev_home, &updated)?;
    }
    Ok(())
}

pub(crate) fn pin_host_key_in(dev_home: &DevHome, hash: &str, alias: &str) -> Result<()> {
    let line = host_key_line(dev_home, hash, alias)?;
    rewrite_known_hosts(dev_home, alias, Some(&line))
}

/// Never creates `~/.dev/ssh/` just to remove a line from nothing.
pub(crate) fn unpin_alias_in(dev_home: &DevHome, alias: &str) -> Result<()> {
    if !dev_home.ssh_known_hosts().exists() {
        return Ok(());
    }
    rewrite_known_hosts(dev_home, alias, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef";

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn key_files(home: &DevHome) -> Vec<PathBuf> {
        key_paths(home, HASH)
            .into_iter()
            .flat_map(|private| [public_half(&private), private])
            .collect()
    }

    #[test]
    fn ensure_keys_sets_private_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());

        ensure_keys_in(&home, HASH).unwrap();

        assert_eq!(mode(&home.ssh_dir()), 0o700);
        assert_eq!(mode(&home.ssh_workspace_dir(HASH)), 0o700);
        for file in key_files(&home) {
            assert_eq!(mode(&file), 0o600, "{}", file.display());
        }
    }

    #[test]
    fn ensure_keys_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        ensure_keys_in(&home, HASH).unwrap();
        let before: Vec<_> = key_paths(&home, HASH)
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();

        ensure_keys_in(&home, HASH).unwrap();

        let after: Vec<_> = key_paths(&home, HASH)
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        assert_eq!(before, after);
    }

    fn derived_public_fields(private: &Path) -> String {
        let out = Command::new(SSH_KEYGEN)
            .arg("-y")
            .arg("-f")
            .arg(private)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn ensure_keys_regenerates_a_half_missing_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        ensure_keys_in(&home, HASH).unwrap();
        let host = home.ssh_host_key(HASH);
        std::fs::remove_file(public_half(&host)).unwrap();

        ensure_keys_in(&home, HASH).unwrap();

        let public = std::fs::read_to_string(public_half(&host)).unwrap();
        let fields = public.split_whitespace().take(2).collect::<Vec<_>>();
        assert_eq!(fields.join(" "), derived_public_fields(&host));
    }

    #[test]
    fn unpin_removes_only_that_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        std::fs::create_dir_all(home.ssh_dir()).unwrap();
        std::fs::write(
            home.ssh_known_hosts(),
            "dev-app ssh-ed25519 AAAA1\ndev-app-1a2b3c ssh-ed25519 AAAA2\ngithub.com ssh-ed25519 AAAA3\n",
        )
        .unwrap();

        unpin_alias_in(&home, "dev-app").unwrap();

        assert_eq!(
            std::fs::read_to_string(home.ssh_known_hosts()).unwrap(),
            "dev-app-1a2b3c ssh-ed25519 AAAA2\ngithub.com ssh-ed25519 AAAA3\n"
        );
    }

    #[test]
    fn unpin_with_no_known_hosts_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());

        unpin_alias_in(&home, "dev-app").unwrap();

        assert!(!home.ssh_dir().exists());
    }

    #[test]
    fn pin_replaces_rather_than_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        ensure_keys_in(&home, HASH).unwrap();

        pin_host_key_in(&home, HASH, "dev-app").unwrap();
        pin_host_key_in(&home, HASH, "dev-app").unwrap();
        remove_keys_in(&home, HASH).unwrap();
        ensure_keys_in(&home, HASH).unwrap();
        pin_host_key_in(&home, HASH, "dev-app").unwrap();

        let known = std::fs::read_to_string(home.ssh_known_hosts()).unwrap();
        let lines: Vec<_> = known.lines().collect();
        assert_eq!(lines.len(), 1, "{known}");
        let expected = format!(
            "dev-app {}",
            derived_public_fields(&home.ssh_host_key(HASH))
        );
        assert_eq!(lines[0], expected);
    }
}
