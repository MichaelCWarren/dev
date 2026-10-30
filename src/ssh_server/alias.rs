use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, bail};

use super::read_workspace_record_in;
use crate::caddy::app_name_from_workspace;
use crate::util::paths::DevHome;

fn alias_base(workspace: &Path) -> String {
    let name = app_name_from_workspace(workspace);
    if name.is_empty() {
        "dev-workspace".to_string()
    } else {
        format!("dev-{name}")
    }
}

fn aliases_held_by_others(dev_home: &DevHome, hash: &str) -> HashSet<String> {
    let Ok(entries) = std::fs::read_dir(dev_home.ssh_dir()) else {
        return HashSet::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|other| other != hash)
        .filter_map(|other| read_workspace_record_in(dev_home, &other))
        .map(|record| record.alias)
        .collect()
}

/// A workspace keeps the alias it first got, so a saved T3 environment keeps
/// working. Two first-time `dev up`s of same-named folders at the same
/// instant can both take the short name; that race is not guarded.
pub(super) fn choose_alias_in(dev_home: &DevHome, hash: &str, workspace: &Path) -> String {
    if let Some(record) = read_workspace_record_in(dev_home, hash) {
        return record.alias;
    }
    let taken = aliases_held_by_others(dev_home, hash);
    let base = alias_base(workspace);
    let short = format!("{base}-{}", &hash[..6]);
    [base, short]
        .into_iter()
        .find(|candidate| !taken.contains(candidate))
        .unwrap_or_else(|| format!("{}-{hash}", alias_base(workspace)))
}

/// The path as ssh config text, `%` doubled for ssh's token expansion. A
/// newline would end the config line, so it is refused.
fn path_text(path: &Path) -> Result<String> {
    let text = path.to_string_lossy();
    if text.contains('\n') {
        bail!("path contains a newline: {text:?}");
    }
    Ok(text.replace('%', "%%"))
}

/// Single-quoted for the shell ssh hands the rest of the line to. Double
/// quotes would still expand `$`, backticks and backslashes.
fn quote_for_proxy_command(path: &Path) -> Result<String> {
    Ok(format!("'{}'", path_text(path)?.replace('\'', "'\\''")))
}

/// Double-quoted for ssh's own tokenizer.
fn quote_for_ssh_option(path: &Path) -> Result<String> {
    let escaped = path_text(path)?.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

pub(super) fn validate_user(user: &str) -> Result<()> {
    let valid = !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        bail!("user {user:?} cannot be written into an ssh config");
    }
    Ok(())
}

pub(super) fn render_alias_config(
    alias: &str,
    hash: &str,
    user: &str,
    dev_exe: &Path,
    client_key: &Path,
    known_hosts: &Path,
) -> Result<String> {
    validate_user(user)?;
    let exe = quote_for_proxy_command(dev_exe)?;
    let key = quote_for_ssh_option(client_key)?;
    let hosts = quote_for_ssh_option(known_hosts)?;
    Ok(format!(
        "# Managed by dev (sshServer). dev down --remove deletes it.\n\
         Host {alias}\n  \
         ProxyCommand {exe} ssh-proxy --workspace-hash {hash}\n  \
         User {user}\n  \
         IdentityFile {key}\n  \
         IdentitiesOnly yes\n  \
         IdentityAgent none\n  \
         UserKnownHostsFile {hosts}\n  \
         HostKeyAlias {alias}\n  \
         StrictHostKeyChecking yes\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_folder_name_falls_back() {
        assert_eq!(alias_base(Path::new("/work/___")), "dev-workspace");
        assert_eq!(alias_base(Path::new("/work/My App")), "dev-my-app");
    }

    #[test]
    fn alias_file_matches_contract() {
        let text = render_alias_config(
            "dev-app",
            "0123456789abcdef",
            "vscode",
            Path::new("/usr/local/bin/dev"),
            Path::new("/home/me/.dev/ssh/0123456789abcdef/id_ed25519"),
            Path::new("/home/me/.dev/ssh/known_hosts"),
        )
        .unwrap();

        assert_eq!(
            text,
            "# Managed by dev (sshServer). dev down --remove deletes it.\n\
             Host dev-app\n  \
             ProxyCommand '/usr/local/bin/dev' ssh-proxy --workspace-hash 0123456789abcdef\n  \
             User vscode\n  \
             IdentityFile \"/home/me/.dev/ssh/0123456789abcdef/id_ed25519\"\n  \
             IdentitiesOnly yes\n  \
             IdentityAgent none\n  \
             UserKnownHostsFile \"/home/me/.dev/ssh/known_hosts\"\n  \
             HostKeyAlias dev-app\n  \
             StrictHostKeyChecking yes\n"
        );
    }

    #[test]
    fn render_rejects_bad_user_and_newlines() {
        let render = |user: &str, exe: &str| {
            render_alias_config(
                "dev-app",
                "0123456789abcdef",
                user,
                Path::new(exe),
                Path::new("/k"),
                Path::new("/h"),
            )
        };
        assert!(render("bad user", "/bin/dev").is_err());
        assert!(render("root", "/bin/de\nv").is_err());
        assert!(render("root", "/bin/dev").is_ok());
    }
}
