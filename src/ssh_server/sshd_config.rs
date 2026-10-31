//! What a `dev ssh-proxy` session hands to `sshd -i`: the env it carries, the
//! config that carries it, and the directory both live in.

use crate::devcontainer::secrets::SecretValue;
use crate::util::token::mint_token;

/// Names sshd sets itself, per session, from the logged-in user's passwd entry
/// or from the connection. `SetEnv` is applied after them and overrides them,
/// and the container env holds the create-time user's values: often root's
/// `HOME` and a stale `TERM`. Passing them would point the session at the
/// wrong home and terminal and hide the connection info tools read.
const SESSION_OWNED: [&str; 12] = [
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "MAIL",
    "TERM",
    "DISPLAY",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "SSH_TTY",
    "SSH_ORIGINAL_COMMAND",
    "SSH_USER_AUTH",
];

const SESSION_DIR_PREFIX: &str = "/dev/shm/dev-sshd-";

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Why a variable cannot go into a session's `SetEnv`, if it cannot.
fn refusal(name: &str, value: &str) -> Option<&'static str> {
    if SESSION_OWNED.contains(&name) {
        Some("sshd sets it for each session")
    } else if !is_valid_name(name) {
        Some("its name is not a valid variable name")
    } else if setenv_token(name, value).is_none() {
        Some("its value contains a line break or NUL")
    } else {
        None
    }
}

/// The env an ssh session gets: the container's, with each secret overriding
/// a container value of the same name, as in a `dev exec`. `secrets` holds the
/// `up` and `exec` values; `create` values arrive through `container_env`.
/// Warnings name the key only, never the value.
pub(crate) fn session_env(
    container_env: &[(String, String)],
    secrets: &[(String, SecretValue)],
) -> (Vec<(String, SecretValue)>, Vec<String>) {
    let mut merged: Vec<(String, SecretValue, bool)> = container_env
        .iter()
        .map(|(name, value)| (name.clone(), SecretValue::new(value.clone()), false))
        .collect();
    for (name, value) in secrets {
        let entry = (name.clone(), SecretValue::new(value.expose()), true);
        match merged.iter_mut().find(|(n, _, _)| n == name) {
            Some(slot) => *slot = entry,
            None => merged.push(entry),
        }
    }

    let mut env = Vec::new();
    let mut warnings = Vec::new();
    for (name, value, from_secret) in merged {
        match refusal(&name, value.expose()) {
            None => env.push((name, value)),
            // The skip list is routine for a container env; only a secret
            // the user asked for by name is worth reporting.
            Some(_) if !from_secret && SESSION_OWNED.contains(&name.as_str()) => {}
            Some(why) => warnings.push(format!(
                "dev ssh-proxy: {name} not passed to ssh sessions: {why}"
            )),
        }
    }
    (env, warnings)
}

/// One `SetEnv` token, or `None` for a value sshd's line-based config cannot
/// carry. Only `\` and `"` need escaping inside one double-quoted token.
pub(crate) fn setenv_token(name: &str, value: &str) -> Option<String> {
    if value.contains(['\n', '\r', '\0']) {
        return None;
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Some(format!("\"{name}={escaped}\""))
}

/// The sshd config text. A `SecretValue` so the secrets in it can never be
/// printed through `Debug` or `Display`.
pub(crate) fn render_sshd_config(dir: &str, env: &[(String, SecretValue)]) -> SecretValue {
    let mut lines = vec![
        format!("HostKey {dir}/ssh_host_ed25519_key"),
        format!("AuthorizedKeysFile {dir}/authorized_keys"),
        "PubkeyAuthentication yes".to_string(),
        // /dev/shm is 1777 and sshd checks every parent directory.
        "StrictModes no".to_string(),
        "UsePAM no".to_string(),
        "PasswordAuthentication no".to_string(),
        "KbdInteractiveAuthentication no".to_string(),
        "PidFile none".to_string(),
        "AllowTcpForwarding local".to_string(),
        "X11Forwarding no".to_string(),
        // -f replaces /etc/ssh/sshd_config, so sftp must be named again.
        "Subsystem sftp internal-sftp".to_string(),
        // With -e, INFO lines would print in the user's terminal on every connect.
        "LogLevel ERROR".to_string(),
    ];
    let tokens: Vec<String> = env
        .iter()
        .filter_map(|(name, value)| setenv_token(name, value.expose()))
        .collect();
    // sshd keeps only the first SetEnv directive.
    if !tokens.is_empty() {
        lines.push(format!("SetEnv {}", tokens.join(" ")));
    }
    SecretValue::new(lines.join("\n") + "\n")
}

/// A random directory under `/dev/shm`, so two connections never share one
/// and a `mkdir` without `-p` fails on a planted path.
pub(crate) fn session_dir_name() -> Option<String> {
    let token = mint_token()?;
    Some(format!("{SESSION_DIR_PREFIX}{}", &token[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tokenizer OpenSSH 8.7+ applies to each sshd_config line
    /// (`argv_split` with `terminate_on_comment`, misc.c).
    fn argv_split(line: &str) -> Vec<String> {
        let chars: Vec<char> = line.chars().collect();
        let mut tokens = Vec::new();
        let mut i = 0;
        loop {
            while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                i += 1;
            }
            if i >= chars.len() || chars[i] == '#' {
                return tokens;
            }
            let mut token = String::new();
            let mut quote: Option<char> = None;
            while i < chars.len() {
                let c = chars[i];
                let next = chars.get(i + 1).copied();
                match (c, quote, next) {
                    ('\\', _, Some(n @ ('\\' | '"' | '\''))) => {
                        token.push(n);
                        i += 1;
                    }
                    ('\\', None, Some(' ')) => {
                        token.push(' ');
                        i += 1;
                    }
                    ('"' | '\'', None, _) => quote = Some(c),
                    (q, Some(open), _) if q == open => quote = None,
                    (' ' | '\t', None, _) => break,
                    _ => token.push(c),
                }
                i += 1;
            }
            tokens.push(token);
        }
    }

    fn secret(name: &str, value: &str) -> (String, SecretValue) {
        (name.to_string(), SecretValue::new(value))
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn setenv_round_trips_through_sshds_tokenizer() {
        for value in [
            "plain",
            "a b",
            "tab\there",
            "say \"hi\"",
            "it's",
            "back\\slash",
            "trailing\\",
            "#hash",
            "$HOME %u",
            "",
        ] {
            let token = setenv_token("K", value).expect("expressible");
            assert_eq!(
                argv_split(&token),
                vec![format!("K={value}")],
                "token {token}"
            );
        }
    }

    #[test]
    fn values_sshd_cannot_express_are_refused() {
        for value in ["a\nb", "a\rb", "a\0b"] {
            assert_eq!(setenv_token("K", value), None, "{value:?}");
        }
    }

    #[test]
    fn session_env_skips_identity_keys_and_lets_secrets_win() {
        let container = [
            pair("HOME", "/root"),
            pair("USER", "root"),
            pair("TERM", "dumb"),
            pair("PATH", "/usr/bin"),
        ];
        let (env, warnings) = session_env(&container, &[secret("PATH", "/x")]);
        let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["PATH"]);
        assert_eq!(env[0].1.expose(), "/x");
        assert!(warnings.is_empty(), "{warnings:?}");

        let (_, warnings) = session_env(&[], &[secret("HOME", "/h")]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("HOME"));

        let (env, warnings) = session_env(&[], &[secret("FOO", "line1\nhunter2")]);
        assert!(env.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("FOO"));
        assert!(!warnings[0].contains("hunter2"));

        let (env, warnings) = session_env(&[pair("BAD-NAME", "v")], &[]);
        assert!(env.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("BAD-NAME"));
    }

    #[test]
    fn session_env_merges_up_and_exec_values_over_the_container_env() {
        let container = [pair("PATH", "/usr/bin"), pair("TOKEN", "stale")];
        let secrets = [secret("TOKEN", "up-value"), secret("E", "exec-value")];

        let (env, warnings) = session_env(&container, &secrets);

        let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["PATH", "TOKEN", "E"]);
        assert_eq!(env[1].1.expose(), "up-value");
        assert_eq!(env[2].1.expose(), "exec-value");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn the_sshd_config_carries_the_decided_options_once() {
        let env = [secret("TOKEN", "hunter2"), secret("PATH", "/x")];
        let rendered = render_sshd_config("/dev/shm/d", &env);
        let text = rendered.expose();
        let lines: Vec<&str> = text.lines().collect();
        for option in [
            "HostKey /dev/shm/d/ssh_host_ed25519_key",
            "AuthorizedKeysFile /dev/shm/d/authorized_keys",
            "PubkeyAuthentication yes",
            "StrictModes no",
            "UsePAM no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PidFile none",
            "AllowTcpForwarding local",
            "X11Forwarding no",
            "Subsystem sftp internal-sftp",
            "LogLevel ERROR",
        ] {
            assert_eq!(
                lines.iter().filter(|l| **l == option).count(),
                1,
                "{option}"
            );
        }
        let setenv: Vec<&&str> = lines.iter().filter(|l| l.starts_with("SetEnv ")).collect();
        assert_eq!(setenv.len(), 1);
        assert_eq!(
            argv_split(setenv[0]),
            ["SetEnv", "TOKEN=hunter2", "PATH=/x"]
        );
        assert!(!format!("{rendered:?}").contains("hunter2"));

        let empty = render_sshd_config("/dev/shm/d", &[]);
        assert!(!empty.expose().contains("SetEnv"));
    }
}
