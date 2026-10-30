use std::os::unix::process::CommandExt;
use std::path::Path;

use anyhow::bail;

use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::devcontainer::config::DevcontainerConfig;
use crate::runtime::detect_runtime;
use crate::ssh_server::{WorkspaceRecord, registered_alias_in};
use crate::util::naming::workspace_hash;
use crate::util::paths::DevHome;

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    cmd: &[String],
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    let config = load_workspace_config_or_warn(workspace, runtime.runtime_name()).map(|(_, c)| c);
    let dev_home = DevHome::current();
    let registered = registered_alias_in(&dev_home, &workspace_hash(workspace)).ok();
    let alias = ssh_target(config.as_ref(), registered, workspace)?;

    // exec, so ssh owns the tty, signals and exit status with no relay between.
    let error = std::process::Command::new("ssh")
        .args(ssh_args(&alias, cmd))
        .exec();
    bail!("could not run ssh: {error}")
}

fn ssh_target(
    config: Option<&DevcontainerConfig>,
    registered: Option<WorkspaceRecord>,
    workspace: &Path,
) -> anyhow::Result<String> {
    if !config.is_some_and(|c| c.ssh_server_enabled()) {
        bail!(
            "sshServer is not enabled for this workspace. Set sshServer.enabled to true \
             (here or in your base config), then run dev up --rebuild."
        );
    }
    match registered {
        Some(record) => Ok(record.alias),
        None => bail!(
            "No ssh alias for this workspace yet. Run dev up in {} first.",
            workspace.display()
        ),
    }
}

/// The `--` keeps a command like `-v` from being read as one of ssh's options.
fn ssh_args(alias: &str, cmd: &[String]) -> Vec<String> {
    let mut args = vec![alias.to_string()];
    if !cmd.is_empty() {
        args.push("--".to_string());
        args.extend_from_slice(cmd);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::jsonc::parse_jsonc;
    use std::path::PathBuf;

    fn config(json: &str) -> DevcontainerConfig {
        parse_jsonc(json).expect("json should parse")
    }

    fn record() -> WorkspaceRecord {
        WorkspaceRecord {
            alias: "dev-proj".to_string(),
            workspace: PathBuf::from("/work/proj"),
            user: "node".to_string(),
            runtime: None,
        }
    }

    #[test]
    fn ssh_target_explains_why_it_cannot_connect() {
        let workspace = Path::new("/work/proj");
        let enabled = config(r#"{"sshServer": {"enabled": true}}"#);
        let disabled = config(r#"{"image": "alpine"}"#);

        for config in [Some(&disabled), None] {
            let err = ssh_target(config, Some(record()), workspace).unwrap_err();
            assert!(err.to_string().contains("sshServer is not enabled"));
        }
        let message = ssh_target(Some(&enabled), None, workspace)
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("Run dev up in /work/proj first"),
            "{message}"
        );
        let alias = ssh_target(Some(&enabled), Some(record()), workspace).unwrap();
        assert_eq!(alias, "dev-proj");
    }

    #[test]
    fn a_remote_command_is_kept_out_of_sshs_options() {
        let cmd = vec!["-v".to_string(), "x".to_string()];
        assert_eq!(ssh_args("dev-proj", &cmd), ["dev-proj", "--", "-v", "x"]);
        assert_eq!(ssh_args("dev-proj", &[]), ["dev-proj"]);
    }
}
