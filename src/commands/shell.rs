use std::path::Path;

use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::runtime::{ContainerRuntime, ContainerState, detect_runtime, resolve_remote_user};
use crate::session::{self, HostIdentity, SessionKind};
use crate::util::{workspace_folder_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    shell: Option<&str>,
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let containers = runtime.list_containers(&filters).await?;

    let container = containers
        .iter()
        .find(|c| c.state == ContainerState::Running)
        .ok_or_else(|| {
            anyhow::anyhow!("No running container found for this workspace. Run `dev up` first.")
        })?;

    // Resolve remoteUser and workspaceFolder from config or image metadata
    let config =
        load_workspace_config_or_warn(workspace, runtime.runtime_name()).map(|(_, config)| config);
    let config_user = config.as_ref().and_then(|c| c.remote_user.clone());
    let user =
        resolve_remote_user(runtime.as_ref(), &container.image, config_user.as_deref()).await?;

    let shell_cmd = if let Some(s) = shell {
        s.to_string()
    } else {
        // Probe for available shells
        let candidates = ["/bin/zsh", "/bin/bash", "/bin/sh"];
        let mut found = None;
        for candidate in &candidates {
            let probe = vec!["test".to_string(), "-x".to_string(), candidate.to_string()];
            let result = runtime
                .exec(&container.id, &probe, user.as_deref(), None)
                .await?;
            if result.exit_code == 0 {
                found = Some(candidate.to_string());
                break;
            }
        }
        found.unwrap_or_else(|| "/bin/sh".to_string())
    };

    // Resolve workspaceFolder the same way `dev up` does, so the shell starts
    // where lifecycle hooks ran.
    let workdir = match config.as_ref() {
        Some(config) => config.workspace_folder_path(workspace, user.as_deref())?,
        None => format!("/workspaces/{}", workspace_folder_name(workspace)),
    };

    // Before starting one more, collect the sessions whose clients are gone:
    // this is the moment the user is about to look at the container anyway, and
    // an orphaned `claude` burns a core until something ends it.
    match session::sweep(runtime.as_ref(), &container.id, user.as_deref()).await {
        Ok(0) => {}
        Ok(reaped) => eprintln!("dev: reaped {reaped} orphaned container session(s)"),
        Err(e) => eprintln!("Warning: could not check for orphaned sessions: {e}"),
    }

    let host = session::host_identity().await;
    let cmd = session_command(&shell_cmd, &workdir, &host);
    let exit_code = attend_session(
        runtime.as_ref(),
        &container.id,
        &cmd,
        user.as_deref(),
        &workdir,
        host.pid,
    )
    .await?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// The command the container runs for an interactive session.
///
/// It records the session before entering the workspace so that a client dying
/// early still leaves something to collect, and `exec`s the login shell so the
/// user's shell is the process, not a child of a wrapper.
fn session_command(shell_cmd: &str, workdir: &str, host: &HostIdentity) -> Vec<String> {
    let quoted_workdir = single_quoted(workdir);
    let quoted_shell = single_quoted(shell_cmd);
    let register = session::register_script(SessionKind::Shell, host);
    vec![
        shell_cmd.to_string(),
        "-c".to_string(),
        format!(
            "{register}cd {quoted_workdir} || \
             {{ printf 'dev: could not enter %s\\n' {quoted_workdir} >&2; exit 1; }}; \
             exec {quoted_shell} -l"
        ),
    ]
}

/// Run the session, and end it if this process is told to go away first.
///
/// An exec carries no disconnect: were `dev` to exit on a signal without saying
/// anything, the daemon would keep the pty open and the container's shell —
/// with whatever it is running — would survive with nothing left to read it.
/// Dropping the interactive future restores the terminal, and the container
/// side is then hung up explicitly.
///
/// The Podman runtime replaces this process with `podman exec`, so none of this
/// runs there; its orphans are collected by the sweep instead.
async fn attend_session(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    cmd: &[String],
    user: Option<&str>,
    workdir: &str,
    host_pid: u32,
) -> anyhow::Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};

    let watch = |kind: SignalKind, name: &str| {
        signal(kind).map_err(|e| anyhow::anyhow!("watch {name}: {e}"))
    };
    let mut hangup = watch(SignalKind::hangup(), "SIGHUP")?;
    let mut terminate = watch(SignalKind::terminate(), "SIGTERM")?;
    let mut interrupt = watch(SignalKind::interrupt(), "SIGINT")?;

    let mut exec = runtime.exec_interactive(container_id, cmd, user, Some(workdir));
    let signalled = tokio::select! {
        // A session that ended on its own has nothing left to hang up, and its
        // record is cleared by the next read of this container.
        exited = &mut exec => return Ok(exited?),
        // Closing the terminal is the common case, and the one that leaves no
        // other trace: the tty's foreground group is hung up, `dev` included.
        _ = hangup.recv() => libc::SIGHUP,
        _ = terminate.recv() => libc::SIGTERM,
        // A raw terminal delivers Ctrl-C to the container as a byte, so this is
        // only ever an explicit signal — which must still end the session.
        _ = interrupt.recv() => libc::SIGINT,
    };

    drop(exec);
    session::release_own_sessions(runtime, container_id, user, host_pid).await;
    // The status a shell reports for a signalled process.
    Ok(128 + signalled)
}

/// Wrap a value the caller supplied so the guest's shell reads it as one word.
///
/// Both values interpolated into the `-c` script come from outside this
/// process: the working directory is resolved from `workspaceFolder` or from
/// the `target=` segment of `workspaceMount`, and the shell can be named
/// outright with `--shell`. A path holding a space would otherwise be split
/// (`cd /workspaces/My Projects/repo` enters `/workspaces/My`), and one holding
/// `;` or a backtick would run as a command. Single quotes suppress every
/// expansion the shell performs, so only the quote itself needs escaping — by
/// closing the run, emitting a literal quote, and reopening.
fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::{HostIdentity, session_command, single_quoted};

    fn host() -> HostIdentity {
        HostIdentity {
            pid: 4131,
            start: "Tue Aug  5 08:56:01 2026".to_string(),
            tty: "ttys016".to_string(),
        }
    }

    /// A session that dies before it is recorded is a session nothing can
    /// collect, so the record is written before anything that can fail — the
    /// `cd` included.
    #[test]
    fn a_session_records_itself_before_it_can_fail() {
        let script = &session_command("/bin/zsh", "/workspaces/repo", &host())[2];
        let recorded = script.find("/tmp/.dev-session-").expect("marker written");
        let entered = script
            .find("cd '/workspaces/repo'")
            .expect("workdir entered");
        assert!(recorded < entered);
        assert!(script.ends_with("exec '/bin/zsh' -l"));
    }

    /// Registration prefixes the same script the workdir is interpolated into,
    /// so it must not become a way around the quoting.
    #[test]
    fn registration_does_not_loosen_the_workdir_quoting() {
        let script = &session_command("/bin/zsh", "/tmp; rm -rf /", &host())[2];
        assert!(script.contains("cd '/tmp; rm -rf /'"));
    }

    #[test]
    fn a_quoted_value_survives_the_guest_shell_as_one_word() {
        assert_eq!(single_quoted("/workspaces/repo"), "'/workspaces/repo'");
        assert_eq!(
            single_quoted("/workspaces/My Projects/repo"),
            "'/workspaces/My Projects/repo'"
        );
    }

    /// The shell script this builds is the only place a `workspaceFolder` or a
    /// `--shell` value reaches a command line, so metacharacters must arrive as
    /// text rather than as syntax.
    #[test]
    fn quoting_leaves_no_metacharacter_live() {
        for hostile in [
            "/tmp; rm -rf /",
            "/tmp && whoami",
            "/tmp`id`",
            "/tmp$(id)",
            "/tmp\nid",
            "/tmp|id",
        ] {
            let quoted = single_quoted(hostile);
            assert_eq!(quoted, format!("'{hostile}'"));
        }

        // A quote of its own is the one character single quotes cannot carry,
        // so the run is closed, the quote emitted literally, and the run
        // reopened — never leaving the quoted state.
        assert_eq!(single_quoted("/tmp/it's"), r"'/tmp/it'\''s'");
        assert_eq!(single_quoted("';id;'"), r"''\'';id;'\'''");
    }
}
