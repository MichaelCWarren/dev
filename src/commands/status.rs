use std::path::Path;

use crate::cmux::{Cmux, SESSION_PILL_STYLE, SHELL_KEY};
use crate::commands::shell::{SessionPill, session_pill_action};
use crate::devcontainer::compose::load_workspace_config;
use crate::runtime::{ContainerInfo, ContainerRuntime, ContainerState, detect_runtime};
use crate::session::{self, SessionMarker};
use crate::util::{find_config_source, workspace_folder_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    // Check for devcontainer config (informational only)
    if find_config_source(workspace).is_err() && !json {
        eprintln!(
            "No devcontainer configuration found in {}",
            workspace.display()
        );
    }

    let runtime = detect_runtime(runtime_override).await?;
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let containers = runtime.list_containers(&filters).await?;

    let sessions = collect_sessions(runtime.as_ref(), &containers).await;
    repaint_session_pill(workspace, runtime.as_ref(), &containers, &sessions).await;

    if json {
        let items: Vec<serde_json::Value> = containers
            .iter()
            .zip(&sessions)
            .map(|(c, sessions)| {
                serde_json::json!({
                    "id": c.id,
                    "name": c.name,
                    "state": format!("{:?}", c.state),
                    "image": c.image,
                    "sessions": listed(sessions).iter().map(session_json).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else if containers.is_empty() {
        println!("No containers running for this workspace.");
        println!("Use `dev up` to start a container for this workspace.");
    } else {
        println!("{:<30} {:<12} IMAGE", "NAME", "STATE");
        for c in &containers {
            println!(
                "{:<30} {:<12} {}",
                c.name,
                format!("{:?}", c.state),
                c.image
            );
        }
        print_sessions(&containers, &sessions);
    }

    Ok(())
}

/// One container's recorded sessions, or `None` for a read that failed.
type ContainerSessions = Option<Vec<(SessionMarker, bool)>>;

/// Read each running container's recorded sessions.
///
/// Informational, so a container that cannot be read contributes nothing to
/// the printed status rather than failing the status the user asked for. The
/// failure is still carried, because to the pill it is not the same as zero
/// live shells. A container that is not running has none to read.
async fn collect_sessions(
    runtime: &dyn ContainerRuntime,
    containers: &[ContainerInfo],
) -> Vec<ContainerSessions> {
    let mut per_container = Vec::with_capacity(containers.len());
    for container in containers {
        let sessions = if container.state == ContainerState::Running {
            session::list_sessions(runtime, &container.id, None)
                .await
                .ok()
        } else {
            Some(Vec::new())
        };
        per_container.push(sessions);
    }
    per_container
}

/// What to print for one container. A read that failed shows nothing, the
/// same as a container with no sessions.
fn listed(sessions: &ContainerSessions) -> &[(SessionMarker, bool)] {
    sessions.as_deref().unwrap_or(&[])
}

/// The read the pill decides from: the running container's session list, or,
/// when this workspace has no running container, evidence of zero live
/// shells. `None` is a read that failed.
fn pill_evidence<'a>(
    containers: &[ContainerInfo],
    sessions: &'a [ContainerSessions],
) -> Option<&'a [(SessionMarker, bool)]> {
    match containers
        .iter()
        .zip(sessions)
        .find(|(c, _)| c.state == ContainerState::Running)
    {
        Some((_, sessions)) => sessions.as_deref(),
        None => Some(&[]),
    }
}

/// Correct a stale session pill without opening a shell.
///
/// `dev shell`'s own guard clears cleanly on a typed `exit`, but a `kill -9`
/// leaves the pill up with nothing left to clear it; this is the other place
/// that reads the live session list and can notice. It holds no guard: the
/// decision below is the whole of what `dev status` does to the pill, and
/// exiting is not by itself a reason to take a live shell's pill down. The
/// config gate goes first because a config that does not load is the cheapest
/// answer of all; either way `dev status` prints nothing new, including on a
/// broken config.
async fn repaint_session_pill(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    containers: &[ContainerInfo],
    sessions: &[ContainerSessions],
) {
    let Ok((_, config)) = load_workspace_config(workspace, runtime.runtime_name()) else {
        return;
    };
    let cmux = Cmux::detect(config.cmux_status_enabled());
    if !cmux.available() {
        return;
    }
    match session_pill_action(
        pill_evidence(containers, sessions),
        std::process::id(),
        false,
        &workspace_folder_name(workspace),
        runtime.runtime_name(),
    ) {
        SessionPill::Show(value) => cmux.set_status(SHELL_KEY, &value, SESSION_PILL_STYLE),
        SessionPill::Clear => cmux.clear_status(SHELL_KEY),
        SessionPill::Leave => return,
    }
    // Nothing here holds a guard whose drop would do this, and the worker
    // dies with the process.
    cmux.flush().await;
}

fn session_json(entry: &(SessionMarker, bool)) -> serde_json::Value {
    let (marker, live) = entry;
    serde_json::json!({
        "kind": format!("{:?}", marker.kind).to_lowercase(),
        "containerPid": marker.container_pid,
        "hostPid": marker.host_pid,
        "hostTty": marker.host_tty,
        "live": live,
    })
}

/// Show which sessions belong to a client that is still around.
///
/// Told apart by the client's terminal, because from inside the container every
/// session looks the same — identical command, identical state, no way to know
/// which one the user is sitting in front of.
fn print_sessions(containers: &[ContainerInfo], sessions: &[ContainerSessions]) {
    let total: usize = sessions.iter().map(|sessions| listed(sessions).len()).sum();
    if total == 0 {
        return;
    }
    println!();
    println!("{:<30} {:<10} {:<10} STATE", "CONTAINER", "SESSION", "TTY");
    for (container, sessions) in containers.iter().zip(sessions) {
        for (marker, live) in listed(sessions) {
            println!(
                "{:<30} {:<10} {:<10} {}",
                container.name,
                format!("{:?}", marker.kind).to_lowercase(),
                marker.host_tty,
                if *live { "live" } else { "orphaned" },
            );
        }
    }
    if sessions.iter().flat_map(listed).any(|(_, live)| !live) {
        println!("\nOrphaned sessions are reaped by the next `dev shell`.");
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainerSessions, collect_sessions, pill_evidence};
    use crate::commands::shell::{SessionPill, session_pill_action};
    use crate::devcontainer::secrets::SecretValue;
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ContainerState,
        ExecResult, ImageMetadata,
    };
    use std::collections::HashMap;
    use std::path::Path;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("unused fake runtime method".into())) })
    }

    /// A runtime whose only interesting answer is what a session read gets:
    /// either the recorded markers or a failure.
    struct StatusFakeRuntime {
        reply: Option<String>,
    }

    impl StatusFakeRuntime {
        fn answering(reply: &str) -> Self {
            Self {
                reply: Some(reply.to_string()),
            }
        }

        fn failing() -> Self {
            Self { reply: None }
        }
    }

    impl ContainerRuntime for StatusFakeRuntime {
        fn runtime_name(&self) -> &'static str {
            "fake"
        }
        fn pull_image(&self, _image: &str) -> BoxFut<'_, ()> {
            unused()
        }
        fn build_image(
            &self,
            _dockerfile: &str,
            _context: &Path,
            _tag: &str,
            _build_args: &HashMap<String, String>,
            _no_cache: bool,
            _verbose: bool,
        ) -> BoxFut<'_, ()> {
            unused()
        }
        fn create_container(&self, _config: &ContainerConfig) -> BoxFut<'_, String> {
            unused()
        }
        fn start_container(&self, _id: &str) -> BoxFut<'_, ()> {
            unused()
        }
        fn stop_container(&self, _id: &str) -> BoxFut<'_, ()> {
            unused()
        }
        fn remove_container(&self, _id: &str) -> BoxFut<'_, ()> {
            unused()
        }
        fn exec(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
            _workdir: Option<&str>,
            _env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            let Some(stdout) = self.reply.clone() else {
                return Box::pin(async { Err(DevError::Runtime("session read failed".into())) });
            };
            Box::pin(async move {
                Ok(ExecResult {
                    exit_code: 0,
                    stdout,
                    stderr: String::new(),
                })
            })
        }
        fn exec_interactive(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
            _workdir: Option<&str>,
            _env: &[(String, SecretValue)],
        ) -> BoxFut<'_, i32> {
            unused()
        }
        fn inspect_container(&self, _id: &str) -> BoxFut<'_, ContainerInfo> {
            unused()
        }
        fn list_containers(&self, _label_filters: &[String]) -> BoxFut<'_, Vec<ContainerInfo>> {
            unused()
        }
        fn image_exists(&self, _image: &str) -> BoxFut<'_, bool> {
            unused()
        }
        fn inspect_image_metadata(&self, _image: &str) -> BoxFut<'_, ImageMetadata> {
            unused()
        }
        fn exec_attached(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
        ) -> BoxFut<'_, AttachedExec> {
            unused()
        }
    }

    fn container(state: ContainerState) -> ContainerInfo {
        ContainerInfo {
            id: "container-id".to_string(),
            name: "container".to_string(),
            state,
            labels: HashMap::new(),
            image: "ubuntu:24.04".to_string(),
        }
    }

    /// A `dev status` that could not read a container is not a `dev status`
    /// that found no shells: pass the failure on, or the pill decides zero
    /// from it and a live `dev shell` loses its pill to an unrelated command.
    #[tokio::test]
    async fn a_session_read_that_failed_is_carried_as_a_failure() {
        let containers = vec![container(ContainerState::Running)];
        let sessions = collect_sessions(&StatusFakeRuntime::failing(), &containers).await;

        assert!(sessions[0].is_none(), "{sessions:?}");
        assert!(matches!(
            session_pill_action(
                pill_evidence(&containers, &sessions),
                std::process::id(),
                false,
                "myproject",
                "fake",
            ),
            SessionPill::Leave
        ));
    }

    #[tokio::test]
    async fn a_session_read_that_answered_is_carried_as_a_list() {
        let containers = vec![container(ContainerState::Running)];
        let marker = format!("720 720 {} - shell ttys001", std::process::id());
        let sessions = collect_sessions(&StatusFakeRuntime::answering(&marker), &containers).await;

        assert_eq!(sessions[0].as_deref().map(<[_]>::len), Some(1));
    }

    /// A container that is not running has no sessions to read, and nothing
    /// was asked of the runtime to find that out.
    #[tokio::test]
    async fn a_stopped_container_reads_as_no_sessions() {
        let containers = vec![container(ContainerState::Stopped)];
        let sessions = collect_sessions(&StatusFakeRuntime::failing(), &containers).await;

        assert_eq!(sessions[0].as_deref(), Some(&[][..]));
    }

    /// `kill -9` a shell, then `dev down`: the pill is stranded and there is
    /// no running container left to count. That is still evidence of zero
    /// shells, and the next `dev status` is the only thing left to act on it.
    #[test]
    fn no_running_container_is_evidence_of_zero_shells() {
        for containers in [vec![], vec![container(ContainerState::Stopped)]] {
            let sessions: Vec<ContainerSessions> =
                containers.iter().map(|_| Some(Vec::new())).collect();
            assert!(
                matches!(
                    session_pill_action(
                        pill_evidence(&containers, &sessions),
                        std::process::id(),
                        false,
                        "myproject",
                        "fake",
                    ),
                    SessionPill::Clear
                ),
                "{containers:?}"
            );
        }
    }
}
