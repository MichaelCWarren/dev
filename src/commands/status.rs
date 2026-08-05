use std::path::Path;

use crate::runtime::{ContainerInfo, ContainerRuntime, ContainerState, detect_runtime};
use crate::session::{self, SessionMarker};
use crate::util::{find_config_source, workspace_labels};

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
                    "sessions": sessions.iter().map(session_json).collect::<Vec<_>>(),
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

/// Read each running container's recorded sessions.
///
/// Informational, so a container that cannot be read contributes nothing rather
/// than failing the status the user asked for.
async fn collect_sessions(
    runtime: &dyn ContainerRuntime,
    containers: &[ContainerInfo],
) -> Vec<Vec<(SessionMarker, bool)>> {
    let mut per_container = Vec::with_capacity(containers.len());
    for container in containers {
        let sessions = if container.state == ContainerState::Running {
            session::list_sessions(runtime, &container.id, None)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        per_container.push(sessions);
    }
    per_container
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
fn print_sessions(containers: &[ContainerInfo], sessions: &[Vec<(SessionMarker, bool)>]) {
    let total: usize = sessions.iter().map(Vec::len).sum();
    if total == 0 {
        return;
    }
    println!();
    println!("{:<30} {:<10} {:<10} STATE", "CONTAINER", "SESSION", "TTY");
    for (container, sessions) in containers.iter().zip(sessions) {
        for (marker, live) in sessions {
            println!(
                "{:<30} {:<10} {:<10} {}",
                container.name,
                format!("{:?}", marker.kind).to_lowercase(),
                marker.host_tty,
                if *live { "live" } else { "orphaned" },
            );
        }
    }
    if sessions.iter().flatten().any(|(_, live)| !live) {
        println!("\nOrphaned sessions are reaped by the next `dev shell`.");
    }
}
