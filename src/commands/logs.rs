use std::path::Path;

use tokio::io::AsyncWriteExt;

use crate::devcontainer::DevcontainerConfig;
use crate::devcontainer::compose::load_workspace_config_or_warn;
use crate::devcontainer::hooklog::hook_log_path;
use crate::runtime::{ContainerRuntime, detect_runtime};
use crate::util::paths::DevHome;
use crate::util::{container_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    hooks_only: bool,
    follow: bool,
    tail: Option<u32>,
) -> anyhow::Result<()> {
    let mut out = tokio::io::stdout();
    print_hook_log(&DevHome::current(), workspace, &mut out).await?;
    if hooks_only {
        return Ok(());
    }

    let runtime = detect_runtime(runtime_override).await?;

    if let Some((config_path, config)) =
        load_workspace_config_or_warn(workspace, runtime.runtime_name())
        && config.is_compose()
    {
        return run_compose_logs(
            workspace,
            &config,
            &config_path,
            runtime.runtime_name(),
            follow,
            tail,
        )
        .await;
    }

    container_logs_with_runtime(workspace, &*runtime, follow, tail, &mut out).await
}

/// Replay the persisted lifecycle-hook log, or say why there is none.
///
/// This is the post-mortem path after a failed `dev up`, so it must work with
/// no runtime running — it is a pure file read.
async fn print_hook_log(
    dev_home: &DevHome,
    workspace: &Path,
    out: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> anyhow::Result<()> {
    let path = hook_log_path(dev_home, workspace);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            out.write_all(format!("=== lifecycle hooks ({}) ===\n", path.display()).as_bytes())
                .await?;
            out.write_all(content.as_bytes()).await?;
            let prev = path.with_file_name("hooks.prev.log");
            if prev.exists() {
                out.write_all(format!("(previous run kept at {})\n", prev.display()).as_bytes())
                    .await?;
            }
        }
        Err(_) => {
            out.write_all(b"No lifecycle hook log for this workspace yet; `dev up` records one.\n")
                .await?;
        }
    }
    Ok(())
}

/// Print each workspace container's log stream, newest container order as the
/// runtime lists them, each under its own banner.
async fn container_logs_with_runtime(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    follow: bool,
    tail: Option<u32>,
    out: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> anyhow::Result<()> {
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let containers = runtime.list_containers(&filters).await?;

    if containers.is_empty() {
        out.write_all(b"No containers found for this workspace. Run `dev up` first.\n")
            .await?;
        return Ok(());
    }

    for c in &containers {
        out.write_all(format!("=== container {} ({:?}) ===\n", c.name, c.state).as_bytes())
            .await?;
        let mut reader = runtime.container_logs(&c.id, follow, tail).await?;
        tokio::io::copy(&mut reader, out).await?;
    }
    out.flush().await?;
    Ok(())
}

/// Compose projects log through `compose logs`, which knows every service —
/// only the primary service carries the devcontainer labels.
async fn run_compose_logs(
    workspace: &Path,
    config: &DevcontainerConfig,
    config_path: &Path,
    runtime_name: &str,
    follow: bool,
    tail: Option<u32>,
) -> anyhow::Result<()> {
    let compose_data = config.docker_compose_file.as_ref().unwrap();
    let compose_files = compose_data.files();
    let devcontainer_dir = config_path.parent().unwrap();
    let project_name = container_name(workspace);

    crate::runtime::compose::compose_logs(
        runtime_name,
        &compose_files,
        devcontainer_dir,
        &project_name,
        follow,
        tail,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::hooklog::HookLog;
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerState, ExecResult,
        ImageMetadata,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("not used by this test".into())) })
    }

    /// A runtime that serves canned containers and canned per-container logs,
    /// and records whether anything listed containers at all.
    struct LogsFakeRuntime {
        containers: Vec<ContainerInfo>,
        logs: HashMap<String, String>,
        listed: Arc<Mutex<bool>>,
    }

    impl LogsFakeRuntime {
        fn new(containers: Vec<(&str, &str)>) -> Self {
            Self {
                containers: containers
                    .iter()
                    .map(|(id, name)| ContainerInfo {
                        id: id.to_string(),
                        name: name.to_string(),
                        state: ContainerState::Running,
                        labels: HashMap::new(),
                        image: "ubuntu:24.04".to_string(),
                    })
                    .collect(),
                logs: HashMap::new(),
                listed: Arc::new(Mutex::new(false)),
            }
        }

        fn with_log(mut self, id: &str, content: &str) -> Self {
            self.logs.insert(id.to_string(), content.to_string());
            self
        }
    }

    impl ContainerRuntime for LogsFakeRuntime {
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
            _env: &[(String, crate::devcontainer::secrets::SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            unused()
        }
        fn exec_interactive(
            &self,
            _id: &str,
            _cmd: &[String],
            _user: Option<&str>,
            _workdir: Option<&str>,
            _env: &[(String, crate::devcontainer::secrets::SecretValue)],
        ) -> BoxFut<'_, i32> {
            unused()
        }
        fn inspect_container(&self, _id: &str) -> BoxFut<'_, ContainerInfo> {
            unused()
        }
        fn list_containers(&self, _label_filters: &[String]) -> BoxFut<'_, Vec<ContainerInfo>> {
            *self.listed.lock().unwrap() = true;
            let containers = self.containers.clone();
            Box::pin(async move { Ok(containers) })
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
        fn container_logs(
            &self,
            id: &str,
            _follow: bool,
            _tail: Option<u32>,
        ) -> BoxFut<'_, Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
            let content = self.logs.get(id).cloned().unwrap_or_default();
            Box::pin(async move {
                Ok(Box::new(std::io::Cursor::new(content.into_bytes()))
                    as Box<dyn tokio::io::AsyncRead + Send + Unpin>)
            })
        }
    }

    #[tokio::test]
    async fn hook_log_is_printed_before_container_logs() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        let log = HookLog::begin(&dev_home, workspace.path(), "create").unwrap();
        log.record(
            "postCreateCommand",
            "npm install",
            &ExecResult {
                exit_code: 0,
                stdout: "added 12 packages\n".to_string(),
                stderr: String::new(),
            },
        );
        drop(log);

        let rt =
            LogsFakeRuntime::new(vec![("c1", "vsc-proj")]).with_log("c1", "container says hi\n");
        let mut out: Vec<u8> = Vec::new();
        print_hook_log(&dev_home, workspace.path(), &mut out)
            .await
            .unwrap();
        container_logs_with_runtime(workspace.path(), &rt, false, None, &mut out)
            .await
            .unwrap();

        let output = String::from_utf8(out).unwrap();
        let hooks_at = output.find("npm install").expect("hook output present");
        let container_at = output
            .find("container says hi")
            .expect("container log present");
        assert!(
            hooks_at < container_at,
            "hook log replays before container logs: {output}"
        );
    }

    #[tokio::test]
    async fn missing_hook_log_prints_hint_instead_of_failing() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();

        let mut out: Vec<u8> = Vec::new();
        print_hook_log(&DevHome::at(home.path()), workspace.path(), &mut out)
            .await
            .unwrap();

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("No lifecycle hook log"), "got: {output}");
    }

    #[tokio::test]
    async fn each_container_gets_a_banner() {
        let workspace = TempDir::new().unwrap();
        let rt = LogsFakeRuntime::new(vec![("c1", "vsc-app"), ("c2", "vsc-db")])
            .with_log("c1", "app log\n")
            .with_log("c2", "db log\n");

        let mut out: Vec<u8> = Vec::new();
        container_logs_with_runtime(workspace.path(), &rt, false, None, &mut out)
            .await
            .unwrap();

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("=== container vsc-app (Running) ==="));
        assert!(output.contains("app log"));
        assert!(output.contains("=== container vsc-db (Running) ==="));
        assert!(output.contains("db log"));
    }

    #[tokio::test]
    async fn no_containers_prints_guidance_not_an_error() {
        let workspace = TempDir::new().unwrap();
        let rt = LogsFakeRuntime::new(vec![]);

        let mut out: Vec<u8> = Vec::new();
        container_logs_with_runtime(workspace.path(), &rt, false, None, &mut out)
            .await
            .unwrap();

        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Run `dev up` first"),
            "an empty workspace is guidance, not a failure"
        );
    }
}
