use std::collections::HashSet;
use std::path::Path;

use crate::devcontainer::Recipe;
use crate::devcontainer::compose::compose_recipe_config_in;
use crate::devcontainer::config::DevcontainerConfig;
use crate::devcontainer::effective::{effective_config_from_parts, load_effective_config_value};
use crate::devcontainer::features::feature_image_tag;
use crate::devcontainer::resolve_features;
use crate::runtime::{ContainerRuntime, detect_runtime};
use crate::util::paths::DevHome;
use crate::util::workspace::find_config_source_in;
use crate::util::{ConfigSource, container_name, workspace_labels};

pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    if runtime.runtime_name() == "apple" {
        anyhow::bail!("Image pruning is not yet supported for Apple Containers");
    }
    run_with_runtime(workspace, &*runtime, &DevHome::current(), dry_run).await
}

/// Remove this workspace's superseded derived feature images.
///
/// The keep set is the safety core: the current image family, resolved exactly
/// the way `dev up`/`dev build` resolve it (with and without the base layer,
/// since a `--no-base` user has a live image under that digest), plus every
/// image an existing container still references. Anything under the
/// workspace's `-features-` tag prefix outside that set is superseded.
pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    dev_home: &DevHome,
    dry_run: bool,
) -> anyhow::Result<()> {
    let folder_image = container_name(workspace);
    let keep = keep_set(workspace, runtime, dev_home, &folder_image).await?;

    let prefix = format!("{folder_image}-features-");
    let stale: Vec<String> = runtime
        .list_images()
        .await?
        .into_iter()
        .flat_map(|image| image.repo_tags)
        .filter(|tag| tag.starts_with(&prefix) && !keep.contains(tag))
        .collect();

    if stale.is_empty() {
        println!("No superseded feature images for this workspace.");
        return Ok(());
    }

    if dry_run {
        for tag in &stale {
            println!("would remove {tag}");
        }
        let mut kept: Vec<&String> = keep.iter().filter(|t| t.starts_with(&prefix)).collect();
        kept.sort();
        for tag in kept {
            println!("keeping {tag} (current)");
        }
        return Ok(());
    }

    let mut failures: Vec<String> = Vec::new();
    for tag in &stale {
        // No force: an in-use conflict is the daemon's report to surface, and
        // one failure must not abort the rest of the sweep.
        match runtime.remove_image(tag).await {
            Ok(()) => println!("removed {tag}"),
            Err(e) => failures.push(format!("remove_image {tag} failed: {e}")),
        }
    }
    if !failures.is_empty() {
        Err(anyhow::anyhow!("{}", failures.join("; ")))
    } else {
        Ok(())
    }
}

async fn keep_set(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    dev_home: &DevHome,
    folder_image: &str,
) -> anyhow::Result<HashSet<String>> {
    let mut keep = HashSet::new();
    keep.insert(folder_image.to_string());
    keep.insert(format!("{folder_image}-uid"));

    for include_base in [true, false] {
        let config =
            effective_config_for(dev_home, workspace, runtime.runtime_name(), include_base)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot determine the current image family, so nothing will be removed: {e}\n\
                         To clean up manually: docker image ls --filter 'reference={folder_image}-features-*'"
                    )
                })?;
        let features = resolve_features(&config)?;
        if !features.is_empty() {
            let tag = feature_image_tag(folder_image, &config, &features);
            keep.insert(format!("{tag}-uid"));
            keep.insert(tag);
        }
    }

    // Anything a container still references stays, whether dev-labeled or a
    // secondary compose service of this workspace's project.
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    for container in runtime.list_containers(&filters).await? {
        keep.insert(container.image);
    }
    let compose_filter = vec![format!("com.docker.compose.project={folder_image}")];
    for container in runtime.list_containers(&compose_filter).await? {
        keep.insert(container.image);
    }
    Ok(keep)
}

/// Resolve the effective config the same way `dev up`/`dev build` do, without
/// writing any project state (no recipe materialization).
fn effective_config_for(
    dev_home: &DevHome,
    workspace: &Path,
    runtime_name: &str,
    include_base: bool,
) -> anyhow::Result<DevcontainerConfig> {
    match find_config_source_in(dev_home, workspace)? {
        ConfigSource::Direct(path) => {
            let (value, ids) =
                load_effective_config_value(&path, include_base, &dev_home.base_config())?;
            Ok(effective_config_from_parts(value, ids)?.config)
        }
        ConfigSource::Recipe(recipe_path) => {
            let recipe = Recipe::from_path(&recipe_path)?;
            let composed = compose_recipe_config_in(
                dev_home,
                &recipe_path,
                &recipe,
                runtime_name,
                include_base,
            )?;
            Ok(effective_config_from_parts(composed.value, composed.base_feature_ids)?.config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::config::DevcontainerConfig;
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerState, ExecResult,
        ImageInfo, ImageMetadata,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("not used by this test".into())) })
    }

    struct PruneFakeRuntime {
        images: Vec<String>,
        containers: Vec<ContainerInfo>,
        removed: Arc<Mutex<Vec<String>>>,
        /// Tags whose removal the daemon refuses (e.g. image in use elsewhere).
        refuse: Vec<String>,
    }

    impl PruneFakeRuntime {
        fn with_images(images: &[&str]) -> Self {
            Self {
                images: images.iter().map(|s| s.to_string()).collect(),
                containers: Vec::new(),
                removed: Arc::new(Mutex::new(Vec::new())),
                refuse: Vec::new(),
            }
        }

        fn container_on(mut self, image: &str) -> Self {
            self.containers.push(ContainerInfo {
                id: "c1".to_string(),
                name: "vsc-old".to_string(),
                state: ContainerState::Stopped,
                labels: HashMap::new(),
                image: image.to_string(),
            });
            self
        }

        fn refusing(mut self, tag: &str) -> Self {
            self.refuse.push(tag.to_string());
            self
        }

        fn removed(&self) -> Vec<String> {
            self.removed.lock().unwrap().clone()
        }
    }

    impl ContainerRuntime for PruneFakeRuntime {
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
        fn list_images(&self) -> BoxFut<'_, Vec<ImageInfo>> {
            let images: Vec<ImageInfo> = self
                .images
                .iter()
                .map(|tag| ImageInfo {
                    repo_tags: vec![tag.clone()],
                })
                .collect();
            Box::pin(async move { Ok(images) })
        }
        fn remove_image(&self, image: &str) -> BoxFut<'_, ()> {
            if self.refuse.contains(&image.to_string()) {
                return Box::pin(async {
                    Err(DevError::Runtime("image is in use by a container".into()))
                });
            }
            self.removed.lock().unwrap().push(image.to_string());
            Box::pin(async { Ok(()) })
        }
    }

    /// A workspace with a features config, its current derived tag, and stale
    /// sibling tags — plus another workspace's images that must never match.
    fn features_workspace() -> (TempDir, TempDir, String, String) {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let config_dir = workspace.path().join(".devcontainer");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_json = r#"{
            "image": "ubuntu:24.04",
            "features": {"ghcr.io/devcontainers/features/node:1": {}}
        }"#;
        std::fs::write(config_dir.join("devcontainer.json"), config_json).unwrap();

        let folder_image = container_name(workspace.path());
        let config: DevcontainerConfig =
            crate::devcontainer::jsonc::parse_jsonc(config_json).expect("test config parses");
        let features = resolve_features(&config).unwrap();
        let current = feature_image_tag(&folder_image, &config, &features);
        (home, workspace, folder_image, current)
    }

    #[tokio::test]
    async fn prune_removes_only_superseded_feature_images_for_this_workspace() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let stale_uid = format!("{stale}-uid");
        let other = "vsc-other-0000000000000000000000000000000000000000000000000000000000000000-features-bbbbbbbbbbbb";
        let rt = PruneFakeRuntime::with_images(&[
            &folder_image,
            &current,
            &format!("{current}-uid"),
            &stale,
            &stale_uid,
            other,
        ]);

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        let mut removed = rt.removed();
        removed.sort();
        assert_eq!(
            removed,
            vec![stale.clone(), stale_uid.clone()],
            "only this workspace's superseded tags go; the current family and \
             other workspaces' images stay"
        );
    }

    #[tokio::test]
    async fn prune_keeps_images_referenced_by_existing_containers() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let rt = PruneFakeRuntime::with_images(&[&current, &stale]).container_on(&stale);

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        assert!(
            rt.removed().is_empty(),
            "a stopped container's image is not superseded"
        );
    }

    #[tokio::test]
    async fn dry_run_reports_but_removes_nothing() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let rt = PruneFakeRuntime::with_images(&[&current, &stale]);

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), true)
            .await
            .unwrap();

        assert!(rt.removed().is_empty());
    }

    #[tokio::test]
    async fn prune_without_config_refuses_with_guidance() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let rt = PruneFakeRuntime::with_images(&["vsc-x-y-features-z"]);

        let err = run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .expect_err("no config means the current family is unknowable");

        assert!(
            format!("{err}").contains("nothing will be removed"),
            "prune fails closed: {err}"
        );
        assert!(rt.removed().is_empty());
    }

    #[tokio::test]
    async fn per_image_removal_failure_does_not_abort_the_rest() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale_a = format!("{folder_image}-features-aaaaaaaaaaaa");
        let stale_b = format!("{folder_image}-features-cccccccccccc");
        let rt = PruneFakeRuntime::with_images(&[&current, &stale_a, &stale_b]).refusing(&stale_a);

        let err = run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .expect_err("the refused removal is still reported");

        assert_eq!(
            rt.removed(),
            vec![stale_b],
            "the sweep continues past a refusal"
        );
        assert!(format!("{err}").contains(&stale_a));
    }

    #[tokio::test]
    async fn prune_keeps_the_no_base_variant_of_the_current_tag() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        std::fs::create_dir_all(dev_home.base_config().parent().unwrap()).unwrap();
        std::fs::write(
            dev_home.base_config(),
            r#"{"features": {"ghcr.io/devcontainers/features/common-utils:2": {}}}"#,
        )
        .unwrap();
        let config_dir = workspace.path().join(".devcontainer");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_json = r#"{
            "image": "ubuntu:24.04",
            "features": {"ghcr.io/devcontainers/features/node:1": {}}
        }"#;
        std::fs::write(config_dir.join("devcontainer.json"), config_json).unwrap();

        let folder_image = container_name(workspace.path());
        let with_base = effective_config_for(&dev_home, workspace.path(), "fake", true).unwrap();
        let without_base =
            effective_config_for(&dev_home, workspace.path(), "fake", false).unwrap();
        let tag_with = feature_image_tag(
            &folder_image,
            &with_base,
            &resolve_features(&with_base).unwrap(),
        );
        let tag_without = feature_image_tag(
            &folder_image,
            &without_base,
            &resolve_features(&without_base).unwrap(),
        );
        assert_ne!(tag_with, tag_without, "the base layer changes the digest");

        let rt = PruneFakeRuntime::with_images(&[&tag_with, &tag_without]);
        run_with_runtime(workspace.path(), &rt, &dev_home, false)
            .await
            .unwrap();

        assert!(
            rt.removed().is_empty(),
            "both the with-base and no-base current tags survive"
        );
    }
}
