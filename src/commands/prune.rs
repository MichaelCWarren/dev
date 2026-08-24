use std::collections::HashSet;
use std::path::Path;

use crate::devcontainer::effective::effective_config_in;
use crate::devcontainer::features::{WORKSPACE_IMAGE_LABEL, feature_image_tag};
use crate::devcontainer::resolve_features;
use crate::devcontainer::uid::uid_image_tag;
use crate::runtime::{ContainerRuntime, ImageInfo, detect_runtime};
use crate::util::paths::DevHome;
use crate::util::{container_name, workspace_labels};

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
/// image an existing container still references. A tag is only ever a removal
/// candidate when it has the exact shape `dev` derives (`-features-` digest,
/// optionally `-uid`) and the `:latest` reference `dev` builds with — compose
/// service images and user-applied tags like `:backup` never match. Dangling
/// rebuild leftovers are claimed through the workspace label the features
/// Dockerfile bakes in.
pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    dev_home: &DevHome,
    dry_run: bool,
) -> anyhow::Result<()> {
    let folder_image = container_name(workspace);
    let keep = keep_set(workspace, runtime, dev_home, &folder_image).await?;
    let images = runtime.list_images().await?;
    let plan = sweep_plan(&images, &keep, &folder_image);

    if plan.stale.is_empty() && plan.dangling.is_empty() {
        println!("No superseded feature images for this workspace.");
        return Ok(());
    }

    if dry_run {
        for tag in &plan.stale {
            println!("would remove {tag}");
        }
        for id in &plan.dangling {
            println!("would remove {id} (dangling)");
        }
        for tag in &plan.kept_current {
            println!("keeping {tag} (current)");
        }
        for tag in &plan.kept_in_use {
            println!("keeping {tag} (in use by a container)");
        }
        return Ok(());
    }

    let mut failures: Vec<String> = Vec::new();
    for reference in plan.stale.iter().chain(plan.dangling.iter()) {
        // No force: an in-use conflict is the daemon's report to surface, and
        // one failure must not abort the rest of the sweep.
        match runtime.remove_image(reference).await {
            Ok(()) => println!("removed {reference}"),
            Err(e) => failures.push(format!("remove_image {reference} failed: {e}")),
        }
    }
    if !failures.is_empty() {
        Err(anyhow::anyhow!("{}", failures.join("; ")))
    } else {
        Ok(())
    }
}

/// What one prune pass would do, split for reporting.
struct SweepPlan {
    /// Superseded `:latest` tags, `-uid` children ahead of their parents.
    stale: Vec<String>,
    /// IDs of dangling images labeled as this workspace's rebuild leftovers.
    dangling: Vec<String>,
    /// Existing family tags in the current image family.
    kept_current: Vec<String>,
    /// Existing family tags only a container still references.
    kept_in_use: Vec<String>,
}

fn sweep_plan(images: &[ImageInfo], keep: &KeepSet, folder_image: &str) -> SweepPlan {
    let prefix = format!("{folder_image}-features-");
    let mut plan = SweepPlan {
        stale: Vec::new(),
        dangling: Vec::new(),
        kept_current: Vec::new(),
        kept_in_use: Vec::new(),
    };
    for image in images {
        for tag in &image.repo_tags {
            // Only `:latest` references are dev's own; a user-applied tag like
            // `:backup` is never removed, and its layers survive the `:latest`
            // untag.
            let Some(name) = tag.strip_suffix(":latest") else {
                continue;
            };
            let name = strip_local_registry(name);
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            if !is_derived_feature_suffix(rest) {
                continue;
            }
            if keep.current.contains(name) {
                plan.kept_current.push(tag.clone());
            } else if keep.in_use.contains(name) {
                plan.kept_in_use.push(tag.clone());
            } else {
                plan.stale.push(tag.clone());
            }
        }
        // A dangling image has no workspace-prefixed tag left; the label the
        // features Dockerfile bakes in is what still ties it to the workspace.
        if image.repo_tags.iter().all(|t| t == "<none>:<none>")
            && image.labels.get(WORKSPACE_IMAGE_LABEL).map(String::as_str) == Some(folder_image)
            && !keep.in_use.contains(&image.id)
        {
            plan.dangling.push(image.id.clone());
        }
    }
    // Remove `-uid` children before the parents they were built FROM: the
    // classic image store refuses to delete a parent with dependent children.
    // A child's tag is its parent's plus a suffix, so longer tags go first.
    plan.stale
        .sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    plan.kept_current.sort();
    plan.kept_in_use.sort();
    plan
}

/// True when `rest` is what follows `-features-` in a tag `dev` derived: the
/// 12-hex digest from `feature_image_tag`, optionally with the `-uid` layer.
/// Compose service images (`{project}-features-{service}`) never match.
fn is_derived_feature_suffix(rest: &str) -> bool {
    let digest = rest.strip_suffix("-uid").unwrap_or(rest);
    digest.len() == 12
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

struct KeepSet {
    /// The current image family, resolved the way `dev up`/`dev build` do.
    current: HashSet<String>,
    /// Images an existing container still references (bare names or IDs).
    in_use: HashSet<String>,
}

async fn keep_set(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    dev_home: &DevHome,
    folder_image: &str,
) -> anyhow::Result<KeepSet> {
    let mut current = HashSet::new();
    current.insert(folder_image.to_string());
    current.insert(uid_image_tag(folder_image, folder_image));

    for include_base in [true, false] {
        let config =
            effective_config_in(dev_home, workspace, runtime.runtime_name(), include_base)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot determine the current image family, so nothing will be removed: {e}\n\
                         To clean up manually: docker image ls --filter 'reference={folder_image}-features-*'"
                    )
                })?;
        let features = resolve_features(&config)?;
        if !features.is_empty() {
            let tag = feature_image_tag(folder_image, &config, &features);
            current.insert(uid_image_tag(&tag, folder_image));
            current.insert(tag);
        }
    }

    // Anything a container still references stays, whether dev-labeled or a
    // secondary compose service of this workspace's project.
    let mut in_use = HashSet::new();
    let labels = workspace_labels(workspace, None);
    let filters: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    for container in runtime.list_containers(&filters).await? {
        in_use.insert(bare_tag(&container.image).to_string());
    }
    let compose_filter = vec![format!("com.docker.compose.project={folder_image}")];
    for container in runtime.list_containers(&compose_filter).await? {
        in_use.insert(bare_tag(&container.image).to_string());
    }
    Ok(KeepSet { current, in_use })
}

/// Podman reports locally built images under the `localhost/` registry; the
/// keep set holds the bare names `dev` builds with.
fn strip_local_registry(name: &str) -> &str {
    name.strip_prefix("localhost/").unwrap_or(name)
}

/// A reference as `dev` names it: no local registry prefix, no implied
/// `:latest` (the daemon reports untagged references as `name:latest`).
fn bare_tag(tag: &str) -> &str {
    strip_local_registry(tag.strip_suffix(":latest").unwrap_or(tag))
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
        images: Vec<ImageInfo>,
        containers: Vec<ContainerInfo>,
        removed: Arc<Mutex<Vec<String>>>,
        /// Tags whose removal the daemon refuses (e.g. image in use elsewhere).
        refuse: Vec<String>,
    }

    impl PruneFakeRuntime {
        fn with_images(images: &[&str]) -> Self {
            let images = images
                .iter()
                .enumerate()
                .map(|(i, tag)| ImageInfo {
                    id: format!("sha256:{i:064}"),
                    // The daemon reports untagged references as `name:latest`;
                    // the fake does the same so the normalization stays pinned.
                    repo_tags: vec![format!("{tag}:latest")],
                    labels: HashMap::new(),
                })
                .collect();
            Self {
                images,
                containers: Vec::new(),
                removed: Arc::new(Mutex::new(Vec::new())),
                refuse: Vec::new(),
            }
        }

        /// An image exactly as the daemon would report it (arbitrary tags,
        /// labels, id) — for the shapes `with_images` cannot express.
        fn raw_image(mut self, image: ImageInfo) -> Self {
            self.images.push(image);
            self
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
            let images = self.images.clone();
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
            vec![format!("{stale_uid}:latest"), format!("{stale}:latest")],
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
        let rt = PruneFakeRuntime::with_images(&[&current, &stale_a, &stale_b])
            .refusing(&format!("{stale_a}:latest"));

        let err = run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .expect_err("the refused removal is still reported");

        assert_eq!(
            rt.removed(),
            vec![format!("{stale_b}:latest")],
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
        let with_base = effective_config_in(&dev_home, workspace.path(), "fake", true).unwrap();
        let without_base = effective_config_in(&dev_home, workspace.path(), "fake", false).unwrap();
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

    /// A compose service whose name starts with `features-` produces an image
    /// under the `-features-` prefix (`{project}-features-api`). Only the
    /// derived digest shape is dev's to remove.
    #[tokio::test]
    async fn prune_never_touches_compose_service_images_under_the_prefix() {
        let (home, workspace, folder_image, current) = features_workspace();
        let service_image = format!("{folder_image}-features-api");
        let rt = PruneFakeRuntime::with_images(&[&current, &service_image]);

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        assert!(
            rt.removed().is_empty(),
            "a compose service image is not a derived feature image"
        );
    }

    /// A user-applied tag is never removed: only the `:latest` reference dev
    /// builds with is a candidate, so a `:backup` survives the sweep of its
    /// superseded `:latest` sibling.
    #[tokio::test]
    async fn prune_leaves_user_applied_tags_alone() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let rt = PruneFakeRuntime::with_images(&[&current]).raw_image(ImageInfo {
            id: "sha256:aaaa".to_string(),
            repo_tags: vec![format!("{stale}:latest"), format!("{stale}:backup")],
            labels: HashMap::new(),
        });

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        assert_eq!(
            rt.removed(),
            vec![format!("{stale}:latest")],
            "the superseded :latest is untagged; the :backup keeps the layers"
        );
    }

    /// Podman reports locally built images under `localhost/`; the sweep still
    /// recognizes both the stale and the current family through the prefix.
    #[tokio::test]
    async fn prune_recognizes_podman_localhost_prefixed_tags() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let rt = PruneFakeRuntime::with_images(&[])
            .raw_image(ImageInfo {
                id: "sha256:aaaa".to_string(),
                repo_tags: vec![format!("localhost/{stale}:latest")],
                labels: HashMap::new(),
            })
            .raw_image(ImageInfo {
                id: "sha256:bbbb".to_string(),
                repo_tags: vec![format!("localhost/{current}:latest")],
                labels: HashMap::new(),
            });

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        assert_eq!(
            rt.removed(),
            vec![format!("localhost/{stale}:latest")],
            "the stale image goes by its daemon-reported reference; the current stays"
        );
    }

    /// The `-uid` child is built FROM its parent, so it must be removed first
    /// or the classic image store refuses the parent with a dependent-child
    /// conflict.
    #[tokio::test]
    async fn prune_removes_uid_children_before_their_parents() {
        let (home, workspace, folder_image, current) = features_workspace();
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let stale_uid = format!("{stale}-uid");
        // Parent listed first: daemon order must not drive removal order.
        let rt = PruneFakeRuntime::with_images(&[&current, &stale, &stale_uid]);

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        assert_eq!(
            rt.removed(),
            vec![format!("{stale_uid}:latest"), format!("{stale}:latest")],
            "children go before the parents they were built from"
        );
    }

    /// A rebuild onto the same tag untags the old build into a dangling image.
    /// The workspace label claims it; unlabeled and other-workspace danglings
    /// stay, as does one a container still runs on.
    #[tokio::test]
    async fn prune_removes_this_workspace_dangling_images_by_label() {
        let (home, workspace, folder_image, current) = features_workspace();
        let mine = ImageInfo {
            id: "sha256:aaaa".to_string(),
            repo_tags: vec![],
            labels: HashMap::from([(WORKSPACE_IMAGE_LABEL.to_string(), folder_image.clone())]),
        };
        let unlabeled = ImageInfo {
            id: "sha256:bbbb".to_string(),
            repo_tags: vec!["<none>:<none>".to_string()],
            labels: HashMap::new(),
        };
        let other_workspace = ImageInfo {
            id: "sha256:cccc".to_string(),
            repo_tags: vec![],
            labels: HashMap::from([(WORKSPACE_IMAGE_LABEL.to_string(), "vsc-other".to_string())]),
        };
        let in_use = ImageInfo {
            id: "sha256:dddd".to_string(),
            repo_tags: vec![],
            labels: HashMap::from([(WORKSPACE_IMAGE_LABEL.to_string(), folder_image.clone())]),
        };
        let rt = PruneFakeRuntime::with_images(&[&current])
            .raw_image(mine)
            .raw_image(unlabeled)
            .raw_image(other_workspace)
            .raw_image(in_use)
            .container_on("sha256:dddd");

        run_with_runtime(workspace.path(), &rt, &DevHome::at(home.path()), false)
            .await
            .unwrap();

        assert_eq!(
            rt.removed(),
            vec!["sha256:aaaa".to_string()],
            "only this workspace's unreferenced dangling image goes"
        );
    }

    /// The dry-run "keeping" report lists images that exist, not the computed
    /// keep set: a never-built `-uid` variant does not appear, and an image
    /// kept only by a container is labeled as such, not as current.
    #[test]
    fn sweep_plan_reports_only_existing_images_as_kept() {
        let folder_image =
            "vsc-ws-0000000000000000000000000000000000000000000000000000000000000000";
        let current = format!("{folder_image}-features-eeeeeeeeeeee");
        let stale = format!("{folder_image}-features-aaaaaaaaaaaa");
        let keep = KeepSet {
            current: HashSet::from([current.clone(), format!("{current}-uid")]),
            in_use: HashSet::from([stale.clone()]),
        };
        let images = [
            ImageInfo {
                id: "sha256:aaaa".to_string(),
                repo_tags: vec![format!("{current}:latest")],
                labels: HashMap::new(),
            },
            ImageInfo {
                id: "sha256:bbbb".to_string(),
                repo_tags: vec![format!("{stale}:latest")],
                labels: HashMap::new(),
            },
        ];

        let plan = sweep_plan(&images, &keep, folder_image);

        assert_eq!(
            plan.kept_current,
            vec![format!("{current}:latest")],
            "the never-built -uid tag is not reported"
        );
        assert_eq!(
            plan.kept_in_use,
            vec![format!("{stale}:latest")],
            "container-kept images are labeled in use, not current"
        );
        assert!(plan.stale.is_empty());
    }
}
