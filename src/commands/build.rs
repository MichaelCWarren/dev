use std::path::Path;

use crate::cmux::{BUILD_KEY, BUILD_STYLE, Cmux};
use crate::devcontainer::compose::{compose_recipe_config, materialize_recipe_directory};
use crate::devcontainer::effective::{
    LockfilePolicy, effective_config_from_parts, load_effective_config,
};
use crate::devcontainer::features::{
    feature_image_tag, generate_feature_dockerfile_with_opts, order_features,
};
use crate::devcontainer::substitute_variables;
use crate::devcontainer::uid;
use crate::devcontainer::{Recipe, download_features, resolve_features, stage_feature_context};
use crate::runtime::{detect_runtime, resolve_remote_user};
use crate::util::{ConfigSource, container_name, find_config_source, workspace_folder_name};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    tag: Option<&str>,
    no_cache: bool,
    verbose: bool,
    frozen_lockfile: bool,
    _buildkit: bool,
    update_remote_user_uid_default: &str,
    no_base: bool,
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    let cmux = Cmux::detect(true);
    run_with_runtime(
        workspace,
        runtime.as_ref(),
        tag,
        no_cache,
        verbose,
        frozen_lockfile,
        update_remote_user_uid_default,
        no_base,
        &cmux,
    )
    .await
}

/// [`run`] body once the runtime has been selected, mirroring
/// `up::run_with_runtime` so a test can drive it with a stand-in
/// [`crate::runtime::ContainerRuntime`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn crate::runtime::ContainerRuntime,
    tag: Option<&str>,
    no_cache: bool,
    verbose: bool,
    frozen_lockfile: bool,
    update_remote_user_uid_default: &str,
    no_base: bool,
    cmux: &Cmux,
) -> anyhow::Result<()> {
    let (config_path, recipe_config) = match find_config_source(workspace)? {
        ConfigSource::Direct(path) => (path, None),
        ConfigSource::Recipe(recipe_path) => {
            let recipe = Recipe::from_path(&recipe_path)?;
            materialize_recipe_directory(&recipe_path, &recipe)?;
            let composed =
                compose_recipe_config(&recipe_path, &recipe, runtime.runtime_name(), !no_base)?;
            (composed.config_path.clone(), Some(composed))
        }
    };
    // Recipe configs resolve their own layers, base included, so the runtime base
    // layer would be a second application whose prune can discard a base selector
    // the recipe deliberately kept.
    let effective = match recipe_config {
        Some(recipe_config) => {
            effective_config_from_parts(recipe_config.value, recipe_config.base_feature_ids)?
        }
        None => load_effective_config(&config_path, !no_base)?,
    };
    let lockfile = LockfilePolicy::new(&effective, frozen_lockfile);
    let config = effective.config;
    let mut pill = cmux.guard(BUILD_KEY, config.cmux_status_enabled());

    let folder_image = container_name(workspace);
    let features = resolve_features(&config)?;
    let has_features = !features.is_empty();
    let default_tag = if has_features {
        feature_image_tag(&folder_image, &config, &features)
    } else {
        folder_image.clone()
    };
    let final_tag = tag.unwrap_or(&default_tag);
    let devcontainer_dir = config_path.parent().map(|p| p.to_path_buf());

    // Build or pull the base image
    let base_image = if let Some(ref image) = config.image {
        pill.phase("build: pulling image", BUILD_STYLE);
        eprintln!("Pulling image '{image}'...");
        runtime.pull_image(image).await?;
        image.clone()
    } else if let Some(ref build) = config.build {
        let context_dir = config_path
            .parent()
            .unwrap()
            .join(build.context.as_deref().unwrap_or("."));
        let dockerfile_path = config_path.parent().unwrap().join(&build.dockerfile);
        let dockerfile_content = std::fs::read_to_string(&dockerfile_path)?;
        pill.phase("build: building image", BUILD_STYLE);
        eprintln!("Building image from Dockerfile...");
        if !has_features {
            // No features — build directly with the final tag.
            runtime
                .build_image(
                    &dockerfile_content,
                    &context_dir,
                    final_tag,
                    &std::collections::HashMap::new(),
                    no_cache,
                    verbose,
                )
                .await?;
            let remote_user =
                resolve_remote_user(runtime, final_tag, config.remote_user.as_deref()).await?;
            let output_tag = if uid::should_remap_uid(
                &config,
                remote_user.as_deref(),
                update_remote_user_uid_default,
            ) {
                pill.phase("build: remapping uid", BUILD_STYLE);
                let meta = runtime.inspect_image_metadata(final_tag).await?;
                let image_user = meta.container_user.as_deref().unwrap_or("root");
                uid::build_uid_image(
                    runtime,
                    final_tag,
                    &folder_image,
                    remote_user.as_deref().unwrap_or("root"),
                    image_user,
                    no_cache,
                    verbose,
                )
                .await?
            } else {
                final_tag.to_string()
            };
            println!("{output_tag}");
            return Ok(());
        }
        // Features present: tag the base Dockerfile build as the folder image.
        runtime
            .build_image(
                &dockerfile_content,
                &context_dir,
                &folder_image,
                &std::collections::HashMap::new(),
                no_cache,
                verbose,
            )
            .await?;
        // Fall through to feature layering below
        let mut features = features;
        pill.phase("build: downloading features", BUILD_STYLE);
        eprintln!("Downloading {} feature(s)...", features.len());
        download_features(&mut features, devcontainer_dir.as_deref()).await?;

        lockfile.apply(devcontainer_dir.as_deref(), &features)?;

        let ordered = order_features(&features);
        let staging_dir = stage_feature_context(&ordered)?;
        let feature_user =
            resolve_remote_user(runtime, &folder_image, config.remote_user.as_deref()).await?;
        let dockerfile = generate_feature_dockerfile_with_opts(
            &folder_image,
            &folder_image,
            &ordered,
            feature_user.as_deref(),
            &config,
        );
        pill.phase("build: building features", BUILD_STYLE);
        eprintln!("Building features image...");
        let result = runtime
            .build_image(
                &dockerfile,
                &staging_dir,
                final_tag,
                &std::collections::HashMap::new(),
                no_cache,
                verbose,
            )
            .await;
        let _ = std::fs::remove_dir_all(&staging_dir);
        result?;
        let output_tag = if uid::should_remap_uid(
            &config,
            feature_user.as_deref(),
            update_remote_user_uid_default,
        ) {
            pill.phase("build: remapping uid", BUILD_STYLE);
            let meta = runtime.inspect_image_metadata(final_tag).await?;
            let image_user = meta.container_user.as_deref().unwrap_or("root");
            uid::build_uid_image(
                runtime,
                final_tag,
                &folder_image,
                feature_user.as_deref().unwrap_or("root"),
                image_user,
                no_cache,
                verbose,
            )
            .await?
        } else {
            final_tag.to_string()
        };
        println!("{output_tag}");
        return Ok(());
    } else if config.is_compose() {
        let compose_data = config.docker_compose_file.as_ref().unwrap();
        let compose_files = compose_data.files();
        let compose_devcontainer_dir = config_path.parent().unwrap();
        let service = config
            .service
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Docker Compose config must specify 'service'"))?;
        let project_name = container_name(workspace);

        // Workspace env vars for Docker Compose variable interpolation.
        let build_folder_name = workspace_folder_name(workspace);
        let build_workspace_source = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.to_path_buf());
        let build_workspace_target = substitute_variables(
            config
                .workspace_folder
                .as_deref()
                .unwrap_or(&format!("/workspaces/{build_folder_name}")),
            workspace,
        );
        let mut compose_env = std::collections::HashMap::new();
        compose_env.insert(
            "localWorkspaceFolder".to_string(),
            build_workspace_source.to_string_lossy().to_string(),
        );
        compose_env.insert(
            "localWorkspaceFolderBasename".to_string(),
            build_folder_name,
        );
        compose_env.insert(
            "containerWorkspaceFolder".to_string(),
            build_workspace_target,
        );

        pill.phase("build: building compose services", BUILD_STYLE);
        eprintln!("Building compose services...");
        crate::runtime::compose::compose_build(
            runtime.runtime_name(),
            &compose_files,
            compose_devcontainer_dir,
            Some(service),
            no_cache,
            verbose,
            &compose_env,
        )
        .await?;

        if !has_features {
            println!("compose:{service}");
            return Ok(());
        }

        // Get the service image for feature layering.
        let base_image = crate::runtime::compose::compose_service_image(
            runtime.runtime_name(),
            &compose_files,
            compose_devcontainer_dir,
            &project_name,
            service,
            &compose_env,
        )
        .await?;

        let feature_tag = feature_image_tag(&folder_image, &config, &features);
        let compose_final_tag = tag.unwrap_or(&feature_tag);

        let mut features = features;
        pill.phase("build: downloading features", BUILD_STYLE);
        eprintln!("Downloading {} feature(s)...", features.len());
        download_features(&mut features, Some(compose_devcontainer_dir)).await?;

        lockfile.apply(Some(compose_devcontainer_dir), &features)?;

        let ordered = order_features(&features);
        let staging_dir = stage_feature_context(&ordered)?;
        let feature_user =
            resolve_remote_user(runtime, &base_image, config.remote_user.as_deref()).await?;
        let dockerfile = generate_feature_dockerfile_with_opts(
            &base_image,
            &folder_image,
            &ordered,
            feature_user.as_deref(),
            &config,
        );
        pill.phase("build: building features", BUILD_STYLE);
        eprintln!("Building features image...");
        let result = runtime
            .build_image(
                &dockerfile,
                &staging_dir,
                compose_final_tag,
                &std::collections::HashMap::new(),
                no_cache,
                verbose,
            )
            .await;
        let _ = std::fs::remove_dir_all(&staging_dir);
        result?;

        let output_tag = if uid::should_remap_uid(
            &config,
            feature_user.as_deref(),
            update_remote_user_uid_default,
        ) {
            pill.phase("build: remapping uid", BUILD_STYLE);
            let meta = runtime.inspect_image_metadata(compose_final_tag).await?;
            let image_user = meta.container_user.as_deref().unwrap_or("root");
            uid::build_uid_image(
                runtime,
                compose_final_tag,
                &folder_image,
                feature_user.as_deref().unwrap_or("root"),
                image_user,
                no_cache,
                verbose,
            )
            .await?
        } else {
            compose_final_tag.to_string()
        };
        println!("{output_tag}");
        return Ok(());
    } else {
        anyhow::bail!(
            "devcontainer.json must specify 'image', 'build.dockerfile', or 'dockerComposeFile'"
        );
    };

    // Image-based config with features
    if !has_features {
        println!("{base_image}");
        return Ok(());
    }

    let mut features = features;
    pill.phase("build: downloading features", BUILD_STYLE);
    eprintln!("Downloading {} feature(s)...", features.len());
    download_features(&mut features, devcontainer_dir.as_deref()).await?;

    lockfile.apply(devcontainer_dir.as_deref(), &features)?;

    let ordered = order_features(&features);
    let staging_dir = stage_feature_context(&ordered)?;
    let feature_user =
        resolve_remote_user(runtime, &base_image, config.remote_user.as_deref()).await?;
    let dockerfile = generate_feature_dockerfile_with_opts(
        &base_image,
        &folder_image,
        &ordered,
        feature_user.as_deref(),
        &config,
    );
    pill.phase("build: building features", BUILD_STYLE);
    eprintln!("Building features image...");
    let result = runtime
        .build_image(
            &dockerfile,
            &staging_dir,
            final_tag,
            &std::collections::HashMap::new(),
            no_cache,
            verbose,
        )
        .await;
    let _ = std::fs::remove_dir_all(&staging_dir);
    result?;

    let output_tag = if uid::should_remap_uid(
        &config,
        feature_user.as_deref(),
        update_remote_user_uid_default,
    ) {
        pill.phase("build: remapping uid", BUILD_STYLE);
        let meta = runtime.inspect_image_metadata(final_tag).await?;
        let image_user = meta.container_user.as_deref().unwrap_or("root");
        uid::build_uid_image(
            runtime,
            final_tag,
            &folder_image,
            feature_user.as_deref().unwrap_or("root"),
            image_user,
            no_cache,
            verbose,
        )
        .await?
    } else {
        final_tag.to_string()
    };
    println!("{output_tag}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_with_runtime;
    use crate::cmux::{BUILD_KEY, Cmux};
    use crate::devcontainer::secrets::SecretValue;
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ExecResult,
        ImageMetadata,
    };
    use std::fs;
    use tempfile::TempDir;

    fn write_project_config(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let devcontainer_dir = dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        let path = devcontainer_dir.join("devcontainer.json");
        fs::write(&path, content).unwrap();
        path
    }

    fn unused<T: Send + 'static>() -> BoxFut<'static, T> {
        Box::pin(async {
            Err(DevError::Runtime(
                "FakeRuntime method unused by dev build tests".into(),
            ))
        })
    }

    /// A runtime whose pull and build always succeed, modelling the
    /// image-only, no-features path `dev build` takes for these tests. Every
    /// other method is unreached by that path and errors if it ever is.
    struct FakeRuntime;

    impl ContainerRuntime for FakeRuntime {
        fn runtime_name(&self) -> &'static str {
            "fake"
        }

        fn pull_image(&self, _image: &str) -> BoxFut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn build_image(
            &self,
            _dockerfile: &str,
            _context: &std::path::Path,
            _tag: &str,
            _build_args: &std::collections::HashMap<String, String>,
            _no_cache: bool,
            _verbose: bool,
        ) -> BoxFut<'_, ()> {
            Box::pin(async { Ok(()) })
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
            unused()
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
            Box::pin(async { Ok(true) })
        }

        fn inspect_image_metadata(&self, _image: &str) -> BoxFut<'_, ImageMetadata> {
            Box::pin(async { Ok(ImageMetadata::default()) })
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

    /// [`run_with_runtime`] over a minimal image-only, no-features config, no
    /// features, `no_base: true` — the path that walks straight to the
    /// bare-tag print at the bottom of the function.
    async fn run_build_with_cmux(workspace: &TempDir, cmux: &Cmux) -> anyhow::Result<()> {
        run_with_runtime(
            workspace.path(),
            &FakeRuntime,
            /* tag */ None,
            /* no_cache */ false,
            /* verbose */ false,
            /* frozen_lockfile */ false,
            /* update_remote_user_uid_default */ "never",
            /* no_base */ true,
            cmux,
        )
        .await
    }

    /// The pull phase is set before the print, and cleared by the guard's
    /// `Drop` on the return right after it — the stuck-pill case the spec
    /// calls out explicitly.
    #[tokio::test]
    async fn build_clears_pill_after_printing_tag() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","cmux":{"status":true}}"#,
        );
        let (cmux, recorder) = Cmux::recording();
        run_build_with_cmux(&workspace, &cmux)
            .await
            .expect("run should succeed");

        let calls = recorder.calls();
        assert_eq!(calls.len(), 2, "expected pull then clear, got: {calls:?}");
        assert_eq!(
            calls[0][..3],
            ["set-status", BUILD_KEY, "build: pulling image"]
        );
        assert_eq!(
            calls[1],
            vec!["clear-status".to_string(), BUILD_KEY.to_string()]
        );
    }

    /// No `cmux` key means the gate is off, so nothing is called at all.
    #[tokio::test]
    async fn build_without_cmux_key_makes_no_calls() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let (cmux, recorder) = Cmux::recording();
        run_build_with_cmux(&workspace, &cmux)
            .await
            .expect("run should succeed");

        assert!(
            recorder.calls().is_empty(),
            "no cmux call should be made without the config key: {:?}",
            recorder.calls()
        );
    }
}
