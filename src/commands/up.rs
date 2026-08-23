use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::devcontainer::compose::{compose_recipe_config, materialize_recipe_directory};
use crate::devcontainer::config::MountSpec;
use crate::devcontainer::effective::{
    LockfilePolicy, effective_config_from_parts, load_effective_config,
};
use crate::devcontainer::features::{
    MergedCapabilities, ResolvedFeature, feature_image_tag, features_from_metadata,
    generate_feature_dockerfile_with_opts, order_features,
};
use crate::devcontainer::secrets::discovery::secrets_file_path;
use crate::devcontainer::secrets::env_name_problem;
use crate::devcontainer::secrets::validate::validate_secrets_at;
use crate::devcontainer::secrets::{ProviderRegistry, SecretValue, ValidatedSecrets};
use crate::devcontainer::uid;
use crate::devcontainer::{
    DevcontainerConfig, Recipe, download_features, merge_feature_capabilities, resolve_features,
    run_create_hooks, run_start_hooks, stage_feature_context, substitute_variables,
    substitute_variables_with_user,
};
use crate::error::DevError;
use crate::runtime::{
    BindMount, ContainerConfig, ContainerRuntime, ContainerState, ExecResult, PortMapping,
    VolumeMount, WorkspaceMount, detect_runtime, resolve_remote_user,
};
use crate::util::{
    ConfigSource, container_name, find_config_source, workspace_folder_name, workspace_labels,
};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    rebuild: bool,
    no_cache: bool,
    verbose: bool,
    frozen_lockfile: bool,
    _buildkit: bool,
    update_remote_user_uid_default: &str,
    port_overrides: &[String],
    secrets_file: Option<&Path>,
    no_base: bool,
    secrets_override: Option<&Path>,
) -> anyhow::Result<()> {
    let runtime = detect_runtime(runtime_override).await?;
    run_with_runtime(
        workspace,
        runtime.as_ref(),
        rebuild,
        no_cache,
        verbose,
        frozen_lockfile,
        update_remote_user_uid_default,
        port_overrides,
        secrets_file,
        no_base,
        secrets_override,
    )
    .await
}

/// Re-register the workspace's Caddy routes when reusing an existing container.
///
/// `dev down` deletes the project's Caddy fragment unconditionally, but the
/// start-existing branch of `dev up` returns before the create path's
/// registration, so a plain `down` → `up` otherwise leaves the container
/// running with no `.test` routes (issue #52). Calling this on restart makes
/// `up` self-healing.
///
/// The route set is the union of the declared `forwardPorts` and any live
/// `dev forward` entries — deduped by host port, with the live entry winning so
/// its custom name / keepalive survive the rewrite. `register_site` overwrites
/// the whole fragment (`caddy.rs`), so registering declared ports alone would
/// silently drop ad-hoc forwards; merging restores them too (issue #53).
/// No-op when nothing is forwarded, and a failed Caddy reload warns rather than
/// failing `dev up`.
fn register_caddy_routes(workspace: &Path, config: &DevcontainerConfig) {
    let declared = caddy_ports_from_config(config);
    let active = crate::commands::forward::active_entries_for_workspace(workspace);
    let ports = merge_caddy_ports(declared, active);
    if !ports.is_empty()
        && let Err(e) = crate::caddy::register_site(workspace, &ports)
    {
        eprintln!("Warning: Caddy setup failed: {e}");
    }
}

/// Union of declared and live Caddy port entries, deduped by host port.
///
/// The live entry wins on conflict because it carries the custom name /
/// keepalive that `dev forward` persisted, which a declared-only entry lacks.
/// Keyed by port in a `BTreeMap`, so the result is sorted by host port to match
/// the ordering `dev forward` uses before `register_site`.
fn merge_caddy_ports(
    declared: Vec<crate::caddy::PortEntry>,
    active: Vec<crate::caddy::PortEntry>,
) -> Vec<crate::caddy::PortEntry> {
    let mut by_port: BTreeMap<u16, crate::caddy::PortEntry> = BTreeMap::new();
    for entry in declared {
        by_port.insert(entry.port, entry);
    }
    for entry in active {
        by_port.insert(entry.port, entry);
    }
    by_port.into_values().collect()
}

/// The Caddy port entries implied by a project's declared `forwardPorts`.
///
/// A port named in the config's `caddy` map gets that hostname; the rest keep
/// the derived `<folder>.test` / `<folder>-<port>.test` names. The map is keyed
/// by **host** port, matching the side Caddy proxies to.
///
/// Empty when nothing is forwarded, which makes registration a no-op. Kept
/// separate from [`register_caddy_routes`] so the mapping is unit-testable
/// without the filesystem/Caddy side effects of `register_site`.
fn caddy_ports_from_config(config: &DevcontainerConfig) -> Vec<crate::caddy::PortEntry> {
    let names = config.caddy.clone().unwrap_or_default();
    config
        .forward_ports
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|p| crate::caddy::PortEntry {
            port: p.host,
            custom_name: names
                .get(&p.host.to_string())
                .map(|n| crate::caddy::qualify_hostname(n)),
            keepalive: None,
        })
        .collect()
}

/// `dev up` body once the runtime has been selected.
///
/// Split from [`run`] so the create/start/readiness flow can be driven with a
/// stand-in [`ContainerRuntime`] in tests — the issue #4 regression boundary is
/// that a failed create or start must propagate as an error before any
/// "ready" message, and that the container config handed to the runtime
/// carries the workspace label that `dev status`/`dev exec` later filter on.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_runtime(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    rebuild: bool,
    no_cache: bool,
    verbose: bool,
    frozen_lockfile: bool,
    update_remote_user_uid_default: &str,
    port_overrides: &[String],
    secrets_file: Option<&Path>,
    no_base: bool,
    secrets_override: Option<&Path>,
) -> anyhow::Result<()> {
    let providers = ProviderRegistry::with_builtins(workspace);
    run_with_runtime_with_providers(
        workspace,
        runtime,
        rebuild,
        no_cache,
        verbose,
        frozen_lockfile,
        update_remote_user_uid_default,
        port_overrides,
        secrets_file,
        no_base,
        secrets_override,
        &providers,
    )
    .await
}

/// [`run_with_runtime`] with the secret providers supplied, so a test can put a
/// fake in front of both validation and resolution. One registry serves both:
/// two would let a fake satisfy validation and then resolve against the real
/// built-ins.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_runtime_with_providers(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    rebuild: bool,
    no_cache: bool,
    verbose: bool,
    frozen_lockfile: bool,
    update_remote_user_uid_default: &str,
    port_overrides: &[String],
    secrets_file: Option<&Path>,
    no_base: bool,
    secrets_override: Option<&Path>,
    providers: &ProviderRegistry,
) -> anyhow::Result<()> {
    let (config_path, recipe_config, project_declared_run_args) =
        match find_config_source(workspace)? {
            ConfigSource::Direct(path) => {
                let project_declared_run_args = config_file_declares_run_args(&path)?;
                (path, None, project_declared_run_args)
            }
            ConfigSource::Recipe(recipe_path) => {
                let recipe = Recipe::from_path(&recipe_path)?;
                let project_declared_run_args = project_declares_run_args(&recipe.customizations);
                materialize_recipe_directory(&recipe_path, &recipe)?;
                let composed =
                    compose_recipe_config(&recipe_path, &recipe, runtime.runtime_name(), !no_base)?;
                (
                    composed.config_path.clone(),
                    Some(composed),
                    project_declared_run_args,
                )
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
    let mut config = effective.config;
    apply_cli_overrides(&mut config, port_overrides)?;

    // Docker Compose configs take a completely separate code path.
    if config.is_compose() {
        reject_project_run_args_for_compose(&config, project_declared_run_args)?;
        // Both refusals precede validation: a flag this path cannot honour is
        // worth saying so about before the user is asked to fix a file the
        // answer does not depend on.
        reject_secrets_file_for_compose(secrets_file)?;
        reject_secrets_override_for_compose(secrets_override)?;
        let secrets = validate_workspace_secrets(
            &config,
            &config_path,
            workspace,
            providers,
            secrets_override,
        )?;
        reject_secrets_for_compose(&config, &secrets)?;
        return run_compose(
            workspace,
            &config,
            &config_path,
            runtime,
            rebuild,
            no_cache,
            verbose,
            update_remote_user_uid_default,
            &lockfile,
        )
        .await;
    }

    // Validate and translate runArgs, then secret references, before any
    // host-visible side effects: initializeCommand, existing-container reuse,
    // lockfile writes, image builds, and container creation must all see the
    // same decision. The recipe directory materialized above is the one write
    // that already happened.
    //
    // This intentionally uses config/default-user substitution here, before
    // image inspection. User-dependent HOME expansion can therefore differ
    // from the later mount/workspace substitution that uses image metadata.
    let run_args: Vec<String> = config
        .run_args
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| substitute_variables_with_user(s, workspace, config.remote_user.as_deref()))
        .collect();
    let resolved_run_args = crate::devcontainer::run_args::resolve_run_args(&run_args, workspace)?;
    reject_run_args_unsupported_by_runtime(runtime.runtime_name(), &resolved_run_args)?;

    // Read once per invocation, here rather than on the create path, so a bad
    // path or a bad document fails on the container-reuse path too.
    let secrets_file_env = match secrets_file {
        Some(path) => load_secrets_file(path)?,
        None => BTreeMap::new(),
    };

    // Parse every secret reference, reject unknown providers, and expand
    // devcontainer variables in the reference bodies and option values with the
    // same workspace and user the runArgs substitution above uses. No provider
    // is asked for a value yet: resolution is on the create path only.
    let secrets = validate_workspace_secrets(
        &config,
        &config_path,
        workspace,
        providers,
        secrets_override,
    )?;

    // Run initializeCommand on the host before anything else (Gap 9).
    if let Some(ref init_cmd) = config.initialize_command {
        run_initialize_command(init_cmd, workspace).await?;
    }

    let labels_list = workspace_labels(workspace, Some(&config_path));
    let filters: Vec<String> = labels_list
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mut existing = runtime.list_containers(&filters).await?;

    // Fallback: search by local_folder only for containers without config_file label.
    // This matches the official CLI's two-step lookup for backward compatibility.
    if existing.is_empty() && labels_list.len() > 1 {
        let fallback_filter = vec![format!("{}={}", labels_list[0].0, labels_list[0].1)];
        let fallback = runtime.list_containers(&fallback_filter).await?;
        for container in fallback {
            if !container.labels.contains_key("devcontainer.config_file") {
                existing.push(container);
            }
        }
    }

    // Handle existing container.
    // Port bindings are fixed at container creation time, so when --ports
    // is supplied we must recreate the container to apply the new mappings.
    let has_port_overrides = !port_overrides.is_empty();
    if let Some(container) = existing.first() {
        match container.state {
            ContainerState::Running if !rebuild && !has_port_overrides => {
                // Gated like every other exit that claims readiness. "Already
                // running" is a readiness claim, and the container this arm
                // reuses may be exactly the one a previous `dev up` refused:
                // the runtime leaves a container it started but cannot exec
                // into in the running state, so without the gate the first
                // `dev up` fails honestly and every later one hands the user a
                // green light for a container no command can run in.
                let user =
                    resolve_remote_user(runtime, &container.image, config.remote_user.as_deref())
                        .await?;
                let workspace_folder = config.workspace_folder_path(workspace, user.as_deref())?;
                verify_container_usable(
                    runtime,
                    &container.id,
                    workspace,
                    user.as_deref(),
                    Some(&workspace_folder),
                )
                .await?;
                // Same self-healing as the restart path below: a route set
                // edited in config (renamed host, added port) has no other
                // moment to reach Caddy, since a running container never takes
                // that path.
                register_caddy_routes(workspace, &config);
                println!("Container '{}' is already running.", container.name);
                return Ok(());
            }
            ContainerState::Stopped if !rebuild && !has_port_overrides => {
                println!("Starting existing container '{}'...", container.name);
                runtime.start_container(&container.id).await?;
                // Resolved before the gate, not just for the hooks: the probe
                // certifies the user every later command actually runs as.
                let user =
                    resolve_remote_user(runtime, &container.image, config.remote_user.as_deref())
                        .await?;
                let workspace_folder = config.workspace_folder_path(workspace, user.as_deref())?;
                verify_container_usable(
                    runtime,
                    &container.id,
                    workspace,
                    user.as_deref(),
                    Some(&workspace_folder),
                )
                .await?;
                // Only the start-time hooks: the create-time ones ran when this
                // container was created, and `postCreateCommand` is where
                // toolchains get installed and databases get seeded.
                let features = restart_feature_hooks(&config, &config_path).await?;
                run_start_hooks(
                    runtime,
                    &container.id,
                    &config,
                    user.as_deref(),
                    Some(&workspace_folder),
                    Some(&features),
                )
                .await?;
                // A plain `dev down` deletes the Caddy fragment but leaves the
                // container stopped, so restore the routes on restart (issue #52).
                register_caddy_routes(workspace, &config);
                println!("Container '{}' started.", container.name);
                return Ok(());
            }
            _ => {
                // Rebuild or port override: remove existing
                if has_port_overrides && !rebuild {
                    eprintln!(
                        "Recreating container '{}' to apply port overrides...",
                        container.name
                    );
                }
                if rebuild {
                    eprintln!("Removing existing container '{}'...", container.name);
                }
                if container.state == ContainerState::Running {
                    runtime.stop_container(&container.id).await?;
                }
                runtime.remove_container(&container.id).await?;
            }
        }
    }

    // Use the same image tag that `dev build` produces so we can reuse it.
    let initial_features = resolve_features(&config)?;
    let has_features = !initial_features.is_empty();
    let needs_build = config.build.is_some() || has_features;
    let folder_image = container_name(workspace);
    let final_tag = if has_features {
        feature_image_tag(&folder_image, &config, &initial_features)
    } else {
        folder_image.clone()
    };

    // Resolve the .devcontainer directory for local feature paths and lockfile.
    let devcontainer_dir: Option<PathBuf> = config_path.parent().map(|p| p.to_path_buf());

    // Track ordered features for later use (capabilities, lifecycle hooks).
    let mut ordered_features = Vec::new();

    let final_image = if !needs_build {
        // Image-based config with no features — use the image directly. If the
        // image is already present locally, skip the pull (mirrors the reference
        // devcontainer CLI, which inspects the local image before pulling).
        let image = config.image.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "devcontainer.json must specify 'image', 'build.dockerfile', or 'dockerComposeFile'"
            )
        })?;
        ensure_image_present(runtime, image).await?;
        image.clone()
    } else if !rebuild && !no_cache && runtime.image_exists(&final_tag).await? {
        // Image already built (e.g. by `dev build`), skip rebuild.
        eprintln!("Image '{final_tag}' already exists, skipping build.");
        final_tag
    } else {
        // Determine base image
        let base_image = if let Some(ref image) = config.image {
            ensure_image_present(runtime, image).await?;
            image.clone()
        } else if let Some(ref build) = config.build {
            let context_dir = config_path
                .parent()
                .unwrap()
                .join(build.context.as_deref().unwrap_or("."));
            let dockerfile_path = config_path.parent().unwrap().join(&build.dockerfile);
            let dockerfile_content = std::fs::read_to_string(&dockerfile_path)?;
            if !has_features {
                // No features — build directly with the final tag.
                eprintln!("Building image from Dockerfile...");
                runtime
                    .build_image(
                        &dockerfile_content,
                        &context_dir,
                        &final_tag,
                        &HashMap::new(),
                        no_cache,
                        verbose,
                    )
                    .await?;
                final_tag.clone()
            } else {
                eprintln!("Building image from Dockerfile...");
                runtime
                    .build_image(
                        &dockerfile_content,
                        &context_dir,
                        &folder_image,
                        &HashMap::new(),
                        no_cache,
                        verbose,
                    )
                    .await?;
                folder_image.clone()
            }
        } else {
            anyhow::bail!(
                "devcontainer.json must specify 'image', 'build.dockerfile', or 'dockerComposeFile'"
            );
        };

        // Handle features
        if has_features {
            let mut features = initial_features;
            let original_count = features.len();
            eprintln!("Downloading {} feature(s)...", original_count);
            if verbose {
                for f in &features {
                    eprintln!("  Feature: {} ({}:{})", f.id, f.oci_ref, f.version);
                }
            }
            download_features(&mut features, devcontainer_dir.as_deref()).await?;

            if features.len() > original_count {
                eprintln!(
                    "Resolved {} transitive dependencies",
                    features.len() - original_count
                );
            }

            // Lockfile handling (Gap 11).
            lockfile.apply(devcontainer_dir.as_deref(), &features)?;

            let ordered = order_features(&features);
            if verbose {
                eprintln!("Feature install order:");
                for (i, f) in ordered.iter().enumerate() {
                    eprintln!(
                        "  {}: {}{}",
                        i + 1,
                        f.id,
                        if f.is_dependency { " (dependency)" } else { "" }
                    );
                }
            }
            let staging_dir = stage_feature_context(&ordered)?;
            let feature_user =
                resolve_remote_user(runtime, &base_image, config.remote_user.as_deref()).await?;
            let dockerfile = generate_feature_dockerfile_with_opts(
                &base_image,
                &ordered,
                feature_user.as_deref(),
                &config,
            );
            if verbose {
                eprintln!("Features Dockerfile:\n{dockerfile}");
            }
            eprintln!("Building features image...");
            let result = runtime
                .build_image(
                    &dockerfile,
                    &staging_dir,
                    &final_tag,
                    &HashMap::new(),
                    no_cache,
                    verbose,
                )
                .await;
            let _ = std::fs::remove_dir_all(&staging_dir);
            result?;

            ordered_features = ordered;
        }

        final_tag
    };

    // Recover feature contributions against the image the features produced, before
    // the UID-remap layer below shadows `final_image` with a derived tag. On the
    // cache-hit path this restores mounts, entrypoints, capabilities, and lifecycle
    // hooks from the image's `devcontainer.metadata` label.
    let ordered_features =
        resolve_effective_features(runtime, &final_image, ordered_features, has_features).await?;
    let mut caps = merge_feature_capabilities(&ordered_features);
    apply_run_args_capabilities(&mut caps, &resolved_run_args);

    // Build container config
    let name = container_name(workspace);

    let mut labels = HashMap::new();
    for (k, v) in &labels_list {
        labels.insert(k.clone(), v.clone());
    }

    // Resolve only here, and only on the create path. Env reaches a container at
    // create, so a `dev up` that reuses a running container gains nothing from
    // resolving and costs a provider prompt every time.
    let resolved_secrets = resolve_create_time_secrets(&secrets, providers).await?;

    // Substitute devcontainer variables in env values
    let mut env = HashMap::new();
    env.insert("REMOTE_CONTAINERS".to_string(), "true".to_string());
    if let Some(ref container_env) = config.container_env {
        for (k, v) in container_env {
            env.insert(k.clone(), substitute_variables(v, workspace));
        }
    }
    if let Some(ref remote_env) = config.remote_env {
        for (k, v) in remote_env {
            env.insert(k.clone(), substitute_variables(v, workspace));
        }
    }
    // `--secrets-file` sits in the `remoteEnv` tier, so a `runArgs` env entry and
    // a resolved `secrets.json` secret both still outrank it.
    apply_secrets_to_env(
        &mut env,
        secrets_file_env.iter().map(|(k, v)| (k.as_str(), v)),
    );

    let ports: Vec<PortMapping> = config.forward_ports.clone().unwrap_or_default();
    let caddy_host_ports = caddy_ports_from_config(&config);

    // Resolve the effective remote user from config or image metadata.
    let effective_user =
        resolve_remote_user(runtime, &final_image, config.remote_user.as_deref()).await?;
    let remote_user = effective_user.as_deref();

    // Optionally build a UID-remapping layer to match host UID/GID.
    let final_image = if uid::should_remap_uid(&config, remote_user, update_remote_user_uid_default)
    {
        let image_meta = runtime.inspect_image_metadata(&final_image).await?;
        let image_user = image_meta.container_user.as_deref().unwrap_or("root");
        uid::build_uid_image(
            runtime,
            &final_image,
            &folder_image,
            remote_user.unwrap_or("root"),
            image_user,
            no_cache,
            verbose,
        )
        .await?
    } else {
        final_image
    };

    // Feature mounts first, then config mounts — the same feature-first order
    // capabilities use, so a project mount can override a feature's target.
    let mut mount_strings = feature_mount_strings(&ordered_features, workspace, remote_user);
    mount_strings.extend(substitute_mounts(
        config.mounts.as_deref().unwrap_or(&[]),
        workspace,
        remote_user,
    ));
    let mounts = parse_mounts(&mount_strings);

    let volume_strings: Vec<String> = config
        .volumes
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| substitute_variables_with_user(s, workspace, remote_user))
        .collect();
    let volumes = parse_volumes(&volume_strings);

    // `runArgs` env was validated before any side effects. Apply it after the
    // effective create-time env map. `run_args::resolve_run_args` already
    // matches Docker CLI precedence by loading all env-files before all
    // explicit --env/-e entries.
    for (k, v) in &resolved_run_args.env {
        env.insert(k.clone(), v.clone());
    }

    // Secrets last: highest precedence over containerEnv, remoteEnv, and both
    // `runArgs` env tiers. Nothing may be inserted into `env` below this line.
    apply_secrets_to_env(
        &mut env,
        resolved_secrets.iter().map(|(k, v)| (k.as_str(), v)),
    );

    let workspace_folder = config.workspace_folder_path(workspace, remote_user)?;

    let container_config = ContainerConfig {
        image: final_image,
        name: name.clone(),
        labels,
        env,
        mounts,
        volumes,
        ports,
        workspace_mount: Some(WorkspaceMount {
            source: workspace.to_path_buf(),
            target: config.workspace_mount_target(workspace, remote_user)?,
        }),
        workspace_folder: Some(workspace_folder.clone()),
        extra_args: vec![],
        entrypoint: {
            let eps = feature_entrypoints(&ordered_features);
            (!eps.is_empty()).then_some(eps)
        },
        init: caps.init,
        privileged: caps.privileged,
        cap_add: caps.cap_add,
        security_opt: caps.security_opt,
        userns_mode: resolved_run_args.userns_mode.clone(),
    };

    if !container_config.mounts.is_empty() {
        eprintln!(
            "Mounting {} bind mount(s)...",
            container_config.mounts.len()
        );
    }

    eprintln!("Creating container '{name}'...");
    let container_id = runtime.create_container(&container_config).await?;

    eprintln!("Starting container '{name}'...");
    runtime.start_container(&container_id).await?;
    verify_container_usable(
        runtime,
        &container_id,
        workspace,
        remote_user,
        Some(&workspace_folder),
    )
    .await?;

    // Run lifecycle hooks — feature hooks first, then config hooks (Gap 6).
    let feature_hooks = if ordered_features.is_empty() {
        None
    } else {
        Some(ordered_features.as_slice())
    };
    run_create_hooks(
        runtime,
        &container_id,
        &config,
        remote_user,
        Some(&workspace_folder),
        feature_hooks,
    )
    .await?;

    // Clone dotfiles if configured (Gap 15).
    if let Some(ref dotfiles) = config.dotfiles {
        install_dotfiles(runtime, &container_id, dotfiles, remote_user).await?;
    }

    println!("Container '{name}' is ready.");

    if !caddy_host_ports.is_empty()
        && let Err(e) = crate::caddy::register_site(workspace, &caddy_host_ports)
    {
        eprintln!("Warning: Caddy setup failed: {e}");
    }

    Ok(())
}

/// Which lifecycle hooks a compose service is owed.
#[derive(Debug, PartialEq, Eq)]
enum ComposeHooks {
    /// The container is new: the create-time hooks, then postStart.
    Create,
    /// The container existed and was started: postStart only.
    Start,
    /// The container was already running, so nothing started.
    None,
}

/// Decide from what was there before `compose up` ran.
///
/// Compose reattaches to an existing container and reports success either way,
/// so this is the only moment the distinction is visible. `--rebuild` recreates
/// the container, which makes it new.
fn compose_hooks_owed(running_before: bool, existed_before: bool, rebuild: bool) -> ComposeHooks {
    if rebuild || !existed_before {
        ComposeHooks::Create
    } else if running_before {
        ComposeHooks::None
    } else {
        ComposeHooks::Start
    }
}

/// Resolve the feature hooks a restarted container is owed.
///
/// The create path gets its ordered features from the image build it just ran.
/// A reused container builds nothing, so a `postStartCommand` declared by a
/// feature has to be resolved on its own. Projects without features skip this
/// entirely and keep an offline restart.
async fn restart_feature_hooks(
    config: &DevcontainerConfig,
    config_path: &Path,
) -> anyhow::Result<Vec<ResolvedFeature>> {
    let mut features = resolve_features(config)?;
    if features.is_empty() {
        return Ok(features);
    }
    let devcontainer_dir = config_path.parent();
    download_features(&mut features, devcontainer_dir).await?;
    Ok(order_features(&features))
}

fn config_file_declares_run_args(config_path: &Path) -> anyhow::Result<bool> {
    let raw = std::fs::read_to_string(config_path)?;
    let value = crate::devcontainer::jsonc::parse_jsonc(&raw)?;
    Ok(project_declares_run_args(&value))
}

fn project_declares_run_args(value: &serde_json::Value) -> bool {
    value
        .get("runArgs")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|args| !args.is_empty())
}

fn reject_project_run_args_for_compose(
    config: &DevcontainerConfig,
    project_declared_run_args: bool,
) -> anyhow::Result<()> {
    let has_effective_run_args = config
        .run_args
        .as_ref()
        .is_some_and(|args| !args.is_empty());
    if config.is_compose() && project_declared_run_args && has_effective_run_args {
        anyhow::bail!(
            "`runArgs` is not supported for Docker Compose devcontainers in `dev`; Compose has no global container-create argument channel. Put equivalent options on the configured Compose service definition instead."
        );
    }
    Ok(())
}

/// Parse, provider-check, and variable-substitute this invocation's references
/// file — the explicit `--secrets` path when given, otherwise the `secrets.json`
/// beside `config_path`. Exactly one of the two is read, never both. No provider
/// is asked for a value, so this is safe to call before any side effect.
fn validate_workspace_secrets(
    config: &DevcontainerConfig,
    config_path: &Path,
    workspace: &Path,
    providers: &ProviderRegistry,
    secrets_override: Option<&Path>,
) -> anyhow::Result<ValidatedSecrets> {
    let path = secrets_file_path(secrets_override, config_path)?;
    Ok(validate_secrets_at(
        path,
        workspace,
        config.remote_user.as_deref(),
        providers,
    )?)
}

/// Resolve the create-time secrets for this `dev up`.
///
/// Create-path only. Env reaches a container at create, so resolving during a
/// `dev up` that reuses a running container buys nothing and costs a biometric
/// prompt every time. `createTime: false` entries are exec-time only and are
/// filtered out by `create_time_entries`.
///
/// The empty case returns before the registry is touched, so "no secrets means
/// no provider call" holds by construction.
async fn resolve_create_time_secrets(
    secrets: &ValidatedSecrets,
    providers: &ProviderRegistry,
) -> anyhow::Result<Vec<(String, SecretValue)>> {
    let refs: Vec<_> = secrets.create_time_entries().cloned().collect();
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    Ok(providers.resolve_all(&refs).await?)
}

/// Apply resolved secrets on top of the create-time env map.
///
/// Last, so a secret outranks `containerEnv`, `remoteEnv`, and both `runArgs`
/// env tiers. Anything inserted into `env` after this call would silently
/// shadow a live secret with a stale one.
/// Write resolved values into the create-time env map. Which tier that lands in
/// is the call site's business; see the two calls in
/// `run_with_runtime_with_providers`.
fn apply_secrets_to_env<'a>(
    env: &mut HashMap<String, String>,
    secrets: impl IntoIterator<Item = (&'a str, &'a SecretValue)>,
) {
    for (key, value) in secrets {
        env.insert(key.to_string(), value.expose().to_string());
    }
}

/// Load the flat `{ "KEY": "literal value" }` document `dev up --secrets-file`
/// takes, matching `devcontainers/cli`.
///
/// Deliberately shares nothing with the `secrets.json` loader: that document
/// carries references and this one carries values. Neither ever sees the
/// other's shape, so nothing has to sniff a document to decide what it is. A
/// value that looks like a reference is still a literal — no provider is
/// consulted and no reference parser is called on anything from this file.
///
/// Parses to `serde_json::Value` and type-checks by hand: deserializing
/// straight into a `String` map would render a mismatch through serde's
/// `Unexpected`, which prints the offending scalar into the error text.
fn load_secrets_file(path: &Path) -> anyhow::Result<BTreeMap<String, SecretValue>> {
    let bytes = std::fs::read(path).map_err(|e| {
        DevError::InvalidConfig(format!(
            "failed to read `--secrets-file` `{}`: {e}",
            path.display()
        ))
    })?;
    let body = std::str::from_utf8(&bytes).map_err(|_| {
        DevError::InvalidConfig(format!(
            "`--secrets-file` `{}` is not valid UTF-8",
            path.display()
        ))
    })?;
    secrets_file_object(path, body)?
        .iter()
        .map(|(key, value)| secrets_file_entry(path, key, value))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(Into::into)
}

/// The top level must be an object. An array, a scalar, or a bare string is
/// rejected without its contents reaching the message.
fn secrets_file_object(
    path: &Path,
    body: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, DevError> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        DevError::InvalidConfig(format!(
            "`--secrets-file` `{}` is not valid JSON: {e}",
            path.display()
        ))
    })?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(DevError::InvalidConfig(format!(
            "`--secrets-file` `{}` must be a JSON object mapping environment variable names to string values",
            path.display()
        ))),
    }
}

/// One entry: a usable environment variable name and a string value. This is
/// what rejects a references document — `version` is a number and `secrets` is
/// an object, so both fail on their value, not on their name.
fn secrets_file_entry(
    path: &Path,
    key: &str,
    value: &serde_json::Value,
) -> Result<(String, SecretValue), DevError> {
    if let Some(reason) = env_name_problem(key) {
        return Err(DevError::InvalidConfig(format!(
            "`--secrets-file` `{}`: `{key}` is not a valid environment variable name: {reason}",
            path.display()
        )));
    }
    let text = value.as_str().ok_or_else(|| {
        DevError::InvalidConfig(format!(
            "`--secrets-file` `{}`: the value for `{key}` is not a string. This flag takes literal values; a `secrets.json` references document goes to `--secrets`",
            path.display()
        ))
    })?;
    Ok((key.to_string(), SecretValue::new(text)))
}

/// Compose writes its environment into a generated override file on disk, which
/// is the one thing `dev` promises never to do with a secret value. Say so
/// rather than accepting the flag and writing the values out.
fn reject_secrets_file_for_compose(secrets_file: Option<&Path>) -> anyhow::Result<()> {
    if let Some(path) = secrets_file {
        anyhow::bail!(
            "`--secrets-file` is not supported for Docker Compose devcontainers in `dev`; Compose environment is written to a generated override file on disk, and `dev` never writes a secret value to disk. Remove `--secrets-file {}` and put the equivalent values on the configured Compose service definition (`environment:` or `env_file:`).",
            path.display()
        );
    }
    Ok(())
}

/// Compose creates its containers through `docker compose up`, so nothing on
/// that path injects create-time secrets. Say so instead of leaving a container
/// that comes up green and misbehaves later with the secrets missing.
///
/// `createTime: false` entries pass. They are never injected at create on any
/// runtime; `dev exec` and `dev shell` resolve them per invocation and pass them
/// on the exec itself, which is a path Compose shares. The generated override
/// file never sees them, so the "no secret value reaches disk" rule holds.
///
/// Non-compose configs pass, so this is safe to call without a caller-side
/// `is_compose()` guard. An empty `secrets` map declares nothing and passes too,
/// matching the empty `runArgs` array rule above.
fn reject_secrets_for_compose(
    config: &DevcontainerConfig,
    secrets: &ValidatedSecrets,
) -> anyhow::Result<()> {
    if !config.is_compose() {
        return Ok(());
    }
    let Some(path) = secrets.source() else {
        return Ok(());
    };
    let create_time: Vec<&str> = secrets.create_time_entries().map(|r| r.key()).collect();
    if create_time.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "create-time secrets are not supported for Docker Compose devcontainers in `dev`; they are injected as container environment when `dev` creates the container, and the Compose path creates containers through `docker compose up` instead. In {}, either add `\"createTime\": false` to {} so the value is injected on `dev exec` and `dev shell` instead, or put the equivalent values on the configured Compose service definition (`environment:` or `env_file:`).",
        path.display(),
        create_time.join(", ")
    );
}

/// `--secrets` replaces the sidecar for one `dev up`, and the Compose path has
/// no create-time injection for it to feed. Refusing it is what keeps the flag
/// from reading as a working override: `dev exec` and `dev shell` rediscover the
/// sidecar per invocation and would never see the named file.
fn reject_secrets_override_for_compose(secrets_override: Option<&Path>) -> anyhow::Result<()> {
    if let Some(path) = secrets_override {
        anyhow::bail!(
            "`--secrets` is not supported for Docker Compose devcontainers in `dev`; `dev up` injects create-time secrets when it creates the container, and the Compose path creates containers through `docker compose up` instead. Remove `--secrets {}`; exec-time secrets come from the `secrets.json` beside the config, which `dev exec` and `dev shell` read on every invocation.",
            path.display()
        );
    }
    Ok(())
}

fn reject_run_args_unsupported_by_runtime(
    runtime_name: &str,
    resolved: &crate::devcontainer::run_args::ResolvedRunArgs,
) -> anyhow::Result<()> {
    if runtime_name != "apple" {
        return Ok(());
    }

    let mut unsupported = Vec::new();
    if !resolved.cap_add.is_empty() {
        unsupported.push("--cap-add");
    }
    if !resolved.security_opt.is_empty() {
        unsupported.push("--security-opt");
    }
    if resolved.userns_mode.is_some() {
        unsupported.push("--userns");
    }
    if resolved.privileged {
        unsupported.push("--privileged");
    }
    if resolved.init {
        unsupported.push("--init");
    }

    if !unsupported.is_empty() {
        anyhow::bail!(
            "`runArgs` flag(s) {} are not supported when the selected runtime is Apple Containers; Apple currently supports only the environment `runArgs` subset (`--env-file`, `--env`, and `-e`). Remove these flags or use runtime-supported devcontainer settings.",
            unsupported.join(", ")
        );
    }
    Ok(())
}

fn apply_run_args_capabilities(
    caps: &mut MergedCapabilities,
    resolved: &crate::devcontainer::run_args::ResolvedRunArgs,
) {
    caps.init |= resolved.init;
    caps.privileged |= resolved.privileged;
    extend_unique(&mut caps.cap_add, &resolved.cap_add);
    extend_unique(&mut caps.security_opt, &resolved.security_opt);
}

fn extend_unique(out: &mut Vec<String>, additions: &[String]) {
    for value in additions {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
}

/// How long to give the runtime to report a just-started container as running.
///
/// Generous because a VM-backed runtime boots a guest before the daemon settles
/// on `Running`; the polls back off so a healthy container is still confirmed
/// in the first hundred milliseconds.
const READINESS_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);
const READINESS_FIRST_POLL: std::time::Duration = std::time::Duration::from_millis(100);
const READINESS_MAX_POLL: std::time::Duration = std::time::Duration::from_secs(1);
/// The least budget an attempt is worth starting with, so a bounded one is
/// never handed a window too short to reach the runtime at all.
const READINESS_MIN_ATTEMPT: std::time::Duration = std::time::Duration::from_millis(250);

/// The retry schedule every part of the readiness gate follows.
///
/// Both halves are asking the same question — is this runtime settled yet? — so
/// both wait the same way. A one-shot check next to a patient one would fail a
/// healthy container on whichever half happened to run first.
struct ReadinessPolls {
    deadline: tokio::time::Instant,
    next: std::time::Duration,
}

impl ReadinessPolls {
    fn until(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            next: READINESS_FIRST_POLL,
        }
    }

    /// Wait before the next attempt, or report that the budget is spent.
    ///
    /// An attempt is only granted when enough budget remains to actually make
    /// one. Sleeping right up to the deadline and reporting another attempt
    /// would hand it a zero-length window: a caller that bounds its work by
    /// [`Self::remaining`] would then time out before the runtime was polled
    /// even once, and report that as the runtime's failure rather than the
    /// real one the previous attempts found.
    async fn wait(&mut self) -> bool {
        let left = self
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if left <= READINESS_MIN_ATTEMPT {
            return false;
        }
        tokio::time::sleep(self.next.min(left - READINESS_MIN_ATTEMPT)).await;
        self.next = (self.next * 2).min(READINESS_MAX_POLL);
        true
    }

    /// What is left of the budget, for bounding an attempt rather than the gap
    /// between two of them.
    ///
    /// Never shorter than [`READINESS_MIN_ATTEMPT`]. Phases share one deadline,
    /// so a phase can start with the budget an earlier one already spent: its
    /// first attempt would then be handed a zero-length window and report the
    /// runtime as unresponsive without ever having asked it. [`Self::wait`]
    /// declines to grant *later* attempts that short, so this floor only ever
    /// applies to a phase's first one.
    fn remaining(&self) -> std::time::Duration {
        self.deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .max(READINESS_MIN_ATTEMPT)
    }
}

/// Confirm a just-started container is running, findable by the same
/// workspace-label query `dev status`/`dev exec` use, *and* able to run a
/// command.
///
/// A successful create/start call is not proof of any of the three: issue #4
/// was a container that `dev up` had started but that neither command could
/// find, and whose create → start → wait sequence could not run a command even
/// once it was found. Reporting readiness is gated on this check so `dev up`
/// and the commands that follow it can never disagree.
async fn verify_container_usable(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    workspace: &Path,
    remote_user: Option<&str>,
    workdir: Option<&str>,
) -> anyhow::Result<()> {
    verify_container_usable_until(
        runtime,
        container_id,
        workspace,
        remote_user,
        workdir,
        tokio::time::Instant::now() + READINESS_BUDGET,
    )
    .await
}

async fn verify_container_usable_until(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    workspace: &Path,
    remote_user: Option<&str>,
    workdir: Option<&str>,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    verify_container_discoverable_until(runtime, container_id, workspace, deadline).await?;
    verify_container_execs_until(runtime, container_id, remote_user, workdir, deadline).await
}

/// Run one trivial command in the container, the way every later command does.
///
/// Discovery and a `Running` state only prove `dev exec` can *locate* the
/// container. A config with no lifecycle hooks and no dotfiles never execs
/// anything else during `dev up`, so without this a container whose exec path
/// is broken — the other half of issue #4 — would still be announced as ready
/// and only fail the first time the user asked it to do something.
///
/// What is being certified is the runtime's create → start → wait sequence, not
/// the image's contents. A reply of any exit status means that sequence works,
/// which is what `dev exec` needs; only a runtime that cannot run a process at
/// all fails the gate. So a scratch or distroless image with no shell is
/// reported and allowed through, while the hang and the lost exit status behind
/// issue #4 are not.
///
/// The probe runs as the resolved `remoteUser`, since that is who lifecycle
/// hooks, `dev exec` and `dev shell` run as — certifying root instead would
/// pass for a config whose user does not exist in the image.
///
/// The call itself is bounded by what remains of the readiness budget, not just
/// the gap between attempts. Issue #4's symptom was a `containerWait` the daemon
/// dropped, which leaves the exec awaiting an exit that never comes — so a gate
/// that only paced its retries would hang on the very failure it exists to
/// catch, with `dev up` silent after "Starting container...".
async fn verify_container_execs_until(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    remote_user: Option<&str>,
    workdir: Option<&str>,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    let probe = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
    let mut polls = ReadinessPolls::until(deadline);
    // The last attempt's outcome is the diagnosis, because it describes the
    // state the container is actually in now. An earlier refusal is kept as
    // context rather than as the headline: a runtime that refused while its
    // exec endpoint was still coming up and then stopped answering altogether
    // is a hang, and reporting the stale refusal would name the wrong symptom
    // for precisely the bug this gate exists to catch.
    let mut refusal: Option<String> = None;

    loop {
        let window = polls.remaining();
        let attempt = tokio::time::timeout(
            window,
            runtime.exec(container_id, &probe, remote_user, workdir, &[]),
        )
        .await;

        let latest = match attempt {
            // A process that ran to completion proves the create → start → wait
            // sequence works, whatever status it reported — and that sequence
            // is the whole of what this gate certifies. The status belongs to
            // the image, so it is passed on as it actually is.
            Ok(Ok(result)) => {
                if result.exit_code != 0 {
                    warn_probe_exited_non_zero(container_id, remote_user, &result);
                }
                return Ok(());
            }
            Ok(Err(e)) if runtime.exec_reports_missing_command(&e) => {
                warn_probe_command_missing(container_id, &e.to_string());
                return Ok(());
            }
            Ok(Err(e)) => {
                refusal = Some(e.to_string());
                e.to_string()
            }
            Err(_) => format!(
                "it did not report an exit within {:.1}s",
                window.as_secs_f64()
            ),
        };

        if !polls.wait().await {
            anyhow::bail!(
                "Container '{container_id}' was started and is running, but no command can be \
                 run in it: {}. `dev exec`, `dev shell` and lifecycle hooks would all \
                 fail the same way.",
                probe_diagnosis(&latest, refusal)
            );
        }
    }
}

/// What to tell the user the probe found, newest signal first.
///
/// The last attempt describes the container as it stands. When an earlier
/// attempt was refused and the last one merely ran out of window, both are
/// worth having: the timeout is what is happening, the refusal is what the
/// runtime last said about why. `refusal` is the most recent one rather than
/// the first — a runtime that refuses its way through several distinct errors
/// before hanging is best described by the last thing it managed to say.
fn probe_diagnosis(latest: &str, refusal: Option<String>) -> String {
    match refusal {
        Some(refusal) if refusal != latest => {
            format!("{latest} (an earlier attempt was refused: {refusal})")
        }
        _ => latest.to_string(),
    }
}

/// Report a probe that ran and exited non-zero, saying what that status means.
///
/// The runtime is fine — it ran the process and reported its exit — so this is
/// a warning, not a readiness failure. What went wrong is worth getting right:
/// 127 and 126 are different problems, and calling a permission problem a
/// missing shell sends the user looking in the wrong place.
fn warn_probe_exited_non_zero(container_id: &str, remote_user: Option<&str>, result: &ExecResult) {
    let as_user = match remote_user {
        Some(user) => format!(" as user '{user}'"),
        None => String::new(),
    };
    let diagnosis = match result.exit_code {
        127 => "no `sh` was found in it".to_string(),
        126 => "`sh` is present but could not be executed — check its mode and whether this \
                user may run it"
            .to_string(),
        code => format!("`sh -c 'exit 0'` exited {code}"),
    };
    let reported = match result.stderr.trim() {
        "" => String::new(),
        stderr => format!(" The runtime reported: {stderr}"),
    };
    eprintln!(
        "Warning: container '{container_id}' runs commands{as_user}, but {diagnosis}. \
         Lifecycle hooks, `dev exec` and `dev shell` will fail the same way.{reported}"
    );
}

/// Report a runtime that declined to run the probe because the image has no
/// such command.
fn warn_probe_command_missing(container_id: &str, reason: &str) {
    eprintln!(
        "Warning: container '{container_id}' accepts commands but has no usable shell ({reason}). \
         Lifecycle hooks, `dev exec` and `dev shell` need one."
    );
}

/// Confirm a just-started container is actually running *and* findable by the
/// same workspace-label query `dev status`/`dev exec` use.
///
/// A failing list is retried like a missing one: this runs in the window where
/// a VM-backed runtime is still settling, so its list call is the most likely
/// thing to fail transiently, and aborting a healthy `dev up` on the first such
/// blip is exactly the spurious failure this gate must not introduce. The last
/// error is only surfaced once the budget is spent.
///
/// Each list is bounded by what remains of the budget, for the same reason the
/// exec probe is: on a VM-backed runtime the list is a synchronous daemon call
/// with no deadline of its own, so a dropped reply here is the same silent hang
/// issue #4 is about. Pacing the gaps between polls would never reach the next
/// one, and `dev up` would sit forever after "Starting container...".
async fn verify_container_discoverable_until(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    workspace: &Path,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    let filters: Vec<String> = workspace_labels(workspace, None)
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    let mut polls = ReadinessPolls::until(deadline);
    // Assigned by every poll, so only the final one's outcome is reported.
    let mut last_error;
    let last_state = loop {
        let window = polls.remaining();
        let listed = tokio::time::timeout(window, runtime.list_containers(&filters)).await;
        let state = match listed {
            Ok(Ok(found)) => {
                // A poll that answered clears the last failure: only a runtime
                // still failing at the deadline may claim the diagnosis, or an
                // early blip masks the not-discoverable report this gate exists
                // to produce.
                last_error = None;
                match found.iter().find(|c| same_container(&c.id, container_id)) {
                    Some(c) if c.state == ContainerState::Running => return Ok(()),
                    Some(c) => Some(c.state.clone()),
                    None => None,
                }
            }
            Ok(Err(e)) => {
                last_error = Some(e.to_string());
                None
            }
            Err(_) => {
                last_error = Some(format!(
                    "it did not answer within {:.1}s",
                    window.as_secs_f64()
                ));
                None
            }
        };

        if !polls.wait().await {
            break state;
        }
    };

    match (last_state, last_error) {
        (Some(state), _) => anyhow::bail!(
            "Container '{container_id}' was started but is {state:?}, not running. \
             Check the runtime's logs for why its init process exited."
        ),
        (None, Some(e)) => anyhow::bail!(
            "Container '{container_id}' was started but the runtime could not be asked \
             whether it is running: {e}"
        ),
        (None, None) => anyhow::bail!(
            "Container '{container_id}' was started but is not discoverable by the \
             workspace labels `dev status` and `dev exec` search for ({}). \
             The container exists but no command can reach it.",
            filters.join(", ")
        ),
    }
}

/// Compare a listed container id with the one create returned.
///
/// Runtimes are inconsistent about returning full or shortened ids, so a
/// prefix match on either side counts as the same container.
fn same_container(listed: &str, created: &str) -> bool {
    !listed.is_empty()
        && !created.is_empty()
        && (listed.starts_with(created) || created.starts_with(listed))
}

fn apply_cli_overrides(
    config: &mut DevcontainerConfig,
    port_overrides: &[String],
) -> anyhow::Result<()> {
    if !port_overrides.is_empty() {
        config.forward_ports = Some(parse_port_overrides(port_overrides)?);
    }
    Ok(())
}

/// Ensure a container image is present locally, pulling it only if missing.
///
/// Mirrors the reference devcontainer CLI behavior: inspect the local image
/// first and pull only when it is not already present. The progress message is
/// printed *before* the pull starts so the user is not left staring at a silent
/// prompt during a potentially long network pull.
pub(crate) async fn ensure_image_present(
    runtime: &dyn ContainerRuntime,
    image: &str,
) -> anyhow::Result<()> {
    if runtime.image_exists(image).await? {
        eprintln!("Using local image '{image}'...");
    } else {
        eprintln!("Pulling image '{image}'...");
        runtime.pull_image(image).await?;
    }
    Ok(())
}

/// Resolve the container capabilities contributed by features.
///
/// On the build path `ordered_features` is populated and is authoritative. On the
/// cache-hit path the features are never resolved, so recover them from the
/// `devcontainer.metadata` label the build wrote onto the image — otherwise a container
/// recreated from a cached image silently loses feature mounts, entrypoints,
/// capabilities, and lifecycle hooks, and a docker-in-docker daemon cannot start.
async fn resolve_effective_features(
    runtime: &dyn ContainerRuntime,
    image: &str,
    ordered_features: Vec<ResolvedFeature>,
    has_features: bool,
) -> anyhow::Result<Vec<ResolvedFeature>> {
    if !ordered_features.is_empty() {
        return Ok(ordered_features);
    }
    if !has_features {
        return Ok(Vec::new());
    }

    // Features were configured but not resolved, so this is the cache-hit path.
    let meta = runtime.inspect_image_metadata(image).await?;
    if meta.metadata_entries.is_empty() {
        eprintln!(
            "Warning: image '{image}' has no devcontainer metadata, so feature \
             contributions (mounts, entrypoints, capabilities, lifecycle hooks) \
             cannot be restored. Run 'dev up --rebuild' to rebuild it."
        );
        return Ok(Vec::new());
    }

    Ok(features_from_metadata(&meta.metadata_entries))
}

/// Run the `initializeCommand` on the host machine (Gap 9).
async fn run_initialize_command(
    cmd: &crate::devcontainer::config::LifecycleCommand,
    workspace: &Path,
) -> anyhow::Result<()> {
    use crate::devcontainer::config::LifecycleCommand;

    async fn run_one(command: &str, workspace: &Path) -> anyhow::Result<()> {
        eprintln!("[lifecycle] Running initializeCommand: {command}");
        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(workspace)
            .status()
            .await?;
        if !output.success() {
            anyhow::bail!(
                "initializeCommand failed (exit {}): {command}",
                output.code().unwrap_or(-1)
            );
        }
        Ok(())
    }

    match cmd {
        LifecycleCommand::Single(command) => {
            run_one(command, workspace).await?;
        }
        LifecycleCommand::Multiple(commands) => {
            for command in commands {
                run_one(command, workspace).await?;
            }
        }
        LifecycleCommand::Parallel(commands) => {
            for command in commands.values() {
                run_one(command, workspace).await?;
            }
        }
    }

    Ok(())
}

/// Clone and install dotfiles in the container (Gap 15).
async fn install_dotfiles(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    dotfiles: &crate::devcontainer::config::DotfilesConfig,
    user: Option<&str>,
) -> anyhow::Result<()> {
    let target = dotfiles.target_path.as_deref().unwrap_or("~/dotfiles");

    eprintln!("Cloning dotfiles from {}...", dotfiles.repository);

    // Clone the dotfiles repo
    let clone_cmd = format!(
        "git clone --depth 1 '{}' '{}'",
        dotfiles.repository.replace('\'', "'\\''"),
        target.replace('\'', "'\\''"),
    );
    let args = vec!["sh".to_string(), "-c".to_string(), clone_cmd];
    let result = runtime.exec(container_id, &args, user, None, &[]).await?;
    if result.exit_code != 0 {
        eprintln!(
            "Warning: failed to clone dotfiles (exit {}):\n{}",
            result.exit_code, result.stderr
        );
        return Ok(());
    }

    // Run the install command if specified
    if let Some(ref install_cmd) = dotfiles.install_command {
        eprintln!("Running dotfiles install command: {install_cmd}");
        let args = vec!["sh".to_string(), "-c".to_string(), install_cmd.clone()];
        let result = runtime.exec(container_id, &args, user, None, &[]).await?;
        if result.exit_code != 0 {
            eprintln!(
                "Warning: dotfiles install command failed (exit {}):\n{}",
                result.exit_code, result.stderr
            );
        }
    }

    Ok(())
}

/// Handle a Docker Compose-based devcontainer config.
///
/// Full pipeline: build the service, layer features on top, UID-remap,
/// generate a compose override injecting labels/env/mounts/ports/image,
/// start services, run lifecycle hooks, install dotfiles.
#[allow(clippy::too_many_arguments)]
async fn run_compose(
    workspace: &Path,
    config: &DevcontainerConfig,
    config_path: &Path,
    runtime: &dyn ContainerRuntime,
    rebuild: bool,
    no_cache: bool,
    verbose: bool,
    update_remote_user_uid_default: &str,
    lockfile: &LockfilePolicy,
) -> anyhow::Result<()> {
    let compose_data = config.docker_compose_file.as_ref().unwrap();
    let compose_files = compose_data.files();
    let devcontainer_dir = config_path.parent().unwrap();
    let devcontainer_dir_buf: Option<PathBuf> = Some(devcontainer_dir.to_path_buf());
    let service = config
        .service
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Docker Compose config must specify 'service'"))?;
    let project_name = container_name(workspace);
    let folder_image = container_name(workspace);
    let runtime_name = runtime.runtime_name();

    // Workspace-related env vars for Docker Compose variable interpolation.
    // Compose files use ${localWorkspaceFolder}, ${localWorkspaceFolderBasename},
    // etc. in volume paths and other settings. These must be set as process env
    // vars so `docker compose` resolves them when parsing the compose file.
    let folder_name = workspace_folder_name(workspace);
    let workspace_source = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let workspace_target = substitute_variables(
        config
            .workspace_folder
            .as_deref()
            .unwrap_or(&format!("/workspaces/{folder_name}")),
        workspace,
    );
    let mut compose_env = HashMap::new();
    compose_env.insert(
        "localWorkspaceFolder".to_string(),
        workspace_source.to_string_lossy().to_string(),
    );
    compose_env.insert(
        "localWorkspaceFolderBasename".to_string(),
        folder_name.clone(),
    );
    compose_env.insert(
        "containerWorkspaceFolder".to_string(),
        workspace_target.clone(),
    );

    // 1. initializeCommand
    if let Some(ref init_cmd) = config.initialize_command {
        run_initialize_command(init_cmd, workspace).await?;
    }

    // 2. Always build the service (features need the base image).
    eprintln!("Building compose services...");
    crate::runtime::compose::compose_build(
        runtime_name,
        &compose_files,
        devcontainer_dir,
        Some(service),
        no_cache,
        verbose,
        &compose_env,
    )
    .await?;

    // 3. Get the built service image name.
    let base_image = crate::runtime::compose::compose_service_image(
        runtime_name,
        &compose_files,
        devcontainer_dir,
        &project_name,
        service,
        &compose_env,
    )
    .await?;
    if verbose {
        eprintln!("Service image: {base_image}");
    }

    // 4. Feature pipeline.
    let initial_features = resolve_features(config)?;
    let has_features = !initial_features.is_empty();
    let mut ordered_features = Vec::new();

    let featured_image = if has_features {
        let mut features = initial_features;
        let original_count = features.len();
        eprintln!("Downloading {} feature(s)...", original_count);
        if verbose {
            for f in &features {
                eprintln!("  Feature: {} ({}:{})", f.id, f.oci_ref, f.version);
            }
        }
        download_features(&mut features, devcontainer_dir_buf.as_deref()).await?;

        if features.len() > original_count {
            eprintln!(
                "Resolved {} transitive dependencies",
                features.len() - original_count
            );
        }

        // Lockfile handling.
        lockfile.apply(devcontainer_dir_buf.as_deref(), &features)?;

        let ordered = order_features(&features);
        if verbose {
            eprintln!("Feature install order:");
            for (i, f) in ordered.iter().enumerate() {
                eprintln!(
                    "  {}: {}{}",
                    i + 1,
                    f.id,
                    if f.is_dependency { " (dependency)" } else { "" }
                );
            }
        }

        let staging_dir = stage_feature_context(&ordered)?;
        let feature_user =
            resolve_remote_user(runtime, &base_image, config.remote_user.as_deref()).await?;
        let feature_tag = feature_image_tag(&folder_image, config, &ordered);
        let dockerfile = generate_feature_dockerfile_with_opts(
            &base_image,
            &ordered,
            feature_user.as_deref(),
            config,
        );
        if verbose {
            eprintln!("Features Dockerfile:\n{dockerfile}");
        }
        eprintln!("Building features image...");
        let result = runtime
            .build_image(
                &dockerfile,
                &staging_dir,
                &feature_tag,
                &HashMap::new(),
                no_cache,
                verbose,
            )
            .await;
        let _ = std::fs::remove_dir_all(&staging_dir);
        result.map_err(|e| anyhow::anyhow!("{e}"))?;

        ordered_features = ordered;
        feature_tag
    } else {
        base_image.clone()
    };

    // 5. Resolve remote user from the final image.
    let effective_user =
        resolve_remote_user(runtime, &featured_image, config.remote_user.as_deref()).await?;
    let remote_user = effective_user.as_deref();

    // 6. UID remapping.
    let final_image = if uid::should_remap_uid(config, remote_user, update_remote_user_uid_default)
    {
        let image_meta = runtime
            .inspect_image_metadata(&featured_image)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let image_user = image_meta.container_user.as_deref().unwrap_or("root");
        uid::build_uid_image(
            runtime,
            &featured_image,
            &folder_image,
            remote_user.unwrap_or("root"),
            image_user,
            no_cache,
            verbose,
        )
        .await?
    } else {
        featured_image
    };

    let image_override = if final_image != base_image {
        Some(final_image.as_str())
    } else {
        None
    };

    // 7. Variable substitution on env, mounts, volumes.
    let mut env = HashMap::new();
    env.insert("REMOTE_CONTAINERS".to_string(), "true".to_string());
    if let Some(ref container_env) = config.container_env {
        for (k, v) in container_env {
            env.insert(
                k.clone(),
                substitute_variables_with_user(v, workspace, remote_user),
            );
        }
    }
    if let Some(ref remote_env) = config.remote_env {
        for (k, v) in remote_env {
            env.insert(
                k.clone(),
                substitute_variables_with_user(v, workspace, remote_user),
            );
        }
    }

    let mut mounts = feature_mount_strings(&ordered_features, workspace, remote_user);
    mounts.extend(substitute_mounts(
        config.mounts.as_deref().unwrap_or(&[]),
        workspace,
        remote_user,
    ));

    let volume_strings: Vec<String> = config
        .volumes
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| substitute_variables_with_user(s, workspace, remote_user))
        .collect();

    let ports: Vec<PortMapping> = config.forward_ports.clone().unwrap_or_default();
    let caddy_host_ports_compose = caddy_ports_from_config(config);

    // 8. Labels + merged feature capabilities.
    let labels_list = workspace_labels(workspace, Some(config_path));
    let caps = merge_feature_capabilities(&ordered_features);

    // 9. Generate and write compose override file.
    let override_content = crate::runtime::compose::generate_compose_override(
        service,
        &labels_list,
        &env,
        &mounts,
        &volume_strings,
        &ports,
        image_override,
        &caps,
        &feature_entrypoints(&ordered_features),
    );
    let override_path = crate::runtime::compose::write_override_file(&override_content)?;
    let override_path_str = override_path.to_string_lossy().to_string();
    if verbose {
        eprintln!("Compose override:\n{override_content}");
    }

    // 10. Rewrite compose file volume sources so `..` resolves to the actual
    //     workspace instead of ~/.dev/devcontainers/. Use rewritten files for
    //     compose_up (not compose_build, which needs original paths for Dockerfiles).
    let mut rewritten_paths = Vec::new();
    let mut up_files: Vec<String> = Vec::new();
    for f in &compose_files {
        let compose_path = if Path::new(f).is_absolute() {
            PathBuf::from(f)
        } else {
            devcontainer_dir.join(f)
        };
        match crate::runtime::compose::rewrite_compose_volumes(&compose_path, workspace) {
            Ok(rewritten) => {
                up_files.push(rewritten.to_string_lossy().to_string());
                rewritten_paths.push(rewritten);
            }
            Err(_) => {
                // Fall back to original if rewrite fails.
                up_files.push(compose_path.to_string_lossy().to_string());
            }
        }
    }
    up_files.push(override_path_str.clone());
    let up_file_refs: Vec<&str> = up_files.iter().map(|s| s.as_str()).collect();

    // Compose reattaches to an existing container instead of reporting that it
    // did so, so the only way to tell creation from reuse is to look before it
    // runs. `--rebuild` recreates the container, which makes it new again.
    let probe = |include_stopped| {
        crate::runtime::compose::compose_container_id(
            runtime_name,
            &up_file_refs,
            devcontainer_dir,
            &project_name,
            service,
            include_stopped,
        )
    };
    let running_before = probe(false).await.is_ok();
    let existed_before = running_before || probe(true).await.is_ok();
    let owed = compose_hooks_owed(running_before, existed_before, rebuild);

    eprintln!("Starting compose services...");
    crate::runtime::compose::compose_up(
        runtime_name,
        &up_file_refs,
        devcontainer_dir,
        &project_name,
        &compose_env,
        verbose,
        rebuild,
    )
    .await?;

    // 11. Get container ID.
    let container_id = crate::runtime::compose::compose_container_id(
        runtime_name,
        &up_file_refs,
        devcontainer_dir,
        &project_name,
        service,
        false,
    )
    .await?;

    // 12. Wait until the resolved target service container is usable before
    //     lifecycle hooks or success reporting can race ahead of Compose.
    verify_compose_service_ready(runtime, workspace, service, &container_id, remote_user).await?;

    // 13. Run lifecycle hooks with feature hooks and correct remote_user.
    let feature_hooks = if ordered_features.is_empty() {
        None
    } else {
        Some(ordered_features.as_slice())
    };
    match owed {
        ComposeHooks::Create => {
            run_create_hooks(
                runtime,
                &container_id,
                config,
                remote_user,
                None,
                feature_hooks,
            )
            .await?;
        }
        ComposeHooks::Start => {
            run_start_hooks(
                runtime,
                &container_id,
                config,
                remote_user,
                None,
                feature_hooks,
            )
            .await?;
        }
        ComposeHooks::None => {}
    }

    // 14. Install dotfiles.
    if let Some(ref dotfiles) = config.dotfiles {
        install_dotfiles(runtime, &container_id, dotfiles, remote_user).await?;
    }

    // Cleanup temp files.
    let _ = std::fs::remove_file(&override_path);
    for p in &rewritten_paths {
        let _ = std::fs::remove_file(p);
    }

    println!(
        "Compose service '{service}' is ready (container {}).",
        &container_id[..12.min(container_id.len())]
    );

    if !caddy_host_ports_compose.is_empty()
        && let Err(e) = crate::caddy::register_site(workspace, &caddy_host_ports_compose)
    {
        eprintln!("Warning: Caddy setup failed: {e}");
    }

    Ok(())
}

/// Confirm the Compose target service container is ready for Dev-controlled
/// execs before lifecycle hooks or the final success message run.
///
/// `docker compose up -d` starts containers and returns once the transition is
/// initiated. It does not prove the target service container is already a
/// usable exec target for workspace commands. The image-based path already
/// gates that claim with [`verify_container_usable`]; Compose uses that same
/// supported seam after resolving the configured service's container id, with
/// one shared deadline across inspect, discovery, and exec.
async fn verify_compose_service_ready(
    runtime: &dyn ContainerRuntime,
    workspace: &Path,
    service: &str,
    container_id: &str,
    remote_user: Option<&str>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + READINESS_BUDGET;
    verify_compose_service_running(runtime, service, container_id, deadline).await?;

    // The cause already names the container and how long its own phase waited,
    // so this adds the Compose context the caller has and the cause does not.
    // It deliberately does not claim a budget-length wait: the phases below
    // fail for reasons other than running out of it.
    verify_container_usable_until(
        runtime,
        container_id,
        workspace,
        remote_user,
        None,
        deadline,
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "Compose service '{service}' did not become usable for workspace commands \
             after compose up: {e}"
        )
    })
}

/// Wait for the resolved Compose service container to report itself running.
///
/// A state the runtime *answered with* is a verdict: Compose has already
/// started the service, so a container it reports as not running has exited,
/// and lifecycle hooks would fail the same way. That is worth failing on at
/// once, with the service context needed to go read its logs.
///
/// An inspect that fails or does not answer is not a verdict — it is this
/// gate's own window, where a daemon settling after `compose up` is most
/// likely to blip — so it is retried on the shared schedule for the same
/// reason [`verify_container_discoverable_until`] retries its list, and only
/// reported once the budget is spent.
async fn verify_compose_service_running(
    runtime: &dyn ContainerRuntime,
    service: &str,
    container_id: &str,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    let mut polls = ReadinessPolls::until(deadline);
    let mut last_error;

    loop {
        let window = polls.remaining();
        match tokio::time::timeout(window, runtime.inspect_container(container_id)).await {
            Ok(Ok(info)) if info.state == ContainerState::Running => return Ok(()),
            Ok(Ok(info)) => anyhow::bail!(
                "Compose service '{service}' container '{container_id}' is {:?}, not running. \
                 Check `compose logs {service}` for why the service exited before Dev could \
                 run workspace commands or lifecycle hooks.",
                info.state
            ),
            Ok(Err(e)) => last_error = e.to_string(),
            Err(_) => last_error = format!("it did not answer within {:.1}s", window.as_secs_f64()),
        }

        if !polls.wait().await {
            anyhow::bail!(
                "Compose service '{service}' container '{container_id}' could not be inspected \
                 after compose up: {last_error}."
            );
        }
    }
}

/// Substitute variables in each mount entry (string or object form) and emit
/// Docker long-form strings, warning about entries that lack `source`/`target`.
/// Long-form mount strings contributed by features, in install order.
///
/// Feature mounts arrive as raw devcontainer JSON (string or object form); each
/// is deserialized into a `MountSpec` and substituted exactly like config
/// mounts, so `${devcontainerId}` volume names resolve. Malformed entries are
/// skipped with a warning, mirroring `substitute_mounts`.
fn feature_mount_strings(
    features: &[ResolvedFeature],
    workspace: &Path,
    remote_user: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    for feature in features {
        for raw in &feature.mounts {
            let emitted = serde_json::from_value::<MountSpec>(raw.clone())
                .ok()
                .and_then(|spec| spec.substitute_and_emit(workspace, remote_user));
            match emitted {
                Some(mount) => out.push(mount),
                None => eprintln!(
                    "Warning: feature '{}' declares an invalid mount entry; skipping: {raw}",
                    feature.id
                ),
            }
        }
    }
    out
}

/// Feature entrypoints in install order. Each is one argv token; per the spec
/// they are `exec "$@"` wrappers, so the runtime chains them ahead of the
/// keep-alive command.
fn feature_entrypoints(features: &[ResolvedFeature]) -> Vec<String> {
    features
        .iter()
        .filter_map(|f| f.entrypoint.clone())
        .collect()
}

fn substitute_mounts(
    mounts: &[MountSpec],
    workspace: &Path,
    remote_user: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    for m in mounts {
        if let Some(emitted) = m.substitute_and_emit(workspace, remote_user) {
            out.push(emitted);
        } else {
            eprintln!("Warning: mount entry is missing source or target; skipping: {m:?}");
        }
    }
    out
}

/// Parse mount strings from devcontainer.json into `BindMount` structs.
///
/// Supports two formats:
/// - Docker long form: `source=X,target=Y,type=bind[,readonly]`
/// - Docker short form: `/host:/container[:ro]`
fn parse_mounts(mount_strings: &[String]) -> Vec<BindMount> {
    let mut mounts = Vec::new();
    for s in mount_strings {
        if let Some(m) = parse_single_mount(s) {
            mounts.push(m);
        } else {
            eprintln!("Warning: could not parse mount string: {s}");
        }
    }
    mounts
}

fn parse_single_mount(s: &str) -> Option<BindMount> {
    let s = s.trim();

    // Short form: /host:/container[:ro]
    if s.starts_with('/') || s.starts_with('.') {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() >= 2 {
            let readonly = parts.get(2).map(|&p| p == "ro").unwrap_or(false);
            return Some(BindMount {
                source: PathBuf::from(parts[0]),
                target: parts[1].to_string(),
                readonly,
            });
        }
        return None;
    }

    // Long form: key=value pairs separated by commas
    let mut source = None;
    let mut target = None;
    let mut readonly = false;

    for part in s.split(',') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            match key {
                "source" | "src" => source = Some(val.to_string()),
                "target" | "dst" | "destination" => target = Some(val.to_string()),
                "readonly" | "ro" => {
                    readonly = val.is_empty() || val == "true" || val == "1";
                }
                "type" => {} // Acknowledged but we only support bind mounts in this context
                _ => {}
            }
        } else if part == "readonly" || part == "ro" {
            readonly = true;
        }
    }

    match (source, target) {
        (Some(src), Some(tgt)) => Some(BindMount {
            source: PathBuf::from(src),
            target: tgt,
            readonly,
        }),
        _ => None,
    }
}

/// Parse CLI `--ports` values into `PortMapping` structs.
///
/// Accepted formats:
/// - `8080` — forward container port 8080 to host port 8080
/// - `9090:8080` — forward container port 8080 to host port 9090
fn parse_port_overrides(args: &[String]) -> anyhow::Result<Vec<PortMapping>> {
    let mut mappings = Vec::new();
    for arg in args {
        let arg = arg.trim();
        if arg.is_empty() {
            continue;
        }
        if let Some((host_str, container_str)) = arg.split_once(':') {
            let host: u16 = host_str
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid host port in '{arg}'"))?;
            let container: u16 = container_str
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid container port in '{arg}'"))?;
            mappings.push(PortMapping { host, container });
        } else {
            let port: u16 = arg
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port '{arg}'"))?;
            mappings.push(PortMapping {
                host: port,
                container: port,
            });
        }
    }
    Ok(mappings)
}

/// Parse volume strings into `VolumeMount` structs.
///
/// Format: `volume-name:/container/path[:ro]`
fn parse_volumes(volume_strings: &[String]) -> Vec<VolumeMount> {
    let mut volumes = Vec::new();
    for s in volume_strings {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() >= 2 {
            let readonly = parts.get(2).is_some_and(|&p| p == "ro");
            volumes.push(VolumeMount {
                name: parts[0].to_string(),
                target: parts[1].to_string(),
                readonly,
            });
        } else {
            eprintln!("Warning: could not parse volume string (expected name:/path[:ro]): {s}");
        }
    }
    volumes
}

#[cfg(test)]
mod tests {
    use super::{
        apply_cli_overrides, apply_run_args_capabilities, apply_secrets_to_env,
        caddy_ports_from_config, ensure_image_present, merge_caddy_ports, parse_mounts,
        parse_single_mount, project_declares_run_args, reject_project_run_args_for_compose,
        reject_secrets_for_compose, reject_secrets_override_for_compose, substitute_mounts,
    };
    use crate::devcontainer::config::{DevcontainerConfig, MountObject, MountSpec};
    use crate::devcontainer::effective::load_effective_config_value;
    use crate::devcontainer::features::MergedCapabilities;
    use crate::devcontainer::secrets::provider::{FakeProvider, PluginPath, ProviderRegistry};
    use crate::devcontainer::secrets::validate::validate_secrets_for_config;
    use crate::devcontainer::secrets::{SecretValue, ValidatedSecrets};
    use crate::error::DevError;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ContainerState,
        ExecResult, ImageMetadata,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::TempDir;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async {
            Err(DevError::Runtime(
                "FakeRuntime method unused by ensure_image_present".into(),
            ))
        })
    }

    fn write_project_config(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let devcontainer_dir = dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        let path = devcontainer_dir.join("devcontainer.json");
        fs::write(&path, content).unwrap();
        path
    }

    /// The sidecar beside a workspace-scope `devcontainer.json`.
    fn write_secrets_json(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let devcontainer_dir = dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        let path = devcontainer_dir.join("secrets.json");
        fs::write(&path, content).unwrap();
        path
    }

    fn write_base_config(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let base_dir = dir.path().join("base");
        fs::create_dir_all(&base_dir).unwrap();
        let path = base_dir.join("devcontainer.json");
        fs::write(&path, content).unwrap();
        path
    }

    fn load_config_with_base(
        config_path: &Path,
        include_base: bool,
        base_config_path: &Path,
    ) -> DevcontainerConfig {
        let (value, _) = load_effective_config_value(config_path, include_base, base_config_path)
            .expect("effective config should load");
        serde_json::from_value(value).expect("effective config should deserialize")
    }

    #[test]
    fn cli_port_overrides_apply_last() {
        let workspace = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "forwardPorts": [3000]}"#,
        );
        let base_path = write_base_config(&home, r#"{"forwardPorts": [8080]}"#);
        let mut config = load_config_with_base(&config_path, true, &base_path);

        apply_cli_overrides(&mut config, &["9090:90".to_string(), "7070".to_string()]).unwrap();

        let ports = config.forward_ports.unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].host, 9090);
        assert_eq!(ports[0].container, 90);
        assert_eq!(ports[1].host, 7070);
        assert_eq!(ports[1].container, 7070);
    }

    #[test]
    fn caddy_ports_map_declared_forward_ports_by_host() {
        // A stopped-container reuse `dev up` restores exactly these routes
        // (issue #52), so the mapping must key on the host-side port.
        let config: DevcontainerConfig =
            serde_json::from_str(r#"{"image": "ubuntu:24.04", "forwardPorts": ["9090:90", 7070]}"#)
                .unwrap();

        let ports = caddy_ports_from_config(&config);

        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 9090);
        assert_eq!(ports[1].port, 7070);
        assert!(ports.iter().all(|p| p.custom_name.is_none()));
    }

    #[test]
    fn caddy_ports_take_hostnames_from_the_config_caddy_map() {
        // The point of the map: a multi-service project gets readable names
        // instead of `<folder>-<port>.test`, and unnamed ports still fall back.
        let config: DevcontainerConfig = serde_json::from_str(
            r#"{
                "image": "ubuntu:24.04",
                "forwardPorts": [5247, 5163, 5001],
                "caddy": {"5247": "chuckos", "5163": "api.chuckos"}
            }"#,
        )
        .unwrap();

        let ports = caddy_ports_from_config(&config);

        assert_eq!(ports[0].custom_name.as_deref(), Some("chuckos.test"));
        assert_eq!(ports[1].custom_name.as_deref(), Some("api.chuckos.test"));
        assert!(ports[2].custom_name.is_none());
    }

    #[test]
    fn caddy_map_keys_are_host_ports_not_container_ports() {
        // `"3001:3000"` publishes on host 3001, which is what Caddy proxies to,
        // so keying the map on the container port must NOT match.
        let config: DevcontainerConfig = serde_json::from_str(
            r#"{
                "image": "ubuntu:24.04",
                "forwardPorts": ["3001:3000"],
                "caddy": {"3000": "wrong", "3001": "right"}
            }"#,
        )
        .unwrap();

        let ports = caddy_ports_from_config(&config);

        assert_eq!(ports[0].port, 3001);
        assert_eq!(ports[0].custom_name.as_deref(), Some("right.test"));
    }

    #[test]
    fn caddy_ports_empty_without_forward_ports() {
        // Empty means `register_caddy_routes` is a no-op — a project with no
        // forwarded ports must not touch Caddy on reuse.
        let config: DevcontainerConfig =
            serde_json::from_str(r#"{"image": "ubuntu:24.04"}"#).unwrap();

        assert!(caddy_ports_from_config(&config).is_empty());
    }

    #[test]
    fn merge_caddy_ports_unions_and_sorts_disjoint_entries() {
        // Declared port from config plus a live ad-hoc `dev forward` on a
        // different port must both survive, sorted by host port.
        let declared = vec![crate::caddy::PortEntry {
            port: 3000,
            custom_name: None,
            keepalive: None,
        }];
        let active = vec![crate::caddy::PortEntry {
            port: 8080,
            custom_name: Some("admin.myapp.test".to_string()),
            keepalive: None,
        }];

        let merged = merge_caddy_ports(declared, active);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].port, 3000);
        assert_eq!(merged[1].port, 8080);
        assert_eq!(merged[1].custom_name.as_deref(), Some("admin.myapp.test"));
    }

    #[test]
    fn merge_caddy_ports_prefers_live_entry_on_conflict() {
        // A declared port that also has a live forwarder must keep the live
        // entry's custom name / keepalive rather than the declared-only nulls —
        // this is the regression the reuse path would otherwise cause.
        let declared = vec![crate::caddy::PortEntry {
            port: 3000,
            custom_name: None,
            keepalive: None,
        }];
        let active = vec![crate::caddy::PortEntry {
            port: 3000,
            custom_name: Some("web.myapp.test".to_string()),
            keepalive: Some("30s".to_string()),
        }];

        let merged = merge_caddy_ports(declared, active);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].port, 3000);
        assert_eq!(merged[0].custom_name.as_deref(), Some("web.myapp.test"));
        assert_eq!(merged[0].keepalive.as_deref(), Some("30s"));
    }

    #[test]
    fn merge_caddy_ports_empty_when_nothing_declared_or_active() {
        assert!(merge_caddy_ports(vec![], vec![]).is_empty());
    }

    #[test]
    fn compose_runargs_from_inherited_layers_are_not_rejected_as_project_declared() {
        let mut config: DevcontainerConfig = serde_json::from_str(
            r#"{"dockerComposeFile":"compose.yml","service":"app","runArgs":["--init"]}"#,
        )
        .unwrap();

        reject_project_run_args_for_compose(&config, false)
            .expect("inherited runArgs are ignored on the Compose path");

        config.run_args = Some(vec![]);
        reject_project_run_args_for_compose(&config, true)
            .expect("an empty project runArgs array is not actionable");
    }

    #[test]
    fn compose_runargs_declared_by_project_are_rejected_with_service_guidance() {
        let config: DevcontainerConfig = serde_json::from_str(
            r#"{"dockerComposeFile":"compose.yml","service":"app","runArgs":["--init"]}"#,
        )
        .unwrap();

        let err = reject_project_run_args_for_compose(&config, true).unwrap_err();
        let msg = format!("{err}");

        assert!(msg.contains("runArgs"), "{msg}");
        assert!(msg.contains("Compose service"), "{msg}");
    }

    /// Parse a `secrets.json` into the value the compose guard inspects, the
    /// same way `run_with_runtime_with_providers` does.
    fn validated_secrets(workspace: &TempDir, content: &str) -> ValidatedSecrets {
        let config_path = write_project_config(workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(workspace, content);
        let fake = FakeProvider::answers_everything();
        validate_secrets_for_config(
            &config_path,
            workspace.path(),
            None,
            &registry_with(workspace, &fake),
        )
        .expect("the fixture must parse and name a known provider")
    }

    fn compose_config() -> DevcontainerConfig {
        serde_json::from_str(r#"{"dockerComposeFile":"compose.yml","service":"app"}"#).unwrap()
    }

    #[test]
    fn compose_project_with_create_time_secrets_is_rejected_with_compose_guidance() {
        let config = compose_config();
        let workspace = TempDir::new().unwrap();
        let secrets = validated_secrets(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"fake://vault/distinctive-reference"}}"#,
        );

        let err = reject_secrets_for_compose(&config, &secrets).unwrap_err();
        let msg = format!("{err}");

        assert!(msg.contains("TOKEN"), "error should name the key: {msg}");
        assert!(
            msg.contains(&secrets.source().unwrap().display().to_string()),
            "error should name the discovered file: {msg}"
        );
        assert!(msg.contains("Compose"), "{msg}");
        assert!(
            msg.contains("createTime"),
            "error should point at the way out: {msg}"
        );
        assert!(
            !msg.contains("distinctive-reference"),
            "no reference body may reach the message: {msg}"
        );
    }

    /// The narrow rule: Compose refuses what it cannot inject, and nothing more.
    /// A `createTime: false` entry never reaches container creation on any
    /// runtime, so the Compose override file never sees it either. `dev exec`
    /// and `dev shell` resolve it per invocation and pass it on the exec.
    #[test]
    fn compose_project_with_exec_time_only_secrets_is_allowed() {
        let config = compose_config();
        let workspace = TempDir::new().unwrap();
        let secrets = validated_secrets(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"fake","ref":"item","createTime":false}}}"#,
        );

        reject_secrets_for_compose(&config, &secrets)
            .expect("an exec-time-only secret is injected on a path Compose shares");
    }

    /// A file mixing both is refused, and the message names only the entries
    /// that are actually the problem.
    #[test]
    fn compose_rejection_names_only_the_create_time_keys() {
        let config = compose_config();
        let workspace = TempDir::new().unwrap();
        let secrets = validated_secrets(
            &workspace,
            r#"{"version":1,"secrets":{
                "AT_CREATE":"fake://one",
                "AT_EXEC":{"provider":"fake","ref":"two","createTime":false}
            }}"#,
        );

        let msg = format!(
            "{}",
            reject_secrets_for_compose(&config, &secrets).unwrap_err()
        );

        assert!(msg.contains("AT_CREATE"), "{msg}");
        assert!(
            !msg.contains("AT_EXEC"),
            "an exec-time key is not what is being refused: {msg}"
        );
    }

    #[test]
    fn compose_project_without_secrets_is_not_rejected() {
        let config = compose_config();

        reject_secrets_for_compose(&config, &ValidatedSecrets::default())
            .expect("no secrets.json is nothing to reject");

        let workspace = TempDir::new().unwrap();
        let empty = validated_secrets(&workspace, r#"{"version":1,"secrets":{}}"#);
        reject_secrets_for_compose(&config, &empty).expect("an empty secrets map declares nothing");
    }

    #[test]
    fn secrets_are_not_rejected_for_non_compose_configs() {
        let config: DevcontainerConfig =
            serde_json::from_str(r#"{"image":"ubuntu:24.04"}"#).unwrap();
        let workspace = TempDir::new().unwrap();
        let secrets = validated_secrets(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"fake://item"}}"#,
        );

        reject_secrets_for_compose(&config, &secrets)
            .expect("the image path resolves secrets rather than rejecting them");
    }

    /// `--secrets` feeds create-time injection only, and Compose has none.
    #[test]
    fn compose_project_with_a_secrets_override_is_rejected() {
        let msg = format!(
            "{}",
            reject_secrets_override_for_compose(Some(Path::new("/w/other-secrets.json")))
                .unwrap_err()
        );

        assert!(msg.contains("--secrets"), "{msg}");
        assert!(msg.contains("other-secrets.json"), "{msg}");
        assert!(msg.contains("Compose"), "{msg}");

        reject_secrets_override_for_compose(None).expect("no override is nothing to reject");
    }

    #[test]
    fn value_declares_project_run_args_only_for_non_empty_arrays() {
        assert!(project_declares_run_args(
            &serde_json::json!({"runArgs": ["--init"]})
        ));
        assert!(!project_declares_run_args(
            &serde_json::json!({"runArgs": []})
        ));
        assert!(!project_declares_run_args(
            &serde_json::json!({"image": "ubuntu"})
        ));
    }

    /// Minimal fake runtime: records `pull_image` calls and returns a fixed
    /// `image_exists` result. Every other trait method is unused by
    /// `ensure_image_present` and returns an error if invoked.
    struct FakeRuntime {
        exists: AtomicBool,
        pull_count: AtomicUsize,
    }

    impl FakeRuntime {
        fn new(exists: bool) -> Self {
            Self {
                exists: AtomicBool::new(exists),
                pull_count: AtomicUsize::new(0),
            }
        }

        fn pull_count(&self) -> usize {
            self.pull_count.load(Ordering::SeqCst)
        }
    }

    impl ContainerRuntime for FakeRuntime {
        fn runtime_name(&self) -> &'static str {
            "fake"
        }

        fn pull_image(&self, _image: &str) -> BoxFut<'_, ()> {
            self.pull_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(()) })
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
            let exists = self.exists.load(Ordering::SeqCst);
            Box::pin(async move { Ok(exists) })
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

    /// When the image is already present locally, `ensure_image_present` must
    /// use it and must NOT pull.
    #[tokio::test]
    async fn ensure_image_present_skips_pull_when_image_exists() {
        let rt = FakeRuntime::new(true);
        ensure_image_present(&rt, "localimg:latest")
            .await
            .expect("helper should succeed when image exists");
        assert_eq!(
            rt.pull_count(),
            0,
            "pull_image must not be called when image_exists returns true"
        );
    }

    /// When the image is missing locally, `ensure_image_present` must pull it
    /// exactly once.
    #[tokio::test]
    async fn ensure_image_present_pulls_when_image_missing() {
        let rt = FakeRuntime::new(false);
        ensure_image_present(&rt, "remoteimg:latest")
            .await
            .expect("helper should succeed after pulling");
        assert_eq!(
            rt.pull_count(),
            1,
            "pull_image must be called exactly once when image_exists returns false"
        );
    }

    /// Regression test for issue #24: the build/features base-image path routes
    /// through `ensure_image_present` and therefore skips the pull when the
    /// image is already local. Mirrors the image-only branch's behavior.
    #[tokio::test]
    async fn build_path_base_image_skips_pull_when_image_exists() {
        let rt = FakeRuntime::new(true);
        // Base-image determination in the build/features branch:
        let image_name = "localimg:latest";
        ensure_image_present(&rt, image_name)
            .await
            .expect("helper should succeed when image exists locally");
        assert_eq!(
            rt.pull_count(),
            0,
            "build path must not call pull_image when image_exists returns true"
        );
    }

    /// `parse_single_mount` must accept a bind-mount long-form string.
    #[test]
    fn parse_single_mount_accepts_bind_long_form() {
        let m = parse_single_mount("source=./,target=/workspace,type=bind,readonly=true")
            .expect("long-form bind mount should parse");
        assert_eq!(m.source, std::path::PathBuf::from("./"));
        assert_eq!(m.target, "/workspace");
        assert!(m.readonly);
    }

    /// `parse_single_mount` must accept a bind-mount long-form string with `ro` flag.
    #[test]
    fn parse_single_mount_accepts_long_form_with_ro() {
        let m = parse_single_mount("source=/host,target=/container,readonly,ro")
            .expect("long-form bind mount with ro keyword should parse");
        assert!(m.readonly);
    }

    /// `parse_single_mount` accepts a non-bind long-form string (type is
    /// ignored; Docker treats a bare source name as a named volume).
    #[test]
    fn parse_single_mount_accepts_non_bind_type() {
        let m = parse_single_mount("source=myvol,target=/data,type=volume")
            .expect("non-bind mount should still parse (type is ignored)");
        assert_eq!(m.source, std::path::PathBuf::from("myvol"));
        assert_eq!(m.target, "/data");
        assert!(!m.readonly);
    }

    /// Non-bind mounts must NOT be dropped: a `type=volume` mount, in either
    /// string or object form, is rendered as a `BindMount` through the same
    /// `substitute_mounts` + `parse_mounts` chain `run` uses.
    #[test]
    fn volume_type_mount_is_rendered_not_dropped() {
        let ws = std::path::Path::new("/home/user/project");
        let specs = vec![
            MountSpec::Plain("source=myvol,target=/data,type=volume".to_string()),
            MountSpec::Object(MountObject {
                source: Some("othervol".to_string()),
                target: Some("/cache".to_string()),
                r#type: Some("volume".to_string()),
                ..Default::default()
            }),
        ];
        let strings = substitute_mounts(&specs, ws, None);
        let mounts = parse_mounts(&strings);
        assert_eq!(mounts.len(), 2, "volume-type mounts must not be dropped");
        assert_eq!(mounts[0].source, std::path::PathBuf::from("myvol"));
        assert_eq!(mounts[0].target, "/data");
        assert!(!mounts[0].readonly);
        assert_eq!(mounts[1].source, std::path::PathBuf::from("othervol"));
        assert_eq!(mounts[1].target, "/cache");
    }

    /// An object mount missing `source` is skipped (with a warning) rather
    /// than rendered, while valid entries in the same list survive.
    #[test]
    fn malformed_object_mount_is_skipped_valid_ones_survive() {
        let ws = std::path::Path::new("/home/user/project");
        let specs = vec![
            MountSpec::Object(MountObject {
                source: None,
                target: Some("/data".to_string()),
                ..Default::default()
            }),
            MountSpec::Plain("/host:/container".to_string()),
        ];
        let strings = substitute_mounts(&specs, ws, None);
        let mounts = parse_mounts(&strings);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].target, "/container");
    }

    // ---- issue #4 regression coverage: create/start error propagation and
    // workspace-label discovery ----
    //
    // `run_with_runtime` is the seam `run` delegates to after runtime
    // detection. These tests drive it with a stand-in runtime over a minimal
    // image-based devcontainer.json so the create/start/readiness flow can be
    // exercised deterministically in CI (no container daemon).

    use crate::util::workspace_labels;
    use std::sync::{Arc, Mutex};

    /// One command `exec` was asked to run, and the user it ran as.
    type ExecCall = (Vec<String>, Option<String>, Option<String>);

    /// Stand-in runtime for `run_with_runtime`, modelling a daemon: created
    /// containers land in `containers`, `start_container` marks them running,
    /// and `list_containers` answers label queries out of that same state — so
    /// the create → discover contract is exercised end to end.
    ///
    /// Each knob reproduces one way the issue #4 path failed: create/start
    /// erroring, the container never reaching running, and the container
    /// existing but being invisible to the label query `dev status`/`dev exec`
    /// use (which is what an undecodable `containerList` reply looks like).
    struct UpFakeRuntime {
        runtime_name: &'static str,
        image_exists: bool,
        create_fails: bool,
        start_fails: bool,
        discoverable: bool,
        starts_running: bool,
        /// Number of list calls that still report the container as stopped,
        /// standing in for daemon-side state that settles late.
        running_after_polls: Arc<AtomicUsize>,
        /// Number of list calls that fail before the runtime answers at all,
        /// standing in for a daemon whose list/XPC call is still settling.
        list_errors_before_success: Arc<AtomicUsize>,
        /// Every list call fails, standing in for a runtime that never answers.
        list_always_fails: bool,
        /// Every list call hangs, standing in for a daemon that accepted the
        /// query and dropped its reply.
        list_never_answers: bool,
        /// Number of inspect calls that fail before the runtime answers at
        /// all, standing in for a daemon still settling after `compose up`.
        inspect_errors_before_success: Arc<AtomicUsize>,
        /// `exec` errors, standing in for a container whose create → start →
        /// wait sequence never reports a command's exit.
        exec_fails: bool,
        /// Number of exec calls that fail before the runtime answers at all,
        /// standing in for an exec endpoint that is still coming up.
        exec_errors_before_success: Arc<AtomicUsize>,
        /// `exec` fails the way a runtime reports an image without the
        /// requested executable, rather than a broken exec path.
        exec_command_missing: bool,
        /// `exec` never returns, standing in for the dropped `containerWait`
        /// behind issue #4: the process runs but its exit is never reported.
        exec_never_returns: bool,
        /// Refuse this many attempts, then stop answering at all — a runtime
        /// that said something specific before a later attempt merely ran out
        /// of window.
        exec_refusals_before_silence: Option<Arc<AtomicUsize>>,
        /// `exec` answers, but with a non-zero status for a command that
        /// cannot fail on its own.
        exec_exit_code: i32,
        /// Commands `exec` was asked to run, with the user each ran as, so the
        /// gate's probe is observable.
        execs: Arc<Mutex<Vec<ExecCall>>>,
        created_id: String,
        created_config: Arc<Mutex<Option<ContainerConfig>>>,
        started_id: Arc<Mutex<Option<String>>>,
        containers: Arc<Mutex<Vec<ContainerInfo>>>,
        /// What `inspect_image_metadata` reports, so cache-path tests can seed
        /// `devcontainer.metadata` entries to recover feature contributions from.
        image_metadata: Arc<Mutex<ImageMetadata>>,
    }

    impl UpFakeRuntime {
        fn ok() -> Self {
            Self {
                runtime_name: "fake",
                image_exists: true,
                create_fails: false,
                start_fails: false,
                discoverable: true,
                starts_running: true,
                running_after_polls: Arc::new(AtomicUsize::new(0)),
                list_errors_before_success: Arc::new(AtomicUsize::new(0)),
                list_always_fails: false,
                list_never_answers: false,
                inspect_errors_before_success: Arc::new(AtomicUsize::new(0)),
                exec_fails: false,
                exec_errors_before_success: Arc::new(AtomicUsize::new(0)),
                exec_command_missing: false,
                exec_never_returns: false,
                exec_refusals_before_silence: None,
                exec_exit_code: 0,
                execs: Arc::new(Mutex::new(Vec::new())),
                created_id: "fake-id".to_string(),
                created_config: Arc::new(Mutex::new(None)),
                started_id: Arc::new(Mutex::new(None)),
                containers: Arc::new(Mutex::new(Vec::new())),
                image_metadata: Arc::new(Mutex::new(ImageMetadata::default())),
            }
        }

        /// Seed the `devcontainer.metadata` entries the fake image reports.
        fn with_metadata_entries(self, entries: Vec<serde_json::Value>) -> Self {
            self.image_metadata.lock().unwrap().metadata_entries = entries;
            self
        }

        fn named_runtime(mut self, runtime_name: &'static str) -> Self {
            self.runtime_name = runtime_name;
            self
        }

        /// Create, start and discovery all succeed, but no command can be run
        /// in the container.
        fn cannot_exec() -> Self {
            Self {
                exec_fails: true,
                ..Self::ok()
            }
        }

        /// Create, start and discovery all succeed, but a command that cannot
        /// fail on its own comes back non-zero — an image with no shell.
        fn execs_report(exit_code: i32) -> Self {
            Self {
                exec_exit_code: exit_code,
                ..Self::ok()
            }
        }

        /// The exec path works, but the runtime reports the image has no such
        /// executable, the way docker declines to start one.
        fn has_no_shell() -> Self {
            Self {
                exec_fails: true,
                exec_command_missing: true,
                ..Self::ok()
            }
        }

        /// The exec endpoint refuses the first `calls` attempts and then works,
        /// standing in for a runtime that is still settling.
        fn execs_after(calls: usize) -> Self {
            Self {
                exec_errors_before_success: Arc::new(AtomicUsize::new(calls)),
                ..Self::ok()
            }
        }

        /// The command is accepted but its exit is never reported — the
        /// dropped `containerWait` behind issue #4.
        fn execs_never_return() -> Self {
            Self {
                exec_never_returns: true,
                ..Self::ok()
            }
        }

        /// Refuses `refusals` attempts, then stops answering, so a later
        /// attempt can only end on its own deadline.
        fn refuses_then_stops_answering(refusals: usize) -> Self {
            Self {
                exec_refusals_before_silence: Some(Arc::new(AtomicUsize::new(refusals))),
                ..Self::ok()
            }
        }

        fn execs(&self) -> Vec<ExecCall> {
            self.execs.lock().unwrap().clone()
        }

        fn failing(create: bool, start: bool) -> Self {
            Self {
                create_fails: create,
                start_fails: start,
                ..Self::ok()
            }
        }

        /// Create and start succeed, but the container never shows up in the
        /// workspace-label query.
        fn undiscoverable() -> Self {
            Self {
                discoverable: false,
                ..Self::ok()
            }
        }

        /// Create and start succeed, but the container never reaches running.
        fn never_running() -> Self {
            Self {
                starts_running: false,
                ..Self::ok()
            }
        }

        /// Create and start succeed, and the container reports running only
        /// after `polls` list calls.
        fn running_late(polls: usize) -> Self {
            Self {
                running_after_polls: Arc::new(AtomicUsize::new(polls)),
                ..Self::ok()
            }
        }

        /// Create and start succeed, but the first `polls` list calls fail
        /// before the runtime answers at all.
        fn listing_fails_at_first(polls: usize) -> Self {
            Self {
                list_errors_before_success: Arc::new(AtomicUsize::new(polls)),
                ..Self::ok()
            }
        }

        /// Create and start succeed, but the runtime can never be listed.
        fn listing_never_works() -> Self {
            Self {
                list_always_fails: true,
                ..Self::ok()
            }
        }

        /// Create and start succeed, but the list query is never answered at
        /// all — the dropped-reply half of issue #4 on the discovery side.
        fn listing_never_answers() -> Self {
            Self {
                list_never_answers: true,
                ..Self::ok()
            }
        }

        /// The first `polls` list calls fail, and every later one succeeds
        /// while still not showing the container.
        fn undiscoverable_after_a_blip(polls: usize) -> Self {
            Self {
                list_errors_before_success: Arc::new(AtomicUsize::new(polls)),
                ..Self::undiscoverable()
            }
        }

        /// Seed the daemon with a container this workspace already has
        /// running, the way an earlier `dev up` left it — including one the
        /// readiness gate refused, which the runtime leaves running.
        fn already_running(self, workspace: &Path, config_path: &Path) -> Self {
            self.containers.lock().unwrap().push(ContainerInfo {
                id: "already-running-id".to_string(),
                name: "already-running".to_string(),
                state: ContainerState::Running,
                labels: workspace_labels(workspace, Some(config_path))
                    .into_iter()
                    .collect(),
                image: "ubuntu:24.04".to_string(),
            });
            self
        }

        fn already_stopped(self, workspace: &Path, config_path: &Path) -> Self {
            self.containers.lock().unwrap().push(ContainerInfo {
                id: "already-stopped-id".to_string(),
                name: "already-stopped".to_string(),
                state: ContainerState::Stopped,
                labels: workspace_labels(workspace, Some(config_path))
                    .into_iter()
                    .collect(),
                image: "ubuntu:24.04".to_string(),
            });
            self
        }

        fn created_config(&self) -> ContainerConfig {
            self.created_config
                .lock()
                .unwrap()
                .clone()
                .expect("create_container was not called")
        }

        fn create_was_attempted(&self) -> bool {
            self.created_config.lock().unwrap().is_some()
        }

        fn compose_target(self, workspace: &Path, state: ContainerState) -> Self {
            self.containers.lock().unwrap().push(ContainerInfo {
                id: self.created_id.clone(),
                name: "dev-app-1".to_string(),
                state,
                labels: workspace_labels(workspace, None).into_iter().collect(),
                image: "ubuntu:24.04".to_string(),
            });
            self
        }
    }

    impl ContainerRuntime for UpFakeRuntime {
        fn runtime_name(&self) -> &'static str {
            self.runtime_name
        }

        fn pull_image(&self, _image: &str) -> BoxFut<'_, ()> {
            // image_exists returns true, so pull_image must never be reached.
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

        fn create_container(&self, config: &ContainerConfig) -> BoxFut<'_, String> {
            let config = config.clone();
            let create_fails = self.create_fails;
            let created_id = self.created_id.clone();
            let capture = self.created_config.clone();
            let containers = self.containers.clone();
            Box::pin(async move {
                if create_fails {
                    return Err(DevError::Runtime(
                        "create_container failed (test-injected)".to_string(),
                    ));
                }
                containers.lock().unwrap().push(ContainerInfo {
                    id: created_id.clone(),
                    name: config.name.clone(),
                    state: ContainerState::Stopped,
                    labels: config.labels.clone(),
                    image: config.image.clone(),
                });
                *capture.lock().unwrap() = Some(config);
                Ok(created_id)
            })
        }

        fn start_container(&self, id: &str) -> BoxFut<'_, ()> {
            let id = id.to_string();
            let start_fails = self.start_fails;
            let starts_running = self.starts_running;
            let capture = self.started_id.clone();
            let containers = self.containers.clone();
            Box::pin(async move {
                if start_fails {
                    return Err(DevError::Runtime(
                        "start_container failed (test-injected)".to_string(),
                    ));
                }
                if starts_running {
                    for container in containers.lock().unwrap().iter_mut() {
                        if container.id == id {
                            container.state = ContainerState::Running;
                        }
                    }
                }
                *capture.lock().unwrap() = Some(id);
                Ok(())
            })
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
            cmd: &[String],
            user: Option<&str>,
            workdir: Option<&str>,
            _env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            let cmd = cmd.to_vec();
            let user = user.map(str::to_string);
            let workdir = workdir.map(str::to_string);
            let exec_fails = self.exec_fails;
            let command_missing = self.exec_command_missing;
            let exit_code = self.exec_exit_code;
            let settling = self.exec_errors_before_success.clone();
            let never_returns = self.exec_never_returns;
            let refusals_left = self.exec_refusals_before_silence.clone();
            let execs = self.execs.clone();
            Box::pin(async move {
                // Session bookkeeping is `dev`'s own traffic. Recording it here
                // would make every count in these tests — of probes, of hooks —
                // depend on how often sessions happen to be swept.
                if !crate::session::is_session_machinery(&cmd) {
                    execs.lock().unwrap().push((cmd, user, workdir));
                }
                // A real exec talks to a daemon, so it is Pending on its first
                // poll. Answering synchronously would let this fake succeed
                // inside a zero-length timeout that a real runtime could never
                // meet, hiding a gate that grants an attempt no budget.
                tokio::task::yield_now().await;
                if never_returns {
                    std::future::pending::<()>().await;
                }
                if let Some(refusals_left) = refusals_left {
                    let refusing = refusals_left
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                        .is_ok();
                    if refusing {
                        return Err(DevError::Runtime("exec failed (test-injected)".to_string()));
                    }
                    // The refusals are spent; from here it simply stops
                    // answering, so a later attempt can only end on its
                    // own deadline.
                    std::future::pending::<()>().await;
                }
                let still_settling = settling
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .is_ok();
                if exec_fails || still_settling {
                    return Err(DevError::Runtime(if command_missing {
                        "OCI runtime exec failed: exec: \"sh\": executable file not found in $PATH"
                            .to_string()
                    } else {
                        "exec failed (test-injected)".to_string()
                    }));
                }
                Ok(ExecResult {
                    exit_code,
                    stdout: String::new(),
                    stderr: if exit_code == 0 {
                        String::new()
                    } else {
                        "sh: not found".to_string()
                    },
                })
            })
        }

        /// Classified the way the docker runtime classifies it, so the gate's
        /// tolerance is exercised through the same seam production uses.
        fn exec_reports_missing_command(&self, error: &DevError) -> bool {
            error.to_string().contains("executable file not found")
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

        fn inspect_container(&self, id: &str) -> BoxFut<'_, ContainerInfo> {
            let id = id.to_string();
            let containers = self.containers.clone();
            let errors_left = self.inspect_errors_before_success.clone();
            Box::pin(async move {
                let transient = errors_left
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .is_ok();
                if transient {
                    return Err(DevError::Runtime(
                        "inspect_container failed (test-injected)".to_string(),
                    ));
                }
                containers
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|container| super::same_container(&container.id, &id))
                    .cloned()
                    .ok_or_else(|| DevError::ContainerNotFound(id))
            })
        }

        fn list_containers(&self, label_filters: &[String]) -> BoxFut<'_, Vec<ContainerInfo>> {
            let filters: Vec<(String, String)> = label_filters
                .iter()
                .map(|f| {
                    let (key, value) = f.split_once('=').unwrap_or((f.as_str(), ""));
                    (key.to_string(), value.to_string())
                })
                .collect();
            let discoverable = self.discoverable;
            let containers = self.containers.clone();
            let settling = self.running_after_polls.clone();
            let list_errors = self.list_errors_before_success.clone();
            let list_always_fails = self.list_always_fails;
            let list_never_answers = self.list_never_answers;
            let started = self.started_id.clone();
            Box::pin(async move {
                // The injected list failures model the window right after
                // start, which is the only one the readiness gate polls in.
                if started.lock().unwrap().is_some() {
                    if list_never_answers {
                        std::future::pending::<()>().await;
                    }
                    let transient = list_errors
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                        .is_ok();
                    if transient || list_always_fails {
                        return Err(DevError::Runtime(
                            "list_containers failed (test-injected)".to_string(),
                        ));
                    }
                }
                if !discoverable {
                    return Ok(Vec::new());
                }
                let still_settling = settling
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .is_ok();
                let known = containers.lock().unwrap().clone();
                Ok(known
                    .into_iter()
                    .filter(|c| {
                        filters
                            .iter()
                            .all(|(key, value)| c.labels.get(key).is_some_and(|got| got == value))
                    })
                    .map(|mut c| {
                        if still_settling {
                            c.state = ContainerState::Stopped;
                        }
                        c
                    })
                    .collect())
            })
        }

        fn image_exists(&self, _image: &str) -> BoxFut<'_, bool> {
            let exists = self.image_exists;
            Box::pin(async move { Ok(exists) })
        }

        fn inspect_image_metadata(&self, _image: &str) -> BoxFut<'_, ImageMetadata> {
            // Defaults report no remote user, and update_remote_user_uid_default
            // ="never" skips UID remap, so the up flow never advances past
            // create/start unless a test seeds metadata entries.
            let meta = self.image_metadata.lock().unwrap().clone();
            Box::pin(async move { Ok(meta) })
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

    /// Drive `run_with_runtime` over a minimal image-based workspace.
    async fn run_up_with_fake(rt: &UpFakeRuntime, workspace: &TempDir) -> anyhow::Result<()> {
        run_up_with_fake_secrets_file(rt, workspace, None).await
    }

    /// [`run_up_with_fake`] with a `--secrets-file` path.
    async fn run_up_with_fake_secrets_file(
        rt: &UpFakeRuntime,
        workspace: &TempDir,
        secrets_file: Option<&Path>,
    ) -> anyhow::Result<()> {
        run_up_with_fake_flags(rt, workspace, secrets_file, None).await
    }

    /// [`run_up_with_fake`] with both secret path flags.
    async fn run_up_with_fake_flags(
        rt: &UpFakeRuntime,
        workspace: &TempDir,
        secrets_file: Option<&Path>,
        secrets_override: Option<&Path>,
    ) -> anyhow::Result<()> {
        super::run_with_runtime(
            workspace.path(),
            rt,
            /* rebuild */ false,
            /* no_cache */ false,
            /* verbose */ false,
            /* frozen_lockfile */ false,
            /* update_remote_user_uid_default */ "never",
            /* port_overrides */ &[],
            /* secrets_file */ secrets_file,
            /* no_base */ true,
            /* secrets_override */ secrets_override,
        )
        .await
    }

    /// A registry holding nothing but `fake`, so no test can reach a real
    /// provider or a plugin binary on the host `PATH`.
    fn registry_with(workspace: &TempDir, fake: &FakeProvider) -> ProviderRegistry {
        let mut providers = ProviderRegistry::empty(workspace.path(), PluginPath::default());
        providers.register(Box::new(fake.clone()));
        providers
    }

    /// [`run_up_with_fake`] with the secret providers supplied.
    async fn run_up_with_providers(
        rt: &UpFakeRuntime,
        workspace: &TempDir,
        providers: &ProviderRegistry,
    ) -> anyhow::Result<()> {
        run_up_with_providers_and_flags(rt, workspace, providers, None, None).await
    }

    /// [`run_up_with_providers`] with a `--secrets-file` path, for the tiers
    /// that only differ once both a resolved secret and a literal are in play.
    async fn run_up_with_providers_and_secrets_file(
        rt: &UpFakeRuntime,
        workspace: &TempDir,
        providers: &ProviderRegistry,
        secrets_file: Option<&Path>,
    ) -> anyhow::Result<()> {
        run_up_with_providers_and_flags(rt, workspace, providers, secrets_file, None).await
    }

    /// [`run_up_with_providers`] with a `--secrets` path.
    async fn run_up_with_providers_and_secrets(
        rt: &UpFakeRuntime,
        workspace: &TempDir,
        providers: &ProviderRegistry,
        secrets_override: Option<&Path>,
    ) -> anyhow::Result<()> {
        run_up_with_providers_and_flags(rt, workspace, providers, None, secrets_override).await
    }

    /// [`run_up_with_providers`] with both secret path flags.
    async fn run_up_with_providers_and_flags(
        rt: &UpFakeRuntime,
        workspace: &TempDir,
        providers: &ProviderRegistry,
        secrets_file: Option<&Path>,
        secrets_override: Option<&Path>,
    ) -> anyhow::Result<()> {
        super::run_with_runtime_with_providers(
            workspace.path(),
            rt,
            /* rebuild */ false,
            /* no_cache */ false,
            /* verbose */ false,
            /* frozen_lockfile */ false,
            /* update_remote_user_uid_default */ "never",
            /* port_overrides */ &[],
            /* secrets_file */ secrets_file,
            /* no_base */ true,
            /* secrets_override */ secrets_override,
            providers,
        )
        .await
    }

    /// A failed `create_container` must propagate as an error from `dev up` —
    /// no readiness may be reported when the container was not created. This
    /// is the core of issue #4's "must not report readiness unless actually
    /// created" acceptance.
    #[tokio::test]
    async fn up_propagates_create_container_error() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::failing(true, false);
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("create_container failure must surface as an error");
        let msg = format!("{err}");
        assert!(
            msg.contains("create_container failed"),
            "error should mention create failure, got: {msg}"
        );
    }

    /// A failed `start_container` must propagate as an error from `dev up` —
    /// readiness must not survive a start failure (issue #4).
    #[tokio::test]
    async fn up_propagates_start_container_error() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::failing(false, true);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("start_container failure must surface as an error");
    }

    /// The container config `dev up` hands to the runtime must carry the
    /// `devcontainer.local_folder` workspace label, and that label must match
    /// the one `dev status`/`dev exec` query with (`workspace_labels(workspace, None)`).
    ///
    /// On the issue #4 broken path, discovery was ID-based and the workspace
    /// label was not the join key, so `dev status`/`dev exec` could not find a
    /// container that `dev up` had just created. This pins the creation to
    /// discovery contract at the `up` layer; the Apple-runtime half is pinned
    /// in `runtime::apple::tests::to_apple_config_truncates_id_and_carries_discovery_label`.
    #[tokio::test]
    async fn up_labels_container_with_workspace_local_folder() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with a cooperating fake runtime");

        let created = rt.created_config();
        let discovery_labels = workspace_labels(workspace.path(), None);
        for (key, value) in &discovery_labels {
            assert_eq!(
                created.labels.get(key),
                Some(value),
                "dev up must set the {key} label used by dev status/dev exec"
            );
        }
        let local_folder = created
            .labels
            .get("devcontainer.local_folder")
            .expect("devcontainer.local_folder label must be set");
        let abs_workspace = workspace
            .path()
            .canonicalize()
            .unwrap_or_else(|_| workspace.path().to_path_buf());
        assert_eq!(
            local_folder,
            &abs_workspace.to_string_lossy().to_string(),
            "local_folder label must be the absolute workspace path"
        );
    }

    /// The reported issue #4 failure: create and start both succeed, but the
    /// container cannot be found by the workspace labels `dev status`/`dev exec`
    /// query with. `dev up` must fail instead of announcing readiness.
    #[tokio::test(start_paused = true)]
    async fn up_fails_when_started_container_is_not_discoverable() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::undiscoverable();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for an undiscoverable container");
        let msg = format!("{err}");
        assert!(
            msg.contains("not discoverable"),
            "error should explain the discovery failure, got: {msg}"
        );
    }

    /// A container that is created and started but never reaches the running
    /// state is not usable by `dev exec`, so `dev up` must not report readiness.
    #[tokio::test(start_paused = true)]
    async fn up_fails_when_started_container_never_runs() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::never_running();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for a container that is not running");
        let msg = format!("{err}");
        assert!(
            msg.contains("not running"),
            "error should explain the container is not running, got: {msg}"
        );
    }

    /// A monorepo config: `workspaceMount` attaches the repository, and
    /// `workspaceFolder` selects one project inside it. `dev up` must hand the
    /// runtime both — the mount root for the bind, the subdirectory for where
    /// commands run — or lifecycle hooks execute in the wrong directory.
    #[tokio::test]
    async fn up_carries_workspace_folder_subdirectory_to_the_runtime() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "workspaceMount": "source=${localWorkspaceFolder},target=/srv/app,type=bind",
                "workspaceFolder": "/srv/app/packages/api"
            }"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with a cooperating fake runtime");

        let created = rt.created_config();
        assert_eq!(
            created.workspace_mount.as_ref().map(|m| m.target.as_str()),
            Some("/srv/app"),
            "the repository must still be mounted at the workspaceMount target"
        );
        assert_eq!(
            created.workspace_folder.as_deref(),
            Some("/srv/app/packages/api"),
            "commands must run in the configured workspaceFolder subdirectory"
        );
    }

    /// Without an explicit `workspaceFolder`, the folder handed to the runtime
    /// is the mount destination, so commands still run in the source tree.
    #[tokio::test]
    async fn up_defaults_workspace_folder_to_the_mount_target() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "workspaceMount": "source=${localWorkspaceFolder},target=/srv/app,type=bind"
            }"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with a cooperating fake runtime");

        let created = rt.created_config();
        assert_eq!(created.workspace_folder.as_deref(), Some("/srv/app"));
    }

    /// A healthy container whose runtime takes a while to report `Running` must
    /// be waited for, not failed. Twelve polls is past what a fixed
    /// hundred-millisecond-per-attempt budget would tolerate, which is the
    /// spurious failure a VM-backed runtime would hit.
    #[tokio::test(start_paused = true)]
    async fn up_waits_for_a_container_that_reports_running_late() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::running_late(12);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a container that settles late must still be accepted");
    }

    /// The readiness gate polls in exactly the window where a VM-backed
    /// runtime's list/XPC call is most likely to fail transiently. A blip
    /// there must be retried like a not-yet-visible container, not turned into
    /// a hard failure for a container that is coming up fine.
    #[tokio::test(start_paused = true)]
    async fn up_retries_a_transient_list_failure_while_waiting_for_readiness() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::listing_fails_at_first(5);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a transient list failure must not abort a healthy `dev up`");
    }

    /// Tolerating list failures must not become ignoring them: a runtime that
    /// never answers has to fail the gate with the reason, not with a
    /// misleading "not discoverable".
    #[tokio::test(start_paused = true)]
    async fn up_reports_the_list_failure_when_it_never_clears() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::listing_never_works();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported when the runtime cannot be asked");
        let msg = format!("{err}");
        assert!(
            msg.contains("list_containers failed"),
            "the error must carry the runtime's own failure, got: {msg}"
        );
    }

    /// A daemon that accepts the list query and drops its reply never fails,
    /// so pacing the gaps between polls would never reach the next one. The
    /// discovery half has to bound the call itself or `dev up` sits silent
    /// after "Starting container..." exactly the way issue #4 did.
    #[tokio::test(start_paused = true)]
    async fn up_fails_when_the_list_query_is_never_answered() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::listing_never_answers();

        let err = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            run_up_with_fake(&rt, &workspace),
        )
        .await
        .expect("the readiness gate must bound the list rather than wait forever")
        .expect_err("readiness must not be reported when the runtime never answers the list");

        let msg = format!("{err}");
        assert!(
            msg.contains("did not answer within"),
            "the error must name the hang, got: {msg}"
        );
    }

    /// A blip that recovered must not claim the diagnosis. Once a later poll
    /// answers, the container really is absent from the workspace-label query
    /// — the exact issue #4 symptom — and that is what has to be reported,
    /// not a transient error the runtime already recovered from.
    #[tokio::test(start_paused = true)]
    async fn up_reports_undiscoverable_when_an_early_list_failure_recovered() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::undiscoverable_after_a_blip(1);
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for an undiscoverable container");
        let msg = format!("{err}");
        assert!(
            msg.contains("not discoverable"),
            "a recovered blip must not mask the discovery diagnosis, got: {msg}"
        );
        assert!(
            !msg.contains("list_containers failed"),
            "the stale error must not be reported once a later poll answered, got: {msg}"
        );
    }

    /// The acceptance criterion is that `dev up` must not report readiness for
    /// a container `dev exec` cannot use — and discovery plus `Running` only
    /// proves `dev exec` can *find* it. A config with no lifecycle hooks and no
    /// dotfiles never execs anything else, so the gate has to run a command
    /// itself or a broken exec path is announced as ready.
    #[tokio::test]
    async fn up_runs_a_command_in_the_container_before_reporting_readiness() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with a cooperating fake runtime");

        assert!(
            !rt.execs().is_empty(),
            "readiness must be gated on a command actually running in the container"
        );
    }

    /// The gate certifies the user every later command runs as. Probing as root
    /// would pass for a config whose `remoteUser` does not exist in the image,
    /// and the first `dev exec` would then fail on user resolution.
    #[tokio::test]
    async fn the_readiness_probe_runs_as_the_resolved_remote_user() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","remoteUser":"vscode"}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with a cooperating fake runtime");

        let (_, user, _) = rt.execs().first().cloned().expect("the gate must probe");
        assert_eq!(
            user.as_deref(),
            Some("vscode"),
            "the probe must run as the user lifecycle hooks and `dev exec` use"
        );
    }

    /// The exec endpoint of a VM-backed runtime can still be coming up when the
    /// daemon already reports `Running`. The discovery half waits that out, so
    /// the probe must too — a one-shot check would fail a healthy container.
    #[tokio::test(start_paused = true)]
    async fn up_retries_a_transient_exec_failure_while_waiting_for_readiness() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::execs_after(5);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a settling exec endpoint must not abort a healthy `dev up`");
    }

    /// Issue #4's actual symptom: the daemon drops the exit wait, so the exec
    /// never returns at all. Pacing the gaps between failures does not catch
    /// that — nothing ever fails — so the gate has to bound the call itself or
    /// `dev up` hangs silently after "Starting container..." forever.
    #[tokio::test(start_paused = true)]
    async fn up_fails_when_the_probe_never_reports_an_exit() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::execs_never_return();

        let err = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            run_up_with_fake(&rt, &workspace),
        )
        .await
        .expect("the readiness gate must bound the probe rather than wait forever")
        .expect_err("readiness must not be reported for a container whose exec never returns");

        let msg = format!("{err}");
        assert!(
            msg.contains("did not report an exit"),
            "the error must name the hang, got: {msg}"
        );
    }

    /// A runtime that refuses for the whole budget must be reported as refusing.
    /// The gate bounds each attempt by what is left, so an attempt granted a
    /// window too short to reach the runtime would time out and overwrite the
    /// real diagnosis with a hang that never happened.
    #[tokio::test(start_paused = true)]
    async fn up_reports_the_runtimes_own_exec_failure_not_a_phantom_hang() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::cannot_exec();

        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for a container that cannot exec");

        let msg = format!("{err}");
        assert!(
            msg.contains("exec failed (test-injected)"),
            "the runtime's own failure must survive to the end, got: {msg}"
        );
        assert!(
            !msg.contains("did not report an exit"),
            "a refusal must not be reported as a hang, got: {msg}"
        );
    }

    /// A runtime that refuses while its exec endpoint is coming up and then
    /// stops answering altogether is hanging, not refusing — the issue #4
    /// symptom. The last attempt leads because it describes the container as it
    /// stands, and the earlier refusal rides along as context rather than as
    /// the headline that would name the wrong problem.
    #[tokio::test(start_paused = true)]
    async fn up_leads_with_the_latest_hang_and_keeps_the_earlier_refusal() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::refuses_then_stops_answering(1);

        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for a container that cannot exec");

        let msg = format!("{err}");
        let hang = msg
            .find("did not report an exit")
            .unwrap_or_else(|| panic!("the hang is what is happening now, got: {msg}"));
        let refused = msg
            .find("exec failed (test-injected)")
            .unwrap_or_else(|| panic!("the earlier refusal must survive as context: {msg}"));
        assert!(
            hang < refused,
            "the latest signal leads and the refusal follows it, got: {msg}"
        );
    }

    /// When every attempt is refused, the refusal is both the latest signal and
    /// the whole story — it must not be dressed up as its own context.
    #[tokio::test(start_paused = true)]
    async fn up_reports_a_refusal_once_when_nothing_else_happened() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::cannot_exec();

        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for a container that cannot exec");

        let msg = format!("{err}");
        assert!(msg.contains("exec failed (test-injected)"), "{msg}");
        assert!(
            !msg.contains("an earlier attempt was refused"),
            "a refusal is not context for itself, got: {msg}"
        );
    }

    /// The other half of issue #4: the container is created, started and
    /// discoverable, but its exec path never reports a command's exit.
    #[tokio::test(start_paused = true)]
    async fn up_fails_when_no_command_can_run_in_the_started_container() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::cannot_exec();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for a container that cannot exec");
        let msg = format!("{err}");
        assert!(
            msg.contains("no command can be run in it"),
            "error should explain the exec failure, got: {msg}"
        );
    }

    /// The reported gap in the first fix: a container the gate has already
    /// refused is left running, so the next `dev up` takes the already-running
    /// arm. That arm must apply the same gate — otherwise the first `dev up`
    /// fails honestly and every later one reports readiness for a container
    /// `dev exec` still cannot run anything in.
    #[tokio::test(start_paused = true)]
    async fn up_refuses_an_already_running_container_no_command_can_run_in() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::cannot_exec().already_running(workspace.path(), &config_path);
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("readiness must not be reported for a reused container that cannot exec");
        let msg = format!("{err}");
        assert!(
            msg.contains("no command can be run in it"),
            "error should explain the exec failure, got: {msg}"
        );
    }

    /// The same arm must still be the fast path for a healthy container: the
    /// gate proves it, nothing is recreated, and `dev up` reports it as
    /// already running.
    #[tokio::test(start_paused = true)]
    async fn up_reuses_an_already_running_container_it_can_run_a_command_in() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a running container that runs commands must be reused");
        assert_eq!(
            rt.execs().len(),
            1,
            "the reused container must be probed exactly once"
        );
        assert!(
            rt.created_config.lock().unwrap().is_none(),
            "a usable running container must not be recreated"
        );
    }

    /// Reusing a running Docker/Podman container is the trigger; the masking
    /// condition is that its configured `WorkingDir` might happen to match the
    /// workspace folder. The probe must name the resolved folder either way so
    /// a stale unrelated `WorkingDir` cannot make `dev up` report readiness for
    /// lifecycle hooks and user commands that will run elsewhere.
    #[tokio::test(start_paused = true)]
    async fn up_probes_a_reused_running_container_in_the_workspace_folder() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "workspaceMount": "source=${localWorkspaceFolder},target=/srv/app,type=bind",
                "workspaceFolder": "/srv/app/packages/api"
            }"#,
        );
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a running reusable container should stay reusable");

        let (_, _, workdir) = rt.execs().first().cloned().expect("the gate must probe");
        assert_eq!(workdir.as_deref(), Some("/srv/app/packages/api"));
        assert!(
            rt.created_config.lock().unwrap().is_none(),
            "the existing container must not be recreated just to correct exec cwd"
        );
    }

    /// Matching control: when the effective workspace folder is the mount root,
    /// the reused-container path still passes that same path explicitly. This
    /// proves the fix is not conditional on detecting a mismatch we cannot
    /// reliably inspect through every runtime.
    #[tokio::test(start_paused = true)]
    async fn up_probes_a_reused_running_container_at_the_mount_root_control_path() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "workspaceMount": "source=${localWorkspaceFolder},target=/srv/app,type=bind"
            }"#,
        );
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a running reusable container should stay reusable");

        let (_, _, workdir) = rt.execs().first().cloned().expect("the gate must probe");
        assert_eq!(workdir.as_deref(), Some("/srv/app"));
    }

    /// A stopped existing container exercises the visible lifecycle symptom:
    /// `postStartCommand` runs after reuse and must not inherit a stale image
    /// or previous-config `WorkingDir`.
    #[tokio::test(start_paused = true)]
    async fn post_start_for_a_reused_stopped_container_runs_in_the_workspace_folder() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "workspaceMount": "source=${localWorkspaceFolder},target=/srv/app,type=bind",
                "workspaceFolder": "/srv/app/packages/api",
                "postStartCommand": "touch started"
            }"#,
        );
        let rt = UpFakeRuntime::ok().already_stopped(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a stopped reusable container should be started in place");

        let execs = rt.execs();
        assert_eq!(
            execs.len(),
            2,
            "reuse should run the readiness probe and the postStartCommand"
        );
        assert!(
            execs
                .iter()
                .all(|(_, _, workdir)| workdir.as_deref() == Some("/srv/app/packages/api")),
            "every workspace-scoped exec must use workspaceFolder, got: {execs:?}"
        );
        assert!(
            rt.created_config.lock().unwrap().is_none(),
            "a stopped reusable container must not be recreated"
        );
    }

    /// Collect the hook bodies from recorded execs. `hook_args` wraps each hook
    /// in `recorded_script`, so the body appears between newlines inside the
    /// `sh -c` argument.
    fn hook_bodies(execs: &[ExecCall]) -> Vec<String> {
        execs
            .iter()
            .filter_map(|(cmd, _, _)| {
                // `recorded_script` is what wraps a hook body, and only hooks
                // go through it — the readiness probe execs a bare script.
                let (before_status, _) = cmd.get(2)?.split_once("\n__dev_rc=$?")?;
                Some(before_status.lines().last()?.to_string())
            })
            .collect()
    }

    /// The reported bug: `postCreateCommand` belongs to container creation, so
    /// restarting a container that already exists must not run it again. Most
    /// setup scripts are not idempotent — this is where toolchains get
    /// installed and databases get seeded.
    #[tokio::test(start_paused = true)]
    async fn post_create_does_not_re_run_when_a_stopped_container_is_reused() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "onCreateCommand": "touch on-create",
                "updateContentCommand": "touch update-content",
                "postCreateCommand": "touch post-create",
                "postStartCommand": "touch post-start"
            }"#,
        );
        let rt = UpFakeRuntime::ok().already_stopped(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a stopped reusable container should be started in place");

        let bodies = hook_bodies(&rt.execs());
        assert_eq!(
            bodies,
            vec!["touch post-start"],
            "reuse owes postStartCommand and nothing else, got: {bodies:?}"
        );
    }

    /// The other half of the same rule: a container that really is new is owed
    /// every create-time hook, in spec order, before postStart.
    #[tokio::test(start_paused = true)]
    async fn a_created_container_runs_every_hook_in_spec_order() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "onCreateCommand": "touch on-create",
                "updateContentCommand": "touch update-content",
                "postCreateCommand": "touch post-create",
                "postStartCommand": "touch post-start"
            }"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a fresh container should come up");

        let bodies = hook_bodies(&rt.execs());
        assert_eq!(
            bodies,
            vec![
                "touch on-create",
                "touch update-content",
                "touch post-create",
                "touch post-start",
            ],
            "a created container is owed the full sequence in spec order, got: {bodies:?}"
        );
    }

    /// Reuse used to be gated on `postStartCommand` being present, which meant
    /// a config with only a `postCreateCommand` decided the question by
    /// accident. It must run nothing here for the right reason.
    #[tokio::test(start_paused = true)]
    async fn a_reused_container_runs_nothing_when_only_post_create_is_declared() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "postCreateCommand": "touch post-create"}"#,
        );
        let rt = UpFakeRuntime::ok().already_stopped(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a stopped reusable container should be started in place");

        let bodies = hook_bodies(&rt.execs());
        assert!(
            bodies.is_empty(),
            "no hook is owed on reuse when only postCreateCommand is declared, got: {bodies:?}"
        );
    }

    /// Feature-declared `postStartCommand`s run on every start, same as the
    /// config's. The restart path builds no image, so it has to resolve the
    /// feature hooks itself or they never fire.
    #[tokio::test(start_paused = true)]
    async fn a_reused_container_runs_feature_post_start_hooks() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "features": {"./greeter": {}}}"#,
        );
        let feature_dir = workspace.path().join(".devcontainer").join("greeter");
        fs::create_dir_all(&feature_dir).unwrap();
        fs::write(
            feature_dir.join("devcontainer-feature.json"),
            r#"{
                "id": "greeter",
                "version": "1.0.0",
                "postCreateCommand": "touch feature-post-create",
                "postStartCommand": "touch feature-post-start"
            }"#,
        )
        .unwrap();
        fs::write(feature_dir.join("install.sh"), "#!/bin/sh\n").unwrap();

        let rt = UpFakeRuntime::ok().already_stopped(workspace.path(), &config_path);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a stopped reusable container should be started in place");

        let bodies = hook_bodies(&rt.execs());
        assert_eq!(
            bodies,
            vec!["touch feature-post-start"],
            "a feature's postStartCommand fires on restart, its postCreateCommand does not, \
             got: {bodies:?}"
        );
    }

    /// Issue #13: feature-declared mounts must reach the created container,
    /// with `${devcontainerId}` resolved to the stable per-workspace hash. On
    /// the cache path the mounts come from the image's metadata label.
    #[tokio::test(start_paused = true)]
    async fn feature_mounts_reach_the_created_container() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "features": {"./dind": {}}}"#,
        );

        let rt = UpFakeRuntime::ok().with_metadata_entries(vec![serde_json::json!({
            "id": "dind",
            "mounts": [{
                "source": "dind-var-lib-docker-${devcontainerId}",
                "target": "/var/lib/docker",
                "type": "volume"
            }]
        })]);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a feature mount must not break container creation");

        let mounts = rt.created_config().mounts;
        let expected = format!(
            "dind-var-lib-docker-{}",
            crate::util::naming::devcontainer_id(workspace.path())
        );
        assert_eq!(mounts.len(), 1, "the feature volume mount must be applied");
        assert_eq!(mounts[0].source, std::path::PathBuf::from(&expected));
        assert_eq!(mounts[0].target, "/var/lib/docker");
    }

    /// Feature mounts come first, so a project mount can override a feature's
    /// target — the same feature-first order capabilities use.
    #[tokio::test(start_paused = true)]
    async fn feature_mounts_precede_config_mounts() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{
                "image": "ubuntu:24.04",
                "features": {"./dind": {}},
                "mounts": ["source=projvol,target=/proj,type=volume"]
            }"#,
        );

        let rt = UpFakeRuntime::ok().with_metadata_entries(vec![serde_json::json!({
            "id": "dind",
            "mounts": ["source=featvol,target=/feat,type=volume"]
        })]);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("feature and config mounts must coexist");

        let sources: Vec<String> = rt
            .created_config()
            .mounts
            .iter()
            .map(|m| m.source.display().to_string())
            .collect();
        assert_eq!(sources, ["featvol", "projvol"]);
    }

    /// Issue #15: feature entrypoints chain into the created container in
    /// install order. On the cache path they come from the image's metadata
    /// label, like every other contribution.
    #[tokio::test(start_paused = true)]
    async fn feature_entrypoints_chain_in_install_order() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "features": {"./dind": {}, "./sshd": {}}}"#,
        );

        let rt = UpFakeRuntime::ok().with_metadata_entries(vec![
            serde_json::json!({"id": "dind", "entrypoint": "/usr/local/share/docker-init.sh"}),
            serde_json::json!({"id": "sshd", "entrypoint": "/usr/local/share/ssh-init.sh"}),
        ]);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("feature entrypoints must not break container creation");

        assert_eq!(
            rt.created_config().entrypoint,
            Some(vec![
                "/usr/local/share/docker-init.sh".to_string(),
                "/usr/local/share/ssh-init.sh".to_string()
            ]),
            "entrypoints chain in install order"
        );
    }

    /// Issue #12: a container recreated from a cached features image gets a
    /// fresh container, so onCreate/postCreate/postStart are owed again. The
    /// cache branch never resolves features, so the hooks must be recovered
    /// from the image's `devcontainer.metadata` label.
    #[tokio::test(start_paused = true)]
    async fn a_container_recreated_from_a_cached_image_reruns_feature_create_hooks() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "features": {"./greeter": {}}}"#,
        );

        // `image_exists` is true, so up takes the cache-hit path; the hooks
        // exist only in the seeded metadata, never on disk.
        let rt = UpFakeRuntime::ok().with_metadata_entries(vec![serde_json::json!({
            "id": "greeter",
            "onCreateCommand": "touch feature-on-create",
            "postCreateCommand": "touch feature-post-create",
            "postStartCommand": "touch feature-post-start"
        })]);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a cached features image should still produce a container");

        let bodies = hook_bodies(&rt.execs());
        assert_eq!(
            bodies,
            vec![
                "touch feature-on-create",
                "touch feature-post-create",
                "touch feature-post-start"
            ],
            "feature hooks recovered from image metadata run on the new container, got: {bodies:?}"
        );
    }

    /// A cached image with no metadata label cannot restore contributions; the
    /// container must still come up, just without feature hooks.
    #[tokio::test(start_paused = true)]
    async fn cached_image_with_empty_metadata_warns_and_creates_without_contributions() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image": "ubuntu:24.04", "features": {"./greeter": {}}}"#,
        );

        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("missing metadata degrades to no contributions, not a failure");

        assert!(
            hook_bodies(&rt.execs()).is_empty(),
            "no hooks can be recovered from an empty metadata label"
        );
        assert!(
            rt.created_config.lock().unwrap().is_some(),
            "the container is still created"
        );
    }

    /// Compose has no reuse branch of its own — it reattaches and reports
    /// success either way — so this table is the whole decision.
    #[test]
    fn compose_hooks_follow_what_was_there_before_up() {
        use super::{ComposeHooks, compose_hooks_owed};

        let cases = [
            // (running_before, existed_before, rebuild, owed)
            (false, false, false, ComposeHooks::Create),
            (false, true, false, ComposeHooks::Start),
            (true, true, false, ComposeHooks::None),
            (true, true, true, ComposeHooks::Create),
            (false, true, true, ComposeHooks::Create),
        ];
        for (running, existed, rebuild, expected) in cases {
            assert_eq!(
                compose_hooks_owed(running, existed, rebuild),
                expected,
                "running={running} existed={existed} rebuild={rebuild}"
            );
        }
    }

    /// What the gate certifies is the runtime's create → start → wait sequence,
    /// not the image's contents. A shell-less scratch or distroless image
    /// answers the probe with a non-zero status — which means that sequence
    /// worked — so `dev up` reports the missing shell and still comes up.
    #[tokio::test(start_paused = true)]
    async fn up_tolerates_an_image_whose_shell_is_missing() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"scratch"}"#);
        let rt = UpFakeRuntime::execs_report(127);
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("an image without a shell must not fail a container that runs commands");
    }

    /// Any status a completed process reported is proof the transport worked,
    /// so it is accepted without a second attempt — the probe only retries a
    /// runtime that could not run the process at all.
    #[tokio::test(start_paused = true)]
    async fn up_accepts_any_status_a_completed_probe_reported() {
        for exit_code in [126, 127, 1] {
            let workspace = TempDir::new().unwrap();
            write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
            let rt = UpFakeRuntime::execs_report(exit_code);
            run_up_with_fake(&rt, &workspace)
                .await
                .unwrap_or_else(|e| panic!("exit {exit_code} proves the exec path works: {e}"));
            assert_eq!(
                rt.execs().len(),
                1,
                "a process that ran needs no retry, exit {exit_code}"
            );
        }
    }

    /// Some runtimes decline to start an exec whose executable is not in the
    /// image rather than running it and reporting 127. That is still the
    /// image's business, not a container `dev exec` cannot reach.
    #[tokio::test(start_paused = true)]
    async fn up_tolerates_a_runtime_that_refuses_a_missing_executable() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"scratch"}"#);
        let rt = UpFakeRuntime::has_no_shell();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a missing shell must be reported, not fail readiness");
    }

    /// Write a `.env` file inside the workspace's `.devcontainer` dir and
    /// return its path string.
    fn write_env_file(workspace: &TempDir, body: &str) -> std::path::PathBuf {
        let dir = workspace.path().join(".devcontainer");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".env");
        fs::write(&path, body).unwrap();
        path
    }

    /// Issue #5's exact reporter configuration: `--env-file` with
    /// `${localWorkspaceFolder}` substitution. The env-file's variables must
    /// reach the container-create request rather than being silently dropped.
    #[tokio::test]
    async fn up_env_file_substitutes_local_workspace_folder() {
        let workspace = TempDir::new().unwrap();
        write_env_file(&workspace, "FROM_FILE=true\nGREETING=hello\n");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file","${localWorkspaceFolder}/.devcontainer/.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with an env-file runArg");

        let env = rt.created_config().env;
        assert_eq!(env.get("FROM_FILE").map(String::as_str), Some("true"));
        assert_eq!(env.get("GREETING").map(String::as_str), Some("hello"));
    }

    /// The `--env-file=PATH` equals-attached form must be accepted too.
    #[tokio::test]
    async fn up_env_file_equals_form() {
        let workspace = TempDir::new().unwrap();
        write_env_file(&workspace, "EQ_FORM=yes\n");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file=${localWorkspaceFolder}/.devcontainer/.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with --env-file= form");

        assert_eq!(
            rt.created_config().env.get("EQ_FORM").map(String::as_str),
            Some("yes")
        );
    }

    /// `--env KEY=VALUE`, `--env=KEY=VALUE`, `-e KEY=VALUE`, and `-eKEY=VALUE`
    /// must all translate into container env entries.
    #[tokio::test]
    async fn up_env_flag_all_syntaxes() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env","A=1","--env=B=2","-e","C=3","-eD=4"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with --env/-e flags");

        let env = rt.created_config().env;
        assert_eq!(env.get("A").map(String::as_str), Some("1"));
        assert_eq!(env.get("B").map(String::as_str), Some("2"));
        assert_eq!(env.get("C").map(String::as_str), Some("3"));
        assert_eq!(env.get("D").map(String::as_str), Some("4"));
    }

    /// Bare env tokens pass through from the host when set, but an unset host
    /// variable fails safely instead of silently leaving the image value in
    /// place.
    #[tokio::test]
    async fn up_env_host_passthrough_errors_when_unset() {
        let workspace = TempDir::new().unwrap();
        unsafe { std::env::set_var("DEV_RUNARGS_UP_HOST_SET_FOR_UNSET_CASE", "host-value") };
        unsafe { std::env::remove_var("DEV_RUNARGS_UP_HOST_UNSET") };
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env","DEV_RUNARGS_UP_HOST_SET_FOR_UNSET_CASE","--env","DEV_RUNARGS_UP_HOST_UNSET"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("unset host pass-through env flag must fail safely");
        unsafe { std::env::remove_var("DEV_RUNARGS_UP_HOST_SET_FOR_UNSET_CASE") };
        let msg = format!("{err}");
        assert!(msg.contains("DEV_RUNARGS_UP_HOST_UNSET"), "{msg}");
        assert!(
            !rt.create_was_attempted(),
            "unset host pass-through must fail before container creation"
        );
    }

    #[tokio::test]
    async fn up_env_host_passthrough_uses_set_host_value() {
        let workspace = TempDir::new().unwrap();
        unsafe { std::env::set_var("DEV_RUNARGS_UP_HOST_SET_ONLY", "host-value") };
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env","DEV_RUNARGS_UP_HOST_SET_ONLY"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let result = run_up_with_fake(&rt, &workspace).await;
        unsafe { std::env::remove_var("DEV_RUNARGS_UP_HOST_SET_ONLY") };
        result.expect("up should succeed with set host pass-through env token");

        let env = rt.created_config().env;
        assert_eq!(
            env.get("DEV_RUNARGS_UP_HOST_SET_ONLY").map(String::as_str),
            Some("host-value")
        );
    }

    /// Docker CLI precedence: all env-files are processed first, then all
    /// `--env`/`-e` entries, regardless of interleaving. Explicit env flags
    /// override duplicate file values even when the flag appears first.
    #[tokio::test]
    async fn up_env_precedence_env_flags_override_env_files() {
        let workspace = TempDir::new().unwrap();
        write_env_file(&workspace, "KEY=from_file\nOTHER=file\n");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","containerEnv":{"KEY":"from_container_env"},"remoteEnv":{"REMOTE_ONLY":"from_remote_env"},"runArgs":["--env","KEY=from_flag","--env-file","${localWorkspaceFolder}/.devcontainer/.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with overlapping env sources");

        let env = rt.created_config().env;
        // Explicit env flags override both env-file and Dev's create-time env map.
        assert_eq!(env.get("KEY").map(String::as_str), Some("from_flag"));
        assert_eq!(env.get("OTHER").map(String::as_str), Some("file"));
        // Existing Dev behavior: remoteEnv is also part of the create-time map.
        assert_eq!(
            env.get("REMOTE_ONLY").map(String::as_str),
            Some("from_remote_env")
        );
    }

    /// `--cap-add`, `--security-opt`, `--privileged`, and `--init` are part of
    /// the supported runArgs subset and map onto existing container-create
    /// runtime fields.
    #[tokio::test]
    async fn up_runtime_option_runargs_reach_container_config() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--cap-add","SYS_PTRACE","--cap-add=NET_ADMIN","--security-opt","seccomp=unconfined","--security-opt=label=disable","--privileged","--init"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("supported runtime option runArgs should create successfully");

        let created = rt.created_config();
        assert_eq!(created.cap_add, vec!["SYS_PTRACE", "NET_ADMIN"]);
        assert_eq!(
            created.security_opt,
            vec!["seccomp=unconfined", "label=disable"]
        );
        assert!(created.privileged);
        assert!(created.init);
    }

    #[tokio::test]
    async fn up_userns_runarg_reaches_container_config() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--userns=keep-id"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("supported userns runArg should create successfully");

        assert_eq!(rt.created_config().userns_mode.as_deref(), Some("keep-id"));
    }

    #[tokio::test]
    async fn apple_runtime_rejects_non_environment_runargs_before_initialize_command() {
        let workspace = TempDir::new().unwrap();
        let marker = workspace.path().join("initialized");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","initializeCommand":"touch initialized","runArgs":["--cap-add","SYS_PTRACE"]}"#,
        );
        let rt = UpFakeRuntime::ok().named_runtime("apple");
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("Apple must reject runtime option runArgs before side effects");
        let msg = format!("{err}");
        assert!(msg.contains("Apple"), "{msg}");
        assert!(msg.contains("--cap-add"), "{msg}");
        assert!(!marker.exists(), "initializeCommand must not run");
        assert!(
            !rt.create_was_attempted(),
            "container creation must not run"
        );
    }

    #[tokio::test]
    async fn apple_runtime_accepts_environment_runargs() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env","A=1"]}"#,
        );
        let rt = UpFakeRuntime::ok().named_runtime("apple");
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("Apple keeps create-time environment runArgs support");

        assert_eq!(
            rt.created_config().env.get("A").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn runargs_capabilities_are_deduplicated_after_feature_capabilities() {
        let mut caps = MergedCapabilities {
            init: false,
            privileged: false,
            cap_add: vec!["SYS_PTRACE".to_string()],
            security_opt: vec!["seccomp=unconfined".to_string()],
        };
        let run_args = crate::devcontainer::run_args::ResolvedRunArgs {
            cap_add: vec!["SYS_PTRACE".to_string(), "NET_ADMIN".to_string()],
            security_opt: vec![
                "seccomp=unconfined".to_string(),
                "label=disable".to_string(),
            ],
            ..Default::default()
        };

        apply_run_args_capabilities(&mut caps, &run_args);

        assert_eq!(caps.cap_add, vec!["SYS_PTRACE", "NET_ADMIN"]);
        assert_eq!(
            caps.security_opt,
            vec!["seccomp=unconfined", "label=disable"]
        );
    }

    /// Repeated env files apply left-to-right; the last file's value for a key
    /// wins.
    #[tokio::test]
    async fn up_repeated_env_files_last_wins() {
        let workspace = TempDir::new().unwrap();
        write_env_file(&workspace, "SHARED=first\n");
        let second = workspace.path().join(".devcontainer").join("second.env");
        fs::write(&second, "SHARED=second\n").unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file","${localWorkspaceFolder}/.devcontainer/.env","--env-file","${localWorkspaceFolder}/.devcontainer/second.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("up should succeed with two env files");

        assert_eq!(
            rt.created_config().env.get("SHARED").map(String::as_str),
            Some("second")
        );
    }

    /// A missing env-file must fail before container creation with an error
    /// naming the path, not silently drop the flag.
    #[tokio::test]
    async fn up_missing_env_file_fails() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file","${localWorkspaceFolder}/.devcontainer/missing.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("a missing env-file must fail before container creation");
        let msg = format!("{err}");
        assert!(
            msg.contains("missing.env"),
            "error should name the missing env-file path, got: {msg}"
        );
        assert!(
            !rt.create_was_attempted(),
            "missing env-file must fail before container creation"
        );
    }

    /// A malformed env-file must fail before container creation with path and
    /// line context, without printing the secret-adjacent value.
    #[tokio::test]
    async fn up_malformed_env_file_fails_before_create_without_leaking_value() {
        let workspace = TempDir::new().unwrap();
        write_env_file(&workspace, "GOOD=1\n=secret-value\n");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file","${localWorkspaceFolder}/.devcontainer/.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("a malformed env-file must fail before container creation");
        let msg = format!("{err}");
        assert!(
            msg.contains(".env"),
            "error should name the env-file: {msg}"
        );
        assert!(msg.contains("line 2"), "error should name the line: {msg}");
        assert!(
            !msg.contains("secret-value"),
            "error must not leak env-file values: {msg}"
        );
        assert!(
            !rt.create_was_attempted(),
            "malformed env-file must fail before container creation"
        );
    }

    /// A non-UTF-8 env-file must fail before container creation without
    /// printing its bytes.
    #[tokio::test]
    async fn up_non_utf8_env_file_fails_before_create_without_leaking_bytes() {
        let workspace = TempDir::new().unwrap();
        let path = write_env_file(&workspace, "");
        fs::write(&path, b"OK=1\n\xff\xfeBAD\n").unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file","${localWorkspaceFolder}/.devcontainer/.env"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("a non-UTF-8 env-file must fail before container creation");
        let msg = format!("{err}");
        assert!(msg.contains("UTF-8"), "error should say UTF-8: {msg}");
        assert!(
            !rt.create_was_attempted(),
            "non-UTF-8 env-file must fail before container creation"
        );
    }

    /// A runArg outside the supported subset must fail before
    /// container creation with an error naming the unsupported flag, rather
    /// than being silently ignored (issue #5: every runArg was dropped).
    #[tokio::test]
    async fn up_unsupported_runarg_fails() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--network","host"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("an unsupported runArg must fail before container creation");
        let msg = format!("{err}");
        assert!(
            msg.contains("--network"),
            "error should name the unsupported flag, got: {msg}"
        );
        assert!(
            !rt.create_was_attempted(),
            "unsupported runArg must fail before container creation"
        );
    }

    /// Unsupported runArgs must be validated before initializeCommand can make
    /// host-visible changes.
    #[tokio::test]
    async fn up_unsupported_runarg_fails_before_initialize_command() {
        let workspace = TempDir::new().unwrap();
        let marker = workspace.path().join("initialized");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","initializeCommand":"touch initialized","runArgs":["--network","host"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("unsupported runArgs must fail before initializeCommand");
        let msg = format!("{err}");
        assert!(msg.contains("--network"), "{msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before runArgs validation"
        );
    }

    /// Existing-container fast paths must not bypass runArgs validation.
    #[tokio::test(start_paused = true)]
    async fn up_unsupported_runarg_fails_for_existing_running_container() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--network","host"]}"#,
        );
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("existing-container path must still validate runArgs");
        let msg = format!("{err}");
        assert!(msg.contains("--network"), "{msg}");
        assert!(
            rt.created_config.lock().unwrap().is_none(),
            "existing container must not be recreated during validation failure"
        );
    }

    const SECRETS_UNKNOWN_PROVIDER: &str =
        r#"{"version":1,"secrets":{"TOKEN":"nosuch://vault/item"}}"#;

    /// A provider name nothing answers to must fail before initializeCommand
    /// touches the host.
    #[tokio::test]
    async fn up_bad_secrets_json_fails_before_initialize_command() {
        let workspace = TempDir::new().unwrap();
        let marker = workspace.path().join("initialized");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","initializeCommand":"touch initialized"}"#,
        );
        write_secrets_json(&workspace, SECRETS_UNKNOWN_PROVIDER);
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("an unknown secret provider must fail before initializeCommand");
        let msg = format!("{err}");
        assert!(
            msg.contains("nosuch"),
            "error should name the provider: {msg}"
        );
        assert!(msg.contains("TOKEN"), "error should name the key: {msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before secrets validation"
        );
        assert!(!rt.create_was_attempted(), "{msg}");
    }

    /// A shorthand with no `://` is a parse failure, and it must land before the
    /// existing-container lookup rather than after it.
    #[tokio::test]
    async fn up_malformed_secret_reference_fails_before_container_lookup() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"no-scheme-here"}}"#,
        );
        // A runtime whose listing always fails: reaching the lookup would report
        // that instead, so the key in the message is the proof of ordering.
        let rt = UpFakeRuntime::listing_never_works();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("a malformed secret reference must fail the command");
        let msg = format!("{err}");
        assert!(
            msg.contains("TOKEN"),
            "secrets validation must precede the existing-container lookup: {msg}"
        );
        assert!(!rt.create_was_attempted(), "{msg}");
    }

    /// A document-level problem fails the same way a reference-level one does.
    #[tokio::test]
    async fn up_invalid_secrets_document_fails_before_container_creation() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":9,"secrets":{"TOKEN":"env://TOKEN"}}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("an unsupported secrets version must fail the command");
        assert!(format!("{err}").contains("version"), "{err}");
        assert!(!rt.create_was_attempted());
    }

    /// A reference body that variable substitution empties is an error, and it
    /// is one before any side effect.
    #[tokio::test]
    async fn up_empty_secret_reference_body_fails_before_container_creation() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"env://${localEnv:DEV_UP_SECRETS_UNSET_BODY}"}}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("an empty reference body must fail the command");
        assert!(format!("{err}").contains("TOKEN"), "{err}");
        assert!(!rt.create_was_attempted());
    }

    /// The existing-container fast path must not bypass secrets validation.
    #[tokio::test(start_paused = true)]
    async fn up_bad_secrets_json_fails_for_existing_running_container() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(&workspace, SECRETS_UNKNOWN_PROVIDER);
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("container reuse must still validate secrets");
        assert!(format!("{err}").contains("nosuch"), "{err}");
        assert!(!rt.create_was_attempted());
    }

    /// The regression guard for every workspace that declares no secrets.
    #[tokio::test]
    async fn up_without_secrets_json_is_unaffected() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a workspace with no secrets.json must be unaffected");
        assert_eq!(rt.created_config().image, "ubuntu:24.04");
    }

    /// A valid `secrets.json` validates, resolves against a real built-in
    /// provider, and the up path proceeds.
    #[tokio::test]
    async fn up_with_a_valid_secrets_json_proceeds() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        fs::write(workspace.path().join("token"), "from-a-file").unwrap();
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"file://${localWorkspaceFolder}/token"}}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake(&rt, &workspace)
            .await
            .expect("a valid secrets.json must not fail the command");
        assert!(rt.create_was_attempted());
    }

    const ONE_FAKE_SECRET: &str = r#"{"version":1,"secrets":{"TOKEN":"fake://item"}}"#;

    /// The whole point of the feature: a resolved value reaches the container
    /// the runtime is asked to create.
    #[tokio::test]
    async fn up_applies_resolved_secret_to_created_env() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(&workspace, ONE_FAKE_SECRET);
        let fake = FakeProvider::answering(&[("TOKEN", "resolved-value")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a resolvable secret must not fail the command");
        assert_eq!(
            rt.created_config().env.get("TOKEN"),
            Some(&"resolved-value".to_string())
        );
    }

    /// A `runArgs` `--env` flag is the last env tier before secrets, and a stale
    /// value there must not shadow a live one.
    #[tokio::test]
    async fn up_secret_outranks_run_args_env_flag() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env","TOKEN=stale"]}"#,
        );
        write_secrets_json(&workspace, ONE_FAKE_SECRET);
        let fake = FakeProvider::answering(&[("TOKEN", "resolved-value")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a resolvable secret must not fail the command");
        assert_eq!(
            rt.created_config().env.get("TOKEN"),
            Some(&"resolved-value".to_string())
        );
    }

    /// The other tier that would silently shadow a live secret.
    #[tokio::test]
    async fn up_secret_outranks_remote_env() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","remoteEnv":{"TOKEN":"stale"}}"#,
        );
        write_secrets_json(&workspace, ONE_FAKE_SECRET);
        let fake = FakeProvider::answering(&[("TOKEN", "resolved-value")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a resolvable secret must not fail the command");
        assert_eq!(
            rt.created_config().env.get("TOKEN"),
            Some(&"resolved-value".to_string())
        );
    }

    /// `createTime: false` is exec-time only: no provider call, no env entry,
    /// and not an error.
    #[tokio::test]
    async fn up_skips_create_time_false_secrets() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":{"provider":"fake","ref":"item","createTime":false}}}"#,
        );
        let fake = FakeProvider::answers_everything();
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("an exec-time-only secret must not fail the command");
        assert_eq!(fake.calls(), 0, "createTime: false must not be resolved");
        assert!(!rt.created_config().env.contains_key("TOKEN"));
    }

    /// The regression guard for every workspace that declares no secrets: not
    /// one provider is asked anything.
    #[tokio::test]
    async fn up_makes_no_provider_call_without_secrets_file() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let fake = FakeProvider::answers_everything();
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a workspace with no secrets.json must be unaffected");
        assert_eq!(fake.calls(), 0);
        assert!(rt.create_was_attempted());
    }

    /// Fan-out belongs to the registry. A per-secret loop in `up.rs` would show
    /// up here as two calls and two provider prompts.
    #[tokio::test]
    async fn up_batches_two_secrets_from_one_provider_into_one_call() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"fake://one","OTHER":"fake://two"}}"#,
        );
        let fake = FakeProvider::answering(&[("TOKEN", "first"), ("OTHER", "second")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("two secrets from one provider must resolve");
        assert_eq!(fake.calls(), 1, "one provider means one resolve call");
        let env = rt.created_config().env;
        assert_eq!(env.get("TOKEN"), Some(&"first".to_string()));
        assert_eq!(env.get("OTHER"), Some(&"second".to_string()));
    }

    /// An `optional` secret whose provider fails is omitted, and the container
    /// is still created. Pinned against the fix where `optional` is parsed but
    /// never consulted, which leaves a laptop with an expired vault session
    /// unable to start any container.
    ///
    /// The resolvable sibling is what stops this passing vacuously: without it
    /// a batch that never ran would look the same as one that ran and omitted.
    #[tokio::test]
    async fn up_omits_optional_secret_whose_provider_fails() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"PRESENT":"fake://present","TOKEN":{"provider":"fake","ref":"item","optional":true}}}"#,
        );
        let fake =
            FakeProvider::answering(&[("PRESENT", "present-value")]).also_failing_for("TOKEN");
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("an optional secret that cannot resolve must not fail the command");
        assert!(rt.create_was_attempted());
        let env = rt.created_config().env;
        assert_eq!(
            env.get("PRESENT"),
            Some(&"present-value".to_string()),
            "the resolvable half of the batch must still land"
        );
        assert!(
            !env.contains_key("TOKEN"),
            "an unresolvable optional secret must be omitted, not set empty"
        );
    }

    /// A required secret that cannot resolve fails the command, naming the key
    /// and nothing the provider answered with.
    #[tokio::test]
    async fn up_fails_when_a_required_secret_cannot_resolve() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"fake://item","KEEP":"fake://other"}}"#,
        );
        // KEEP resolves, TOKEN has no fixture: the batch half-succeeds, so the
        // error is the place a sibling value could leak.
        let fake = FakeProvider::answering(&[("KEEP", "s3cr3t-fixture")]);
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect_err("a required secret that cannot resolve must fail the command");
        let msg = format!("{err}");
        assert!(msg.contains("TOKEN"), "error should name the key: {msg}");
        assert!(!msg.contains("s3cr3t-fixture"), "{msg}");
        assert!(!rt.create_was_attempted());
    }

    /// Secrets are applied last, so they overwrite whatever the earlier env
    /// tiers left under the same key. Both call sites feed the same function, so
    /// the `--secrets-file` map and the resolved list get the same treatment.
    #[test]
    fn apply_secrets_to_env_overwrites_existing_key() {
        let resolved = [("TOKEN".to_string(), SecretValue::new("resolved-value"))];
        let mut env = HashMap::new();
        env.insert("TOKEN".to_string(), "from-env-file".to_string());
        apply_secrets_to_env(&mut env, resolved.iter().map(|(k, v)| (k.as_str(), v)));
        assert_eq!(env.get("TOKEN"), Some(&"resolved-value".to_string()));

        let from_file: BTreeMap<String, SecretValue> =
            [("TOKEN".to_string(), SecretValue::new("literal-value"))].into();
        apply_secrets_to_env(&mut env, from_file.iter().map(|(k, v)| (k.as_str(), v)));
        assert_eq!(env.get("TOKEN"), Some(&"literal-value".to_string()));
    }

    /// Validation already expanded every reference. A second pass here would
    /// eat a literal `$` out of a vault path.
    #[tokio::test]
    async fn up_does_not_substitute_secret_references() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"TOKEN":"fake://vault/${NOT_A_TOKEN}/item"}}"#,
        );
        let fake = FakeProvider::answers_everything();
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("an unrecognised variable must be left alone, not fail the command");
        let batches = fake.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0][0].reference(), "vault/${NOT_A_TOKEN}/item");
    }

    // ---- up-path secret invariants ----
    //
    // Four guarantees that a tidy-up of `run_with_runtime` would otherwise
    // break silently: resolution stays on the create path, no `Debug` prints a
    // value, an optional failure is survivable, and a resolved secret outranks
    // every other env tier.

    /// Hoisting the resolve call above the existing-container lookup costs a
    /// provider prompt on every warm `dev up`, which is what makes people turn
    /// secrets off. Validation still fires on this path; resolution must not.
    #[tokio::test(start_paused = true)]
    async fn up_does_not_resolve_secrets_when_reusing_a_running_container() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(&workspace, ONE_FAKE_SECRET);
        let fake = FakeProvider::answering(&[("TOKEN", "resolved-value")]);
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a reusable running container must not need secrets");
        assert_eq!(fake.calls(), 0, "reusing a container must not resolve");
        assert!(
            !rt.create_was_attempted(),
            "a zero call count proves nothing if the run never reached either branch"
        );
        assert_eq!(
            rt.execs().len(),
            1,
            "the reuse arm must run through the readiness probe"
        );
    }

    /// Restoring `#[derive(Debug)]` on `ContainerConfig`, or adding a
    /// convenience `Debug` to `SecretValue`, turns one future `{:?}` line into
    /// a full secret dump. Nothing prints either today, so nothing else fails.
    #[tokio::test]
    async fn up_created_config_debug_does_not_leak_a_resolved_secret() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"LEAK_CHECK":"fake://leak"}}"#,
        );
        let fake = FakeProvider::answering(&[("LEAK_CHECK", "hunter2-sentinel")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a resolvable secret must not fail the command");

        let created = rt.created_config();
        assert_eq!(
            created.env.get("LEAK_CHECK").map(String::as_str),
            Some("hunter2-sentinel"),
            "redaction that works by losing the value is not redaction"
        );
        let rendered = format!("{created:?}");
        assert!(
            !rendered.contains("hunter2-sentinel"),
            "ContainerConfig Debug must not print env values"
        );
        assert!(
            rendered.contains("LEAK_CHECK"),
            "env keys must stay visible for debugging"
        );
        assert!(
            rendered.contains("***"),
            "redacted values must be marked, not dropped"
        );
        let value = format!("{:?}", SecretValue::new("hunter2-sentinel"));
        assert!(
            !value.contains("hunter2-sentinel"),
            "SecretValue Debug must not print the value"
        );
    }

    /// Applying resolved secrets before the `runArgs` env loop instead of after
    /// it lets a checked-in `.env` win over the vault: the container comes up
    /// fine and the app talks to the wrong backend.
    #[tokio::test]
    async fn up_secret_overrides_a_conflicting_env_file_key() {
        let workspace = TempDir::new().unwrap();
        write_env_file(&workspace, "SHARED=from_env_file\nOTHER=from_env_file\n");
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env-file","${localWorkspaceFolder}/.devcontainer/.env"]}"#,
        );
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"SHARED":"fake://shared"}}"#,
        );
        let fake = FakeProvider::answering(&[("SHARED", "from_secret")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect("a resolvable secret must not fail the command");
        let env = rt.created_config().env;
        assert_eq!(env.get("SHARED").map(String::as_str), Some("from_secret"));
        assert_eq!(
            env.get("OTHER").map(String::as_str),
            Some("from_env_file"),
            "an env-file that stopped loading would look like a secret winning"
        );
    }

    // ---- `--secrets-file`: literal values, in the `remoteEnv` tier ----
    //
    // A separate document from `secrets.json` with a separate loader. Nothing
    // here parses a reference or asks a provider anything, and no error carries
    // a value out of the document.

    /// A `--secrets-file` document somewhere outside the workspace.
    fn write_literals_file(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("literals.json");
        fs::write(&path, content).unwrap();
        path
    }

    fn load_literals(
        dir: &TempDir,
        content: &str,
    ) -> anyhow::Result<BTreeMap<String, SecretValue>> {
        super::load_secrets_file(&write_literals_file(dir, content))
    }

    #[test]
    fn secrets_file_loads_every_entry_as_a_literal() {
        let dir = TempDir::new().unwrap();
        let loaded = load_literals(&dir, r#"{"ONE":"first","TWO":"op://Private/x/y"}"#)
            .expect("a flat string map must load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["ONE"].expose(), "first");
        assert_eq!(
            loaded["TWO"].expose(),
            "op://Private/x/y",
            "a value that looks like a reference is still a literal"
        );
    }

    #[test]
    fn secrets_file_empty_object_is_valid_and_empty() {
        let dir = TempDir::new().unwrap();
        assert!(
            load_literals(&dir, "{}")
                .expect("{} is a valid document")
                .is_empty()
        );
    }

    #[test]
    fn secrets_file_debug_prints_no_value() {
        let dir = TempDir::new().unwrap();
        let loaded = load_literals(&dir, r#"{"ONE":"first-value"}"#).unwrap();
        let rendered = format!("{loaded:?}");
        assert!(rendered.contains("ONE"));
        assert!(!rendered.contains("first-value"), "{rendered}");
    }

    /// Table of documents this loader must reject, each with the text that must
    /// be in the message and the text that must not.
    #[test]
    fn secrets_file_rejects_bad_documents_without_echoing_values() {
        let cases: &[(&str, &str, &str)] = &[
            (
                r#"{"version":1,"secrets":{"K":"op://a/b/c"}}"#,
                "secrets",
                "op://a/b/c",
            ),
            (
                r#"["sentinel-alpha","sentinel-beta"]"#,
                "must be a JSON object",
                "sentinel-alpha",
            ),
            (
                r#""just-a-string""#,
                "must be a JSON object",
                "just-a-string",
            ),
            (r#"{"PIN":1234}"#, "PIN", "1234"),
            (r#"{"BAD KEY":"v"}"#, "BAD KEY", "v\""),
            (
                r#"{"":"v"}"#,
                "not a valid environment variable name",
                "v\"",
            ),
            (r#"{"A=B":"v"}"#, "A=B", "v\""),
            // U+00A0. `secrets.json` refuses it, so this flag must too:
            // `env_name_problem` is the one rule both go through.
            ("{\"A\u{a0}B\":\"v\"}", "contains whitespace", "v\""),
            (r#"{"K":"#, "not valid JSON", "K\":"),
        ];
        for (body, expected, forbidden) in cases {
            let dir = TempDir::new().unwrap();
            let err = load_literals(&dir, body).expect_err(&format!("`{body}` must be rejected"));
            let msg = format!("{err}");
            assert!(msg.contains(expected), "`{body}` gave: {msg}");
            assert!(!msg.contains(forbidden), "`{body}` leaked content: {msg}");
        }
    }

    #[test]
    fn secrets_file_non_utf8_names_the_path_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("literals.json");
        fs::write(&path, [0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d]).unwrap();
        let err = super::load_secrets_file(&path).expect_err("non-UTF-8 must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("literals.json"), "{msg}");
        assert!(msg.contains("not valid UTF-8"), "{msg}");
    }

    #[tokio::test]
    async fn up_secrets_file_values_reach_the_created_container() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(&literals, r#"{"TOKEN":"literal-value"}"#);
        let rt = UpFakeRuntime::ok();
        run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect("a valid --secrets-file must not fail the command");
        assert_eq!(
            rt.created_config().env.get("TOKEN"),
            Some(&"literal-value".to_string())
        );
    }

    /// The flag sits in the `remoteEnv` tier, so it beats a config-declared
    /// `remoteEnv` entry for the same key.
    #[tokio::test]
    async fn up_secrets_file_overrides_remote_env_for_the_same_key() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","remoteEnv":{"TOKEN":"from_remote_env","KEEP":"from_remote_env"}}"#,
        );
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(&literals, r#"{"TOKEN":"from_secrets_file"}"#);
        let rt = UpFakeRuntime::ok();
        run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect("a valid --secrets-file must not fail the command");
        let env = rt.created_config().env;
        assert_eq!(env.get("TOKEN"), Some(&"from_secrets_file".to_string()));
        assert_eq!(
            env.get("KEEP"),
            Some(&"from_remote_env".to_string()),
            "a remoteEnv that stopped loading would look like the flag winning"
        );
    }

    /// ...and loses to `runArgs` env, which is the tier above it.
    #[tokio::test]
    async fn up_run_args_env_overrides_secrets_file_for_the_same_key() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","runArgs":["--env","TOKEN=from_run_args"]}"#,
        );
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(
            &literals,
            r#"{"TOKEN":"from_secrets_file","KEEP":"from_secrets_file"}"#,
        );
        let rt = UpFakeRuntime::ok();
        run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect("a valid --secrets-file must not fail the command");
        let env = rt.created_config().env;
        assert_eq!(env.get("TOKEN"), Some(&"from_run_args".to_string()));
        assert_eq!(env.get("KEEP"), Some(&"from_secrets_file".to_string()));
    }

    /// ...and loses to a resolved `secrets.json` secret, which is applied last.
    #[tokio::test]
    async fn up_resolved_secret_overrides_secrets_file_for_the_same_key() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(&workspace, ONE_FAKE_SECRET);
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(
            &literals,
            r#"{"TOKEN":"from_secrets_file","KEEP":"from_secrets_file"}"#,
        );
        let fake = FakeProvider::answering(&[("TOKEN", "resolved-value")]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers_and_secrets_file(
            &rt,
            &workspace,
            &registry_with(&workspace, &fake),
            Some(&path),
        )
        .await
        .expect("a resolvable secret must not fail the command");
        let env = rt.created_config().env;
        assert_eq!(env.get("TOKEN"), Some(&"resolved-value".to_string()));
        assert_eq!(env.get("KEEP"), Some(&"from_secrets_file".to_string()));
    }

    /// A references document handed to the values flag is rejected by its
    /// shape, before initializeCommand touches the host.
    #[tokio::test]
    async fn up_rejects_a_reference_shaped_secrets_file_before_any_side_effect() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","initializeCommand":"touch initialized"}"#,
        );
        let marker = workspace.path().join("initialized");
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(
            &literals,
            r#"{"version":1,"secrets":{"TOKEN":"op://Private/x/y"}}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect_err("a references document must not load as literal values");
        let msg = format!("{err}");
        assert!(msg.contains("--secrets"), "{msg}");
        assert!(!msg.contains("op://Private/x/y"), "{msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before the --secrets-file check"
        );
        assert!(!rt.create_was_attempted(), "{msg}");
    }

    /// Unlike the sidecar, an explicitly named file must be there.
    #[tokio::test]
    async fn up_rejects_a_missing_secrets_file_path() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let literals = TempDir::new().unwrap();
        let path = literals.path().join("nothing-here.json");
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect_err("a missing --secrets-file path must fail the command");
        let msg = format!("{err}");
        assert!(msg.contains("nothing-here.json"), "{msg}");
        assert!(!rt.create_was_attempted(), "{msg}");
    }

    /// The reuse path injects nothing, but it still validates: a bad document
    /// is a bad document whichever branch the run would have taken.
    #[tokio::test(start_paused = true)]
    async fn up_rejects_a_bad_secrets_file_on_the_reuse_path_too() {
        let workspace = TempDir::new().unwrap();
        let config_path = write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(&literals, r#"{"PIN":1234}"#);
        let rt = UpFakeRuntime::ok().already_running(workspace.path(), &config_path);
        let err = run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect_err("container reuse must still validate --secrets-file");
        let msg = format!("{err}");
        assert!(msg.contains("PIN"), "{msg}");
        assert!(!msg.contains("1234"), "{msg}");
        assert!(rt.execs().is_empty(), "the reuse arm must not have run");
    }

    /// Compose environment is written to a generated override file on disk, so
    /// the flag is refused before any compose command runs.
    #[tokio::test]
    async fn up_rejects_a_secrets_file_on_a_compose_project() {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        fs::write(
            devcontainer_dir.join("compose.yml"),
            "services:\n  app:\n    image: ubuntu:24.04\n",
        )
        .unwrap();
        write_project_config(
            &workspace,
            r#"{"dockerComposeFile":"compose.yml","service":"app","initializeCommand":"touch initialized"}"#,
        );
        let marker = workspace.path().join("initialized");
        let literals = TempDir::new().unwrap();
        let path = write_literals_file(&literals, r#"{"TOKEN":"literal-value"}"#);
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake_secrets_file(&rt, &workspace, Some(&path))
            .await
            .expect_err("--secrets-file must fail before any compose command");
        let msg = format!("{err}");
        assert!(msg.contains("--secrets-file"), "{msg}");
        assert!(msg.contains("Compose"), "{msg}");
        assert!(!msg.contains("literal-value"), "{msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before the compose rejection"
        );
    }

    // ---- `--secrets`: a references file from somewhere else ----
    //
    // Replacement, never a merge: exactly one references file is read per
    // `dev up`, so there is no precedence order between two reference sources.

    /// A references document outside the workspace, for `--secrets`.
    fn write_out_of_tree_secrets(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("elsewhere.json");
        fs::write(&path, content).unwrap();
        path
    }

    /// The invariant most likely to rot: a sidecar that exists is not read, not
    /// parsed, and contributes no key. Both keys go through the same fake, so a
    /// missing `SIDECAR_ONLY` cannot be an unresolvable-provider accident.
    #[tokio::test]
    async fn up_secrets_flag_overrides_sidecar() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        write_secrets_json(
            &workspace,
            r#"{"version":1,"secrets":{"SIDECAR_ONLY":"fake://sidecar"}}"#,
        );
        let elsewhere = TempDir::new().unwrap();
        let path = write_out_of_tree_secrets(
            &elsewhere,
            r#"{"version":1,"secrets":{"OVERRIDE_ONLY":"fake://override"}}"#,
        );
        let fake = FakeProvider::answering(&[
            ("OVERRIDE_ONLY", "from-override"),
            ("SIDECAR_ONLY", "from-sidecar"),
        ]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers_and_secrets(
            &rt,
            &workspace,
            &registry_with(&workspace, &fake),
            Some(&path),
        )
        .await
        .expect("an explicit --secrets file must not fail the command");
        let env = rt.created_config().env;
        assert_eq!(env.get("OVERRIDE_ONLY"), Some(&"from-override".to_string()));
        assert!(
            !env.contains_key("SIDECAR_ONLY"),
            "--secrets replaces the sidecar, it does not merge with it"
        );
        assert_eq!(
            fake.batch_keys(),
            vec![vec!["OVERRIDE_ONLY".to_string()]],
            "the sidecar must not even be parsed"
        );
    }

    /// A missing sidecar is not an error. A path the user typed is.
    #[tokio::test]
    async fn up_missing_explicit_secrets_path_errors_before_side_effects() {
        let workspace = TempDir::new().unwrap();
        write_project_config(
            &workspace,
            r#"{"image":"ubuntu:24.04","initializeCommand":"touch initialized"}"#,
        );
        let marker = workspace.path().join("initialized");
        let elsewhere = TempDir::new().unwrap();
        let path = elsewhere.path().join("never-created.json");
        // A runtime whose listing always fails: reaching the lookup would report
        // that instead, so the path in the message is the proof of ordering.
        let rt = UpFakeRuntime::listing_never_works();
        let err = run_up_with_fake_flags(&rt, &workspace, None, Some(&path))
            .await
            .expect_err("a --secrets path that is not a file must fail the command");
        let msg = format!("{err}");
        assert!(msg.contains("never-created.json"), "{msg}");
        assert!(msg.contains("--secrets"), "{msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before the --secrets check"
        );
        assert!(!rt.create_was_attempted(), "{msg}");
    }

    /// Both flags at once. Each loads through its own loader, and the resolved
    /// `--secrets` entry still wins because resolved secrets are applied last.
    #[tokio::test]
    async fn up_secrets_and_secrets_file_stay_independent() {
        let workspace = TempDir::new().unwrap();
        write_project_config(&workspace, r#"{"image":"ubuntu:24.04"}"#);
        let elsewhere = TempDir::new().unwrap();
        let references = write_out_of_tree_secrets(
            &elsewhere,
            r#"{"version":1,"secrets":{"SHARED":"fake://shared","REFERENCE_ONLY":"fake://ref"}}"#,
        );
        let literals = TempDir::new().unwrap();
        let values = write_literals_file(
            &literals,
            r#"{"SHARED":"from_secrets_file","LITERAL_ONLY":"literal-value"}"#,
        );
        let fake = FakeProvider::answering(&[
            ("SHARED", "from_reference"),
            ("REFERENCE_ONLY", "reference-value"),
        ]);
        let rt = UpFakeRuntime::ok();
        run_up_with_providers_and_flags(
            &rt,
            &workspace,
            &registry_with(&workspace, &fake),
            Some(&values),
            Some(&references),
        )
        .await
        .expect("both secret flags together must not fail the command");
        let env = rt.created_config().env;
        assert_eq!(env.get("SHARED"), Some(&"from_reference".to_string()));
        assert_eq!(
            env.get("REFERENCE_ONLY"),
            Some(&"reference-value".to_string())
        );
        assert_eq!(env.get("LITERAL_ONLY"), Some(&"literal-value".to_string()));
    }

    /// The compose branch returns before anything would read a references file,
    /// so an accepted `--secrets` would be a path read by nothing.
    #[tokio::test]
    async fn up_rejects_explicit_secrets_for_compose() {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        fs::write(
            devcontainer_dir.join("compose.yml"),
            "services:\n  app:\n    image: ubuntu:24.04\n",
        )
        .unwrap();
        write_project_config(
            &workspace,
            r#"{"dockerComposeFile":"compose.yml","service":"app","initializeCommand":"touch initialized"}"#,
        );
        let marker = workspace.path().join("initialized");
        let elsewhere = TempDir::new().unwrap();
        // Empty on purpose: naming a file this path reads with nothing is still
        // the silent misbehaviour the rejection exists to prevent.
        let path = write_out_of_tree_secrets(&elsewhere, r#"{"version":1,"secrets":{}}"#);
        let fake = FakeProvider::answers_everything();
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_providers_and_secrets(
            &rt,
            &workspace,
            &registry_with(&workspace, &fake),
            Some(&path),
        )
        .await
        .expect_err("--secrets must fail before any compose command");
        let msg = format!("{err}");
        assert!(msg.contains("elsewhere.json"), "{msg}");
        assert!(msg.contains("Compose"), "{msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before the compose rejection"
        );
        assert_eq!(fake.calls(), 0, "the compose path resolves nothing");
    }

    /// Compose projects have a separate runtime path; non-empty runArgs must
    /// fail explicitly instead of being silently ignored or passed to docker
    /// compose indirectly.
    #[tokio::test]
    async fn compose_project_with_runargs_fails_with_compose_guidance() {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        fs::write(
            devcontainer_dir.join("compose.yml"),
            "services:\n  app:\n    image: ubuntu:24.04\n",
        )
        .unwrap();
        write_project_config(
            &workspace,
            r#"{"dockerComposeFile":"compose.yml","service":"app","runArgs":["--env","A=1"]}"#,
        );
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_fake(&rt, &workspace)
            .await
            .expect_err("compose runArgs must fail explicitly before compose commands");
        let msg = format!("{err}");
        assert!(msg.contains("runArgs"), "{msg}");
        assert!(
            msg.contains("Compose") || msg.contains("compose"),
            "error should direct users to compose service configuration: {msg}"
        );
    }

    /// The Compose path builds its own env map and never reads `secrets.json`,
    /// so a declared secret must fail before `run_compose` does anything. The
    /// missing `initialized` marker is the proof: `initializeCommand` is the
    /// first thing `run_compose` runs.
    #[tokio::test]
    async fn compose_project_with_secrets_fails_before_any_compose_side_effect() {
        let workspace = TempDir::new().unwrap();
        let devcontainer_dir = workspace.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        fs::write(
            devcontainer_dir.join("compose.yml"),
            "services:\n  app:\n    image: ubuntu:24.04\n",
        )
        .unwrap();
        write_project_config(
            &workspace,
            r#"{"dockerComposeFile":"compose.yml","service":"app","initializeCommand":"touch initialized"}"#,
        );
        write_secrets_json(&workspace, ONE_FAKE_SECRET);
        let marker = workspace.path().join("initialized");

        let fake = FakeProvider::answers_everything();
        let rt = UpFakeRuntime::ok();
        let err = run_up_with_providers(&rt, &workspace, &registry_with(&workspace, &fake))
            .await
            .expect_err("a compose secrets.json must fail before any compose command");
        let msg = format!("{err}");

        assert!(msg.contains("secrets.json"), "{msg}");
        assert!(msg.contains("Compose"), "{msg}");
        assert!(
            !marker.exists(),
            "initializeCommand must not run before the compose rejection"
        );
        assert!(!rt.create_was_attempted(), "{msg}");
        assert_eq!(fake.calls(), 0, "the compose path resolves nothing");
    }

    /// Compose `up -d` can return and `compose ps -q <service>` can identify
    /// the target container while its exec endpoint is still settling. The
    /// Compose path must wait through the same bounded usability seam as the
    /// image path, then return immediately once an exec can run.
    #[tokio::test(start_paused = true)]
    async fn compose_readiness_waits_until_the_target_service_can_exec() {
        let workspace = TempDir::new().unwrap();
        let rt =
            UpFakeRuntime::execs_after(3).compose_target(workspace.path(), ContainerState::Running);

        super::verify_compose_service_ready(
            &rt,
            workspace.path(),
            "app",
            "fake-id",
            Some("vscode"),
        )
        .await
        .expect("a Compose service whose exec endpoint settles must become ready");

        assert_eq!(
            rt.execs().len(),
            4,
            "readiness must retry the transient exec failures and stop after the first success"
        );
        assert!(
            rt.execs()
                .iter()
                .all(|(_, user, workdir)| user.as_deref() == Some("vscode")
                    && workdir.as_deref().is_none()),
            "Compose readiness must preserve the existing Compose command working-directory behavior"
        );
    }

    /// Terminal Compose service states are not startup timing: once the
    /// resolved service container is known to be stopped, hooks would fail the
    /// same way and the user needs service/container context immediately.
    #[tokio::test(start_paused = true)]
    async fn compose_readiness_fails_terminal_target_service_state_promptly() {
        let workspace = TempDir::new().unwrap();
        let rt = UpFakeRuntime::ok().compose_target(workspace.path(), ContainerState::Stopped);
        let started = tokio::time::Instant::now();

        let err =
            super::verify_compose_service_ready(&rt, workspace.path(), "app", "fake-id", None)
                .await
                .expect_err("a stopped Compose target service must fail readiness");
        let msg = format!("{err}");

        assert!(msg.contains("Compose service 'app'"), "{msg}");
        assert!(msg.contains("fake-id"), "{msg}");
        assert!(msg.contains("not running"), "{msg}");
        assert!(
            rt.execs().is_empty(),
            "terminal service state must fail before probing exec"
        );
        assert!(
            tokio::time::Instant::now().duration_since(started) < super::READINESS_FIRST_POLL,
            "terminal service state must not spend the readiness retry budget"
        );
    }

    /// An inspect that fails is this gate's own settling window, not a verdict
    /// on the service: the daemon is most likely to blip in exactly the moment
    /// after `compose up` that readiness polls. Retried like every other
    /// runtime query here, so a healthy service is not failed on a blip.
    #[tokio::test(start_paused = true)]
    async fn compose_readiness_retries_a_transient_inspect_failure() {
        let workspace = TempDir::new().unwrap();
        let rt = UpFakeRuntime {
            inspect_errors_before_success: Arc::new(AtomicUsize::new(3)),
            ..UpFakeRuntime::ok()
        }
        .compose_target(workspace.path(), ContainerState::Running);

        super::verify_compose_service_ready(&rt, workspace.path(), "app", "fake-id", None)
            .await
            .expect("a blipping inspect must be retried, not treated as a failed service");
    }

    /// A runtime that never answers an inspect cannot be asked whether the
    /// service is running, so readiness must spend its budget and then report
    /// what the runtime last said — not hang, and not run hooks.
    #[tokio::test(start_paused = true)]
    async fn compose_readiness_fails_when_the_service_can_never_be_inspected() {
        let workspace = TempDir::new().unwrap();
        let rt = UpFakeRuntime {
            inspect_errors_before_success: Arc::new(AtomicUsize::new(usize::MAX)),
            ..UpFakeRuntime::ok()
        }
        .compose_target(workspace.path(), ContainerState::Running);
        let started = tokio::time::Instant::now();

        let err =
            super::verify_compose_service_ready(&rt, workspace.path(), "app", "fake-id", None)
                .await
                .expect_err("an uninspectable Compose service must fail readiness");
        let msg = format!("{err}");

        assert!(
            tokio::time::Instant::now().duration_since(started) <= super::READINESS_BUDGET,
            "an uninspectable service must not outlive the readiness budget"
        );
        assert!(msg.contains("Compose service 'app'"), "{msg}");
        assert!(msg.contains("could not be inspected"), "{msg}");
        assert!(
            msg.contains("inspect_container failed (test-injected)"),
            "{msg}"
        );
        assert!(
            rt.execs().is_empty(),
            "a service that cannot be inspected must not be probed"
        );
    }

    /// A service that is running and discoverable but never reports an exec
    /// exit must exhaust the bounded readiness budget, not hang forever or let
    /// lifecycle hooks run.
    #[tokio::test(start_paused = true)]
    async fn compose_readiness_fails_when_target_service_never_becomes_usable() {
        let workspace = TempDir::new().unwrap();
        let rt = UpFakeRuntime::execs_never_return()
            .compose_target(workspace.path(), ContainerState::Running);

        let err = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            super::verify_compose_service_ready(&rt, workspace.path(), "app", "fake-id", None),
        )
        .await
        .expect("Compose readiness must bound the probe rather than wait forever")
        .expect_err("a never-usable Compose service must fail readiness");
        let msg = format!("{err}");

        assert!(msg.contains("Compose service 'app'"), "{msg}");
        assert!(msg.contains("fake-id"), "{msg}");
        assert!(msg.contains("did not report an exit"), "{msg}");
    }

    /// Compose readiness is one user-visible 15-second operation, not one
    /// 15-second budget for discovery followed by another for exec. Both
    /// phases are slow here; the old stacked-budget implementation succeeded
    /// after the documented bound instead of failing at the shared deadline.
    #[tokio::test(start_paused = true)]
    async fn compose_readiness_shares_one_deadline_across_discovery_and_exec() {
        let workspace = TempDir::new().unwrap();
        let rt = UpFakeRuntime {
            list_errors_before_success: Arc::new(AtomicUsize::new(16)),
            exec_errors_before_success: Arc::new(AtomicUsize::new(16)),
            ..UpFakeRuntime::ok()
        }
        .compose_target(workspace.path(), ContainerState::Running);
        rt.start_container("fake-id")
            .await
            .expect("fake start marks the compose target as in the post-up window");

        let started = tokio::time::Instant::now();
        let err =
            super::verify_compose_service_ready(&rt, workspace.path(), "app", "fake-id", None)
                .await
                .expect_err("compose readiness must fail at the one shared deadline");
        let elapsed = tokio::time::Instant::now().duration_since(started);
        let msg = format!("{err}");

        assert!(
            elapsed <= super::READINESS_BUDGET,
            "readiness must not exceed the shared budget; elapsed {elapsed:?}"
        );
        assert!(
            elapsed >= super::READINESS_BUDGET - super::READINESS_MIN_ATTEMPT,
            "both phases share one budget, so a run that fails in both must spend \
             nearly all of it rather than stopping at one phase's share; elapsed {elapsed:?}"
        );
        assert!(msg.contains("Compose service 'app'"), "{msg}");
        assert!(msg.contains("fake-id"), "{msg}");
        assert!(
            msg.contains("did not report an exit") || msg.contains("exec failed (test-injected)"),
            "the timeout should retain the exec-side last cause after discovery consumed budget: {msg}"
        );
    }

    /// Lifecycle hooks are the visible race: without a readiness gate the
    /// first postStartCommand is the first exec and fails. The bounded helper
    /// must finish before hooks run, so the hook is after the successful probe.
    #[tokio::test(start_paused = true)]
    async fn compose_lifecycle_hooks_run_only_after_readiness_probe_succeeds() {
        let workspace = TempDir::new().unwrap();
        let config: DevcontainerConfig = serde_json::from_str(
            r#"{"dockerComposeFile":"compose.yml","service":"app","postStartCommand":"touch ready"}"#,
        )
        .unwrap();
        let rt =
            UpFakeRuntime::execs_after(2).compose_target(workspace.path(), ContainerState::Running);

        super::verify_compose_service_ready(&rt, workspace.path(), "app", "fake-id", None)
            .await
            .expect("readiness should wait for the target service to become usable");
        crate::devcontainer::run_create_hooks(&rt, "fake-id", &config, None, None, None)
            .await
            .expect("lifecycle hook should run after readiness");

        let execs = rt.execs();
        assert_eq!(
            execs.len(),
            4,
            "two transient probe failures, one successful probe, then the lifecycle hook"
        );
        let last = execs
            .last()
            .map(|(cmd, _, _)| cmd.join(" "))
            .unwrap_or_default();
        assert!(
            last.starts_with("sh -c ") && last.contains("\ntouch ready\n"),
            "the lifecycle hook must not race ahead of the successful readiness probe, got: {last}"
        );
    }

    /// A runtime that shortens ids (as Apple Containers does, to fit its
    /// 36-character limit) must still count as discovered.
    #[test]
    fn same_container_tolerates_shortened_ids() {
        assert!(super::same_container("abc123def456", "abc123def456"));
        assert!(super::same_container("abc123def456", "abc123"));
        assert!(super::same_container("abc123", "abc123def456"));
        assert!(!super::same_container("abc123", "xyz789"));
        assert!(!super::same_container("", "abc123"));
        assert!(!super::same_container("abc123", ""));
    }
}
