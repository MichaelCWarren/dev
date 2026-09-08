use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::DevError;
use crate::oci::{download_artifact, extract_archive, sha256_hex};
use crate::util::paths::DevHome;

use super::config::{DevcontainerConfig, LifecycleCommand};
use super::jsonc::parse_jsonc;

/// One entry of a feature's `options` block. Only `default` is used: the spec has
/// the orchestrating tool export every declared option, falling back to this when
/// the project does not set one.
#[derive(Deserialize, Default)]
struct FeatureOptionDef {
    #[serde(default)]
    default: Option<serde_json::Value>,
}

/// Metadata from `devcontainer-feature.json` inside a feature artifact.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct FeatureJsonMeta {
    #[serde(default)]
    install_after: Option<Vec<String>>,
    #[serde(default)]
    depends_on: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    container_env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    options: Option<BTreeMap<String, FeatureOptionDef>>,
    #[serde(default)]
    mounts: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    init: Option<bool>,
    #[serde(default)]
    privileged: Option<bool>,
    #[serde(default)]
    cap_add: Option<Vec<String>>,
    #[serde(default)]
    security_opt: Option<Vec<String>>,
    #[serde(default)]
    entrypoint: Option<String>,
    #[serde(default)]
    on_create_command: Option<serde_json::Value>,
    #[serde(default)]
    post_create_command: Option<serde_json::Value>,
    #[serde(default)]
    post_start_command: Option<serde_json::Value>,
    #[serde(default)]
    post_attach_command: Option<serde_json::Value>,
}

/// A resolved devcontainer feature ready for installation.
#[derive(Debug, Clone)]
pub struct ResolvedFeature {
    pub id: String,
    pub oci_ref: String,
    pub version: String,
    pub options: serde_json::Value,
    pub install_script_path: PathBuf,
    /// Features that must be installed before this one (soft ordering hint).
    pub install_after: Vec<String>,
    /// Environment variables to set in the container from this feature.
    pub container_env: BTreeMap<String, String>,
    /// Defaults for options the project did not set, from the feature's own metadata.
    pub option_defaults: BTreeMap<String, serde_json::Value>,
    /// Mount specifications from this feature.
    pub mounts: Vec<serde_json::Value>,
    /// Whether this feature requires an init process.
    pub init: bool,
    /// Whether this feature requires privileged mode.
    pub privileged: bool,
    /// Additional Linux capabilities required by this feature.
    pub cap_add: Vec<String>,
    /// Security options required by this feature.
    pub security_opt: Vec<String>,
    /// Custom entrypoint from this feature.
    pub entrypoint: Option<String>,
    /// Lifecycle hooks contributed by this feature.
    pub lifecycle_hooks: FeatureLifecycleHooks,
    /// Whether this feature was added as a transitive dependency via `dependsOn`.
    pub is_dependency: bool,
}

/// Lifecycle hooks declared by a feature in its `devcontainer-feature.json`.
#[derive(Debug, Clone, Default)]
pub struct FeatureLifecycleHooks {
    pub on_create_command: Option<LifecycleCommand>,
    pub post_create_command: Option<LifecycleCommand>,
    pub post_start_command: Option<LifecycleCommand>,
    pub post_attach_command: Option<LifecycleCommand>,
}

/// Parse a lifecycle command from a JSON value (string, array, or object).
fn parse_lifecycle_command(val: &serde_json::Value) -> Option<LifecycleCommand> {
    match val {
        serde_json::Value::String(s) => Some(LifecycleCommand::Single(s.clone())),
        serde_json::Value::Array(arr) => {
            let strs: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if strs.is_empty() {
                None
            } else {
                Some(LifecycleCommand::Multiple(strs))
            }
        }
        serde_json::Value::Object(obj) => {
            let map: BTreeMap<String, String> = obj
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
            if map.is_empty() {
                None
            } else {
                Some(LifecycleCommand::Parallel(map))
            }
        }
        _ => None,
    }
}

/// Determine the kind of feature reference.
enum FeatureRefKind {
    /// Local path (starts with `./` or `../`).
    Local(PathBuf),
    /// Direct tarball URL (starts with `https://`).
    Tarball(String),
    /// OCI registry reference (everything else).
    Oci { oci_ref: String, version: String },
}

/// Parse feature references from the config and resolve them into installable features.
pub fn resolve_features(config: &DevcontainerConfig) -> Result<Vec<ResolvedFeature>, DevError> {
    resolve_features_in(config, &DevHome::current())
}

/// Every feature the config asks for, plus the one `dev` supplies itself.
///
/// `cmux.agent` is an opt-in for a capability, not a request for a particular
/// image layer, so turning it on is what puts the `cmux-agent` feature in the
/// build. That feature ships inside this binary (see
/// [`crate::cmux::agent::stage_feature_in`]) rather than in a registry or the
/// repository, so nothing has to be fetched or copied for the key to work.
///
/// This is the one choke point every build path calls, which is why the
/// injection lives here rather than at each of `up` and `build`'s call sites.
pub fn resolve_features_in(
    config: &DevcontainerConfig,
    home: &DevHome,
) -> Result<Vec<ResolvedFeature>, DevError> {
    let mut resolved: Vec<ResolvedFeature> = config
        .features
        .iter()
        .flatten()
        .map(|(id, options)| resolve_one(id, options.clone()))
        .collect();

    if config.cmux_agent_enabled() {
        let staged = crate::cmux::agent::stage_feature_in(home)?;
        resolved.push(resolve_one(
            &staged.to_string_lossy(),
            serde_json::Value::Object(serde_json::Map::new()),
        ));
    }

    Ok(resolved)
}

/// One entry of a `features` map, before anything has been downloaded.
fn resolve_one(id: &str, options: serde_json::Value) -> ResolvedFeature {
    let (oci_ref, version) = match classify_feature_ref(id) {
        FeatureRefKind::Local(_) | FeatureRefKind::Tarball(_) => {
            // For local/tarball features, oci_ref stores the original id
            // and version is unused. The actual path is resolved during download.
            (id.to_string(), String::new())
        }
        FeatureRefKind::Oci { oci_ref, version } => (oci_ref, version),
    };
    ResolvedFeature {
        id: id.to_string(),
        oci_ref,
        version,
        options,
        install_script_path: PathBuf::new(),
        install_after: Vec::new(),
        container_env: BTreeMap::new(),
        option_defaults: BTreeMap::new(),
        mounts: Vec::new(),
        init: false,
        privileged: false,
        cap_add: Vec::new(),
        security_opt: Vec::new(),
        entrypoint: None,
        lifecycle_hooks: FeatureLifecycleHooks::default(),
        is_dependency: false,
    }
}

/// Ids of `roots` plus every feature they transitively require via `dependsOn`.
///
/// Feature provenance is not recorded on `ResolvedFeature`, so the dependency
/// closure has to be recomputed from the downloaded metadata. Callers use this to
/// separate the features a project owns from the ones a lower-priority layer
/// (e.g. `~/.dev/base/devcontainer.json`) contributed.
pub fn features_required_by(
    features: &[ResolvedFeature],
    roots: &HashSet<String>,
) -> HashSet<String> {
    let by_id: HashMap<&str, &ResolvedFeature> =
        features.iter().map(|f| (f.id.as_str(), f)).collect();
    let mut reachable: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = roots.iter().cloned().collect();

    while let Some(id) = queue.pop() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        let Some(feature) = by_id.get(id.as_str()) else {
            continue;
        };
        if let Some(deps) = read_depends_on(feature) {
            for dep_id in deps.keys() {
                if !reachable.contains(dep_id) {
                    queue.push(dep_id.clone());
                }
            }
        }
    }

    reachable
}

/// Tag for the image produced by layering `features` onto the config's base image.
///
/// The digest suffix makes the tag a true cache key, so an image built from a
/// different effective config (for example one that merged
/// `~/.dev/base/devcontainer.json` when this one did not) can never be mistaken
/// for a cache hit.
///
/// The hashed inputs must stay in step with everything
/// [`generate_feature_dockerfile_with_opts`] bakes into the image: the base image
/// selector, the declared features, the `_REMOTE_USER`/`_CONTAINER_USER` build
/// environment derived from `remoteUser`, and the `containerEnv`/`remoteEnv` maps
/// written into the `devcontainer.metadata` label. Fields that never reach the
/// image (`forwardPorts`, `name`, `customizations`, …) are deliberately excluded
/// so unrelated edits do not force a rebuild.
///
/// `features` may be either the declared set or the post-download set including
/// transitive dependencies; dependencies are filtered out so both yield the same
/// digest.
pub fn feature_image_tag(
    folder_image: &str,
    config: &DevcontainerConfig,
    features: &[ResolvedFeature],
) -> String {
    use sha2::{Digest, Sha256};

    let mut declared: Vec<(&str, &serde_json::Value)> = features
        .iter()
        .filter(|f| !f.is_dependency)
        .map(|f| (f.id.as_str(), &f.options))
        .collect();
    declared.sort_by(|a, b| a.0.cmp(b.0));

    let build = config.build.as_ref().map(|b| {
        serde_json::json!({
            "dockerfile": b.dockerfile,
            "context": b.context,
            "args": b.args,
        })
    });
    fn sorted_env(env: &Option<HashMap<String, String>>) -> Option<Vec<(&str, &str)>> {
        env.as_ref().map(|map| {
            let mut pairs: Vec<(&str, &str)> =
                map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            pairs
        })
    }
    // Bump whenever the generated Dockerfile or label encoding changes shape:
    // the digest is the cache key, so images built with the old scheme must
    // stop being cache hits. 2: `\$` label escaping (pre-fix images carry
    // dollar-stripped `${devcontainerId}` mounts) and the workspace label.
    // 3: options a feature declares but the project did not set are now exported
    // from the feature's own defaults, so install scripts see different input.
    // 4: dependsOn edges dropped by the old closure walk are recorded again, so
    // images cached with a feature installed before its dependency must rebuild.
    // 5: the build context carries symlinks and directories it used to drop, and
    // file modes are no longer widened, so a feature whose install.sh tolerated a
    // missing file built an image that is a cache hit but quietly incomplete.
    const TAG_FORMAT: u32 = 5;
    let inputs = serde_json::json!({
        "tagFormat": TAG_FORMAT,
        "image": config.image,
        "build": build,
        "features": declared,
        "remoteUser": config.remote_user,
        "containerEnv": sorted_env(&config.container_env),
        "remoteEnv": sorted_env(&config.remote_env),
    });

    let mut hasher = Sha256::new();
    hasher.update(inputs.to_string().as_bytes());
    let digest = hex::encode(hasher.finalize());

    format!("{folder_image}-features-{}", &digest[..12])
}

/// Classify a feature reference string into its kind.
fn classify_feature_ref(id: &str) -> FeatureRefKind {
    if id.starts_with("./") || id.starts_with("../") || id.starts_with('/') {
        FeatureRefKind::Local(PathBuf::from(id))
    } else if id.starts_with("https://") {
        FeatureRefKind::Tarball(id.to_string())
    } else {
        let (oci_ref, version) = parse_feature_ref(id);
        FeatureRefKind::Oci { oci_ref, version }
    }
}

/// Download OCI artifacts for each feature, populating `install_script_path` and metadata fields.
/// On download failure, prompts the user to skip the feature or abort.
///
/// After downloading all user-specified features, this also resolves transitive
/// `dependsOn` dependencies recursively.
pub async fn download_features(
    features: &mut Vec<ResolvedFeature>,
    devcontainer_dir: Option<&std::path::Path>,
) -> Result<(), DevError> {
    // First pass: download all explicitly listed features.
    for feature in features.iter_mut() {
        download_single_feature(feature, devcontainer_dir).await?;
    }

    // Second pass: resolve transitive dependsOn dependencies.
    resolve_depends_on(features, devcontainer_dir).await?;

    Ok(())
}

/// Download a single feature artifact based on its reference kind.
async fn download_single_feature(
    feature: &mut ResolvedFeature,
    devcontainer_dir: Option<&std::path::Path>,
) -> Result<(), DevError> {
    let extracted_dir = match classify_feature_ref(&feature.id) {
        FeatureRefKind::Local(rel_path) => {
            // An absolute path answers for itself; only a relative one needs a
            // .devcontainer/ to resolve against. `dev`'s own staged feature is
            // absolute and reaches here from configs that have no such directory.
            let abs_path = if rel_path.is_absolute() {
                rel_path
            } else {
                let base = devcontainer_dir.ok_or_else(|| {
                    DevError::FeatureNotFound(format!(
                        "Cannot resolve local feature '{}': no .devcontainer directory",
                        feature.id
                    ))
                })?;
                base.join(&rel_path)
            };
            if !abs_path.exists() {
                return Err(DevError::FeatureNotFound(format!(
                    "Local feature directory not found: {}",
                    abs_path.display()
                )));
            }
            abs_path
        }
        FeatureRefKind::Tarball(url) => download_tarball_feature(&url).await?,
        FeatureRefKind::Oci { .. } => {
            let result = download_artifact(&feature.oci_ref, &feature.version).await;
            match result {
                Ok(dir) => dir,
                Err(e) => {
                    eprintln!("Warning: failed to download feature '{}': {e}", feature.id);
                    if feature.is_dependency {
                        // Dependencies are mandatory — don't prompt, just fail.
                        return Err(DevError::Registry(format!(
                            "required dependency '{}': {e}",
                            feature.id
                        )));
                    }
                    let skip = dialoguer::Confirm::new()
                        .with_prompt(format!("Skip feature '{}' and continue?", feature.id))
                        .default(true)
                        .interact()
                        .unwrap_or(false);
                    if skip {
                        return Ok(());
                    }
                    return Err(DevError::Registry(format!("feature '{}': {e}", feature.id)));
                }
            }
        }
    };

    // Verify install.sh exists
    let install_sh = extracted_dir.join("install.sh");
    if !install_sh.exists() {
        return Err(DevError::FeatureNotFound(format!(
            "install.sh not found in feature '{}'",
            feature.id
        )));
    }

    // Read optional devcontainer-feature.json for metadata
    let meta_path = extracted_dir.join("devcontainer-feature.json");
    if meta_path.exists() {
        let content = std::fs::read_to_string(&meta_path)?;
        let meta: FeatureJsonMeta = parse_jsonc(&content)?;
        apply_feature_metadata(feature, &meta);
    }

    feature.install_script_path = extracted_dir;
    Ok(())
}

/// Apply parsed metadata from devcontainer-feature.json to a ResolvedFeature.
fn apply_feature_metadata(feature: &mut ResolvedFeature, meta: &FeatureJsonMeta) {
    if let Some(ref install_after) = meta.install_after {
        feature.install_after = install_after.clone();
    }
    if let Some(ref container_env) = meta.container_env {
        feature.container_env = container_env.clone();
    }
    if let Some(ref options) = meta.options {
        feature.option_defaults = options
            .iter()
            .filter_map(|(name, def)| def.default.clone().map(|d| (name.clone(), d)))
            .collect();
    }
    if let Some(ref mounts) = meta.mounts {
        feature.mounts = mounts.clone();
    }
    if let Some(init) = meta.init {
        feature.init = init;
    }
    if let Some(privileged) = meta.privileged {
        feature.privileged = privileged;
    }
    if let Some(ref cap_add) = meta.cap_add {
        feature.cap_add = cap_add.clone();
    }
    if let Some(ref security_opt) = meta.security_opt {
        feature.security_opt = security_opt.clone();
    }
    if meta.entrypoint.is_some() {
        feature.entrypoint = meta.entrypoint.clone();
    }

    // Parse lifecycle hooks
    if let Some(ref val) = meta.on_create_command {
        feature.lifecycle_hooks.on_create_command = parse_lifecycle_command(val);
    }
    if let Some(ref val) = meta.post_create_command {
        feature.lifecycle_hooks.post_create_command = parse_lifecycle_command(val);
    }
    if let Some(ref val) = meta.post_start_command {
        feature.lifecycle_hooks.post_start_command = parse_lifecycle_command(val);
    }
    if let Some(ref val) = meta.post_attach_command {
        feature.lifecycle_hooks.post_attach_command = parse_lifecycle_command(val);
    }
}

/// Read `depends_on` from a feature's `devcontainer-feature.json`, if present.
fn read_depends_on(feature: &ResolvedFeature) -> Option<HashMap<String, serde_json::Value>> {
    let meta_path = feature
        .install_script_path
        .join("devcontainer-feature.json");
    if !meta_path.exists() {
        return None;
    }
    let content = match std::fs::read_to_string(&meta_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "Warning: cannot read feature metadata for '{}' at {}: {e}. \
                 Its dependencies will be treated as absent.",
                feature.id,
                meta_path.display()
            );
            return None;
        }
    };
    let meta: FeatureJsonMeta = match parse_jsonc(&content) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!(
                "Warning: cannot parse feature metadata for '{}' at {}: {e}. \
                 Its dependencies will be treated as absent.",
                feature.id,
                meta_path.display()
            );
            return None;
        }
    };
    meta.depends_on
}

/// Recursively resolve `dependsOn` entries, downloading any features not already present.
async fn resolve_depends_on(
    features: &mut Vec<ResolvedFeature>,
    devcontainer_dir: Option<&std::path::Path>,
) -> Result<(), DevError> {
    let mut visited: HashSet<String> = features.iter().map(|f| f.id.clone()).collect();
    let mut queue: Vec<(String, serde_json::Value)> = Vec::new();

    // Cache depends_on per feature ID to avoid re-reading JSON files.
    let mut deps_cache: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();

    // Collect all dependsOn entries from already-downloaded features.
    for feature in features.iter() {
        if let Some(deps) = read_depends_on(feature) {
            for (dep_id, dep_opts) in &deps {
                if !visited.contains(dep_id) {
                    queue.push((dep_id.clone(), dep_opts.clone()));
                    visited.insert(dep_id.clone());
                }
            }
            deps_cache.insert(feature.id.clone(), deps);
        }
    }

    // Process the queue: download each dependency, read its metadata, and enqueue
    // any of its own dependsOn entries that haven't been visited yet.
    while let Some((dep_id, dep_opts)) = queue.pop() {
        let (oci_ref, version) = match classify_feature_ref(&dep_id) {
            FeatureRefKind::Local(_) | FeatureRefKind::Tarball(_) => {
                (dep_id.clone(), String::new())
            }
            FeatureRefKind::Oci { oci_ref, version } => (oci_ref, version),
        };

        let mut dep_feature = ResolvedFeature {
            id: dep_id.clone(),
            oci_ref,
            version,
            options: dep_opts,
            install_script_path: PathBuf::new(),
            install_after: Vec::new(),
            container_env: BTreeMap::new(),
            option_defaults: BTreeMap::new(),
            mounts: Vec::new(),
            init: false,
            privileged: false,
            cap_add: Vec::new(),
            security_opt: Vec::new(),
            entrypoint: None,
            lifecycle_hooks: FeatureLifecycleHooks::default(),
            is_dependency: true,
        };

        download_single_feature(&mut dep_feature, devcontainer_dir).await?;

        // Check for transitive dependencies in the newly downloaded feature.
        if let Some(deps) = read_depends_on(&dep_feature) {
            for (transitive_id, transitive_opts) in &deps {
                if !visited.contains(transitive_id) {
                    queue.push((transitive_id.clone(), transitive_opts.clone()));
                    visited.insert(transitive_id.clone());
                }
            }
            deps_cache.insert(dep_feature.id.clone(), deps);
        }

        features.push(dep_feature);
    }

    // Record every dependsOn edge as an install_after, from the cached metadata
    // rather than by re-reading files. This has to happen after the whole closure
    // is known: a feature discovered later than the dependency it declares would
    // otherwise never see that dependency popped, and lose the edge entirely.
    for f in features.iter_mut() {
        let Some(deps) = deps_cache.get(&f.id) else {
            continue;
        };
        let mut dep_ids: Vec<&String> = deps.keys().collect();
        dep_ids.sort();
        for dep_id in dep_ids {
            if !f.install_after.contains(dep_id) {
                f.install_after.push(dep_id.clone());
            }
        }
    }

    Ok(())
}

/// Download a feature distributed as a tarball URL.
async fn download_tarball_feature(url: &str) -> Result<PathBuf, DevError> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| DevError::Registry(format!("Failed to download tarball {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(DevError::Registry(format!(
            "HTTP {} downloading tarball {url}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| DevError::Registry(format!("Failed to read tarball {url}: {e}")))?;

    let digest = sha256_hex(&bytes);
    let extract_dir = std::env::temp_dir().join(format!(
        "dev-feature-tarball-{}",
        &digest[..16.min(digest.len())]
    ));

    if !extract_dir.exists() {
        extract_archive(&bytes, &extract_dir)?;
    }

    Ok(extract_dir)
}

/// Stage feature files into a temp directory for use as a Docker build context.
///
/// Each feature's extracted directory is copied into `staging_dir/{i}/` where `i`
/// is the feature's index in the ordered list.
pub fn stage_feature_context(features: &[ResolvedFeature]) -> Result<PathBuf, DevError> {
    let staging_dir = std::env::temp_dir().join(format!("dev-features-{}", std::process::id()));
    std::fs::create_dir_all(&staging_dir)?;

    // We package each feature as a tarball rather than a plain directory
    // because Apple Containers' `container build` has a bug where files
    // inside subdirectories of the build context are not transferred.
    // Using `ADD <tarball>` in the Dockerfile works around this since
    // ADD auto-extracts archives and root-level files transfer correctly.
    for (i, feature) in features.iter().enumerate() {
        if feature.install_script_path.as_os_str().is_empty() {
            continue;
        }
        let tar_path = staging_dir.join(format!("{i}.tar"));
        create_tar(&feature.install_script_path, &tar_path)?;
    }

    Ok(staging_dir)
}

/// Create a tar archive of a directory's contents (without the directory itself).
///
/// Deterministic on purpose: these bytes are the Docker build context and
/// `ADD {i}.tar` is a cache key, so identical content must produce identical
/// bytes. Timestamps and ownership are dropped, and modes are masked; nothing
/// else about the host reaches the archive.
/// [`crate::cmux::agent::stage_feature_in`] rewrites its files on every run, and
/// its absolute-path id always sorts to feature 0, so a fresh mtime there misses
/// the first context instruction and reinstalls every feature above it.
fn create_tar(src_dir: &std::path::Path, tar_path: &std::path::Path) -> Result<(), DevError> {
    let file = std::fs::File::create(tar_path).map_err(|e| tar_error(tar_path, e))?;
    let mut builder = tar::Builder::new(file);
    append_dir_deterministic(&mut builder, src_dir, std::path::Path::new(""))?;
    builder
        .finish()
        .map_err(|e| DevError::Runtime(format!("Failed to finalize tar: {e}")))?;
    Ok(())
}

fn tar_error(path: &std::path::Path, e: impl std::fmt::Display) -> DevError {
    DevError::Runtime(format!("Failed to tar {}: {e}", path.display()))
}

/// Append a directory's entries under `prefix`, sorted by name, with headers
/// built by hand so nothing about the host reaches the archive.
fn append_dir_deterministic<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    dir: &std::path::Path,
    prefix: &std::path::Path,
) -> Result<(), DevError> {
    let read = std::fs::read_dir(dir).map_err(|e| tar_error(dir, e))?;
    let mut entries: Vec<_> = read
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| tar_error(dir, e))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = prefix.join(entry.file_name());
        // Symlinks are followed, which is what `tar::Builder` did before this
        // walk replaced it: a link to a file is archived as its target's bytes,
        // a link to a directory is walked. Both are deterministic, and skipping
        // them instead leaves install.sh without files its feature shipped.
        let meta = std::fs::metadata(&path).map_err(|e| tar_error(&path, e))?;

        if meta.is_dir() {
            append_entry(builder, &name, &path, &meta, tar::EntryType::Directory, &[])?;
            append_dir_deterministic(builder, &path, &name)?;
            continue;
        }
        // Sockets, fifos and devices mean nothing in a feature artifact.
        if !meta.is_file() {
            continue;
        }

        let data = std::fs::read(&path).map_err(|e| tar_error(&path, e))?;
        append_entry(builder, &name, &path, &meta, tar::EntryType::Regular, &data)?;
    }
    Ok(())
}

fn append_entry<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    name: &std::path::Path,
    path: &std::path::Path,
    meta: &std::fs::Metadata,
    entry_type: tar::EntryType,
    data: &[u8],
) -> Result<(), DevError> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(data.len() as u64);
    header.set_mode(normalized_mode(meta));
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    builder
        .append_data(&mut header, name, data)
        .map_err(|e| tar_error(path, e))
}

/// Keep the read and execute bits the source carried and drop the rest, so a
/// file shipped at 0600 is not republished to every user in the image and a
/// 0777 one does not arrive group-writable.
#[cfg(unix)]
fn normalized_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o755
}

#[cfg(not(unix))]
fn normalized_mode(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() { 0o755 } else { 0o644 }
}

/// Convert an option name to an environment variable name per the devcontainer spec:
/// replace non-alphanumeric/underscore chars with `_`, strip leading digits/underscores, uppercase.
fn option_name_to_env(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_start_matches(|c: char| c.is_ascii_digit() || c == '_');
    let result = if trimmed.is_empty() {
        &sanitized
    } else {
        trimmed
    };
    result.to_uppercase()
}

/// Parse a feature reference like "ghcr.io/devcontainers/features/node:1" into (ref, version).
fn parse_feature_ref(id: &str) -> (String, String) {
    if let Some((base, version)) = id.rsplit_once(':') {
        (base.to_string(), version.to_string())
    } else {
        (id.to_string(), "latest".to_string())
    }
}

/// Sort features by their `install_after` dependencies (topological sort).
pub fn order_features(features: &[ResolvedFeature]) -> Vec<ResolvedFeature> {
    // Features reach here in `HashMap` iteration order — from devcontainer.json's
    // `features` object and from the `dependsOn` closure — which reshuffles every
    // process. Sorting by id first makes the generated Dockerfile byte-identical
    // between builds, so Docker's layer cache holds and installs are not re-run.
    let sorted: Vec<ResolvedFeature> = {
        let mut v = features.to_vec();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    };
    let features = &sorted[..];

    let id_to_idx: HashMap<&str, usize> = features
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.as_str(), i))
        .collect();

    let mut in_degree = vec![0usize; features.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); features.len()];

    for (i, f) in features.iter().enumerate() {
        for dep_id in &f.install_after {
            if let Some(&dep_idx) = id_to_idx.get(dep_id.as_str()) {
                dependents[dep_idx].push(i);
                in_degree[i] += 1;
            }
        }
    }

    // Kahn's algorithm, FIFO so features with no ordering constraint between
    // them stay in sorted id order rather than coming out reversed.
    let mut queue: VecDeque<usize> = in_degree
        .iter()
        .enumerate()
        .filter(|&(_, d)| *d == 0)
        .map(|(i, _)| i)
        .collect();

    let mut ordered = Vec::with_capacity(features.len());

    while let Some(idx) = queue.pop_front() {
        ordered.push(features[idx].clone());
        for &dep_idx in &dependents[idx] {
            in_degree[dep_idx] -= 1;
            if in_degree[dep_idx] == 0 {
                queue.push_back(dep_idx);
            }
        }
    }

    // If there are cycles, append remaining features in original order.
    if ordered.len() < features.len() {
        for (i, f) in features.iter().enumerate() {
            if in_degree[i] > 0 {
                ordered.push(f.clone());
            }
        }
    }

    ordered
}

/// Image label naming the workspace image a derived feature image belongs to.
/// `dev prune` matches it to claim dangling rebuild leftovers.
pub const WORKSPACE_IMAGE_LABEL: &str = "dev.workspace-image";

/// Generate a composite Dockerfile that installs all features on top of a base image.
///
/// Per the devcontainer spec, feature install scripts expect several environment
/// variables to be set by the orchestrating tool.  We inject them right after the
/// FROM line so every RUN step can see them.
///
/// Gap 1 fix: Each feature's `containerEnv` is emitted as `ENV` directives.
/// Gap 3 fix: `_REMOTE_USER_HOME` is resolved dynamically via `getent passwd`.
/// Gap 4 fix: A `LABEL devcontainer.metadata` is appended with merged metadata.
/// Gap 12 fix: Feature install scripts are wrapped with env sourcing and error context.
pub fn generate_feature_dockerfile_with_opts(
    base_image: &str,
    workspace_image: &str,
    features: &[ResolvedFeature],
    remote_user: Option<&str>,
    config: &DevcontainerConfig,
) -> String {
    let user = remote_user.unwrap_or("root");

    let mut lines: Vec<String> = Vec::new();

    lines.push(format!("FROM {base_image}"));

    // Set _REMOTE_USER / _CONTAINER_USER immediately so later RUN steps can reference them.
    lines.push(format!("ENV _REMOTE_USER=\"{user}\""));
    lines.push(format!("ENV _CONTAINER_USER=\"{user}\""));

    // Static fallback for standard users; overridden dynamically below.
    let static_home = if user == "root" {
        "/root".to_string()
    } else {
        format!("/home/{user}")
    };
    lines.push(format!("ENV _REMOTE_USER_HOME=\"{static_home}\""));
    lines.push(format!("ENV _CONTAINER_USER_HOME=\"{static_home}\""));

    // Dynamically resolve home directory at build time using getent passwd.
    // This handles non-standard users like postgres (/var/lib/postgresql),
    // nginx (/var/cache/nginx), etc. instead of assuming /home/<user>.
    // Write a helper script that feature install scripts will source.
    lines.push(format!(
        "RUN _HOME=$(getent passwd \"{user}\" 2>/dev/null | cut -d: -f6) && \
         if [ -n \"$_HOME\" ]; then \
           echo \"export _REMOTE_USER_HOME=$_HOME\" > /usr/local/share/dev-container-user-home.sh && \
           echo \"export _CONTAINER_USER_HOME=$_HOME\" >> /usr/local/share/dev-container-user-home.sh; \
         fi"
    ));

    for (i, feature) in features.iter().enumerate() {
        let stage_dir = format!("/tmp/dev-features/{i}");
        if feature.install_script_path.as_os_str().is_empty() {
            continue;
        }

        // Emit feature's containerEnv as ENV directives (Gap 1).
        // These intentionally persist in the final image — they are part of
        // the container's runtime environment, not build-time options.
        for (key, val) in &feature.container_env {
            let escaped_val = val.replace('\\', "\\\\").replace('"', "\\\"");
            lines.push(format!("ENV {key}=\"{escaped_val}\""));
        }

        // Collect feature options to pass as scoped exports in the RUN step.
        // Options must NOT be emitted as ENV directives because ENV persists
        // across all subsequent Dockerfile steps. A feature setting e.g.
        // VERSION=3.12 would leak into later features that use $VERSION with
        // a different meaning (e.g. copilot-cli defaulting to "latest").
        // The spec has the tool export every option the feature declares, so a
        // script can read an option it never told the project about. Project
        // values win; the feature's own defaults fill the rest.
        let mut effective: BTreeMap<&str, &serde_json::Value> = feature
            .option_defaults
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        if let Some(obj) = feature.options.as_object() {
            for (key, val) in obj {
                effective.insert(key.as_str(), val);
            }
        }

        let mut option_exports = Vec::new();
        for (key, val) in effective {
            let env_name = option_name_to_env(key);
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            // Escape special characters for safe embedding in a printf '%b'
            // expression inside a Dockerfile RUN step. This handles newlines,
            // tabs, carriage returns, backslashes, and single quotes without
            // breaking the Dockerfile syntax.
            let escaped_val = val_str
                .replace('\\', "\\\\")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t")
                .replace('\'', "'\\''");
            option_exports.push(format!(
                "export {env_name}=\"$(printf '%b' '{escaped_val}')\""
            ));
        }

        // Always use ADD to extract the feature tarball from the uploaded build
        // context. RUN --mount=type=bind requires a BuildKit gRPC session server
        // that Bollard does not start, causing "context not found" on Linux with
        // older Docker Engine (Docker Desktop on Mac silently works around it).
        lines.push(format!("ADD {i}.tar {stage_dir}/"));

        // Wrapper script with env sourcing, scoped options, and error context.
        lines.push(format!(
            "RUN {wrapper}",
            wrapper =
                feature_wrapper_script(&feature.id, &feature.version, &stage_dir, &option_exports),
        ));
    }

    // Build and emit the devcontainer.metadata label (Gap 4).
    let metadata_label = build_metadata_label(features, config, remote_user);
    // Escape the JSON for use in a Dockerfile LABEL. Dollar signs take a
    // backslash escape (`\$`): `$$` is Compose syntax, and Docker's builder
    // strips the dollar from `$${...}`, corrupting stored `${devcontainerId}`
    // mounts and `$`-bearing hook commands on the metadata-recovery path.
    let escaped = metadata_label
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$");
    lines.push(format!("LABEL devcontainer.metadata=\"{escaped}\""));

    // Names the workspace the image was derived for, so `dev prune` can find
    // rebuild leftovers after the daemon untags them (a dangling image keeps
    // its labels but loses the workspace-prefixed tag).
    lines.push(format!(
        "LABEL {WORKSPACE_IMAGE_LABEL}=\"{workspace_image}\""
    ));

    lines.join("\n")
}

/// Generate the wrapper script that sources environment files and provides
/// error context around a feature's install.sh (Gap 12).
///
/// The wrapper:
/// 1. Sources the dynamic user home script (for non-standard users)
/// 2. Exports feature options as scoped environment variables
/// 3. Sets error context variables (_DEV_FEATURE_ID, _DEV_FEATURE_VERSION)
/// 4. Runs install.sh with `set -e` for proper error propagation
/// 5. Reports clear error messages on failure
fn feature_wrapper_script(
    feature_id: &str,
    feature_version: &str,
    stage_dir: &str,
    option_exports: &[String],
) -> String {
    // Shell-escape the feature ID for safe embedding in the script.
    let escaped_id = feature_id.replace('\'', "'\\''");
    let escaped_version = feature_version.replace('\'', "'\\''");

    let options_block = if option_exports.is_empty() {
        String::new()
    } else {
        format!("{} && ", option_exports.join(" && "))
    };

    format!(
        "set -e && \
         if [ -f /usr/local/share/dev-container-user-home.sh ]; then \
           . /usr/local/share/dev-container-user-home.sh; \
         fi && \
         {options_block}\
         export _DEV_FEATURE_ID='{escaped_id}' && \
         export _DEV_FEATURE_VERSION='{escaped_version}' && \
         cd {stage_dir} && \
         chmod +x install.sh && \
         if ! ./install.sh; then \
           echo \"ERROR: Feature '{escaped_id}' (version '{escaped_version}') install.sh failed\" >&2; \
           exit 1; \
         fi"
    )
}

/// Build the JSON array for the `devcontainer.metadata` image label.
///
/// Includes one entry per feature (with its contributed containerEnv, mounts,
/// capabilities, lifecycle hooks) followed by one entry for the base devcontainer.json
/// config (remoteUser, containerEnv, lifecycle hooks, etc.).
fn build_metadata_label(
    features: &[ResolvedFeature],
    config: &DevcontainerConfig,
    remote_user: Option<&str>,
) -> String {
    let mut metadata: Vec<serde_json::Value> = Vec::new();

    // Feature entries.
    for feature in features {
        let mut entry = serde_json::Map::new();
        entry.insert("id".into(), serde_json::Value::String(feature.id.clone()));

        if !feature.container_env.is_empty() {
            entry.insert(
                "containerEnv".into(),
                serde_json::to_value(&feature.container_env).unwrap_or_default(),
            );
        }
        if !feature.mounts.is_empty() {
            entry.insert(
                "mounts".into(),
                serde_json::Value::Array(feature.mounts.clone()),
            );
        }
        if feature.init {
            entry.insert("init".into(), serde_json::Value::Bool(true));
        }
        if feature.privileged {
            entry.insert("privileged".into(), serde_json::Value::Bool(true));
        }
        if !feature.cap_add.is_empty() {
            entry.insert(
                "capAdd".into(),
                serde_json::to_value(&feature.cap_add).unwrap_or_default(),
            );
        }
        if !feature.security_opt.is_empty() {
            entry.insert(
                "securityOpt".into(),
                serde_json::to_value(&feature.security_opt).unwrap_or_default(),
            );
        }
        if feature.entrypoint.is_some() {
            entry.insert(
                "entrypoint".into(),
                serde_json::Value::String(feature.entrypoint.clone().unwrap_or_default()),
            );
        }

        // Include lifecycle hooks in metadata so they survive the build.
        insert_lifecycle_hook(
            &mut entry,
            "onCreateCommand",
            &feature.lifecycle_hooks.on_create_command,
        );
        insert_lifecycle_hook(
            &mut entry,
            "postCreateCommand",
            &feature.lifecycle_hooks.post_create_command,
        );
        insert_lifecycle_hook(
            &mut entry,
            "postStartCommand",
            &feature.lifecycle_hooks.post_start_command,
        );
        insert_lifecycle_hook(
            &mut entry,
            "postAttachCommand",
            &feature.lifecycle_hooks.post_attach_command,
        );

        metadata.push(serde_json::Value::Object(entry));
    }

    // Base config entry.
    let mut base_entry = serde_json::Map::new();
    if let Some(user) = remote_user {
        base_entry.insert(
            "remoteUser".into(),
            serde_json::Value::String(user.to_string()),
        );
    }
    if let Some(ref env) = config.container_env {
        base_entry.insert("containerEnv".into(), sorted_env_value(env));
    }
    if let Some(ref remote_env) = config.remote_env {
        base_entry.insert("remoteEnv".into(), sorted_env_value(remote_env));
    }
    metadata.push(serde_json::Value::Object(base_entry));

    serde_json::to_string(&metadata).unwrap_or_else(|_| "[]".to_string())
}

/// Serialize an env map with its keys in sorted order.
///
/// `serde_json`'s `preserve_order` feature makes its maps insertion-ordered, so a
/// `HashMap` would otherwise land in the `devcontainer.metadata` label in a
/// different order on every build.
fn sorted_env_value(env: &HashMap<String, String>) -> serde_json::Value {
    let sorted: BTreeMap<&str, &str> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    serde_json::to_value(sorted).unwrap_or_default()
}

/// Insert a lifecycle hook into a metadata entry if it's Some.
fn insert_lifecycle_hook(
    entry: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    hook: &Option<LifecycleCommand>,
) {
    if let Some(cmd) = hook {
        let val = match cmd {
            LifecycleCommand::Single(s) => serde_json::Value::String(s.clone()),
            LifecycleCommand::Multiple(arr) => serde_json::Value::Array(
                arr.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
            LifecycleCommand::Parallel(map) => serde_json::to_value(map).unwrap_or_default(),
        };
        entry.insert(key.into(), val);
    }
}

/// Merge feature-contributed container capabilities (init, privileged, capAdd, securityOpt)
/// into a single set of values. Booleans are OR'd, arrays are unioned.
pub fn merge_feature_capabilities(features: &[ResolvedFeature]) -> MergedCapabilities {
    let mut result = MergedCapabilities::default();
    for f in features {
        result.init = result.init || f.init;
        result.privileged = result.privileged || f.privileged;
        for cap in &f.cap_add {
            if !result.cap_add.contains(cap) {
                result.cap_add.push(cap.clone());
            }
        }
        for opt in &f.security_opt {
            if !result.security_opt.contains(opt) {
                result.security_opt.push(opt.clone());
            }
        }
    }
    result
}

/// Aggregated container capabilities from all features.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergedCapabilities {
    pub init: bool,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub security_opt: Vec<String>,
}

/// Rebuild the features that produced an image from its `devcontainer.metadata`
/// label entries, as written by `build_metadata_label`.
///
/// Entries appear in install order, so the returned list preserves the original
/// feature order. The trailing base-config entry is the only one without an
/// `"id"` key and is skipped. Only the contribution fields the label carries
/// (mounts, entrypoint, capabilities, lifecycle hooks) are restored; build-time
/// fields such as `options` and `install_script_path` are defaulted and must not
/// be read from a recovered feature.
pub fn features_from_metadata(entries: &[serde_json::Value]) -> Vec<ResolvedFeature> {
    entries
        .iter()
        .filter_map(feature_from_metadata_entry)
        .collect()
}

fn feature_from_metadata_entry(entry: &serde_json::Value) -> Option<ResolvedFeature> {
    let id = entry.get("id")?.as_str()?.to_string();
    let hooks = FeatureLifecycleHooks {
        on_create_command: entry
            .get("onCreateCommand")
            .and_then(parse_lifecycle_command),
        post_create_command: entry
            .get("postCreateCommand")
            .and_then(parse_lifecycle_command),
        post_start_command: entry
            .get("postStartCommand")
            .and_then(parse_lifecycle_command),
        post_attach_command: entry
            .get("postAttachCommand")
            .and_then(parse_lifecycle_command),
    };
    let mut feature = ResolvedFeature {
        oci_ref: id.clone(),
        id,
        version: String::new(),
        options: serde_json::Value::Null,
        install_script_path: PathBuf::new(),
        install_after: Vec::new(),
        container_env: BTreeMap::new(),
        option_defaults: BTreeMap::new(),
        mounts: entry
            .get("mounts")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default(),
        init: entry_flag(entry, "init"),
        privileged: entry_flag(entry, "privileged"),
        cap_add: Vec::new(),
        security_opt: Vec::new(),
        entrypoint: entry
            .get("entrypoint")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        lifecycle_hooks: hooks,
        is_dependency: false,
    };
    union_string_array(entry.get("capAdd"), &mut feature.cap_add);
    union_string_array(entry.get("securityOpt"), &mut feature.security_opt);
    Some(feature)
}

/// Read a boolean metadata key, treating absent or non-boolean values as false.
fn entry_flag(entry: &serde_json::Value, key: &str) -> bool {
    entry
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Append the string members of a JSON array into `target`, preserving first-seen
/// order and skipping duplicates. Non-string members are ignored.
fn union_string_array(value: Option<&serde_json::Value>, target: &mut Vec<String>) {
    let Some(items) = value.and_then(serde_json::Value::as_array) else {
        return;
    };
    for item in items.iter().filter_map(serde_json::Value::as_str) {
        if !target.iter().any(|existing| existing == item) {
            target.push(item.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn feature(id: &str) -> ResolvedFeature {
        ResolvedFeature {
            id: id.to_string(),
            oci_ref: id.to_string(),
            version: "latest".to_string(),
            options: serde_json::Value::Null,
            install_script_path: PathBuf::new(),
            install_after: Vec::new(),
            container_env: BTreeMap::new(),
            option_defaults: BTreeMap::new(),
            mounts: Vec::new(),
            init: false,
            privileged: false,
            cap_add: Vec::new(),
            security_opt: Vec::new(),
            entrypoint: None,
            lifecycle_hooks: FeatureLifecycleHooks::default(),
            is_dependency: false,
        }
    }

    fn empty_config() -> DevcontainerConfig {
        serde_json::from_str("{}").expect("empty devcontainer.json should deserialize")
    }

    fn parse_label(label: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(label).expect("metadata label should be a JSON array")
    }

    /// The cached-image capability recovery: features restored from the label, then
    /// merged exactly as the build path merges freshly resolved features.
    fn capabilities_from_metadata(entries: &[serde_json::Value]) -> MergedCapabilities {
        merge_feature_capabilities(&features_from_metadata(entries))
    }

    /// The capabilities recovered from a built image must equal those the build itself
    /// derived. This is the guard against key-name drift between `build_metadata_label`
    /// and `capabilities_from_metadata` (e.g. `capAdd` vs `cap_add`), which no
    /// hand-written JSON fixture would catch.
    #[test]
    fn capabilities_survive_metadata_label_roundtrip() {
        let mut dind = feature("ghcr.io/devcontainers/features/docker-in-docker:2");
        dind.privileged = true;
        dind.init = true;
        dind.cap_add = vec!["SYS_PTRACE".to_string()];
        dind.security_opt = vec!["seccomp=unconfined".to_string()];
        let features = vec![dind];

        let label = build_metadata_label(&features, &empty_config(), None);
        let recovered = capabilities_from_metadata(&parse_label(&label));

        assert!(
            recovered.privileged,
            "privileged must survive the roundtrip"
        );
        assert_eq!(recovered, merge_feature_capabilities(&features));
    }

    /// A feature declaring no capabilities must not acquire any via the label, and the
    /// trailing base-config entry must be ignored harmlessly.
    #[test]
    fn plain_feature_roundtrips_without_capabilities() {
        let features = vec![feature("ghcr.io/devcontainers/features/node:1")];

        let label = build_metadata_label(&features, &empty_config(), Some("node"));
        let recovered = capabilities_from_metadata(&parse_label(&label));

        assert_eq!(recovered, MergedCapabilities::default());
    }

    #[test]
    fn capabilities_union_across_entries_and_deduplicate() {
        let entries = vec![
            serde_json::json!({"id": "a", "capAdd": ["SYS_PTRACE"]}),
            serde_json::json!({
                "id": "b",
                "privileged": true,
                "capAdd": ["SYS_PTRACE", "NET_ADMIN"],
                "securityOpt": ["seccomp=unconfined"],
            }),
        ];

        let caps = capabilities_from_metadata(&entries);

        assert!(caps.privileged);
        assert_eq!(caps.cap_add, ["SYS_PTRACE", "NET_ADMIN"]);
        assert_eq!(caps.security_opt, ["seccomp=unconfined"]);
    }

    /// An image with no recoverable metadata must yield no capabilities rather than
    /// panicking or inventing them.
    #[test]
    fn capabilities_from_metadata_defaults_when_absent() {
        assert_eq!(
            capabilities_from_metadata(&[]),
            MergedCapabilities::default()
        );

        let no_caps = capabilities_from_metadata(&[serde_json::json!({"id": "a"})]);
        assert_eq!(no_caps, MergedCapabilities::default());
    }

    /// Malformed values must be ignored, not coerced into capabilities.
    #[test]
    fn capabilities_from_metadata_ignores_malformed_values() {
        let entries = vec![serde_json::json!({
            "id": "a",
            "privileged": "yes",
            "capAdd": "SYS_PTRACE",
            "securityOpt": [42, "seccomp=unconfined"],
        })];

        let caps = capabilities_from_metadata(&entries);

        assert!(!caps.privileged, "a non-boolean must not enable privileged");
        assert!(
            caps.cap_add.is_empty(),
            "a non-array capAdd must be ignored"
        );
        assert_eq!(caps.security_opt, ["seccomp=unconfined"]);
    }

    /// The workspace label ties a derived image back to its workspace even
    /// after a rebuild untags it — `dev prune` claims danglings through it.
    #[test]
    fn dockerfile_labels_the_workspace_image() {
        let dockerfile = generate_feature_dockerfile_with_opts(
            "base:latest",
            "vsc-test",
            &[],
            None,
            &empty_config(),
        );
        assert!(
            dockerfile.contains("LABEL dev.workspace-image=\"vsc-test\""),
            "generated Dockerfile must carry the workspace label:\n{dockerfile}"
        );
    }

    /// The metadata LABEL must escape `$` with a backslash: `$$` is Compose
    /// syntax, and Docker's builder strips the dollar from `$${...}`, so a
    /// `${devcontainerId}` mount stored that way comes back corrupted on the
    /// cached-image recovery path (found live against Docker 29).
    #[test]
    fn metadata_label_escapes_dollars_for_the_dockerfile_builder() {
        let mut dind = feature("ghcr.io/devcontainers/features/docker-in-docker:2");
        dind.mounts = vec![serde_json::json!({
            "source": "dind-var-lib-docker-${devcontainerId}",
            "target": "/var/lib/docker",
            "type": "volume"
        })];

        let dockerfile = generate_feature_dockerfile_with_opts(
            "ubuntu:24.04",
            "vsc-test",
            &[dind],
            None,
            &empty_config(),
        );
        let label_line = dockerfile
            .lines()
            .find(|l| l.starts_with("LABEL devcontainer.metadata="))
            .expect("the metadata label is emitted");

        assert!(
            label_line.contains("dind-var-lib-docker-\\${devcontainerId}"),
            "dollars take the backslash escape Docker preserves: {label_line}"
        );
        assert!(
            !label_line.contains("$$"),
            "no Compose-style doubling: {label_line}"
        );
    }

    /// Everything the label writer records for a feature must be recoverable, in
    /// install order, with the id-less base-config entry skipped. This guards the
    /// cached-image path, which recreates containers without re-resolving features.
    #[test]
    fn features_from_metadata_restores_hooks_mounts_and_entrypoint_in_install_order() {
        let mut dind = feature("ghcr.io/devcontainers/features/docker-in-docker:2");
        dind.mounts = vec![serde_json::json!({
            "source": "dind-var-lib-docker-${devcontainerId}",
            "target": "/var/lib/docker",
            "type": "volume"
        })];
        dind.entrypoint = Some("/usr/local/share/docker-init.sh".to_string());
        dind.lifecycle_hooks.on_create_command =
            Some(LifecycleCommand::Single("touch on-create".to_string()));
        dind.lifecycle_hooks.post_start_command =
            Some(LifecycleCommand::Single("touch post-start".to_string()));
        let node = feature("ghcr.io/devcontainers/features/node:1");
        let features = vec![dind, node];

        let label = build_metadata_label(&features, &empty_config(), Some("vscode"));
        let recovered = features_from_metadata(&parse_label(&label));

        assert_eq!(recovered.len(), 2, "the id-less base entry must be skipped");
        assert_eq!(recovered[0].id, features[0].id);
        assert_eq!(recovered[1].id, features[1].id);
        assert_eq!(recovered[0].mounts, features[0].mounts);
        assert_eq!(recovered[0].entrypoint, features[0].entrypoint);
        assert_eq!(
            format!("{:?}", recovered[0].lifecycle_hooks),
            format!("{:?}", features[0].lifecycle_hooks),
            "lifecycle hooks must survive the roundtrip"
        );
        assert!(recovered[1].lifecycle_hooks.post_start_command.is_none());
        assert!(recovered[1].entrypoint.is_none());
    }

    /// Adapter over `feature` for tests that exercise Dockerfile generation.
    ///
    /// Sets `install_script_path`, without which `generate_feature_dockerfile_with_opts`
    /// skips the feature entirely and emits no RUN step to assert against.
    fn make_feature(id: &str, options: serde_json::Value) -> ResolvedFeature {
        let mut resolved = feature(id);
        resolved.options = options;
        resolved.install_script_path = PathBuf::from("/tmp/fake");
        resolved
    }

    #[test]
    fn dockerfile_is_identical_whatever_order_features_arrive_in() {
        // devcontainer.json's `features` object is a HashMap, so the resolved list
        // arrives shuffled. A shuffled Dockerfile misses Docker's layer cache and
        // reinstalls every feature on every build.
        let mut a = make_feature("ghcr.io/x/alpha:1", serde_json::json!({}));
        a.container_env.insert("ZED".to_string(), "z".to_string());
        a.container_env.insert("ALPHA".to_string(), "a".to_string());
        let b = make_feature("ghcr.io/x/beta:1", serde_json::json!({}));
        let c = make_feature("ghcr.io/x/gamma:1", serde_json::json!({}));

        let config = empty_config();
        let render = |features: &[ResolvedFeature]| {
            let ordered = order_features(features);
            generate_feature_dockerfile_with_opts(
                "base:latest",
                "vsc-test",
                &ordered,
                Some("root"),
                &config,
            )
        };

        let forward = render(&[a.clone(), b.clone(), c.clone()]);
        let shuffled = render(&[c, a, b]);
        assert_eq!(
            forward, shuffled,
            "feature order must not depend on input order"
        );
        assert!(
            forward.find("ENV ALPHA=").unwrap() < forward.find("ENV ZED=").unwrap(),
            "containerEnv should be emitted in sorted key order.\nDockerfile:\n{forward}"
        );
    }

    #[test]
    fn metadata_label_is_identical_whatever_order_features_arrive_in() {
        let mut config = empty_config();
        config.container_env = Some(HashMap::from([
            ("ZED".to_string(), "z".to_string()),
            ("ALPHA".to_string(), "a".to_string()),
            ("MID".to_string(), "m".to_string()),
        ]));
        let a = make_feature("ghcr.io/x/alpha:1", serde_json::json!({}));
        let b = make_feature("ghcr.io/x/beta:1", serde_json::json!({}));

        let first = build_metadata_label(
            &order_features(&[a.clone(), b.clone()]),
            &config,
            Some("root"),
        );
        let second = build_metadata_label(&order_features(&[b, a]), &config, Some("root"));
        assert_eq!(first, second);
    }

    fn config_with(json: &str) -> DevcontainerConfig {
        super::super::jsonc::parse_jsonc(json).expect("config parses")
    }

    /// The whole point of `cmux.agent` being one key: turning it on is what
    /// puts the feature in the build, with no second declaration and nothing
    /// for the user to fetch or copy.
    #[test]
    fn cmux_agent_adds_the_feature_dev_carries() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());

        let resolved =
            resolve_features_in(&config_with(r#"{"cmux": {"agent": true}}"#), &home).unwrap();

        let staged = tmp.path().join("features/cmux-agent");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, staged.to_string_lossy());
        assert!(staged.join("install.sh").is_file());
    }

    #[test]
    fn the_feature_joins_the_ones_the_config_asked_for() {
        let tmp = tempfile::tempdir().unwrap();
        let resolved = resolve_features_in(
            &config_with(r#"{"features": {"ghcr.io/x/y:1": {}}, "cmux": {"agent": true}}"#),
            &DevHome::at(tmp.path()),
        )
        .unwrap();

        let ids: Vec<&str> = resolved.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"ghcr.io/x/y:1"));
        assert!(ids.iter().any(|id| id.ends_with("features/cmux-agent")));
    }

    /// Off unless asked for, including with the sibling sub-key on: nothing is
    /// staged and no layer is added.
    #[test]
    fn without_the_key_nothing_is_added_or_staged() {
        for json in [
            r#"{"image": "alpine"}"#,
            r#"{"cmux": {"status": true}}"#,
            r#"{"cmux": {"agent": false}}"#,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let resolved =
                resolve_features_in(&config_with(json), &DevHome::at(tmp.path())).unwrap();
            assert!(resolved.is_empty(), "{json} added a feature");
            assert!(!tmp.path().join("features").exists(), "{json} staged one");
        }
    }

    /// Reference form a local feature directory is named by in devcontainer.json.
    fn local_ref(name: &str) -> String {
        format!("./{name}")
    }

    /// Write a feature directory that `local_ref(name)` resolves to.
    fn write_local_feature(devcontainer_dir: &std::path::Path, name: &str, depends_on: &[&str]) {
        let dir = devcontainer_dir.join(name);
        std::fs::create_dir_all(&dir).expect("feature directory should be creatable");
        let mut meta = serde_json::json!({ "id": name, "version": "1.0.0" });
        if !depends_on.is_empty() {
            let deps: serde_json::Map<String, serde_json::Value> = depends_on
                .iter()
                .map(|dep| (local_ref(dep), serde_json::json!({})))
                .collect();
            meta["dependsOn"] = serde_json::Value::Object(deps);
        }
        std::fs::write(
            dir.join("devcontainer-feature.json"),
            serde_json::to_string(&meta).expect("feature metadata should serialize"),
        )
        .expect("feature metadata should be writable");
        std::fs::write(dir.join("install.sh"), "#!/bin/sh\nexit 0\n")
            .expect("install.sh should be writable");
    }

    /// The build path for local features up to the ordering step: resolve the listed
    /// ids, then download them, which walks the `dependsOn` closure off disk.
    async fn resolve_closure(
        devcontainer_dir: &std::path::Path,
        listed: &[&str],
    ) -> Vec<ResolvedFeature> {
        let mut config = empty_config();
        config.features = Some(
            listed
                .iter()
                .map(|name| (local_ref(name), serde_json::json!({})))
                .collect(),
        );
        let mut resolved = resolve_features(&config).expect("local features should resolve");
        download_features(&mut resolved, Some(devcontainer_dir))
            .await
            .expect("local features should resolve off disk");
        resolved
    }

    fn feature_ids(features: &[ResolvedFeature]) -> Vec<String> {
        features.iter().map(|f| f.id.clone()).collect()
    }

    fn install_position(features: &[ResolvedFeature], name: &str) -> usize {
        let id = local_ref(name);
        features
            .iter()
            .position(|f| f.id == id)
            .unwrap_or_else(|| panic!("{id} missing from closure {:?}", feature_ids(features)))
    }

    /// `dependsOn` features never pass through devcontainer.json's `features` object:
    /// `resolve_depends_on` discovers them by draining a queue seeded from a HashMap,
    /// so they arrive in a different order every process. `order_features` is the one
    /// choke point both paths share, and the sort has to cover this one too.
    #[tokio::test]
    async fn depends_on_closure_installs_in_one_order_however_it_is_discovered() {
        let tmp = TempDir::new().expect("tempdir should be creatable");
        let dir = tmp.path();
        // A diamond, so `base` is reached twice by different routes.
        write_local_feature(dir, "app", &["lib", "tool"]);
        write_local_feature(dir, "lib", &["base"]);
        write_local_feature(dir, "tool", &["base"]);
        write_local_feature(dir, "base", &[]);
        write_local_feature(dir, "solo", &[]);

        let closure = resolve_closure(dir, &["app", "solo"]).await;
        assert_eq!(closure.len(), 5, "closure: {:?}", feature_ids(&closure));

        // Every declared dependsOn has to survive as an install_after edge. `base` is
        // the one that gets dropped when the edge is only recorded for features
        // already resolved at the moment the dependency is popped: whichever of `lib`
        // and `tool` is discovered second loses it.
        let declared: &[(&str, &[&str])] = &[
            ("app", &["lib", "tool"]),
            ("lib", &["base"]),
            ("tool", &["base"]),
            ("solo", &[]),
            ("base", &[]),
        ];
        for (name, deps) in declared {
            let found = &closure[install_position(&closure, name)].install_after;
            let mut expected: Vec<String> = deps.iter().map(|d| local_ref(d)).collect();
            expected.sort();
            let mut actual = found.clone();
            actual.sort();
            assert_eq!(actual, expected, "install_after edges for {name}");
        }

        // The closure arrives in whatever order the HashMap-seeded queue drained it.
        // Reversing it is the cheap stand-in for that reshuffle, and unlike relying on
        // HashMap randomness it fails deterministically if the sort is dropped.
        let forward = order_features(&closure);
        let reversed = order_features(&closure.iter().rev().cloned().collect::<Vec<_>>());
        assert_eq!(
            feature_ids(&forward),
            feature_ids(&reversed),
            "discovery order must not reach the install order"
        );

        let relisted = order_features(&resolve_closure(dir, &["solo", "app"]).await);
        assert_eq!(
            feature_ids(&forward),
            feature_ids(&relisted),
            "listing order in devcontainer.json must not reach the install order"
        );

        let config = empty_config();
        let render = |features: &[ResolvedFeature]| {
            generate_feature_dockerfile_with_opts(
                "base:latest",
                "vsc-test",
                features,
                Some("root"),
                &config,
            )
        };
        assert_eq!(render(&forward), render(&reversed));

        assert!(install_position(&forward, "base") < install_position(&forward, "lib"));
        assert!(install_position(&forward, "base") < install_position(&forward, "tool"));
        assert!(install_position(&forward, "lib") < install_position(&forward, "app"));
        assert!(install_position(&forward, "tool") < install_position(&forward, "app"));
    }

    /// `read_depends_on` hands back a HashMap, so `resolve_depends_on` appends to
    /// `install_after` in an order that reshuffles every process. Only the set of
    /// edges may reach the output, never the order they were recorded in.
    #[test]
    fn install_after_order_within_a_feature_does_not_reach_the_install_order() {
        let mut app = feature("./app");
        app.install_after = vec![
            "./base".to_string(),
            "./lib".to_string(),
            "./tool".to_string(),
        ];
        let mut lib = feature("./lib");
        lib.install_after = vec!["./base".to_string()];
        let mut tool = feature("./tool");
        tool.install_after = vec!["./base".to_string()];
        let base = feature("./base");

        let forward = order_features(&[app.clone(), lib.clone(), tool.clone(), base.clone()]);

        app.install_after.reverse();
        let reversed = order_features(&[base, tool, lib, app]);

        assert_eq!(feature_ids(&forward), feature_ids(&reversed));
        assert_eq!(
            feature_ids(&forward),
            vec!["./base", "./lib", "./tool", "./app"],
            "unconstrained features should stay in sorted id order"
        );
    }

    #[test]
    fn declared_option_defaults_are_exported_and_project_values_win() {
        let mut feature = make_feature("feature-a", serde_json::json!({"version": "3.12"}));
        feature.option_defaults.insert(
            "version".to_string(),
            serde_json::Value::String("latest".to_string()),
        );
        feature.option_defaults.insert(
            "terragrunt".to_string(),
            serde_json::Value::String("latest".to_string()),
        );
        feature.option_defaults.insert(
            "installSentinel".to_string(),
            serde_json::Value::Bool(false),
        );

        let config = empty_config();
        let dockerfile = generate_feature_dockerfile_with_opts(
            "base:latest",
            "vsc-test",
            &[feature],
            Some("root"),
            &config,
        );

        assert!(
            dockerfile.contains(r#"export TERRAGRUNT="$(printf '%b' 'latest')""#),
            "an option the project left unset should come from the feature default.\nDockerfile:\n{dockerfile}"
        );
        assert!(
            dockerfile.contains(r#"export INSTALLSENTINEL="$(printf '%b' 'false')""#),
            "non-string defaults should be exported too.\nDockerfile:\n{dockerfile}"
        );
        assert!(
            dockerfile.contains(r#"export VERSION="$(printf '%b' '3.12')""#),
            "the project's value should win over the default.\nDockerfile:\n{dockerfile}"
        );
        assert!(
            !dockerfile.contains(r#"export VERSION="$(printf '%b' 'latest')""#),
            "the default must not also be exported for an option the project set.\nDockerfile:\n{dockerfile}"
        );
    }

    #[test]
    fn feature_options_do_not_leak_across_features() {
        let features = vec![
            make_feature("feature-a", serde_json::json!({"version": "3.12"})),
            make_feature("feature-b", serde_json::json!({})),
        ];
        let config = empty_config();
        let dockerfile = generate_feature_dockerfile_with_opts(
            "base:latest",
            "vsc-test",
            &features,
            Some("root"),
            &config,
        );

        // Feature options should be in RUN (scoped), not ENV (global).
        assert!(
            !dockerfile.contains("ENV VERSION="),
            "Feature options must not use ENV directives (they leak across features).\nDockerfile:\n{dockerfile}"
        );
        // feature-a's RUN should contain the export.
        assert!(
            dockerfile.contains("export VERSION=\"$(printf '%b' '3.12')\""),
            "Feature-a's RUN step should export VERSION.\nDockerfile:\n{dockerfile}"
        );
    }

    #[test]
    fn container_env_uses_env_directive() {
        // containerEnv intentionally persists in the image — should use ENV.
        let mut feature = make_feature("feature-a", serde_json::json!({}));
        feature
            .container_env
            .insert("MY_VAR".to_string(), "hello".to_string());
        let features = vec![feature];
        let config = empty_config();
        let dockerfile = generate_feature_dockerfile_with_opts(
            "base:latest",
            "vsc-test",
            &features,
            Some("root"),
            &config,
        );
        assert!(
            dockerfile.contains("ENV MY_VAR=\"hello\""),
            "containerEnv should use ENV directives.\nDockerfile:\n{dockerfile}"
        );
    }

    #[test]
    fn option_name_to_env_uppercases() {
        assert_eq!(option_name_to_env("version"), "VERSION");
        assert_eq!(option_name_to_env("nodeVersion"), "NODEVERSION");
        assert_eq!(option_name_to_env("my-option"), "MY_OPTION");
    }

    #[test]
    fn feature_options_escape_special_characters() {
        let features = vec![make_feature(
            "feature-a",
            serde_json::json!({"desc": "line1\nline2"}),
        )];
        let config = empty_config();
        let dockerfile = generate_feature_dockerfile_with_opts(
            "base:latest",
            "vsc-test",
            &features,
            Some("root"),
            &config,
        );
        // Newlines should be escaped as \n inside printf, not literal newlines
        // that would break the Dockerfile RUN instruction.
        assert!(
            !dockerfile.contains("line1\nline2"),
            "Literal newlines must not appear in Dockerfile.\nDockerfile:\n{dockerfile}"
        );
        assert!(
            dockerfile.contains("export DESC=\"$(printf '%b' 'line1\\nline2')\""),
            "Special characters should be escaped via printf.\nDockerfile:\n{dockerfile}"
        );
    }

    /// [`write_feature_tree`] with an executable install.sh, landed in an odd
    /// mode so a test can tell a preserved mode from a normalized one.
    fn write_executable_feature_tree(dir: &std::path::Path) {
        write_feature_tree(dir);
        set_mode(&dir.join("install.sh"), 0o700);
    }

    /// Every mode in a test tree is set by hand. One the umask picked would make
    /// the golden fingerprint below differ between machines.
    fn set_mode(path: &std::path::Path, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .expect("mode should be settable");
        }
        #[cfg(not(unix))]
        let _ = (path, mode);
    }

    /// Give every file a new mtime, the way `stage_feature_in` does by rewriting
    /// the cmux-agent files on every run.
    fn bump_mtimes(dir: &std::path::Path, to: std::time::SystemTime) {
        for entry in std::fs::read_dir(dir).expect("tree should be readable") {
            let path = entry.expect("entry should be readable").path();
            if path.is_dir() {
                bump_mtimes(&path, to);
                continue;
            }
            std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("file should be writable")
                .set_modified(to)
                .expect("mtime should be settable");
        }
    }

    /// The tarball is the Docker build context and `ADD {i}.tar` is a cache key,
    /// so a touched-but-unchanged feature must produce the same bytes.
    #[test]
    fn tar_bytes_survive_an_mtime_bump() {
        let tmp = TempDir::new().expect("temp dir");
        let src = tmp.path().join("feature");
        write_executable_feature_tree(&src);

        let first = tmp.path().join("first.tar");
        create_tar(&src, &first).expect("first tar should be created");

        bump_mtimes(
            &src,
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        );

        let second = tmp.path().join("second.tar");
        create_tar(&src, &second).expect("second tar should be created");

        assert_eq!(
            std::fs::read(&first).expect("first tar reads"),
            std::fs::read(&second).expect("second tar reads"),
            "identical content must produce identical bytes"
        );
    }

    /// One tar entry, flattened for assertions.
    struct TarEntry {
        name: String,
        mode: u32,
        mtime: u64,
        uid: u64,
        gid: u64,
        is_dir: bool,
        data: Vec<u8>,
    }

    fn read_tar(path: &std::path::Path) -> Vec<TarEntry> {
        use std::io::Read;
        let file = std::fs::File::open(path).expect("tar reads");
        let mut archive = tar::Archive::new(file);
        archive
            .entries()
            .expect("entries should be listable")
            .map(|entry| {
                let mut entry = entry.expect("entry should be readable");
                let header = entry.header().clone();
                let mut data = Vec::new();
                entry.read_to_end(&mut data).expect("body should read");
                TarEntry {
                    name: entry
                        .path()
                        .expect("path should decode")
                        .display()
                        .to_string(),
                    mode: header.mode().expect("mode should decode"),
                    mtime: header.mtime().expect("mtime should decode"),
                    uid: header.uid().expect("uid should decode"),
                    gid: header.gid().expect("gid should decode"),
                    is_dir: header.entry_type().is_dir(),
                    data,
                }
            })
            .collect()
    }

    fn tar_entry<'a>(entries: &'a [TarEntry], name: &str) -> &'a TarEntry {
        entries
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("{name} should be in the archive"))
    }

    /// Tar a tree written by [`write_feature_tree`], with `extra` run against it
    /// first.
    fn tar_of_feature_tree(tmp: &TempDir, extra: impl FnOnce(&std::path::Path)) -> Vec<TarEntry> {
        let src = tmp.path().join("feature");
        write_feature_tree(&src);
        extra(&src);
        let tar_path = tmp.path().join("feature.tar");
        create_tar(&src, &tar_path).expect("tar should be created");
        read_tar(&tar_path)
    }

    #[test]
    fn tar_headers_carry_no_host_metadata() {
        let tmp = TempDir::new().expect("temp dir");
        let entries = tar_of_feature_tree(&tmp, |src| {
            set_mode(&src.join("install.sh"), 0o700);
            #[cfg(unix)]
            std::os::unix::fs::symlink(src.join("install.sh"), src.join("link.sh"))
                .expect("symlink should be creatable");
        });

        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        let mut expected = vec!["devcontainer-feature.json", "install.sh"];
        if cfg!(unix) {
            expected.push("link.sh");
        }
        expected.extend(["scripts", "scripts/helper.sh"]);
        assert_eq!(
            names, expected,
            "entries must be name-sorted, with directories carried"
        );

        for entry in &entries {
            assert_eq!(
                (entry.mtime, entry.uid, entry.gid),
                (0, 0, 0),
                "{} kept host metadata",
                entry.name
            );
        }

        let mode = |name: &str| tar_entry(&entries, name).mode;
        let executable = if cfg!(unix) { 0o700 } else { 0o644 };
        assert_eq!(
            mode("install.sh"),
            executable,
            "an odd exec mode is narrowed, never widened to 0755"
        );
        assert_eq!(mode("scripts/helper.sh"), 0o644);
        assert_eq!(mode("devcontainer-feature.json"), 0o644);
        assert_eq!(mode("scripts"), 0o755);
        assert!(tar_entry(&entries, "scripts").is_dir);
    }

    /// Features ship links like `scripts/common -> ../shared/common.sh`. Leaving
    /// one out of the context kills install.sh inside the container with a "No
    /// such file or directory" that names nothing this code touched.
    #[cfg(unix)]
    #[test]
    fn tar_follows_a_symlink_to_its_target() {
        let tmp = TempDir::new().expect("temp dir");
        let entries = tar_of_feature_tree(&tmp, |src| {
            std::fs::create_dir_all(src.join("shared")).expect("shared dir should be creatable");
            std::fs::write(src.join("shared/common.sh"), "common\n").expect("target writes");
            set_mode(&src.join("shared"), 0o755);
            set_mode(&src.join("shared/common.sh"), 0o644);
            std::os::unix::fs::symlink("../shared/common.sh", src.join("scripts/common.sh"))
                .expect("symlink should be creatable");
        });

        assert_eq!(
            tar_entry(&entries, "scripts/common.sh").data,
            b"common\n",
            "a symlink must arrive as the bytes it points at"
        );
    }

    /// Nested files survive without directory headers because Docker's unpacker
    /// invents missing parents. An empty directory is the case that does not.
    #[test]
    fn tar_keeps_an_empty_directory() {
        let tmp = TempDir::new().expect("temp dir");
        let entries = tar_of_feature_tree(&tmp, |src| {
            std::fs::create_dir_all(src.join("cache")).expect("cache dir should be creatable");
            set_mode(&src.join("cache"), 0o755);
        });

        assert!(
            tar_entry(&entries, "cache").is_dir,
            "an empty directory a feature ships must reach the image"
        );
    }

    /// A file a feature keeps to itself must not land in the image readable by
    /// every user in the container.
    #[cfg(unix)]
    #[test]
    fn tar_keeps_a_restrictive_mode() {
        let tmp = TempDir::new().expect("temp dir");
        let entries = tar_of_feature_tree(&tmp, |src| {
            set_mode(&src.join("devcontainer-feature.json"), 0o600);
        });

        assert_eq!(tar_entry(&entries, "devcontainer-feature.json").mode, 0o600);
    }

    /// "Permission denied (os error 13)" on its own, in the middle of an image
    /// build, points at nothing.
    #[test]
    fn tar_errors_name_the_path() {
        let tmp = TempDir::new().expect("temp dir");
        let err = create_tar(&tmp.path().join("gone"), &tmp.path().join("out.tar"))
            .expect_err("a missing source directory should fail");
        assert!(
            err.to_string().contains("gone"),
            "the error must name the path: {err}"
        );
    }

    /// A feature set shaped like a real project's: a local feature whose
    /// absolute-path id sorts ahead of every registry id, plus two registry
    /// features where one installs after the other.
    ///
    /// Ids are fixed strings while the staged directories live under `root`,
    /// because the Dockerfile embeds the id and never the staging path. That is
    /// what lets the fingerprint below be a constant.
    fn fingerprint_features(root: &std::path::Path) -> Vec<ResolvedFeature> {
        let staged = |name: &str| {
            let dir = root.join(name);
            write_feature_tree(&dir);
            dir
        };

        let mut local = feature("/staged/cmux-agent");
        local.install_script_path = staged("cmux-agent");

        let mut git = make_feature(
            "ghcr.io/devcontainers/features/git:1",
            serde_json::json!({"version": "latest"}),
        );
        git.install_script_path = staged("git");
        git.version = "1".to_string();

        let mut gh = make_feature(
            "ghcr.io/devcontainers/features/github-cli:1",
            serde_json::json!({}),
        );
        gh.install_script_path = staged("github-cli");
        gh.version = "1".to_string();
        gh.install_after = vec!["ghcr.io/devcontainers/features/git:1".to_string()];
        gh.container_env
            .insert("GH_NO_UPDATE_NOTIFIER".to_string(), "1".to_string());

        vec![local, git, gh]
    }

    /// Write a feature directory shaped like the ones that ship a `scripts/`
    /// subdirectory, so the recursive walk is covered. Nothing is executable,
    /// which keeps the fingerprint below the same on every platform.
    fn write_feature_tree(dir: &std::path::Path) {
        std::fs::create_dir_all(dir.join("scripts")).expect("tree should be creatable");
        std::fs::write(dir.join("install.sh"), "#!/bin/sh\nexit 0\n").expect("install.sh writes");
        std::fs::write(dir.join("devcontainer-feature.json"), "{}").expect("metadata writes");
        std::fs::write(dir.join("scripts/helper.sh"), "echo hi\n").expect("helper writes");
        set_mode(&dir.join("scripts"), 0o755);
        set_mode(&dir.join("install.sh"), 0o644);
        set_mode(&dir.join("devcontainer-feature.json"), 0o644);
        set_mode(&dir.join("scripts/helper.sh"), 0o644);
    }

    fn fingerprint_config(env_keys: &[&str]) -> DevcontainerConfig {
        let pairs: Vec<String> = env_keys
            .iter()
            .map(|key| format!("\"{key}\": \"{key}-value\""))
            .collect();
        let pairs = pairs.join(", ");
        config_with(&format!(
            r#"{{"remoteUser": "vscode", "containerEnv": {{{pairs}}}, "remoteEnv": {{{pairs}}}}}"#
        ))
    }

    /// One hash over everything a build hands Docker: the generated Dockerfile
    /// and every staged tarball, in the order the Dockerfile adds them.
    fn build_input_fingerprint(
        features: &[ResolvedFeature],
        config: &DevcontainerConfig,
        staging: &std::path::Path,
    ) -> String {
        use sha2::{Digest, Sha256};

        std::fs::create_dir_all(staging).expect("staging dir should be creatable");
        let ordered = order_features(features);
        let mut hasher = Sha256::new();
        hasher.update(generate_feature_dockerfile_with_opts(
            "base:latest",
            "vsc-test",
            &ordered,
            Some("vscode"),
            config,
        ));
        for (i, feature) in ordered.iter().enumerate() {
            let tar = staging.join(format!("{i}.tar"));
            create_tar(&feature.install_script_path, &tar).expect("tar should be created");
            hasher.update(std::fs::read(&tar).expect("tar reads"));
        }
        format!("{:x}", hasher.finalize())
    }

    /// Locks the bytes a build hands Docker. A `HashMap` that reaches the image
    /// makes this flap between CI runs, since each process seeds its own hasher.
    #[test]
    fn build_input_fingerprint_is_stable() {
        let tmp = TempDir::new().expect("temp dir");
        let features = fingerprint_features(&tmp.path().join("features"));
        let config = fingerprint_config(&["ALPHA", "BETA"]);

        assert_eq!(
            build_input_fingerprint(&features, &config, &tmp.path().join("staging")),
            "bded8a0646cbb7f90e65b6bf9fccc998880f43d8a2b53a455bd6f70e7905d48b",
            "the build input changed shape. If that was deliberate, update this \
             hash and decide whether TAG_FORMAT needs a bump so images built \
             under the old scheme stop being cache hits."
        );
    }

    /// The same inputs in a different order must produce the same bytes. This is
    /// the half the golden hash cannot cover: it stays true when the generated
    /// shape changes on purpose.
    #[test]
    fn build_input_ignores_the_order_inputs_arrive_in() {
        let tmp = TempDir::new().expect("temp dir");

        let features = fingerprint_features(&tmp.path().join("features"));
        let first = build_input_fingerprint(
            &features,
            &fingerprint_config(&["ALPHA", "BETA"]),
            &tmp.path().join("first"),
        );

        let mut shuffled = fingerprint_features(&tmp.path().join("shuffled"));
        shuffled.reverse();
        let second = build_input_fingerprint(
            &shuffled,
            &fingerprint_config(&["BETA", "ALPHA"]),
            &tmp.path().join("second"),
        );

        assert_eq!(first, second);
    }
}
