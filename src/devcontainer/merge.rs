use serde_json::Value;
use std::collections::BTreeMap;

/// Which configuration layer a merged value came from, for `dev config explain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayerId {
    GlobalTemplate(String),
    Base,
    Runtime(String),
    Project,
    RecipeFeatures,
    RecipeCustomizations,
}

impl std::fmt::Display for LayerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LayerId::GlobalTemplate(name) => write!(f, "global-template:{name}"),
            LayerId::Base => write!(f, "base"),
            LayerId::Runtime(name) => write!(f, "runtime:{name}"),
            LayerId::Project => write!(f, "project"),
            LayerId::RecipeFeatures => write!(f, "recipe-features"),
            LayerId::RecipeCustomizations => write!(f, "recipe-customizations"),
        }
    }
}

/// Origin sink for a tracked merge.
///
/// Production merges pass `Noop` and pay nothing; `dev config explain` passes
/// `Recording` and gets, for every written key path (`"image"`,
/// `"containerEnv.EDITOR"`, `"mounts[2]"`, `features["…/node:1"]`), the layer
/// that wrote it. A deduplicated array entry records nothing on the skip, so a
/// duplicate stays credited to the first layer that contributed it.
pub enum Provenance {
    Noop,
    Recording(BTreeMap<String, LayerId>),
}

impl Provenance {
    pub fn recording() -> Self {
        Provenance::Recording(BTreeMap::new())
    }

    pub fn into_origins(self) -> BTreeMap<String, LayerId> {
        match self {
            Provenance::Noop => BTreeMap::new(),
            Provenance::Recording(map) => map,
        }
    }

    fn set(&mut self, path: String, layer: &LayerId) {
        if let Provenance::Recording(map) = self {
            map.insert(path, layer.clone());
        }
    }
}

/// Fields where the base config value should override the template (scalar semantics).
const SCALAR_FIELDS: &[&str] = &["name", "image", "remoteUser", "shutdownAction", "waitFor"];

/// Lifecycle command fields. Named-command objects merge as a union; other
/// lifecycle forms keep scalar override behavior.
const LIFECYCLE_FIELDS: &[&str] = &[
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
];

/// Fields that are arrays and should be concatenated (base appended to template),
/// deduplicating entries that appear in both layers.
const ARRAY_FIELDS: &[&str] = &["forwardPorts", "mounts"];

/// Array fields that concatenate without deduplication. `runArgs` is here
/// because repeated flags (e.g. `--env-file`) are legitimate and order matters
/// for left-to-right precedence — deduping would silently drop the second
/// `--env-file` and break env-file loading (issue #5).
const ARRAY_CONCAT_FIELDS: &[&str] = &["runArgs"];

/// Fields that are key-value maps and should be merged (base keys override template keys).
const MAP_FIELDS: &[&str] = &["remoteEnv", "containerEnv", "caddy", "cmux"];

/// Fields that are feature maps (special merge: union of keys).
const FEATURE_FIELDS: &[&str] = &["features"];

/// Merge a single overlay layer on top of a base value, using field-type strategies:
/// - Scalar fields: overlay overrides base
/// - Lifecycle fields: named-command objects union (overlay wins per name); any
///   other form overrides base
/// - Array fields: concatenate (overlay appended to base, skipping duplicates)
/// - Map fields: merge (overlay keys override base keys)
/// - Feature fields: union (overlay features added to base features)
/// - Unknown fields: overlay wins
///
/// Production callers use [`merge_layer_tracked`] with a `Noop` sink; this
/// untracked form remains as the reference the equivalence test compares against.
#[cfg(test)]
pub fn merge_layer(base: &mut Value, overlay: &Value) {
    // The layer id is a placeholder: a Noop sink records nothing.
    merge_layer_tracked(base, overlay, &LayerId::Project, &mut Provenance::Noop);
}

/// [`merge_layer`] with per-value origin recording for `dev config explain`.
///
/// Behavior over the merged value is identical to `merge_layer`; the only
/// addition is that each terminal write also records its key path against
/// `layer` in `prov`.
pub fn merge_layer_tracked(
    base: &mut Value,
    overlay: &Value,
    layer: &LayerId,
    prov: &mut Provenance,
) {
    let overlay_obj = match overlay.as_object() {
        Some(obj) if !obj.is_empty() => obj,
        _ => return,
    };

    let base_obj = match base.as_object_mut() {
        Some(obj) => obj,
        None => return,
    };

    for (key, overlay_val) in overlay_obj {
        if SCALAR_FIELDS.contains(&key.as_str()) {
            base_obj.insert(key.clone(), overlay_val.clone());
            prov.set(key.clone(), layer);
        } else if LIFECYCLE_FIELDS.contains(&key.as_str()) {
            merge_lifecycle_command(base_obj, key, overlay_val, layer, prov);
        } else if FEATURE_FIELDS.contains(&key.as_str()) {
            merge_feature_map(base_obj, key, overlay_val, layer, prov);
        } else if ARRAY_CONCAT_FIELDS.contains(&key.as_str()) {
            merge_array_concat(base_obj, key, overlay_val, layer, prov);
        } else if ARRAY_FIELDS.contains(&key.as_str()) {
            merge_array(base_obj, key, overlay_val, layer, prov);
        } else if MAP_FIELDS.contains(&key.as_str()) {
            merge_map(base_obj, key, overlay_val, layer, prov);
        } else {
            base_obj.insert(key.clone(), overlay_val.clone());
            prov.set(key.clone(), layer);
        }
    }
}

fn merge_lifecycle_command(
    dest_obj: &mut serde_json::Map<String, Value>,
    key: &str,
    overlay_val: &Value,
    layer: &LayerId,
    prov: &mut Provenance,
) {
    let Some(overlay_map) = overlay_val.as_object() else {
        dest_obj.insert(key.to_string(), overlay_val.clone());
        prov.set(key.to_string(), layer);
        return;
    };

    let dest_val = dest_obj
        .entry(key.to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if let Some(dest_map) = dest_val.as_object_mut() {
        for (name, command) in overlay_map {
            dest_map.insert(name.clone(), command.clone());
            prov.set(format!("{key}.{name}"), layer);
        }
    } else {
        dest_obj.insert(key.to_string(), overlay_val.clone());
        prov.set(key.to_string(), layer);
    }
}

/// Compose N layers in order (first = lowest priority, last = highest priority).
/// Returns the merged result.
#[cfg(test)]
pub fn merge_layers(layers: &[Value]) -> Value {
    let mut result = Value::Object(serde_json::Map::new());
    for layer in layers {
        merge_layer(&mut result, layer);
    }
    result
}

/// [`merge_layers`] with per-value origin recording for `dev config explain`.
pub fn merge_layers_tracked(layers: &[(LayerId, Value)], prov: &mut Provenance) -> Value {
    let mut result = Value::Object(serde_json::Map::new());
    for (id, layer) in layers {
        merge_layer_tracked(&mut result, layer, id, prov);
    }
    result
}

/// Union feature maps: base features are added to template features.
/// If both have the same feature, base options override.
fn merge_feature_map(
    dest_obj: &mut serde_json::Map<String, Value>,
    key: &str,
    base_val: &Value,
    layer: &LayerId,
    prov: &mut Provenance,
) {
    let base_features = match base_val.as_object() {
        Some(obj) => obj,
        None => return,
    };

    let dest_features = dest_obj
        .entry(key)
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if let Some(dest_map) = dest_features.as_object_mut() {
        for (feature_key, feature_val) in base_features {
            dest_map.insert(feature_key.clone(), feature_val.clone());
            prov.set(format!("{key}[\"{feature_key}\"]"), layer);
        }
    }
}

/// Concatenate arrays: base values appended to template values, skipping duplicates.
fn merge_array(
    dest_obj: &mut serde_json::Map<String, Value>,
    key: &str,
    base_val: &Value,
    layer: &LayerId,
    prov: &mut Provenance,
) {
    let base_arr = match base_val.as_array() {
        Some(arr) => arr,
        None => return,
    };

    let dest_arr = dest_obj
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()));

    if let Some(dest_vec) = dest_arr.as_array_mut() {
        for item in base_arr {
            if !dest_vec.contains(item) {
                // Indices are final: merging only ever appends. A duplicate
                // records nothing, so the first contributing layer keeps credit.
                dest_vec.push(item.clone());
                prov.set(format!("{key}[{}]", dest_vec.len() - 1), layer);
            }
        }
    }
}

/// Concatenate arrays without deduplication. Used for `runArgs`, where repeated
/// flags are legitimate and the left-to-right order is semantically meaningful.
fn merge_array_concat(
    dest_obj: &mut serde_json::Map<String, Value>,
    key: &str,
    base_val: &Value,
    layer: &LayerId,
    prov: &mut Provenance,
) {
    let base_arr = match base_val.as_array() {
        Some(arr) => arr,
        None => return,
    };

    let dest_arr = dest_obj
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()));

    if let Some(dest_vec) = dest_arr.as_array_mut() {
        for item in base_arr {
            dest_vec.push(item.clone());
            prov.set(format!("{key}[{}]", dest_vec.len() - 1), layer);
        }
    }
}

/// Merge maps: base keys override template keys.
fn merge_map(
    dest_obj: &mut serde_json::Map<String, Value>,
    key: &str,
    base_val: &Value,
    layer: &LayerId,
    prov: &mut Provenance,
) {
    let base_map = match base_val.as_object() {
        Some(obj) => obj,
        None => return,
    };

    let dest_map = dest_obj
        .entry(key)
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if let Some(dest_m) = dest_map.as_object_mut() {
        for (k, v) in base_map {
            dest_m.insert(k.clone(), v.clone());
            prov.set(format!("{key}.{k}"), layer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    /// The tracked merge is the production merge: a Noop sink must yield a
    /// bit-identical result to the untracked entry points.
    #[test]
    fn noop_provenance_changes_nothing() {
        let base = serde_json::json!({
            "remoteUser": "vscode",
            "mounts": ["source=a,target=/a,type=volume"],
            "containerEnv": {"EDITOR": "vim"},
            "features": {"ghcr.io/x/y:1": {}},
            "runArgs": ["--env-file", ".env"],
            "postCreateCommand": {"setup": "make setup"}
        });
        let project = serde_json::json!({
            "image": "ubuntu:24.04",
            "mounts": ["source=a,target=/a,type=volume", "source=b,target=/b,type=volume"],
            "containerEnv": {"TERM": "xterm"},
            "runArgs": ["--env-file", ".env"],
            "postCreateCommand": {"lint": "make lint"}
        });

        let plain = merge_layers(&[base.clone(), project.clone()]);
        let tracked = merge_layers_tracked(
            &[(LayerId::Base, base), (LayerId::Project, project)],
            &mut Provenance::Noop,
        );

        assert_eq!(plain, tracked);
    }

    /// Every write class records the layer that performed it, keyed the way
    /// `dev config explain` prints: scalars by key, maps and lifecycle
    /// commands by sub-key, arrays by final index, features by quoted id.
    #[test]
    fn tracked_merge_credits_values_to_their_layers() {
        let base = serde_json::json!({
            "remoteUser": "vscode",
            "containerEnv": {"EDITOR": "vim"},
            "mounts": ["source=a,target=/a,type=volume"],
            "features": {"ghcr.io/x/y:1": {}},
            "postCreateCommand": {"setup": "make setup"}
        });
        let project = serde_json::json!({
            "image": "ubuntu:24.04",
            "containerEnv": {"EDITOR": "nano", "TERM": "xterm"},
            "mounts": ["source=b,target=/b,type=volume"],
            "postCreateCommand": {"lint": "make lint"}
        });

        let mut prov = Provenance::recording();
        merge_layers_tracked(
            &[(LayerId::Base, base), (LayerId::Project, project)],
            &mut prov,
        );
        let origins = prov.into_origins();

        assert_eq!(origins["image"], LayerId::Project);
        assert_eq!(origins["remoteUser"], LayerId::Base);
        assert_eq!(
            origins["containerEnv.EDITOR"],
            LayerId::Project,
            "overridden sub-key"
        );
        assert_eq!(origins["containerEnv.TERM"], LayerId::Project);
        assert_eq!(origins["mounts[0]"], LayerId::Base);
        assert_eq!(origins["mounts[1]"], LayerId::Project);
        assert_eq!(origins["features[\"ghcr.io/x/y:1\"]"], LayerId::Base);
        assert_eq!(origins["postCreateCommand.setup"], LayerId::Base);
        assert_eq!(origins["postCreateCommand.lint"], LayerId::Project);
    }

    #[test]
    fn cmux_sub_keys_are_credited_per_layer() {
        let base = serde_json::json!({
            "cmux": {"status": true}
        });
        let project = serde_json::json!({
            "cmux": {"agent": true}
        });

        let mut prov = Provenance::recording();
        let merged = merge_layers_tracked(
            &[(LayerId::Base, base), (LayerId::Project, project)],
            &mut prov,
        );
        let origins = prov.into_origins();

        assert_eq!(origins["cmux.status"], LayerId::Base);
        assert_eq!(origins["cmux.agent"], LayerId::Project);
        let cmux = merged["cmux"].as_object().unwrap();
        assert_eq!(cmux["status"], true);
        assert_eq!(cmux["agent"], true);
    }

    /// A deduplicated array entry is dropped on the later layer, so the first
    /// contributing layer keeps the credit.
    #[test]
    fn deduped_array_entry_keeps_lower_layer_credit() {
        let mount = "source=a,target=/a,type=volume";
        let base = serde_json::json!({ "mounts": [mount] });
        let project = serde_json::json!({ "mounts": [mount] });

        let mut prov = Provenance::recording();
        let merged = merge_layers_tracked(
            &[(LayerId::Base, base), (LayerId::Project, project)],
            &mut prov,
        );
        let origins = prov.into_origins();

        assert_eq!(merged["mounts"].as_array().unwrap().len(), 1);
        assert_eq!(origins["mounts[0]"], LayerId::Base);
    }

    fn setup_merge_test(
        base_content: &str,
        dest_content: &str,
    ) -> (TempDir, TempDir, std::path::PathBuf) {
        // Set up base config
        let base_dir = TempDir::new().unwrap();
        fs::write(base_dir.path().join("devcontainer.json"), base_content).unwrap();

        // Set up dest config
        let dest_dir = TempDir::new().unwrap();
        let devcontainer_dir = dest_dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        let dest_config = devcontainer_dir.join("devcontainer.json");
        fs::write(&dest_config, dest_content).unwrap();

        (base_dir, dest_dir, dest_config)
    }

    fn merge_with_base(base_path: &Path, dest: &Path) -> anyhow::Result<bool> {
        let base_config_path = base_path.join("devcontainer.json");
        if !base_config_path.is_file() {
            return Ok(false);
        }

        let dest_config_path = dest.join(".devcontainer/devcontainer.json");
        if !dest_config_path.is_file() {
            return Ok(false);
        }

        let base_raw = fs::read_to_string(&base_config_path)?;
        let base: Value = serde_json::from_str(&base_raw)?;

        let dest_raw = fs::read_to_string(&dest_config_path)?;
        let mut dest_json: Value = serde_json::from_str(&dest_raw)?;

        let base_obj = match base.as_object() {
            Some(obj) if !obj.is_empty() => obj,
            _ => return Ok(false),
        };

        let dest_obj = dest_json.as_object_mut().unwrap();

        for (key, base_val) in base_obj {
            let mut prov = Provenance::Noop;
            if SCALAR_FIELDS.contains(&key.as_str()) {
                dest_obj.insert(key.clone(), base_val.clone());
            } else if FEATURE_FIELDS.contains(&key.as_str()) {
                merge_feature_map(dest_obj, key, base_val, &LayerId::Project, &mut prov);
            } else if ARRAY_CONCAT_FIELDS.contains(&key.as_str()) {
                merge_array_concat(dest_obj, key, base_val, &LayerId::Project, &mut prov);
            } else if ARRAY_FIELDS.contains(&key.as_str()) {
                merge_array(dest_obj, key, base_val, &LayerId::Project, &mut prov);
            } else if MAP_FIELDS.contains(&key.as_str()) {
                merge_map(dest_obj, key, base_val, &LayerId::Project, &mut prov);
            } else {
                dest_obj.insert(key.clone(), base_val.clone());
            }
        }

        let formatted = serde_json::to_string_pretty(&dest_json)?;
        fs::write(&dest_config_path, formatted)?;

        Ok(true)
    }

    #[test]
    fn test_merge_features_union() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"features": {"ghcr.io/features/zsh": {}}}"#,
            r#"{"features": {"ghcr.io/features/node": {}}}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let features = json["features"].as_object().unwrap();
        assert!(features.contains_key("ghcr.io/features/node"));
        assert!(features.contains_key("ghcr.io/features/zsh"));
    }

    #[test]
    fn test_merge_arrays_concatenate() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"mounts": ["source=a,target=/a,type=bind"]}"#,
            r#"{"mounts": ["source=b,target=/b,type=bind"]}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let mounts = json["mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0], "source=b,target=/b,type=bind");
        assert_eq!(mounts[1], "source=a,target=/a,type=bind");
    }

    #[test]
    fn test_merge_maps_base_overrides() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"remoteEnv": {"POSH_THEME": "/home/vscode/.config/omp/theme.omp.json", "SHARED": "base"}}"#,
            r#"{"remoteEnv": {"NODE_ENV": "development", "SHARED": "template"}}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let env = json["remoteEnv"].as_object().unwrap();
        assert_eq!(env["NODE_ENV"], "development");
        assert_eq!(env["POSH_THEME"], "/home/vscode/.config/omp/theme.omp.json");
        assert_eq!(env["SHARED"], "base"); // base wins
    }

    /// A per-port map, so a recipe naming one service's host doesn't wipe the
    /// names a lower layer gave the others.
    #[test]
    fn test_merge_caddy_hostnames_per_port() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"caddy": {"5163": "api.chuckos"}}"#,
            r#"{"caddy": {"5247": "chuckos", "5163": "template"}}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let caddy = json["caddy"].as_object().unwrap();
        assert_eq!(caddy["5247"], "chuckos");
        assert_eq!(caddy["5163"], "api.chuckos"); // base wins
    }

    #[test]
    fn test_merge_cmux_per_sub_key() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"cmux": {"status": true}}"#,
            r#"{"cmux": {"agent": true, "status": false}}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let cmux = json["cmux"].as_object().unwrap();
        assert_eq!(cmux["status"], true); // base wins
        assert_eq!(cmux["agent"], true); // template sub-key survives
    }

    #[test]
    fn test_merge_scalars_base_overrides() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"remoteUser": "vscode"}"#,
            r#"{"image": "ubuntu", "remoteUser": "root"}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        assert_eq!(json["image"], "ubuntu"); // template preserved
        assert_eq!(json["remoteUser"], "vscode"); // base overrides
    }

    #[test]
    fn test_merge_no_base_config() {
        let dest_dir = TempDir::new().unwrap();
        let devcontainer_dir = dest_dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        fs::write(
            devcontainer_dir.join("devcontainer.json"),
            r#"{"image": "ubuntu"}"#,
        )
        .unwrap();

        let base_dir = TempDir::new().unwrap();
        // No base config file created
        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_merge_empty_base_config() {
        let (base_dir, dest_dir, _) = setup_merge_test(r#"{}"#, r#"{"image": "ubuntu"}"#);

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(!result); // Empty base = no-op
    }

    #[test]
    fn test_merge_forward_ports_concatenate() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"forwardPorts": [9090]}"#,
            r#"{"forwardPorts": [3000, 8080]}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let ports = json["forwardPorts"].as_array().unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], 3000);
        assert_eq!(ports[1], 8080);
        assert_eq!(ports[2], 9090);
    }

    /// `runArgs` must concatenate without deduplicating: repeated flags such as
    /// `--env-file` are legitimate and order matters (left-to-right precedence).
    /// A single project layer repeating `--env-file` must keep every occurrence.
    #[test]
    fn test_merge_run_args_preserves_repeated_flags() {
        let dest_dir = TempDir::new().unwrap();
        let devcontainer_dir = dest_dir.path().join(".devcontainer");
        fs::create_dir_all(&devcontainer_dir).unwrap();
        let dest_config = devcontainer_dir.join("devcontainer.json");
        fs::write(
            &dest_config,
            r#"{"image":"ubuntu","runArgs":["--env-file","a.env","--env-file","b.env"]}"#,
        )
        .unwrap();
        let base_dir = TempDir::new().unwrap();

        let _ = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let run_args = json["runArgs"].as_array().unwrap();
        assert_eq!(
            run_args
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["--env-file", "a.env", "--env-file", "b.env"],
            "repeated --env-file flags must survive the merge"
        );
    }

    /// Across base + project layers, `runArgs` concatenate in order without
    /// dedup, so a flag repeated in both layers is preserved.
    #[test]
    fn test_merge_run_args_concatenates_layers_without_dedup() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"runArgs":["--env","BASE=1"]}"#,
            r#"{"runArgs":["--env-file","project.env"]}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        let run_args = json["runArgs"].as_array().unwrap();
        assert_eq!(
            run_args
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["--env-file", "project.env", "--env", "BASE=1"],
            "project runArgs come first, base appended, no dedup"
        );
    }

    #[test]
    fn test_merge_unknown_fields_base_wins() {
        let (base_dir, dest_dir, dest_config) = setup_merge_test(
            r#"{"customSetting": "from-base"}"#,
            r#"{"image": "ubuntu", "customSetting": "from-template"}"#,
        );

        let result = merge_with_base(base_dir.path(), dest_dir.path()).unwrap();
        assert!(result);

        let json: Value = serde_json::from_str(&fs::read_to_string(&dest_config).unwrap()).unwrap();
        assert_eq!(json["customSetting"], "from-base");
    }

    #[test]
    fn lifecycle_named_commands_merge_as_union() {
        let layers = vec![
            serde_json::json!({
                "postCreateCommand": {
                    "base-dotfiles": "install-dotfiles",
                    "shared": "base"
                }
            }),
            serde_json::json!({
                "postCreateCommand": {
                    "project-setup": "cargo fetch",
                    "shared": "project"
                }
            }),
        ];

        let merged = merge_layers(&layers);
        assert_eq!(
            merged["postCreateCommand"]["base-dotfiles"],
            "install-dotfiles"
        );
        assert_eq!(merged["postCreateCommand"]["project-setup"], "cargo fetch");
        assert_eq!(merged["postCreateCommand"]["shared"], "project");
    }

    #[test]
    fn lifecycle_non_object_forms_still_override() {
        let layers = vec![
            serde_json::json!({
                "postCreateCommand": {
                    "base-dotfiles": "install-dotfiles"
                }
            }),
            serde_json::json!({
                "postCreateCommand": "project setup"
            }),
        ];

        let merged = merge_layers(&layers);
        assert_eq!(merged["postCreateCommand"], "project setup");
    }
}
