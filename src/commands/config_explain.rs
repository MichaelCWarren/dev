use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::devcontainer::Recipe;
use crate::devcontainer::compose::compose_recipe_config_tracked_in;
use crate::devcontainer::effective::load_effective_config_value_tracked;
use crate::devcontainer::merge::{LayerId, Provenance};
use crate::runtime::{ALLOW_RELAY_PROPERTY, RELAY_PROPERTY};
use crate::util::ConfigSource;
use crate::util::paths::DevHome;

/// `dev config explain`: the effective merged config, annotated per value with
/// the layer it came from — the merge `dev up` actually performs, not the raw
/// project file `dev config list` shows.
pub async fn run(
    workspace: &Path,
    runtime_override: Option<&str>,
    json: bool,
    no_base: bool,
) -> anyhow::Result<()> {
    let runtime_name = super::config::detected_runtime_name(runtime_override).await;
    let report = explain(&DevHome::current(), workspace, &runtime_name, !no_base)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    } else {
        print!("{}", report.render());
    }
    Ok(())
}

/// One configuration layer as shown in the report header.
struct LayerRow {
    id: String,
    path: PathBuf,
    present: bool,
}

struct ExplainReport {
    workspace: PathBuf,
    kind: &'static str,
    runtime_layer: String,
    layers: Vec<LayerRow>,
    config: Value,
    origins: BTreeMap<String, LayerId>,
    dropped: Vec<String>,
    relay: RelayPermission,
}

/// The base config's half of the SSH agent relay decision.
///
/// It is read from that file directly and never merged, so `Provenance` has
/// nothing to say about it and the report must not pretend otherwise — a
/// fabricated `base` origin would be exactly the kind of lie the probed bits
/// of `HostAccess` exist to avoid. Hence its own block, outside the
/// merged-key table.
struct RelayPermission {
    base: PathBuf,
    allowed: bool,
}

impl RelayPermission {
    fn read(dev_home: &DevHome) -> Self {
        Self {
            base: dev_home.base_config(),
            allowed: crate::runtime::ssh_agent_relay_allowed_in(dev_home),
        }
    }
}

/// Build the report by running the same tracked pipeline `dev up` merges with.
fn explain(
    dev_home: &DevHome,
    workspace: &Path,
    runtime_name: &str,
    include_base: bool,
) -> anyhow::Result<ExplainReport> {
    let mut prov = Provenance::recording();
    match crate::util::workspace::find_config_source_in(dev_home, workspace)? {
        ConfigSource::Direct(config_path) => {
            let base_path = dev_home.base_config();
            let (config, _ids, dropped) = load_effective_config_value_tracked(
                &config_path,
                include_base,
                &base_path,
                &mut prov,
            )?;
            let mut layers = Vec::new();
            if include_base {
                layers.push(LayerRow {
                    id: LayerId::Base.to_string(),
                    present: base_path.is_file(),
                    path: base_path,
                });
            }
            layers.push(LayerRow {
                id: LayerId::Project.to_string(),
                present: true,
                path: config_path,
            });
            Ok(ExplainReport {
                workspace: workspace.to_path_buf(),
                kind: "direct",
                runtime_layer: runtime_name.to_string(),
                layers,
                config,
                origins: prov.into_origins(),
                dropped,
                relay: RelayPermission::read(dev_home),
            })
        }
        ConfigSource::Recipe(recipe_path) => {
            let recipe = Recipe::from_path(&recipe_path)?;
            let (composed, dropped) = compose_recipe_config_tracked_in(
                dev_home,
                &recipe_path,
                &recipe,
                runtime_name,
                include_base,
                &mut prov,
            )?;
            let layers = recipe_layers(dev_home, &recipe, &recipe_path, runtime_name, include_base);
            Ok(ExplainReport {
                workspace: workspace.to_path_buf(),
                kind: "recipe",
                runtime_layer: runtime_name.to_string(),
                layers,
                config: composed.value,
                origins: prov.into_origins(),
                dropped,
                relay: RelayPermission::read(dev_home),
            })
        }
    }
}

fn recipe_layers(
    dev_home: &DevHome,
    recipe: &Recipe,
    recipe_path: &Path,
    runtime_name: &str,
    include_base: bool,
) -> Vec<LayerRow> {
    let mut layers = Vec::new();
    let global = dev_home.global_template_config(&recipe.global_template);
    layers.push(LayerRow {
        id: LayerId::GlobalTemplate(recipe.global_template.clone()).to_string(),
        present: global.is_file(),
        path: global,
    });
    if include_base {
        let base = dev_home.base_config();
        layers.push(LayerRow {
            id: LayerId::Base.to_string(),
            present: base.is_file(),
            path: base,
        });
    }
    let runtime = dev_home.runtime_config(runtime_name);
    layers.push(LayerRow {
        id: LayerId::Runtime(runtime_name.to_string()).to_string(),
        present: runtime.is_file(),
        path: runtime,
    });
    for id in [LayerId::RecipeFeatures, LayerId::RecipeCustomizations] {
        layers.push(LayerRow {
            id: id.to_string(),
            present: true,
            path: recipe_path.to_path_buf(),
        });
    }
    layers
}

impl ExplainReport {
    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# effective config for {} ({} project, runtime layer: {})\n",
            self.workspace.display(),
            self.kind,
            self.runtime_layer
        ));
        out.push_str(
            "# this is the merge `dev up` uses; `dev config list` shows the project file alone\n",
        );
        out.push_str("# layers (lowest to highest priority):\n");
        for layer in &self.layers {
            out.push_str(&format!(
                "#   {:<24} {}{}\n",
                layer.id,
                layer.path.display(),
                if layer.present { "" } else { "   (absent)" }
            ));
        }
        for (path, layer) in self.sorted_origins() {
            let Some(value) = resolve_path(&self.config, path) else {
                continue; // replaced wholesale by a later layer, or selector-pruned
            };
            out.push_str(&format!("{path} = {value}  <- {layer}\n"));
        }
        for key in &self.dropped {
            out.push_str(&format!(
                "# dropped by selector precedence: {key} (the highest layer's image/build/compose choice wins)\n"
            ));
        }
        out.push_str(&self.render_relay());
        out.push_str(
            "# notes: ${...} variables are shown unexpanded (substitution happens per consumer at run time);\n\
             #        duplicate array entries stay credited to the first layer that contributed them;\n\
             #        `dev up --ports` applies after this merge.\n",
        );
        out
    }

    /// Whether the merged config asks for the relay, and which layer asked.
    /// The request does pass through the merge, so this origin is real.
    fn relay_requested(&self) -> bool {
        self.config
            .get("sshAgent")
            .and_then(|settings| settings.get("relay"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn relay_requested_by(&self) -> Option<&LayerId> {
        self.origins.get(RELAY_PROPERTY)
    }

    fn relay_effective(&self) -> bool {
        self.relay.allowed && self.relay_requested()
    }

    fn render_relay(&self) -> String {
        let allowed_by = if self.relay.allowed {
            format!("{} ({ALLOW_RELAY_PROPERTY})", self.relay.base.display())
        } else {
            format!(
                "not allowed ({} does not set {ALLOW_RELAY_PROPERTY})",
                self.relay.base.display()
            )
        };
        let requested_by = match (self.relay_requested(), self.relay_requested_by()) {
            (true, Some(layer)) => layer.to_string(),
            (true, None) => "requested, layer unrecorded".to_string(),
            (false, _) => "not requested".to_string(),
        };
        format!(
            "# ssh agent relay (decided outside the merge; the permission is read from the base \
             file alone):\n\
             #   allowed by     {allowed_by}\n\
             #   requested by   {requested_by}\n\
             #   effective      {}\n",
            if self.relay_effective() { "on" } else { "off" }
        )
    }

    /// Origin entries with array indexes in numeric order (`mounts[2]` before
    /// `mounts[10]`), where the map's plain string order would interleave them.
    fn sorted_origins(&self) -> Vec<(&String, &LayerId)> {
        let mut entries: Vec<(&String, &LayerId)> = self.origins.iter().collect();
        entries.sort_by_cached_key(|(path, _)| origin_sort_key(path));
        entries
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "workspace": self.workspace.display().to_string(),
            "kind": self.kind,
            "runtimeLayer": self.runtime_layer,
            "layers": self.layers.iter().map(|l| serde_json::json!({
                "id": l.id,
                "path": l.path.display().to_string(),
                "present": l.present,
            })).collect::<Vec<_>>(),
            "config": self.config,
            // serde_json's `preserve_order` feature keeps this insertion order
            // in the emitted JSON, so `--json` shows the same numeric array
            // ordering `render` does.
            "origins": self.sorted_origins().into_iter()
                .map(|(k, v)| (k.clone(), Value::String(v.to_string())))
                .collect::<serde_json::Map<_, _>>(),
            "dropped": self.dropped,
            "sshAgentRelay": {
                "allowedBy": self.relay.allowed.then(|| self.relay.base.display().to_string()),
                "requestedBy": self.relay_requested()
                    .then(|| self.relay_requested_by().map(LayerId::to_string))
                    .flatten(),
                "effective": self.relay_effective(),
            },
            "notes": [
                "variables-unexpanded",
                "duplicates-credited-to-first-contributing-layer",
                "cli-port-overrides-apply-after-merge",
            ],
        })
    }
}

/// An origin path split into its selector shape. `Provenance::set` call sites
/// in merge.rs render exactly these four shapes (`key`, `key.sub`,
/// `key[index]`, `key["quoted id"]`); parsing them once here keeps the sort
/// key and the config lookup from drifting apart.
enum OriginPath<'a> {
    Plain(&'a str),
    Sub(&'a str, &'a str),
    Index(&'a str, usize),
    Quoted(&'a str, &'a str),
}

fn parse_origin_path(path: &str) -> Option<OriginPath<'_>> {
    if let Some((key, rest)) = path.split_once('[') {
        let inner = rest.strip_suffix(']')?;
        if let Some(id) = inner.strip_prefix('"').and_then(|i| i.strip_suffix('"')) {
            return Some(OriginPath::Quoted(key, id));
        }
        return Some(OriginPath::Index(key, inner.parse().ok()?));
    }
    if let Some((key, sub)) = path.split_once('.') {
        return Some(OriginPath::Sub(key, sub));
    }
    Some(OriginPath::Plain(path))
}

/// Sort key that keeps array entries in numeric order (`mounts[2]` before
/// `mounts[10]`); every other shape keeps plain string order.
fn origin_sort_key(path: &str) -> (String, usize) {
    match parse_origin_path(path) {
        Some(OriginPath::Index(key, index)) => (key.to_string(), index),
        _ => (path.to_string(), 0),
    }
}

/// Look an origin path back up in the merged config.
fn resolve_path<'a>(config: &'a Value, path: &str) -> Option<&'a Value> {
    match parse_origin_path(path)? {
        OriginPath::Plain(key) => config.get(key),
        OriginPath::Sub(key, sub) => config.get(key)?.get(sub),
        OriginPath::Index(key, index) => config.get(key)?.get(index),
        OriginPath::Quoted(key, id) => config.get(key)?.get(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    /// A direct project reports the base layer beneath it, with per-value
    /// origins matching which file actually supplied each value.
    #[test]
    fn explain_reports_base_and_project_origins_for_a_direct_project() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(
            &dev_home.base_config(),
            r#"{"remoteUser": "vscode", "containerEnv": {"EDITOR": "vim"}}"#,
        );
        write(
            &workspace.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:24.04", "containerEnv": {"TERM": "xterm"}}"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", true).unwrap();

        assert_eq!(report.kind, "direct");
        assert_eq!(report.origins["image"], LayerId::Project);
        assert_eq!(report.origins["remoteUser"], LayerId::Base);
        assert_eq!(report.origins["containerEnv.EDITOR"], LayerId::Base);
        assert_eq!(report.origins["containerEnv.TERM"], LayerId::Project);
        assert!(report.dropped.is_empty());

        let rendered = report.render();
        assert!(
            rendered.contains("remoteUser = \"vscode\"  <- base"),
            "{rendered}"
        );
    }

    /// The relay consent gets its own block because the permission never
    /// passes through the merge: `Provenance` has no honest origin for it,
    /// and inventing a `base` one would be the same lie the probed bits of
    /// `HostAccess` exist to prevent. The request does merge, so that half
    /// is credited to a real layer.
    #[test]
    fn explain_reports_the_relay_consent_outside_the_merged_keys() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(
            &dev_home.base_config(),
            r#"{"sshAgent": {"allowRelay": true}}"#,
        );
        write(
            &workspace.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:24.04", "sshAgent": {"relay": true}}"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", true).unwrap();
        let rendered = report.render();

        assert_eq!(report.origins["sshAgent.relay"], LayerId::Project);
        assert!(
            rendered.contains(&format!(
                "allowed by     {}",
                dev_home.base_config().display()
            )),
            "{rendered}"
        );
        assert!(rendered.contains("requested by   project"), "{rendered}");
        assert!(rendered.contains("effective      on"), "{rendered}");
        assert_eq!(report.to_json()["sshAgentRelay"]["effective"], true);
    }

    /// A project writing `allowRelay` into its own config puts the key in the
    /// merged document, where it is reported as the merged key it is — and
    /// the block still says not allowed, because the block reads the base
    /// file and not the merge. A block sourced from the merged value would
    /// read this project's own key as its permission.
    #[test]
    fn explain_reports_a_relay_request_the_base_did_not_allow() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(&dev_home.base_config(), r#"{"remoteUser": "vscode"}"#);
        write(
            &workspace.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:24.04", "sshAgent": {"relay": true, "allowRelay": true}}"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", true).unwrap();
        let rendered = report.render();

        assert_eq!(
            report.origins["sshAgent.allowRelay"],
            LayerId::Project,
            "the merged document is reported as it is"
        );
        assert!(
            rendered.contains(&format!(
                "not allowed ({} does not set sshAgent.allowRelay)",
                dev_home.base_config().display()
            )),
            "{rendered}"
        );
        assert!(rendered.contains("effective      off"), "{rendered}");
        assert_eq!(report.to_json()["sshAgentRelay"]["allowedBy"], Value::Null);
        assert_eq!(
            report.to_json()["sshAgentRelay"]["requestedBy"],
            "project",
            "the user should still see that the project asked"
        );
    }

    #[test]
    fn explain_reports_cmux_sub_key_origins() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(&dev_home.base_config(), r#"{"cmux": {"status": true}}"#);
        write(
            &workspace.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:24.04", "cmux": {"agent": false}}"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", true).unwrap();

        assert_eq!(report.origins["cmux.status"], LayerId::Base);
        assert_eq!(report.origins["cmux.agent"], LayerId::Project);
        assert_eq!(report.config["cmux"]["status"], true);
    }

    /// A base-layer selector losing to the project's is reported as dropped,
    /// not silently absent.
    #[test]
    fn explain_reports_selector_precedence_drops() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(&dev_home.base_config(), r#"{"image": "ubuntu:24.04"}"#);
        write(
            &workspace.path().join(".devcontainer/devcontainer.json"),
            r#"{"build": {"dockerfile": "Dockerfile"}}"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", true).unwrap();

        assert_eq!(report.dropped, ["image"]);
        assert!(report.config.get("image").is_none());
        assert!(
            report
                .render()
                .contains("dropped by selector precedence: image")
        );
    }

    /// `--no-base` reports project-only origins and no base layer row.
    #[test]
    fn explain_without_base_reports_project_only() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(&dev_home.base_config(), r#"{"remoteUser": "vscode"}"#);
        write(
            &workspace.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:24.04"}"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", false).unwrap();

        assert!(!report.origins.contains_key("remoteUser"));
        assert!(report.layers.iter().all(|l| l.id != "base"));
    }

    /// `explain` on a single-file target has no layers to attribute; base and
    /// global config reject it with guidance instead of showing nonsense.
    #[tokio::test]
    async fn explain_on_base_or_global_targets_is_rejected_with_guidance() {
        let home = TempDir::new().unwrap();
        let config = home.path().join("devcontainer.json");
        fs::write(&config, "{}").unwrap();
        let action = Some(crate::cli::ConfigAction::Explain {
            json: false,
            no_base: false,
        });

        let err = crate::commands::config::run_base(&config, action, 0)
            .await
            .expect_err("base config has no layered origins to explain");
        assert!(
            format!("{err}").contains("workspace-scoped"),
            "the refusal must point at `dev config explain`: {err}"
        );
    }

    /// A recipe project reports all five origins: template, base, runtime,
    /// recipe-injected features, and customizations.
    #[test]
    fn explain_json_shape_for_a_recipe_project() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let dev_home = DevHome::at(home.path());
        write(
            &dev_home.global_template_config("rust-dev"),
            r#"{"image": "mcr.microsoft.com/devcontainers/rust:1"}"#,
        );
        write(&dev_home.base_config(), r#"{"remoteUser": "vscode"}"#);
        write(
            &dev_home.runtime_config("docker"),
            r#"{"containerEnv": {"RUNTIME": "docker"}}"#,
        );
        write(
            &workspace.path().join(".devcontainer/recipe.json"),
            r#"{
                "globalTemplate": "rust-dev",
                "features": ["ghcr.io/devcontainers/features/node:1"],
                "customizations": {"postCreateCommand": {"setup": "cargo fetch"}}
            }"#,
        );

        let report = explain(&dev_home, workspace.path(), "docker", true).unwrap();
        assert_eq!(report.kind, "recipe");
        assert_eq!(
            report.origins["image"],
            LayerId::GlobalTemplate("rust-dev".into())
        );
        assert_eq!(report.origins["remoteUser"], LayerId::Base);
        assert_eq!(
            report.origins["containerEnv.RUNTIME"],
            LayerId::Runtime("docker".into())
        );
        assert_eq!(
            report.origins["features[\"ghcr.io/devcontainers/features/node:1\"]"],
            LayerId::RecipeFeatures
        );
        assert_eq!(
            report.origins["postCreateCommand.setup"],
            LayerId::RecipeCustomizations
        );

        let json = report.to_json();
        assert_eq!(json["kind"], "recipe");
        assert_eq!(json["origins"]["remoteUser"], "base");
        assert_eq!(
            json["origins"]["postCreateCommand.setup"],
            "recipe-customizations"
        );
        assert_eq!(json["layers"].as_array().unwrap().len(), 5);
    }

    /// `--json` origins follow the same numeric array ordering `render` uses;
    /// serde_json's `preserve_order` keeps the map's insertion order on output.
    #[test]
    fn json_origins_keep_numeric_array_order() {
        let mut origins = BTreeMap::new();
        for i in [0, 1, 2, 10, 11] {
            origins.insert(format!("mounts[{i}]"), LayerId::Project);
        }
        let report = ExplainReport {
            workspace: PathBuf::from("/ws"),
            kind: "direct",
            runtime_layer: "docker".to_string(),
            layers: vec![],
            config: serde_json::json!({}),
            origins,
            dropped: vec![],
            relay: RelayPermission::read(&DevHome::at("/nonexistent")),
        };
        let keys: Vec<String> = report.to_json()["origins"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            [
                "mounts[0]",
                "mounts[1]",
                "mounts[2]",
                "mounts[10]",
                "mounts[11]"
            ]
        );
    }
}
