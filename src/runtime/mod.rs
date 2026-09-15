#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod apple;
pub mod compose;
pub mod docker;
#[cfg(test)]
pub(crate) mod fake_daemon;
pub mod host_access;
pub mod paste_bridge;
pub mod podman;
pub mod terminal_input;
pub mod terminal_relay;
#[cfg(test)]
pub(crate) mod test_peer;

pub use host_access::HostAccess;

use crate::error::DevError;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::devcontainer::jsonc::parse_jsonc;
use crate::devcontainer::secrets::SecretValue;
use crate::runtime::terminal_relay::UnitFut;
use crate::util::paths::DevHome;

pub(crate) const DEFAULT_RUNTIME_PROPERTY: &str = "defaultRuntime";
pub(crate) const ACCEPTED_RUNTIME_VALUES: &str = "docker, podman, apple";
pub(crate) const DOCKER_SOCKET_PROPERTY: &str = "dockerSocket";
/// The base config's grant for the SSH agent relay. Deliberately a different
/// key from the `sshAgent.relay` a project asks with: one key meaning both
/// "may" and "will" is what let a cloned repository turn the relay on for
/// itself.
pub(crate) const ALLOW_RELAY_PROPERTY: &str = "sshAgent.allowRelay";
/// The key a project asks with, named here so the messages about the pair and
/// the base-layer refusal spell it the same way.
pub(crate) const RELAY_PROPERTY: &str = "sshAgent.relay";

/// Everything docker socket discovery reads from outside the process, so a
/// test never depends on the machine running it (its real `DOCKER_HOST`,
/// home directory, or a stray `/var/run/docker.sock`).
pub(crate) struct SocketEnv {
    pub(crate) docker_host: Option<String>,
    pub(crate) home: Option<PathBuf>,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
    pub(crate) system_socket: PathBuf,
}

impl SocketEnv {
    pub(crate) fn current() -> Self {
        Self {
            // An exported-but-empty value names no daemon; docker's own CLI
            // treats it as unset and so does this.
            docker_host: std::env::var("DOCKER_HOST")
                .ok()
                .filter(|host| !host.is_empty()),
            home: dirs::home_dir(),
            xdg_runtime_dir: std::env::var("XDG_RUNTIME_DIR").ok().map(PathBuf::from),
            system_socket: PathBuf::from("/var/run/docker.sock"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeName {
    Docker,
    Podman,
    Apple,
}

impl RuntimeName {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "docker" => Some(Self::Docker),
            "podman" => Some(Self::Podman),
            "apple" => Some(Self::Apple),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Apple => "apple",
        }
    }
}

impl std::fmt::Display for RuntimeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeSelection {
    Explicit(RuntimeName),
    Configured(RuntimeName),
    Auto,
}

/// Container state as reported by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ContainerState {
    Running,
    Stopped,
    NotFound,
}

/// Configuration for creating a new container.
#[derive(Clone)]
pub struct ContainerConfig {
    pub image: String,
    pub name: String,
    pub labels: HashMap<String, String>,
    pub env: HashMap<String, String>,
    pub mounts: Vec<BindMount>,
    pub volumes: Vec<VolumeMount>,
    pub tmpfs: Vec<TmpfsMount>,
    pub ports: Vec<PortMapping>,
    pub workspace_mount: Option<WorkspaceMount>,
    /// Resolved `workspaceFolder`: where commands run inside the container.
    /// Equal to the workspace mount target unless the config selects a
    /// subdirectory of it.
    pub workspace_folder: Option<String>,
    /// Leftover raw `runArgs` after variable substitution. Now always empty:
    /// the supported subset of `runArgs` is translated into create-time fields
    /// by `devcontainer::run_args` before container creation, and every other
    /// flag is rejected (issue #5 — `runArgs` used to be silently dropped).
    /// Retained so the struct stays a plain data bag the runtime tests build.
    #[allow(dead_code)]
    pub extra_args: Vec<String>,
    /// Exec-form entrypoint argv. Feature entrypoints are `exec "$@"` wrappers,
    /// so multiple entries chain: each wrapper execs the remainder as its args.
    pub entrypoint: Option<Vec<String>>,
    /// Run an init process inside the container (--init).
    pub init: bool,
    /// Run the container in privileged mode (--privileged).
    pub privileged: bool,
    /// Additional Linux capabilities to add (--cap-add).
    pub cap_add: Vec<String>,
    /// Security options (--security-opt).
    pub security_opt: Vec<String>,
    /// User namespace mode (--userns).
    pub userns_mode: Option<String>,
    /// Extra `/etc/hosts` entries in Docker's `host:ip` form.
    pub extra_hosts: Vec<String>,
}

/// Wraps the env map so `ContainerConfig`'s `Debug` prints keys without values.
/// Values may be resolved secrets; see the secrets design doc's security rules.
struct RedactedValues<'a>(&'a HashMap<String, String>);

impl std::fmt::Debug for RedactedValues<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, "***")))
            .finish()
    }
}

/// Hand-written so env values never reach a log or a panic message. Adding a
/// field to `ContainerConfig` means adding it here too — the compiler will not
/// tell you.
impl std::fmt::Debug for ContainerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerConfig")
            .field("image", &self.image)
            .field("name", &self.name)
            .field("labels", &self.labels)
            .field("env", &RedactedValues(&self.env))
            .field("mounts", &self.mounts)
            .field("volumes", &self.volumes)
            .field("tmpfs", &self.tmpfs)
            .field("ports", &self.ports)
            .field("workspace_mount", &self.workspace_mount)
            .field("workspace_folder", &self.workspace_folder)
            .field("extra_args", &self.extra_args)
            .field("entrypoint", &self.entrypoint)
            .field("init", &self.init)
            .field("privileged", &self.privileged)
            .field("cap_add", &self.cap_add)
            .field("security_opt", &self.security_opt)
            .field("userns_mode", &self.userns_mode)
            .field("extra_hosts", &self.extra_hosts)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: String,
    pub readonly: bool,
}

/// A named Docker volume mounted into the container.
#[derive(Debug, Clone)]
pub struct VolumeMount {
    pub name: String,
    pub target: String,
    pub readonly: bool,
}

/// A tmpfs mounted into the container; no host-side source. `size` and `mode`
/// are passed to the runtime verbatim (`tmpfs-size` / `tmpfs-mode` values).
#[derive(Debug, Clone)]
pub struct TmpfsMount {
    pub target: String,
    pub size: Option<String>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub host: u16,
    pub container: u16,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMount {
    pub source: PathBuf,
    pub target: String,
}

/// Metadata about an existing container.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub state: ContainerState,
    pub labels: HashMap<String, String>,
    pub image: String,
}

/// A locally stored image: the tags that reference it.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Daemon image ID (`sha256:...`); the only handle a dangling image has.
    pub id: String,
    pub repo_tags: Vec<String>,
    pub labels: HashMap<String, String>,
}

/// Result of a non-interactive exec command.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Metadata extracted from a container image's labels and config.
#[derive(Debug, Clone, Default)]
pub struct ImageMetadata {
    pub remote_user: Option<String>,
    pub container_user: Option<String>,
    /// Raw `devcontainer.metadata` label entries, in label order. Empty when the label
    /// is absent or unparseable. Retained so callers can recover settings contributed by
    /// the features that built an image without re-resolving those features.
    pub metadata_entries: Vec<serde_json::Value>,
    /// Environment variables from the OCI image config (`Env` field).
    #[allow(dead_code)]
    pub env: Vec<String>,
}

/// Handle to a running exec session with attached stdin/stdout byte streams.
pub struct AttachedExec {
    pub stdin: Pin<Box<dyn AsyncWrite + Send>>,
    pub stdout: Pin<Box<dyn AsyncRead + Send>>,
}

/// A boxed future that is Send.
pub(crate) type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DevError>> + Send + 'a>>;

/// Render exec env pairs as the `KEY=VALUE` strings every runtime's wire
/// format wants. The result holds raw secret material: it goes straight to
/// the daemon and is never logged or formatted.
pub(crate) fn env_assignments(env: &[(String, SecretValue)]) -> Vec<String> {
    env.iter()
        .map(|(key, value)| format!("{key}={}", value.expose()))
        .collect()
}

/// Current terminal size as (columns, rows), or None when stdout is not a tty.
pub(crate) fn terminal_size() -> Option<(u16, u16)> {
    use std::os::fd::AsRawFd;
    let fd = std::io::stdout().as_raw_fd();
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 && ws.ws_row > 0
    {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
}

/// Trait abstracting over container runtimes (Docker, Podman, Apple Containers).
#[allow(dead_code)]
pub trait ContainerRuntime: Send + Sync {
    /// Short name identifying this runtime (e.g. "docker", "podman", "apple").
    fn runtime_name(&self) -> &'static str;

    fn pull_image(&self, image: &str) -> BoxFut<'_, ()>;

    fn build_image(
        &self,
        dockerfile: &str,
        context: &Path,
        tag: &str,
        build_args: &HashMap<String, String>,
        no_cache: bool,
        verbose: bool,
    ) -> BoxFut<'_, ()>;

    fn create_container(&self, config: &ContainerConfig) -> BoxFut<'_, String>;

    fn start_container(&self, id: &str) -> BoxFut<'_, ()>;

    fn stop_container(&self, id: &str) -> BoxFut<'_, ()>;

    fn remove_container(&self, id: &str) -> BoxFut<'_, ()>;

    /// Run a command inside the container.
    ///
    /// `workdir` is for callers that have a command-scoped directory such as
    /// the resolved devcontainer `workspaceFolder`. Leaving it unset preserves
    /// runtime inheritance for commands with their own target semantics.
    ///
    /// `env` applies to this exec alone. It does not change the container's own
    /// environment, so nothing started outside this command sees it.
    fn exec(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
        env: &[(String, SecretValue)],
    ) -> BoxFut<'_, ExecResult>;

    /// Whether an [`Self::exec`] failure means the image has no such
    /// executable, rather than the runtime being unable to run one at all.
    ///
    /// Only the runtime knows the difference, because only it knows which of
    /// its own failures can carry that meaning: docker declines to start the
    /// exec and answers with a server error, while Apple's daemon fails the
    /// start step. Callers use this to tell an image without a shell — which is
    /// the image's business — from a container they cannot run anything in.
    ///
    /// A process that ran and exited is not this: whatever status it reported,
    /// the runtime created, started and waited for it. Implementations must
    /// answer `false` for anything they cannot attribute to the command itself,
    /// so a transport, start or wait failure stays fatal to readiness.
    fn exec_reports_missing_command(&self, _error: &DevError) -> bool {
        false
    }

    /// Run a command attached to the caller's terminal, returning its exit code
    /// once it finishes. `workdir` and `env` have the same meaning as on
    /// [`Self::exec`].
    fn exec_interactive(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
        env: &[(String, SecretValue)],
    ) -> BoxFut<'_, i32>;

    /// Write `bytes` to `target` inside the container, creating its parent
    /// directory. The file lands non-executable; a caller that needs it to run
    /// follows with a `chmod`.
    ///
    /// The default declines, so a runtime with no copy channel stays honest
    /// rather than reporting a write that never happened.
    fn copy_in<'a>(
        &'a self,
        _id: &'a str,
        _user: Option<&'a str>,
        _bytes: Vec<u8>,
        _target: &'a str,
    ) -> BoxFut<'a, ()> {
        let name = self.runtime_name();
        Box::pin(async move {
            Err(DevError::Runtime(format!(
                "copying a file in is not supported by the {name} runtime"
            )))
        })
    }

    fn inspect_container(&self, id: &str) -> BoxFut<'_, ContainerInfo>;

    fn list_containers(&self, label_filters: &[String]) -> BoxFut<'_, Vec<ContainerInfo>>;

    fn image_exists(&self, image: &str) -> BoxFut<'_, bool>;

    fn inspect_image_metadata(&self, image: &str) -> BoxFut<'_, ImageMetadata>;

    /// Create an exec session with attached stdin/stdout streams (no TTY).
    /// Used for port forwarding via netcat inside the container.
    fn exec_attached(
        &self,
        id: &str,
        cmd: &[String],
        user: Option<&str>,
    ) -> BoxFut<'_, AttachedExec>;

    /// Read a container's log stream (stdout and stderr interleaved). `tail`
    /// limits output to the last N lines; `follow` keeps the stream open.
    ///
    /// The default declines, so runtimes without a log channel stay honest.
    fn container_logs(
        &self,
        _id: &str,
        _follow: bool,
        _tail: Option<u32>,
    ) -> BoxFut<'_, Box<dyn AsyncRead + Send + Unpin>> {
        let name = self.runtime_name();
        Box::pin(async move {
            Err(DevError::Runtime(format!(
                "container logs are not supported by the {name} runtime"
            )))
        })
    }

    /// Every locally stored image. Callers filter by tag prefix in code —
    /// docker and podman `reference` filter syntaxes differ, prefix matching
    /// here is portable.
    fn list_images(&self) -> BoxFut<'_, Vec<ImageInfo>> {
        let name = self.runtime_name();
        Box::pin(async move {
            Err(DevError::Runtime(format!(
                "listing images is not supported by the {name} runtime"
            )))
        })
    }

    /// Remove one image by tag or id. Not forced: an in-use conflict is the
    /// daemon's report to surface, not to override.
    fn remove_image(&self, _image: &str) -> BoxFut<'_, ()> {
        let name = self.runtime_name();
        Box::pin(async move {
            Err(DevError::Runtime(format!(
                "removing images is not supported by the {name} runtime"
            )))
        })
    }

    /// The docker-API socket this runtime is connected to, when it has one.
    ///
    /// The default declines, so a runtime that does not speak over a bollard
    /// client stays honest instead of reporting a path nothing was ever
    /// connected to. Overridden by the bollard-backed runtimes, which is what
    /// lets flavor detection tell one docker-API daemon from another.
    fn socket_path(&self) -> Option<&str> {
        None
    }

    /// What a runtime with no host-access story promises: nothing, and no
    /// behavior change.
    fn host_access(&self) -> HostAccess {
        HostAccess::unknown()
    }

    /// Probe this runtime's daemon once and cache what it reports, so a later
    /// `host_access()` call can answer synchronously. Detection cannot fail
    /// and its caller has nothing to handle; the default no-op is what a
    /// runtime with no daemon to probe takes.
    fn detect_host_access(&self) -> UnitFut<'_> {
        Box::pin(async {})
    }

    /// The daemon's own version string, once detection has run and it
    /// reported one.
    fn daemon_version(&self) -> Option<&str> {
        None
    }
}

/// Resolve the effective remote user by checking the devcontainer config first,
/// then falling back to the image's embedded metadata.
pub async fn resolve_remote_user(
    runtime: &dyn ContainerRuntime,
    image: &str,
    config_user: Option<&str>,
) -> Result<Option<String>, DevError> {
    if let Some(u) = config_user {
        return Ok(Some(u.to_string()));
    }
    let meta = runtime.inspect_image_metadata(image).await?;
    Ok(meta.remote_user.or(meta.container_user))
}

/// Detect which container runtime is available, or use an explicit override.
pub async fn detect_runtime(
    override_runtime: Option<&str>,
) -> Result<Box<dyn ContainerRuntime>, DevError> {
    let base = BaseConfig::read(&DevHome::current());
    let selection = select_runtime(&base, override_runtime)?;
    let runtime = match selection {
        RuntimeSelection::Explicit(name) => connect_explicit_runtime(&base, name).await,
        RuntimeSelection::Configured(name) => connect_configured_runtime(&base, name).await,
        RuntimeSelection::Auto => detect_auto_runtime(&base).await,
    }?;
    // Every selection path returns through this match, so this is the one
    // place that has already pinged the winning daemon and not a losing
    // candidate `detect_auto_runtime` tried and discarded.
    runtime.detect_host_access().await;
    Ok(runtime)
}

/// `~/.dev/base/devcontainer.json`, read and parsed once per command rather
/// than once per key. A missing, unreadable or unparseable file reads as "no
/// value", loudly in the unparseable case; only a present-but-wrong-typed key
/// is the caller's problem to reject.
struct BaseConfig {
    path: PathBuf,
    json: Option<serde_json::Value>,
}

impl BaseConfig {
    fn read(dev_home: &DevHome) -> Self {
        let path = dev_home.base_config();
        let json = fs::read_to_string(&path).ok().and_then(|raw| {
            match parse_jsonc::<serde_json::Value>(&raw) {
                Ok(value) => Some(value),
                Err(e) => {
                    // Every preference here reads as absent when the file does
                    // not parse, and `sshAgent.allowRelay` reading as absent is
                    // a capability silently withdrawn.
                    eprintln!(
                        "Warning: {} does not parse ({e}), so every preference it sets is being \
                         ignored, including any {ALLOW_RELAY_PROPERTY} grant.",
                        path.display()
                    );
                    None
                }
            }
        });
        Self { path, json }
    }

    /// The value at a dotted path, so a nested preference is addressed by the
    /// same string `dev base config set` and the messages about it use.
    fn value(&self, property: &str) -> Option<&serde_json::Value> {
        let mut current = self.json.as_ref()?;
        for segment in property.split('.') {
            current = current.get(segment)?;
        }
        Some(current)
    }
}

/// Whether the user's own base config permits a project to ask for the SSH
/// agent relay.
///
/// Read from `~/.dev/base/devcontainer.json` alone, never from the merged
/// config: a project layer can write any key it likes into the merge, and
/// this is the one key it must not be able to write. `--no-base` does not
/// reach it, for the same reason it does not reach `defaultRuntime` — it
/// skips base devcontainer content, not `dev`'s own preferences.
pub(crate) fn ssh_agent_relay_allowed_in(dev_home: &DevHome) -> bool {
    BaseConfig::read(dev_home)
        .value(ALLOW_RELAY_PROPERTY)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// The `&DevHome` seam the tests drive; production reads the base config once
/// and calls [`select_runtime`] with it.
#[cfg(test)]
pub(crate) fn select_runtime_in(
    dev_home: &DevHome,
    override_runtime: Option<&str>,
) -> Result<RuntimeSelection, DevError> {
    select_runtime(&BaseConfig::read(dev_home), override_runtime)
}

fn select_runtime(
    base: &BaseConfig,
    override_runtime: Option<&str>,
) -> Result<RuntimeSelection, DevError> {
    if let Some(name) = override_runtime {
        return RuntimeName::parse(name)
            .map(RuntimeSelection::Explicit)
            .ok_or_else(|| DevError::Runtime(format!("Unknown runtime: {name}")));
    }

    let Some(value) = base.value(DEFAULT_RUNTIME_PROPERTY) else {
        return Ok(RuntimeSelection::Auto);
    };
    let Some(value) = value.as_str() else {
        return Err(DevError::InvalidConfig(format!(
            "{DEFAULT_RUNTIME_PROPERTY} in {} must be a string. Accepted values: {ACCEPTED_RUNTIME_VALUES}. \
             Run `dev base config set {DEFAULT_RUNTIME_PROPERTY} <value>` to change it or \
             `dev base config unset {DEFAULT_RUNTIME_PROPERTY}` to return to automatic detection.",
            base.path.display()
        )));
    };

    RuntimeName::parse(value)
        .map(RuntimeSelection::Configured)
        .ok_or_else(|| invalid_configured_runtime_error(value, &base.path))
}

/// Docker-API sockets to check when no `dockerSocket` pin narrows the search,
/// unfiltered by existence. Shared between the real candidate list and the
/// "nothing answered" error, which names every location it would have
/// checked even when none of them exist.
fn default_docker_socket_locations(env: &SocketEnv) -> Vec<PathBuf> {
    let mut locations = Vec::new();
    if let Some(rest) = env
        .docker_host
        .as_deref()
        .and_then(|host| host.strip_prefix("unix://"))
    {
        locations.push(PathBuf::from(rest));
    }
    locations.push(env.system_socket.clone());
    if let Some(home) = &env.home {
        // The flavor-specific paths come first because OrbStack populates
        // `~/.docker/run/docker.sock` as well as its own, and connecting
        // through the generic path leaves `detect_flavor_from_socket_path`
        // reading an OrbStack daemon as Docker Desktop.
        locations.push(home.join(".orbstack/run/docker.sock"));
        locations.push(home.join(".colima/default/docker.sock"));
        locations.push(home.join(".docker/run/docker.sock"));
    }
    if let Some(xdg) = &env.xdg_runtime_dir {
        locations.push(xdg.join("docker.sock"));
    }
    locations
}

/// The `&DevHome` seam the tests drive; production reads the base config once
/// and calls [`docker_socket_candidates`] with it.
#[cfg(test)]
pub(crate) fn docker_socket_candidates_in(
    dev_home: &DevHome,
    env: &SocketEnv,
) -> Result<Vec<PathBuf>, DevError> {
    docker_socket_candidates(&BaseConfig::read(dev_home), env)
}

/// The docker-API sockets to try, in order: a pinned `dockerSocket` is
/// exclusive when present, because an explicit choice that silently resolves
/// elsewhere is worse than a failure the user then debugs against the wrong
/// daemon. Otherwise every default location that exists, deduplicated
/// keeping the first occurrence.
fn docker_socket_candidates(base: &BaseConfig, env: &SocketEnv) -> Result<Vec<PathBuf>, DevError> {
    if let Some(value) = base.value(DOCKER_SOCKET_PROPERTY) {
        return pinned_docker_socket(value, &base.path).map(|path| vec![path]);
    }

    let mut seen = HashSet::new();
    Ok(default_docker_socket_locations(env)
        .into_iter()
        .filter(|path| path.exists() && seen.insert(path.clone()))
        .collect())
}

/// Validate a pinned `dockerSocket` value and confirm the socket exists.
/// Paths are used verbatim — no tilde expansion — so anything not already
/// absolute can only ever fail to exist.
fn pinned_docker_socket(value: &serde_json::Value, base_path: &Path) -> Result<PathBuf, DevError> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid_docker_socket_error(&value.to_string(), base_path))?;
    if !text.starts_with('/') {
        return Err(invalid_docker_socket_error(text, base_path));
    }
    let path = PathBuf::from(text);
    if !path.exists() {
        return Err(missing_docker_socket_error(text, base_path));
    }
    Ok(path)
}

fn invalid_docker_socket_error(value: &str, base_path: &Path) -> DevError {
    DevError::InvalidConfig(format!(
        "{DOCKER_SOCKET_PROPERTY} in {} must be an absolute path: '{value}'. \
         Run `dev base config set {DOCKER_SOCKET_PROPERTY} <path>` to change it or \
         `dev base config unset {DOCKER_SOCKET_PROPERTY}` to return to automatic detection.",
        base_path.display()
    ))
}

fn missing_docker_socket_error(path: &str, base_path: &Path) -> DevError {
    DevError::NoRuntime(format!(
        "{DOCKER_SOCKET_PROPERTY} in {} is set to '{path}', but that socket does not exist.\n\n\
         Run `dev base config set {DOCKER_SOCKET_PROPERTY} <path>` to change it or \
         `dev base config unset {DOCKER_SOCKET_PROPERTY}` to return to automatic detection.",
        base_path.display()
    ))
}

/// The ping is bounded: a socket that accepts and never answers would
/// otherwise hold the user for bollard's own 120s client timeout, once per
/// candidate.
async fn try_docker_socket(path: &Path) -> Result<docker::DockerRuntime, String> {
    let socket = path.to_string_lossy();
    let rt = docker::DockerRuntime::connect_to_socket(&socket).map_err(|e| e.to_string())?;
    match tokio::time::timeout(host_access::HOST_DETECT_BUDGET, rt.ping()).await {
        Ok(Ok(())) => Ok(rt),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "no answer within {:.0}s",
            host_access::HOST_DETECT_BUDGET.as_secs_f64()
        )),
    }
}

async fn connect_first_answering_docker_socket(
    candidates: &[PathBuf],
    env: &SocketEnv,
) -> Result<docker::DockerRuntime, DevError> {
    let mut last_failure = None;
    for candidate in candidates {
        match try_docker_socket(candidate).await {
            Ok(rt) => return Ok(rt),
            Err(reason) => last_failure = Some(reason),
        }
    }
    Err(no_docker_socket_answered_error(
        candidates,
        env,
        last_failure,
    ))
}

/// Why a `DOCKER_HOST` contributed no candidate, or `None` when it did.
/// Either it names a scheme this connect path cannot speak, or it names a
/// unix path with no socket at it — a typo there otherwise drops out at the
/// `path.exists()` filter and leaves the user on whichever other daemon
/// answered, with nothing said.
fn ignored_docker_host_note(docker_host: &str) -> Option<String> {
    let Some(path) = docker_host.strip_prefix("unix://") else {
        return Some(format!(
            "DOCKER_HOST is set to '{docker_host}', which this connect path ignores (it speaks unix sockets only)."
        ));
    };
    if Path::new(path).exists() {
        return None;
    }
    Some(format!(
        "DOCKER_HOST names '{path}', but no socket exists there, so it was skipped."
    ))
}

/// Nothing answered a ping on any candidate socket. Lists every path tried
/// (or, with no candidates, every location that would have been checked),
/// the last connection failure, and a `dockerSocket` pin as the way forward.
fn no_docker_socket_answered_error(
    candidates: &[PathBuf],
    env: &SocketEnv,
    last_failure: Option<String>,
) -> DevError {
    let tried = if candidates.is_empty() {
        let checked: Vec<String> = default_docker_socket_locations(env)
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        format!(
            "No docker socket exists at any of the checked locations: {}.",
            checked.join(", ")
        )
    } else {
        let list: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
        format!("Tried: {}.", list.join(", "))
    };
    let reason = last_failure
        .map(|r| format!(" Last failure: {r}."))
        .unwrap_or_default();

    let mut sections = vec![format!("No docker daemon answered a ping.{reason}"), tried];
    if let Some(note) = env
        .docker_host
        .as_deref()
        .and_then(ignored_docker_host_note)
    {
        sections.push(note);
    }
    sections.push(format!(
        "Start your Docker daemon (Docker Desktop, OrbStack, Colima or Engine), or run \
         `dev base config set {DOCKER_SOCKET_PROPERTY} <path>` to pin one."
    ));
    sections.push("Then try `dev <subcommand>` again.".to_string());

    DevError::NoRuntime(sections.join("\n\n"))
}

/// The pinned socket exists but nothing answered on it. Distinct from
/// [`no_docker_socket_answered_error`], which advises pinning a socket —
/// advice this user has already taken.
fn pinned_docker_socket_never_answered_error(
    path: &Path,
    base_path: &Path,
    reason: &str,
) -> DevError {
    DevError::NoRuntime(format!(
        "{DOCKER_SOCKET_PROPERTY} in {} pins '{}', but no docker daemon answered a ping there: {reason}\n\n\
         Start the daemon that owns that socket, or run \
         `dev base config set {DOCKER_SOCKET_PROPERTY} <path>` to pin a different one or \
         `dev base config unset {DOCKER_SOCKET_PROPERTY}` to return to automatic detection.\n\n\
         Then try `dev <subcommand>` again.",
        base_path.display(),
        path.display()
    ))
}

async fn connect_docker_runtime_in(
    base: &BaseConfig,
    env: &SocketEnv,
) -> Result<docker::DockerRuntime, DevError> {
    let candidates = docker_socket_candidates(base, env)?;
    if let (Some(_), Some(pinned)) = (base.value(DOCKER_SOCKET_PROPERTY), candidates.first()) {
        return try_docker_socket(pinned).await.map_err(|reason| {
            pinned_docker_socket_never_answered_error(pinned, &base.path, &reason)
        });
    }
    let runtime = connect_first_answering_docker_socket(&candidates, env).await?;
    if let Some(note) = env
        .docker_host
        .as_deref()
        .and_then(ignored_docker_host_note)
    {
        eprintln!("Warning: {note}");
    }
    Ok(runtime)
}

async fn connect_docker_runtime(base: &BaseConfig) -> Result<docker::DockerRuntime, DevError> {
    connect_docker_runtime_in(base, &SocketEnv::current()).await
}

/// `--runtime docker` failing gets the same actionable-error treatment as a
/// configured default, naming the flag rather than `defaultRuntime` since
/// nothing here came from base config.
fn explicit_docker_runtime_unavailable_error(err: DevError) -> DevError {
    DevError::NoRuntime(format!(
        "--runtime docker is unavailable on this host: {err}\n\n\
         Start your Docker daemon (Docker Desktop, OrbStack, Colima or Engine).\n\n\
         Then try `dev <subcommand>` again."
    ))
}

/// Connecting only builds a client, so the ping is what says a daemon is
/// there at all.
async fn connect_podman_runtime() -> Result<podman::PodmanRuntime, DevError> {
    podman_answering_a_ping(podman::PodmanRuntime::connect()?).await
}

/// Bounded for the same reason [`try_docker_socket`] is: a socket that
/// accepts and never answers would otherwise hold the user for bollard's own
/// 120s client timeout.
async fn podman_answering_a_ping(
    rt: podman::PodmanRuntime,
) -> Result<podman::PodmanRuntime, DevError> {
    match tokio::time::timeout(host_access::HOST_DETECT_BUDGET, rt.ping()).await {
        Ok(Ok(())) => Ok(rt),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(DevError::NoRuntime(format!(
            "the podman socket accepted a connection but answered no ping within {:.0}s",
            host_access::HOST_DETECT_BUDGET.as_secs_f64()
        ))),
    }
}

async fn connect_explicit_runtime(
    base: &BaseConfig,
    runtime_name: RuntimeName,
) -> Result<Box<dyn ContainerRuntime>, DevError> {
    match runtime_name {
        RuntimeName::Docker => {
            let rt = connect_docker_runtime(base)
                .await
                .map_err(explicit_docker_runtime_unavailable_error)?;
            Ok(Box::new(rt))
        }
        RuntimeName::Podman => {
            let rt = connect_podman_runtime().await?;
            Ok(Box::new(rt))
        }
        RuntimeName::Apple => connect_explicit_apple_runtime().await,
    }
}

async fn connect_configured_runtime(
    base: &BaseConfig,
    runtime_name: RuntimeName,
) -> Result<Box<dyn ContainerRuntime>, DevError> {
    match runtime_name {
        RuntimeName::Docker => {
            let rt = connect_docker_runtime(base)
                .await
                .map_err(|err| configured_runtime_unavailable_error(runtime_name, err))?;
            Ok(Box::new(rt))
        }
        RuntimeName::Podman => {
            let rt = connect_podman_runtime()
                .await
                .map_err(|err| configured_runtime_unavailable_error(runtime_name, err))?;
            Ok(Box::new(rt))
        }
        RuntimeName::Apple => connect_configured_apple_runtime().await,
    }
}

#[cfg(all(target_os = "macos", feature = "apple"))]
async fn connect_explicit_apple_runtime() -> Result<Box<dyn ContainerRuntime>, DevError> {
    let rt = apple::AppleRuntime::connect()?;
    rt.ping().await?;
    Ok(Box::new(rt))
}

#[cfg(not(all(target_os = "macos", feature = "apple")))]
async fn connect_explicit_apple_runtime() -> Result<Box<dyn ContainerRuntime>, DevError> {
    Err(DevError::Runtime("Unknown runtime: apple".to_string()))
}

#[cfg(all(target_os = "macos", feature = "apple"))]
async fn connect_configured_apple_runtime() -> Result<Box<dyn ContainerRuntime>, DevError> {
    let rt = apple::AppleRuntime::connect()
        .map_err(|err| configured_runtime_unavailable_error(RuntimeName::Apple, err))?;
    rt.ping()
        .await
        .map_err(|err| configured_runtime_unavailable_error(RuntimeName::Apple, err))?;
    Ok(Box::new(rt))
}

#[cfg(not(all(target_os = "macos", feature = "apple")))]
async fn connect_configured_apple_runtime() -> Result<Box<dyn ContainerRuntime>, DevError> {
    Err(configured_runtime_not_compiled_error(RuntimeName::Apple))
}

fn invalid_configured_runtime_error(value: &str, path: &Path) -> DevError {
    DevError::InvalidConfig(format!(
        "Invalid {DEFAULT_RUNTIME_PROPERTY} value in {}: '{value}'. Accepted values: {ACCEPTED_RUNTIME_VALUES}. \
         Run `dev base config set {DEFAULT_RUNTIME_PROPERTY} <value>` to change it or \
         `dev base config unset {DEFAULT_RUNTIME_PROPERTY}` to return to automatic detection.",
        path.display()
    ))
}

fn configured_runtime_unavailable_error(runtime_name: RuntimeName, err: DevError) -> DevError {
    let remediation = match runtime_name {
        RuntimeName::Docker => {
            "Start your Docker daemon (Docker Desktop, OrbStack, Colima or Engine)"
        }
        RuntimeName::Podman => "Start Podman (`podman machine start` on macOS)",
        RuntimeName::Apple => "Start Apple Containers and make sure its service is running",
    };
    DevError::NoRuntime(format!(
        "Configured {DEFAULT_RUNTIME_PROPERTY} '{runtime_name}' is unavailable on this host: {err}\n\n\
         {remediation}, or run `dev base config set {DEFAULT_RUNTIME_PROPERTY} <docker|podman|apple>` \
         to choose another runtime. Run `dev base config unset {DEFAULT_RUNTIME_PROPERTY}` to return to automatic detection."
    ))
}

#[cfg(not(all(target_os = "macos", feature = "apple")))]
fn configured_runtime_not_compiled_error(runtime_name: RuntimeName) -> DevError {
    let detail = match runtime_name {
        RuntimeName::Apple => {
            "The Apple runtime requires a dev binary built on macOS with the apple feature."
        }
        RuntimeName::Docker | RuntimeName::Podman => {
            "This runtime is not available in the current dev binary."
        }
    };
    DevError::NoRuntime(format!(
        "Configured {DEFAULT_RUNTIME_PROPERTY} '{runtime_name}' is not available in this dev binary. {detail}\n\n\
         Run `dev base config set {DEFAULT_RUNTIME_PROPERTY} <docker|podman|apple>` to choose another runtime, \
         or `dev base config unset {DEFAULT_RUNTIME_PROPERTY}` to return to automatic detection."
    ))
}

/// The docker half of auto detection. A failure is normally non-fatal, so
/// podman still gets its turn, but a failure under a pinned `dockerSocket` is
/// carried back out: whether the pin resolved to nothing or to a socket that
/// never answered, falling through to podman's generic diagnosis would leave
/// the user debugging a pin nobody mentioned.
async fn auto_docker_runtime(
    base: &BaseConfig,
    env: &SocketEnv,
) -> (Option<docker::DockerRuntime>, Option<DevError>) {
    match connect_docker_runtime_in(base, env).await {
        Ok(rt) => (Some(rt), None),
        Err(err) if base.value(DOCKER_SOCKET_PROPERTY).is_some() => (None, Some(err)),
        Err(_) => (None, None),
    }
}

async fn detect_auto_runtime(base: &BaseConfig) -> Result<Box<dyn ContainerRuntime>, DevError> {
    // Auto-detect: check which runtimes are actually running.
    // Apple Containers disabled for now — use --runtime apple to opt in.
    let env = SocketEnv::current();
    let (docker_running, pinned_docker_error) = auto_docker_runtime(base, &env).await;

    // A `dockerSocket` pin names the daemon the user chose, so podman never
    // gets a turn against it: answering with podman would discard the choice
    // and the pin's own failure along with it.
    if base.value(DOCKER_SOCKET_PROPERTY).is_some() {
        return match (docker_running, pinned_docker_error) {
            (Some(rt), _) => Ok(Box::new(rt)),
            (None, Some(err)) => Err(err),
            (None, None) => Err(diagnose_no_runtime().await),
        };
    }

    // Prefer Podman if both are running, otherwise use whichever is running.
    match (connect_podman_runtime().await.ok(), docker_running) {
        (Some(rt), _) => Ok(Box::new(rt)),
        (None, Some(rt)) => Ok(Box::new(rt)),
        (None, None) => Err(diagnose_no_runtime().await),
    }
}

async fn command_exists(cmd: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(cmd)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn run_command(cmd: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}
async fn diagnose_no_runtime() -> DevError {
    // Apple Containers diagnostic disabled for now.
    let has_docker = command_exists("docker").await;
    let has_podman = command_exists("podman").await;

    let podman_hint = if has_podman {
        if let Some(json) = run_command("podman", &["machine", "list", "--format", "json"]).await {
            if let Ok(machines) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(arr) = machines.as_array() {
                    if arr.is_empty() {
                        Some("  podman machine init && podman machine start")
                    } else {
                        Some("  podman machine start")
                    }
                } else {
                    Some("  podman machine start")
                }
            } else {
                Some("  podman machine start")
            }
        } else {
            Some("  podman machine start")
        }
    } else {
        None
    };

    let docker_hint = if has_docker {
        Some(
            "  Start your Docker daemon (Docker Desktop, OrbStack, `colima start`, or `systemctl start docker`)",
        )
    } else {
        None
    };

    match (podman_hint, docker_hint) {
        (Some(podman), Some(docker)) => DevError::NoRuntime(format!(
            "Both Podman and Docker are installed but neither is running.\n\nStart one of them:\n{podman}\n  — or —\n{docker}\n\nThen try `dev <subcommand>` again."
        )),
        (Some(podman), None) => DevError::NoRuntime(format!(
            "Podman is installed but not running.\n\nRun:\n{podman}\n\nThen try `dev <subcommand>` again."
        )),
        (None, Some(docker)) => DevError::NoRuntime(format!(
            "Docker is installed but the daemon is not running.\n\n{docker}, then try `dev <subcommand>` again."
        )),
        (None, None) => {
            DevError::NoRuntime("No container runtime found. Install Docker or Podman.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::paths::DevHome;
    use std::fs;
    use tempfile::TempDir;

    fn dev_home_with_base_config(content: Option<&str>) -> (TempDir, DevHome) {
        let dir = TempDir::new().unwrap();
        let home = DevHome::at(dir.path());
        if let Some(content) = content {
            let path = home.base_config();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        (dir, home)
    }

    #[test]
    fn missing_default_runtime_keeps_auto_detection_behavior() {
        let (_dir, home) = dev_home_with_base_config(None);

        assert_eq!(
            select_runtime_in(&home, None).unwrap(),
            RuntimeSelection::Auto
        );
    }

    #[test]
    fn configured_default_runtime_is_loaded_from_base_config() {
        for runtime in ["docker", "podman", "apple"] {
            let (_dir, home) =
                dev_home_with_base_config(Some(&format!(r#"{{"defaultRuntime":"{runtime}"}}"#)));

            assert_eq!(
                select_runtime_in(&home, None).unwrap(),
                RuntimeSelection::Configured(RuntimeName::parse(runtime).unwrap())
            );
        }
    }

    #[test]
    fn explicit_runtime_override_wins_over_configured_default() {
        let (_dir, home) = dev_home_with_base_config(Some(r#"{"defaultRuntime":"apple"}"#));

        assert_eq!(
            select_runtime_in(&home, Some("docker")).unwrap(),
            RuntimeSelection::Explicit(RuntimeName::Docker)
        );
    }

    #[test]
    fn invalid_configured_default_runtime_names_value_and_accepted_values() {
        let (_dir, home) = dev_home_with_base_config(Some(r#"{"defaultRuntime":"containerd"}"#));

        let err = select_runtime_in(&home, None).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("containerd"), "{message}");
        assert!(message.contains("defaultRuntime"), "{message}");
        assert!(message.contains("docker, podman, apple"), "{message}");
        assert!(
            message.contains("dev base config set defaultRuntime"),
            "{message}"
        );
        assert!(
            message.contains("dev base config unset defaultRuntime"),
            "{message}"
        );
    }

    #[test]
    fn malformed_base_config_degrades_runtime_selection_to_auto() {
        let (_dir, home) = dev_home_with_base_config(Some(r#"{"remoteUser":"vscode","#));

        assert_eq!(
            select_runtime_in(&home, None).unwrap(),
            RuntimeSelection::Auto
        );
    }

    #[test]
    fn unreadable_base_config_contents_degrade_runtime_selection_to_auto() {
        let dir = TempDir::new().unwrap();
        let home = DevHome::at(dir.path());
        let path = home.base_config();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, [0xff, 0xfe, 0xfd]).unwrap();

        assert_eq!(
            select_runtime_in(&home, None).unwrap(),
            RuntimeSelection::Auto
        );
    }

    #[test]
    fn explicit_runtime_override_bypasses_malformed_base_config() {
        let (_dir, home) = dev_home_with_base_config(Some(r#"{"defaultRuntime":"#));

        assert_eq!(
            select_runtime_in(&home, Some("podman")).unwrap(),
            RuntimeSelection::Explicit(RuntimeName::Podman)
        );
    }

    #[test]
    fn configured_unavailable_runtime_error_is_distinct_and_actionable_for_every_runtime() {
        for (runtime_name, remediation) in [
            (RuntimeName::Docker, "Start your Docker daemon"),
            (RuntimeName::Podman, "Start Podman"),
            (RuntimeName::Apple, "Start Apple Containers"),
        ] {
            let err = configured_runtime_unavailable_error(
                runtime_name,
                DevError::Runtime(format!("cannot connect to {runtime_name}")),
            );
            let message = err.to_string();

            assert!(
                message.contains(&format!(
                    "Configured defaultRuntime '{runtime_name}' is unavailable"
                )),
                "{message}"
            );
            assert!(
                message.contains(&format!("cannot connect to {runtime_name}")),
                "{message}"
            );
            assert!(message.contains(remediation), "{message}");
            assert!(
                message.contains("dev base config set defaultRuntime"),
                "{message}"
            );
            assert!(
                message.contains("dev base config unset defaultRuntime"),
                "{message}"
            );
            assert!(!message.contains("Unknown runtime"), "{message}");
        }
    }

    #[cfg(not(all(target_os = "macos", feature = "apple")))]
    #[test]
    fn configured_not_compiled_runtime_error_is_distinct_and_actionable() {
        let err = configured_runtime_not_compiled_error(RuntimeName::Apple);
        let message = err.to_string();

        assert!(
            message
                .contains("Configured defaultRuntime 'apple' is not available in this dev binary"),
            "{message}"
        );
        assert!(message.contains("macOS"), "{message}");
        assert!(message.contains("apple feature"), "{message}");
        assert!(
            message.contains("dev base config set defaultRuntime"),
            "{message}"
        );
        assert!(
            message.contains("dev base config unset defaultRuntime"),
            "{message}"
        );
        assert!(!message.contains("Unknown runtime"), "{message}");
    }

    /// A `SocketEnv` whose every path lives under `tmp`, so a test never
    /// depends on the real `DOCKER_HOST`, home directory, or a stray
    /// `/var/run/docker.sock` on the machine running it. `docker_host` starts
    /// `None`; tests that need one build on top with struct update syntax.
    fn socket_env_in(tmp: &Path) -> SocketEnv {
        SocketEnv {
            docker_host: None,
            home: Some(tmp.join("home")),
            xdg_runtime_dir: Some(tmp.join("xdg")),
            system_socket: tmp.join("system/docker.sock"),
        }
    }

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"").unwrap();
    }

    #[test]
    fn a_pinned_docker_socket_is_the_only_candidate() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        for path in default_docker_socket_locations(&env) {
            touch(&path);
        }
        let pinned = dir.path().join("pinned.sock");
        touch(&pinned);
        let (_base_dir, home) = dev_home_with_base_config(Some(&format!(
            r#"{{"dockerSocket":"{}"}}"#,
            pinned.display()
        )));

        assert_eq!(
            docker_socket_candidates_in(&home, &env).unwrap(),
            vec![pinned]
        );
    }

    #[test]
    fn a_pinned_docker_socket_that_does_not_exist_is_an_error_not_a_fallback() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        for path in default_docker_socket_locations(&env) {
            touch(&path);
        }
        let pinned = dir.path().join("pinned.sock");
        let (_base_dir, home) = dev_home_with_base_config(Some(&format!(
            r#"{{"dockerSocket":"{}"}}"#,
            pinned.display()
        )));

        let message = docker_socket_candidates_in(&home, &env)
            .unwrap_err()
            .to_string();

        assert!(message.contains(&pinned.display().to_string()), "{message}");
        assert!(message.contains("dockerSocket"), "{message}");
    }

    #[test]
    fn a_pinned_docker_socket_must_be_an_absolute_path() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        let cases = [
            (
                r#"{"dockerSocket":"relative/docker.sock"}"#,
                "relative/docker.sock",
            ),
            (
                r#"{"dockerSocket":"~/.colima/default/docker.sock"}"#,
                "~/.colima/default/docker.sock",
            ),
            (r#"{"dockerSocket":123}"#, "123"),
        ];

        for (config, expected_value) in cases {
            let (_base_dir, home) = dev_home_with_base_config(Some(config));

            let err = docker_socket_candidates_in(&home, &env).unwrap_err();

            assert!(
                matches!(err, DevError::InvalidConfig(_)),
                "{config}: {err:?}"
            );
            assert!(err.to_string().contains(expected_value), "{config}: {err}");
        }
    }

    #[test]
    fn docker_host_contributes_a_candidate_only_for_unix_urls() {
        let dir = TempDir::new().unwrap();
        let dh_sock = dir.path().join("dh.sock");
        touch(&dh_sock);
        let (_base_dir, home) = dev_home_with_base_config(None);

        let cases = [
            (format!("unix://{}", dh_sock.display()), true),
            ("tcp://127.0.0.1:2375".to_string(), false),
            ("ssh://host".to_string(), false),
        ];
        for (docker_host, expect_member) in cases {
            let env = SocketEnv {
                docker_host: Some(docker_host.clone()),
                ..socket_env_in(dir.path())
            };

            let candidates = docker_socket_candidates_in(&home, &env).unwrap();

            assert_eq!(
                candidates.contains(&dh_sock),
                expect_member,
                "DOCKER_HOST={docker_host}: {candidates:?}"
            );
        }
    }

    #[test]
    fn candidates_are_ordered_config_then_docker_host_then_the_known_daemon_sockets() {
        let dir = TempDir::new().unwrap();
        let dh_sock = dir.path().join("dh.sock");
        let env = SocketEnv {
            docker_host: Some(format!("unix://{}", dh_sock.display())),
            ..socket_env_in(dir.path())
        };
        let home_dir = env.home.clone().unwrap();
        let xdg_dir = env.xdg_runtime_dir.clone().unwrap();
        let expected = vec![
            dh_sock,
            env.system_socket.clone(),
            home_dir.join(".orbstack/run/docker.sock"),
            home_dir.join(".colima/default/docker.sock"),
            home_dir.join(".docker/run/docker.sock"),
            xdg_dir.join("docker.sock"),
        ];
        for path in &expected {
            touch(path);
        }
        let (_base_dir, home) = dev_home_with_base_config(None);

        assert_eq!(docker_socket_candidates_in(&home, &env).unwrap(), expected);
    }

    #[test]
    fn only_sockets_that_exist_are_candidates() {
        let dir = TempDir::new().unwrap();
        let dh_sock = dir.path().join("dh.sock");
        let env = SocketEnv {
            docker_host: Some(format!("unix://{}", dh_sock.display())),
            ..socket_env_in(dir.path())
        };
        let all = default_docker_socket_locations(&env);
        assert_eq!(all.len(), 6, "fixture must cover all six default locations");
        touch(&all[0]);
        touch(&all[3]);
        let (_base_dir, home) = dev_home_with_base_config(None);

        let candidates = docker_socket_candidates_in(&home, &env).unwrap();

        assert_eq!(candidates, vec![all[0].clone(), all[3].clone()]);
        for absent in [&all[1], &all[2], &all[4], &all[5]] {
            assert!(
                !candidates.contains(absent),
                "{absent:?} must be absent: {candidates:?}"
            );
        }
    }

    #[test]
    fn the_same_socket_reached_two_ways_is_visited_once() {
        let dir = TempDir::new().unwrap();
        let base_env = socket_env_in(dir.path());
        let system_socket = base_env.system_socket.clone();
        touch(&system_socket);
        let env = SocketEnv {
            docker_host: Some(format!("unix://{}", system_socket.display())),
            ..base_env
        };
        let (_base_dir, home) = dev_home_with_base_config(None);

        let candidates = docker_socket_candidates_in(&home, &env).unwrap();

        assert_eq!(
            candidates.iter().filter(|p| **p == system_socket).count(),
            1,
            "{candidates:?}"
        );
    }

    #[test]
    fn an_unparseable_base_config_leaves_socket_discovery_on_the_defaults() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        for path in default_docker_socket_locations(&env) {
            touch(&path);
        }
        let (_base_dir, home) = dev_home_with_base_config(Some("{not json"));

        assert_eq!(
            docker_socket_candidates_in(&home, &env).unwrap(),
            default_docker_socket_locations(&env)
        );
    }

    #[test]
    fn a_base_config_carrying_both_keys_still_selects_the_configured_runtime() {
        let dir = TempDir::new().unwrap();
        let pinned = dir.path().join("pinned.sock");
        touch(&pinned);
        let (_base_dir, home) = dev_home_with_base_config(Some(&format!(
            r#"{{"defaultRuntime":"podman","dockerSocket":"{}"}}"#,
            pinned.display()
        )));
        let env = socket_env_in(dir.path());

        assert_eq!(
            select_runtime_in(&home, None).unwrap(),
            RuntimeSelection::Configured(RuntimeName::Podman)
        );
        assert_eq!(
            docker_socket_candidates_in(&home, &env).unwrap(),
            vec![pinned]
        );
    }

    /// Two candidates: the first constructs a client but nothing answers behind
    /// it, the second is a real listener. Connecting must not stop at the first
    /// candidate that merely builds a client — that is today's bug against a
    /// stale `/var/run/docker.sock`.
    #[tokio::test]
    async fn the_first_socket_that_answers_a_ping_is_the_one_connected() {
        use crate::runtime::fake_daemon::read_http_request;
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixListener;

        let dead = tempfile::NamedTempFile::new().expect("stand-in dead socket");
        let dir = TempDir::new().unwrap();
        let live_path = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&live_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            request
        });

        let candidates = vec![dead.path().to_path_buf(), live_path.clone()];
        let env = socket_env_in(dir.path());

        let runtime = connect_first_answering_docker_socket(&candidates, &env)
            .await
            .expect("the second candidate answers");

        assert_eq!(runtime.socket_path(), live_path.to_str().unwrap());

        let request = server.await.unwrap();
        // No `/v<version>` prefix in practice: `Docker::ping` requests `/_ping`
        // verbatim (bollard 0.20.2 `src/system.rs:85`) and does not route it
        // through version negotiation the way other endpoints are.
        assert!(request.starts_with("GET /_ping"), "{request}");
    }

    /// Every other fallback test uses a regular file as the bad candidate,
    /// which fails `connect` instantly with ENOTSOCK and never reaches the
    /// budget at all. This one accepts and then says nothing — a stale
    /// `/var/run/docker.sock` — which is the only case the budget exists for.
    /// The elapsed assertion is what makes this a test of the budget rather
    /// than of `Err`: with the timeout deleted the same `Err` arrives, 120s
    /// later, and the user reads that as a hang.
    #[tokio::test(start_paused = true)]
    async fn a_socket_that_accepts_and_never_answers_costs_only_the_ping_budget() {
        use tokio::net::UnixListener;

        let dir = TempDir::new().unwrap();
        let silent_path = dir.path().join("silent.sock");
        let silent = UnixListener::bind(&silent_path).unwrap();
        let _server = tokio::spawn(async move {
            let (_stream, _) = silent.accept().await.unwrap();
            std::future::pending::<()>().await
        });

        let started = tokio::time::Instant::now();
        let reason = try_docker_socket(&silent_path)
            .await
            .err()
            .expect("nothing answered");

        assert_eq!(
            started.elapsed(),
            host_access::HOST_DETECT_BUDGET,
            "a silent socket must cost its budget, not bollard's 120s"
        );
        assert!(reason.contains("no answer"), "{reason}");
    }

    #[tokio::test]
    async fn no_answering_socket_names_everything_that_was_tried() {
        let dir = TempDir::new().unwrap();
        let dead_one = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let dead_two = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let candidates = vec![dead_one.path().to_path_buf(), dead_two.path().to_path_buf()];
        let env = socket_env_in(dir.path());

        let message = connect_first_answering_docker_socket(&candidates, &env)
            .await
            .err()
            .expect("no candidate answers")
            .to_string();

        assert!(
            message.contains(&dead_one.path().display().to_string()),
            "{message}"
        );
        assert!(
            message.contains(&dead_two.path().display().to_string()),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_non_unix_docker_host_is_named_in_the_failure() {
        let dir = TempDir::new().unwrap();
        let env = SocketEnv {
            docker_host: Some("tcp://127.0.0.1:2375".to_string()),
            ..socket_env_in(dir.path())
        };
        let (_base_dir, home) = dev_home_with_base_config(None);
        let candidates = docker_socket_candidates_in(&home, &env).unwrap();
        assert!(candidates.is_empty(), "fixture must have no live sockets");

        let message = connect_first_answering_docker_socket(&candidates, &env)
            .await
            .err()
            .expect("no candidate answers")
            .to_string();

        assert!(message.contains("tcp://127.0.0.1:2375"), "{message}");
    }

    #[tokio::test]
    async fn a_pinned_socket_that_never_answers_is_carried_out_of_auto_detection() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        let dead = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let (_base_dir, home) = dev_home_with_base_config(Some(&format!(
            r#"{{"dockerSocket":"{}"}}"#,
            dead.path().display()
        )));

        let (runtime, pinned_error) = auto_docker_runtime(&BaseConfig::read(&home), &env).await;

        assert!(runtime.is_none());
        let message = pinned_error
            .expect("a pinned socket that answers nothing is not silently ignored")
            .to_string();
        assert!(
            message.contains(&dead.path().display().to_string()),
            "{message}"
        );
        assert!(message.contains(DOCKER_SOCKET_PROPERTY), "{message}");
        assert!(
            message.contains("pins"),
            "the error must say the pin is what answered nothing: {message}"
        );
        assert!(
            !message.contains("to pin one"),
            "a user who already pinned a socket must not be advised to pin one: {message}"
        );
    }

    /// OrbStack writes `~/.docker/run/docker.sock` as well as its own socket.
    /// With the generic path ahead of it, `dev` connects through a path that
    /// names no flavor, and a daemon too slow to answer `/info` is then read
    /// off that path as Docker Desktop — whose row skips UID remapping and
    /// promises host socket mounts OrbStack does not deliver.
    #[test]
    fn a_flavor_specific_socket_outranks_the_generic_docker_one() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        let home_dir = env.home.clone().unwrap();
        let orbstack = home_dir.join(".orbstack/run/docker.sock");
        let generic = home_dir.join(".docker/run/docker.sock");
        touch(&orbstack);
        touch(&generic);
        let (_base_dir, home) = dev_home_with_base_config(None);

        let candidates = docker_socket_candidates_in(&home, &env).unwrap();

        assert_eq!(candidates, vec![orbstack, generic]);
    }

    /// The note is what keeps a `DOCKER_HOST` that contributed no candidate
    /// from vanishing. A typo'd unix path is the case that matters: it is
    /// dropped at the `path.exists()` filter, and without a note the user is
    /// left on whichever other daemon answered.
    #[test]
    fn a_docker_host_that_contributed_no_candidate_is_named() {
        let live = tempfile::NamedTempFile::new().unwrap();
        let live_path = live.path().display().to_string();

        assert_eq!(
            ignored_docker_host_note(&format!("unix://{live_path}")),
            None,
            "a unix socket that exists is used, so there is nothing to report"
        );

        let missing = ignored_docker_host_note("unix:///Users/me/.colima/work/docker.sock")
            .expect("a unix path with no socket at it is dropped and must be reported");
        assert!(
            missing.contains("/Users/me/.colima/work/docker.sock"),
            "{missing}"
        );

        let non_unix = ignored_docker_host_note("tcp://127.0.0.1:2375")
            .expect("a scheme this path cannot speak must be reported");
        assert!(non_unix.contains("tcp://127.0.0.1:2375"), "{non_unix}");
    }

    /// A podman socket that accepts and never answers must not hold the user
    /// for bollard's 120s client timeout — the budget docker's candidates
    /// have had all along.
    #[tokio::test(start_paused = true)]
    async fn a_podman_socket_that_never_answers_gives_up_within_the_budget() {
        use tokio::net::UnixListener;

        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await
        });

        let rt = podman::PodmanRuntime(
            docker::BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
                .expect("building a client must not need a daemon to answer"),
        );

        let started = tokio::time::Instant::now();
        let err = podman_answering_a_ping(rt)
            .await
            .err()
            .expect("nothing answered");

        assert!(
            started.elapsed() < host_access::HOST_DETECT_BUDGET * 2,
            "gave up after {:?}",
            started.elapsed()
        );
        assert!(err.to_string().contains("podman"), "{err}");
    }

    #[tokio::test]
    async fn an_unpinned_docker_failure_leaves_auto_detection_to_podman() {
        let dir = TempDir::new().unwrap();
        let env = socket_env_in(dir.path());
        touch(&env.system_socket);
        let (_base_dir, home) = dev_home_with_base_config(None);

        let (runtime, pinned_error) = auto_docker_runtime(&BaseConfig::read(&home), &env).await;

        assert!(runtime.is_none());
        assert!(pinned_error.is_none());
    }

    /// A wrapper that forgets to override the defaulted `None`, or that
    /// canonicalizes the path on the way in, leaves flavor detection with
    /// nothing to discriminate on.
    #[test]
    fn every_bollard_backed_runtime_reports_its_socket() {
        let docker_socket = tempfile::NamedTempFile::new().expect("stand-in docker socket");
        let podman_socket = tempfile::NamedTempFile::new().expect("stand-in podman socket");
        let docker_path = docker_socket.path().to_string_lossy().to_string();
        let podman_path = podman_socket.path().to_string_lossy().to_string();

        let docker = docker::DockerRuntime::connect_to_socket(&docker_path)
            .expect("building a docker client must not need a daemon");
        let podman = podman::PodmanRuntime(
            docker::BollardRuntime::connect_to_socket(&podman_path)
                .expect("building a podman client must not need a daemon"),
        );
        let docker: &dyn ContainerRuntime = &docker;
        let podman: &dyn ContainerRuntime = &podman;

        assert_eq!(docker.socket_path(), Some(docker_path.as_str()));
        assert_eq!(podman.socket_path(), Some(podman_path.as_str()));
    }

    fn container_config_with_env(env: &[(&str, &str)]) -> ContainerConfig {
        ContainerConfig {
            image: "ubuntu:24.04".to_string(),
            name: "vsc-test".to_string(),
            labels: HashMap::new(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            mounts: vec![],
            volumes: vec![],
            tmpfs: vec![],
            ports: vec![],
            workspace_mount: None,
            workspace_folder: None,
            extra_args: vec![],
            entrypoint: None,
            init: false,
            privileged: false,
            cap_add: vec![],
            security_opt: vec![],
            userns_mode: None,
            extra_hosts: vec![],
        }
    }

    #[test]
    fn debug_hides_env_values() {
        let config = container_config_with_env(&[("SECRET", "hunter2")]);

        let rendered = format!("{config:?}");

        assert!(rendered.contains("SECRET"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn debug_keeps_other_fields() {
        let config = container_config_with_env(&[]);

        let rendered = format!("{config:?}");

        assert!(rendered.contains("ubuntu:24.04"), "{rendered}");
        assert!(rendered.contains("vsc-test"), "{rendered}");
    }

    #[test]
    fn alternate_debug_hides_env_values() {
        let config = container_config_with_env(&[("SECRET", "hunter2")]);

        let rendered = format!("{config:#?}");

        assert!(rendered.contains("SECRET"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }
}
