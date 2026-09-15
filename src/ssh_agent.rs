//! The host end of the SSH agent relay.
//!
//! On Docker Desktop the base layer's 1Password bind mount reaches the
//! container directly. Where that mount does not arrive as a usable socket
//! (OrbStack, for one — see [`crate::runtime::HostAccess::host_sockets_mount`]),
//! this gives the container a TCP path back to `dev`'s own `$SSH_AUTH_SOCK`
//! instead, guarded by a per-container token.
//!
//! Unlike `crate::cmux::agent`'s relay, this one outlives the process that
//! started it: `dev up` exits in seconds, but the container's self-heal
//! script (`~/.dev/container/ssh-config`'s `Match exec`) dials the relay at
//! arbitrary later moments — every `git push`, every `ssh`. So it runs as a
//! detached daemon rather than an in-process task tied to a session's
//! `Drop`. It claims its workspace with a lock the kernel releases on
//! process death, and records its port and pid beside that lock:
//! `~/.dev/ssh-relay/<workspace-hash>.json` survives a reboot and pids
//! restart low, so nothing here signals a pid it has not first seen the lock
//! held for.
//!
//! A unix agent socket is protected by filesystem permissions; putting it on
//! a TCP port hands the ability to sign with the user's keys to anything
//! that can reach the port. The listener binds loopback only — see
//! [`crate::runtime::HostAccess::host_callback`], which this reuses rather
//! than re-deciding — and the per-connection token is the rest of the
//! boundary. `dev up` binds the port itself, before the container exists,
//! and hands the listener to the daemon: a port rebound later is a port
//! something else can hold first, and the shim sends its token the instant
//! the socket opens.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixStream};

use crate::devcontainer::config::DevcontainerConfig;
use crate::devcontainer::secrets::SecretValue;
use crate::error::DevError;
use crate::runtime::{
    ALLOW_RELAY_PROPERTY, ContainerRuntime, HostAccess, RELAY_PROPERTY, ssh_agent_relay_allowed_in,
};
use crate::util::naming::workspace_hash;
use crate::util::paths::DevHome;
use crate::util::process::kill_and_wait;
use crate::util::token::mint_token;

/// Bumped with the shim's own constant whenever the handshake below changes
/// shape. A shim from an image built against an older `dev` is refused
/// rather than half-understood.
const PROTOCOL: &str = "dev-ssh-agent/1";

/// A request is one line: `<protocol> <token>`. Nothing legitimate
/// approaches this, so an oversized line is refused rather than bounding
/// something real.
const MAX_HANDSHAKE: u64 = 256;

/// How long a connection may take to send its handshake. Generous next to a
/// local TCP round trip, but a connection that never sends one must not pile
/// up on the daemon forever.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

/// A local unix socket has no legitimate reason to hang; this bounds the
/// upstream probe against a wedged agent rather than a slow one.
const UPSTREAM_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Always loopback. Widening it to reach a container that cannot reach
/// loopback is never the fallback — see
/// [`crate::runtime::HostAccess::host_callback`], which is what actually
/// decides whether a relay runs at all.
const BIND_IP: &str = "127.0.0.1";

/// How a token travels to a process rather than through argv (so it stays
/// out of `ps`) or the state file (so it stays off the host's disk): the
/// daemon reads it from here, and so does the exec that writes the
/// container's own copy.
const TOKEN_ENV: &str = "DEV_SSH_AGENT_RELAY_TOKEN";

/// Where the container reads its current token from, preferred by the shim
/// over [`TOKEN_CONTAINER_ENV`]. A container's environment is fixed at
/// create and Docker cannot change it on a live container, so the copy in
/// there is good for as long as the container runs; this file is rewritten
/// every time a daemon starts, which is what lets a captured token stop
/// working.
const TOKEN_FILE: &str = "/run/dev-ssh/token";

/// The env vars a container reads. Kept as constants so the writer and the
/// two readers (the exec-based probe here, and the container's shim) cannot
/// drift from each other by a typo.
const UPSTREAM_ENV: &str = "DEV_SSH_AGENT_UPSTREAM";
const TOKEN_CONTAINER_ENV: &str = "DEV_SSH_AGENT_TOKEN";

/// A relay's port and the token that gates it. Never carries the alias:
/// that is only needed once, to build the env a fresh container is given.
pub(crate) struct Endpoint {
    pub port: u16,
    pub token: String,
}

// --- The feature `dev` carries ------------------------------------------

/// The feature's own files, carried in this binary. `dev` installs as a
/// single binary from a release, so a feature living only in the repository
/// would be a feature nobody has. See [`crate::cmux::agent`]'s sibling
/// constant, which this mirrors rather than shares: the two keys are
/// independent, and a container must be able to carry one without the
/// other's image layer.
const FEATURE_FILES: [(&str, &str); 3] = [
    (
        "devcontainer-feature.json",
        include_str!("../features/ssh-agent-relay/devcontainer-feature.json"),
    ),
    (
        "install.sh",
        include_str!("../features/ssh-agent-relay/install.sh"),
    ),
    (
        "ssh-agent-upstream",
        include_str!("../features/ssh-agent-relay/ssh-agent-upstream"),
    ),
];

/// The directory name the feature is staged under, and the last segment of
/// the id the build sees.
pub(crate) const FEATURE_NAME: &str = "ssh-agent-relay";

/// Where `install.sh` lands the shim. Named by absolute path everywhere it
/// is used — the base layer's relay script execs it directly, and this is
/// deliberately never put on `PATH` — so the constant is the one place that
/// path can drift from the feature's own `install.sh`.
pub(crate) const SHIM_PATH: &str = "/usr/local/share/dev-ssh/bin/ssh-agent-upstream";

/// Write the feature out and hand back the path a build can resolve it by.
/// Delegates the staging loop to
/// [`crate::devcontainer::features::stage_embedded_feature`], shared with
/// [`crate::cmux::agent::stage_feature_in`].
pub(crate) fn stage_feature_in(home: &DevHome) -> Result<PathBuf, DevError> {
    crate::devcontainer::features::stage_embedded_feature(home, FEATURE_NAME, &FEATURE_FILES)
}

// --- Consent ----------------------------------------------------------

/// What this run may do about the relay.
///
/// Two keys in two files decide it: a project asks with `sshAgent.relay`,
/// and only the user's own base config grants with `sshAgent.allowRelay`.
/// The relay runs on both, which is why a config a repository ships can
/// never be the whole of it — the relay hands whatever runs in the container
/// the ability to sign with the host's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDecision {
    /// Nothing asked, so nothing to decide.
    Off,
    /// The project asked and the base config has not granted it.
    RequestedNotAllowed,
    /// Asked and granted.
    On,
}

impl RelayDecision {
    pub fn is_on(self) -> bool {
        matches!(self, RelayDecision::On)
    }
}

/// The decision plus the two files that made it, resolved once per command
/// so nothing downstream re-derives it from a config value and no two
/// messages name a different file.
pub(crate) struct RelayConsent {
    decision: RelayDecision,
    /// The base config, which grants.
    base: PathBuf,
    /// The project config, which asks.
    requested_by: PathBuf,
}

impl RelayConsent {
    /// The request comes from the merged config and the permission from the
    /// base file, and neither reads the other's key. A recipe workspace has
    /// no project layer to source the request from, so the merge is the only
    /// place every project shape can be asked; that is safe precisely
    /// because the base's `allowRelay` cannot merge into a `relay`.
    pub(crate) fn resolve_in(
        config: &DevcontainerConfig,
        requested_by: &Path,
        home: &DevHome,
    ) -> Self {
        Self {
            decision: relay_decision_in(config, home),
            base: home.base_config(),
            requested_by: requested_by.to_path_buf(),
        }
    }

    pub(crate) fn decision(&self) -> RelayDecision {
        self.decision
    }

    /// Say that a repository asked for the host's keys and did not get them.
    /// The user should learn this happened whether or not they go on to
    /// grant it, and should not go looking in the project for the switch.
    pub(crate) fn report(&self) {
        if let Some(message) = self.refusal_message() {
            eprintln!("{message}");
        }
    }

    /// The on-state: the host's agent is reachable on a loopback port for as
    /// long as the container lives, so say so, once, with both files and the
    /// port that carries it.
    pub(crate) fn announce(&self, port: u16) {
        eprintln!("{}", self.on_message(port));
    }

    /// Built rather than printed, so what it has to name is assertable.
    fn refusal_message(&self) -> Option<String> {
        if self.decision != RelayDecision::RequestedNotAllowed {
            return None;
        }
        Some(format!(
            "Warning: this project asked for access to your SSH agent, and it was refused.\n  \
             {requested} sets {RELAY_PROPERTY}, which would let anything running in the \
             container sign with the keys in your host agent.\n  \
             Your base config refused it, not the project: {base} does not set \
             {ALLOW_RELAY_PROPERTY}.\n  \
             To allow it, run `dev base config set {ALLOW_RELAY_PROPERTY} true`. Until then the \
             relay stays off and the container gets no agent.",
            requested = self.requested_by.display(),
            base = self.base.display(),
        ))
    }

    fn on_message(&self, port: u16) -> String {
        format!(
            "SSH agent relay on: {requested} asks ({RELAY_PROPERTY}) and {base} allows it \
             ({ALLOW_RELAY_PROPERTY}); your agent is reachable from this container on \
             {BIND_IP}:{port} for its lifetime.",
            requested = self.requested_by.display(),
            base = self.base.display(),
        )
    }
}

fn decide_relay(requested: bool, allowed: bool) -> RelayDecision {
    match (requested, allowed) {
        (false, _) => RelayDecision::Off,
        (true, false) => RelayDecision::RequestedNotAllowed,
        (true, true) => RelayDecision::On,
    }
}

/// The decision alone, for the read-only consumers that only need to know
/// which features an image carries (`dev prune`, image-tag computation).
/// Every command that can start a relay resolves a [`RelayConsent`] instead,
/// so it has the two files to name in what it prints.
pub(crate) fn relay_decision_in(config: &DevcontainerConfig, home: &DevHome) -> RelayDecision {
    decide_relay(
        config.ssh_agent_relay_requested(),
        ssh_agent_relay_allowed_in(home),
    )
}

// --- The gate ---------------------------------------------------------

/// The three conditions decidable without touching the network: the relay is
/// consented to, and the host access descriptor says a container has both a
/// name for the host and a route to a loopback listener on it.
/// `host_sockets_mount` is deliberately not read here — it is `dev status`'s
/// business, not a gate, per the doc comment on
/// [`DevcontainerConfig::cmux_agent_enabled`]'s sibling rule.
fn relay_wanted(relay: RelayDecision, access: HostAccess) -> bool {
    relay.is_on() && access.host_callback().is_ok()
}

/// Where this process's own agent lives, as `dev` itself was started —
/// the shell the user ran `dev up` from, not a value resolved on the
/// container's behalf.
fn upstream_path() -> Option<PathBuf> {
    let path = std::env::var_os("SSH_AUTH_SOCK")?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// A live agent behind `path`, checked with a connect bounded by
/// [`UPSTREAM_PROBE_TIMEOUT`]. A dead 1Password refuses the connect, which
/// is exactly the failure this exists to catch.
async fn upstream_answers(path: &Path) -> bool {
    tokio::time::timeout(UPSTREAM_PROBE_TIMEOUT, UnixStream::connect(path))
        .await
        .is_ok_and(|connected| connected.is_ok())
}

/// A relay that is bound but not yet serving. `dev up` holds one of these
/// from before the container exists until the daemon is started, then hands
/// the listener itself over: nothing rebinds the port, so nothing else can
/// hold it while the token guarding it is being baked into a container.
pub(crate) struct PendingRelay {
    pub(crate) endpoint: Endpoint,
    listener: TcpListener,
}

/// Decide, and mint, the endpoint a fresh container should be given: the
/// alias to reach it by, and a bound listener carrying the port/token pair
/// — or `None` at any of the four gates, ordered so the one that touches the
/// network is last.
pub(crate) async fn wanted_endpoint(
    relay: RelayDecision,
    access: HostAccess,
) -> Option<(&'static str, PendingRelay)> {
    wanted_endpoint_from(relay, access, upstream_path()).await
}

/// [`upstream_path`] reads the environment `dev` itself was started in,
/// which a test cannot vary without changing its own; taking it as an
/// argument is the seam.
async fn wanted_endpoint_from(
    relay: RelayDecision,
    access: HostAccess,
    upstream: Option<PathBuf>,
) -> Option<(&'static str, PendingRelay)> {
    if !relay_wanted(relay, access) {
        return None;
    }
    let callback = access.host_callback().ok()?;
    let upstream = upstream?;
    if !upstream_answers(&upstream).await {
        return None;
    }
    let token = mint_token()?;
    let listener = TcpListener::bind((callback.bind, 0)).await.ok()?;
    let port = listener.local_addr().ok()?.port();
    Some((
        callback.alias,
        PendingRelay {
            endpoint: Endpoint { port, token },
            listener,
        },
    ))
}

/// The environment a freshly created container needs, built the way
/// `crate::cmux::agent::relay_env` is: a pure function of what varies, so it
/// is asserted without binding anything.
pub(crate) fn upstream_env(alias: &str, port: u16, token: &str) -> Vec<(String, String)> {
    vec![
        (UPSTREAM_ENV.to_string(), format!("tcp:{alias}:{port}")),
        (TOKEN_CONTAINER_ENV.to_string(), token.to_string()),
    ]
}

// --- Reading the endpoint back off a reused container ------------------

/// The value of `key` in a `NAME=value\n`-per-line stdout, ignoring every
/// other line — a login shell's own banner included. A key that appears
/// twice is refused rather than resolved: the read-back prints each of these
/// once, so a second occurrence is a value carrying a newline, and picking
/// either one lets a project's own `containerEnv` choose the token that
/// guards the user's agent.
fn env_value<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
    let mut found = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='));
    let value = found.next()?;
    found.next().is_none().then_some(value)
}

/// The port a `tcp:<host>:<port>` upstream names, with every field required
/// to mean something: a host because that is what the container dials, a
/// non-zero port because `bind(0)` on a zero would serve an address nothing
/// was told, and digits only because `u16::from_str` otherwise accepts a
/// `+51482` no shim can dial.
fn upstream_port(upstream: &str) -> Option<u16> {
    let (host, port) = upstream.strip_prefix("tcp:")?.rsplit_once(':')?;
    if host.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    (port != 0).then_some(port)
}

/// The endpoint a reused container was given at create time, recovered from
/// its own environment. `None` covers everything that is not a well-formed
/// `tcp:` pair: absent output, an empty or malformed field, a `unix:`
/// upstream (nothing for this daemon to reconcile), or a login shell's own
/// banner mixed into the same stdout.
///
/// The empty token is the case that costs the most. The read-back prints an
/// unset variable as `NAME=`, and a project's own `containerEnv` can name an
/// upstream on any create that minted no relay of its own, so this is
/// reachable from a repository alone. A daemon started for such an endpoint
/// admits every local process and is refused by the container's own shim.
pub(crate) fn parse_endpoint(stdout: &str) -> Option<Endpoint> {
    let port = upstream_port(env_value(stdout, UPSTREAM_ENV)?)?;
    let token = env_value(stdout, TOKEN_CONTAINER_ENV)?;
    (!token.is_empty()).then(|| Endpoint {
        port,
        token: token.to_string(),
    })
}

/// What the read-back execs. `printenv` with arguments prints bare values,
/// which [`parse_endpoint`] cannot tell apart; bare `printenv` pulls every
/// secret in the container back into this process and lets any value
/// containing a newline forge either field. `printf` reuses its format
/// across both pairs, so this is exactly two `NAME=value` lines whatever the
/// environment holds, and an unset var yields `NAME=`, which
/// [`parse_endpoint`] already refuses.
fn read_endpoint_command() -> Vec<String> {
    let script = format!(
        r#"printf '%s=%s\n' {UPSTREAM_ENV} "${UPSTREAM_ENV}" {TOKEN_CONTAINER_ENV} "${TOKEN_CONTAINER_ENV}""#
    );
    vec!["sh".to_string(), "-c".to_string(), script]
}

/// Ask a container what endpoint it was told at create time, the way
/// `crate::cmux::agent::installed_agents` asks what it carries: one exec,
/// stdout turned into an answer by a pure parser.
pub(crate) async fn read_endpoint(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> Option<Endpoint> {
    let result = runtime
        .exec(container_id, &read_endpoint_command(), user, None, &[])
        .await
        .ok()?;
    parse_endpoint(&result.stdout)
}

/// The exec that puts a token where the shim looks first. The token itself
/// travels in the exec's environment; only the user name reaches argv.
/// `umask` sets the mode rather than a later `chmod`, so the token is never
/// briefly readable, and the trailing newline is what lets the shim's `read`
/// succeed rather than report EOF.
fn write_token_command(user: Option<&str>, file: &str) -> Vec<String> {
    let dir = file.rsplit_once('/').map_or("/", |(dir, _)| dir);
    let chown = match user {
        Some(user) => format!("\nchown {user} {dir} {file}"),
        None => String::new(),
    };
    let script = format!(
        "set -e\numask 077\nmkdir -p {dir}\nprintf '%s\\n' \"${TOKEN_ENV}\" > {file}{chown}"
    );
    vec!["sh".to_string(), "-c".to_string(), script]
}

/// A running container's token file, so the daemon and the shim can be given
/// the same new token in one breath.
pub(crate) struct TokenSink<'a> {
    runtime: &'a dyn ContainerRuntime,
    container_id: &'a str,
    user: Option<&'a str>,
}

impl<'a> TokenSink<'a> {
    pub(crate) fn new(
        runtime: &'a dyn ContainerRuntime,
        container_id: &'a str,
        user: Option<&'a str>,
    ) -> Self {
        TokenSink {
            runtime,
            container_id,
            user,
        }
    }

    /// Put `token` where the shim reads first. `false` leaves the copy in
    /// the container's environment as the only one either side has: good
    /// enough on the create path, where that copy is one this run minted,
    /// and the reason [`TokenSink::rotate`] refuses on the reuse path, where
    /// it is whatever the container was created with.
    /// Runs as root: `/run` is root-owned in every image, and the file is
    /// handed to the remote user the shim runs as.
    async fn write(&self, token: &str) -> bool {
        let env = [(TOKEN_ENV.to_string(), SecretValue::new(token))];
        let result = self
            .runtime
            .exec(
                self.container_id,
                &write_token_command(self.user, TOKEN_FILE),
                Some("root"),
                None,
                &env,
            )
            .await;
        match result {
            Ok(result) if result.exit_code == 0 => true,
            Ok(result) => {
                eprintln!(
                    "Warning: could not write the SSH agent relay token to {TOKEN_FILE}: {}",
                    result.stderr.trim()
                );
                false
            }
            Err(e) => {
                eprintln!("Warning: could not write the SSH agent relay token: {e}");
                false
            }
        }
    }

    /// A fresh token for a daemon about to start, already in the container's
    /// token file, or `None` when there is none to serve with.
    ///
    /// There is deliberately no fallback to the token baked into the
    /// container's environment. A project's own `containerEnv` can set that
    /// value, and a project can make the write fail — a read-only `/run`, or
    /// an image whose `/run` root cannot `mkdir` in — so falling back would
    /// let a repository choose the credential guarding the user's agent, on
    /// a port it also chose, reachable by anything on the host's loopback.
    async fn rotate(&self) -> Option<String> {
        let token = mint_token()?;
        self.write(&token).await.then_some(token)
    }
}

// --- The daemon's own lifecycle -----------------------------------------

/// What `~/.dev/ssh-relay/<workspace-hash>.json` records. No token: it
/// reaches the daemon through the child's environment, never disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RelayState {
    pub(crate) port: u16,
    pub(crate) pid: u32,
}

fn read_relay_state_in(dev_home: &DevHome, hash: &str) -> Option<RelayState> {
    let content = std::fs::read_to_string(dev_home.ssh_relay_state_file(hash)).ok()?;
    serde_json::from_str(&content).ok()
}

/// Written whole or not at all: an interrupted create-truncate-write leaves
/// unparsable JSON, and a daemon nothing can find is a signing listener
/// nothing can stop.
fn write_relay_state_in(dev_home: &DevHome, hash: &str, state: &RelayState) -> Option<()> {
    use std::io::Write;

    let path = dev_home.ssh_relay_state_file(hash);
    let dir = path.parent()?;
    std::fs::create_dir_all(dir).ok()?;
    let json = serde_json::to_string(state).ok()?;
    let temp = dir.join(format!("{hash}.{}.tmp", std::process::id()));
    let mut open = std::fs::OpenOptions::new();
    open.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let written = open
        .open(&temp)
        .and_then(|mut file| file.write_all(json.as_bytes()))
        .and_then(|()| std::fs::rename(&temp, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
        return None;
    }
    Some(())
}

fn remove_relay_state_in(dev_home: &DevHome, hash: &str) {
    let _ = std::fs::remove_file(dev_home.ssh_relay_state_file(hash));
}

/// The daemon's claim on a workspace: created on first use, zero bytes for
/// its whole life, only ever locked. `None` means another daemon holds it.
/// The kernel releases the lock when the holder dies, SIGKILL included, so
/// there is no stale lock to clean up after a crash or a reboot.
fn hold_relay_lock(dev_home: &DevHome, hash: &str) -> Option<std::fs::File> {
    let path = dev_home.ssh_relay_lock_file(hash);
    std::fs::create_dir_all(path.parent()?).ok()?;
    let mut open = std::fs::OpenOptions::new();
    open.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let file = open.open(&path).ok()?;
    try_lock(&file).then_some(file)
}

fn try_lock(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Evidence that a probe found the lock held. [`kill_locked_daemon`] takes
/// one rather than trusting its caller: a recorded pid survives a reboot and
/// pids restart low, so the probe is the only thing that tells a live relay
/// of ours from whatever inherited its number.
struct LockHeld;

/// Whether a daemon of ours owns this workspace right now. A parent only
/// ever probes: holding the lock across a spawn would make the child fail to
/// take it. Never creates the file, so a workspace that has never run a
/// relay leaves nothing behind.
fn relay_lock_is_held(dev_home: &DevHome, hash: &str) -> Option<LockHeld> {
    let file = std::fs::File::open(dev_home.ssh_relay_lock_file(hash)).ok()?;
    if try_lock(&file) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return None;
    }
    Some(LockHeld)
}

/// Stop the recorded daemon. Reachable only with a [`LockHeld`] in hand, so
/// no path can be written that signals a pid on the strength of the state
/// file alone.
fn kill_locked_daemon(dev_home: &DevHome, hash: &str, _held: LockHeld) {
    if let Some(state) = read_relay_state_in(dev_home, hash) {
        kill_and_wait(state.pid);
    }
}

/// The hidden subcommand the daemon is re-exec'd as. It takes no address:
/// the parent bound the port and hands over the listener, which also leaves
/// no way to ask this process for a wider bind.
const DAEMON_SUBCOMMAND: &str = "ssh-agent-relay";

/// Everything about the daemon's launch except the listener: the token
/// travels in the environment so it stays out of `ps`, and `setsid` puts the
/// daemon in its own session so a Ctrl-C during `postCreateCommand` does not
/// take the relay down with `dev up`.
fn daemon_command(exe: PathBuf, hash: &str, token: &str) -> std::process::Command {
    let mut command = std::process::Command::new(exe);
    command
        .args([DAEMON_SUBCOMMAND, "--workspace-hash", hash])
        .env(TOKEN_ENV, token)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    // Safe: the closure captures nothing, and `setsid` is async-signal-safe.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

/// How long a spawned daemon has to record itself. It covers this binary's
/// own start and the daemon's own [`UPSTREAM_PROBE_TIMEOUT`]; the wait ends
/// as soon as the daemon records or exits, so only one that comes up wedged
/// costs the whole bound.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(3);
const DAEMON_READY_POLL: Duration = Duration::from_millis(10);

/// Re-exec this binary as the hidden relay daemon, with `listener` as its
/// stdin. The spawn dups it onto fd 0 and clears close-on-exec, so the
/// daemon serves the very port the container was told to dial.
///
/// A daemon that exits during startup writes its reason to a nulled stderr
/// and leaves the spawn itself looking like a success, so waiting for it to
/// record itself is the only thing that can tell the user their container is
/// about to dial a port nothing serves.
async fn spawn_daemon(dev_home: &DevHome, hash: &str, listener: TcpListener, token: &str) -> bool {
    match launch_daemon(hash, listener, token) {
        Ok(mut child) => {
            if daemon_records_itself(dev_home, hash, &mut child).await {
                return true;
            }
            eprintln!(
                "Warning: the SSH agent relay did not start. Agent forwarding is unavailable \
                 for this container; check that `ssh-add -l` answers on the host, then run \
                 `dev up` again."
            );
            false
        }
        Err(e) => {
            eprintln!(
                "Warning: the SSH agent relay could not be started: {e}. Agent forwarding is \
                 unavailable for this container."
            );
            false
        }
    }
}

fn launch_daemon(
    hash: &str,
    listener: TcpListener,
    token: &str,
) -> std::io::Result<std::process::Child> {
    let exe = std::env::current_exe()?;
    let handoff = std::process::Stdio::from(std::os::fd::OwnedFd::from(listener.into_std()?));
    daemon_command(exe, hash, token).stdin(handoff).spawn()
}

/// Whether the spawned daemon claimed the workspace and recorded itself,
/// which [`run_daemon`]'s order makes the same thing as "is about to serve".
/// The pid is what makes this evidence rather than a guess: the state file a
/// previous daemon left can name the very port this one was handed, and on
/// the reuse path it usually does.
async fn daemon_records_itself(
    dev_home: &DevHome,
    hash: &str,
    child: &mut std::process::Child,
) -> bool {
    let pid = child.id();
    // The same clock the sleep below runs on, so the budget is what a test
    // with a paused clock measures rather than three real seconds of spin.
    let deadline = tokio::time::Instant::now() + DAEMON_READY_TIMEOUT;
    loop {
        if read_relay_state_in(dev_home, hash).is_some_and(|state| state.pid == pid) {
            return true;
        }
        let still_running = matches!(child.try_wait(), Ok(None));
        if !still_running || tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(DAEMON_READY_POLL).await;
    }
}

/// Start the daemon for a container that is being created, with the listener
/// bound before the image was even built. `bind(0)` cannot return a port a
/// live process holds, so there are only two cases: a daemon of ours is
/// running for this workspace on some other port, or none is.
///
/// Returns whether a daemon is now serving, so the caller announcing the
/// on-state says it only of a relay that came up.
pub(crate) async fn start_relay(
    dev_home: &DevHome,
    workspace: &Path,
    pending: Option<PendingRelay>,
    container: &TokenSink<'_>,
) -> bool {
    let Some(pending) = pending else {
        return false;
    };
    let hash = workspace_hash(workspace);
    if let Some(held) = relay_lock_is_held(dev_home, &hash) {
        kill_locked_daemon(dev_home, &hash, held);
    }
    // The same token the container's environment already carries: nothing to
    // rotate on a container this run just made, but the file has to exist
    // for the next `dev up` to have something to replace.
    container.write(&pending.endpoint.token).await;
    spawn_daemon(dev_home, &hash, pending.listener, &pending.endpoint.token).await
}

/// What to do about a reused container's endpoint, decided before anything
/// is signalled or spawned. `bound` is whether this process just took the
/// port the container will dial; `recorded_port` is what the state file says
/// our own daemon serves.
#[derive(Debug, PartialEq, Eq)]
enum ReuseAction {
    /// Our daemon already serves that port.
    Leave,
    /// We hold the port, so a daemon of ours can have it. Whether one has to
    /// be stopped first is not decided here: that needs a [`LockHeld`].
    Serve,
    /// Our daemon is stale on an old container's port and a foreigner holds
    /// this one: stop ours, then try for the port once more.
    Reclaim,
    /// No daemon of ours, and something else owns the port. Declining is the
    /// answer here, not a wider bind.
    Decline,
}

fn reuse_action(
    lock_held: bool,
    bound: bool,
    recorded_port: Option<u16>,
    wanted_port: u16,
) -> ReuseAction {
    match (lock_held, bound) {
        (_, true) => ReuseAction::Serve,
        (true, false) if recorded_port == Some(wanted_port) => ReuseAction::Leave,
        (true, false) => ReuseAction::Reclaim,
        (false, false) => ReuseAction::Decline,
    }
}

async fn bind_relay_port(port: u16) -> Option<TcpListener> {
    TcpListener::bind((BIND_IP, port)).await.ok()
}

fn warn_port_held(port: u16) {
    eprintln!(
        "Warning: SSH agent relay port {port} is held by another process. Agent forwarding is \
         unavailable for this container; recreate it with `dev up --rebuild` for a new port."
    );
}

fn warn_token_not_replaced() {
    eprintln!(
        "Warning: the SSH agent relay could not write {TOKEN_FILE} in this container, so it \
         cannot replace the token the container was created with. Agent forwarding is \
         unavailable for this container until `/run` is writable inside it; recreating the \
         container does not help on its own."
    );
}

/// Make sure a daemon is serving the port a reused container was told to
/// dial, per [`reuse_action`]. Every daemon started here gets a token this
/// run minted, so the one the container was created with stops being enough
/// to sign with — and where that token cannot be delivered, no daemon starts
/// at all.
pub(crate) async fn ensure_relay(
    dev_home: &DevHome,
    workspace: &Path,
    endpoint: &Endpoint,
    container: &TokenSink<'_>,
) -> bool {
    let hash = workspace_hash(workspace);
    let lock_held = relay_lock_is_held(dev_home, &hash);
    // Before any kill, so the port is never released back to the loser of
    // the race it is being taken from.
    let bound = bind_relay_port(endpoint.port).await;
    let recorded_port = read_relay_state_in(dev_home, &hash).map(|state| state.port);

    let listener = match reuse_action(
        lock_held.is_some(),
        bound.is_some(),
        recorded_port,
        endpoint.port,
    ) {
        // The running daemon keeps the token it was started with, and only
        // it knows that token: rotating without restarting it would leave
        // the shim reading one the relay refuses.
        ReuseAction::Leave => return true,
        ReuseAction::Decline => {
            warn_port_held(endpoint.port);
            return false;
        }
        ReuseAction::Serve => {
            if let Some(held) = lock_held {
                kill_locked_daemon(dev_home, &hash, held);
            }
            bound
        }
        ReuseAction::Reclaim => {
            if let Some(held) = lock_held {
                kill_locked_daemon(dev_home, &hash, held);
            }
            bind_relay_port(endpoint.port).await
        }
    };
    match listener {
        Some(listener) => {
            // Rotate before the spawn: the daemon gets whichever token the
            // write left in effect, so the reverse order breaks every dial.
            match container.rotate().await {
                Some(token) => spawn_daemon(dev_home, &hash, listener, &token).await,
                None => {
                    warn_token_not_replaced();
                    false
                }
            }
        }
        None => {
            warn_port_held(endpoint.port);
            false
        }
    }
}

/// Bring this workspace's relay in line with a container `dev up` is
/// reusing. The key can have been flipped either way since the container was
/// created, and its baked environment is the only record of what it dials.
pub(crate) async fn reconcile_relay(
    consent: &RelayConsent,
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    dev_home: &DevHome,
    workspace: &Path,
) {
    // A container created while the relay was consented to keeps a working
    // endpoint baked in, so a permission since withdrawn has to take the
    // daemon down here as surely as an unset key does.
    if !consent.decision().is_on() {
        stop_relay(dev_home, workspace);
        return;
    }
    match read_endpoint(runtime, container_id, user).await {
        Some(endpoint) => {
            let container = TokenSink::new(runtime, container_id, user);
            if ensure_relay(dev_home, workspace, &endpoint, &container).await {
                consent.announce(endpoint.port);
            }
        }
        None => eprintln!(
            "Warning: {RELAY_PROPERTY} is on, but this container was created without a relay \
             endpoint. Recreate it with `dev up --rebuild` to enable agent forwarding."
        ),
    }
}

/// Stop this workspace's relay if one is running, and clear its state file
/// either way. A listener that can sign with the user's keys must not
/// outlive the container it was opened for.
pub(crate) fn stop_relay(dev_home: &DevHome, workspace: &Path) {
    let hash = workspace_hash(workspace);
    if let Some(held) = relay_lock_is_held(dev_home, &hash) {
        if read_relay_state_in(dev_home, &hash).is_some() {
            kill_locked_daemon(dev_home, &hash, held);
        } else {
            eprintln!(
                "Warning: an SSH agent relay is running for this workspace but has not recorded \
                 itself yet, so it could not be stopped."
            );
        }
    }
    remove_relay_state_in(dev_home, &hash);
}

// --- The daemon process itself ------------------------------------------

/// The listener `dev up` bound before the container existed, handed over as
/// this process's stdin. Binding here instead would leave a window in which
/// another local process could take the port and be handed the token by the
/// first shim that dialed it.
fn inherited_listener() -> anyhow::Result<TcpListener> {
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};

    const HANDOFF_FD: RawFd = 0;
    // Safe: `dev up` spawns this process with the listener on fd 0 and
    // nothing else in it reads or closes that descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(HANDOFF_FD) };
    let listener = std::net::TcpListener::from(inherited);
    listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("fd {HANDOFF_FD} is not the relay listener: {e}"))?;
    listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(listener)?)
}

/// The token this daemon admits on, refused when it is empty as well as
/// when it is unset: an empty one admits every local process, and no
/// container's shim would dial it. Nothing in the relay path can hand a
/// daemon an empty token now that [`parse_endpoint`] refuses the endpoint
/// that carried one, so this is defence in depth rather than a path anything
/// reaches. Takes the value rather than reading it, so it can be reached
/// without the fd 0 handover [`run_daemon`] needs.
fn daemon_token(from_env: Option<String>) -> anyhow::Result<String> {
    from_env
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{TOKEN_ENV} is unset or empty"))
}

/// The hidden relay process: take the listener it was handed, claim the
/// workspace, and serve until killed. The order is the invariant every
/// caller leans on — claim, then record, then serve — so that a daemon which
/// is serving is always one the next `dev up` or `dev down` can find.
///
/// Everything that can refuse to serve is settled before the claim, which
/// keeps "recorded" meaning "about to serve" and leaves a single file write
/// between the two rather than the agent probe's half second: a `dev down`
/// landing in that gap would signal whatever pid the *previous* daemon
/// recorded and report success over a relay that is still serving.
pub async fn run_daemon(workspace_hash: &str) -> anyhow::Result<()> {
    let listener = inherited_listener()?;
    let dev_home = DevHome::current();
    let token = daemon_token(std::env::var(TOKEN_ENV).ok())?;
    let upstream = upstream_path().ok_or_else(|| anyhow::anyhow!("SSH_AUTH_SOCK is not set"))?;
    if !upstream_answers(&upstream).await {
        anyhow::bail!("no agent answers at {}", upstream.display());
    }
    // Held for this process's whole life. Losing it means another daemon
    // already owns this workspace, which is how two racing ones resolve.
    let Some(_lock) = hold_relay_lock(&dev_home, workspace_hash) else {
        return Ok(());
    };
    let state = RelayState {
        port: listener.local_addr()?.port(),
        pid: std::process::id(),
    };
    write_relay_state_in(&dev_home, workspace_hash, &state)
        .ok_or_else(|| anyhow::anyhow!("could not record the relay state file"))?;
    accept_loop(listener, token, upstream).await;
    Ok(())
}

async fn accept_loop(listener: TcpListener, token: String, upstream: PathBuf) {
    while let Ok((stream, _)) = listener.accept().await {
        let token = token.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            serve(stream, &token, &upstream).await;
        });
    }
}

/// One connection: admit it, dial the agent fresh, then pipe until either
/// side closes. Never dials the agent before the token check passes — a
/// wrong token gets no reply and never reaches [`UnixStream::connect`].
async fn serve(stream: TcpStream, token: &str, upstream: &Path) -> Option<()> {
    let mut reader = BufReader::new(stream);
    admit(&mut reader, token).await?;
    let agent = UnixStream::connect(upstream).await.ok()?;
    // The reader, not the raw stream: anything the client pipelined behind
    // the handshake line is already in this buffer, and unwrapping would
    // drop it.
    reader.get_mut().write_all(b"ok\n").await.ok()?;
    pipe(reader, agent).await;
    Some(())
}

/// The handshake: `<protocol> <token>\n`, capped and deadlined so neither a
/// silent peer nor an oversized line can hold a connection open.
async fn admit(stream: &mut BufReader<TcpStream>, token: &str) -> Option<()> {
    let mut line = String::new();
    tokio::time::timeout(
        HANDSHAKE_DEADLINE,
        stream.take(MAX_HANDSHAKE).read_line(&mut line),
    )
    .await
    .ok()?
    .ok()
    .filter(|read| *read > 0)?;
    parse_handshake(line.trim_end_matches('\n'), token)
}

/// `None` is a refusal, and the caller never says which of the two fields
/// was wrong — same rule as `crate::cmux::agent::parse_header`. An empty
/// `token` refuses every line rather than matching an empty field: a daemon
/// with nothing to check is one nothing may be admitted to.
fn parse_handshake(line: &str, token: &str) -> Option<()> {
    let mut fields = line.split(' ');
    let protocol = fields.next()?;
    let sent = fields.next()?;
    (fields.next().is_none() && !token.is_empty() && protocol == PROTOCOL && sent == token)
        .then_some(())
}

/// Raw bytes both ways until either side closes, half-closing the opposite
/// direction on EOF — the same shape as `commands::forward::handle_connection`.
/// Unlike that relay's request/response framing, nothing here parses or
/// caps what flows after the handshake: the agent protocol is self-framing,
/// and a cap would truncate a large signature or certificate request.
async fn pipe(client: BufReader<TcpStream>, agent: UnixStream) {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut agent_read, mut agent_write) = agent.into_split();

    let agent_to_client = async {
        tokio::io::copy(&mut agent_read, &mut client_write).await?;
        client_write.shutdown().await
    };
    let client_to_agent = async {
        tokio::io::copy(&mut client_read, &mut agent_write).await?;
        agent_write.shutdown().await
    };

    tokio::select! {
        _ = agent_to_client => {}
        _ = client_to_agent => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::net::UnixListener;

    use super::*;
    use crate::devcontainer::jsonc::parse_jsonc;
    use crate::runtime::docker::DockerFlavor;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ExecResult, ImageMetadata,
    };

    const TOKEN: &str = "test-token-0123456789abcdef";
    /// `cargo test` has no per-test timeout, so every test below that reads
    /// from a live socket carries its own: a regression that stops answering
    /// must report a failure rather than wedge the suite.
    const TEST_BOUND: Duration = Duration::from_secs(10);
    const CLIENT_TO_AGENT: &[u8] = b"hello agent";
    const AGENT_TO_CLIENT: &[u8] = b"hello client";

    /// A stand-in for `$SSH_AUTH_SOCK`: a real `UnixListener` in a tempdir.
    /// `serve` dials it exactly as it would dial the real agent, so this
    /// proves the pipe rather than assuming it.
    fn spawn_fake_agent(path: PathBuf) -> tokio::task::JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
            let listener = UnixListener::bind(&path).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut from_client = vec![0u8; CLIENT_TO_AGENT.len()];
            stream.read_exact(&mut from_client).await.unwrap();
            stream.write_all(AGENT_TO_CLIENT).await.unwrap();
            from_client
        })
    }

    #[tokio::test]
    async fn the_handshake_admits_the_session_token_and_pipes_both_ways() {
        tokio::time::timeout(TEST_BOUND, async {
            let tmp = tempfile::tempdir().unwrap();
            let agent_path = tmp.path().join("agent.sock");
            let agent = spawn_fake_agent(agent_path.clone());

            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(stream, TOKEN, &agent_path).await
            });

            let mut client = TcpStream::connect(addr).await.unwrap();
            client
                .write_all(format!("{PROTOCOL} {TOKEN}\n").as_bytes())
                .await
                .unwrap();
            let mut ok = [0u8; 3];
            client.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"ok\n");

            client.write_all(CLIENT_TO_AGENT).await.unwrap();
            let mut from_agent = vec![0u8; AGENT_TO_CLIENT.len()];
            client.read_exact(&mut from_agent).await.unwrap();
            assert_eq!(from_agent, AGENT_TO_CLIENT);

            drop(client);
            assert_eq!(agent.await.unwrap(), CLIENT_TO_AGENT);
            assert!(server.await.unwrap().is_some());
        })
        .await
        .expect("an admitted handshake must pipe both ways within the bound");
    }

    /// The second assertion is the point: dialing the agent before the token
    /// check would let an unauthenticated peer open agent connections.
    #[tokio::test]
    async fn a_wrong_token_gets_no_reply_and_never_dials_the_agent() {
        tokio::time::timeout(TEST_BOUND, async {
            let tmp = tempfile::tempdir().unwrap();
            let agent_path = tmp.path().join("agent.sock");
            let agent_listener = UnixListener::bind(&agent_path).unwrap();
            let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel::<()>(1);
            tokio::spawn(async move {
                let _ = agent_listener.accept().await;
                let _ = accepted_tx.send(()).await;
            });

            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(stream, TOKEN, &agent_path).await
            });

            let mut client = TcpStream::connect(addr).await.unwrap();
            client
                .write_all(format!("{PROTOCOL} wrong-token\n").as_bytes())
                .await
                .unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert!(reply.is_empty(), "a wrong token must get no reply");
            assert!(server.await.unwrap().is_none());

            // A beat for a buggy implementation to have dialed the agent
            // before this checks: the point is that it never gets the chance.
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(
                accepted_rx.try_recv().is_err(),
                "a rejected handshake must never reach the agent"
            );
        })
        .await
        .expect("a refused handshake must be dropped within the bound");
    }

    /// Drive one handshake line through `serve` against an upstream that is
    /// never dialed on a refused handshake, and hand back what the client
    /// read. Shared by every refusal case below.
    async fn refused_handshake(line: &str) -> Vec<u8> {
        tokio::time::timeout(TEST_BOUND, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let bogus_upstream = PathBuf::from("/nonexistent/dev-ssh-agent-test.sock");
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(stream, TOKEN, &bogus_upstream).await
            });

            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(line.as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert!(server.await.unwrap().is_none());
            reply
        })
        .await
        .expect("a refused handshake must be dropped within the bound")
    }

    #[tokio::test]
    async fn another_protocol_version_is_refused() {
        assert!(
            refused_handshake(&format!("dev-ssh-agent/2 {TOKEN}\n"))
                .await
                .is_empty()
        );
        assert!(
            refused_handshake(&format!("dev-ssh-agent {TOKEN}\n"))
                .await
                .is_empty()
        );
    }

    /// Real time, unlike its neighbours: a paused clock auto-advances to the
    /// next timer whenever the runtime idles, so an outer bound on virtual
    /// time fires while the socket this is watching is still closing. The
    /// handshake deadline is what this costs.
    #[tokio::test]
    async fn a_handshake_that_never_arrives_is_dropped() {
        tokio::time::timeout(TEST_BOUND, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let bogus_upstream = PathBuf::from("/nonexistent/dev-ssh-agent-test.sock");
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(stream, TOKEN, &bogus_upstream).await
            });

            let mut client = TcpStream::connect(addr).await.unwrap();

            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert!(
                reply.is_empty(),
                "a connection that never sends a handshake must be dropped, not answered"
            );
            assert!(server.await.unwrap().is_none());
        })
        .await
        .expect("a silent connection must be dropped within the bound");
    }

    #[tokio::test]
    async fn an_oversized_handshake_line_is_refused() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bogus_upstream = PathBuf::from("/nonexistent/dev-ssh-agent-test.sock");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve(stream, TOKEN, &bogus_upstream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let oversized = vec![b'x'; MAX_HANDSHAKE as usize + 64];
        client.write_all(&oversized).await.unwrap();

        let mut reply = Vec::new();
        // Bounded so an unbounded read shows up as a failed test rather than
        // a hung one.
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .expect("an unbounded read would hang here instead of closing")
            .unwrap();
        assert!(
            reply.is_empty(),
            "an oversized handshake line must be refused, not buffered"
        );
        assert!(server.await.unwrap().is_none());
    }

    /// A daemon with no token to check must admit nobody rather than admit
    /// whoever sends an empty field. Nothing in the relay path can hand it
    /// an empty token now, so this is the layer under the one
    /// [`parse_endpoint`] holds.
    #[test]
    fn a_daemon_with_an_empty_token_admits_nothing() {
        for line in [format!("{PROTOCOL} "), format!("{PROTOCOL} {TOKEN}")] {
            assert!(
                parse_handshake(&line, "").is_none(),
                "an empty daemon token admitted {line:?}"
            );
        }
        assert!(
            parse_handshake(&format!("{PROTOCOL} {TOKEN}"), TOKEN).is_some(),
            "a real token still admits its own handshake"
        );
    }

    /// The same gate one layer down, where the daemon reads the token it
    /// will serve on. [`daemon_token`] takes the value rather than reading
    /// the environment itself, which is what makes it reachable here without
    /// a daemon spawn and an fd 0 handover.
    #[test]
    fn a_daemon_refuses_to_start_without_a_token_to_check() {
        assert!(
            daemon_token(None).is_err(),
            "an unset {TOKEN_ENV} must stop the daemon"
        );
        assert!(
            daemon_token(Some(String::new())).is_err(),
            "an empty {TOKEN_ENV} must stop the daemon, not admit every local process"
        );
        assert_eq!(
            daemon_token(Some(TOKEN.to_string())).expect("a real token starts the daemon"),
            TOKEN
        );
    }

    /// Two aliases, so the literal that used to live here cannot quietly
    /// come back — the same reasoning `cmux::agent`'s own env test uses.
    #[test]
    fn the_container_is_handed_the_alias_address_and_the_token() {
        let token = "a".repeat(64);
        for alias in ["host.docker.internal", "host.containers.internal"] {
            let env: HashMap<_, _> = upstream_env(alias, 51482, &token).into_iter().collect();
            assert_eq!(env[UPSTREAM_ENV], format!("tcp:{alias}:51482"));
            assert_eq!(env[TOKEN_CONTAINER_ENV], token);
        }
    }

    #[test]
    fn the_endpoint_is_read_back_from_the_container_environment() {
        let token = "b".repeat(64);
        let well_formed = format!(
            "DEV_SSH_AGENT_UPSTREAM=tcp:host.docker.internal:51482\nDEV_SSH_AGENT_TOKEN={token}\n"
        );
        let with_banner = format!(
            "Welcome to Ubuntu 24.04.1 LTS\nDEV_SSH_AGENT_UPSTREAM=tcp:host.docker.internal:51482\nDEV_SSH_AGENT_TOKEN={token}\n"
        );
        let no_token = "DEV_SSH_AGENT_UPSTREAM=tcp:host.docker.internal:51482\n".to_string();
        let unix_upstream = format!(
            "DEV_SSH_AGENT_UPSTREAM=unix:/ssh-agent/host-agent.sock\nDEV_SSH_AGENT_TOKEN={token}\n"
        );
        let empty_token =
            "DEV_SSH_AGENT_UPSTREAM=tcp:host.docker.internal:51482\nDEV_SSH_AGENT_TOKEN=\n"
                .to_string();

        type Case<'a> = (&'a str, &'a str, Option<(u16, &'a str)>);
        let cases: [Case; 6] = [
            (
                "a well-formed tcp: and token pair",
                well_formed.as_str(),
                Some((51482, token.as_str())),
            ),
            ("empty output", "", None),
            ("a tcp: line with no token", no_token.as_str(), None),
            (
                "a unix: upstream -- nothing for this daemon to start",
                unix_upstream.as_str(),
                None,
            ),
            (
                "a login shell's own banner mixed into the same stdout",
                with_banner.as_str(),
                Some((51482, token.as_str())),
            ),
            (
                "an empty token, which is how the read-back prints an unset var \
                 and what a project's own containerEnv can name an upstream without",
                empty_token.as_str(),
                None,
            ),
        ];

        for (name, stdout, expected) in cases {
            let got = parse_endpoint(stdout);
            match expected {
                Some((port, token)) => {
                    let endpoint = got.unwrap_or_else(|| panic!("{name}: expected an endpoint"));
                    assert_eq!(endpoint.port, port, "{name}");
                    assert_eq!(endpoint.token, token, "{name}");
                }
                None => assert!(got.is_none(), "{name}: expected no endpoint"),
            }
        }
    }

    /// Every field of the upstream a container names has to mean something,
    /// and a project's own `containerEnv` is what can name it. Port zero is
    /// the costly one: `bind_relay_port(0)` always succeeds, so a repository
    /// that names it makes every `dev up` stop the workspace's daemon and
    /// start a replacement on a port nothing was told to dial.
    #[test]
    fn an_upstream_is_read_only_when_every_field_means_something() {
        let cases = [
            ("tcp:host.docker.internal:51482", Some(51482)),
            ("tcp:h:00080", Some(80)),
            ("tcp:h:65535", Some(65535)),
            ("tcp::51482", None),
            ("tcp:h:0", None),
            ("tcp:h:+80", None),
            ("tcp:h: 80", None),
            ("tcp:h:65536", None),
            ("tcp:h:", None),
            ("tcp:h", None),
            ("tcp:", None),
            ("unix:/ssh-agent/host-agent.sock", None),
            ("", None),
        ];

        for (upstream, expected) in cases {
            assert_eq!(upstream_port(upstream), expected, "upstream={upstream:?}");
        }
    }

    /// The read-back is a shell command on one side and a parser on the
    /// other, and nothing in the type system holds them together: running
    /// the real command against a real shell and feeding its stdout to the
    /// real parser is what catches a pair that has stopped agreeing.
    /// `printenv DEV_SSH_AGENT_UPSTREAM DEV_SSH_AGENT_TOKEN` prints bare
    /// values and fails exactly here.
    #[test]
    fn the_read_back_command_produces_what_the_parser_reads() {
        let token = "c".repeat(64);
        let command = read_endpoint_command();
        let output = std::process::Command::new(&command[0])
            .args(&command[1..])
            .env(UPSTREAM_ENV, "tcp:host.docker.internal:51482")
            .env(TOKEN_CONTAINER_ENV, &token)
            .output()
            .expect("sh should run the read-back command");

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.lines().count(),
            2,
            "the read-back must print exactly the two vars, got: {stdout:?}"
        );
        let endpoint = parse_endpoint(&stdout).expect("the parser must read its own command back");
        assert_eq!(endpoint.port, 51482);
        assert_eq!(endpoint.token, token);
    }

    /// A container that was never handed a relay answers with empty values,
    /// which must read as no endpoint rather than as a port of zero.
    #[test]
    fn the_read_back_command_reports_unset_vars_as_no_endpoint() {
        let command = read_endpoint_command();
        let output = std::process::Command::new(&command[0])
            .args(&command[1..])
            .env_remove(UPSTREAM_ENV)
            .env_remove(TOKEN_CONTAINER_ENV)
            .output()
            .expect("sh should run the read-back command");

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout, format!("{UPSTREAM_ENV}=\n{TOKEN_CONTAINER_ENV}=\n"));
        assert!(parse_endpoint(&stdout).is_none());
    }

    /// A value carrying a newline must not be able to forge the other field.
    /// A project's `containerEnv` is what sets these, so choosing between a
    /// forged line and the real one would let a repository pick the token
    /// that guards the user's agent. Refusing the read is the answer.
    #[test]
    fn a_newline_in_one_value_cannot_forge_the_other() {
        let command = read_endpoint_command();
        let output = std::process::Command::new(&command[0])
            .args(&command[1..])
            .env(
                UPSTREAM_ENV,
                format!("tcp:host.docker.internal:51482\n{TOKEN_CONTAINER_ENV}=forged"),
            )
            .env(TOKEN_CONTAINER_ENV, "the-real-token")
            .output()
            .expect("sh should run the read-back command");

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("=forged"),
            "the forged line must actually reach the parser, got: {stdout:?}"
        );
        assert!(
            parse_endpoint(&stdout).is_none(),
            "a forged second line must refuse the read, not win it"
        );
    }

    /// The decision table this relay is built on. Which rows stop a daemon
    /// is not part of it: [`kill_locked_daemon`] takes a [`LockHeld`], so
    /// only a caller holding the probe's own answer can signal anything, and
    /// the two `Serve` rows differ by whether that probe found one.
    #[test]
    fn a_reused_container_gets_the_port_it_was_told_or_a_refusal() {
        const WANTED: u16 = 51482;
        let cases = [
            (
                "our daemon already serves that port",
                true,
                false,
                Some(WANTED),
                ReuseAction::Leave,
            ),
            (
                "our daemon is stale on an old port and a foreigner holds this one",
                true,
                false,
                Some(4242),
                ReuseAction::Reclaim,
            ),
            (
                "no daemon of ours, and something else owns the port",
                false,
                false,
                None,
                ReuseAction::Decline,
            ),
            (
                "our daemon is alive on another port and this one is free",
                true,
                true,
                Some(4242),
                ReuseAction::Serve,
            ),
            (
                "cold start, typically after a reboot",
                false,
                true,
                None,
                ReuseAction::Serve,
            ),
        ];

        for (name, lock_held, bound, recorded_port, expected) in cases {
            assert_eq!(
                reuse_action(lock_held, bound, recorded_port, WANTED),
                expected,
                "{name}"
            );
        }
    }

    /// A signing credential in every `ps` is the failure this guards: the
    /// token reaches the daemon by environment and must never appear in an
    /// argument, and the daemon takes no address at all now that the parent
    /// hands over the listener it bound.
    #[test]
    fn the_daemon_is_handed_its_token_by_environment_and_never_by_argv() {
        let token = "d".repeat(64);
        let command = daemon_command(PathBuf::from("/usr/local/bin/dev"), "abc123", &token);

        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["ssh-agent-relay", "--workspace-hash", "abc123"]);
        assert!(
            !args.iter().any(|arg| arg.contains(&token)),
            "the token must not be in argv, got: {args:?}"
        );
        let env: Vec<_> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(
            env.contains(&(TOKEN_ENV.to_string(), Some(token.clone()))),
            "the token must reach the daemon by environment, got: {env:?}"
        );
    }

    /// A daemon that dies during startup writes its reason to a nulled
    /// stderr and leaves the spawn looking like a success, so the recorded
    /// pid is the only evidence `dev up` has that anything is about to
    /// serve the port the container was just told to dial.
    #[tokio::test]
    async fn a_daemon_is_ready_once_it_has_recorded_its_own_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let mut daemon = spawn_a_long_lived_process();
        write_relay_state_in(
            &home,
            "abc123",
            &RelayState {
                port: 51482,
                pid: daemon.id(),
            },
        )
        .expect("the state file writes");

        let ready = daemon_records_itself(&home, "abc123", &mut daemon).await;

        let _ = daemon.kill();
        let _ = daemon.wait();
        assert!(
            ready,
            "a daemon that recorded itself must be reported ready"
        );
    }

    /// The state file a previous daemon left names the very port this one
    /// was handed, and on the reuse path it usually does, so only the pid
    /// tells the two apart. Virtual time here: the budget is what the wait
    /// costs, and a check that matched on the port alone would return
    /// without spending any of it.
    #[tokio::test(start_paused = true)]
    async fn a_pid_a_previous_daemon_recorded_is_not_evidence_this_one_started() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let predecessor = spawn_a_long_lived_process();
        let mut daemon = spawn_a_long_lived_process();
        write_relay_state_in(
            &home,
            "abc123",
            &RelayState {
                port: 51482,
                pid: predecessor.id(),
            },
        )
        .expect("the state file writes");

        let started = tokio::time::Instant::now();
        let ready = daemon_records_itself(&home, "abc123", &mut daemon).await;
        let elapsed = started.elapsed();

        for mut child in [predecessor, daemon] {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(
            !ready,
            "another process's pid must not be read as this daemon's claim"
        );
        assert_eq!(
            elapsed, DAEMON_READY_TIMEOUT,
            "a daemon that never records itself must be waited for exactly its budget"
        );
    }

    /// The other way the wait ends: a daemon that exited has nothing left to
    /// wait for, and spending the whole budget on it delays the warning the
    /// user needs by three seconds of every `dev up`.
    #[tokio::test]
    async fn a_daemon_that_exits_during_startup_is_not_waited_out() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let mut daemon = std::process::Command::new("true")
            .spawn()
            .expect("true should spawn");

        let started = std::time::Instant::now();
        let ready = daemon_records_itself(&home, "abc123", &mut daemon).await;
        let elapsed = started.elapsed();

        assert!(!ready, "a daemon that exited never recorded itself");
        assert!(
            elapsed < DAEMON_READY_TIMEOUT,
            "an exited daemon must end the wait, not be waited out: took {elapsed:?}"
        );
    }

    /// The window this closes: binding the port to learn its number and
    /// dropping the listener lets any local process take it before the
    /// daemon comes up, and the shim hands over the token the instant the
    /// socket opens.
    #[tokio::test]
    async fn the_minted_port_stays_bound_until_the_daemon_is_handed_it() {
        let tmp = tempfile::tempdir().unwrap();
        let agent_path = tmp.path().join("agent.sock");
        let _agent = UnixListener::bind(&agent_path).unwrap();

        let (alias, pending) = wanted_endpoint_from(
            RelayDecision::On,
            HostAccess::for_flavor(DockerFlavor::OrbStack),
            Some(agent_path),
        )
        .await
        .expect("every gate agrees, so an endpoint must be minted");

        assert_eq!(alias, "host.docker.internal");
        assert!(
            TcpListener::bind(("127.0.0.1", pending.endpoint.port))
                .await
                .is_err(),
            "the minted port must still be held, not released for anything to take"
        );

        let env: HashMap<_, _> =
            upstream_env(alias, pending.endpoint.port, &pending.endpoint.token)
                .into_iter()
                .collect();
        assert_eq!(
            env[UPSTREAM_ENV],
            format!("tcp:{alias}:{}", pending.endpoint.port)
        );
        assert_eq!(env[TOKEN_CONTAINER_ENV], pending.endpoint.token);
        assert_ne!(
            pending.endpoint.token,
            pending.endpoint.port.to_string(),
            "the container is handed the minted token, not the port"
        );
    }

    /// The recreate that used to go wrong: a new container minting the port
    /// its predecessor's daemon still holds, which left that daemon alive on
    /// the port with the old token while the container carried the new one,
    /// and every handshake refused. A live listener is a port `bind(0)` will
    /// not hand out, so the collision cannot happen, and the create path has
    /// no compare-the-recorded-port branch to return early on.
    #[tokio::test]
    async fn a_recreate_never_mints_the_port_a_surviving_daemon_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let agent_path = tmp.path().join("agent.sock");
        let _agent = UnixListener::bind(&agent_path).unwrap();

        // Standing in for the daemon of the container being replaced.
        let survivor = TcpListener::bind((BIND_IP, 0)).await.unwrap();
        let survivor_port = survivor.local_addr().unwrap().port();

        // Held, not dropped, so no two rounds can be handed the same port
        // either.
        let mut minted = Vec::new();
        for _ in 0..8 {
            let (_, pending) = wanted_endpoint_from(
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::OrbStack),
                Some(agent_path.clone()),
            )
            .await
            .expect("every gate agrees, so an endpoint must be minted");
            minted.push(pending);
        }

        assert!(
            minted
                .iter()
                .all(|pending| pending.endpoint.port != survivor_port),
            "a recreate was handed the port a live daemon is serving"
        );
        let tokens: std::collections::HashSet<_> = minted
            .iter()
            .map(|pending| pending.endpoint.token.as_str())
            .collect();
        assert_eq!(
            tokens.len(),
            minted.len(),
            "every container is handed a token of its own"
        );
    }

    /// A dead 1Password is the case: no agent answers, so nothing is minted
    /// and no container is told to dial a relay that will never serve.
    #[tokio::test]
    async fn no_endpoint_is_minted_when_the_agent_does_not_answer() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            wanted_endpoint_from(
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::OrbStack),
                Some(tmp.path().join("nothing-here.sock")),
            )
            .await
            .is_none()
        );
        assert!(
            wanted_endpoint_from(
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::OrbStack),
                None,
            )
            .await
            .is_none(),
            "a shell with no SSH_AUTH_SOCK has no agent to relay"
        );
    }

    /// Retry `attempt` for a second before giving up. Another test in this
    /// binary spawning a process forks a copy of every open descriptor, and
    /// that copy keeps the lock until the child `exec`s, so "free" is only
    /// ever true within a beat here. `dev` itself never sees this: the daemon
    /// holds its lock for its whole life, and a parent closes its probe
    /// before it spawns anything.
    fn within_a_beat<T>(mut attempt: impl FnMut() -> Option<T>) -> Option<T> {
        for _ in 0..50 {
            if let Some(value) = attempt() {
                return Some(value);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    fn lock_is_released(home: &DevHome, hash: &str) -> bool {
        within_a_beat(|| relay_lock_is_held(home, hash).is_none().then_some(())).is_some()
    }

    /// Two daemons racing for the same workspace resolve here, and the
    /// kernel releases the lock on process death, so nothing has to clean
    /// one up after a crash or a reboot.
    #[test]
    fn only_one_daemon_can_claim_a_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());

        assert!(
            relay_lock_is_held(&home, "abc123").is_none(),
            "a workspace that has never run a relay is free"
        );
        assert!(
            !home.ssh_relay_lock_file("abc123").exists(),
            "probing must not leave a lock file behind for every workspace"
        );

        let claim = hold_relay_lock(&home, "abc123").expect("the first claim wins");
        assert!(
            hold_relay_lock(&home, "abc123").is_none(),
            "the second loses"
        );
        assert!(relay_lock_is_held(&home, "abc123").is_some());
        assert!(
            relay_lock_is_held(&home, "def456").is_none(),
            "the lock is per workspace"
        );

        drop(claim);
        assert!(
            lock_is_released(&home, "abc123"),
            "closing the file releases the claim"
        );
        assert!(
            within_a_beat(|| hold_relay_lock(&home, "abc123")).is_some(),
            "a released workspace can be claimed again"
        );
    }

    /// Probing must never leave the lock held: the daemon is spawned right
    /// after and would fail to claim the workspace it was started for.
    #[test]
    fn probing_the_lock_does_not_hold_it() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        drop(hold_relay_lock(&home, "abc123").expect("create the lock file"));

        assert!(lock_is_released(&home, "abc123"));
        assert!(
            within_a_beat(|| hold_relay_lock(&home, "abc123")).is_some(),
            "a daemon spawned after a probe must still be able to claim the lock"
        );
    }

    fn spawn_a_long_lived_process() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep should spawn")
    }

    /// The state file outlives a reboot and pids restart low, so a recorded
    /// pid on its own names whatever inherited it. Without the lock probe
    /// this is `dev down` terminating an unrelated process of the user's.
    #[test]
    fn a_recorded_pid_is_left_alone_when_no_daemon_holds_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let workspace = tmp.path().join("workspace");
        let hash = workspace_hash(&workspace);
        let mut bystander = spawn_a_long_lived_process();
        write_relay_state_in(
            &home,
            &hash,
            &RelayState {
                port: 51482,
                pid: bystander.id(),
            },
        )
        .expect("the state file writes");

        stop_relay(&home, &workspace);

        let ended = bystander.try_wait().expect("the bystander can be polled");
        let _ = bystander.kill();
        let _ = bystander.wait();
        assert!(
            ended.is_none(),
            "a pid recorded under no lock must be left alone"
        );
        assert!(
            !home.ssh_relay_state_file(&hash).exists(),
            "the stale state file must still be cleared"
        );
    }

    /// The other half: a held lock means a live daemon of ours, and `dev
    /// down` must stop it rather than leave a listener that can sign with
    /// the user's keys outliving its container.
    #[test]
    fn a_recorded_daemon_is_stopped_when_the_lock_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let workspace = tmp.path().join("workspace");
        let hash = workspace_hash(&workspace);
        // Standing in for the daemon: this process holds the claim while a
        // separate one plays the pid the state file records.
        let claim = hold_relay_lock(&home, &hash).expect("the lock is free");
        let mut daemon = spawn_a_long_lived_process();
        let pid = daemon.id();
        write_relay_state_in(&home, &hash, &RelayState { port: 51482, pid })
            .expect("the state file writes");
        let reaper = std::thread::spawn(move || daemon.wait());

        stop_relay(&home, &workspace);

        let status = reaper
            .join()
            .expect("the reaper thread joins")
            .expect("the recorded process is waited on");
        assert!(!status.success(), "the recorded daemon must be stopped");
        assert!(!home.ssh_relay_state_file(&hash).exists());
        drop(claim);
    }

    /// An interrupted write used to leave unparsable JSON, and `dev down`
    /// then read nothing and stopped nothing. Rename is what makes the file
    /// either the old state or the new one.
    #[test]
    fn the_state_file_is_replaced_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let path = home.ssh_relay_state_file("abc123");
        write_relay_state_in(
            &home,
            "abc123",
            &RelayState {
                port: 1111,
                pid: 11,
            },
        )
        .unwrap();
        let first = std::fs::metadata(&path).unwrap();

        write_relay_state_in(
            &home,
            "abc123",
            &RelayState {
                port: 2222,
                pid: 22,
            },
        )
        .unwrap();

        assert_eq!(read_relay_state_in(&home, "abc123").unwrap().port, 2222);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1,
            "the temporary file must not be left behind"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                first.ino(),
                std::fs::metadata(&path).unwrap().ino(),
                "a rewrite must replace the file, not truncate it in place"
            );
        }
    }

    fn config_with_relay(enabled: bool) -> DevcontainerConfig {
        parse_jsonc(&format!(r#"{{"sshAgent": {{"relay": {enabled}}}}}"#))
            .expect("json should parse")
    }

    /// A `DevHome` whose base config holds `base`, or has no base file at
    /// all when `None` — the shape a machine that has never run
    /// `dev base config set` is in.
    fn home_with_base(tmp: &tempfile::TempDir, base: Option<&str>) -> DevHome {
        let home = DevHome::at(tmp.path());
        if let Some(contents) = base {
            let path = home.base_config();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, contents).unwrap();
        }
        home
    }

    fn consent(config: &DevcontainerConfig, home: &DevHome) -> RelayConsent {
        RelayConsent::resolve_in(
            config,
            Path::new("/ws/.devcontainer/devcontainer.json"),
            home,
        )
    }

    /// The regression that guards the whole fix: a project can put anything
    /// into the merged config, `allowRelay` included, so a permission read
    /// off the merged value is a permission the repository grants itself.
    ///
    /// Both base shapes, because they fail closed by different routes. A base
    /// that exists and parses and simply does not mention the key is the one
    /// every machine is in, and it is the shape that actually walks the
    /// lookup; a machine with no base file at all short-circuits before the
    /// walk and would keep passing on its own.
    #[test]
    fn a_merged_allow_relay_grants_nothing_whatever_the_base_says() {
        let config: DevcontainerConfig =
            parse_jsonc(r#"{"sshAgent": {"relay": true, "allowRelay": true}}"#)
                .expect("json should parse");

        let tmp = tempfile::tempdir().unwrap();
        let present = home_with_base(&tmp, Some(r#"{"remoteUser": "vscode"}"#));
        assert!(
            present.base_config().is_file(),
            "the base file must be present and parseable for this half"
        );
        assert_eq!(
            relay_decision_in(&config, &present),
            RelayDecision::RequestedNotAllowed,
            "a base that says nothing about the relay grants nothing"
        );

        let tmp = tempfile::tempdir().unwrap();
        let absent = home_with_base(&tmp, None);
        assert!(
            !absent.base_config().exists(),
            "the base file must be absent for this half"
        );
        assert_eq!(
            relay_decision_in(&config, &absent),
            RelayDecision::RequestedNotAllowed,
            "a machine that has never written a base config grants nothing"
        );
    }

    /// The four rows of the decision, each with what `dev up` says about it.
    /// The refused row is the security event: it has to name the file that
    /// asked, say the base decided, and name the command that would permit
    /// it, or the user goes looking in the project for a switch that is not
    /// there.
    #[test]
    fn the_four_consent_rows_decide_and_report() {
        let allowed = r#"{"sshAgent": {"allowRelay": true}}"#;

        // Row 1: nothing asked, nothing granted.
        let tmp = tempfile::tempdir().unwrap();
        let off = consent(&config_with_relay(false), &home_with_base(&tmp, None));
        assert_eq!(off.decision(), RelayDecision::Off);
        assert_eq!(off.refusal_message(), None);

        // Row 2: granted, but this project never asked.
        let tmp = tempfile::tempdir().unwrap();
        let unasked = consent(
            &config_with_relay(false),
            &home_with_base(&tmp, Some(allowed)),
        );
        assert_eq!(unasked.decision(), RelayDecision::Off);
        assert_eq!(unasked.refusal_message(), None);

        // Row 3: asked without a grant.
        let tmp = tempfile::tempdir().unwrap();
        let home = home_with_base(&tmp, Some(r#"{"remoteUser": "vscode"}"#));
        let refused = consent(&config_with_relay(true), &home);
        assert_eq!(refused.decision(), RelayDecision::RequestedNotAllowed);
        let message = refused
            .refusal_message()
            .expect("a refused request is a security event, not a silent no");
        assert!(
            message.contains("/ws/.devcontainer/devcontainer.json"),
            "the file that asked must be named: {message}"
        );
        assert!(
            message.contains(&home.base_config().display().to_string()),
            "the base config that refused must be named: {message}"
        );
        assert!(
            message.contains("dev base config set sshAgent.allowRelay true"),
            "the command that would permit it must be named: {message}"
        );

        // Row 4: asked and granted.
        let tmp = tempfile::tempdir().unwrap();
        let home = home_with_base(&tmp, Some(allowed));
        let on = consent(&config_with_relay(true), &home);
        assert_eq!(on.decision(), RelayDecision::On);
        assert_eq!(on.refusal_message(), None);
        let message = on.on_message(51482);
        assert!(
            message.contains("/ws/.devcontainer/devcontainer.json"),
            "the on-state names the file that asked: {message}"
        );
        assert!(
            message.contains(&home.base_config().display().to_string()),
            "the on-state names the file that allowed it: {message}"
        );
        assert!(
            message.contains("127.0.0.1:51482"),
            "the on-state names the address the keys are reachable at: {message}"
        );
    }

    /// The permission is a key of its own, in a file of its own. Neither
    /// name can stand in for the other, which is what stops a later
    /// refactor from collapsing "may" and "will" back into one key.
    #[test]
    fn neither_key_stands_in_for_the_other() {
        let tmp = tempfile::tempdir().unwrap();
        let project_asks = config_with_relay(true);

        // A base that only asks is not a base that grants.
        let asking_base = home_with_base(&tmp, Some(r#"{"sshAgent": {"relay": true}}"#));
        assert_eq!(
            relay_decision_in(&project_asks, &asking_base),
            RelayDecision::RequestedNotAllowed
        );

        // A grant is not a request: a project that never asked stays off.
        let tmp = tempfile::tempdir().unwrap();
        let granting_base = home_with_base(&tmp, Some(r#"{"sshAgent": {"allowRelay": true}}"#));
        let silent_project: DevcontainerConfig =
            parse_jsonc(r#"{"image": "ubuntu:24.04"}"#).expect("json should parse");
        assert_eq!(
            relay_decision_in(&silent_project, &granting_base),
            RelayDecision::Off
        );
    }

    /// A grant that is not the boolean `true` is not a grant. A base config
    /// full of `"allowRelay": "yes"` should fail closed rather than read as
    /// truthy.
    #[test]
    fn only_a_true_boolean_grants_the_relay() {
        for base in [
            r#"{"sshAgent": {"allowRelay": false}}"#,
            r#"{"sshAgent": {"allowRelay": "true"}}"#,
            r#"{"sshAgent": {"allowRelay": 1}}"#,
            r#"{"sshAgent": {}}"#,
            r#"{"sshAgent.allowRelay": true}"#,
            "{ not json at all",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let home = home_with_base(&tmp, Some(base));
            assert_eq!(
                relay_decision_in(&config_with_relay(true), &home),
                RelayDecision::RequestedNotAllowed,
                "{base} was read as a grant"
            );
        }
    }

    /// Table-driven over the consent decision and the three capability
    /// conditions, built from real `HostAccess` rows so each reads as a
    /// flavor rather than a loose bool.
    #[test]
    fn a_relay_is_wanted_only_when_every_gate_agrees() {
        let cases = [
            // OrbStack is the flavor this exists for: alias yes, loopback yes.
            (
                "OrbStack, consented",
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::OrbStack),
                true,
            ),
            (
                "OrbStack, nothing asked",
                RelayDecision::Off,
                HostAccess::for_flavor(DockerFlavor::OrbStack),
                false,
            ),
            // The security case: the project asked and the base did not
            // permit it. Every capability agrees, and it still must not run.
            (
                "OrbStack, asked but not allowed",
                RelayDecision::RequestedNotAllowed,
                HostAccess::for_flavor(DockerFlavor::OrbStack),
                false,
            ),
            // Colima has no gateway_alias, so no container has a name to dial.
            (
                "Colima, consented",
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::Colima),
                false,
            ),
            // Engine names an alias but reaches_host_loopback is false there.
            (
                "Engine, consented",
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::Engine),
                false,
            ),
            // Desktop's host_sockets_mount is true too, but consent is a
            // switch, not a veto: it must still start the relay.
            (
                "Desktop, consented",
                RelayDecision::On,
                HostAccess::for_flavor(DockerFlavor::DockerDesktop),
                true,
            ),
        ];

        for (name, relay, access, expected) in cases {
            assert_eq!(relay_wanted(relay, access), expected, "{name}");
        }
    }

    #[test]
    fn the_state_file_round_trips_and_is_not_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let state = RelayState {
            port: 51482,
            pid: 4242,
        };

        write_relay_state_in(&home, "abc123", &state).expect("the state file writes");
        let read_back = read_relay_state_in(&home, "abc123").expect("the state file reads back");
        assert_eq!(read_back.port, state.port);
        assert_eq!(read_back.pid, state.pid);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(home.ssh_relay_state_file("abc123"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the state file must not be world- or group-readable"
            );
        }
    }

    // --- The carried feature -------------------------------------------

    fn embedded(name: &str) -> &'static str {
        FEATURE_FILES
            .iter()
            .find(|(file, _)| *file == name)
            .map(|(_, contents)| *contents)
            .unwrap_or_else(|| panic!("{name} is not carried in the binary"))
    }

    /// The one thing that must not drift. Both halves of the handshake ship
    /// in the same artifact, so this only has to hold them to the same
    /// value — mirrors `crate::cmux::agent::tests::the_shim_declares_the_same_protocol`.
    #[test]
    fn the_ssh_shim_declares_the_same_protocol() {
        assert!(
            embedded("ssh-agent-upstream").contains(&format!("readonly PROTOCOL=\"{PROTOCOL}\"")),
            "the embedded shim does not declare {PROTOCOL}"
        );
    }

    /// The other thing that must not drift. `install.sh` decides where the
    /// shim actually lands and [`SHIM_PATH`] is what `dev status` and the
    /// base layer's relay script exec; a drift between them compiles, passes
    /// everything else, and shows up as a container with no agent.
    #[test]
    fn the_shim_is_installed_where_dev_looks_for_it() {
        let install = embedded("install.sh");
        let (dir, file) = SHIM_PATH.rsplit_once('/').expect("SHIM_PATH is absolute");
        assert!(
            install.contains(&format!("BIN_DIR={dir}\n")),
            "install.sh does not land the shim in {dir}"
        );
        assert!(
            install.contains(&format!("\"$BIN_DIR/{file}\"")),
            "install.sh does not install the shim as {file}"
        );
    }

    /// What the binary carries has to be the feature as written, or the repo
    /// and the shipped copy say different things.
    #[test]
    fn the_binary_carries_the_ssh_feature_as_written() {
        for (name, contents) in FEATURE_FILES {
            let on_disk = std::fs::read_to_string(format!("features/ssh-agent-relay/{name}"))
                .unwrap_or_else(|e| panic!("reading features/ssh-agent-relay/{name}: {e}"));
            assert_eq!(on_disk, contents, "features/ssh-agent-relay/{name} drifted");
        }
    }

    /// The point of embedding: a `dev` installed as a bare binary can still
    /// produce the feature, with nothing fetched and nothing copied by hand.
    #[test]
    fn staging_writes_the_whole_ssh_feature_out() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());

        let dir = stage_feature_in(&home).expect("staging writes the feature");

        assert_eq!(dir, tmp.path().join("features/ssh-agent-relay"));
        for (name, contents) in FEATURE_FILES {
            assert_eq!(std::fs::read_to_string(dir.join(name)).unwrap(), contents);
        }
    }

    /// Upgrading `dev` has to refresh a directory an older one already
    /// wrote, or a stale shim would outlive the protocol it was built
    /// against.
    #[test]
    fn staging_overwrites_what_an_older_run_left() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let dir = home.staged_feature_dir("ssh-agent-relay");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ssh-agent-upstream"), "#!/bin/sh\nexit 0\n").unwrap();

        stage_feature_in(&home).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.join("ssh-agent-upstream")).unwrap(),
            embedded("ssh-agent-upstream")
        );
    }

    /// These files are tarred into the build context, and that tar is a
    /// Docker cache key. A mode left to the umask makes the same `dev up`
    /// produce a different context from one shell than from another.
    ///
    /// Staging over files that are already 0600 is what makes this bite: a
    /// fresh `std::fs::write` lands on 0644 under the default umask all by
    /// itself, and truncating an existing file keeps whatever mode it had.
    #[cfg(unix)]
    #[test]
    fn staging_sets_modes_the_umask_cannot_move() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let dir = stage_feature_in(&home).expect("staging writes the feature");
        for (name, _) in FEATURE_FILES {
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        stage_feature_in(&home).expect("staging writes the feature again");

        for (name, _) in FEATURE_FILES {
            let mode = std::fs::metadata(dir.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644, "{name} kept the mode it was found at");
        }
    }

    // --- The shim itself, run for real -----------------------------------

    const SHIM_SCRIPT: &str = "features/ssh-agent-relay/ssh-agent-upstream";

    /// `bash` on the machine running `cargo test`, piped so a payload
    /// (including a NUL byte) can be pushed and read without going through a
    /// shell variable on this side either.
    fn spawn_shim(env: &[(&str, &str)]) -> tokio::process::Child {
        // A path that does not exist, so these rows read the environment and
        // never whatever `/run/dev-ssh/token` the host running the tests
        // happens to have.
        spawn_shim_reading("/nonexistent/dev-ssh-test/token", env)
    }

    fn spawn_shim_reading(token_file: &str, env: &[(&str, &str)]) -> tokio::process::Child {
        let mut command = tokio::process::Command::new("bash");
        command
            .arg(SHIM_SCRIPT)
            .arg(token_file)
            // Running `cargo test` inside a container this branch set up
            // would otherwise leave both vars set, and the rows that prove
            // what the shim does without them would pass for no reason.
            .env_remove(UPSTREAM_ENV)
            .env_remove(TOKEN_CONTAINER_ENV)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        for (key, value) in env {
            command.env(key, value);
        }
        command.spawn().expect("bash should spawn")
    }

    fn tcp_upstream(port: u16) -> String {
        format!("tcp:127.0.0.1:{port}")
    }

    /// The handshake, then the pump proven in both directions with a payload
    /// that contains a NUL byte — the one thing a shell variable would drop,
    /// which is why the pump may never route a payload through one.
    #[tokio::test]
    async fn the_shim_hands_over_its_token_then_streams_both_ways() {
        tokio::time::timeout(TEST_BOUND, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let mut child = spawn_shim(&[
                ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                ("DEV_SSH_AGENT_TOKEN", TOKEN),
            ]);
            let mut child_stdin = child.stdin.take().unwrap();
            let mut child_stdout = child.stdout.take().unwrap();

            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("{PROTOCOL} {TOKEN}\n"));
            let mut stream = reader.into_inner();
            stream.write_all(b"ok\n").await.unwrap();

            const TO_AGENT: &[u8] = b"\x00stdin-to-socket\x00";
            const TO_CLIENT: &[u8] = b"\x00socket-to-stdout\x00";

            child_stdin.write_all(TO_AGENT).await.unwrap();
            let mut from_stdin = vec![0u8; TO_AGENT.len()];
            stream.read_exact(&mut from_stdin).await.unwrap();
            assert_eq!(
                from_stdin, TO_AGENT,
                "a NUL byte from stdin must reach the socket unchanged"
            );

            stream.write_all(TO_CLIENT).await.unwrap();
            let mut from_socket = vec![0u8; TO_CLIENT.len()];
            child_stdout.read_exact(&mut from_socket).await.unwrap();
            assert_eq!(
                from_socket, TO_CLIENT,
                "a NUL byte from the socket must reach stdout unchanged"
            );

            drop(child_stdin);
            drop(stream);
            let _ = child.kill().await;
        })
        .await
        .expect("the shim must hand over the token and stream both ways within the bound");
    }

    /// `dev status` reads this exit status as its liveness check:
    /// an accepted handshake against a stream that then just ends must exit
    /// 0 having written nothing, without needing anything on stdin.
    #[tokio::test]
    async fn the_shim_exits_clean_when_the_stream_ends() {
        tokio::time::timeout(TEST_BOUND, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let mut child = spawn_shim(&[
                ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                ("DEV_SSH_AGENT_TOKEN", TOKEN),
            ]);
            drop(child.stdin.take().unwrap());

            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("{PROTOCOL} {TOKEN}\n"));
            let mut stream = reader.into_inner();
            stream.write_all(b"ok\n").await.unwrap();

            let output = child.wait_with_output().await.unwrap();
            assert!(
                output.status.success(),
                "an accepted handshake whose stream just ends must exit 0"
            );
            assert!(
                output.stdout.is_empty(),
                "nothing must be written to stdout"
            );
            drop(stream);
        })
        .await
        .expect("the shim must exit once the stream ends, not hang");
    }

    /// The token a container was created with lives in its environment for
    /// the container's whole life, because Docker cannot change that
    /// environment while it runs. The file is what `dev up` can replace, so
    /// it has to win.
    #[tokio::test]
    async fn the_shim_prefers_the_token_file_over_the_baked_in_one() {
        tokio::time::timeout(TEST_BOUND, async {
            let tmp = tempfile::tempdir().unwrap();
            let token_file = tmp.path().join("token");
            std::fs::write(&token_file, "rotated-token\n").unwrap();

            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut child = spawn_shim_reading(
                token_file.to_str().unwrap(),
                &[
                    ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                    ("DEV_SSH_AGENT_TOKEN", TOKEN),
                ],
            );

            let (stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("{PROTOCOL} rotated-token\n"));
            let _ = child.kill().await;
        })
        .await
        .expect("the shim must dial with the token file's value");
    }

    /// The fallback the previous test must not have removed: a container
    /// built before the token file existed carries only the environment, and
    /// a `/run` that cannot be written leaves it that way.
    #[tokio::test]
    async fn the_shim_falls_back_to_the_environment_when_there_is_no_token_file() {
        tokio::time::timeout(TEST_BOUND, async {
            let tmp = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut child = spawn_shim_reading(
                tmp.path().join("absent").to_str().unwrap(),
                &[
                    ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                    ("DEV_SSH_AGENT_TOKEN", TOKEN),
                ],
            );

            let (stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("{PROTOCOL} {TOKEN}\n"));
            let _ = child.kill().await;
        })
        .await
        .expect("an absent token file must leave the environment's copy in use");
    }

    /// The command runs inside a container under `sh -c` with `set -e`, so a
    /// mistake in it is a silent failure to rotate rather than a compile
    /// error. Running it for real against a temporary path is what catches
    /// that, and the mode is the point: a token any process in the container
    /// can read is no better than the environment it replaces.
    #[test]
    fn the_token_file_is_written_whole_and_unreadable_to_anyone_else() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("dev-ssh/token");
        let token = "e".repeat(64);
        let command = write_token_command(None, file.to_str().unwrap());

        let output = std::process::Command::new(&command[0])
            .args(&command[1..])
            .env(TOKEN_ENV, &token)
            .output()
            .expect("sh should run the write command");
        assert!(
            output.status.success(),
            "the write command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{token}\n"),
            "the shim's `read` needs the trailing newline"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the token file is readable by others");
            let dir = std::fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir & 0o777, 0o700, "the token directory is traversable");
        }
    }

    /// Same reason the daemon's own token travels by environment: a token in
    /// argv is a token in `ps` for every process in the container.
    #[test]
    fn the_container_token_reaches_it_by_environment_and_never_by_argv() {
        let token = "f".repeat(64);
        for user in [None, Some("dev")] {
            let command = write_token_command(user, TOKEN_FILE);
            assert!(
                !command.iter().any(|arg| arg.contains(&token)),
                "the token must not be in argv, got: {command:?}"
            );
            assert!(command[2].contains(&format!("${TOKEN_ENV}")));
            assert_eq!(
                command[2].contains("chown dev"),
                user.is_some(),
                "the file is handed to the remote user when there is one"
            );
        }
    }

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("not used by this test".into())) })
    }

    /// A container the token write either lands in or does not. `exit_code`
    /// stands in for the two ways a project can make it fail: a read-only
    /// `/run`, or an image whose root cannot `mkdir` there.
    struct WriteFakeRuntime {
        exit_code: i32,
        written: std::sync::Mutex<Vec<String>>,
    }

    impl WriteFakeRuntime {
        fn new(exit_code: i32) -> Self {
            WriteFakeRuntime {
                exit_code,
                written: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// What reached the container, read out of the exec's environment
        /// the way the shell command there reads it.
        fn tokens_written(&self) -> Vec<String> {
            self.written.lock().unwrap().clone()
        }
    }

    impl ContainerRuntime for WriteFakeRuntime {
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
            env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            for (name, value) in env {
                if name == TOKEN_ENV {
                    self.written
                        .lock()
                        .unwrap()
                        .push(value.expose().to_string());
                }
            }
            let exit_code = self.exit_code;
            Box::pin(async move {
                Ok(ExecResult {
                    stdout: String::new(),
                    stderr: "mkdir: cannot create directory '/run/dev-ssh': Read-only file system"
                        .to_string(),
                    exit_code,
                })
            })
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
    }

    /// There is deliberately no fallback to the token the container was
    /// created with: a project's own `containerEnv` sets that value and a
    /// project can make this write fail, so falling back would let a
    /// repository choose the credential guarding the user's agent.
    #[tokio::test]
    async fn a_container_that_cannot_take_a_token_rotates_to_nothing() {
        let runtime = WriteFakeRuntime::new(1);
        let sink = TokenSink::new(&runtime, "container-id", None);

        assert!(
            sink.rotate().await.is_none(),
            "a token that could not be delivered must not be reported as the one in effect"
        );
    }

    /// The other half: what a rotation returns is what the container was
    /// given, and every rotation mints a fresh one, which is what stops the
    /// token a previous run handed out from still signing.
    #[tokio::test]
    async fn a_rotation_gives_the_container_the_token_it_returns() {
        let runtime = WriteFakeRuntime::new(0);
        let sink = TokenSink::new(&runtime, "container-id", None);

        let first = sink.rotate().await.expect("a writable container rotates");
        let second = sink.rotate().await.expect("a writable container rotates");

        assert_ne!(first, second, "every rotation mints a token of its own");
        assert_eq!(
            runtime.tokens_written(),
            [first.clone(), second],
            "the container must be given the tokens the rotations returned"
        );
        assert_eq!(first.len(), 64, "a rotation returns a minted token");
    }

    /// Set for the child half of the test below, which is the run that
    /// actually calls [`ensure_relay`].
    const ROTATION_GATE_CHILD: &str = "DEV_TEST_SSH_ROTATION_GATE_CHILD";

    const GATE_TEST: &str =
        "ssh_agent::tests::a_reused_container_that_cannot_take_a_new_token_gets_no_daemon";

    /// The gate a compiler cannot hold: spawning here instead of warning
    /// type-checks, and leaves a daemon serving the user's agent on a token
    /// the container's own environment chose, on a port it also chose.
    ///
    /// The warning is the observable, so the call runs in a child of this
    /// test binary: `cargo test` captures `eprintln!` per test thread, and
    /// a daemon spawned from a test binary can never record itself, so
    /// [`spawn_daemon`]'s own warnings are what their absence rules out.
    #[test]
    fn a_reused_container_that_cannot_take_a_new_token_gets_no_daemon() {
        if std::env::var_os(ROTATION_GATE_CHILD).is_some() {
            decline_a_container_that_cannot_take_a_token();
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([GATE_TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROTATION_GATE_CHILD, "1")
            .output()
            .expect("the test binary re-runs itself");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "the child run failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed"),
            "the child must have run {GATE_TEST}, got:\n{stdout}"
        );
        assert!(
            stderr.contains(&format!("could not write {TOKEN_FILE}")),
            "a container that cannot take a new token must be reported, got:\n{stderr}"
        );
        for spawned in ["did not start", "could not be started"] {
            assert!(
                !stderr.contains(spawned),
                "no daemon may be spawned for a container that kept its old token, got:\n{stderr}"
            );
        }
    }

    /// CPU time charged to this process's reaped children. A daemon
    /// `ensure_relay` started is one it waited on, and a waited-on child's
    /// CPU time is all that is left of it once it is gone.
    fn reaped_children_cpu() -> Duration {
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) },
            0,
            "getrusage should answer"
        );
        let spent = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1_000);
        spent(usage.ru_utime) + spent(usage.ru_stime)
    }

    /// The child half. Everything it asserts on is its own state; the
    /// warnings it prints are the parent's.
    fn decline_a_container_that_cannot_take_a_token() {
        let tmp = tempfile::tempdir().unwrap();
        let home = DevHome::at(tmp.path());
        let workspace = tmp.path().join("workspace");
        let port = std::net::TcpListener::bind((BIND_IP, 0))
            .expect("a port to stand in for the one the container was told to dial")
            .local_addr()
            .unwrap()
            .port();
        let endpoint = Endpoint {
            port,
            // What a project's own `containerEnv` can name.
            token: "9".repeat(64),
        };
        let runtime = WriteFakeRuntime::new(1);
        let sink = TokenSink::new(&runtime, "container-id", None);

        let spawned_before = reaped_children_cpu();
        let serving = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(ensure_relay(&home, &workspace, &endpoint, &sink));

        assert!(
            !serving,
            "a relay that never started must not be reported as serving, or `dev up` announces \
             an agent the container cannot reach"
        );
        assert_eq!(
            runtime.tokens_written().len(),
            1,
            "the rotation must have been reached, or this proves nothing about it"
        );
        assert_eq!(
            reaped_children_cpu(),
            spawned_before,
            "a daemon was spawned for a container that kept the token it was created with"
        );
        assert!(
            read_relay_state_in(&home, &workspace_hash(&workspace)).is_none(),
            "a declined relay records no daemon"
        );
    }

    /// A relay that closes after an accepted handshake is what `dev down`
    /// leaves behind while a `dev shell` still holds an agent connection.
    /// Neither direction of the pump may be the only one that can end the
    /// script: stdin here stays open and unwritten throughout, so a shim
    /// that waits on it blocks an ssh that will never complete or fail.
    #[tokio::test]
    async fn the_shim_gives_up_when_the_relay_closes_under_it() {
        tokio::time::timeout(TEST_BOUND, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let mut child = spawn_shim(&[
                ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                ("DEV_SSH_AGENT_TOKEN", TOKEN),
            ]);
            let child_stdin = child.stdin.take().unwrap();

            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("{PROTOCOL} {TOKEN}\n"));
            let mut stream = reader.into_inner();
            stream.write_all(b"ok\n").await.unwrap();
            drop(stream);

            let output = child.wait_with_output().await.unwrap();
            assert!(
                output.status.success(),
                "a relay that closes after admitting the shim must end it cleanly"
            );
            drop(child_stdin);
        })
        .await
        .expect("the shim must end with the relay, not wait on a stdin nothing will write");
    }

    /// The normal case: a container carries the feature but was never handed
    /// a relay. None of these four rows may block on
    /// stdin before there is anywhere to send bytes — proven by leaving the
    /// write end open and unwritten throughout the wait, so a regression
    /// that reads stdin first hangs the test instead of passing it.
    #[tokio::test]
    async fn the_shim_fails_without_an_upstream_in_its_environment() {
        tokio::time::timeout(TEST_BOUND, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let live_upstream = tcp_upstream(addr.port());

            let cases: [(&str, &[(&str, &str)]); 4] = [
                ("an unset upstream", &[("DEV_SSH_AGENT_TOKEN", TOKEN)]),
                (
                    "an empty upstream",
                    &[
                        ("DEV_SSH_AGENT_UPSTREAM", ""),
                        ("DEV_SSH_AGENT_TOKEN", TOKEN),
                    ],
                ),
                (
                    "a unix: upstream",
                    &[
                        ("DEV_SSH_AGENT_UPSTREAM", "unix:/ssh-agent/host-agent.sock"),
                        ("DEV_SSH_AGENT_TOKEN", TOKEN),
                    ],
                ),
                (
                    "a tcp: upstream with no token",
                    &[("DEV_SSH_AGENT_UPSTREAM", live_upstream.as_str())],
                ),
            ];

            for (name, env) in cases {
                let mut child = spawn_shim(env);
                // Held open and never written to for the life of the wait:
                // the shim must decide it has nowhere to send bytes before
                // it ever reads this end.
                let child_stdin = child.stdin.take().unwrap();

                let output = child
                    .wait_with_output()
                    .await
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(!output.status.success(), "{name}: must exit non-zero");
                assert!(
                    output.stdout.is_empty(),
                    "{name}: must write nothing to stdout"
                );
                drop(child_stdin);
            }

            // The fourth row names a live listener; it must never be dialed,
            // since the token check comes before the upstream is even read.
            let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(
                accept.is_err(),
                "a tcp: upstream with no token must never be dialed"
            );
        })
        .await
        .expect("every row must fail within the bound, not hang");
    }

    /// A shim that pumps into a rejected connection hangs every `git push`
    /// instead of failing it, so both refusal shapes — a status other than
    /// `ok`, and a connection closed having written nothing — must exit
    /// non-zero without ever relaying a byte that follows the refusal.
    #[tokio::test]
    async fn the_shim_gives_up_when_the_handshake_is_refused() {
        tokio::time::timeout(TEST_BOUND, async {
            // A status other than "ok", on a connection kept open past the
            // refusal so a buggy pump has somewhere to read from.
            {
                let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let addr = listener.local_addr().unwrap();
                let child = spawn_shim(&[
                    ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                    ("DEV_SSH_AGENT_TOKEN", TOKEN),
                ]);

                let (mut stream, _) = listener.accept().await.unwrap();
                let mut line = String::new();
                BufReader::new(&mut stream)
                    .read_line(&mut line)
                    .await
                    .unwrap();
                stream.write_all(b"no\n").await.unwrap();

                // A beat for a buggy shim to start pumping before this reads
                // the far side back: the marker must never surface on
                // stdout.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = stream.write_all(b"should-never-be-pumped").await;

                let output = child.wait_with_output().await.unwrap();
                assert!(
                    !output.status.success(),
                    "a refused status must exit non-zero"
                );
                assert!(
                    output.stdout.is_empty(),
                    "a refused handshake must never reach the pump"
                );
            }

            // A connection closed having written nothing.
            {
                let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let addr = listener.local_addr().unwrap();
                let child = spawn_shim(&[
                    ("DEV_SSH_AGENT_UPSTREAM", &tcp_upstream(addr.port())),
                    ("DEV_SSH_AGENT_TOKEN", TOKEN),
                ]);

                let (mut stream, _) = listener.accept().await.unwrap();
                let mut line = String::new();
                BufReader::new(&mut stream)
                    .read_line(&mut line)
                    .await
                    .unwrap();
                drop(stream);

                let output = child.wait_with_output().await.unwrap();
                assert!(
                    !output.status.success(),
                    "a closed handshake must exit non-zero"
                );
                assert!(
                    output.stdout.is_empty(),
                    "a closed handshake must never reach the pump"
                );
            }
        })
        .await
        .expect("a refused handshake must exit within the bound, not hang");
    }
}
