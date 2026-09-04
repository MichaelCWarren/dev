//! The host end of the container agent relay.
//!
//! An agent running inside a container cannot reach cmux. The CLI is Mach-O,
//! and cmux's socket accepts only processes descended from one of its own
//! terminals, which no container process can be. `dev shell` is such a
//! descendant, so it listens on loopback and runs each forwarded verb against
//! the real CLI here.
//!
//! What reaches this listener from a container reaches it from anything else
//! on the host's loopback: Docker Desktop proxies `host.docker.internal`
//! through it, so the bind address gates nothing. The per-session token and
//! [`verb_allowed`] are the whole boundary.
//!
//! The container side is the `cmux-agent` feature's shim. It is installed at
//! build time, not copied in, because it needs a PATH entry only a root
//! build step can write. See `features/cmux-agent/`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::devcontainer::secrets::SecretValue;
use crate::runtime::ContainerRuntime;

use super::Spawner;

/// Bumped with the shim's own constant whenever the framing below changes. A
/// shim from an image built against an older `dev` is refused rather than
/// half-understood, and the wrapper reads that refusal as "no cmux" and runs
/// claude untouched.
const PROTOCOL: &str = "dev-cmux/1";

/// Where the `cmux-agent` feature installs its shim, and where the wrappers
/// are landed beside it. Each wrapper resolves the CLI as `$self_dir/cmux`, so
/// sharing one directory is what makes that lookup work without PATH.
const SHIM_DIR: &str = "/usr/local/share/dev-cmux/bin";

/// Where the `cmux-agent` feature installs its shim.
const SHIM_PATH: &str = "/usr/local/share/dev-cmux/bin/cmux";

/// The wrappers this relay can serve: cmux's own filename beside its CLI, and
/// the name the agent is invoked by.
///
/// cmux ships three wrappers and only claude's is here. codex's and grok's both
/// ask the CLI to generate hook scripts on disk, which through this relay means
/// the host's disk and host paths the container cannot run. Landing either
/// wrapper would wire an agent to files that are not there. See
/// [`WRITE_VERBS`], which is what refuses the calls themselves.
const WRAPPERS: [(&str, &str); 1] = [("cmux-claude-wrapper", "claude")];

/// An empty socket inode. The wrapper tests `-S` on this path before it will
/// ping, so the file has to exist and has to be a socket; nothing ever
/// connects to it, because the shim's channel is the relay, not this.
const SOCKET_PATH: &str = "/tmp/dev-cmux.sock";

/// Creates [`SOCKET_PATH`]. perl is Essential on every Debian and Ubuntu
/// image, which is more than can be said for python, socat, or nc.
const SOCKET_SCRIPT: &str = "\
    use Socket; \
    unlink $ARGV[0]; \
    socket(S, PF_UNIX, SOCK_STREAM, 0) || exit 1; \
    bind(S, sockaddr_un($ARGV[0])) || exit 1; \
    listen(S, 1) || exit 1;";

/// How long a forwarded verb may take. cmux allows its own PermissionRequest
/// hook 125s because the answer is a person's, so a shorter ceiling here
/// would cut off the one call whose result the agent actually waits on.
const CALL_TIMEOUT: Duration = Duration::from_secs(125);

/// Passed to the CLI for the same reason: its own default is 15s, which a
/// permission prompt outlives.
const RESPONSE_TIMEOUT: (&str, &str) = ("CMUXTERM_CLI_RESPONSE_TIMEOUT_SEC", "120");

/// A request is a header line, a few argument lines, and a payload. Nothing
/// cmux sends a hook approaches these, so they refuse malformed input rather
/// than bound anything legitimate.
const MAX_HEADER: u64 = 512;
const MAX_ARGS: usize = 8;
const MAX_BODY: usize = 1 << 20;

/// A listening relay, and the environment a container needs to reach it.
///
/// Aborting on drop is what ties the listener to the session: `dev shell`
/// holds one of these across `attend_session`, which returns on both its own
/// exit and a signal, so there is no path that leaves a port open.
pub struct Relay {
    addr: SocketAddr,
    token: String,
    task: JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    /// The environment that points cmux's wrapper at this relay.
    ///
    /// `CMUX_BUNDLED_CLI_PATH` is how the wrapper resolves the binary it runs
    /// hooks through, so naming the shim there means hooks work even if the
    /// user's shell rewrote PATH out from under the feature's entry.
    pub fn env(&self) -> Vec<(String, SecretValue)> {
        relay_env(self.addr.port(), &self.token)
    }
}

/// The environment a container needs, built from the two things that vary.
/// Separate from [`Relay`] so it can be read back without binding a port or
/// resolving a cmux, neither of which this decides anything about.
fn relay_env(port: u16, token: &str) -> Vec<(String, SecretValue)> {
    let mut env = vec![
        (
            "DEV_CMUX_RELAY".to_string(),
            SecretValue::new(format!("host.docker.internal:{port}")),
        ),
        ("DEV_CMUX_TOKEN".to_string(), SecretValue::new(token)),
        (
            "CMUX_SOCKET_PATH".to_string(),
            SecretValue::new(SOCKET_PATH),
        ),
        (
            "CMUX_BUNDLED_CLI_PATH".to_string(),
            SecretValue::new(SHIM_PATH),
        ),
    ];
    for name in ["CMUX_SURFACE_ID", "CMUX_WORKSPACE_ID"] {
        if let Ok(value) = std::env::var(name) {
            env.push((name.to_string(), SecretValue::new(value)));
        }
    }
    env
}

/// Start a relay for this session, or `None` if there is no cmux to forward
/// to. Silent on every failure, like everything else in this module.
pub async fn start() -> Option<Relay> {
    let spawner = super::live()?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.ok()?;
    let addr = listener.local_addr().ok()?;
    let token = mint_token()?;
    let task = tokio::spawn(accept_loop(listener, token.clone(), spawner));
    Some(Relay { addr, token, task })
}

/// 32 bytes of urandom, hex encoded. The only thing standing between this
/// listener and anything else that can reach the host's loopback, so it is
/// read straight from the kernel rather than derived from anything guessable.
fn mint_token() -> Option<String> {
    use std::io::Read;

    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut buf)
        .ok()?;
    Some(hex::encode(buf))
}

async fn accept_loop(listener: TcpListener, token: String, spawner: &'static Spawner) {
    while let Ok((stream, _)) = listener.accept().await {
        let token = token.clone();
        tokio::spawn(async move {
            let _ = serve(stream, &token, spawner).await;
        });
    }
}

/// One request, one response, one connection. `None` closes without a reply,
/// which the shim reads as a failure and reports as "no cmux".
async fn serve(stream: TcpStream, token: &str, spawner: &Spawner) -> Option<()> {
    let mut stream = BufReader::new(stream);
    let (args, body) = read_request(&mut stream, token).await?;
    if !verb_allowed(&args) {
        return None;
    }
    // Answered here rather than forwarded: the wrapper's liveness check is on
    // claude's startup path, and what it needs to know is whether this relay
    // is alive, which is settled by having reached this line.
    let output = if args[0] == "ping" {
        Vec::new()
    } else {
        run_verb(spawner, &args, body).await?
    };
    let mut stream = stream.into_inner();
    stream
        .write_all(format!("ok {}\n", output.len()).as_bytes())
        .await
        .ok()?;
    stream.write_all(&output).await.ok()?;
    stream.flush().await.ok()
}

async fn read_request(
    stream: &mut BufReader<TcpStream>,
    token: &str,
) -> Option<(Vec<String>, Vec<u8>)> {
    let mut header = String::new();
    stream
        .take(MAX_HEADER)
        .read_line(&mut header)
        .await
        .ok()
        .filter(|read| *read > 0)?;
    let (argc, body_len) = parse_header(header.trim_end_matches('\n'), token)?;

    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        let mut arg = String::new();
        stream.take(MAX_HEADER).read_line(&mut arg).await.ok()?;
        args.push(arg.trim_end_matches('\n').to_string());
    }

    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await.ok()?;
    Some((args, body))
}

/// `<protocol> <token> <argc> <body_len>`. `None` is a refusal, and the caller
/// never says which of the four was wrong.
fn parse_header(line: &str, token: &str) -> Option<(usize, usize)> {
    let mut fields = line.split(' ');
    let protocol = fields.next()?;
    let sent = fields.next()?;
    let argc: usize = fields.next()?.parse().ok()?;
    let body_len: usize = fields.next()?.parse().ok()?;
    if fields.next().is_some() || protocol != PROTOCOL || sent != token {
        return None;
    }
    ((1..=MAX_ARGS).contains(&argc) && body_len <= MAX_BODY).then_some((argc, body_len))
}

/// cmux's verbs for wiring an agent up, as opposed to reporting on one.
///
/// Every one of these generates files in the home directory of whichever
/// machine runs the CLI, and the relay runs everything on the host. A container
/// asking for one would write into the user's own home and still leave the
/// container's agent unconfigured, because the paths generated are host paths.
/// Refused by name ahead of any shape check, since `install` is a perfectly
/// ordinary-looking event name that [`is_event_name`] would wave through.
///
/// `inject-args` belongs here despite reading like a query: it writes
/// `~/.cmux/hooks/cmux-codex-hook-*.sh` and returns argv pointing at those
/// paths. Verified by watching the files appear during a container probe.
const WRITE_VERBS: [&str; 4] = ["install", "uninstall", "setup", "inject-args"];

/// The verbs the relay will run: those that report upward, and no others.
///
/// This is claude and only claude, and the reason is structural rather than a
/// matter of effort. cmux wires claude up by injecting an inline `--settings`
/// blob whose hook commands run `"$CMUX_CLAUDE_HOOK_CMUX_BIN" hooks claude
/// <event>`, so the commands travel in argv and resolve, inside the container,
/// to the shim. Every other agent it supports is wired up by generating hook
/// scripts on disk and pointing the agent at those paths. Run through this
/// relay that generation lands on the host, which is both the wrong machine and
/// a change to a machine this feature must not touch. See [`WRITE_VERBS`].
///
/// The event name stays shape-checked because cmux adds events between
/// versions and a fixed list would silently drop new ones.
fn verb_allowed(args: &[String]) -> bool {
    if args.iter().any(|arg| WRITE_VERBS.contains(&arg.as_str())) {
        return false;
    }
    let parts: Vec<&str> = args.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["ping"] => true,
        ["hooks", "claude", event] => is_event_name(event),
        ["hooks", "feed", "--source", "claude"] => true,
        _ => false,
    }
}

/// Lowercase ASCII words joined by single dashes. Shape only: whether the name
/// is one the relay will run is [`verb_allowed`]'s to say, and it refuses the
/// write verbs before ever asking this.
fn is_event_name(event: &str) -> bool {
    !event.is_empty()
        && event.len() <= 40
        && event
            .split('-')
            .all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase()))
}

/// Run one allowed verb against the real CLI, with the hook payload on stdin.
async fn run_verb(spawner: &Spawner, args: &[String], body: Vec<u8>) -> Option<Vec<u8>> {
    use std::process::Stdio;

    let mut command = tokio::process::Command::from(spawner.base_command(args));
    command
        .env(RESPONSE_TIMEOUT.0, RESPONSE_TIMEOUT.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = command.spawn().ok()?;
    let mut stdin = child.stdin.take()?;
    let write = async move {
        stdin.write_all(&body).await.ok();
        stdin.shutdown().await.ok();
    };
    let (_, output) = tokio::join!(
        write,
        tokio::time::timeout(CALL_TIMEOUT, child.wait_with_output())
    );
    let output = output.ok()?.ok()?;
    output.status.success().then_some(output.stdout)
}

/// One of cmux's wrappers, beside the CLI this process resolved.
fn host_wrapper(name: &str) -> Option<PathBuf> {
    let wrapper = super::live()?.binary.parent()?.join(name);
    wrapper.is_file().then_some(wrapper)
}

/// Asks two things in one exec: does this container carry the `cmux-agent`
/// feature, and which of [`WRAPPERS`]' agents does it actually have.
///
/// Probed rather than read off the image's metadata label, because the label
/// records what the image was built with and this asks what the container has
/// now. Run through a login shell so the answer is the PATH the session itself
/// will see; an agent installed under the user's home is invisible to a bare
/// exec. The wrappers' own directory is skipped, or a wrapper landed by an
/// earlier session would answer for the agent it stands in for.
fn probe_script() -> String {
    let agents: Vec<&str> = WRAPPERS.iter().map(|(_, agent)| *agent).collect();
    format!(
        "test -x {SHIM_PATH} || exit 1\n\
         for a in {}; do\n\
           IFS=:\n\
           for d in $PATH; do\n\
             [ \"$d\" = {SHIM_DIR} ] && continue\n\
             if [ -x \"$d/$a\" ]; then printf '%s\\n' \"$a\"; break; fi\n\
           done\n\
         done\n\
         exit 0\n",
        agents.join(" ")
    )
}

/// The agents this container can host, or `None` when it carries no shim.
/// An empty list is `None` too: a relay with no wrapper to feed reports
/// nothing, so there is no reason to open one.
pub async fn installed_agents(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> Option<Vec<String>> {
    let probe = [
        "sh".to_string(),
        "-lc".to_string(),
        probe_script(),
        "dev-cmux".to_string(),
    ];
    let result = runtime
        .exec(container_id, &probe, user, None, &[])
        .await
        .ok()?;
    if result.exit_code != 0 {
        return None;
    }
    let agents = parse_probe(&result.stdout);
    (!agents.is_empty()).then_some(agents)
}

/// The agents the probe named, keeping only those [`WRAPPERS`] knows, so a
/// login shell's own chatter on stdout cannot add one.
fn parse_probe(stdout: &str) -> Vec<String> {
    WRAPPERS
        .iter()
        .map(|(_, agent)| *agent)
        .filter(|agent| stdout.lines().any(|line| line.trim() == *agent))
        .map(str::to_string)
        .collect()
}

/// Put the socket inode and each agent's wrapper in place. `false` leaves the
/// session with no agent reporting and nothing else changed.
pub async fn prepare_container(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    agents: &[String],
) -> bool {
    for (wrapper_name, agent) in WRAPPERS {
        if !agents.iter().any(|wanted| wanted == agent) {
            continue;
        }
        let target = format!("{SHIM_DIR}/{agent}");
        let Some(wrapper) = host_wrapper(wrapper_name) else {
            return false;
        };
        let Ok(bytes) = std::fs::read(&wrapper) else {
            return false;
        };
        if runtime
            .copy_in(container_id, user, bytes, &target)
            .await
            .is_err()
            || !run_ok(runtime, container_id, user, &["chmod", "+x", &target]).await
        {
            return false;
        }
    }
    run_ok(
        runtime,
        container_id,
        user,
        &["perl", "-e", SOCKET_SCRIPT, "--", SOCKET_PATH],
    )
    .await
}

async fn run_ok(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    cmd: &[&str],
) -> bool {
    let cmd: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
    matches!(
        runtime.exec(container_id, &cmd, user, None, &[]).await,
        Ok(result) if result.exit_code == 0
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "abc123";

    fn header(line: &str) -> Option<(usize, usize)> {
        parse_header(line, TOKEN)
    }

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn header_parses_a_well_formed_request() {
        assert_eq!(header("dev-cmux/1 abc123 3 86"), Some((3, 86)));
    }

    #[test]
    fn header_refuses_a_wrong_token() {
        assert_eq!(header("dev-cmux/1 nope 3 86"), None);
    }

    #[test]
    fn header_refuses_another_protocol_version() {
        assert_eq!(header("dev-cmux/2 abc123 3 86"), None);
        assert_eq!(header("dev-cmux abc123 3 86"), None);
    }

    #[test]
    fn header_refuses_counts_it_will_not_read() {
        assert_eq!(header("dev-cmux/1 abc123 0 0"), None);
        assert_eq!(header("dev-cmux/1 abc123 9 0"), None);
        assert_eq!(header("dev-cmux/1 abc123 1 1048577"), None);
        assert_eq!(header("dev-cmux/1 abc123 1 -1"), None);
    }

    #[test]
    fn header_refuses_trailing_fields() {
        assert_eq!(header("dev-cmux/1 abc123 1 0 extra"), None);
    }

    #[test]
    fn allowlist_admits_ping_and_claude_hooks() {
        assert!(verb_allowed(&args(&["ping"])));
        assert!(verb_allowed(&args(&["hooks", "claude", "session-start"])));
        assert!(verb_allowed(&args(&["hooks", "claude", "pre-tool-use"])));
        assert!(verb_allowed(&args(&[
            "hooks", "feed", "--source", "claude"
        ])));
    }

    /// `inject-args` reads like a query and is not one: it generates
    /// `~/.cmux/hooks/cmux-codex-hook-*.sh` in the runner's home and answers
    /// with argv naming those paths. Through this relay the runner is the host,
    /// so it would write to the user's machine and hand the container paths
    /// that do not exist there.
    #[test]
    fn allowlist_refuses_codex_inject_args() {
        assert!(!verb_allowed(&args(&["hooks", "codex", "inject-args"])));
        assert!(!verb_allowed(&args(&["hooks", "codex"])));
        assert!(!verb_allowed(&args(&["hooks", "codex", "session-start"])));
    }

    /// The invariant this relay is built on: it reports and it returns, and it
    /// never writes. `cmux hooks <agent> install` generates configuration in
    /// the home of whichever machine runs the CLI, and the relay runs it on the
    /// host, so every one of these has to be refused for every agent cmux
    /// lists. Widening the allowlist should mean deleting an assertion here,
    /// not slipping past a shape check.
    #[test]
    fn allowlist_refuses_every_verb_that_writes_on_the_host() {
        let agents = [
            "claude",
            "codex",
            "grok",
            "opencode",
            "pi",
            "omp",
            "campfire",
            "amp",
            "cursor",
            "gemini",
            "kiro",
            "antigravity",
            "rovodev",
            "hermes-agent",
            "copilot",
            "codebuddy",
            "factory",
            "qoder",
        ];
        for agent in agents {
            for verb in WRITE_VERBS {
                assert!(
                    !verb_allowed(&args(&["hooks", agent, verb])),
                    "hooks {agent} {verb} must be refused"
                );
                assert!(
                    !verb_allowed(&args(&["hooks", agent, verb, "--yes"])),
                    "hooks {agent} {verb} --yes must be refused"
                );
            }
        }
        assert!(!verb_allowed(&args(&["hooks", "setup"])));
        assert!(!verb_allowed(&args(&["hooks", "uninstall", "claude"])));
    }

    /// `install` is a perfectly ordinary event-name shape, which is exactly why
    /// the refusal cannot live in the shape check.
    #[test]
    fn a_write_verb_still_looks_like_an_event_name() {
        for verb in WRITE_VERBS {
            assert!(is_event_name(verb), "{verb} passes the shape check");
            assert!(!verb_allowed(&args(&["hooks", "claude", verb])));
        }
    }

    #[test]
    fn the_probe_reads_back_only_agents_the_wrappers_cover() {
        assert_eq!(parse_probe("claude\n"), ["claude"]);
        assert!(parse_probe("").is_empty());
        // Neither a login shell's own banner nor an agent this relay does not
        // serve can add itself to the list.
        assert!(parse_probe("Welcome to Ubuntu\ncodex\ngrok\nsudo\n").is_empty());
    }

    /// The point of the allowlist: a container may report an agent's hooks and
    /// nothing else, however it frames the request.
    #[test]
    fn allowlist_refuses_every_other_verb() {
        assert!(!verb_allowed(&args(&["set-status", "dev_build", "owned"])));
        assert!(!verb_allowed(&args(&[
            "notify", "--title", "x", "--body", "y"
        ])));
        assert!(!verb_allowed(&args(&["hooks", "codex", "session-start"])));
        assert!(!verb_allowed(&args(&[
            "hooks", "feed", "--source", "codex"
        ])));
        assert!(!verb_allowed(&args(&["ping", "--socket", "/elsewhere"])));
        assert!(!verb_allowed(&[]));
    }

    #[test]
    fn event_names_are_shape_checked_not_listed() {
        assert!(is_event_name("session-end"));
        assert!(!is_event_name(""));
        assert!(!is_event_name("-leading"));
        assert!(!is_event_name("trailing-"));
        assert!(!is_event_name("double--dash"));
        assert!(!is_event_name("Session-Start"));
        assert!(!is_event_name("../../etc/passwd"));
        assert!(!is_event_name("session start"));
    }

    /// A `Spawner` the ping path never reaches: `serve` answers a ping itself,
    /// so nothing here is ever executed.
    fn unreachable_spawner() -> Spawner {
        Spawner {
            binary: PathBuf::from("/nonexistent/cmux"),
            socket: PathBuf::from("/nonexistent/cmux.sock"),
        }
    }

    /// Drive one request through `serve` over a real socket pair and hand back
    /// whatever came out, so the framing is tested in both directions rather
    /// than only through `parse_header`.
    async fn round_trip(request: &[u8], token: &str) -> Vec<u8> {
        use tokio::io::AsyncWriteExt as _;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = token.to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = serve(stream, &token, &unreachable_spawner()).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.flush().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        server.await.unwrap();
        reply
    }

    #[tokio::test]
    async fn a_ping_is_answered_without_running_anything() {
        let request = format!("{PROTOCOL} {TOKEN} 1 0\nping\n");
        assert_eq!(round_trip(request.as_bytes(), TOKEN).await, b"ok 0\n");
    }

    /// The token is the only thing between this listener and anything else on
    /// the host's loopback, so a wrong one gets no reply at all.
    #[tokio::test]
    async fn a_wrong_token_gets_no_reply() {
        let request = format!("{PROTOCOL} wrong-token 1 0\nping\n");
        assert!(round_trip(request.as_bytes(), TOKEN).await.is_empty());
    }

    #[tokio::test]
    async fn a_refused_verb_gets_no_reply() {
        let request = format!("{PROTOCOL} {TOKEN} 3 0\nset-status\ndev_build\nowned\n");
        assert!(round_trip(request.as_bytes(), TOKEN).await.is_empty());
    }

    /// Reads back the environment without binding a port or resolving a cmux,
    /// so the test says the same thing on a machine that has neither.
    #[test]
    fn the_container_is_handed_a_reachable_address_and_the_session_token() {
        let env: std::collections::HashMap<_, _> = relay_env(51482, "a".repeat(64).as_str())
            .into_iter()
            .map(|(k, v)| (k, v.expose().to_string()))
            .collect();
        assert_eq!(env["DEV_CMUX_RELAY"], "host.docker.internal:51482");
        assert_eq!(env["DEV_CMUX_TOKEN"].len(), 64);
        assert_eq!(env["CMUX_SOCKET_PATH"], SOCKET_PATH);
        assert_eq!(env["CMUX_BUNDLED_CLI_PATH"], SHIM_PATH);
    }

    /// The one thing that must not drift. The shim ships as a file in the
    /// feature directory, which cargo would otherwise never look at, so its
    /// half of the framing is pinned here at compile time.
    #[test]
    fn the_shim_declares_the_same_protocol() {
        let shim = include_str!("../../features/cmux-agent/cmux");
        assert!(
            shim.contains(&format!("readonly PROTOCOL=\"{PROTOCOL}\"")),
            "features/cmux-agent/cmux does not declare {PROTOCOL}"
        );
    }

    #[test]
    fn tokens_differ_between_sessions() {
        let first = mint_token().expect("urandom is readable");
        assert_eq!(first.len(), 64);
        assert_ne!(first, mint_token().unwrap());
    }
}
