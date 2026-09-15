//! The runtime section of `dev status`: what daemon answered, what a
//! container running on it can reach, and whether the integrations built on
//! that reach actually work right now.
//!
//! Follows `config_explain`'s report shape — a data struct, a pure `render`,
//! a pure `to_json`, and a builder that does the actual work — so `dev
//! status` stays a thin caller of `build_report`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::cmux::agent as cmux_agent;
use crate::commands::up;
use crate::devcontainer::DevcontainerConfig;
use crate::devcontainer::secrets::SecretValue;
use crate::runtime::docker::DockerFlavor;
use crate::runtime::{
    ContainerInfo, ContainerRuntime, ContainerState, ExecResult, HostAccess, resolve_remote_user,
};
use crate::ssh_agent;

/// Bounds one probe exec against a daemon that stopped answering entirely.
/// `dev up` already gated this container through its own readiness budget;
/// this only keeps `dev status` itself from hanging on it.
const PROBE_BUDGET: Duration = Duration::from_secs(5);

/// Bounds the image inspect `resolve_remote_user` falls through to when the
/// config names no `remoteUser`. It runs before the first probe, against a
/// client whose own default is two minutes, so leaving it unbudgeted would
/// hang `dev status` well before [`PROBE_BUDGET`] ever applied.
const USER_BUDGET: Duration = Duration::from_secs(5);

const HOST_ALIAS: &str = "host alias";
const SSH_AGENT: &str = "ssh agent";
const DIND: &str = "dind";
const CMUX_RELAY: &str = "cmux relay";

const NO_HOST_ALIAS_NOTE: &str = "This flavor has no host alias, so every integration that calls back to the host is off: the cmux agent relay and the SSH agent relay alike.";

const NO_CONTAINER_HINT: &str =
    "The live checks need a running container.\n\n  dev up\n\nThen try `dev status` again.";

/// The whole runtime section: static facts about the daemon plus, when a
/// container is running, the four live checks against it.
pub(crate) struct RuntimeReport {
    socket_path: Option<String>,
    daemon_version: Option<String>,
    access: HostAccess,
    checks: Option<Vec<CheckRow>>,
    mount_warning: Option<String>,
}

impl RuntimeReport {
    fn facts(&self) -> Vec<Fact> {
        build_facts(
            self.access,
            self.socket_path.as_deref(),
            self.daemon_version.as_deref(),
        )
    }

    pub(crate) fn render(&self) -> String {
        let mut sections = vec![render_facts_table(&self.facts())];
        if self.access.gateway_alias.is_none() {
            sections.push(NO_HOST_ALIAS_NOTE.to_string());
        }
        match &self.checks {
            Some(checks) => {
                sections.push(render_checks_table(checks));
                sections.extend(
                    checks
                        .iter()
                        .filter(|check| check.status == CheckStatus::Failed)
                        .filter_map(|check| check.remediation.clone()),
                );
            }
            None => sections.push(NO_CONTAINER_HINT.to_string()),
        }
        if let Some(warning) = &self.mount_warning {
            sections.push(warning.clone());
        }
        format!("\n{}\n", sections.join("\n\n"))
    }

    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "socket": self.socket_path,
            "flavor": self.access.flavor.map(DockerFlavor::as_str),
            "daemonVersion": self.daemon_version,
            "facts": self.facts().iter().map(Fact::to_json).collect::<Vec<_>>(),
            "checks": self
                .checks
                .as_ref()
                .map(|checks| checks.iter().map(CheckRow::to_json).collect::<Vec<_>>()),
            "mountWarning": self.mount_warning,
        })
    }
}

/// Build the report. Static facts are always available; the live checks run
/// only when this workspace has a running container, and refine `access`
/// with whatever they actually measured.
pub(crate) async fn build_report(
    workspace: &Path,
    runtime: &dyn ContainerRuntime,
    containers: &[ContainerInfo],
    config: Option<&DevcontainerConfig>,
) -> RuntimeReport {
    let socket_path = runtime.socket_path().map(str::to_string);
    let daemon_version = runtime.daemon_version().map(str::to_string);
    let mut access = runtime.host_access();

    let mount_warning = config.and_then(|config| mount_scope_warning(config, workspace, access));

    let checks = match containers
        .iter()
        .find(|c| c.state == ContainerState::Running)
    {
        Some(container) => {
            let user = resolve_check_user(runtime, container, config).await;
            let (rows, refined) =
                run_live_checks(runtime, &container.id, user.as_deref(), config, access).await;
            access = refined;
            Some(rows)
        }
        None => None,
    };

    RuntimeReport {
        socket_path,
        daemon_version,
        access,
        checks,
        mount_warning,
    }
}

/// The user each probe runs as, matching `dev exec`'s own resolution: the
/// config's `remoteUser`, falling back to the image's own metadata. A user
/// that cannot be resolved in [`USER_BUDGET`] still leaves every other fact
/// worth printing, so this degrades to no override rather than failing or
/// stalling `dev status` outright.
async fn resolve_check_user(
    runtime: &dyn ContainerRuntime,
    container: &ContainerInfo,
    config: Option<&DevcontainerConfig>,
) -> Option<String> {
    let config_user = config.and_then(|c| c.remote_user.clone());
    tokio::time::timeout(
        USER_BUDGET,
        resolve_remote_user(runtime, &container.image, config_user.as_deref()),
    )
    .await
    .ok()?
    .unwrap_or(None)
}

/// The one flavor-keyed check in this module: Colima's filesystem only shares
/// the host's home directory with the VM, and no `HostAccess` field describes
/// that constraint.
fn mount_scope_warning(
    config: &DevcontainerConfig,
    workspace: &Path,
    access: HostAccess,
) -> Option<String> {
    if access.flavor != Some(DockerFlavor::Colima) {
        return None;
    }
    let home = dirs::home_dir()?;
    let sources = up::configured_bind_sources(config, workspace, config.remote_user.as_deref());
    let outside = mount_sources_outside_home(&sources, &home);
    colima_mount_warning(&outside)
}

/// `Path::starts_with` compares whole components, so `/Users/mwarrenx` does
/// not pass for a home of `/Users/mwarren` the way a string prefix test
/// would.
fn mount_sources_outside_home(sources: &[PathBuf], home: &Path) -> Vec<PathBuf> {
    sources
        .iter()
        .filter(|source| !source.starts_with(home))
        .cloned()
        .collect()
}

fn colima_mount_warning(outside: &[PathBuf]) -> Option<String> {
    if outside.is_empty() {
        return None;
    }
    let list = outside
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "Colima only shares your home directory with the VM; these configured mount sources fall outside it and will not be visible in the container: {list}"
    ))
}

/// One row of the static fact table. `source` is `None` for the three rows
/// that describe the daemon connection itself rather than a `HostAccess`
/// field.
struct Fact {
    label: &'static str,
    value: String,
    source: Option<&'static str>,
}

impl Fact {
    fn render(&self) -> String {
        match self.source {
            Some(source) => format!("{:<21}{:<41}{source}", self.label, self.value),
            None => format!("{:<21}{}", self.label, self.value),
        }
    }

    fn to_json(&self) -> Value {
        serde_json::json!({ "label": self.label, "value": self.value, "source": self.source })
    }
}

/// The label a `bool` fact prints, with both answers spelled at the row
/// that owns them.
fn yes_no(value: bool, yes: &'static str, no: &'static str) -> &'static str {
    if value { yes } else { no }
}

/// Every fact row, in print order: the three daemon-connection rows, then
/// one row per `HostAccess` field. The row count never depends on the
/// answers, so a field added to `HostAccess` later is one more row in
/// `access_facts` and nothing else.
fn build_facts(
    access: HostAccess,
    socket_path: Option<&str>,
    daemon_version: Option<&str>,
) -> Vec<Fact> {
    let mut facts = daemon_facts(access.flavor, socket_path, daemon_version);
    facts.extend(access_facts(access));
    facts
}

fn daemon_facts(
    flavor: Option<DockerFlavor>,
    socket_path: Option<&str>,
    daemon_version: Option<&str>,
) -> Vec<Fact> {
    vec![
        Fact {
            label: "socket",
            value: socket_path.unwrap_or("n/a").to_string(),
            source: None,
        },
        Fact {
            label: "flavor",
            value: flavor
                .map(DockerFlavor::as_str)
                .unwrap_or("unknown")
                .to_string(),
            source: None,
        },
        Fact {
            label: "daemon version",
            value: daemon_version.unwrap_or("unknown").to_string(),
            source: None,
        },
    ]
}

fn access_facts(access: HostAccess) -> Vec<Fact> {
    vec![
        Fact {
            label: "host alias",
            value: access.gateway_alias.unwrap_or("none").to_string(),
            source: Some(yes_no(access.probed.gateway_alias, "probe", "table")),
        },
        Fact {
            label: "alias injected",
            value: yes_no(access.injects_alias, "yes (by the daemon)", "no").to_string(),
            source: Some("table"),
        },
        Fact {
            label: "host loopback",
            value: yes_no(access.reaches_host_loopback, "reachable", "unreachable").to_string(),
            source: Some(yes_no(
                access.probed.reaches_host_loopback,
                "probe",
                "table",
            )),
        },
        Fact {
            label: "docker socket mount",
            value: yes_no(access.socket_mounts_work, "works", "does not work").to_string(),
            source: Some("table"),
        },
        Fact {
            label: "host socket mounts",
            value: yes_no(access.host_sockets_mount, "work", "do not work").to_string(),
            source: Some("table"),
        },
        Fact {
            label: "ownership",
            value: yes_no(access.squashes_ownership, "squashed", "not squashed").to_string(),
            source: Some("table"),
        },
    ]
}

fn render_facts_table(facts: &[Fact]) -> String {
    let mut lines = vec![format!("{:<21}{:<41}{}", "FACT", "VALUE", "SOURCE")];
    lines.extend(facts.iter().map(Fact::render));
    lines.join("\n")
}

fn render_checks_table(checks: &[CheckRow]) -> String {
    let mut lines = vec![format!("{:<17}{:<11}{}", "CHECK", "RESULT", "DETAIL")];
    lines.extend(
        checks
            .iter()
            .map(|c| format!("{:<17}{:<11}{}", c.name, c.status.as_str(), c.detail)),
    );
    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Failed,
    Skipped,
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// One live check's outcome. `remediation` is `Some` only for a `Failed` row;
/// `render` prints it after the check table, never inline in the row.
struct CheckRow {
    name: &'static str,
    status: CheckStatus,
    detail: String,
    remediation: Option<String>,
}

impl CheckRow {
    fn to_json(&self) -> Value {
        serde_json::json!({
            "name": self.name,
            "status": self.status.as_str(),
            "detail": self.detail,
        })
    }
}

fn ok_row(name: &'static str, detail: impl Into<String>) -> CheckRow {
    CheckRow {
        name,
        status: CheckStatus::Ok,
        detail: detail.into(),
        remediation: None,
    }
}

fn skip_row(name: &'static str, detail: impl Into<String>) -> CheckRow {
    CheckRow {
        name,
        status: CheckStatus::Skipped,
        detail: detail.into(),
        remediation: None,
    }
}

fn failed_row(name: &'static str, detail: impl Into<String>, remediation: String) -> CheckRow {
    CheckRow {
        name,
        status: CheckStatus::Failed,
        detail: detail.into(),
        remediation: Some(remediation),
    }
}

/// Run the four live checks, in the fixed order a fake asserts on. A
/// successful cmux ping is the only thing that ever refines `access`.
async fn run_live_checks(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    config: Option<&DevcontainerConfig>,
    access: HostAccess,
) -> (Vec<CheckRow>, HostAccess) {
    let mut rows = vec![
        check_host_alias(runtime, container_id, user, access).await,
        check_ssh_agent(runtime, container_id, user).await,
        check_dind(runtime, container_id, user).await,
    ];
    let (cmux_row, verified) = check_cmux_relay(runtime, container_id, user, config, access).await;
    rows.push(cmux_row);
    (rows, verified.unwrap_or(access))
}

/// What one bounded exec came back with, collapsed to the four shapes every
/// check here decides from.
enum ProbeOutcome {
    Ran(ExecResult),
    MissingCommand(String),
    Refused(String),
    TimedOut(f64),
}

async fn run_probe(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    cmd: &[String],
    user: Option<&str>,
    env: &[(String, SecretValue)],
) -> ProbeOutcome {
    let attempt = tokio::time::timeout(
        PROBE_BUDGET,
        runtime.exec(container_id, cmd, user, None, env),
    )
    .await;
    match attempt {
        // A shell reports a command it could not find as exit 127, which is
        // the same fact the runtime reports as an error on the exec itself.
        Ok(Ok(result)) if result.exit_code == 127 => {
            ProbeOutcome::MissingCommand(result.stderr.trim().to_string())
        }
        Ok(Ok(result)) => ProbeOutcome::Ran(result),
        Ok(Err(e)) if runtime.exec_reports_missing_command(&e) => {
            ProbeOutcome::MissingCommand(e.to_string())
        }
        Ok(Err(e)) => ProbeOutcome::Refused(e.to_string()),
        Err(_) => ProbeOutcome::TimedOut(PROBE_BUDGET.as_secs_f64()),
    }
}

impl ProbeOutcome {
    /// Peel off the two outcomes no check reads for itself: an exec the
    /// runtime refused reports its own error, one that outran the budget
    /// reports the budget. `Err` is the row to return as it stands.
    fn decidable(
        self,
        name: &'static str,
        remediation: impl FnOnce() -> String,
    ) -> Result<Self, CheckRow> {
        match self {
            ProbeOutcome::Refused(detail) => Err(failed_row(name, detail, remediation())),
            ProbeOutcome::TimedOut(secs) => {
                Err(failed_row(name, timeout_detail(secs), remediation()))
            }
            decidable => Ok(decidable),
        }
    }
}

/// The wording `verify_container_execs_until` uses for the same failure.
fn timeout_detail(secs: f64) -> String {
    format!("it did not report an exit within {secs:.1}s")
}

/// The `sh -lc` shape every probe here uses, matching
/// `cmux::agent::probe_script`/`installed_agents`: a login shell is not
/// optional, because the answer has to be the PATH and environment the
/// session itself sees.
fn probe_cmd(script: String) -> Vec<String> {
    vec![
        "sh".to_string(),
        "-lc".to_string(),
        script,
        "dev-status".to_string(),
    ]
}

async fn check_host_alias(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    access: HostAccess,
) -> CheckRow {
    let Some(alias) = access.gateway_alias else {
        return skip_row(HOST_ALIAS, "this flavor has no host alias");
    };
    let cmd = probe_cmd(format!("getent hosts {alias}"));
    let outcome = match run_probe(runtime, container_id, &cmd, user, &[])
        .await
        .decidable(HOST_ALIAS, || remediation_host_alias(alias))
    {
        Ok(outcome) => outcome,
        Err(row) => return row,
    };
    match outcome {
        ProbeOutcome::MissingCommand(_) => skip_row(HOST_ALIAS, "no getent in this container"),
        ProbeOutcome::Ran(r) if r.exit_code == 0 => match parse_getent_address(&r.stdout, alias) {
            Some(addr) => ok_row(HOST_ALIAS, format!("resolves to {addr}")),
            None => failed_row(
                HOST_ALIAS,
                format!("`getent hosts {alias}` printed no address"),
                remediation_host_alias(alias),
            ),
        },
        _ => failed_row(
            HOST_ALIAS,
            format!("could not resolve `{alias}`"),
            remediation_host_alias(alias),
        ),
    }
}

/// `getent hosts` answers `<address> <name>...`, so a line only counts when
/// it carries the alias among its names and opens with something shaped like
/// an address. A login shell's own banner shares this stdout, and the address
/// reported here is the whole point of the check.
fn parse_getent_address(stdout: &str, alias: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let mut tokens = line.split_whitespace();
        let address = tokens.next().filter(|token| looks_like_address(token))?;
        tokens
            .any(|name| name == alias)
            .then(|| address.to_string())
    })
}

fn looks_like_address(token: &str) -> bool {
    token
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '%'))
}

fn remediation_host_alias(alias: &str) -> String {
    format!(
        "The host alias `{alias}` did not resolve inside the container.\n\n  Recreate the container so the alias is written again: `dev down && dev up`\n\nThen try `dev status` again."
    )
}

/// The facts one ssh agent probe reports, each on its own prefixed line so a
/// login shell's own banner cannot be mistaken for one.
struct SshProbeFacts {
    upstream: String,
    auth_sock: String,
    shim_executable: bool,
    socket_is_socket: bool,
    ssh_add: SshAddStatus,
}

#[derive(Debug, Clone, Copy)]
enum SshAddStatus {
    Missing,
    Answered {
        exit_code: i32,
        identity_count: usize,
    },
}

/// Always exits 0; the answer is entirely in stdout, so a shell error never
/// gets mistaken for the agent's own refusal.
fn ssh_probe_script() -> String {
    format!(
        "printf 'UPSTREAM:%s\\n' \"${{DEV_SSH_AGENT_UPSTREAM:-}}\"; \
         printf 'AUTHSOCK:%s\\n' \"${{SSH_AUTH_SOCK:-}}\"; \
         printf 'SHIM:%s\\n' \"$([ -x {shim} ] && echo yes || echo no)\"; \
         printf 'SOCKET:%s\\n' \"$([ -S /dev/shm/ssh-agent.sock ] && echo yes || echo no)\"; \
         if command -v ssh-add >/dev/null 2>&1; then \
           out=$(ssh-add -l 2>/dev/null); code=$?; \
           printf 'SSHADD:%s:%s\\n' \"$code\" \"$(printf '%s\\n' \"$out\" | grep -c .)\"; \
         else \
           printf 'SSHADD:missing\\n'; \
         fi",
        shim = ssh_agent::SHIM_PATH,
    )
}

fn parse_ssh_probe(stdout: &str) -> SshProbeFacts {
    let mut facts = SshProbeFacts {
        upstream: String::new(),
        auth_sock: String::new(),
        shim_executable: false,
        socket_is_socket: false,
        ssh_add: SshAddStatus::Missing,
    };
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("UPSTREAM:") {
            facts.upstream = value.to_string();
        } else if let Some(value) = line.strip_prefix("AUTHSOCK:") {
            facts.auth_sock = value.to_string();
        } else if let Some(value) = line.strip_prefix("SHIM:") {
            facts.shim_executable = value == "yes";
        } else if let Some(value) = line.strip_prefix("SOCKET:") {
            facts.socket_is_socket = value == "yes";
        } else if let Some(value) = line.strip_prefix("SSHADD:") {
            facts.ssh_add = parse_ssh_add_status(value);
        }
    }
    facts
}

fn parse_ssh_add_status(value: &str) -> SshAddStatus {
    if value == "missing" {
        return SshAddStatus::Missing;
    }
    let mut parts = value.splitn(2, ':');
    let exit_code = parts.next().and_then(|s| s.parse().ok());
    let identity_count = parts.next().and_then(|s| s.parse().ok());
    match (exit_code, identity_count) {
        (Some(exit_code), Some(identity_count)) => SshAddStatus::Answered {
            exit_code,
            identity_count,
        },
        _ => SshAddStatus::Missing,
    }
}

/// The mechanism read from the container's own environment, never from
/// `HostAccess`: a container created before the descriptor changed its mind
/// is exactly the case worth catching.
fn ssh_mechanism_label(upstream: &str) -> &'static str {
    if upstream.is_empty() {
        "no upstream configured"
    } else if upstream.starts_with("unix:") {
        "relay (unix)"
    } else if upstream.starts_with("tcp:") {
        "relay"
    } else {
        "unrecognized upstream"
    }
}

fn identities_phrase(count: usize) -> String {
    if count == 1 {
        "1 identity loaded".to_string()
    } else {
        format!("{count} identities loaded")
    }
}

/// A bound socket is not evidence the agent answers — a host listener lost to
/// a reboot leaves a socat that still passes `test -S` while every ssh fails
/// — so the note is worth carrying into the detail whenever `ssh-add` itself
/// could not reach anything.
fn ssh_add_refused_detail(mechanism: &str, exit_code: i32, socket_is_socket: bool) -> String {
    let socket_note = if socket_is_socket {
        "; the local socket is bound, but nothing behind it answered"
    } else {
        ""
    };
    format!("{mechanism}, ssh-add could not contact the agent (exit {exit_code}){socket_note}")
}

/// Whether this container was ever given an agent to reach. The upstream
/// alone cannot say: the base layer's mounted socket leaves it empty and
/// still expects a working agent, so a relay of its that died must stay a
/// failure. Every sign of an agent therefore has to be absent — no upstream,
/// no `SSH_AUTH_SOCK`, and nothing bound where the base layer puts its
/// socket. Only then has the container nothing to answer for, and reporting
/// that as a failure sends the reader after a relay nobody asked for.
fn nothing_configured(facts: &SshProbeFacts) -> bool {
    facts.upstream.is_empty() && facts.auth_sock.is_empty() && !facts.socket_is_socket
}

/// The pure half of the ssh agent check: everything decidable from one
/// probe's facts. `NeedsLivenessProbe` is the one case that costs a second
/// exec.
enum SshVerdict {
    Row(CheckStatus, String),
    NeedsLivenessProbe,
}

fn interpret_ssh_probe(facts: &SshProbeFacts) -> SshVerdict {
    let mechanism = ssh_mechanism_label(&facts.upstream);
    if nothing_configured(facts) {
        return SshVerdict::Row(
            CheckStatus::Skipped,
            "no ssh agent configured for this container".to_string(),
        );
    }
    if facts.upstream.starts_with("tcp:") && !facts.shim_executable {
        return SshVerdict::Row(
            CheckStatus::Failed,
            format!(
                "{mechanism}, the `{}` feature is not installed so the upstream shim is missing",
                ssh_agent::FEATURE_NAME
            ),
        );
    }
    match facts.ssh_add {
        SshAddStatus::Answered {
            exit_code: 0,
            identity_count,
        } => SshVerdict::Row(
            CheckStatus::Ok,
            format!("{mechanism}, {}", identities_phrase(identity_count)),
        ),
        SshAddStatus::Answered { exit_code: 1, .. } => SshVerdict::Row(
            CheckStatus::Ok,
            format!("{mechanism}, agent answered, no identities loaded"),
        ),
        SshAddStatus::Answered { exit_code, .. } => SshVerdict::Row(
            CheckStatus::Failed,
            ssh_add_refused_detail(mechanism, exit_code, facts.socket_is_socket),
        ),
        // The shim only speaks for a `tcp:` upstream: it exits 1 on anything
        // else, because the base layer's own script connects a mount. Running
        // it for a mount would report every slim image without `ssh-add` as a
        // broken relay.
        SshAddStatus::Missing if facts.upstream.starts_with("tcp:") => {
            SshVerdict::NeedsLivenessProbe
        }
        SshAddStatus::Missing => SshVerdict::Row(
            CheckStatus::Skipped,
            format!("{mechanism}, no ssh-add in this container to ask the agent"),
        ),
    }
}

async fn check_ssh_agent(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> CheckRow {
    let cmd = probe_cmd(ssh_probe_script());
    let result = match run_probe(runtime, container_id, &cmd, user, &[]).await {
        ProbeOutcome::Ran(r) => r,
        ProbeOutcome::MissingCommand(detail) | ProbeOutcome::Refused(detail) => {
            return failed_row(SSH_AGENT, detail, remediation_ssh_agent());
        }
        ProbeOutcome::TimedOut(secs) => {
            return failed_row(SSH_AGENT, timeout_detail(secs), remediation_ssh_agent());
        }
    };
    let facts = parse_ssh_probe(&result.stdout);
    match interpret_ssh_probe(&facts) {
        SshVerdict::Row(CheckStatus::Ok, detail) => ok_row(SSH_AGENT, detail),
        SshVerdict::Row(CheckStatus::Skipped, detail) => skip_row(SSH_AGENT, detail),
        SshVerdict::Row(CheckStatus::Failed, detail) => {
            failed_row(SSH_AGENT, detail, remediation_ssh_agent())
        }
        SshVerdict::NeedsLivenessProbe => {
            check_ssh_liveness(runtime, container_id, user, &facts).await
        }
    }
}

/// Falls back to the shim's liveness probe when the image has no `ssh-add` to
/// answer for it and the container was given a `tcp:` upstream, the only kind
/// the shim answers for. The probe's one side effect is a short-lived
/// connection to the host agent, made only to prove the handshake succeeds.
async fn check_ssh_liveness(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    facts: &SshProbeFacts,
) -> CheckRow {
    let mechanism = ssh_mechanism_label(&facts.upstream);
    let cmd = vec![
        "sh".to_string(),
        "-lc".to_string(),
        format!(": | {}", ssh_agent::SHIM_PATH),
    ];
    let outcome = match run_probe(runtime, container_id, &cmd, user, &[])
        .await
        .decidable(SSH_AGENT, remediation_ssh_agent)
    {
        Ok(outcome) => outcome,
        Err(row) => return row,
    };
    match outcome {
        ProbeOutcome::Ran(r) if r.exit_code == 0 => ok_row(
            SSH_AGENT,
            format!(
                "{mechanism}, ssh-add was unavailable, the upstream shim reports the agent is reachable"
            ),
        ),
        _ => failed_row(
            SSH_AGENT,
            format!(
                "{mechanism}, ssh-add was unavailable and the upstream shim could not reach the agent"
            ),
            remediation_ssh_agent(),
        ),
    }
}

fn remediation_ssh_agent() -> String {
    "The SSH agent is not answering inside the container.\n\n  Check the socat listener: `dev exec -- ls -l /dev/shm/ssh-agent.sock`\n  — or —\n  Recreate the container so the host relay and postStartCommand both run again: `dev down && dev up`\n\nThen try `dev shell` again.".to_string()
}

async fn check_dind(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
) -> CheckRow {
    let cmd = probe_cmd("docker version --format '{{.Server.Version}}'".to_string());
    let outcome = match run_probe(runtime, container_id, &cmd, user, &[])
        .await
        .decidable(DIND, remediation_dind)
    {
        Ok(outcome) => outcome,
        Err(row) => return row,
    };
    match outcome {
        ProbeOutcome::Ran(r) if r.exit_code == 0 => match parse_dind_version(&r.stdout) {
            Some(version) => ok_row(DIND, format!("server {version}")),
            None => ok_row(DIND, "the daemon answered but reported no server version"),
        },
        ProbeOutcome::Ran(r) => failed_row(DIND, r.stderr.trim().to_string(), remediation_dind()),
        _ => skip_row(DIND, "no docker CLI in this container"),
    }
}

/// `docker version --format` prints the version by itself, but a login
/// shell's banner reaches the same stdout, so keep only a line shaped like a
/// version. `0 updates can be applied immediately.` is a banner line that
/// also starts with a digit, hence the whole-line test.
fn parse_dind_version(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| looks_like_version(line))
        .map(str::to_string)
}

fn looks_like_version(line: &str) -> bool {
    line.starts_with(|c: char| c.is_ascii_digit())
        && line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
}

fn remediation_dind() -> String {
    "The Docker daemon inside this container is not reachable.\n\n  The docker-in-docker feature contributes `privileged` and its entrypoint through the image's `devcontainer.metadata` label; an image built without that label loses both. Rebuild it: `dev build --no-cache && dev up`\n\nThen try `dev status` again.".to_string()
}

async fn check_cmux_relay(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    user: Option<&str>,
    config: Option<&DevcontainerConfig>,
    access: HostAccess,
) -> (CheckRow, Option<HostAccess>) {
    if !config.is_some_and(DevcontainerConfig::cmux_agent_enabled) {
        return (
            skip_row(CMUX_RELAY, "cmux.agent is not enabled for this project"),
            None,
        );
    }
    if let Err(reason) = access.host_callback() {
        return (skip_row(CMUX_RELAY, reason), None);
    }
    // `start` answers `None` for a terminal cmux never opened, but also for a
    // listener it could not bind or a token it could not mint, and it does not
    // say which. The row claims only what this side knows.
    let Some(relay) = cmux_agent::start(access).await else {
        return (
            skip_row(
                CMUX_RELAY,
                "no relay to ping: no cmux in this terminal, or its host listener did not open",
            ),
            None,
        );
    };
    let outcome = run_probe(
        runtime,
        container_id,
        &cmux_agent::ping_command(),
        user,
        &relay.env(),
    )
    .await;
    interpret_cmux_ping(outcome, access)
}

/// A successful ping proves the container reached a host-loopback listener,
/// so it is the only outcome that refines `access`. A refused or timed-out
/// ping proves nothing either way — a token or `PROTOCOL` mismatch fails the
/// same way an unreachable host does — so it leaves `access` on the table.
fn interpret_cmux_ping(
    outcome: ProbeOutcome,
    access: HostAccess,
) -> (CheckRow, Option<HostAccess>) {
    let outcome = match outcome.decidable(CMUX_RELAY, remediation_cmux_relay) {
        Ok(outcome) => outcome,
        Err(row) => return (row, None),
    };
    match outcome {
        ProbeOutcome::Ran(r) if r.exit_code == 0 => (
            ok_row(CMUX_RELAY, "shim answered"),
            Some(access.with_loopback_verified(true)),
        ),
        ProbeOutcome::MissingCommand(_) => (
            skip_row(
                CMUX_RELAY,
                "the cmux-agent feature is not installed in this container",
            ),
            None,
        ),
        _ => (
            failed_row(
                CMUX_RELAY,
                "the shim did not answer the ping",
                remediation_cmux_relay(),
            ),
            None,
        ),
    }
}

fn remediation_cmux_relay() -> String {
    "The cmux agent shim did not answer.\n\n  Recreate the container so the relay is reachable again: `dev down && dev up`\n\nThen try `dev status` again.".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DevError;
    use crate::runtime::host_access::Probed;
    use crate::runtime::{AttachedExec, BoxFut, ContainerConfig, ImageMetadata};
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("unused fake runtime method".into())) })
    }

    /// One recorded exec call: the script it ran, who it ran as, and which
    /// env keys rode along (never the secret values themselves).
    #[derive(Debug, Clone)]
    struct RecordedCall {
        cmd: Vec<String>,
        user: Option<String>,
        env_keys: Vec<String>,
    }

    /// What one dispatched exec call answers with. `Delayed` stands in for a
    /// daemon that never answers: bounded by a real `tokio::time::sleep`
    /// rather than a future that never resolves, so a test using it under
    /// `start_paused` cannot itself hang if the timeout it means to prove
    /// ever goes missing.
    enum ExecReply {
        Result(ExecResult),
        Err(DevError),
        Delayed(Duration),
    }

    fn ok(stdout: impl Into<String>) -> ExecReply {
        ExecReply::Result(ExecResult {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    fn exec_exit(code: i32, stdout: &str, stderr: &str) -> ExecReply {
        ExecReply::Result(ExecResult {
            exit_code: code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        })
    }

    type Dispatch = Box<dyn Fn(&[String]) -> ExecReply + Send + Sync>;

    /// A runtime whose `exec` dispatches on the script it is given rather
    /// than call order, and records every call. Shaped like `status.rs`'s
    /// `StatusFakeRuntime`.
    struct CheckFakeRuntime {
        dispatch: Dispatch,
        calls: Mutex<Vec<RecordedCall>>,
        /// How long `inspect_image_metadata` takes to answer and the
        /// `remoteUser` it names when it does. Bounded by a real sleep for
        /// the same reason [`ExecReply::Delayed`] is.
        image_inspect: Option<(Duration, &'static str)>,
    }

    impl CheckFakeRuntime {
        fn new(dispatch: impl Fn(&[String]) -> ExecReply + Send + Sync + 'static) -> Self {
            Self {
                dispatch: Box::new(dispatch),
                calls: Mutex::new(Vec::new()),
                image_inspect: None,
            }
        }

        fn with_image_inspect(mut self, delay: Duration, remote_user: &'static str) -> Self {
            self.image_inspect = Some((delay, remote_user));
            self
        }

        fn calls(&self) -> Vec<RecordedCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ContainerRuntime for CheckFakeRuntime {
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
            cmd: &[String],
            user: Option<&str>,
            _workdir: Option<&str>,
            env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            self.calls.lock().unwrap().push(RecordedCall {
                cmd: cmd.to_vec(),
                user: user.map(str::to_string),
                env_keys: env.iter().map(|(k, _)| k.clone()).collect(),
            });
            match (self.dispatch)(cmd) {
                ExecReply::Result(result) => Box::pin(async move { Ok(result) }),
                ExecReply::Err(error) => Box::pin(async move { Err(error) }),
                ExecReply::Delayed(duration) => Box::pin(async move {
                    tokio::time::sleep(duration).await;
                    Ok(ExecResult {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }),
            }
        }
        fn exec_reports_missing_command(&self, error: &DevError) -> bool {
            matches!(error, DevError::Runtime(msg) if msg.starts_with("missing-command:"))
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
            let Some((delay, remote_user)) = self.image_inspect else {
                return unused();
            };
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(ImageMetadata {
                    remote_user: Some(remote_user.to_string()),
                    container_user: None,
                    metadata_entries: Vec::new(),
                    env: Vec::new(),
                })
            })
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

    fn desktop_access() -> HostAccess {
        HostAccess::for_flavor(DockerFlavor::DockerDesktop)
    }

    fn enabled_cmux_config() -> DevcontainerConfig {
        serde_json::from_str(r#"{"image": "ubuntu:24.04", "cmux": {"agent": true}}"#)
            .expect("a minimal config with cmux.agent enabled must parse")
    }

    /// Answers every probe shape this module issues: host alias, ssh agent
    /// (including its liveness fallback), dind, matched on the script text
    /// rather than call order.
    fn generic_dispatch(cmd: &[String]) -> ExecReply {
        let script = cmd.get(2).map(String::as_str).unwrap_or("");
        if script.starts_with("getent hosts") {
            ok("198.19.249.2 host.docker.internal\n")
        } else if script.contains("UPSTREAM:%s") {
            ok("UPSTREAM:\nSHIM:no\nSOCKET:no\nSSHADD:missing\n")
        } else if script.starts_with(": |") {
            exec_exit(1, "", "")
        } else if script.starts_with("docker version") {
            ok("27.4.0\n")
        } else {
            exec_exit(127, "", "")
        }
    }

    /// Runs the four live checks against `generic_dispatch` and hands back
    /// both the outcomes and everything the fake recorded.
    async fn drive_all_checks(
        access: HostAccess,
        config: &DevcontainerConfig,
    ) -> (Vec<CheckRow>, Vec<RecordedCall>) {
        let runtime = CheckFakeRuntime::new(generic_dispatch);
        let (rows, _) =
            run_live_checks(&runtime, "container-id", Some("dev"), Some(config), access).await;
        (rows, runtime.calls())
    }

    fn running_container(image: &str) -> ContainerInfo {
        ContainerInfo {
            id: "container-id".to_string(),
            name: "dev-workspace".to_string(),
            state: ContainerState::Running,
            labels: HashMap::new(),
            image: image.to_string(),
        }
    }

    fn config_naming_no_remote_user() -> DevcontainerConfig {
        serde_json::from_str(r#"{"image": "ubuntu:24.04"}"#)
            .expect("a config naming no remoteUser must parse")
    }

    /// The image inspect runs before the first probe, so `PROBE_BUDGET` never
    /// reaches it and the client's own two-minute default is what a wedged
    /// daemon would otherwise cost. The elapsed time is the assertion: an
    /// unbudgeted await against a daemon that answers late ends up at the
    /// same `Some(user)` this is meant to rule out.
    #[tokio::test(start_paused = true)]
    async fn a_wedged_image_inspect_gives_up_on_the_probe_user_inside_its_own_budget() {
        let runtime = CheckFakeRuntime::new(|_| exec_exit(127, "", ""))
            .with_image_inspect(USER_BUDGET + Duration::from_secs(115), "image-user");

        let started = tokio::time::Instant::now();
        let user = resolve_check_user(
            &runtime,
            &running_container("ubuntu:24.04"),
            Some(&config_naming_no_remote_user()),
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(elapsed, USER_BUDGET);
        assert_eq!(
            user, None,
            "a user that could not be resolved degrades to no override"
        );
    }

    /// The budget bounds the inspect rather than replacing it: a daemon that
    /// answers inside it still names the user every probe then runs as.
    #[tokio::test(start_paused = true)]
    async fn an_image_inspect_that_answers_inside_the_budget_still_names_the_probe_user() {
        let runtime = CheckFakeRuntime::new(|_| exec_exit(127, "", ""))
            .with_image_inspect(Duration::from_secs(1), "image-user");

        let user = resolve_check_user(
            &runtime,
            &running_container("ubuntu:24.04"),
            Some(&config_naming_no_remote_user()),
        )
        .await;

        assert_eq!(user.as_deref(), Some("image-user"));
    }

    /// Table-driven over `ssh-add`'s three exit codes: 0 and 1 both mean the
    /// agent answered, only 2 means it could not be reached.
    #[test]
    fn an_ssh_agent_that_cannot_be_contacted_is_told_apart_from_one_with_no_keys() {
        let cases = [
            (0, CheckStatus::Ok),
            (1, CheckStatus::Ok),
            (2, CheckStatus::Failed),
        ];
        for (exit_code, expected) in cases {
            let facts = SshProbeFacts {
                upstream: String::new(),
                auth_sock: "/dev/shm/ssh-agent.sock".to_string(),
                shim_executable: false,
                socket_is_socket: false,
                ssh_add: SshAddStatus::Answered {
                    exit_code,
                    identity_count: 0,
                },
            };
            let SshVerdict::Row(status, _) = interpret_ssh_probe(&facts) else {
                panic!("exit_code={exit_code}: expected a decided row, not a liveness fallback");
            };
            assert_eq!(status, expected, "exit_code={exit_code}");
        }
    }

    /// A container told about no agent at all has nothing to answer for, so
    /// the row skips the way `dind` and `cmux relay` already do rather than
    /// sending the reader after a relay nobody asked for. The second row is
    /// the one that keeps this honest: the base layer's mounted socket also
    /// leaves the upstream empty, and a relay of its that died must stay a
    /// failure.
    #[test]
    fn a_container_given_no_agent_skips_while_a_configured_one_that_died_fails() {
        let cases = [
            ("", CheckStatus::Skipped),
            ("/dev/shm/ssh-agent.sock", CheckStatus::Failed),
        ];
        for (auth_sock, expected) in cases {
            let facts = SshProbeFacts {
                upstream: String::new(),
                auth_sock: auth_sock.to_string(),
                shim_executable: false,
                socket_is_socket: false,
                ssh_add: SshAddStatus::Answered {
                    exit_code: 2,
                    identity_count: 0,
                },
            };
            let SshVerdict::Row(status, _) = interpret_ssh_probe(&facts) else {
                panic!("auth_sock={auth_sock:?}: expected a decided row");
            };
            assert_eq!(status, expected, "auth_sock={auth_sock:?}");
        }
    }

    /// The probe has to report `SSH_AUTH_SOCK` for the skip above to be able
    /// to tell those two apart at all.
    #[test]
    fn the_ssh_probe_reports_the_auth_sock_it_found() {
        let facts = parse_ssh_probe("UPSTREAM:\nAUTHSOCK:/dev/shm/ssh-agent.sock\nSHIM:no\n");
        assert_eq!(facts.auth_sock, "/dev/shm/ssh-agent.sock");
        assert!(
            ssh_probe_script().contains("SSH_AUTH_SOCK"),
            "the probe script must read SSH_AUTH_SOCK, got: {}",
            ssh_probe_script()
        );
    }

    #[test]
    fn the_ssh_mechanism_is_read_from_the_upstream_the_container_was_given() {
        assert_eq!(ssh_mechanism_label(""), "no upstream configured");
        assert_eq!(
            ssh_mechanism_label("unix:/ssh-agent/host-agent.sock"),
            "relay (unix)"
        );
        assert_eq!(
            ssh_mechanism_label("tcp:host.docker.internal:51482"),
            "relay"
        );
    }

    #[test]
    fn a_bound_socket_alone_is_not_reported_as_a_working_agent() {
        let facts = SshProbeFacts {
            upstream: "unix:/ssh-agent/host-agent.sock".to_string(),
            auth_sock: "/dev/shm/ssh-agent.sock".to_string(),
            shim_executable: true,
            socket_is_socket: true,
            ssh_add: SshAddStatus::Answered {
                exit_code: 2,
                identity_count: 0,
            },
        };
        let SshVerdict::Row(status, detail) = interpret_ssh_probe(&facts) else {
            panic!("exit code 2 must be a decided row, not a liveness fallback");
        };
        assert_eq!(status, CheckStatus::Failed);
        assert!(
            detail.contains("the local socket is bound"),
            "a bound socket alone must not read as ok: {detail}"
        );
    }

    #[tokio::test]
    async fn an_image_without_ssh_add_falls_back_to_the_shim_liveness_probe() {
        for (liveness_exit, expected) in [(0, CheckStatus::Ok), (1, CheckStatus::Failed)] {
            let runtime = CheckFakeRuntime::new(move |cmd| {
                let script = cmd.get(2).map(String::as_str).unwrap_or("");
                if script.starts_with(": |") {
                    exec_exit(liveness_exit, "", "")
                } else {
                    ok(
                        "UPSTREAM:tcp:host.docker.internal:51482\nSHIM:yes\nSOCKET:yes\nSSHADD:missing\n",
                    )
                }
            });

            let row = check_ssh_agent(&runtime, "container-id", None).await;

            assert_eq!(row.status, expected, "liveness_exit={liveness_exit}");
            assert_eq!(
                runtime.calls().len(),
                2,
                "a missing ssh-add must fall back to a second exec, the shim's own liveness probe"
            );
        }
    }

    /// The shim exits 1 on anything but a `tcp:` upstream, so asking it about
    /// a mount can only report a working agent as broken. The exec count is
    /// the assertion that matters: the shim must never be reached at all.
    #[tokio::test]
    async fn a_missing_ssh_add_outside_a_tcp_upstream_never_reaches_the_shim() {
        for upstream in ["unix:/ssh-agent/host-agent.sock", ""] {
            let runtime = CheckFakeRuntime::new(move |_| {
                ok(format!(
                    "UPSTREAM:{upstream}\nSHIM:yes\nSOCKET:yes\nSSHADD:missing\n"
                ))
            });

            let row = check_ssh_agent(&runtime, "container-id", None).await;

            assert_eq!(row.status, CheckStatus::Skipped, "upstream={upstream:?}");
            assert_eq!(
                row.detail,
                format!(
                    "{}, no ssh-add in this container to ask the agent",
                    ssh_mechanism_label(upstream)
                ),
                "upstream={upstream:?}"
            );
            assert_eq!(
                row.remediation, None,
                "nothing is broken, so nothing to send the user debugging: upstream={upstream:?}"
            );
            assert_eq!(
                runtime.calls().len(),
                1,
                "upstream={upstream:?}: the shim may not be invoked for an upstream it refuses"
            );
        }
    }

    #[test]
    fn a_tcp_upstream_with_no_shim_installed_is_a_failure() {
        let facts = SshProbeFacts {
            upstream: "tcp:host.docker.internal:51482".to_string(),
            auth_sock: String::new(),
            shim_executable: false,
            socket_is_socket: false,
            ssh_add: SshAddStatus::Missing,
        };
        let SshVerdict::Row(status, detail) = interpret_ssh_probe(&facts) else {
            panic!("a tcp upstream with no shim must be a decided row, not a liveness fallback");
        };
        assert_eq!(status, CheckStatus::Failed);
        assert!(detail.contains(ssh_agent::FEATURE_NAME), "{detail}");
    }

    #[test]
    fn a_login_shells_chatter_on_stdout_cannot_be_mistaken_for_the_answer() {
        let stdout = "Message of the day\nWelcome to Ubuntu 24.04 LTS\nUPSTREAM:tcp:host.docker.internal:51482\nSHIM:yes\nSOCKET:yes\nSSHADD:0:2\n";

        let facts = parse_ssh_probe(stdout);

        assert_eq!(facts.upstream, "tcp:host.docker.internal:51482");
        assert!(facts.shim_executable);
        assert!(facts.socket_is_socket);
        assert!(matches!(
            facts.ssh_add,
            SshAddStatus::Answered {
                exit_code: 0,
                identity_count: 2
            }
        ));
    }

    /// Both chatter lines are real: `0 updates can be applied immediately.`
    /// opens with a token that passes the address shape on its own, so the
    /// alias has to be found among the names before the line counts.
    #[tokio::test]
    async fn a_login_shells_chatter_is_not_read_as_the_address_the_host_alias_resolves_to() {
        let access = desktop_access();
        let chatter = "Welcome to Ubuntu 24.04 LTS\n0 updates can be applied immediately.\n";
        let with_answer = CheckFakeRuntime::new(move |_| {
            ok(format!("{chatter}198.19.249.2 host.docker.internal\n"))
        });

        let row = check_host_alias(&with_answer, "container-id", None, access).await;

        assert_eq!(row.status, CheckStatus::Ok, "{}", row.detail);
        assert_eq!(row.detail, "resolves to 198.19.249.2");

        let chatter_only = CheckFakeRuntime::new(move |_| ok(chatter));

        let row = check_host_alias(&chatter_only, "container-id", None, access).await;

        assert_eq!(row.status, CheckStatus::Failed, "{}", row.detail);
        assert_eq!(
            row.detail,
            "`getent hosts host.docker.internal` printed no address"
        );
    }

    #[tokio::test]
    async fn an_address_answering_for_another_name_is_not_the_host_alias() {
        let runtime = CheckFakeRuntime::new(|_| ok("172.17.0.1 gateway.internal\n"));

        let row = check_host_alias(&runtime, "container-id", None, desktop_access()).await;

        assert_eq!(row.status, CheckStatus::Failed, "{}", row.detail);
        assert!(row.remediation.is_some());
    }

    #[tokio::test]
    async fn a_container_without_the_docker_cli_reports_dind_as_skipped_not_failed() {
        let by_exit_127 = CheckFakeRuntime::new(|_| exec_exit(127, "", "sh: docker: not found"));
        let row = check_dind(&by_exit_127, "container-id", None).await;
        assert_eq!(row.status, CheckStatus::Skipped, "{:?}", row.detail);
        assert_eq!(row.detail, "no docker CLI in this container");

        let by_missing_command = CheckFakeRuntime::new(|_| {
            ExecReply::Err(DevError::Runtime(
                "missing-command: no such executable".into(),
            ))
        });
        let row = check_dind(&by_missing_command, "container-id", None).await;
        assert_eq!(row.status, CheckStatus::Skipped, "{:?}", row.detail);
        assert_eq!(row.detail, "no docker CLI in this container");
    }

    #[tokio::test]
    async fn an_unreachable_docker_daemon_reports_dind_as_failed() {
        let runtime = CheckFakeRuntime::new(|_| {
            exec_exit(
                1,
                "",
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
            )
        });

        let row = check_dind(&runtime, "container-id", None).await;

        assert_eq!(row.status, CheckStatus::Failed);
        assert!(
            row.detail.contains("Cannot connect to the Docker daemon"),
            "{}",
            row.detail
        );
    }

    #[tokio::test]
    async fn a_login_shells_chatter_is_not_read_as_the_dind_server_version() {
        let with_version =
            CheckFakeRuntime::new(|_| ok("0 updates can be applied immediately.\n27.4.0\n"));

        let row = check_dind(&with_version, "container-id", None).await;

        assert_eq!(row.status, CheckStatus::Ok, "{}", row.detail);
        assert_eq!(row.detail, "server 27.4.0");

        let chatter_only = CheckFakeRuntime::new(|_| ok("0 updates can be applied immediately.\n"));

        let row = check_dind(&chatter_only, "container-id", None).await;

        assert_eq!(row.status, CheckStatus::Ok, "{}", row.detail);
        assert_eq!(
            row.detail,
            "the daemon answered but reported no server version"
        );
    }

    #[tokio::test]
    async fn a_container_without_the_cmux_shim_reports_the_relay_as_skipped() {
        let access = desktop_access();
        let by_exit_127 = CheckFakeRuntime::new(|_| exec_exit(127, "", "sh: cmux: not found"));
        let outcomes = [
            run_probe(
                &by_exit_127,
                "container-id",
                &cmux_agent::ping_command(),
                None,
                &[],
            )
            .await,
            ProbeOutcome::MissingCommand("missing-command: no such file".to_string()),
        ];
        for outcome in outcomes {
            let (row, refined) = interpret_cmux_ping(outcome, access);
            assert_eq!(row.status, CheckStatus::Skipped);
            assert_eq!(
                row.detail,
                "the cmux-agent feature is not installed in this container"
            );
            assert!(refined.is_none());
        }
    }

    #[tokio::test]
    async fn a_flavor_with_no_gateway_alias_skips_both_host_callback_checks_and_says_so() {
        let access = HostAccess::for_flavor(DockerFlavor::Colima);
        let config = enabled_cmux_config();
        let runtime =
            CheckFakeRuntime::new(|cmd| panic!("no exec expected for either check: {cmd:?}"));

        let host_alias_row = check_host_alias(&runtime, "container-id", None, access).await;
        assert_eq!(host_alias_row.status, CheckStatus::Skipped);
        assert_eq!(host_alias_row.detail, "this flavor has no host alias");

        let (relay_row, refined) =
            check_cmux_relay(&runtime, "container-id", None, Some(&config), access).await;
        assert_eq!(relay_row.status, CheckStatus::Skipped);
        assert_eq!(relay_row.detail, "this flavor has no host alias");
        assert!(refined.is_none());
        assert!(
            runtime.calls().is_empty(),
            "neither check may exec when there is no host alias to resolve"
        );

        let report = RuntimeReport {
            socket_path: None,
            daemon_version: None,
            access,
            checks: Some(vec![host_alias_row, relay_row]),
            mount_warning: None,
        };
        let rendered = report.render();
        assert!(rendered.contains("cmux agent relay"), "{rendered}");
        assert!(rendered.contains("SSH agent relay"), "{rendered}");
    }

    #[test]
    fn both_socket_mount_fields_get_their_own_row() {
        let access = HostAccess::for_flavor(DockerFlavor::OrbStack);

        let facts = access_facts(access);

        let docker_socket = facts
            .iter()
            .find(|f| f.label == "docker socket mount")
            .expect("a docker socket mount row");
        let host_sockets = facts
            .iter()
            .find(|f| f.label == "host socket mounts")
            .expect("a host socket mounts row");
        assert_ne!(docker_socket.label, host_sockets.label);
        assert_eq!(docker_socket.value, "works");
        assert_eq!(host_sockets.value, "do not work");
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_that_never_answers_is_reported_as_a_timeout_naming_the_seconds() {
        let access = desktop_access();
        let runtime =
            CheckFakeRuntime::new(|_| ExecReply::Delayed(PROBE_BUDGET + Duration::from_secs(60)));

        let row = check_host_alias(&runtime, "container-id", None, access).await;

        assert_eq!(row.status, CheckStatus::Failed);
        assert_eq!(row.detail, timeout_detail(PROBE_BUDGET.as_secs_f64()));
    }

    #[tokio::test]
    async fn every_probe_runs_as_the_resolved_remote_user_through_a_login_shell() {
        let (rows, calls) = drive_all_checks(desktop_access(), &enabled_cmux_config()).await;

        assert!(!calls.is_empty());
        for call in &calls {
            assert_eq!(call.cmd[0], "sh", "{call:?}");
            assert_eq!(call.cmd[1], "-lc", "{call:?}");
            assert_eq!(call.user.as_deref(), Some("dev"), "{call:?}");
        }
        // `generic_dispatch` answers anything it does not recognise,
        // including the relay's own ping, with exit 127: whether or not this
        // process has a live cmux to answer `agent::start`, an unmatched
        // script reads as a missing shim rather than a broken relay.
        let relay = rows
            .iter()
            .find(|row| row.name == CMUX_RELAY)
            .expect("a cmux relay row");
        assert_eq!(relay.status, CheckStatus::Skipped);
    }

    /// `cmux_agent::start` resolves a real cmux target through a
    /// process-global `OnceLock`, so whether the relay ping runs at all
    /// depends on this process having a live cmux — true in a cmux-run
    /// session, false in a plain terminal. Either way, no call but the ping
    /// itself may carry `DEV_CMUX_TOKEN`.
    #[tokio::test]
    async fn only_the_relay_probe_is_given_relay_credentials() {
        let (_, calls) = drive_all_checks(desktop_access(), &enabled_cmux_config()).await;

        assert!(!calls.is_empty());
        let is_relay_ping = |call: &RecordedCall| {
            call.cmd
                .iter()
                .any(|arg| arg.contains("cmux") && arg.contains("ping"))
        };

        for call in calls.iter().filter(|call| !is_relay_ping(call)) {
            assert!(
                call.env_keys.is_empty(),
                "no probe but the relay ping may carry relay credentials: {call:?}"
            );
        }
        for call in calls.iter().filter(|call| is_relay_ping(call)) {
            assert!(
                call.env_keys.contains(&"DEV_CMUX_TOKEN".to_string()),
                "the relay ping must carry its own token: {call:?}"
            );
        }
    }

    #[test]
    fn a_relay_ping_that_answered_marks_host_loopback_as_probed() {
        let access = HostAccess::for_flavor(DockerFlavor::Engine);
        let outcome = ProbeOutcome::Ran(ExecResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });

        let (row, refined) = interpret_cmux_ping(outcome, access);

        assert_eq!(row.status, CheckStatus::Ok);
        let refined = refined.expect("a successful ping must refine the descriptor");
        assert!(refined.reaches_host_loopback);
        assert!(refined.probed.reaches_host_loopback);
        let loopback_fact = access_facts(refined)
            .into_iter()
            .find(|f| f.label == "host loopback")
            .expect("a host loopback row");
        assert_eq!(loopback_fact.source, Some("probe"));
    }

    #[test]
    fn a_relay_ping_that_failed_leaves_host_loopback_on_the_table_value() {
        let access = HostAccess::for_flavor(DockerFlavor::Engine);
        let outcomes = [
            ProbeOutcome::Ran(ExecResult {
                exit_code: 1,
                stdout: String::new(),
                stderr: String::new(),
            }),
            ProbeOutcome::Refused("token mismatch".to_string()),
            ProbeOutcome::TimedOut(5.0),
        ];
        for outcome in outcomes {
            let (row, refined) = interpret_cmux_ping(outcome, access);
            assert_eq!(row.status, CheckStatus::Failed);
            assert!(refined.is_none(), "a failed ping proves nothing either way");
            let loopback_fact = access_facts(refined.unwrap_or(access))
                .into_iter()
                .find(|f| f.label == "host loopback")
                .expect("a host loopback row");
            assert_eq!(loopback_fact.source, Some("table"));
        }
    }

    #[test]
    fn mount_sources_outside_the_home_directory_are_named() {
        let home = Path::new("/Users/mwarren");
        let sources = vec![
            PathBuf::from("/Users/mwarren/.ssh"),
            PathBuf::from("/Users/mwarrenx/keys"),
            PathBuf::from("/opt/certs"),
        ];

        let outside = mount_sources_outside_home(&sources, home);

        assert_eq!(
            outside,
            vec![
                PathBuf::from("/Users/mwarrenx/keys"),
                PathBuf::from("/opt/certs"),
            ],
            "a string-prefix test would wave /Users/mwarrenx/keys through"
        );
    }

    #[test]
    fn the_mount_scope_warning_is_raised_only_on_colima() {
        let config: DevcontainerConfig = serde_json::from_str(
            r#"{"image": "ubuntu:24.04", "mounts": ["source=/opt/certs,target=/certs,type=bind"]}"#,
        )
        .expect("a config with one mount outside home must parse");
        let workspace = Path::new("/tmp/workspace");
        let accesses = [
            HostAccess::unknown(),
            HostAccess::for_flavor(DockerFlavor::DockerDesktop),
            HostAccess::for_flavor(DockerFlavor::OrbStack),
            HostAccess::for_flavor(DockerFlavor::Engine),
        ];
        for access in accesses {
            assert_eq!(
                mount_scope_warning(&config, workspace, access),
                None,
                "{:?}",
                access.flavor
            );
        }
        assert!(
            mount_scope_warning(
                &config,
                workspace,
                HostAccess::for_flavor(DockerFlavor::Colima)
            )
            .is_some()
        );
    }

    #[test]
    fn an_undetected_flavor_prints_as_unknown_rather_than_engine() {
        let report = RuntimeReport {
            socket_path: None,
            daemon_version: None,
            access: HostAccess::unknown(),
            checks: None,
            mount_warning: None,
        };

        let rendered = report.render();

        assert!(rendered.contains("unknown"), "{rendered}");
        assert!(!rendered.contains("engine"), "{rendered}");
    }

    #[test]
    fn the_static_facts_are_printed_with_no_container_and_the_hint_says_dev_up() {
        let report = RuntimeReport {
            socket_path: Some("/var/run/docker.sock".to_string()),
            daemon_version: Some("27.4.0".to_string()),
            access: desktop_access(),
            checks: None,
            mount_warning: None,
        };

        let rendered = report.render();

        assert!(rendered.contains("/var/run/docker.sock"));
        assert!(rendered.contains("docker-desktop"));
        assert!(rendered.contains("27.4.0"));
        assert!(rendered.contains("dev up"));
        assert!(
            !rendered.contains("CHECK"),
            "no checks were run: {rendered}"
        );
    }

    #[test]
    fn each_descriptor_row_says_whether_it_came_from_the_table_or_a_probe() {
        let mut access = HostAccess::for_flavor(DockerFlavor::Engine);
        access.probed = Probed {
            gateway_alias: true,
            reaches_host_loopback: false,
        };

        let facts = access_facts(access);
        let by_label = |label: &str| facts.iter().find(|f| f.label == label).unwrap();

        assert_eq!(by_label("host alias").source, Some("probe"));
        assert_eq!(by_label("host loopback").source, Some("table"));
        for label in [
            "alias injected",
            "docker socket mount",
            "host socket mounts",
            "ownership",
        ] {
            assert_eq!(by_label(label).source, Some("table"), "{label}");
        }
    }

    #[test]
    fn the_json_object_carries_the_runtime_section_beside_the_containers() {
        let report = RuntimeReport {
            socket_path: Some("/var/run/docker.sock".to_string()),
            daemon_version: Some("27.4.0".to_string()),
            access: desktop_access(),
            checks: Some(vec![
                ok_row(HOST_ALIAS, "resolves to 198.19.249.2"),
                failed_row(
                    SSH_AGENT,
                    "could not contact the agent",
                    remediation_ssh_agent(),
                ),
            ]),
            mount_warning: Some("Colima only shares your home directory with the VM".to_string()),
        };

        let value = report.to_json();

        let checks = value["checks"].as_array().expect("checks must be an array");
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0]["status"], "ok");
        assert_eq!(checks[0]["detail"], "resolves to 198.19.249.2");
        assert_eq!(checks[1]["status"], "failed");
        assert_eq!(checks[1]["detail"], "could not contact the agent");
        assert!(value["mountWarning"].as_str().unwrap().contains("Colima"));
    }
}
