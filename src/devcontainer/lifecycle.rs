use crate::devcontainer::config::{DevcontainerConfig, LifecycleCommand};
use crate::devcontainer::features::{FeatureLifecycleHooks, ResolvedFeature};
use crate::devcontainer::hooklog::HookLog;
use crate::devcontainer::secrets::SecretValue;
use crate::error::DevError;
use crate::runtime::{ContainerRuntime, ExecResult};
use crate::session::{HostIdentity, SessionKind, host_identity, recorded_script};

/// Which hooks a container is owed at this moment.
///
/// A container is created once and started many times, and the spec splits the
/// hooks along that line. Callers pick a variant by naming the moment they are
/// at, so the decision cannot drift from what actually runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stages {
    CreateAndStart,
    StartOnly,
}

/// Where a container's hooks run, as whom, and what each one is handed.
pub struct HookTarget<'a, R: ?Sized> {
    pub runtime: &'a R,
    pub container_id: &'a str,
    pub user: Option<&'a str>,
    /// The resolved `workspaceFolder`, so a reused container with a stale
    /// `WorkingDir` does not run hooks in an unrelated directory.
    pub workdir: Option<&'a str>,
    pub log: Option<&'a HookLog>,
    /// Handed to every hook exec.
    pub env: &'a [(String, SecretValue)],
    /// This process, as each hook's session record names it.
    pub host: &'a HostIdentity,
}

/// Execute the hooks a freshly created container is owed.
///
/// Runs, in spec order: `onCreateCommand`, `updateContentCommand`,
/// `postCreateCommand`, `postStartCommand` — feature hooks before config hooks
/// at each stage. Use [`run_start_hooks`] for a container that already existed.
///
/// `postAttachCommand` is not run here as it requires an attached session.
/// Use [`run_post_attach_hooks`] for that.
pub async fn run_create_hooks<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    config: &DevcontainerConfig,
    features: Option<&[ResolvedFeature]>,
) -> Result<(), DevError> {
    run_hooks(target, config, features, Stages::CreateAndStart).await
}

/// Execute the hooks a container that already existed is owed on restart.
///
/// Runs `postStartCommand` only. The create-time hooks ran when the container
/// was created, and re-running them would repeat work that is rarely idempotent
/// — `postCreateCommand` is where toolchains get installed and databases get
/// seeded.
pub async fn run_start_hooks<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    config: &DevcontainerConfig,
    features: Option<&[ResolvedFeature]>,
) -> Result<(), DevError> {
    run_hooks(target, config, features, Stages::StartOnly).await
}

async fn run_hooks<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    config: &DevcontainerConfig,
    features: Option<&[ResolvedFeature]>,
    stages: Stages,
) -> Result<(), DevError> {
    let (runtime, container_id, user) = (target.runtime, target.container_id, target.user);
    // Before adding sessions of its own, this collects the ones whose client is
    // gone — a container being brought up is one nothing else has looked at yet.
    match crate::session::sweep(runtime, container_id, user).await {
        Ok(0) => {}
        Ok(reaped) => eprintln!("[lifecycle] Reaped {reaped} orphaned container session(s)"),
        Err(e) => eprintln!("[lifecycle] Warning: could not check for orphaned sessions: {e}"),
    }

    let hooks = run_hooks_in_order(target, config, features, stages);
    attend_hooks(runtime, container_id, user, target.host, hooks).await
}

/// Run the hooks, and end whichever is running if `dev` is told to go away.
///
/// A hook is an exec like any other, so an interrupted `dev up` would otherwise
/// leave its `postCreateCommand` installing a toolchain into a container that
/// nobody is waiting for any more.
async fn attend_hooks<R, F>(
    runtime: &R,
    container_id: &str,
    user: Option<&str>,
    host: &HostIdentity,
    hooks: F,
) -> Result<(), DevError>
where
    R: ContainerRuntime + ?Sized,
    F: std::future::Future<Output = Result<(), DevError>>,
{
    use tokio::signal::unix::{SignalKind, signal};

    let watch = |kind: SignalKind, name: &str| {
        signal(kind).map_err(|e| DevError::Runtime(format!("watch {name}: {e}")))
    };
    let mut interrupt = watch(SignalKind::interrupt(), "SIGINT")?;
    let mut terminate = watch(SignalKind::terminate(), "SIGTERM")?;
    let mut hangup = watch(SignalKind::hangup(), "SIGHUP")?;

    let mut hooks = Box::pin(hooks);
    let signalled = tokio::select! {
        done = &mut hooks => return done,
        _ = interrupt.recv() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
        _ = hangup.recv() => "SIGHUP",
    };

    drop(hooks);
    crate::session::release_own_sessions(runtime, container_id, user, host.pid).await;
    Err(DevError::Runtime(format!(
        "lifecycle hooks were interrupted by {signalled}"
    )))
}

async fn run_hooks_in_order<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    config: &DevcontainerConfig,
    features: Option<&[ResolvedFeature]>,
    stages: Stages,
) -> Result<(), DevError> {
    let empty = Vec::new();
    let features = features.unwrap_or(&empty);

    if stages == Stages::CreateAndStart {
        run_stage(
            target,
            "onCreateCommand",
            features,
            |h| h.on_create_command.as_ref(),
            config.on_create_command.as_ref(),
        )
        .await?;

        // updateContentCommand: config only, features don't declare this.
        if let Some(cmd) = config.update_content_command.as_ref() {
            run_hook(target, "updateContentCommand", cmd).await?;
        }

        run_stage(
            target,
            "postCreateCommand",
            features,
            |h| h.post_create_command.as_ref(),
            config.post_create_command.as_ref(),
        )
        .await?;
    }

    run_stage(
        target,
        "postStartCommand",
        features,
        |h| h.post_start_command.as_ref(),
        config.post_start_command.as_ref(),
    )
    .await
}

/// Run one lifecycle stage: every feature's hook in dependency order, then the
/// devcontainer.json hook.
async fn run_stage<R, F>(
    target: &HookTarget<'_, R>,
    stage: &str,
    features: &[ResolvedFeature],
    feature_hook: F,
    config_hook: Option<&LifecycleCommand>,
) -> Result<(), DevError>
where
    R: ContainerRuntime + ?Sized,
    F: Fn(&FeatureLifecycleHooks) -> Option<&LifecycleCommand>,
{
    for f in features {
        if let Some(cmd) = feature_hook(&f.lifecycle_hooks) {
            run_hook(target, &format!("{stage} [{}]", f.id), cmd).await?;
        }
    }
    if let Some(cmd) = config_hook {
        run_hook(target, stage, cmd).await?;
    }
    Ok(())
}

/// Execute `postAttachCommand` hooks from features and the devcontainer config.
///
/// This should be called when attaching to an existing container via an IDE
/// integration (e.g., VS Code Remote Containers), not on every exec/shell invocation.
#[allow(dead_code)]
pub async fn run_post_attach_hooks<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    config: &DevcontainerConfig,
    user: Option<&str>,
    workdir: Option<&str>,
    features: Option<&[ResolvedFeature]>,
    log: Option<&HookLog>,
) -> Result<(), DevError> {
    let empty = Vec::new();
    let features = features.unwrap_or(&empty);
    let host = host_identity().await;
    let target = HookTarget {
        runtime,
        container_id,
        user,
        workdir,
        log,
        env: &[],
        host: &host,
    };

    run_stage(
        &target,
        "postAttachCommand",
        features,
        |h| h.post_attach_command.as_ref(),
        config.post_attach_command.as_ref(),
    )
    .await
}

async fn run_hook<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    name: &str,
    cmd: &LifecycleCommand,
) -> Result<(), DevError> {
    match cmd {
        LifecycleCommand::Single(command) => {
            run_in_turn(target, name, std::slice::from_ref(command)).await
        }
        LifecycleCommand::Multiple(commands) => run_in_turn(target, name, commands).await,
        LifecycleCommand::Parallel(commands) => run_parallel(target, name, commands).await,
    }
}

async fn run_in_turn<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    name: &str,
    commands: &[String],
) -> Result<(), DevError> {
    for command in commands {
        eprintln!("[lifecycle] Running {name}: {command}");
        run_command(target, name, command).await?;
    }
    Ok(())
}

/// The log and any failure name the hook by `name`; the progress line is the
/// caller's.
async fn run_command<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    name: &str,
    command: &str,
) -> Result<(), DevError> {
    let args = hook_args(command, target.host);
    let result = target
        .runtime
        .exec(
            target.container_id,
            &args,
            target.user,
            target.workdir,
            target.env,
        )
        .await?;
    record_hook(target.log, name, command, &result);
    check_result(name, command, &result)
}

/// Append a hook's outcome to the workspace hook log, when one is being kept.
fn record_hook(log: Option<&HookLog>, name: &str, command: &str, result: &ExecResult) {
    if let Some(log) = log {
        log.record(name, command, result);
    }
}

/// The shell invocation for one hook.
///
/// A hook is the longest-running thing `dev up` does — installing a toolchain,
/// starting a service — and the one most likely to be interrupted. Recording it
/// means an abandoned `dev up` leaves something that can be found and ended,
/// rather than an install that runs on in a container nobody is watching.
fn hook_args(command: &str, host: &HostIdentity) -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        recorded_script(command, SessionKind::Hook, host),
    ]
}

/// Run named commands in parallel using tokio tasks (Gap 14).
async fn run_parallel<R: ContainerRuntime + ?Sized>(
    target: &HookTarget<'_, R>,
    name: &str,
    commands: &std::collections::BTreeMap<String, String>,
) -> Result<(), DevError> {
    use futures_util::future::join_all;

    let futures = commands.iter().map(|(label, command)| async move {
        eprintln!("[lifecycle] Running {name} ({label}): {command}");
        run_command(target, name, command).await
    });

    for result in join_all(futures).await {
        result?;
    }

    Ok(())
}

fn check_result(hook_name: &str, command: &str, result: &ExecResult) -> Result<(), DevError> {
    if result.exit_code != 0 {
        eprintln!(
            "[lifecycle] {hook_name} failed (exit {}):\nstdout: {}\nstderr: {}",
            result.exit_code, result.stdout, result.stderr
        );
        return Err(DevError::LifecycleHook {
            command: command.to_string(),
            code: result.exit_code,
        });
    }
    Ok(())
}
