use crate::devcontainer::config::{DevcontainerConfig, LifecycleCommand};
use crate::devcontainer::features::{FeatureLifecycleHooks, ResolvedFeature};
use crate::devcontainer::hooklog::HookLog;
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

/// Execute the hooks a freshly created container is owed.
///
/// Runs, in spec order: `onCreateCommand`, `updateContentCommand`,
/// `postCreateCommand`, `postStartCommand` — feature hooks before config hooks
/// at each stage. Use [`run_start_hooks`] for a container that already existed.
///
/// `postAttachCommand` is not run here as it requires an attached session.
/// Use [`run_post_attach_hooks`] for that.
pub async fn run_create_hooks<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    config: &DevcontainerConfig,
    user: Option<&str>,
    workdir: Option<&str>,
    features: Option<&[ResolvedFeature]>,
    log: Option<&HookLog>,
) -> Result<(), DevError> {
    run_hooks(
        runtime,
        container_id,
        config,
        user,
        workdir,
        features,
        log,
        Stages::CreateAndStart,
    )
    .await
}

/// Execute the hooks a container that already existed is owed on restart.
///
/// Runs `postStartCommand` only. The create-time hooks ran when the container
/// was created, and re-running them would repeat work that is rarely idempotent
/// — `postCreateCommand` is where toolchains get installed and databases get
/// seeded.
pub async fn run_start_hooks<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    config: &DevcontainerConfig,
    user: Option<&str>,
    workdir: Option<&str>,
    features: Option<&[ResolvedFeature]>,
    log: Option<&HookLog>,
) -> Result<(), DevError> {
    run_hooks(
        runtime,
        container_id,
        config,
        user,
        workdir,
        features,
        log,
        Stages::StartOnly,
    )
    .await
}

/// Container lifecycle hooks are workspace-scoped commands: callers pass the
/// resolved `workspaceFolder` so a reused container with a stale `WorkingDir`
/// does not run hooks in an unrelated directory.
#[allow(clippy::too_many_arguments)]
async fn run_hooks<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    config: &DevcontainerConfig,
    user: Option<&str>,
    workdir: Option<&str>,
    features: Option<&[ResolvedFeature]>,
    log: Option<&HookLog>,
    stages: Stages,
) -> Result<(), DevError> {
    // Before adding sessions of its own, this collects the ones whose client is
    // gone — a container being brought up is one nothing else has looked at yet.
    match crate::session::sweep(runtime, container_id, user).await {
        Ok(0) => {}
        Ok(reaped) => eprintln!("[lifecycle] Reaped {reaped} orphaned container session(s)"),
        Err(e) => eprintln!("[lifecycle] Warning: could not check for orphaned sessions: {e}"),
    }

    let host = host_identity().await;
    let hooks = run_hooks_in_order(
        runtime,
        container_id,
        config,
        user,
        workdir,
        features,
        log,
        &host,
        stages,
    );
    attend_hooks(runtime, container_id, user, &host, hooks).await
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

#[allow(clippy::too_many_arguments)]
async fn run_hooks_in_order<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    config: &DevcontainerConfig,
    user: Option<&str>,
    workdir: Option<&str>,
    features: Option<&[ResolvedFeature]>,
    log: Option<&HookLog>,
    host: &HostIdentity,
    stages: Stages,
) -> Result<(), DevError> {
    let empty = Vec::new();
    let features = features.unwrap_or(&empty);

    if stages == Stages::CreateAndStart {
        run_stage(
            runtime,
            container_id,
            "onCreateCommand",
            features,
            |h| h.on_create_command.as_ref(),
            config.on_create_command.as_ref(),
            user,
            workdir,
            log,
            host,
        )
        .await?;

        // updateContentCommand: config only, features don't declare this.
        if let Some(cmd) = config.update_content_command.as_ref() {
            run_hook(
                runtime,
                container_id,
                "updateContentCommand",
                cmd,
                user,
                workdir,
                log,
                host,
            )
            .await?;
        }

        run_stage(
            runtime,
            container_id,
            "postCreateCommand",
            features,
            |h| h.post_create_command.as_ref(),
            config.post_create_command.as_ref(),
            user,
            workdir,
            log,
            host,
        )
        .await?;
    }

    run_stage(
        runtime,
        container_id,
        "postStartCommand",
        features,
        |h| h.post_start_command.as_ref(),
        config.post_start_command.as_ref(),
        user,
        workdir,
        log,
        host,
    )
    .await
}

/// Run one lifecycle stage: every feature's hook in dependency order, then the
/// devcontainer.json hook.
#[allow(clippy::too_many_arguments)]
async fn run_stage<R, F>(
    runtime: &R,
    container_id: &str,
    stage: &str,
    features: &[ResolvedFeature],
    feature_hook: F,
    config_hook: Option<&LifecycleCommand>,
    user: Option<&str>,
    workdir: Option<&str>,
    log: Option<&HookLog>,
    host: &HostIdentity,
) -> Result<(), DevError>
where
    R: ContainerRuntime + ?Sized,
    F: Fn(&FeatureLifecycleHooks) -> Option<&LifecycleCommand>,
{
    for f in features {
        if let Some(cmd) = feature_hook(&f.lifecycle_hooks) {
            run_hook(
                runtime,
                container_id,
                &format!("{stage} [{}]", f.id),
                cmd,
                user,
                workdir,
                log,
                host,
            )
            .await?;
        }
    }
    if let Some(cmd) = config_hook {
        run_hook(runtime, container_id, stage, cmd, user, workdir, log, host).await?;
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

    run_stage(
        runtime,
        container_id,
        "postAttachCommand",
        features,
        |h| h.post_attach_command.as_ref(),
        config.post_attach_command.as_ref(),
        user,
        workdir,
        log,
        &host,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_hook<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    name: &str,
    cmd: &LifecycleCommand,
    user: Option<&str>,
    workdir: Option<&str>,
    log: Option<&HookLog>,
    host: &HostIdentity,
) -> Result<(), DevError> {
    match cmd {
        LifecycleCommand::Single(command) => {
            eprintln!("[lifecycle] Running {name}: {command}");
            let args = hook_args(command, host);
            let result = runtime
                .exec(container_id, &args, user, workdir, &[])
                .await?;
            record_hook(log, name, command, &result);
            check_result(name, command, &result)?;
        }
        LifecycleCommand::Multiple(commands) => {
            for command in commands {
                eprintln!("[lifecycle] Running {name}: {command}");
                let args = hook_args(command, host);
                let result = runtime
                    .exec(container_id, &args, user, workdir, &[])
                    .await?;
                record_hook(log, name, command, &result);
                check_result(name, command, &result)?;
            }
        }
        LifecycleCommand::Parallel(commands) => {
            run_parallel(
                runtime,
                container_id,
                name,
                commands,
                user,
                workdir,
                log,
                host,
            )
            .await?;
        }
    }
    Ok(())
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
#[allow(clippy::too_many_arguments)]
async fn run_parallel<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    name: &str,
    commands: &std::collections::HashMap<String, String>,
    user: Option<&str>,
    workdir: Option<&str>,
    log: Option<&HookLog>,
    host: &HostIdentity,
) -> Result<(), DevError> {
    use futures_util::future::join_all;

    let futures: Vec<_> = commands
        .iter()
        .map(|(label, command)| {
            let label = label.clone();
            let command = command.clone();
            let container_id = container_id.to_string();
            let name = name.to_string();
            let user = user.map(|u| u.to_string());
            let workdir = workdir.map(|d| d.to_string());

            async move {
                eprintln!("[lifecycle] Running {name} ({label}): {command}");
                let args = hook_args(&command, host);
                let result = runtime
                    .exec(
                        &container_id,
                        &args,
                        user.as_deref(),
                        workdir.as_deref(),
                        &[],
                    )
                    .await?;
                record_hook(log, &name, &command, &result);
                check_result(&name, &command, &result)?;
                Ok::<(), DevError>(())
            }
        })
        .collect();

    let results = join_all(futures).await;
    for result in results {
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
