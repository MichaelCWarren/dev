use crate::devcontainer::config::{DevcontainerConfig, LifecycleCommand};
use crate::devcontainer::features::ResolvedFeature;
use crate::error::DevError;
use crate::runtime::{ContainerRuntime, ExecResult};
use crate::session::{HostIdentity, SessionKind, host_identity, recorded_script};

/// Execute all lifecycle hooks in the devcontainer spec order.
///
/// Container lifecycle hooks are workspace-scoped commands: callers pass the
/// resolved `workspaceFolder` so a reused container with a stale `WorkingDir`
/// does not run hooks in an unrelated directory.
///
/// Hooks run in order:
/// 1. onCreateCommand  (feature hooks first, then devcontainer.json)
/// 2. updateContentCommand
/// 3. postCreateCommand (feature hooks first, then devcontainer.json)
/// 4. postStartCommand  (feature hooks first, then devcontainer.json)
///
/// `postAttachCommand` is not run here as it requires an attached session.
/// Use [`run_post_attach_hooks`] for that.
pub async fn run_lifecycle_hooks<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    config: &DevcontainerConfig,
    user: Option<&str>,
    workdir: Option<&str>,
    features: Option<&[ResolvedFeature]>,
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
        &host,
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
    host: &HostIdentity,
) -> Result<(), DevError> {
    let empty = Vec::new();
    let features = features.unwrap_or(&empty);

    // onCreateCommand: features first (in dependency order), then config
    for f in features {
        if let Some(ref cmd) = f.lifecycle_hooks.on_create_command {
            run_hook(
                runtime,
                container_id,
                &format!("onCreateCommand [{}]", f.id),
                cmd,
                user,
                workdir,
                host,
            )
            .await?;
        }
    }
    if let Some(ref cmd) = config.on_create_command {
        run_hook(
            runtime,
            container_id,
            "onCreateCommand",
            cmd,
            user,
            workdir,
            host,
        )
        .await?;
    }

    // updateContentCommand: config only (features don't declare this)
    if let Some(ref cmd) = config.update_content_command {
        run_hook(
            runtime,
            container_id,
            "updateContentCommand",
            cmd,
            user,
            workdir,
            host,
        )
        .await?;
    }

    // postCreateCommand: features first, then config
    for f in features {
        if let Some(ref cmd) = f.lifecycle_hooks.post_create_command {
            run_hook(
                runtime,
                container_id,
                &format!("postCreateCommand [{}]", f.id),
                cmd,
                user,
                workdir,
                host,
            )
            .await?;
        }
    }
    if let Some(ref cmd) = config.post_create_command {
        run_hook(
            runtime,
            container_id,
            "postCreateCommand",
            cmd,
            user,
            workdir,
            host,
        )
        .await?;
    }

    // postStartCommand: features first, then config
    for f in features {
        if let Some(ref cmd) = f.lifecycle_hooks.post_start_command {
            run_hook(
                runtime,
                container_id,
                &format!("postStartCommand [{}]", f.id),
                cmd,
                user,
                workdir,
                host,
            )
            .await?;
        }
    }
    if let Some(ref cmd) = config.post_start_command {
        run_hook(
            runtime,
            container_id,
            "postStartCommand",
            cmd,
            user,
            workdir,
            host,
        )
        .await?;
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
) -> Result<(), DevError> {
    let empty = Vec::new();
    let features = features.unwrap_or(&empty);
    let host = host_identity().await;
    let host = &host;

    for f in features {
        if let Some(ref cmd) = f.lifecycle_hooks.post_attach_command {
            run_hook(
                runtime,
                container_id,
                &format!("postAttachCommand [{}]", f.id),
                cmd,
                user,
                workdir,
                host,
            )
            .await?;
        }
    }
    if let Some(ref cmd) = config.post_attach_command {
        run_hook(
            runtime,
            container_id,
            "postAttachCommand",
            cmd,
            user,
            workdir,
            host,
        )
        .await?;
    }

    Ok(())
}

async fn run_hook<R: ContainerRuntime + ?Sized>(
    runtime: &R,
    container_id: &str,
    name: &str,
    cmd: &LifecycleCommand,
    user: Option<&str>,
    workdir: Option<&str>,
    host: &HostIdentity,
) -> Result<(), DevError> {
    match cmd {
        LifecycleCommand::Single(command) => {
            eprintln!("[lifecycle] Running {name}: {command}");
            let args = hook_args(command, host);
            let result = runtime.exec(container_id, &args, user, workdir).await?;
            check_result(name, command, &result)?;
        }
        LifecycleCommand::Multiple(commands) => {
            for command in commands {
                eprintln!("[lifecycle] Running {name}: {command}");
                let args = hook_args(command, host);
                let result = runtime.exec(container_id, &args, user, workdir).await?;
                check_result(name, command, &result)?;
            }
        }
        LifecycleCommand::Parallel(commands) => {
            run_parallel(runtime, container_id, name, commands, user, workdir, host).await?;
        }
    }
    Ok(())
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
    runtime: &R,
    container_id: &str,
    name: &str,
    commands: &std::collections::HashMap<String, String>,
    user: Option<&str>,
    workdir: Option<&str>,
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
                    .exec(&container_id, &args, user.as_deref(), workdir.as_deref())
                    .await?;
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
