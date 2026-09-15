use std::time::Duration;

use crate::runtime::docker::{BollardRuntime, DockerFlavor, detect_flavor};

/// How long a daemon gets to answer a ping. A local socket round trip is
/// well inside this; the number matters only against bollard's own 120s
/// client timeout (`docker.rs`'s `connect_to_socket`), which would otherwise
/// stall every `dev up` behind a wedged daemon.
pub(crate) const HOST_DETECT_BUDGET: Duration = Duration::from_secs(2);

/// How long a daemon gets to answer `/info`. Far longer than the ping budget
/// because `/_ping` returns two bytes while `/info` enumerates images,
/// containers, plugins and driver status: on a loaded or warming daemon it
/// routinely takes seconds with the ping still instant. The result is cached
/// for the life of the process and never retried, so one impatient timeout
/// costs the whole run its flavor.
pub(crate) const INFO_DETECT_BUDGET: Duration = Duration::from_secs(10);

/// What a container run through this daemon can reach on the host, and what
/// the host can reach back into the container. One row per Docker flavor
/// (`HostAccess::for_flavor`), plus `unknown()` and `podman()` for the
/// runtimes that are not a flavor-detected Docker daemon.
///
/// `Copy` is deliberate: refining a row (`with_loopback_verified`) consumes
/// and returns one rather than mutating a shared cache in place, so nothing
/// that costs `Copy` may be added here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAccess {
    /// The daemon's flavor, when this runtime speaks the Docker API and
    /// detection has run and could tell. `None` for every other runtime, and
    /// for a Docker daemon whose flavor could not be told apart. Present only
    /// so `dev status` can report it through `&dyn ContainerRuntime`, which
    /// has no other route to the flavor.
    pub flavor: Option<DockerFlavor>,
    /// The hostname a container uses to reach the host. `None` means there is
    /// no such name on this daemon, and every integration that needs to call
    /// back into the host stays off rather than resolving something wrong.
    pub gateway_alias: Option<&'static str>,
    /// Whether the daemon writes `gateway_alias` into the container's
    /// `/etc/hosts` itself. When false and `gateway_alias` is `Some`, the
    /// consumer must add `<alias>:host-gateway` to `extra_hosts`; when true
    /// it must not, since on Desktop that flag flips the resolved address to
    /// IPv6.
    pub injects_alias: bool,
    /// Whether a host listener bound to `127.0.0.1` answers a container that
    /// connects to `gateway_alias`. When false the consumer declines: it does
    /// not start the listener, and must not widen the bind to some address
    /// the container might reach instead.
    pub reaches_host_loopback: bool,
    /// Whether the host's own docker socket, bind-mounted into a container,
    /// gives a working docker client (docker-outside-of-docker). When false,
    /// callers report it unavailable instead of mounting a dead end.
    pub socket_mounts_work: bool,
    /// Whether an arbitrary host unix socket, bind-mounted into a container,
    /// is usable inside it — the case that matters is the 1Password agent
    /// socket. Reports and explains, does not gate: when false, `dev status`
    /// says the mounted agent socket cannot be relied on.
    pub host_sockets_mount: bool,
    /// Whether the mount layer presents bind-mounted files as owned by
    /// whoever opens them, so matching host and container UIDs buys nothing.
    /// When false, the mount preserves host uid/gid and consumers build the
    /// UID-remapping layer (`should_remap_uid`).
    pub squashes_ownership: bool,
    /// Which of the fields above were measured on this machine rather than
    /// taken from the flavor's table row.
    pub probed: Probed,
}

/// One `bool` per `HostAccess` field whose value can be measured rather than
/// assumed. `false` means the value beside it is the flavor's table row;
/// `dev status` prints "verified" only when the matching bit here is set, so
/// a guess is never reported as a fact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Probed {
    pub gateway_alias: bool,
    pub reaches_host_loopback: bool,
}

impl Probed {
    /// Nothing measured. A `const` rather than `Default::default()` because
    /// the flavor table is a `const fn`.
    pub const UNPROBED: Self = Self {
        gateway_alias: false,
        reaches_host_loopback: false,
    };
}

impl HostAccess {
    /// The table row for a known Docker flavor — the only place a flavor
    /// turns into behavior.
    pub const fn for_flavor(flavor: DockerFlavor) -> Self {
        match flavor {
            // Desktop special-cases `host.docker.internal` and injects it
            // itself. `src/cmux/agent.rs` already binds 127.0.0.1 and reaches
            // the container through that alias, and `host_sockets_mount` is
            // evidenced the same way: `~/.dev/base/devcontainer.json` mounts
            // the 1Password agent socket and it works today.
            DockerFlavor::DockerDesktop => Self {
                flavor: Some(flavor),
                gateway_alias: Some("host.docker.internal"),
                injects_alias: true,
                reaches_host_loopback: true,
                socket_mounts_work: true,
                host_sockets_mount: true,
                squashes_ownership: true,
                probed: Probed::UNPROBED,
            },
            // Alias and loopback are the vendor's claim, unverified here;
            // `dev status`'s relay ping is what confirms them. `host_sockets_mount` is
            // false on purpose: the VM special-cases its own docker socket
            // through the mount layer, but an arbitrary unix socket like the
            // 1Password agent's does not survive it.
            DockerFlavor::OrbStack => Self {
                flavor: Some(flavor),
                gateway_alias: Some("host.docker.internal"),
                injects_alias: true,
                reaches_host_loopback: true,
                socket_mounts_work: true,
                host_sockets_mount: false,
                squashes_ownership: false,
                probed: Probed::UNPROBED,
            },
            // `:host-gateway` resolves relative to the Lima guest, not the
            // Mac `dev` runs on, so an alias here would point at the wrong
            // machine — worse than none. This row promises nothing and gets
            // no host-callback integration at all.
            DockerFlavor::Colima => Self {
                flavor: Some(flavor),
                gateway_alias: None,
                injects_alias: false,
                reaches_host_loopback: false,
                socket_mounts_work: false,
                host_sockets_mount: false,
                squashes_ownership: false,
                probed: Probed::UNPROBED,
            },
            // Engine names an alias but injects nothing, and `:host-gateway`
            // resolves to the bridge address, which a listener bound only to
            // 127.0.0.1 cannot reach. Both socket fields are true because a
            // bind mount there is an ordinary bind mount on one kernel.
            DockerFlavor::Engine => Self {
                flavor: Some(flavor),
                gateway_alias: Some("host.docker.internal"),
                injects_alias: false,
                reaches_host_loopback: false,
                socket_mounts_work: true,
                host_sockets_mount: true,
                squashes_ownership: false,
                probed: Probed::UNPROBED,
            },
        }
    }

    /// What a runtime with no host-access story promises: nothing. The one
    /// exception is `squashes_ownership`, which repeats today's
    /// `should_remap_uid` macOS skip (`src/devcontainer/uid.rs`) so this
    /// default changes no one's behavior — Apple and every test fake are
    /// already living under it.
    pub const fn unknown() -> Self {
        Self {
            flavor: None,
            gateway_alias: None,
            injects_alias: false,
            reaches_host_loopback: false,
            socket_mounts_work: false,
            host_sockets_mount: false,
            squashes_ownership: cfg!(target_os = "macos"),
            probed: Probed::UNPROBED,
        }
    }

    /// The row for a podman daemon, which is never flavor-detected: podman
    /// names its own gateway alias and injects it, but none of the three
    /// socket/loopback bools is verified for podman machine yet, so they stay
    /// conservative until a probe can confirm them. `squashes_ownership` keeps
    /// today's remapping behavior on both platforms rather than picking one
    /// up by accident.
    pub const fn podman() -> Self {
        Self {
            flavor: None,
            gateway_alias: Some("host.containers.internal"),
            injects_alias: true,
            reaches_host_loopback: false,
            socket_mounts_work: false,
            host_sockets_mount: false,
            squashes_ownership: cfg!(target_os = "macos"),
            probed: Probed::UNPROBED,
        }
    }

    /// Fold in a measured loopback result, marking it verified. Consumes and
    /// returns a `Copy` value, so a caller refines its own copy and the
    /// cached row is untouched — `dev status` is the only caller.
    pub const fn with_loopback_verified(mut self, reachable: bool) -> Self {
        self.reaches_host_loopback = reachable;
        self.probed.reaches_host_loopback = true;
        self
    }

    /// A row that promises nothing at all, including on macOS. The base for
    /// a test that sets only the fields it is about, through struct-update
    /// syntax, rather than restating all eight.
    #[cfg(test)]
    pub(crate) const fn all_off() -> Self {
        Self {
            flavor: None,
            gateway_alias: None,
            injects_alias: false,
            reaches_host_loopback: false,
            socket_mounts_work: false,
            host_sockets_mount: false,
            squashes_ownership: false,
            probed: Probed::UNPROBED,
        }
    }

    /// Where a host-callback integration (the cmux relay, the ssh agent
    /// relay) listens and what a container reaches it by, or why it cannot
    /// run here — the `Err` is what `dev status` prints.
    ///
    /// The bind is always loopback: widening it to reach a container would
    /// open the listener to every interface the host has, leaving each
    /// relay's own token as the entire boundary instead of the network. A
    /// daemon whose containers cannot reach a host loopback listener is
    /// refused here rather than widened.
    pub(crate) fn host_callback(&self) -> Result<HostCallback, &'static str> {
        let Some(alias) = self.gateway_alias else {
            return Err("this flavor has no host alias");
        };
        if !self.reaches_host_loopback {
            return Err("containers on this flavor cannot reach a host loopback listener");
        }
        Ok(HostCallback {
            bind: "127.0.0.1",
            alias,
        })
    }

    /// The `--add-host` entry to hand the daemon so a container can resolve
    /// the host, or none. Setting it when the daemon already injects the
    /// alias itself (Docker Desktop) overrides that address with our own and
    /// flips it to IPv6, breaking a working setup.
    pub(crate) fn host_gateway_entry(&self) -> Option<String> {
        match self.gateway_alias {
            Some(alias) if !self.injects_alias => Some(format!("{alias}:host-gateway")),
            _ => None,
        }
    }
}

/// The two addresses a host-callback listener needs: the one it binds, and
/// the one the container is handed.
pub(crate) struct HostCallback {
    pub bind: &'static str,
    pub alias: &'static str,
}

/// A daemon's host-access row plus the version string it reported, cached
/// together so `dev status` recovering the version never costs a second
/// `info()` round trip. The version lives outside `HostAccess` because a
/// `String` there would cost every consumer `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedDaemon {
    pub access: HostAccess,
    pub version: Option<String>,
}

impl DetectedDaemon {
    /// Ask the daemon what it is, once, and turn the answer into a row.
    /// Infallible: a timeout or a transport error degrades to a
    /// socket-path-only guess rather than failing `dev up`.
    pub async fn probe(runtime: &BollardRuntime) -> Self {
        let info = match tokio::time::timeout(INFO_DETECT_BUDGET, runtime.info()).await {
            Ok(Ok(info)) => Some(info),
            Ok(Err(_)) | Err(_) => None,
        };
        let version = info.as_ref().and_then(|info| info.server_version.clone());
        let access = match detect_flavor(info.as_ref(), runtime.socket_path()) {
            Some(flavor) => HostAccess::for_flavor(flavor),
            None => HostAccess::unknown(),
        };
        Self {
            access: refine_for_server_version(access, version.as_deref()),
            version,
        }
    }
}

/// `--add-host <alias>:host-gateway` needs Engine 20.10 or newer; below that,
/// `dev` has no way to wire the alias it would otherwise add. Only a row that
/// names an alias but does not get it injected by the daemon needs this —
/// today that is `Engine` alone, since every self-injecting row already
/// works regardless of version.
fn refine_for_server_version(mut access: HostAccess, server_version: Option<&str>) -> HostAccess {
    if access.injects_alias || access.gateway_alias.is_none() {
        return access;
    }
    let Some(version) = server_version.and_then(parse_major_minor) else {
        return access;
    };
    if version < (20, 10) {
        access.gateway_alias = None;
        // Only this arm measured anything. Leaving the alias at the table's
        // value is the table speaking, and `dev status` must not report it as
        // a probe.
        access.probed.gateway_alias = true;
    }
    access
}

fn parse_major_minor(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::secrets::SecretValue;
    use crate::error::DevError;
    use crate::runtime::podman::PodmanRuntime;
    use crate::runtime::{
        AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ContainerRuntime, ExecResult,
        ImageMetadata,
    };
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    /// The whole table asserted row by row, every column. The cells that
    /// matter most: Desktop's `injects_alias: true` (a `false` there
    /// re-introduces the `--add-host` IPv6 flip), OrbStack's
    /// `host_sockets_mount: false` (a `true` there tells OrbStack users their
    /// agent socket mount works when it may not), and Colima's all-off row.
    #[test]
    fn each_flavor_promises_only_what_it_delivers() {
        let cases = [
            // (flavor, gateway_alias, injects_alias, reaches_host_loopback,
            //  socket_mounts_work, host_sockets_mount, squashes_ownership)
            (
                DockerFlavor::DockerDesktop,
                Some("host.docker.internal"),
                true,
                true,
                true,
                true,
                true,
            ),
            (
                DockerFlavor::OrbStack,
                Some("host.docker.internal"),
                true,
                true,
                true,
                false,
                false,
            ),
            (
                DockerFlavor::Colima,
                None,
                false,
                false,
                false,
                false,
                false,
            ),
            (
                DockerFlavor::Engine,
                Some("host.docker.internal"),
                false,
                false,
                true,
                true,
                false,
            ),
        ];
        for (
            flavor,
            gateway_alias,
            injects_alias,
            reaches_host_loopback,
            socket_mounts_work,
            host_sockets_mount,
            squashes_ownership,
        ) in cases
        {
            let access = HostAccess::for_flavor(flavor);
            assert_eq!(access.flavor, Some(flavor), "flavor={flavor}: flavor");
            assert_eq!(
                access.gateway_alias, gateway_alias,
                "flavor={flavor}: gateway_alias"
            );
            assert_eq!(
                access.injects_alias, injects_alias,
                "flavor={flavor}: injects_alias"
            );
            assert_eq!(
                access.reaches_host_loopback, reaches_host_loopback,
                "flavor={flavor}: reaches_host_loopback"
            );
            assert_eq!(
                access.socket_mounts_work, socket_mounts_work,
                "flavor={flavor}: socket_mounts_work"
            );
            assert_eq!(
                access.host_sockets_mount, host_sockets_mount,
                "flavor={flavor}: host_sockets_mount"
            );
            assert_eq!(
                access.squashes_ownership, squashes_ownership,
                "flavor={flavor}: squashes_ownership"
            );
            assert_eq!(
                access.probed,
                Probed::default(),
                "flavor={flavor}: a table row starts unprobed"
            );
        }
    }

    /// OrbStack's docker socket and an arbitrary host socket do not survive
    /// the mount layer the same way, so the two fields must be free to
    /// disagree; Desktop and Colima each agree with themselves because
    /// nothing splits them there.
    #[test]
    fn the_two_socket_questions_are_answered_separately() {
        let orbstack = HostAccess::for_flavor(DockerFlavor::OrbStack);
        assert_ne!(
            orbstack.socket_mounts_work, orbstack.host_sockets_mount,
            "OrbStack special-cases its own docker socket but not an arbitrary one"
        );

        let desktop = HostAccess::for_flavor(DockerFlavor::DockerDesktop);
        assert_eq!(desktop.socket_mounts_work, desktop.host_sockets_mount);

        let colima = HostAccess::for_flavor(DockerFlavor::Colima);
        assert_eq!(colima.socket_mounts_work, colima.host_sockets_mount);
    }

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("not used by this test".into())) })
    }

    struct MinimalFakeRuntime;

    impl ContainerRuntime for MinimalFakeRuntime {
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
            _env: &[(String, SecretValue)],
        ) -> BoxFut<'_, ExecResult> {
            unused()
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

    /// Fails if any of the three defaults is widened, which would silently
    /// switch Apple and every test fake onto behavior nobody asked for.
    #[tokio::test]
    async fn a_runtime_without_a_host_access_story_promises_nothing() {
        let runtime = MinimalFakeRuntime;
        let runtime: &dyn ContainerRuntime = &runtime;

        let access = runtime.host_access();
        assert_eq!(access.flavor, None);
        assert_eq!(access.gateway_alias, None);
        assert!(!access.injects_alias);
        assert!(!access.reaches_host_loopback);
        assert!(!access.socket_mounts_work);
        assert!(!access.host_sockets_mount);
        #[cfg(target_os = "macos")]
        assert!(
            access.squashes_ownership,
            "the unknown row keeps the macOS UID-remapping skip it inherited"
        );
        #[cfg(not(target_os = "macos"))]
        assert!(
            !access.squashes_ownership,
            "off a Mac there is no squashing mount layer to defer to"
        );
        assert_eq!(runtime.daemon_version(), None);

        runtime.detect_host_access().await;
        assert_eq!(
            runtime.host_access(),
            access,
            "the default no-op must neither panic nor invent a value"
        );
    }

    /// Fails if podman is ever routed through the Docker flavor table.
    #[tokio::test]
    async fn podman_names_its_own_host_alias() {
        // A path rather than a live daemon: bollard only checks that the
        // socket is there, and nothing here sends a request over it.
        let socket = tempfile::NamedTempFile::new().expect("stand-in socket");
        let runtime = PodmanRuntime(
            BollardRuntime::connect_to_socket(&socket.path().to_string_lossy())
                .expect("building a podman client must not need a daemon"),
        );
        let runtime: &dyn ContainerRuntime = &runtime;

        let access = runtime.host_access();
        assert_eq!(access.flavor, None);
        assert_eq!(access.gateway_alias, Some("host.containers.internal"));
        assert!(access.injects_alias);

        runtime.detect_host_access().await;
        assert_eq!(
            runtime.host_access(),
            access,
            "podman's row is a constant, never routed through the Docker flavor table"
        );
    }

    /// The refinement applied to the one row that names an alias but does not
    /// get it injected by the daemon. Fails if the version gate is skipped or
    /// applied to a self-injecting row, and fails if a version new enough to
    /// leave the alias alone is marked probed: nothing was measured there, so
    /// `dev status` would claim a probe for a value read straight off the
    /// table.
    #[test]
    fn an_engine_too_old_for_host_gateway_names_no_alias() {
        let cases = [
            // (server_version, gateway_alias_after, probed_after)
            (Some("19.03.15"), None, true),
            (Some("20.10.24"), Some("host.docker.internal"), false),
            (Some("24.0.7"), Some("host.docker.internal"), false),
            (None, Some("host.docker.internal"), false),
            (Some("garbage"), Some("host.docker.internal"), false),
        ];
        for (server_version, gateway_alias_after, probed_after) in cases {
            let refined = refine_for_server_version(
                HostAccess::for_flavor(DockerFlavor::Engine),
                server_version,
            );
            assert_eq!(
                refined.gateway_alias, gateway_alias_after,
                "server_version={server_version:?}"
            );
            assert_eq!(
                refined.probed.gateway_alias, probed_after,
                "server_version={server_version:?}"
            );
        }

        let desktop = HostAccess::for_flavor(DockerFlavor::DockerDesktop);
        let refined = refine_for_server_version(desktop, Some("19.03.15"));
        assert_eq!(
            refined, desktop,
            "a row that injects its own alias must not be touched by the version gate"
        );
    }

    /// `for_flavor` leaves `probed` all false; `with_loopback_verified(true)`
    /// sets both the field and its `Probed` bool while leaving every other
    /// field alone. Fails if the two are ever collapsed into one bool, which
    /// is what would let `dev status` print a guess as verified.
    #[test]
    fn a_probed_value_is_distinguishable_from_the_table_default() {
        let table_row = HostAccess::for_flavor(DockerFlavor::Engine);
        assert_eq!(table_row.probed, Probed::default());
        assert!(
            !table_row.reaches_host_loopback,
            "Engine's table row starts unreachable"
        );

        let verified = table_row.with_loopback_verified(true);
        assert!(
            verified.reaches_host_loopback,
            "a verified measurement overrides the table row"
        );
        assert!(
            verified.probed.reaches_host_loopback,
            "the measurement must be marked probed"
        );
        assert!(
            !verified.probed.gateway_alias,
            "only the field that was measured is marked probed"
        );

        assert_eq!(verified.flavor, table_row.flavor);
        assert_eq!(verified.gateway_alias, table_row.gateway_alias);
        assert_eq!(verified.injects_alias, table_row.injects_alias);
        assert_eq!(verified.socket_mounts_work, table_row.socket_mounts_work);
        assert_eq!(verified.host_sockets_mount, table_row.host_sockets_mount);
        assert_eq!(verified.squashes_ownership, table_row.squashes_ownership);
    }

    /// A descriptor carrying only the two fields `host_callback` reads.
    fn access(gateway_alias: Option<&'static str>, reaches_host_loopback: bool) -> HostAccess {
        HostAccess {
            gateway_alias,
            reaches_host_loopback,
            ..HostAccess::all_off()
        }
    }

    /// Fails if a missing alias still yields an address, and fails if an
    /// unreachable-loopback daemon yields any bind at all — the regression
    /// that would publish a relay on every interface the host has.
    #[test]
    fn a_host_callback_is_offered_only_where_a_container_can_reach_a_loopback_listener() {
        let cases = [
            (
                Some("host.docker.internal"),
                true,
                Ok(("127.0.0.1", "host.docker.internal")),
            ),
            (
                Some("host.docker.internal"),
                false,
                Err("containers on this flavor cannot reach a host loopback listener"),
            ),
            (None, true, Err("this flavor has no host alias")),
            (None, false, Err("this flavor has no host alias")),
        ];
        for (gateway_alias, reaches_host_loopback, expected) in cases {
            let access = access(gateway_alias, reaches_host_loopback);
            assert_eq!(
                access
                    .host_callback()
                    .map(|callback| (callback.bind, callback.alias)),
                expected,
                "gateway_alias={gateway_alias:?} reaches_host_loopback={reaches_host_loopback}"
            );
        }
    }

    /// A fake-daemon socket that accepts and never writes back, so
    /// `DetectedDaemon::probe` must fall back once its own budget gives up
    /// rather than sitting on bollard's 120s client timeout.
    ///
    /// The elapsed assertion is the whole test: the flavor and the absent
    /// version read the same whether `info()` gave up at the budget or at
    /// bollard's 120s, so without a clock this passes with the timeout
    /// deleted outright. This is the test that pins which bound applies to
    /// `info()`; `a_slow_info_is_given_more_room_than_a_ping` covers the
    /// other half, a daemon slow enough to need the larger one.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_never_answers_falls_back_within_the_budget() {
        let dir = tempfile::TempDir::new().unwrap();
        let colima_dir = dir.path().join(".colima").join("default");
        std::fs::create_dir_all(&colima_dir).unwrap();
        let socket_path = colima_dir.join("docker.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let _server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Accept and never respond, so the client's info() call hangs
            // until the probe's own budget gives up on it.
            std::future::pending::<()>().await
        });

        let runtime = BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
            .expect("building a docker client must not need a daemon to answer");

        let started = tokio::time::Instant::now();
        let detected = DetectedDaemon::probe(&runtime).await;

        assert_eq!(
            started.elapsed(),
            INFO_DETECT_BUDGET,
            "`info()` must be what gave up, at its own budget"
        );
        assert_eq!(detected.access.flavor, Some(DockerFlavor::Colima));
        assert_eq!(
            detected.version, None,
            "a daemon that never answered reported no version"
        );
    }

    /// `/_ping` returns two bytes; `/info` enumerates images, containers,
    /// plugins and driver status, so seconds there is ordinary on a loaded or
    /// warming daemon. Sharing the ping's budget loses the flavor for the
    /// whole process — the result is cached and never retried — and the
    /// container is created with no host alias at all.
    ///
    /// What this proves is that the two budgets are not one constant, and
    /// that a daemon slower than the ping's still gets its flavor. It does
    /// not pin the bound itself:
    /// `a_daemon_that_never_answers_falls_back_within_the_budget` does that,
    /// so neither of the two is redundant with the other.
    #[tokio::test(start_paused = true)]
    async fn a_slow_info_is_given_more_room_than_a_ping() {
        assert!(
            INFO_DETECT_BUDGET > HOST_DETECT_BUDGET,
            "an /info budget no larger than the ping's is the bug this covers"
        );
        let delay = HOST_DETECT_BUDGET * 2;
        assert!(delay < INFO_DETECT_BUDGET);

        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        // The delay is taken before `accept`, not between reading the request
        // and answering it: the timer has to exist before the runtime first
        // goes idle, or paused time advances straight to the probe's own
        // deadline and the daemon never gets its turn.
        let server = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let (mut stream, _) = listener.accept().await.unwrap();
            let _request = crate::runtime::fake_daemon::read_http_request(&mut stream).await;
            let body = r#"{"OperatingSystem":"OrbStack","ServerVersion":"27.1.1"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let runtime = BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
            .expect("building a docker client must not need a daemon");

        let started = tokio::time::Instant::now();
        let detected = DetectedDaemon::probe(&runtime).await;
        server.await.unwrap();

        assert!(
            started.elapsed() >= HOST_DETECT_BUDGET,
            "the fixture must outlast the ping budget, got {:?}",
            started.elapsed()
        );
        assert_eq!(detected.access.flavor, Some(DockerFlavor::OrbStack));
        assert_eq!(detected.version.as_deref(), Some("27.1.1"));
    }

    /// A fake daemon answering `GET /info` with a canned body; the version it
    /// reports is kept for `dev status` to read without a second round trip.
    #[tokio::test]
    async fn the_daemon_version_is_kept_for_reporting() {
        async fn probed_version(body: &'static str) -> Option<String> {
            let dir = tempfile::TempDir::new().unwrap();
            let socket_path = dir.path().join("docker.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();

            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _request = crate::runtime::fake_daemon::read_http_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });

            let runtime = BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
                .expect("building a docker client must not need a daemon");
            let runtime: &dyn ContainerRuntime = &runtime;
            runtime.detect_host_access().await;
            server.await.unwrap();
            runtime.daemon_version().map(str::to_string)
        }

        let version =
            probed_version(r#"{"OperatingSystem":"OrbStack","ServerVersion":"27.1.1"}"#).await;
        assert_eq!(version.as_deref(), Some("27.1.1"));

        let version = probed_version(r#"{"OperatingSystem":"OrbStack"}"#).await;
        assert_eq!(
            version, None,
            "a daemon that reports no ServerVersion must not be remembered as one"
        );
    }

    /// The same fake daemon, probed twice against a socket path spelling a
    /// different flavor than the daemon itself reports. Fails if the cache
    /// is overwritable, which is what would let a later caller record a
    /// daemon `dev` is not using, or send a second request trying.
    #[tokio::test]
    async fn a_detected_daemon_is_recorded_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let colima_dir = dir.path().join(".colima").join("default");
        std::fs::create_dir_all(&colima_dir).unwrap();
        let socket_path = colima_dir.join("docker.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let request_count = Arc::new(AtomicUsize::new(0));
        let counted = request_count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let _request = crate::runtime::fake_daemon::read_http_request(&mut stream).await;
                let body = r#"{"OperatingSystem":"OrbStack"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let runtime = BollardRuntime::connect_to_socket(&socket_path.to_string_lossy())
            .expect("building a docker client must not need a daemon");
        let runtime: &dyn ContainerRuntime = &runtime;

        runtime.detect_host_access().await;
        runtime.detect_host_access().await;
        server.abort();

        assert_eq!(
            runtime.host_access().flavor,
            Some(DockerFlavor::OrbStack),
            "the daemon's own answer must win over the socket path's Colima guess"
        );
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "a second detect_host_access() call must not send a second request"
        );
    }

    /// Fails if the sync path ever tries to reach the daemon or unwraps the
    /// empty cell.
    #[test]
    fn host_access_is_the_unknown_row_until_detection_runs() {
        let socket = tempfile::NamedTempFile::new().expect("stand-in socket");
        let runtime = BollardRuntime::connect_to_socket(&socket.path().to_string_lossy())
            .expect("building a docker client must not need a daemon");
        let runtime: &dyn ContainerRuntime = &runtime;

        assert_eq!(runtime.host_access(), HostAccess::unknown());
        assert_eq!(runtime.daemon_version(), None);
    }
}
