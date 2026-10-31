//! The in-container store for `up` secrets.
//!
//! `dev up` resolves these once and leaves them in the container, so a later
//! `dev exec`, `dev shell` or ssh session can read them without asking the
//! provider again. Values only ever travel in the env of a root exec on the way
//! in and as hex on stdout of a root exec on the way out. There is no stdin
//! route because only Docker implements piped exec, and none through argv or
//! host disk because those are visible to other users of the machine.
//!
//! [`UP_STORE_DIR`] is a root-owned 0700 directory on a tmpfs holding one
//! child per workspace, named by the workspace's store key, because two
//! workspaces can share one Compose container. A child holds one regular file
//! per secret. File names are the hex of the key, because key names may hold
//! `/` or be `..`.

use super::SecretValue;
use crate::error::DevError;
use crate::runtime::{ContainerRuntime, ExecResult};
use crate::session::shm_tmpfs_guard;

pub const UP_STORE_DIR: &str = "/dev/shm/dev-secrets";

/// Exit code the scripts use when `/dev/shm` is not a tmpfs, so the host can
/// say so rather than reporting a generic failure.
const NOT_TMPFS_EXIT: i32 = 3;

const COMMAND_NOT_FOUND_EXIT: i32 = 127;

const ENV_PREFIX: &str = "DEV_UP_SECRET_";

const ABSENT_LINE: &str = "dev-secrets absent";
const PRESENT_LINE: &str = "dev-secrets 1";

/// What a read found. Both lists keep the order of the keys asked for.
#[derive(Debug, Default)]
pub(crate) struct UpStoreRead {
    pub found: Vec<(String, SecretValue)>,
    pub missing: Vec<String>,
}

/// Succeeds only for a directory that is mode 0700 and owned by `$owner`.
///
/// `/dev/shm` is sticky and world-writable, so a non-root user can squat the
/// parent's name before `dev up` makes it. Owner and mode are what tell a
/// squatter's directory from ours, and a symlink shows `l...` and fails. The
/// mode is matched as a prefix because GNU `ls` appends `.` or `+` and macOS
/// appends `@`. `stat -c` is avoided because BSD `stat` lacks it.
const TRUSTED_FUNCTION: &str = r#"trusted() {
  line=$(ls -ldn "$1" 2>/dev/null) || return 1
  set -- $line
  case $1 in drwx------*) ;; *) return 1 ;; esac
  [ "$3" = "$owner" ]
}
"#;

/// Makes the parent trusted or fails. `mkdir` has no `-p`, so a name planted
/// again after the `rm` makes it fail rather than be followed. Once the parent
/// is root's and 0700, nothing below it can be raced by another user.
const TRUST_PARENT: &str = r#"trusted "$root" || { rm -rf "$root"; mkdir -m 700 "$root" || exit 1; }
trusted "$root" || { echo 'dev-secrets is not a root-owned 0700 directory' >&2; exit 1; }
"#;

/// The prefix of every store exec's `$0`, which is how a runtime fake tells
/// them apart from other execs.
pub(crate) const UP_STORE_ARGV0: &str = "dev-up-store";

#[derive(Clone, Copy)]
enum StoreAction {
    Write,
    Read,
    Clear,
}

impl StoreAction {
    fn argv0(self) -> String {
        let action = match self {
            StoreAction::Write => "write",
            StoreAction::Read => "read",
            StoreAction::Clear => "clear",
        };
        format!("{UP_STORE_ARGV0}-{action}")
    }
}

/// Replaces this workspace's stored set with `values`.
///
/// A reader sees the old complete set, no set, or the new complete set, never
/// part of one. Between the `rm` of the old child and the `mv` of the new one
/// the set is briefly absent, because POSIX `mv` cannot swap a non-empty
/// directory in one step.
pub(crate) async fn write_up_store(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    store_key: &str,
    values: &[(String, SecretValue)],
) -> Result<(), DevError> {
    check_store_key(store_key)?;
    if let Some((key, _)) = values.iter().find(|(_, v)| v.expose().contains('\0')) {
        return Err(DevError::Runtime(format!(
            "secret `{key}` contains a NUL byte and cannot be stored in the container"
        )));
    }
    let names: Vec<String> = values.iter().map(|(key, _)| hex::encode(key)).collect();
    let env: Vec<(String, SecretValue)> = values
        .iter()
        .enumerate()
        .map(|(i, (_, value))| (value_env(i), SecretValue::new(value.expose())))
        .collect();
    let script = write_script(store_key, &names);
    let result = run_store_exec(runtime, container_id, StoreAction::Write, script, &env).await?;
    match result.exit_code {
        0 => Ok(()),
        NOT_TMPFS_EXIT => Err(not_tmpfs()),
        _ => Err(exec_failure("write", &result)),
    }
}

/// Reads this workspace's stored values for `keys`, reporting which were not
/// there. Whether a missing key matters is the caller's decision.
pub(crate) async fn read_up_store(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    store_key: &str,
    keys: &[String],
) -> Result<UpStoreRead, DevError> {
    if keys.is_empty() {
        return Ok(UpStoreRead::default());
    }
    check_store_key(store_key)?;
    let names: Vec<String> = keys.iter().map(hex::encode).collect();
    let script = read_script(store_key, &names);
    let result = run_store_exec(runtime, container_id, StoreAction::Read, script, &[]).await?;
    match result.exit_code {
        0 => parse_read_output(&result.stdout, keys),
        NOT_TMPFS_EXIT => Err(not_tmpfs()),
        _ => Err(exec_failure("read", &result)),
    }
}

/// Removes this workspace's stored set, if there is one. Nothing is written,
/// so a disk-backed `/dev/shm` is no reason to refuse.
pub(crate) async fn clear_up_store(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    store_key: &str,
) -> Result<(), DevError> {
    check_store_key(store_key)?;
    let script = clear_script(store_key);
    let result = run_store_exec(runtime, container_id, StoreAction::Clear, script, &[]).await?;
    match result.exit_code {
        // 127 is a missing `sh` or `rm`. The write needs both, so nothing can
        // have been stored, and an image without a shell is not warned about.
        0 | COMMAND_NOT_FOUND_EXIT => Ok(()),
        _ => Err(exec_failure("clear", &result)),
    }
}

/// The key is inlined into the scripts, so only hex is accepted.
fn check_store_key(store_key: &str) -> Result<(), DevError> {
    if !store_key.is_empty() && store_key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(DevError::Runtime(format!(
        "`{store_key}` is not a valid secret store key"
    )))
}

async fn run_store_exec(
    runtime: &dyn ContainerRuntime,
    container_id: &str,
    action: StoreAction,
    script: String,
    env: &[(String, SecretValue)],
) -> Result<ExecResult, DevError> {
    let command = vec!["sh".to_string(), "-c".to_string(), script, action.argv0()];
    runtime
        .exec(container_id, &command, Some("root"), None, env)
        .await
}

fn value_env(index: usize) -> String {
    format!("{ENV_PREFIX}{index}")
}

/// What every script starts with. The positional parameters are overrides only
/// tests pass, so production runs against the real paths.
fn script_prelude(store_key: &str) -> String {
    format!(
        "root=${{1:-{UP_STORE_DIR}}} mounts=${{2:-/proc/mounts}} owner=${{3:-0}}\n\
         store=\"$root/{store_key}\" new=\"$root/{store_key}.new\" made=\n\
         {TRUSTED_FUNCTION}"
    )
}

fn tmpfs_check() -> String {
    shm_tmpfs_guard("refusing to touch dev-secrets there", NOT_TMPFS_EXIT) + "\n"
}

/// `names` are hex made by the host, so they are safe to inline.
fn write_script(store_key: &str, names: &[String]) -> String {
    let mut script = script_prelude(store_key);
    script.push_str(&tmpfs_check());
    script.push_str("umask 077\n");
    script.push_str(TRUST_PARENT);
    script.push_str("trap '[ -z \"$made\" ] || rm -rf \"$new\"' EXIT\n");
    script.push_str("rm -rf \"$new\"\nmkdir -m 700 \"$new\" || exit 1\nmade=1\n");
    script.push_str("{ true");
    for (i, name) in names.iter().enumerate() {
        script.push_str(&format!(
            " &&\nprintf '%s' \"${}\" > \"$new/{name}\"",
            value_env(i)
        ));
    }
    script.push_str(" ; } || exit 1\n");
    for i in 0..names.len() {
        script.push_str(&format!("unset {}\n", value_env(i)));
    }
    script.push_str("rm -rf \"$store\"\nmv \"$new\" \"$store\" || exit 1\nmade=\n");
    script
}

/// The store is looked for before `od` is, so a workspace with nothing stored
/// reads as absent in an image without `od`.
fn read_script(store_key: &str, names: &[String]) -> String {
    let mut script = script_prelude(store_key);
    script.push_str(&tmpfs_check());
    script.push_str(&format!(
        "{{ trusted \"$root\" && trusted \"$store\"; }} || {{ echo '{ABSENT_LINE}'; exit 0; }}\n"
    ));
    script.push_str(
        "command -v od >/dev/null || { echo 'od is missing in this container' >&2; exit 1; }\n",
    );
    script.push_str(&format!("echo '{PRESENT_LINE}'\n"));
    for name in names {
        script.push_str(&format!(
            "if [ -f \"$store/{name}\" ]; then printf '+'; \
             od -An -v -tx1 \"$store/{name}\" | tr -d ' \\n'; echo; else echo '-'; fi\n"
        ));
    }
    script
}

/// An untrusted parent is not ours, and removing a path through it could
/// follow a squatter's symlink, so it is left alone.
fn clear_script(store_key: &str) -> String {
    let mut script = script_prelude(store_key);
    script.push_str("trusted \"$root\" || exit 0\nrm -rf \"$store\" \"$new\"\n");
    script
}

/// Never includes `stdout`, which holds hex secret material.
fn parse_read_output(stdout: &str, keys: &[String]) -> Result<UpStoreRead, DevError> {
    let lines: Vec<&str> = stdout.lines().collect();
    if lines == [ABSENT_LINE] {
        return Ok(UpStoreRead {
            found: Vec::new(),
            missing: keys.to_vec(),
        });
    }
    let [marker, entries @ ..] = lines.as_slice() else {
        return Err(unreadable());
    };
    if *marker != PRESENT_LINE || entries.len() != keys.len() {
        return Err(unreadable());
    }
    let mut read = UpStoreRead::default();
    for (key, line) in keys.iter().zip(entries) {
        match parse_line(line)? {
            Some(value) => read.found.push((key.clone(), value)),
            None => read.missing.push(key.clone()),
        }
    }
    Ok(read)
}

fn parse_line(line: &str) -> Result<Option<SecretValue>, DevError> {
    if line == "-" {
        return Ok(None);
    }
    let encoded = line.strip_prefix('+').ok_or_else(unreadable)?;
    let bytes = hex::decode(encoded).map_err(|_| unreadable())?;
    let value = String::from_utf8(bytes).map_err(|_| unreadable())?;
    Ok(Some(SecretValue::new(value)))
}

fn unreadable() -> DevError {
    DevError::Runtime(format!(
        "the secret store at {UP_STORE_DIR} returned unreadable output"
    ))
}

fn not_tmpfs() -> DevError {
    DevError::Runtime(format!(
        "/dev/shm is not a tmpfs in this container, so `up` secrets would land on disk; \
         dev refuses to store them at {UP_STORE_DIR}"
    ))
}

fn exec_failure(action: &str, result: &ExecResult) -> DevError {
    DevError::Runtime(format!(
        "failed to {action} the secret store at {UP_STORE_DIR} (exit {}): {}",
        result.exit_code,
        result.stderr.trim()
    ))
}

/// Whether `cmd` is one of the store's execs, of any kind.
#[cfg(test)]
pub(crate) fn is_up_store_exec(cmd: &[String]) -> bool {
    cmd.get(3)
        .is_some_and(|argv0| argv0.starts_with(UP_STORE_ARGV0))
}

#[cfg(test)]
fn is_store_action(cmd: &[String], action: StoreAction) -> bool {
    cmd.get(3).is_some_and(|argv0| *argv0 == action.argv0())
}

#[cfg(test)]
fn is_up_store_read(cmd: &[String]) -> bool {
    is_store_action(cmd, StoreAction::Read)
}

#[cfg(test)]
pub(crate) fn is_up_store_write(cmd: &[String]) -> bool {
    is_store_action(cmd, StoreAction::Write)
}

#[cfg(test)]
pub(crate) fn is_up_store_clear(cmd: &[String]) -> bool {
    is_store_action(cmd, StoreAction::Clear)
}

/// The store key a store exec names, read back out of its script.
#[cfg(test)]
pub(crate) fn up_store_key(cmd: &[String]) -> Option<String> {
    let script = cmd.get(2)?;
    let rest = script.split("store=\"$root/").nth(1)?;
    Some(rest.split('"').next()?.to_string())
}

/// The store as a runtime fake holds it. The default is no store at all.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct FakeUpStore {
    stored: Option<Vec<(String, String)>>,
    unreadable: bool,
}

#[cfg(test)]
impl FakeUpStore {
    pub(crate) fn storing(pairs: &[(&str, &str)]) -> Self {
        let stored = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        FakeUpStore {
            stored: Some(stored),
            unreadable: false,
        }
    }

    /// Every read fails the way an image without `od` makes it fail.
    pub(crate) fn unreadable() -> Self {
        FakeUpStore {
            stored: None,
            unreadable: true,
        }
    }

    /// What the read script would print for `cmd`, or `None` when `cmd` is not
    /// a store read and the fake should answer it some other way.
    pub(crate) fn answer(&self, cmd: &[String]) -> Option<ExecResult> {
        if !is_up_store_read(cmd) {
            return None;
        }
        if self.unreadable {
            return Some(ExecResult {
                exit_code: 1,
                stdout: String::new(),
                stderr: "od is missing in this container\n".to_string(),
            });
        }
        Some(ExecResult {
            exit_code: 0,
            stdout: self.read_reply(cmd),
            stderr: String::new(),
        })
    }

    /// The store reads among `calls`, finding each call's argv with `cmd`.
    pub(crate) fn reads<T: Clone>(calls: &[T], cmd: impl Fn(&T) -> &[String]) -> Vec<T> {
        calls
            .iter()
            .filter(|call| is_up_store_read(cmd(call)))
            .cloned()
            .collect()
    }

    fn read_reply(&self, cmd: &[String]) -> String {
        let Some(stored) = &self.stored else {
            return format!("{ABSENT_LINE}\n");
        };
        let mut out = format!("{PRESENT_LINE}\n");
        let marker = "-f \"$store/";
        for line in cmd[2].lines().filter(|l| l.starts_with("if [ ")) {
            let name = line
                .split(marker)
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();
            let value = stored
                .iter()
                .find(|(key, _)| hex::encode(key) == name)
                .map(|(_, value)| value);
            match value {
                Some(value) => out.push_str(&format!("+{}\n", hex::encode(value))),
                None => out.push_str("-\n"),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::secrets::expose;
    use crate::runtime::{AttachedExec, BoxFut, ContainerConfig, ContainerInfo, ImageMetadata};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;

    type ExecCall = (Vec<String>, Option<String>, Vec<(String, String)>);

    struct StoreFakeRuntime {
        reply: Mutex<ExecResult>,
        calls: Mutex<Vec<ExecCall>>,
    }

    impl StoreFakeRuntime {
        fn answering(exit_code: i32, stdout: &str, stderr: &str) -> Self {
            StoreFakeRuntime {
                reply: Mutex::new(ExecResult {
                    exit_code,
                    stdout: stdout.to_string(),
                    stderr: stderr.to_string(),
                }),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<ExecCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn unused<T>() -> BoxFut<'static, T> {
        Box::pin(async { Err(DevError::Runtime("not used by this test".into())) })
    }

    impl ContainerRuntime for StoreFakeRuntime {
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
            self.calls
                .lock()
                .unwrap()
                .push((cmd.to_vec(), user.map(str::to_string), expose(env)));
            let reply = self.reply.lock().unwrap();
            let result = ExecResult {
                exit_code: reply.exit_code,
                stdout: reply.stdout.clone(),
                stderr: reply.stderr.clone(),
            };
            Box::pin(async move { Ok(result) })
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

    const KEY: &str = "0123456789abcdef";

    fn pair(key: &str, value: &str) -> (String, SecretValue) {
        (key.to_string(), SecretValue::new(value))
    }

    #[tokio::test]
    async fn the_write_puts_values_in_env_and_never_in_argv() {
        let runtime = StoreFakeRuntime::answering(0, "", "");
        let values = [
            pair("ALPHA", "distinctive-one\nsecond line"),
            pair("BETA", "distinctive-two"),
        ];
        write_up_store(&runtime, "c1", KEY, &values).await.unwrap();

        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        let (cmd, user, env) = &calls[0];
        assert_eq!(user.as_deref(), Some("root"));
        for word in cmd {
            assert!(!word.contains("distinctive-one"), "value in argv");
            assert!(!word.contains("distinctive-two"), "value in argv");
        }
        assert!(env.iter().all(|(n, _)| n.starts_with("DEV_UP_SECRET_")));
        let exposed: Vec<&str> = env.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(exposed, ["distinctive-one\nsecond line", "distinctive-two"]);
    }

    #[tokio::test]
    async fn the_write_script_names_hex_files_not_raw_keys() {
        let runtime = StoreFakeRuntime::answering(0, "", "");
        write_up_store(&runtime, "c1", KEY, &[pair("A/../B", "v")])
            .await
            .unwrap();

        let argv = runtime.calls()[0].0.join(" ");
        assert!(argv.contains(&hex::encode("A/../B")));
        assert!(!argv.contains("A/../B"));
        assert!(argv.contains("grep -q ' /dev/shm tmpfs '"));
        assert!(argv.contains("umask 077"));
        assert!(argv.contains("mv "));
    }

    #[tokio::test]
    async fn a_nul_in_a_value_is_refused_before_any_exec() {
        let runtime = StoreFakeRuntime::answering(0, "", "");
        let err = write_up_store(&runtime, "c1", KEY, &[pair("TOKEN", "zq9\0xv7")])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("TOKEN"));
        assert!(!err.contains("zq9") && !err.contains("xv7"));
        assert!(runtime.calls().is_empty());
    }

    #[tokio::test]
    async fn a_disk_backed_shm_is_reported_as_such() {
        let runtime = StoreFakeRuntime::answering(NOT_TMPFS_EXIT, "", "");
        let written = write_up_store(&runtime, "c1", KEY, &[pair("A", "v")])
            .await
            .unwrap_err();
        assert!(written.to_string().contains("tmpfs"));
        let read = read_up_store(&runtime, "c1", KEY, &["A".to_string()])
            .await
            .unwrap_err();
        assert!(read.to_string().contains("tmpfs"));
    }

    #[tokio::test]
    async fn a_failed_write_names_the_store_and_stderr() {
        let runtime = StoreFakeRuntime::answering(1, "", "mv: boom\n");
        let err = write_up_store(&runtime, "c1", KEY, &[pair("A", "hunter2-value")])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(UP_STORE_DIR));
        assert!(err.contains('1'));
        assert!(err.contains("mv: boom"));
        assert!(!err.contains("hunter2-value"));
    }

    #[tokio::test]
    async fn the_read_runs_one_root_exec_and_returns_found_and_missing() {
        let stdout = format!("dev-secrets 1\n+{}\n-\n", hex::encode("value-a"));
        let runtime = StoreFakeRuntime::answering(0, &stdout, "");
        let keys = ["A".to_string(), "B".to_string()];
        let read = read_up_store(&runtime, "c1", KEY, &keys).await.unwrap();

        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.as_deref(), Some("root"));
        assert!(calls[0].2.is_empty());
        assert_eq!(read.found.len(), 1);
        assert_eq!(read.found[0].0, "A");
        assert_eq!(read.found[0].1.expose(), "value-a");
        assert_eq!(read.missing, ["B"]);
    }

    #[tokio::test]
    async fn an_absent_store_reports_every_key_missing() {
        let runtime = StoreFakeRuntime::answering(0, "dev-secrets absent\n", "");
        let keys = ["A".to_string(), "B".to_string()];
        let read = read_up_store(&runtime, "c1", KEY, &keys).await.unwrap();
        assert!(read.found.is_empty());
        assert_eq!(read.missing, ["A", "B"]);
    }

    #[tokio::test]
    async fn no_keys_means_no_exec() {
        let runtime = StoreFakeRuntime::answering(0, "", "");
        let read = read_up_store(&runtime, "c1", KEY, &[]).await.unwrap();
        assert!(read.found.is_empty() && read.missing.is_empty());
        assert!(runtime.calls().is_empty());
    }

    #[tokio::test]
    async fn unreadable_output_is_an_error_without_the_output() {
        let secret_hex = hex::encode("topsecret");
        let cases = [
            String::new(),
            format!("dev-secrets 2\n+{secret_hex}\n-\n"),
            format!("dev-secrets 1\n+{secret_hex}\n"),
            "dev-secrets 1\n+zz\n-\n".to_string(),
        ];
        let keys = ["A".to_string(), "B".to_string()];
        for stdout in cases {
            let runtime = StoreFakeRuntime::answering(0, &stdout, "");
            let err = read_up_store(&runtime, "c1", KEY, &keys)
                .await
                .expect_err(&format!("accepted {stdout:?}"))
                .to_string();
            assert!(err.contains("unreadable"));
            assert!(!err.contains(&secret_hex));
        }
    }

    #[tokio::test]
    async fn every_exec_names_the_workspace_key() {
        let runtime = StoreFakeRuntime::answering(0, "dev-secrets absent\n", "");
        write_up_store(&runtime, "c1", KEY, &[pair("A", "v")])
            .await
            .unwrap();
        read_up_store(&runtime, "c1", KEY, &["A".to_string()])
            .await
            .unwrap();
        clear_up_store(&runtime, "c1", KEY).await.unwrap();
        let calls = runtime.calls();
        assert_eq!(calls.len(), 3);
        for (cmd, user, _) in &calls {
            assert_eq!(up_store_key(cmd).as_deref(), Some(KEY));
            assert_eq!(user.as_deref(), Some("root"));
        }
        assert!(is_up_store_write(&calls[0].0));
        assert!(is_up_store_read(&calls[1].0));
        assert!(is_up_store_clear(&calls[2].0));
    }

    #[tokio::test]
    async fn a_key_that_is_not_hex_is_refused_before_any_exec() {
        let runtime = StoreFakeRuntime::answering(0, "", "");
        for key in ["", "../x", "ab\"; touch pwned; \""] {
            assert!(write_up_store(&runtime, "c1", key, &[]).await.is_err());
            assert!(
                read_up_store(&runtime, "c1", key, &["A".to_string()])
                    .await
                    .is_err()
            );
            assert!(clear_up_store(&runtime, "c1", key).await.is_err());
        }
        assert!(runtime.calls().is_empty());
    }

    #[tokio::test]
    async fn a_failed_clear_names_the_store_and_stderr() {
        let runtime = StoreFakeRuntime::answering(1, "", "rm: busy\n");
        let err = clear_up_store(&runtime, "c1", KEY)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(UP_STORE_DIR) && err.contains("rm: busy"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_clear_in_a_container_without_a_shell_is_not_an_error() {
        let runtime = StoreFakeRuntime::answering(127, "", "sh: not found\n");
        clear_up_store(&runtime, "c1", KEY).await.unwrap();
    }
}

#[cfg(test)]
mod store_script_tests {
    use super::*;
    use crate::util::process::shells;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use tempfile::TempDir;

    const TMPFS_MOUNTS: &str = "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n";
    const DISK_MOUNTS: &str = "/dev/sda1 /dev/shm ext4 rw 0 0\n";
    const K1: &str = "1111111111111111";
    const K2: &str = "2222222222222222";

    struct Fixture {
        tmp: TempDir,
        root: PathBuf,
        mounts: PathBuf,
    }

    impl Fixture {
        fn new(mounts: &str) -> Self {
            let tmp = TempDir::new().unwrap();
            let root = tmp.path().join("dev-secrets");
            let mounts_file = tmp.path().join("mounts");
            std::fs::write(&mounts_file, mounts).unwrap();
            Fixture {
                tmp,
                root,
                mounts: mounts_file,
            }
        }

        fn child(&self, key: &str) -> PathBuf {
            self.root.join(key)
        }

        fn run(&self, shell: &str, script: &str, owner: u32, env: &[(String, String)]) -> Output {
            let words: Vec<&str> = shell.split(' ').collect();
            let mut command = Command::new(words[0]);
            command
                .args(&words[1..])
                .args(["-c", script, UP_STORE_ARGV0])
                .arg(&self.root)
                .arg(&self.mounts)
                .arg(owner.to_string());
            for (name, value) in env {
                command.env(name, value);
            }
            command.output().unwrap()
        }

        fn write(&self, shell: &str, key: &str, values: &[(&str, &str)]) -> Output {
            self.write_wrapped(shell, key, values, me(), "")
        }

        /// `before` runs ahead of the script, so a test can redefine a
        /// utility as a shell function.
        fn write_wrapped(
            &self,
            shell: &str,
            key: &str,
            values: &[(&str, &str)],
            owner: u32,
            before: &str,
        ) -> Output {
            let names: Vec<String> = values.iter().map(|(k, _)| hex::encode(k)).collect();
            let env: Vec<(String, String)> = values
                .iter()
                .enumerate()
                .map(|(i, (_, v))| (value_env(i), v.to_string()))
                .collect();
            let script = format!("{before}{}", write_script(key, &names));
            self.run(shell, &script, owner, &env)
        }

        fn read_output(&self, shell: &str, key: &str, keys: &[&str], owner: u32) -> Output {
            let names: Vec<String> = keys.iter().map(hex::encode).collect();
            self.run(shell, &read_script(key, &names), owner, &[])
        }

        fn read(&self, shell: &str, key: &str, keys: &[&str]) -> UpStoreRead {
            let output = self.read_output(shell, key, keys, me());
            assert!(output.status.success(), "{shell}: {output:?}");
            parse_keys(&output, keys)
        }

        fn clear(&self, shell: &str, key: &str) -> Output {
            self.run(shell, &clear_script(key), me(), &[])
        }

        /// A 0700 directory outside the store holding a planted value for `A`.
        fn planted_target(&self) -> PathBuf {
            let target = self.tmp.path().join("target");
            std::fs::create_dir(&target).unwrap();
            set_mode(&target, 0o700);
            std::fs::write(target.join(hex::encode("A")), "planted").unwrap();
            target
        }
    }

    fn parse_keys(output: &Output, keys: &[&str]) -> UpStoreRead {
        let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        parse_read_output(&String::from_utf8_lossy(&output.stdout), &keys).unwrap()
    }

    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn found<'a>(read: &'a UpStoreRead, key: &str) -> Option<&'a str> {
        read.found
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.expose())
    }

    fn succeeded(out: &Output, shell: &str) {
        assert!(out.status.success(), "{shell}: {out:?}");
    }

    #[test]
    fn values_round_trip_through_the_real_scripts() {
        let values = [
            ("A", "line1\nline2\n"),
            ("B", "  spaced  "),
            ("C", ""),
            ("D", "pässwörd"),
            ("E", "$(touch pwned) 'q' \"dq\""),
        ];
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.write(shell, K1, &values), shell);
            let keys = ["A", "B", "C", "D", "E", "NEVER"];
            let read = fx.read(shell, K1, &keys);
            for (key, value) in values {
                assert_eq!(found(&read, key), Some(value), "{shell}: {key}");
            }
            assert_eq!(read.missing, ["NEVER"], "{shell}");
            assert!(!Path::new("pwned").exists());
            assert!(!fx.tmp.path().join("pwned").exists());
        }
    }

    #[test]
    fn a_write_replaces_the_whole_set() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.write(shell, K1, &[("A", "old"), ("B", "keep")]), shell);
            succeeded(&fx.write(shell, K1, &[("A", "new")]), shell);
            let read = fx.read(shell, K1, &["A", "B"]);
            assert_eq!(found(&read, "A"), Some("new"), "{shell}");
            assert_eq!(read.missing, ["B"], "{shell}");
            assert!(!fx.root.join(format!("{K1}.new")).exists(), "{shell}");
        }
    }

    #[test]
    fn the_store_is_private() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            // Loosen the umask the script inherits, so only its own umask can narrow modes.
            let out = fx.write_wrapped(shell, K1, &[("A", "v")], me(), "umask 000\n");
            succeeded(&out, shell);
            assert_eq!(mode(&fx.root), 0o700, "{shell}");
            assert_eq!(mode(&fx.child(K1)), 0o700, "{shell}");
            assert_eq!(mode(&fx.child(K1).join(hex::encode("A"))), 0o600, "{shell}");
        }
    }

    /// What a non-root user can leave at the parent's name in `/dev/shm`.
    fn squat(fx: &Fixture, kind: &str) {
        match kind {
            "symlink" => symlink(fx.planted_target(), &fx.root).unwrap(),
            "file" => std::fs::write(&fx.root, "planted").unwrap(),
            "mode" => {
                std::fs::create_dir(&fx.root).unwrap();
                std::fs::create_dir(fx.child(K1)).unwrap();
                set_mode(&fx.child(K1), 0o700);
                std::fs::write(fx.child(K1).join(hex::encode("A")), "planted").unwrap();
                set_mode(&fx.root, 0o755);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_squatted_parent_is_discarded_and_replaced() {
        for shell in shells() {
            for kind in ["symlink", "file", "mode"] {
                let fx = Fixture::new(TMPFS_MOUNTS);
                squat(&fx, kind);
                let read = fx.read(shell, K1, &["A"]);
                assert_eq!(read.missing, ["A"], "{shell} {kind}: squat trusted");
                succeeded(&fx.write(shell, K1, &[("A", "fresh")]), shell);
                assert!(!fx.root.is_symlink(), "{shell} {kind}");
                assert!(fx.root.is_dir(), "{shell} {kind}");
                assert_eq!(mode(&fx.root), 0o700, "{shell} {kind}");
                let read = fx.read(shell, K1, &["A"]);
                assert_eq!(found(&read, "A"), Some("fresh"), "{shell} {kind}");
                let target = fx.tmp.path().join("target");
                if kind == "symlink" {
                    let planted = std::fs::read_to_string(target.join(hex::encode("A")));
                    assert_eq!(
                        planted.unwrap(),
                        "planted",
                        "{shell}: write followed the link"
                    );
                    assert!(
                        !target.join(K1).exists(),
                        "{shell}: write followed the link"
                    );
                }
            }
        }
    }

    /// A test cannot make a directory root's, so the replacement the script
    /// makes is no more trusted than the squat, and the write has to refuse.
    #[test]
    fn a_parent_owned_by_someone_else_is_discarded_and_never_written() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.write(shell, K1, &[("A", "v")]), shell);
            let out = fx.read_output(shell, K1, &["A"], me() + 1);
            succeeded(&out, shell);
            assert_eq!(
                parse_keys(&out, &["A"]).missing,
                ["A"],
                "{shell}: owner ignored"
            );

            let out = fx.write_wrapped(shell, K1, &[("A", "other")], me() + 1, "");
            assert!(!out.status.success(), "{shell}: {out:?}");
            assert!(
                !fx.child(K1).exists(),
                "{shell}: squatter's dir kept or written"
            );
        }
    }

    /// The squatter wins the race between the `rm` and the `mkdir`.
    #[test]
    fn a_parent_planted_again_after_its_removal_is_never_followed() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            let target = fx.planted_target();
            symlink(&target, &fx.root).unwrap();
            let replant = format!(
                "rm() {{ command rm \"$@\"; if [ \"$2\" = \"$root\" ]; then ln -s '{}' \"$root\"; fi; }}\n",
                target.display()
            );
            let out = fx.write_wrapped(shell, K1, &[("A", "fresh")], me(), &replant);
            assert!(!out.status.success(), "{shell}: {out:?}");
            // `mkdir` itself must refuse; the re-check after it is the backstop.
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(!stderr.contains("not a root-owned"), "{shell}: {stderr}");
            assert!(
                !target.join(K1).exists(),
                "{shell}: write followed the link"
            );
            assert!(!target.join(format!("{K1}.new")).exists(), "{shell}");
        }
    }

    #[test]
    fn two_keys_coexist_and_replacing_one_leaves_the_other() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.write(shell, K1, &[("A", "one")]), shell);
            succeeded(&fx.write(shell, K2, &[("A", "two")]), shell);
            assert_eq!(
                found(&fx.read(shell, K1, &["A"]), "A"),
                Some("one"),
                "{shell}"
            );
            assert_eq!(
                found(&fx.read(shell, K2, &["A"]), "A"),
                Some("two"),
                "{shell}"
            );

            succeeded(&fx.write(shell, K1, &[("B", "one-b")]), shell);
            let first = fx.read(shell, K1, &["A", "B"]);
            assert_eq!(first.missing, ["A"], "{shell}");
            assert_eq!(found(&first, "B"), Some("one-b"), "{shell}");
            assert_eq!(
                found(&fx.read(shell, K2, &["A"]), "A"),
                Some("two"),
                "{shell}"
            );
        }
    }

    #[test]
    fn a_clear_removes_only_its_own_key() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.clear(shell, K1), shell);
            succeeded(&fx.write(shell, K1, &[("A", "one")]), shell);
            succeeded(&fx.write(shell, K2, &[("A", "two")]), shell);
            succeeded(&fx.clear(shell, K1), shell);
            assert_eq!(fx.read(shell, K1, &["A"]).missing, ["A"], "{shell}");
            assert!(!fx.child(K1).exists(), "{shell}");
            assert_eq!(
                found(&fx.read(shell, K2, &["A"]), "A"),
                Some("two"),
                "{shell}"
            );
        }
    }

    #[test]
    fn a_clear_needs_no_tmpfs_and_leaves_a_squatted_parent_alone() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.write(shell, K1, &[("A", "one")]), shell);
            std::fs::write(&fx.mounts, DISK_MOUNTS).unwrap();
            succeeded(&fx.clear(shell, K1), shell);
            assert!(!fx.child(K1).exists(), "{shell}");

            let fx = Fixture::new(TMPFS_MOUNTS);
            let target = fx.planted_target();
            std::fs::create_dir(target.join(K1)).unwrap();
            symlink(&target, &fx.root).unwrap();
            succeeded(&fx.clear(shell, K1), shell);
            assert!(target.join(K1).exists(), "{shell}: clear followed the link");
        }
    }

    #[test]
    fn a_disk_backed_shm_refuses_before_making_anything() {
        for shell in shells() {
            let fx = Fixture::new(DISK_MOUNTS);
            let out = fx.write(shell, K1, &[("A", "v")]);
            assert_eq!(out.status.code(), Some(NOT_TMPFS_EXIT), "{shell}: {out:?}");
            assert!(!fx.root.exists(), "{shell}");
            let out = fx.read_output(shell, K1, &["A"], me());
            assert_eq!(out.status.code(), Some(NOT_TMPFS_EXIT), "{shell}: {out:?}");
        }
    }

    /// A directory holding only what the read script needs before it looks
    /// for `od`.
    fn bin_without_od(fx: &Fixture) -> PathBuf {
        let bin = fx.tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        for tool in ["grep", "ls"] {
            let path = std::env::var_os("PATH").unwrap();
            let real = std::env::split_paths(&path)
                .map(|dir| dir.join(tool))
                .find(|p| p.is_file())
                .unwrap();
            symlink(real, bin.join(tool)).unwrap();
        }
        bin
    }

    #[test]
    fn an_absent_store_reads_as_absent_without_od() {
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            let bin = bin_without_od(&fx);
            let names = [hex::encode("A")];
            let script = format!("PATH='{}'\n{}", bin.display(), read_script(K1, &names));
            let out = fx.run(shell, &script, me(), &[]);
            succeeded(&out, shell);
            assert_eq!(parse_keys(&out, &["A"]).missing, ["A"], "{shell}");
        }
    }

    #[test]
    fn a_long_repeated_value_is_not_folded_by_od() {
        let value = "ab".repeat(100);
        for shell in shells() {
            let fx = Fixture::new(TMPFS_MOUNTS);
            succeeded(&fx.write(shell, K1, &[("A", &value)]), shell);
            let read = fx.read(shell, K1, &["A"]);
            assert_eq!(found(&read, "A"), Some(value.as_str()), "{shell}");
        }
    }
}
