//! The `exec` provider: `"exec://vault kv get -field=token secret/ci"` runs that
//! command and takes its stdout as the secret. It is the escape hatch that makes
//! Vault, AWS Secrets Manager, `pass`, `sops` and anything else with a CLI work
//! without dev knowing about any of them.
//!
//! The shorthand is three slashes for an absolute program: `exec:///bin/echo`.
//! `exec://` is the scheme separator and the command brings its own leading `/`.
//!
//! **No shell is involved.** dev splits the command string into argv itself and
//! hands it to `execvp`, so `;`, `|`, `&&`, `$VAR`, backticks, `~` and globs are
//! ordinary characters inside an argument and nothing expands them.
//! `exec://foo | bar` passes `|` and `bar` as two arguments to `foo`.
//!
//! Splitting rules, in full:
//!
//! - Whitespace outside quotes separates words, and a run of it produces no
//!   empty words.
//! - `'...'` is literal. Every character between the quotes is kept as written,
//!   including backslashes, double quotes, spaces and newlines.
//! - `"..."` keeps its contents, except that `\"` yields `"` and `\\` yields `\`.
//!   A backslash before anything else is kept along with that character, so
//!   `"C:\path"` stays `C:\path`.
//! - Outside quotes, `\` makes the next character literal: `a\ b` is one word.
//! - Quotes join to their neighbours rather than starting a word, so `a"b"c` is
//!   the single word `abc`.
//! - An unterminated quote, a trailing `\`, and a command that is empty or all
//!   whitespace each fail that key.
//!
//! Those rules give substituted variables shell semantics, which is the least
//! surprising answer available: an unquoted `${localEnv:OPTS}` that came back
//! empty vanishes, while a quoted one becomes a real empty argument. Most CLIs
//! read an empty argument and an absent one as different things, so the
//! difference is worth keeping.
//!
//! The provider recognises no options, and that is deliberate rather than
//! incidental: no option value can ever become an argv entry, so an option that
//! substituted to `""` cannot slip into the command as a blank argument.
//!
//! The command cannot read stdin (it is `/dev/null`) and is bounded at 120
//! seconds, so a tool that expects to prompt interactively has to be given its
//! credentials another way.
//!
//! Nothing here constructs a `DevError`: every failure is a `KeyFailure` reason
//! and the registry decides what it means. A malformed command surfaces at
//! resolution rather than at early validation, because the reference parser does
//! not know that `exec` reads its body as a command line — early validation
//! catches an unknown provider, not a bad quote.
//!
//! **Trust.** Anyone who can write an `exec://` reference can already run
//! arbitrary host shell: `initializeCommand` runs `sh -c` on the host
//! (`commands/up.rs`) and `postCreateCommand` runs `sh -c` in the container
//! (`devcontainer/lifecycle.rs`), both from the same config tree that carries
//! `secrets.json`. `exec` adds no trust that was not already there and is weaker
//! than either, because it never reaches a shell.
//!
//! **The value is never printed.** stdout goes straight into a `SecretValue` and
//! into nothing else. Failure reasons name the key, the command as written, the
//! exit status, and at most one capped line of stderr. A credential therefore
//! belongs in the environment the command reads, not in the command string.

use super::super::SecretValue;
use super::super::provider::{ResolvedBatch, SecretProvider};
use super::super::reference::SecretRef;
use super::trim_trailing_newline;
use crate::runtime::BoxFut;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};
use std::time::Duration;

/// Long enough for a pinentry passphrase or a slow Vault round trip, short
/// enough that a wedged `dev up` says so within the minute.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// How much of a stderr line a failure reason carries.
const STDERR_HINT_CHARS: usize = 200;

/// Runs a command from config and takes its stdout as the secret.
// The allow comes off when the registry registers the built-ins.
#[allow(dead_code)]
pub struct ExecProvider {
    workspace: PathBuf,
    timeout: Duration,
    runner: Runner,
}

/// How a command actually gets run. Production spawns a child; tests answer from
/// a fixture, so the suite never starts a process it did not write itself.
enum Runner {
    Spawn,
    #[cfg(test)]
    Fixture(Fixture),
}

#[cfg(test)]
type Fixture = std::sync::Arc<dyn Fn(&[String]) -> RunOutcome + Send + Sync>;

/// What one run produced. A timeout and a spawn failure are neither an `Output`
/// nor a reason on their own, so all three arms come back and `resolve_one`
/// words them.
enum RunOutcome {
    Finished(Output),
    SpawnFailed(std::io::Error),
    TimedOut,
}

/// Which quote the splitter is inside.
enum Quoting {
    Bare,
    Single,
    Double,
}

#[allow(dead_code)]
impl ExecProvider {
    /// `workspace` is the host workspace folder every command runs in, matching
    /// `initializeCommand` and the `file` provider's relative-path rule. There is
    /// no option for it; see the note on `cwd` below.
    pub fn new(workspace: &Path) -> Self {
        ExecProvider {
            workspace: workspace.to_path_buf(),
            timeout: DEFAULT_TIMEOUT,
            runner: Runner::Spawn,
        }
    }

    #[cfg(test)]
    fn with_timeout(workspace: &Path, timeout: Duration) -> Self {
        ExecProvider {
            timeout,
            ..ExecProvider::new(workspace)
        }
    }

    /// The seam the tests run against: an injected runner answers without a
    /// process ever starting.
    #[cfg(test)]
    fn with_runner(
        workspace: &Path,
        answer: impl Fn(&[String]) -> RunOutcome + Send + Sync + 'static,
    ) -> Self {
        ExecProvider {
            runner: Runner::Fixture(std::sync::Arc::new(answer)),
            ..ExecProvider::new(workspace)
        }
    }

    /// `Err` carries a per-key reason, not a `DevError`: every ref is its own
    /// command, so one that fails says nothing about the next and can never be a
    /// whole-batch failure.
    async fn resolve_one(&self, secret: &SecretRef) -> Result<SecretValue, String> {
        check_no_options(secret)?;
        let command = secret.reference();
        let argv = split_command(command)?;
        if argv[0].is_empty() {
            return Err("the command starts with an empty program name".to_string());
        }
        match self.run(&argv).await {
            RunOutcome::Finished(output) => value_from_output(command, &output),
            RunOutcome::SpawnFailed(err) => Err(spawn_reason(&argv[0], err)),
            RunOutcome::TimedOut => Err(format!(
                "`{command}` did not finish within {}s",
                self.timeout.as_secs()
            )),
        }
    }

    async fn run(&self, argv: &[String]) -> RunOutcome {
        match &self.runner {
            Runner::Spawn => self.spawn(argv).await,
            #[cfg(test)]
            Runner::Fixture(answer) => answer(argv),
        }
    }

    /// No shell, no stdin, the workspace as the working directory, and a bound.
    ///
    /// `stdin(Stdio::null())` is explicit because tokio's `output()` leaves stdin
    /// alone where `std`'s nulls it; without it a command would read the terminal
    /// and eat input meant for `dev up`. `kill_on_drop` is what makes the timeout
    /// real: the elapsed future drops the child, and the child has to die with it.
    async fn spawn(&self, argv: &[String]) -> RunOutcome {
        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(&self.workspace)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(self.timeout, cmd.output()).await {
            Err(_) => RunOutcome::TimedOut,
            Ok(Err(err)) => RunOutcome::SpawnFailed(err),
            Ok(Ok(output)) => RunOutcome::Finished(output),
        }
    }
}

impl SecretProvider for ExecProvider {
    fn name(&self) -> &str {
        "exec"
    }

    /// Sequential, not `join_all`: two `vault` calls racing for the same terminal
    /// interleave their prompts, and a user who cannot read a prompt cannot
    /// answer it.
    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        Box::pin(async move {
            let mut batch = ResolvedBatch::new();
            for secret in refs {
                match self.resolve_one(secret).await {
                    Ok(value) => batch.push_value(secret.key(), value),
                    Err(reason) => batch.push_failure(secret.key(), reason),
                }
            }
            Ok(batch)
        })
    }
}

/// The one place stdout is read: it becomes a `SecretValue` or nothing. No
/// failure reason is built from it, not even lossily.
fn value_from_output(command: &str, output: &Output) -> Result<SecretValue, String> {
    if !output.status.success() {
        return Err(exit_reason(command, output));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("`{command}` printed output that is not valid UTF-8"))?;
    let value = trim_trailing_newline(text);
    if value.is_empty() {
        return Err(format!("`{command}` succeeded but printed nothing"));
    }
    Ok(SecretValue::new(value))
}

fn exit_reason(command: &str, output: &Output) -> String {
    let status = status_text(&output.status);
    match stderr_hint(&output.stderr) {
        hint if hint.is_empty() => format!("`{command}` failed ({status})"),
        hint => format!("`{command}` failed ({status}): {hint}"),
    }
}

/// A child killed by a signal has no exit code, and saying `signal 9` is honest
/// where a made-up `-1` is not.
fn status_text(status: &ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit {code}"),
        (None, Some(signal)) => format!("signal {signal}"),
        (None, None) => "no exit status".to_string(),
    }
}

/// The first non-blank line of stderr, trimmed and capped.
///
/// stderr is not the value, but a badly behaved tool could print one there, so
/// this takes one line rather than the stream and caps what it takes.
fn stderr_hint(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .take(STDERR_HINT_CHARS)
        .collect()
}

/// "Not installed" is per key here, unlike `op`: `exec` runs a different binary
/// for every ref, so one missing binary says nothing about the next.
fn spawn_reason(program: &str, err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        format!("`{program}` is not installed or not on PATH")
    } else {
        format!("cannot run `{program}`: {err}")
    }
}

/// Reject any provider option, so a typo is a message rather than a setting that
/// quietly does nothing.
fn check_no_options(secret: &SecretRef) -> Result<(), String> {
    match secret.options().keys().next() {
        Some(name) => Err(format!(
            "the `exec` provider takes no options, but `{name}` was given"
        )),
        None => Ok(()),
    }
}

/// Split a command string into argv. No shell, no expansion. See the module
/// header for the rules.
fn split_command(command: &str) -> Result<Vec<String>, String> {
    let mut argv: Vec<String> = Vec::new();
    let mut word = String::new();
    // Distinct from `word.is_empty()`: it is what makes `""` an argument while a
    // run of spaces is not.
    let mut started = false;
    let mut quoting = Quoting::Bare;
    let mut chars = command.chars().peekable();

    while let Some(c) = chars.next() {
        match quoting {
            Quoting::Bare => match c {
                c if c.is_whitespace() => {
                    if started {
                        argv.push(std::mem::take(&mut word));
                        started = false;
                    }
                    continue;
                }
                '\\' => word.push(
                    chars
                        .next()
                        .ok_or_else(|| "the command ends with a trailing `\\`".to_string())?,
                ),
                '\'' => quoting = Quoting::Single,
                '"' => quoting = Quoting::Double,
                _ => word.push(c),
            },
            Quoting::Single => match c {
                '\'' => quoting = Quoting::Bare,
                _ => word.push(c),
            },
            Quoting::Double => match c {
                '"' => quoting = Quoting::Bare,
                // Only `\"` and `\\` escape; every other backslash is literal.
                '\\' => match chars.peek() {
                    Some('"' | '\\') => word.push(chars.next().unwrap_or_default()),
                    _ => word.push('\\'),
                },
                _ => word.push(c),
            },
        }
        started = true;
    }

    if let Some(quote) = quoting.open_quote() {
        return Err(format!("the command has an unterminated `{quote}` quote"));
    }
    if started {
        argv.push(word);
    }
    if argv.is_empty() {
        return Err("the command is empty".to_string());
    }
    Ok(argv)
}

impl Quoting {
    fn open_quote(&self) -> Option<char> {
        match self {
            Quoting::Bare => None,
            Quoting::Single => Some('\''),
            Quoting::Double => Some('"'),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Instant;
    use tempfile::TempDir;

    const VALUE: &str = "hunter2";

    fn exec_ref(key: &str, command: &str) -> SecretRef {
        SecretRef::new(key, "exec", command).unwrap()
    }

    fn split(command: &str) -> Vec<String> {
        split_command(command).unwrap()
    }

    fn finished(code: i32, stdout: &[u8], stderr: &str) -> RunOutcome {
        RunOutcome::Finished(Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    fn killed(signal: i32) -> RunOutcome {
        RunOutcome::Finished(Output {
            status: ExitStatus::from_raw(signal),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    /// A provider whose every command answers with `outcome`.
    fn answering(outcome: impl Fn() -> RunOutcome + Send + Sync + 'static) -> ExecProvider {
        ExecProvider::with_runner(Path::new("/workspace"), move |_| outcome())
    }

    fn real(workspace: &TempDir) -> ExecProvider {
        ExecProvider::new(workspace.path())
    }

    async fn resolve(provider: &ExecProvider, refs: &[SecretRef]) -> ResolvedBatch {
        provider.resolve(refs).await.unwrap()
    }

    async fn one_value(provider: &ExecProvider, command: &str) -> String {
        let batch = resolve(provider, &[exec_ref("KEY", command)]).await;
        assert!(
            batch.failures().is_empty(),
            "unexpected failure: {:?}",
            batch.failures()
        );
        batch.values()[0].1.expose().to_string()
    }

    async fn one_reason(provider: &ExecProvider, command: &str) -> String {
        let batch = resolve(provider, &[exec_ref("KEY", command)]).await;
        assert!(batch.values().is_empty(), "unexpectedly resolved");
        assert_eq!(batch.failures()[0].key, "KEY");
        batch.failures()[0].reason.clone()
    }

    #[test]
    fn splits_a_plain_command_on_whitespace() {
        assert_eq!(
            split("vault kv get -field=token secret/ci"),
            ["vault", "kv", "get", "-field=token", "secret/ci"]
        );
    }

    #[test]
    fn single_quotes_keep_spaces_in_one_word() {
        assert_eq!(
            split("aws secretsmanager get-secret-value --secret-id 'my prod key'"),
            [
                "aws",
                "secretsmanager",
                "get-secret-value",
                "--secret-id",
                "my prod key"
            ]
        );
    }

    #[test]
    fn single_quotes_keep_double_quotes_and_brackets() {
        assert_eq!(
            split(r#"sops -d --extract '["db"]["pw"]' secrets.yaml"#),
            ["sops", "-d", "--extract", r#"["db"]["pw"]"#, "secrets.yaml"]
        );
    }

    #[test]
    fn quotes_join_to_their_neighbours() {
        assert_eq!(split(r#"a"b"c"#), ["abc"]);
        assert_eq!(split("a'b'c"), ["abc"]);
        assert_eq!(split(r#"--extract='["k"]'"#), [r#"--extract=["k"]"#]);
    }

    #[test]
    fn backslash_escapes_outside_and_inside_double_quotes() {
        assert_eq!(split(r"a\ b"), ["a b"]);
        assert_eq!(split(r#""C:\path""#), [r"C:\path"]);
        assert_eq!(split(r#""say \"hi\"""#), [r#"say "hi""#]);
        assert_eq!(split(r#""back\\slash""#), [r"back\slash"]);
        assert_eq!(split(r"'a\ b'"), [r"a\ b"]);
    }

    #[test]
    fn an_unterminated_quote_names_the_quote_character() {
        let single = split_command("echo 'unterminated").unwrap_err();
        assert!(single.contains('\''), "names the quote: {single}");
        let double = split_command(r#"echo "unterminated"#).unwrap_err();
        assert!(double.contains('"'), "names the quote: {double}");
    }

    #[test]
    fn a_trailing_backslash_is_an_error() {
        let reason = split_command(r"echo trailing\").unwrap_err();
        assert!(reason.contains('\\'), "{reason}");
    }

    #[test]
    fn a_command_emptied_by_substitution_is_an_error() {
        for command in ["", "   ", "\t\n"] {
            let reason = split_command(command).unwrap_err();
            assert!(reason.contains("empty"), "{command:?}: {reason}");
        }
    }

    #[test]
    fn an_unquoted_empty_substitution_vanishes() {
        assert_eq!(
            split("vault kv get  secret/ci"),
            ["vault", "kv", "get", "secret/ci"]
        );
    }

    #[test]
    fn a_quoted_empty_substitution_becomes_an_empty_argument() {
        let argv = split(r#"vault kv get "" secret/ci"#);
        assert_eq!(argv.len(), 5);
        assert_eq!(argv[3], "");
        assert_eq!(split("a '' b").len(), 3);
    }

    #[test]
    fn a_substitution_emptied_inside_an_argument_survives() {
        assert_eq!(
            split("vault -field= secret/ci"),
            ["vault", "-field=", "secret/ci"]
        );
    }

    #[test]
    fn shell_metacharacters_are_inert() {
        assert_eq!(split("echo a; rm -rf /"), ["echo", "a;", "rm", "-rf", "/"]);
        assert_eq!(split("foo | bar"), ["foo", "|", "bar"]);
        assert_eq!(
            split("echo $HOME ~ * && >out"),
            ["echo", "$HOME", "~", "*", "&&", ">out"]
        );
    }

    #[tokio::test]
    async fn a_quoted_empty_program_name_fails_the_key() {
        let provider = answering(|| finished(0, b"never runs", ""));
        let reason = one_reason(&provider, r#""" --flag"#).await;
        assert!(reason.contains("empty program name"), "{reason}");
    }

    #[tokio::test]
    async fn stdout_is_the_value_with_one_trailing_newline_removed() {
        let provider = answering(|| finished(0, b"hunter2\n", ""));
        assert_eq!(one_value(&provider, "/bin/echo hunter2").await, VALUE);
    }

    #[tokio::test]
    async fn interior_and_leading_whitespace_is_kept() {
        let provider = answering(|| finished(0, b"  a b  \n", ""));
        assert_eq!(one_value(&provider, "/bin/echo x").await, "  a b  ");
    }

    #[tokio::test]
    async fn a_non_zero_exit_fails_the_key_without_its_stdout() {
        let provider = answering(|| finished(7, b"hunter2\n", "vault: permission denied\n"));
        let reason = one_reason(&provider, "vault kv get secret/ci").await;

        assert!(reason.contains('7'), "carries the exit code: {reason}");
        assert!(reason.contains("vault kv get secret/ci"), "{reason}");
        assert!(reason.contains("permission denied"), "{reason}");
        assert!(!reason.contains(VALUE), "leaked stdout: {reason}");
        assert!(!reason.contains("KEY"), "repeats the key: {reason}");
    }

    #[tokio::test]
    async fn a_signalled_child_reports_the_signal_not_a_made_up_code() {
        let provider = answering(|| killed(9));
        let reason = one_reason(&provider, "/bin/sleep 1").await;

        assert!(reason.contains("signal 9"), "{reason}");
        assert!(!reason.contains("-1"), "{reason}");
    }

    #[tokio::test]
    async fn only_the_first_line_of_stderr_is_carried_and_it_is_capped() {
        let long = "x".repeat(500);
        let stderr = format!("{long}\nhunter2\n");
        let provider = answering(move || finished(1, b"", &stderr));
        let reason = one_reason(&provider, "/bin/false").await;

        assert!(!reason.contains(VALUE), "carried a later line: {reason}");
        assert!(reason.contains(&"x".repeat(STDERR_HINT_CHARS)), "{reason}");
        assert!(
            !reason.contains(&"x".repeat(STDERR_HINT_CHARS + 1)),
            "uncapped: {reason}"
        );
    }

    #[tokio::test]
    async fn empty_stdout_after_trimming_fails_the_key() {
        for stdout in [b"".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
            let owned = stdout.to_vec();
            let provider = answering(move || finished(0, &owned, ""));
            let reason = one_reason(&provider, "/usr/bin/true").await;
            assert!(reason.contains("printed nothing"), "{reason}");
        }
    }

    #[tokio::test]
    async fn non_utf8_stdout_fails_without_printing_the_bytes() {
        let provider = answering(|| finished(0, &[0xff, 0xfe], ""));
        let reason = one_reason(&provider, "/bin/cat raw").await;

        assert!(reason.contains("not valid UTF-8"), "{reason}");
        assert!(!reason.contains('\u{fffd}'), "rendered the bytes: {reason}");
        assert!(!reason.contains("255"), "rendered the bytes: {reason}");
    }

    #[tokio::test]
    async fn a_missing_binary_names_it_and_mentions_path() {
        let provider = answering(|| {
            RunOutcome::SpawnFailed(std::io::Error::from(std::io::ErrorKind::NotFound))
        });
        let reason = one_reason(&provider, "dev-no-such-binary-xyz --flag").await;

        assert!(reason.contains("dev-no-such-binary-xyz"), "{reason}");
        assert!(reason.contains("PATH"), "{reason}");
        assert!(
            !reason.contains("failed (exit"),
            "reads as an exit: {reason}"
        );
    }

    #[tokio::test]
    async fn another_spawn_failure_carries_the_io_error() {
        let provider = answering(|| {
            RunOutcome::SpawnFailed(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
        let reason = one_reason(&provider, "/bin/echo x").await;

        assert!(reason.contains("cannot run"), "{reason}");
        assert!(!reason.contains("PATH"), "{reason}");
    }

    #[tokio::test]
    async fn an_option_fails_the_key_naming_the_option() {
        let provider = answering(|| finished(0, b"hunter2\n", ""));
        let refs = vec![
            exec_ref("KEY", "/bin/echo x")
                .with_option("vault", "Private".into())
                .with_option("account", "work".into()),
        ];
        let batch = resolve(&provider, &refs).await;

        assert!(batch.values().is_empty());
        let reason = &batch.failures()[0].reason;
        assert!(reason.contains("takes no options"), "{reason}");
        assert!(reason.contains("`account`"), "first in order: {reason}");
    }

    #[tokio::test]
    async fn a_batch_resolves_in_declaration_order_under_its_own_keys() {
        let provider = ExecProvider::with_runner(Path::new("/w"), |argv| {
            finished(0, format!("{}\n", argv[1]).as_bytes(), "")
        });
        let refs = vec![
            exec_ref("A", "/bin/echo alpha"),
            exec_ref("B", "/bin/echo beta"),
            exec_ref("C", "/bin/echo gamma"),
        ];
        let batch = resolve(&provider, &refs).await;

        let pairs: Vec<(&str, &str)> = batch
            .values()
            .iter()
            .map(|(key, value)| (key.as_str(), value.expose()))
            .collect();
        assert_eq!(pairs, [("A", "alpha"), ("B", "beta"), ("C", "gamma")]);
        assert!(batch.failures().is_empty());
    }

    #[tokio::test]
    async fn one_bad_command_does_not_discard_its_neighbours() {
        let provider = ExecProvider::with_runner(Path::new("/w"), |argv| match argv[1].as_str() {
            "bad" => finished(3, b"", "no such item"),
            other => finished(0, format!("{other}\n").as_bytes(), ""),
        });
        let refs = vec![
            exec_ref("A", "/bin/echo alpha"),
            exec_ref("B", "/bin/echo bad"),
            exec_ref("C", "/bin/echo gamma"),
        ];
        let result = provider.resolve(&refs).await;

        let batch = result.expect("a failing command is never a whole-batch error");
        assert_eq!(batch.values().len(), 2);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "B");
    }

    #[tokio::test]
    async fn an_optional_ref_is_reported_not_dropped() {
        let provider = answering(|| finished(1, b"", ""));
        let refs = vec![exec_ref("KEY", "/usr/bin/false").with_optional(true)];
        let batch = resolve(&provider, &refs).await;

        assert_eq!(
            batch.failures()[0].key,
            "KEY",
            "the registry owns `optional`"
        );
    }

    #[tokio::test]
    async fn batch_debug_hides_the_value() {
        let provider = answering(|| finished(0, b"hunter2\n", ""));
        let batch = resolve(&provider, &[exec_ref("KEY", "/bin/echo x")]).await;
        let out = format!("{batch:?}");

        assert!(out.contains("KEY"), "{out}");
        assert!(!out.contains(VALUE), "leaked the value: {out}");
    }

    #[test]
    fn provider_name_is_exec() {
        assert_eq!(ExecProvider::new(Path::new("/w")).name(), "exec");
    }

    #[tokio::test]
    async fn empty_batch_resolves_to_nothing() {
        let batch = resolve(&ExecProvider::new(Path::new("/w")), &[]).await;

        assert!(batch.values().is_empty());
        assert!(batch.failures().is_empty());
    }

    // The tests below start real processes. They use only `/bin` tools that read
    // and write nothing, because they cover the wiring a fixture cannot: the
    // working directory, closed stdin, a missing binary, and the timeout.

    #[tokio::test]
    async fn a_real_command_yields_its_stdout() {
        let workspace = TempDir::new().unwrap();
        assert_eq!(
            one_value(&real(&workspace), "/bin/echo hunter2").await,
            VALUE
        );
    }

    #[tokio::test]
    async fn a_real_missing_binary_is_a_key_failure() {
        let workspace = TempDir::new().unwrap();
        let reason = one_reason(&real(&workspace), "dev-no-such-binary-xyz").await;

        assert!(reason.contains("dev-no-such-binary-xyz"), "{reason}");
        assert!(reason.contains("PATH"), "{reason}");
    }

    #[tokio::test]
    async fn the_child_runs_in_the_workspace_folder() {
        let workspace = TempDir::new().unwrap();
        let expected = std::fs::canonicalize(workspace.path()).unwrap();
        let value = one_value(&real(&workspace), "/bin/pwd").await;

        assert_eq!(Path::new(&value), expected);
    }

    #[tokio::test]
    async fn stdin_is_closed_rather_than_inherited() {
        let workspace = TempDir::new().unwrap();
        // Without the explicit `Stdio::null()` this `cat` blocks the suite.
        let value = one_value(&real(&workspace), r#"/bin/sh -c "cat; echo done""#).await;

        assert_eq!(value, "done");
    }

    #[tokio::test]
    async fn the_timeout_fires_and_names_the_bound() {
        let workspace = TempDir::new().unwrap();
        let provider = ExecProvider::with_timeout(workspace.path(), Duration::from_millis(200));
        let started = Instant::now();
        let reason = one_reason(&provider, "/bin/sleep 30").await;

        assert!(reason.contains("did not finish within"), "{reason}");
        assert!(reason.contains("/bin/sleep 30"), "{reason}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited too long"
        );
    }

    #[tokio::test]
    async fn a_timed_out_ref_does_not_stop_its_neighbours() {
        let workspace = TempDir::new().unwrap();
        let provider = ExecProvider::with_timeout(workspace.path(), Duration::from_millis(200));
        let refs = vec![
            exec_ref("A", "/bin/echo alpha"),
            exec_ref("B", "/bin/sleep 30"),
            exec_ref("C", "/bin/echo gamma"),
        ];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(batch.values().len(), 2);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "B");
    }
}
