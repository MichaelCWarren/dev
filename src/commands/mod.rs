pub mod base;
pub mod build;
pub mod config;
pub mod config_explain;
pub mod down;
pub mod exec;
pub mod forward;
pub mod global;
pub mod init;
pub mod list;
pub mod logs;
pub mod new;
pub mod open;
pub mod prune;
pub mod shell;
pub mod ssh;
pub mod ssh_proxy;
pub mod status;
pub mod status_runtime;
pub mod up;
pub mod vscode;

/// Print each warning on its own line to `out`, which is stderr in production
/// and a buffer in tests that check what a command printed.
pub(crate) fn print_warnings(
    out: &mut dyn std::io::Write,
    warnings: impl IntoIterator<Item = String>,
) {
    for warning in warnings {
        // A warning that cannot be written has nowhere left to be reported.
        let _ = writeln!(out, "{warning}");
    }
}
