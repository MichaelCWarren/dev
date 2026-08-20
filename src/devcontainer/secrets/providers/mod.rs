pub mod env;
pub mod exec;
pub mod file;
pub mod keychain;
pub mod op;
pub mod plugin;

#[allow(unused_imports)]
pub use env::EnvProvider;
#[allow(unused_imports)]
pub use exec::ExecProvider;
#[allow(unused_imports)]
pub use file::FileProvider;
#[allow(unused_imports)]
pub use keychain::KeychainProvider;
#[allow(unused_imports)]
pub use op::OpProvider;
#[allow(unused_imports)]
pub use plugin::{PLUGIN_PROTOCOL_VERSION, PluginProvider};

/// Removes one trailing `\r\n` or `\n`, and nothing else. Shared by the `file`
/// and `exec` providers, which both treat a command or file's final newline as
/// formatting rather than part of the secret.
pub(crate) fn trim_trailing_newline(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::trim_trailing_newline;

    #[test]
    fn trim_trailing_newline_removes_one_ending_only() {
        assert_eq!(trim_trailing_newline("v"), "v");
        assert_eq!(trim_trailing_newline("v\n"), "v");
        assert_eq!(trim_trailing_newline("v\r\n"), "v");
        assert_eq!(trim_trailing_newline("v\n\n"), "v\n");
        assert_eq!(trim_trailing_newline(""), "");
        assert_eq!(trim_trailing_newline("\n"), "");
    }
}
