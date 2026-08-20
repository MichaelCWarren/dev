use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum DevError {
    #[error("No devcontainer configuration found in {0}")]
    NoConfig(String),

    #[error("Invalid devcontainer configuration: {0}")]
    InvalidConfig(String),

    #[error("Container runtime error: {0}")]
    Runtime(String),

    #[error("{0}")]
    NoRuntime(String),

    #[error("Container not found for workspace: {0}")]
    ContainerNotFound(String),

    #[error("OCI registry error: {0}")]
    Registry(String),

    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Feature not found: {0}")]
    FeatureNotFound(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Lifecycle hook failed: {command} (exit code {code})")]
    LifecycleHook { command: String, code: i32 },

    #[error("Image build failed: {0}")]
    BuildFailed(String),

    // Secrets errors name the env-var key, the provider, and a reason built from
    // paths, exit codes and fixed text. Never a resolved value.
    /// A `secrets.json` entry whose reference is malformed, or names a provider
    /// that does not exist. Raised by early validation, before any side effect.
    #[error("Invalid secret reference for `{key}`: {reason}")]
    SecretReference { key: String, reason: String },

    /// A provider ran and did not produce a value for this key. `optional`
    /// secrets turn this into an omitted key rather than a failure.
    #[error("Failed to resolve secret `{key}` from provider `{provider}`: {reason}")]
    SecretResolution {
        key: String,
        provider: String,
        reason: String,
    },

    /// A provider failed for a whole batch, so no key in that batch could have
    /// resolved. The provider-to-registry channel: `resolve_all` expands it into
    /// a per-key failure and it does not reach the user in this form.
    #[error("Secret provider `{provider}` failed: {reason}")]
    SecretProviderFailed { provider: String, reason: String },

    #[error("User cancelled operation")]
    Cancelled,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Bollard(#[from] bollard::errors::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reference_names_the_key_and_the_reason() {
        let err = DevError::SecretReference {
            key: "LINEAR_API_KEY".to_string(),
            reason: "reference has no `://` scheme".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid secret reference for `LINEAR_API_KEY`: reference has no `://` scheme"
        );
    }

    #[test]
    fn secret_resolution_names_the_key_and_the_provider_but_no_value() {
        let err = DevError::SecretResolution {
            key: "DB_PASSWORD".to_string(),
            provider: "keychain".to_string(),
            reason: "item not found in the login keychain".to_string(),
        };
        let msg = err.to_string();
        assert_eq!(
            msg,
            "Failed to resolve secret `DB_PASSWORD` from provider `keychain`: \
             item not found in the login keychain"
        );
        assert!(
            !msg.contains("hunter2"),
            "resolution errors must not leak values: {msg}"
        );
    }

    #[test]
    fn secret_provider_failed_names_the_provider_and_has_no_key_slot() {
        let err = DevError::SecretProviderFailed {
            provider: "op".to_string(),
            reason: "the 1Password CLI is not signed in; run `op signin`".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Secret provider `op` failed: the 1Password CLI is not signed in; run `op signin`"
        );
    }
}
