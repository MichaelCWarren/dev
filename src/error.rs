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

    /// The runtime has no such operation at all, as opposed to one that failed.
    #[error("Container runtime error: {0}")]
    Unsupported(String),

    #[error("{0}")]
    NoRuntime(String),

    /// Required `up` secrets the in-container store does not hold. Names keys only.
    #[error("{0}")]
    UpSecretsNotStored(String),

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

impl DevError {
    /// What kind of error this is, built only from the variant, an I/O kind or
    /// an HTTP status, never from message text, which can quote whatever the
    /// failing call read (a container's env, for one).
    pub fn content_free_class(&self) -> String {
        match self {
            Self::Bollard(e) => bollard_class(e),
            Self::Io(e) => format!("Io ({:?})", e.kind()),
            Self::NoConfig(_) => "NoConfig".into(),
            Self::InvalidConfig(_) => "InvalidConfig".into(),
            Self::Runtime(_) => "Runtime".into(),
            Self::Unsupported(_) => "Unsupported".into(),
            Self::NoRuntime(_) => "NoRuntime".into(),
            Self::UpSecretsNotStored(_) => "UpSecretsNotStored".into(),
            Self::ContainerNotFound(_) => "ContainerNotFound".into(),
            Self::Registry(_) => "Registry".into(),
            Self::TemplateNotFound(_) => "TemplateNotFound".into(),
            Self::FeatureNotFound(_) => "FeatureNotFound".into(),
            Self::Cache(_) => "Cache".into(),
            Self::LifecycleHook { .. } => "LifecycleHook".into(),
            Self::BuildFailed(_) => "BuildFailed".into(),
            Self::SecretReference { .. } => "SecretReference".into(),
            Self::SecretResolution { .. } => "SecretResolution".into(),
            Self::SecretProviderFailed { .. } => "SecretProviderFailed".into(),
            Self::Cancelled => "Cancelled".into(),
            Self::SerdeJson(_) => "SerdeJson".into(),
            Self::Reqwest(_) => "Reqwest".into(),
        }
    }
}

fn bollard_class(error: &bollard::errors::Error) -> String {
    use bollard::errors::Error as B;
    match error {
        B::DockerResponseServerError {
            status_code: 404, ..
        } => "not found (HTTP 404)".into(),
        B::DockerResponseServerError { status_code, .. } => format!("HTTP {status_code}"),
        B::SocketNotFoundError(_) => "daemon unreachable".into(),
        B::IOError { .. }
        | B::HyperResponseError { .. }
        | B::HyperLegacyError { .. }
        | B::HttpClientError { .. } => "connection error".into(),
        B::RequestTimeoutError => "timed out".into(),
        B::JsonDataError { .. } | B::JsonSerdeError { .. } => "unreadable response".into(),
        _ => "Bollard".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "class-sentinel-value";

    #[test]
    fn content_free_class_names_the_kind_and_never_the_message() {
        let server = |status_code| {
            DevError::Bollard(bollard::errors::Error::DockerResponseServerError {
                status_code,
                message: format!("bad env API_TOKEN={SENTINEL}"),
            })
        };
        let bollard = DevError::Bollard;
        let unparsable = serde_json::from_str::<u8>(&format!("\"{SENTINEL}\"")).unwrap_err();
        let cases = [
            (server(404), "not found (HTTP 404)"),
            (server(500), "HTTP 500"),
            (
                DevError::Bollard(bollard::errors::Error::SocketNotFoundError(
                    SENTINEL.to_string(),
                )),
                "daemon unreachable",
            ),
            (
                bollard(bollard::errors::Error::IOError {
                    err: std::io::Error::new(std::io::ErrorKind::BrokenPipe, SENTINEL),
                }),
                "connection error",
            ),
            (
                bollard(bollard::errors::Error::JsonDataError {
                    message: SENTINEL.to_string(),
                    column: 0,
                }),
                "unreadable response",
            ),
            (
                bollard(bollard::errors::Error::JsonSerdeError { err: unparsable }),
                "unreadable response",
            ),
            (
                bollard(bollard::errors::Error::DockerStreamError {
                    error: SENTINEL.to_string(),
                }),
                "Bollard",
            ),
            (DevError::Runtime(SENTINEL.to_string()), "Runtime"),
            (
                DevError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    SENTINEL,
                )),
                "Io (ConnectionRefused)",
            ),
        ];
        for (error, class) in cases {
            assert!(error.to_string().contains(SENTINEL), "{error}");
            let named = error.content_free_class();
            assert!(!named.contains(SENTINEL), "{named}");
            assert_eq!(named, class);
        }
        assert_eq!(
            DevError::Bollard(bollard::errors::Error::RequestTimeoutError).content_free_class(),
            "timed out"
        );
    }

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
