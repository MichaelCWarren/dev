//! The seam every secret provider implements: the [`SecretProvider`] trait, the
//! [`ProviderRegistry`] that maps a provider name to an implementation, and the
//! three-way lookup that ends in a built-in, a `dev-secret-<name>` plugin on the
//! search path, or the error early validation reports.
//!
//! `resolve` is batch by design: it is what lets `op` collapse eight lookups
//! into one `op inject`, and therefore one biometric prompt. Exec-time
//! re-resolution is the same call with a different slice of refs, not a second
//! entry point.
//!
//! Two rules live here rather than in any provider. The registry applies
//! `optional`, so no provider reads that flag and no provider drops a key it was
//! handed. And the registry owns the filesystem, so the plugin lookup re-checks
//! a provider name before joining it to a directory even though the reference
//! parser already restricted the charset.
//!
//! Nothing caches. The same refs are resolved again at exec time, and a stale
//! value is worse than a second prompt.

use super::SecretValue;
use super::reference::SecretRef;
use crate::devcontainer::secrets::providers::plugin::PluginProvider;
use crate::devcontainer::secrets::providers::{
    EnvProvider, ExecProvider, FileProvider, KeychainProvider, OpProvider,
};
use crate::error::DevError;
use crate::runtime::BoxFut;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::{Arc, Mutex};

/// Reason attached to a key the provider answered nothing about at all.
const NO_VALUE_RETURNED: &str = "the provider returned no value for this key";

/// Resolves the secrets belonging to one provider.
///
/// Batch by design: it is what lets `op` collapse eight lookups into a single
/// `op inject` and therefore a single biometric prompt.
// The allow comes off when Group 5's `up.rs` validation reaches these types.
#[allow(dead_code)]
pub trait SecretProvider: Send + Sync {
    /// The scheme this provider answers to (`op`, `keychain`, `env`, ...).
    ///
    /// `&str` rather than `&'static str`: a plugin provider learns its name at
    /// runtime and would otherwise need a `Box::leak` per plugin.
    fn name(&self) -> &str;

    /// Resolve every ref in one call.
    ///
    /// `Err` means the whole batch failed and no key in it could have resolved;
    /// a single key that failed while the rest succeeded belongs in
    /// [`ResolvedBatch::push_failure`]. Implementations must not cache and must
    /// not read [`SecretRef::optional`].
    ///
    /// The shared `'a` on `&self` and `refs` lets a provider borrow the slice it
    /// was handed instead of cloning it into the future.
    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch>;
}

/// One key a provider could not resolve while the rest of the batch succeeded.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KeyFailure {
    pub key: String,
    /// Why it failed. May name the reference or a path, never a value, and never
    /// the key: [`reconcile`] wraps this in `SecretResolution { key, .. }`, so a
    /// reason that repeats the key stutters in the rendered message.
    pub reason: String,
}

/// What one provider returned for one batch of refs.
///
/// `Debug` is derived and stays safe because `SecretValue`'s own `Debug` prints
/// `***`.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ResolvedBatch {
    values: Vec<(String, SecretValue)>,
    failures: Vec<KeyFailure>,
}

#[allow(dead_code)]
impl ResolvedBatch {
    pub fn new() -> Self {
        ResolvedBatch::default()
    }

    pub fn push_value(&mut self, key: impl Into<String>, value: SecretValue) {
        self.values.push((key.into(), value));
    }

    pub fn push_failure(&mut self, key: impl Into<String>, reason: impl Into<String>) {
        self.failures.push(KeyFailure {
            key: key.into(),
            reason: reason.into(),
        });
    }

    pub fn values(&self) -> &[(String, SecretValue)] {
        &self.values
    }

    pub fn failures(&self) -> &[KeyFailure] {
        &self.failures
    }

    pub fn into_parts(self) -> (Vec<(String, SecretValue)>, Vec<KeyFailure>) {
        (self.values, self.failures)
    }
}

/// The directories a `dev-secret-<name>` lookup searches.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct PluginPath {
    entries: Vec<PathBuf>,
}

#[allow(dead_code)]
impl PluginPath {
    /// The process `PATH`.
    pub fn from_env() -> Self {
        PluginPath::from_os_str(&std::env::var_os("PATH").unwrap_or_default())
    }

    /// A search path from a `PATH`-shaped value. Taking the value as data is
    /// what makes the plugin fallback testable without mutating the process
    /// environment, which edition 2024 makes `unsafe` and which would race every
    /// other test in this process.
    pub fn from_os_str(value: &OsStr) -> Self {
        PluginPath {
            entries: std::env::split_paths(value)
                // POSIX reads an empty entry as the current directory, which
                // would pick a plugin up out of the workspace by accident.
                .filter(|entry| !entry.as_os_str().is_empty())
                .collect(),
        }
    }

    /// The first executable file named `binary` in the search path.
    pub fn find(&self, binary: &str) -> Option<PathBuf> {
        if !is_single_path_component(binary) {
            return None;
        }
        self.entries
            .iter()
            .map(|dir| dir.join(binary))
            .find(|candidate| is_executable_file(candidate))
    }
}

/// A `dev-secret-<provider>` executable found on the search path.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PluginBinary {
    pub provider: String,
    pub path: PathBuf,
}

/// What a provider name resolved to.
#[allow(dead_code)]
pub enum ProviderLookup<'a> {
    BuiltIn(&'a dyn SecretProvider),
    Plugin(PluginBinary),
}

/// Hand-written because `&dyn SecretProvider` is not `Debug`. Prints the
/// provider name and the plugin path, both of which are already public.
impl std::fmt::Debug for ProviderLookup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderLookup::BuiltIn(provider) => {
                f.debug_tuple("BuiltIn").field(&provider.name()).finish()
            }
            ProviderLookup::Plugin(binary) => f.debug_tuple("Plugin").field(binary).finish(),
        }
    }
}

/// The providers one command can resolve secrets through.
///
/// Holds the workspace folder and the plugin search path because both are fixed
/// for one command: callers build the registry once and then ask it questions.
#[allow(dead_code)]
pub struct ProviderRegistry {
    providers: BTreeMap<String, Box<dyn SecretProvider>>,
    workspace: PathBuf,
    plugin_path: PluginPath,
}

#[allow(dead_code)]
impl ProviderRegistry {
    /// The registry production uses: built-ins registered, plugins found on the
    /// process `PATH`. Empty of built-ins until Group 4 and Group 5 register
    /// `env`, `file`, `op`, `keychain` and `exec` here.
    pub fn with_builtins(workspace: &Path) -> Self {
        ProviderRegistry::with_builtins_in(workspace, PluginPath::from_env())
    }

    /// [`Self::with_builtins`] with an explicit plugin search path, so tests
    /// point the fallback at a `TempDir`.
    pub fn with_builtins_in(workspace: &Path, plugin_path: PluginPath) -> Self {
        let mut registry = ProviderRegistry::empty(workspace, plugin_path);
        registry.register(Box::new(EnvProvider));
        registry.register(Box::new(ExecProvider::new(workspace)));
        registry.register(Box::new(FileProvider::new(workspace)));
        registry.register(Box::new(KeychainProvider));
        registry.register(Box::new(OpProvider::new()));
        registry
    }

    /// No providers. Tests register their own.
    pub fn empty(workspace: &Path, plugin_path: PluginPath) -> Self {
        ProviderRegistry {
            providers: BTreeMap::new(),
            workspace: workspace.to_path_buf(),
            plugin_path,
        }
    }

    /// Store a provider under its own `name()`. Re-registering a name replaces it.
    pub fn register(&mut self, provider: Box<dyn SecretProvider>) {
        self.providers.insert(provider.name().to_string(), provider);
    }

    /// Registered names, sorted by the `BTreeMap`, so error text is identical
    /// run to run.
    pub fn known_names(&self) -> Vec<&str> {
        self.providers.keys().map(String::as_str).collect()
    }

    /// The workspace folder, for providers that resolve relative paths.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// A registered name, else a `dev-secret-<provider>` on the registry's
    /// plugin search path, else an error naming the key and the provider.
    pub fn lookup(&self, key: &str, provider: &str) -> Result<ProviderLookup<'_>, DevError> {
        if let Some(built_in) = self.providers.get(provider) {
            return Ok(ProviderLookup::BuiltIn(built_in.as_ref()));
        }
        if let Some(path) = self.plugin_binary(provider) {
            return Ok(ProviderLookup::Plugin(PluginBinary {
                provider: provider.to_string(),
                path,
            }));
        }
        Err(unknown_provider_error(key, provider, &self.known_names()))
    }

    /// Resolve every ref, one provider call per distinct provider. Pairs come
    /// back in `refs` order, not grouped by provider.
    ///
    /// `secrets.json` loading rejects duplicate keys, so nothing here
    /// deduplicates; two refs sharing a key both resolve and the caller's map
    /// insert decides.
    pub async fn resolve_all(
        &self,
        refs: &[SecretRef],
    ) -> Result<Vec<(String, SecretValue)>, DevError> {
        let mut resolved: BTreeMap<String, SecretValue> = BTreeMap::new();
        for (provider, group) in group_by_provider(refs) {
            // The lookup sits outside the whole-batch failure path on purpose: a
            // provider name nothing answers to is a config error that fails the
            // command, and `optional` cannot excuse it. That keeps resolution in
            // step with early validation, which reports the same error.
            let first_key = group.first().map(SecretRef::key).unwrap_or_default();
            let batch = match self.lookup(first_key, &provider)? {
                ProviderLookup::BuiltIn(built_in) => built_in.resolve(&group).await,
                ProviderLookup::Plugin(binary) => {
                    let plugin = PluginProvider::new(binary, self.workspace());
                    plugin.resolve(&group).await
                }
            };
            let batch = batch.unwrap_or_else(|err| batch_failure(&group, whole_batch_reason(err)));
            resolved.extend(reconcile(&group, batch)?);
        }
        Ok(refs
            .iter()
            .filter_map(|r| {
                resolved
                    .get(r.key())
                    .map(|value| (r.key().to_string(), value.clone()))
            })
            .collect())
    }

    /// The plugin executable for a provider name, or `None` when the name is not
    /// a single path component. Guarding here is what stops a provider name from
    /// building a path of its own: `dev-secret-../../../tmp/evil` would
    /// otherwise walk out of the search directory.
    fn plugin_binary(&self, provider: &str) -> Option<PathBuf> {
        if !is_single_path_component(provider) {
            return None;
        }
        self.plugin_path.find(&format!("dev-secret-{provider}"))
    }
}

/// Group refs by provider, keeping first-appearance order of providers and
/// declaration order within each group. Pure, no I/O.
fn group_by_provider(refs: &[SecretRef]) -> Vec<(String, Vec<SecretRef>)> {
    let mut groups: Vec<(String, Vec<SecretRef>)> = Vec::new();
    for r in refs {
        match groups.iter_mut().find(|(name, _)| name == r.provider()) {
            Some((_, group)) => group.push(r.clone()),
            None => groups.push((r.provider().to_string(), vec![r.clone()])),
        }
    }
    groups
}

/// Turn one provider's batch into pairs, applying `optional` per key.
///
/// A key the provider mentioned in neither list counts as a failure: a provider
/// bug must not silently drop a required secret. A key the provider returned
/// that nobody asked for is ignored, which matters most for the plugin tier
/// where the response is JSON written by someone else's binary.
fn reconcile(
    refs: &[SecretRef],
    batch: ResolvedBatch,
) -> Result<Vec<(String, SecretValue)>, DevError> {
    let (values, failures) = batch.into_parts();
    let values: BTreeMap<String, SecretValue> = values.into_iter().collect();
    let failures: BTreeMap<String, String> = failures
        .into_iter()
        .map(|failure| (failure.key, failure.reason))
        .collect();

    let mut pairs = Vec::new();
    for r in refs {
        if let Some(value) = values.get(r.key()) {
            pairs.push((r.key().to_string(), value.clone()));
            continue;
        }
        if r.optional() {
            continue;
        }
        return Err(DevError::SecretResolution {
            key: r.key().to_string(),
            provider: r.provider().to_string(),
            reason: failures
                .get(r.key())
                .cloned()
                .unwrap_or_else(|| NO_VALUE_RETURNED.to_string()),
        });
    }
    Ok(pairs)
}

/// Spread a whole-batch failure across every key in the group, so `optional`
/// means the same thing whichever way a provider failed.
fn batch_failure(refs: &[SecretRef], reason: String) -> ResolvedBatch {
    let mut batch = ResolvedBatch::new();
    for r in refs {
        batch.push_failure(r.key(), reason.clone());
    }
    batch
}

/// The reason a whole-batch failure carries into each key. `SecretProviderFailed`
/// is unwrapped rather than rendered, because `reconcile` re-attributes it to a
/// key and the rendered form already names the provider.
fn whole_batch_reason(err: DevError) -> String {
    match err {
        DevError::SecretProviderFailed { reason, .. } => reason,
        other => other.to_string(),
    }
}

/// Build the error for a provider name that is neither registered nor backed by
/// a plugin.
fn unknown_provider_error(key: &str, provider: &str, known: &[&str]) -> DevError {
    let known = if known.is_empty() {
        "no providers are registered".to_string()
    } else {
        format!("known providers are {}", known.join(", "))
    };
    DevError::SecretReference {
        key: key.to_string(),
        reason: format!(
            "uses unknown provider `{provider}`; {known}; or put an executable \
             `dev-secret-{provider}` on PATH"
        ),
    }
}

/// Whether a name can be joined to a directory without escaping it.
fn is_single_path_component(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(char::is_whitespace)
        && matches!(
            Path::new(name).components().collect::<Vec<_>>().as_slice(),
            [Component::Normal(component)] if *component == OsStr::new(name)
        )
}

/// Follows symlinks: a symlink to an executable is executable.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Test double for [`SecretProvider`]. Answers from a fixed map and counts its
/// `resolve` calls, which is what the up-path tests read to prove resolution
/// never fires when a container is reused.
///
/// [`ProviderRegistry::register`] takes ownership, so a test registers a clone
/// and asserts against the original: every piece of shared state is behind an
/// `Arc`.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FakeProvider {
    name: &'static str,
    /// Env var key to the value this double answers with.
    values: BTreeMap<String, String>,
    /// Answer a key that is not in `values` with a value derived from the key.
    answers_unknown: bool,
    /// These keys come back as `KeyFailure`s while the rest of the batch resolves.
    fails_for: Vec<String>,
    /// These keys come back as neither a value nor a failure, which is the
    /// provider bug `reconcile` has to catch. Off unless a test asks for it.
    omits: Vec<String>,
    /// Values for keys nobody asked for, which `reconcile` has to ignore.
    unasked: Vec<(String, String)>,
    /// The batch as a whole fails with this reason, the way an uninstalled `op` does.
    batch_failure: Option<String>,
    /// Bumped once per `resolve` call, never once per ref.
    calls: Arc<AtomicUsize>,
    /// Every batch handed to `resolve`, in call order.
    batches: Arc<Mutex<Vec<Vec<SecretRef>>>>,
}

#[cfg(test)]
impl FakeProvider {
    /// Answers every key with a value derived from the key, so a test that only
    /// cares about the call count needs no fixture.
    pub(crate) fn answers_everything() -> Self {
        FakeProvider {
            name: "fake",
            values: BTreeMap::new(),
            answers_unknown: true,
            fails_for: Vec::new(),
            omits: Vec::new(),
            unasked: Vec::new(),
            batch_failure: None,
            calls: Arc::new(AtomicUsize::new(0)),
            batches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Answers from a fixed map. A key not in the map is a `KeyFailure`, the way
    /// a real provider reports an item it cannot find.
    pub(crate) fn answering(values: &[(&str, &str)]) -> Self {
        FakeProvider {
            values: values
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            answers_unknown: false,
            ..FakeProvider::answers_everything()
        }
    }

    /// Answers everything except `key`. The double for the `optional` path,
    /// where a failed secret is omitted rather than fatal.
    pub(crate) fn failing_for(key: &str) -> Self {
        FakeProvider {
            fails_for: vec![key.to_string()],
            ..FakeProvider::answers_everything()
        }
    }

    /// The whole batch fails, the way `op` does when it is not installed. The
    /// registry expands this into a `KeyFailure` per key, which `failing_for`
    /// does not exercise.
    pub(crate) fn unavailable(reason: &str) -> Self {
        FakeProvider {
            batch_failure: Some(reason.to_string()),
            ..FakeProvider::answers_everything()
        }
    }

    /// Counts and records, answers nothing. For tests where `resolve` must not
    /// fire, so an unexpected call surfaces in `calls()` and downstream both.
    pub(crate) fn recording() -> Self {
        FakeProvider::answering(&[])
    }

    pub(crate) fn also_failing_for(mut self, key: &str) -> Self {
        self.fails_for.push(key.to_string());
        self
    }

    /// Answers neither a value nor a failure for `key`.
    pub(crate) fn omitting(mut self, key: &str) -> Self {
        self.omits.push(key.to_string());
        self
    }

    /// Answers `key` even when the batch did not ask for it.
    pub(crate) fn answering_unasked(mut self, key: &str, value: &str) -> Self {
        self.unasked.push((key.to_string(), value.to_string()));
        self
    }

    pub(crate) fn named(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub(crate) fn batches(&self) -> Vec<Vec<SecretRef>> {
        self.batches.lock().unwrap().clone()
    }

    /// The keys of each batch, which is what most assertions actually want.
    pub(crate) fn batch_keys(&self) -> Vec<Vec<String>> {
        self.batches()
            .iter()
            .map(|batch| batch.iter().map(|r| r.key().to_string()).collect())
            .collect()
    }

    fn answer(&self, secret: &SecretRef, batch: &mut ResolvedBatch) {
        let key = secret.key();
        if self.omits.iter().any(|omitted| omitted == key) {
            return;
        }
        if self.fails_for.iter().any(|failed| failed == key) {
            batch.push_failure(key, format!("fake provider was told to fail `{key}`"));
        } else if let Some(value) = self.values.get(key) {
            batch.push_value(key, SecretValue::new(value.as_str()));
        } else if self.answers_unknown {
            batch.push_value(key, SecretValue::new(format!("value-for-{key}")));
        } else {
            batch.push_failure(key, format!("fake provider has no fixture for `{key}`"));
        }
    }
}

#[cfg(test)]
impl Default for FakeProvider {
    fn default() -> Self {
        FakeProvider::answers_everything()
    }
}

#[cfg(test)]
impl SecretProvider for FakeProvider {
    fn name(&self) -> &str {
        self.name
    }

    // Counting and recording happen at call time, not first poll, so the
    // `MutexGuard` never enters the future and the future stays `Send`.
    fn resolve<'a>(&'a self, refs: &'a [SecretRef]) -> BoxFut<'a, ResolvedBatch> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.batches.lock().unwrap().push(refs.to_vec());
        Box::pin(async move {
            if let Some(reason) = &self.batch_failure {
                return Err(DevError::SecretProviderFailed {
                    provider: self.name.to_string(),
                    reason: reason.clone(),
                });
            }
            let mut batch = ResolvedBatch::new();
            for secret in refs {
                self.answer(secret, &mut batch);
            }
            for (key, value) in &self.unasked {
                batch.push_value(key.as_str(), SecretValue::new(value.as_str()));
            }
            Ok(batch)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::TempDir;

    /// A double answering `value-for-<key>` under the name a test registers it by.
    fn fake(name: &'static str) -> FakeProvider {
        FakeProvider::answers_everything().named(name)
    }

    fn secret_ref(key: &str, provider: &str) -> SecretRef {
        SecretRef::new(key, provider, "a/b/c").unwrap()
    }

    fn optional_ref(key: &str, provider: &str) -> SecretRef {
        secret_ref(key, provider).with_optional(true)
    }

    fn plugin_path_of(dirs: &[&Path]) -> PluginPath {
        let joined: OsString = std::env::join_paths(dirs).unwrap();
        PluginPath::from_os_str(&joined)
    }

    fn empty_registry() -> ProviderRegistry {
        ProviderRegistry::empty(Path::new("/workspace"), PluginPath::default())
    }

    fn registry_with(provider: FakeProvider) -> ProviderRegistry {
        let mut registry = empty_registry();
        registry.register(Box::new(provider));
        registry
    }

    fn plant(dir: &Path, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// An executable `/bin/sh` fixture, for the tests that reach the plugin arm.
    fn plant_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn registered_provider_resolves_to_its_implementation() {
        let registry = registry_with(fake("stub"));
        match registry.lookup("KEY", "stub").unwrap() {
            ProviderLookup::BuiltIn(provider) => assert_eq!(provider.name(), "stub"),
            ProviderLookup::Plugin(binary) => panic!("expected a built-in, got {binary:?}"),
        }
    }

    #[test]
    fn register_stores_under_the_providers_own_name_and_replaces_a_repeat() {
        let mut registry = empty_registry();
        registry.register(Box::new(fake("op")));
        registry.register(Box::new(fake("env")));
        assert_eq!(registry.known_names(), vec!["env", "op"]);

        registry.register(Box::new(fake("op")));
        assert_eq!(registry.known_names(), vec!["env", "op"]);
    }

    #[test]
    fn unknown_provider_error_names_key_and_provider() {
        let registry = empty_registry();
        let msg = format!("{}", registry.lookup("KEY", "opp").unwrap_err());
        assert!(msg.contains("KEY"), "names the key: {msg}");
        assert!(msg.contains("opp"), "names the provider: {msg}");
        assert!(msg.contains("dev-secret-opp"), "names the plugin: {msg}");
        assert!(!msg.contains("a/b/c"), "no reference body: {msg}");
    }

    #[test]
    fn unknown_provider_error_lists_the_registered_names() {
        let mut registry = registry_with(fake("op"));
        registry.register(Box::new(fake("env")));
        let msg = format!("{}", registry.lookup("KEY", "opp").unwrap_err());
        assert!(msg.contains("env, op"), "lists sorted names: {msg}");
    }

    #[test]
    fn plugin_fallback_finds_dev_secret_binary_in_injected_path() {
        let dir = TempDir::new().unwrap();
        let planted = plant(dir.path(), "dev-secret-foo", 0o755);
        let registry =
            ProviderRegistry::with_builtins_in(Path::new("/w"), plugin_path_of(&[dir.path()]));
        match registry.lookup("KEY", "foo").unwrap() {
            ProviderLookup::Plugin(binary) => {
                assert_eq!(binary.provider, "foo");
                assert_eq!(binary.path, planted);
            }
            ProviderLookup::BuiltIn(_) => panic!("expected a plugin"),
        }
    }

    #[test]
    fn plugin_fallback_ignores_non_executable_file() {
        let dir = TempDir::new().unwrap();
        plant(dir.path(), "dev-secret-foo", 0o644);
        let registry = ProviderRegistry::empty(Path::new("/w"), plugin_path_of(&[dir.path()]));
        assert!(registry.lookup("KEY", "foo").is_err());
    }

    #[test]
    fn plugin_fallback_ignores_directory() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("dev-secret-foo")).unwrap();
        let registry = ProviderRegistry::empty(Path::new("/w"), plugin_path_of(&[dir.path()]));
        assert!(registry.lookup("KEY", "foo").is_err());
    }

    #[test]
    fn plugin_fallback_skips_empty_path_entries() {
        let dir = TempDir::new().unwrap();
        plant(dir.path(), "dev-secret-foo", 0o755);
        let path = PluginPath::from_os_str(OsStr::new(":"));
        assert!(path.find("dev-secret-foo").is_none());
        let _ = dir;
    }

    #[test]
    fn provider_name_with_path_separator_never_touches_the_filesystem() {
        let dir = TempDir::new().unwrap();
        let inner = dir.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        plant(dir.path(), "dev-secret-evil", 0o755);
        let registry = ProviderRegistry::empty(Path::new("/w"), plugin_path_of(&[&inner]));

        for name in ["../evil", "sub/evil", "/absolute", ".."] {
            assert!(
                registry.lookup("KEY", name).is_err(),
                "`{name}` escaped the search directory"
            );
        }
    }

    #[test]
    fn provider_name_with_whitespace_is_rejected() {
        let dir = TempDir::new().unwrap();
        plant(dir.path(), "dev-secret-my provider", 0o755);
        let registry = ProviderRegistry::empty(Path::new("/w"), plugin_path_of(&[dir.path()]));
        let msg = format!("{}", registry.lookup("KEY", "my provider").unwrap_err());
        assert!(msg.contains("my provider"), "names the provider: {msg}");
    }

    #[test]
    fn plugin_lookup_never_reads_process_path() {
        let dir = TempDir::new().unwrap();
        let registry = ProviderRegistry::empty(Path::new("/w"), plugin_path_of(&[dir.path()]));
        assert!(registry.lookup("KEY", "sh").is_err());
        assert!(registry.lookup("KEY", "env").is_err());
    }

    #[test]
    fn batch_debug_hides_values() {
        let mut batch = ResolvedBatch::new();
        batch.push_value("TOKEN", SecretValue::new("hunter2"));
        batch.push_failure("OTHER", "no such item in the vault");
        let out = format!("{batch:?}");
        assert!(out.contains("TOKEN"), "keeps the key: {out}");
        assert!(out.contains("***"), "redacts: {out}");
        assert!(!out.contains("hunter2"), "leaked the value: {out}");
    }

    #[tokio::test]
    async fn one_resolve_call_per_provider_per_batch() {
        let stub = fake("stub");
        let registry = registry_with(stub.clone());
        let refs = vec![
            secret_ref("A", "stub"),
            secret_ref("B", "stub"),
            secret_ref("C", "stub"),
        ];
        registry.resolve_all(&refs).await.unwrap();

        assert_eq!(stub.calls(), 1);
        let batches = stub.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 3);
    }

    #[tokio::test]
    async fn two_providers_get_one_call_each() {
        let one = fake("p1");
        let two = fake("p2");
        let mut registry = registry_with(one.clone());
        registry.register(Box::new(two.clone()));
        let refs = vec![
            secret_ref("A", "p1"),
            secret_ref("B", "p2"),
            secret_ref("C", "p1"),
        ];
        registry.resolve_all(&refs).await.unwrap();

        assert_eq!(one.calls(), 1);
        assert_eq!(two.calls(), 1);
        assert_eq!(one.batches()[0].len(), 2);
        assert_eq!(two.batches()[0].len(), 1);
    }

    #[tokio::test]
    async fn results_follow_declaration_order() {
        let mut registry = registry_with(fake("p1"));
        registry.register(Box::new(fake("p2")));
        let refs = vec![
            secret_ref("A", "p1"),
            secret_ref("B", "p2"),
            secret_ref("C", "p1"),
        ];
        let pairs = registry.resolve_all(&refs).await.unwrap();

        let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, vec!["A", "B", "C"]);
        assert_eq!(pairs[0].1.expose(), "value-for-A");
    }

    #[tokio::test]
    async fn optional_key_failure_is_omitted() {
        let registry = registry_with(FakeProvider::failing_for("B").named("stub"));
        let refs = vec![
            secret_ref("A", "stub"),
            optional_ref("B", "stub"),
            secret_ref("C", "stub"),
        ];
        let pairs = registry.resolve_all(&refs).await.unwrap();

        let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, vec!["A", "C"]);
    }

    #[tokio::test]
    async fn required_key_failure_is_fatal() {
        let registry = registry_with(FakeProvider::failing_for("B").named("stub"));
        let refs = vec![secret_ref("A", "stub"), secret_ref("B", "stub")];
        let err = registry.resolve_all(&refs).await.unwrap_err();

        assert!(matches!(err, DevError::SecretResolution { .. }));
        let msg = format!("{err}");
        assert!(msg.contains('B'), "names the key: {msg}");
        assert!(msg.contains("stub"), "names the provider: {msg}");
        assert!(msg.contains("told to fail"), "carries the reason: {msg}");
        assert!(!msg.contains("value-for-A"), "leaked a value: {msg}");
    }

    #[tokio::test]
    async fn whole_batch_error_still_respects_optional() {
        let stub = FakeProvider::unavailable("op is not installed").named("stub");
        let registry = registry_with(stub);
        let refs = vec![optional_ref("A", "stub"), optional_ref("B", "stub")];
        assert!(registry.resolve_all(&refs).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn whole_batch_error_is_fatal_for_a_required_key() {
        let stub = FakeProvider::unavailable("op is not signed in").named("stub");
        let registry = registry_with(stub);
        let refs = vec![optional_ref("A", "stub"), secret_ref("B", "stub")];
        let err = registry.resolve_all(&refs).await.unwrap_err();

        assert!(
            matches!(err, DevError::SecretResolution { ref key, .. } if key == "B"),
            "wrong variant or key: {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("op is not signed in"), "carries reason: {msg}");
    }

    #[tokio::test]
    async fn missing_key_in_batch_is_a_failure() {
        let registry = registry_with(fake("stub").omitting("B"));
        let refs = vec![secret_ref("A", "stub"), secret_ref("B", "stub")];
        let err = registry.resolve_all(&refs).await.unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains('B'), "names the key: {msg}");
        assert!(msg.contains(NO_VALUE_RETURNED), "says why: {msg}");
    }

    #[tokio::test]
    async fn extra_key_in_batch_is_ignored() {
        let registry = registry_with(fake("stub").answering_unasked("UNASKED", "x"));
        let refs = vec![secret_ref("A", "stub")];
        let pairs = registry.resolve_all(&refs).await.unwrap();

        let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, vec!["A"]);
    }

    #[tokio::test]
    async fn two_invocations_call_the_provider_twice() {
        let stub = fake("stub");
        let registry = registry_with(stub.clone());
        let refs = vec![secret_ref("A", "stub")];
        registry.resolve_all(&refs).await.unwrap();
        registry.resolve_all(&refs).await.unwrap();

        assert_eq!(stub.calls(), 2);
    }

    #[tokio::test]
    async fn unknown_provider_fails_resolve_all_even_for_an_optional_ref() {
        let registry = empty_registry();
        let refs = vec![optional_ref("A", "nope")];
        let err = registry.resolve_all(&refs).await.unwrap_err();
        assert!(matches!(err, DevError::SecretReference { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn plugin_arm_runs_the_dev_secret_binary() {
        let dir = TempDir::new().unwrap();
        plant_script(
            dir.path(),
            "dev-secret-foo",
            "cat >/dev/null\necho '{\"version\":1,\"secrets\":[{\"key\":\"A\",\"value\":\"alpha\"}]}'",
        );
        let registry = ProviderRegistry::empty(dir.path(), plugin_path_of(&[dir.path()]));
        let pairs = registry
            .resolve_all(&[secret_ref("A", "foo")])
            .await
            .unwrap();

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "A");
        assert_eq!(pairs[0].1.expose(), "alpha");
    }

    #[tokio::test]
    async fn a_failing_plugin_becomes_a_key_failure_the_registry_owns() {
        let dir = TempDir::new().unwrap();
        plant_script(dir.path(), "dev-secret-foo", "exit 3");
        let registry = ProviderRegistry::empty(dir.path(), plugin_path_of(&[dir.path()]));

        assert!(
            registry
                .resolve_all(&[optional_ref("A", "foo")])
                .await
                .unwrap()
                .is_empty()
        );

        let err = registry
            .resolve_all(&[secret_ref("A", "foo")])
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(matches!(err, DevError::SecretResolution { .. }), "{msg}");
        assert!(msg.contains("dev-secret-foo"), "names the plugin: {msg}");
        assert!(msg.contains("code 3"), "names the exit code: {msg}");
    }

    #[test]
    fn registry_keeps_the_workspace_it_was_built_with() {
        let registry = ProviderRegistry::with_builtins(Path::new("/workspace"));
        assert_eq!(registry.workspace(), Path::new("/workspace"));
        assert_eq!(
            registry.known_names(),
            vec!["env", "exec", "file", "keychain", "op"]
        );
    }

    #[tokio::test]
    async fn fake_provider_answers_from_its_fixture() {
        let provider = FakeProvider::answering(&[("A", "alpha")]);
        let refs = vec![secret_ref("A", "fake")];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(batch.values()[0].0, "A");
        assert_eq!(batch.values()[0].1.expose(), "alpha");
        assert!(batch.failures().is_empty());
    }

    #[tokio::test]
    async fn fake_provider_counts_one_call_per_batch() {
        let provider = FakeProvider::answers_everything();
        let refs = vec![
            secret_ref("A", "fake"),
            secret_ref("B", "fake"),
            secret_ref("C", "fake"),
        ];
        provider.resolve(&refs).await.unwrap();
        assert_eq!(provider.calls(), 1);

        provider.resolve(&refs).await.unwrap();
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn fake_provider_counts_a_future_that_is_never_awaited() {
        let provider = FakeProvider::answers_everything();
        let refs = vec![secret_ref("A", "fake")];
        drop(provider.resolve(&refs));

        assert_eq!(provider.calls(), 1, "counts at call time, not first poll");
    }

    #[tokio::test]
    async fn fake_provider_records_batch_membership() {
        let provider = FakeProvider::answers_everything();
        let refs = vec![
            secret_ref("A", "fake"),
            secret_ref("B", "fake"),
            secret_ref("C", "fake"),
        ];
        provider.resolve(&refs).await.unwrap();

        assert_eq!(provider.batch_keys(), vec![vec!["A", "B", "C"]]);
        assert_eq!(provider.batches()[0], refs);
    }

    #[tokio::test]
    async fn fake_provider_answers_in_input_order() {
        let provider = FakeProvider::answering(&[("B", "beta"), ("A", "alpha")]);
        let refs = vec![secret_ref("B", "fake"), secret_ref("A", "fake")];
        let batch = provider.resolve(&refs).await.unwrap();

        let keys: Vec<&str> = batch.values().iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, vec!["B", "A"]);
    }

    #[tokio::test]
    async fn fake_provider_shares_its_counter_with_a_clone() {
        let provider = FakeProvider::answers_everything();
        let registered = provider.clone();
        let refs = vec![secret_ref("A", "fake")];
        registered.resolve(&refs).await.unwrap();

        assert_eq!(provider.calls(), 1);
        assert_eq!(provider.batch_keys(), vec![vec!["A"]]);
    }

    #[tokio::test]
    async fn fake_provider_fails_one_key_and_answers_the_rest() {
        let provider = FakeProvider::failing_for("B");
        let refs = vec![
            secret_ref("A", "fake"),
            secret_ref("B", "fake"),
            secret_ref("C", "fake"),
        ];
        let batch = provider.resolve(&refs).await.unwrap();

        let keys: Vec<&str> = batch.values().iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, vec!["A", "C"]);
        assert_eq!(batch.failures().len(), 1);
        assert_eq!(batch.failures()[0].key, "B");
        assert!(batch.failures()[0].reason.contains('B'), "names the key");
        assert!(
            !batch.failures()[0].reason.contains("value-for"),
            "leaked a value: {}",
            batch.failures()[0].reason
        );
    }

    #[tokio::test]
    async fn fake_provider_fails_two_keys() {
        let provider = FakeProvider::failing_for("A").also_failing_for("B");
        let refs = vec![secret_ref("A", "fake"), secret_ref("B", "fake")];
        let batch = provider.resolve(&refs).await.unwrap();

        let failed: Vec<&str> = batch
            .failures()
            .iter()
            .map(|failure| failure.key.as_str())
            .collect();
        assert_eq!(failed, vec!["A", "B"]);
        assert!(batch.values().is_empty());
    }

    #[tokio::test]
    async fn fake_provider_unavailable_fails_the_whole_batch() {
        let provider = FakeProvider::unavailable("op is not installed").named("op");
        let refs = vec![secret_ref("A", "op"), secret_ref("B", "op")];
        let err = provider.resolve(&refs).await.unwrap_err();

        assert!(
            matches!(err, DevError::SecretProviderFailed { .. }),
            "{err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("op is not installed"), "carries reason: {msg}");
        assert!(!msg.contains("value-for"), "leaked a value: {msg}");
    }

    #[tokio::test]
    async fn fake_provider_recording_answers_nothing_but_still_counts() {
        let provider = FakeProvider::recording();
        let refs = vec![secret_ref("A", "fake")];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(provider.calls(), 1);
        assert!(batch.values().is_empty());
        assert_eq!(batch.failures()[0].key, "A");
    }

    #[tokio::test]
    async fn fake_provider_answers_everything_without_a_fixture() {
        let batch = FakeProvider::default()
            .resolve(&[secret_ref("TOKEN", "fake")])
            .await
            .unwrap();

        assert_eq!(batch.values()[0].1.expose(), "value-for-TOKEN");
    }

    #[test]
    fn fake_provider_reports_the_name_it_was_given() {
        assert_eq!(FakeProvider::answers_everything().name(), "fake");
        assert_eq!(FakeProvider::answers_everything().named("op").name(), "op");
    }

    #[tokio::test]
    async fn fake_provider_ignores_the_optional_flag() {
        let provider = FakeProvider::failing_for("B");
        let refs = vec![optional_ref("B", "fake")];
        let batch = provider.resolve(&refs).await.unwrap();

        assert_eq!(batch.failures()[0].key, "B", "the registry owns `optional`");
    }

    #[tokio::test]
    async fn fake_provider_debug_of_a_resolved_value_is_redacted() {
        let provider = FakeProvider::answering(&[("A", "hunter2")]);
        let batch = provider.resolve(&[secret_ref("A", "fake")]).await.unwrap();

        let out = format!("{:?}", batch.values()[0].1);
        assert!(out.contains("***"), "redacts: {out}");
        assert!(!out.contains("hunter2"), "leaked the value: {out}");
    }

    #[test]
    fn the_trait_is_object_safe_and_the_registry_crosses_an_await() {
        let _: Box<dyn SecretProvider> = Box::new(FakeProvider::default());
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProviderRegistry>();
        assert_send_sync::<Box<dyn SecretProvider>>();
    }
}
