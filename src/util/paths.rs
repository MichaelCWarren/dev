use std::path::PathBuf;

/// Root of user-level dev config: `~/.dev/`
pub fn dev_home() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".dev")
}

/// Global templates directory: `~/.dev/global/`
pub fn global_dir() -> PathBuf {
    dev_home().join("global")
}

/// User-scoped project devcontainers: `~/.dev/devcontainers/`
pub fn devcontainers_dir() -> PathBuf {
    dev_home().join("devcontainers")
}

/// Base config directory: `~/.dev/base/`
pub fn base_config_dir() -> PathBuf {
    dev_home().join("base")
}

/// The `~/.dev/` layout resolved against an explicit root.
///
/// The free functions above resolve against the real home directory, which makes
/// the code that reads this layout untestable without touching the user's own
/// `~/.dev/`. Taking the root as a value lets composition run against a temporary
/// tree in tests while production keeps using [`DevHome::current`].
#[derive(Debug, Clone)]
pub struct DevHome {
    root: PathBuf,
}

impl DevHome {
    /// The real `~/.dev/`.
    ///
    /// Panics under test: a test that reads the developer's own `~/.dev` can
    /// validate their base `secrets.json` and resolve it against real
    /// providers, prompting them while the suite runs.
    pub fn current() -> Self {
        #[cfg(test)]
        panic!(
            "tests must use DevHome::at(<tempdir>); DevHome::current() reads the developer's real ~/.dev"
        );
        #[cfg(not(test))]
        DevHome { root: dev_home() }
    }

    /// A `~/.dev/`-shaped layout rooted at an arbitrary directory.
    #[cfg(test)]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        DevHome { root: root.into() }
    }

    /// The global templates directory, `~/.dev/global/`.
    pub fn global_dir(&self) -> PathBuf {
        self.root.join("global")
    }

    /// The user-scoped project devcontainers directory, `~/.dev/devcontainers/`.
    pub fn devcontainers_dir(&self) -> PathBuf {
        self.root.join("devcontainers")
    }

    /// A global template's `.devcontainer/devcontainer.json`.
    pub fn global_template_config(&self, template: &str) -> PathBuf {
        self.root
            .join("global")
            .join(template)
            .join(".devcontainer/devcontainer.json")
    }

    /// A global template's `.devcontainer/` directory.
    pub fn global_template_dir(&self, template: &str) -> PathBuf {
        self.root
            .join("global")
            .join(template)
            .join(".devcontainer")
    }

    /// Where `dev` stages a feature it carries in its own binary,
    /// `~/.dev/features/<name>/`. Rewritten on every run, so upgrading `dev`
    /// upgrades what the next image build installs.
    pub fn staged_feature_dir(&self, name: &str) -> PathBuf {
        self.root.join("features").join(name)
    }

    /// The base config file, `~/.dev/base/devcontainer.json`.
    pub fn base_config(&self) -> PathBuf {
        self.root.join("base/devcontainer.json")
    }

    /// The base secrets file, `~/.dev/base/secrets.json`.
    pub fn base_secrets(&self) -> PathBuf {
        self.root.join("base/secrets.json")
    }

    /// A runtime's config file, `~/.dev/<runtime>/devcontainer.json`.
    pub fn runtime_config(&self, runtime: &str) -> PathBuf {
        self.root.join(runtime).join("devcontainer.json")
    }

    /// A workspace's hook-log directory, `~/.dev/logs/<workspace-hash>/`.
    pub fn workspace_logs_dir(&self, workspace_hash: &str) -> PathBuf {
        self.root.join("logs").join(workspace_hash)
    }

    /// A workspace's SSH agent relay state file,
    /// `~/.dev/ssh-relay/<workspace-hash>.json`. Records the daemon's port
    /// and pid, so a later `dev up` can tell its own relay from a stale one.
    pub fn ssh_relay_state_file(&self, workspace_hash: &str) -> PathBuf {
        self.root
            .join("ssh-relay")
            .join(format!("{workspace_hash}.json"))
    }

    /// A workspace's SSH agent relay lock file,
    /// `~/.dev/ssh-relay/<workspace-hash>.lock`. Separate from the state
    /// file because that one is replaced by rename: a lock taken on an
    /// inode a rename then unlinks stops excluding anything.
    pub fn ssh_relay_lock_file(&self, workspace_hash: &str) -> PathBuf {
        self.root
            .join("ssh-relay")
            .join(format!("{workspace_hash}.lock"))
    }

    /// The directory `dev` keeps ssh server material in, `~/.dev/ssh/`.
    pub fn ssh_dir(&self) -> PathBuf {
        self.root.join("ssh")
    }

    /// A workspace's ssh key directory, `~/.dev/ssh/<workspace-hash>/`.
    pub fn ssh_workspace_dir(&self, workspace_hash: &str) -> PathBuf {
        self.ssh_dir().join(workspace_hash)
    }

    /// A workspace's ssh client key, `~/.dev/ssh/<workspace-hash>/id_ed25519`.
    /// The public half is the same path plus `.pub`.
    pub fn ssh_client_key(&self, workspace_hash: &str) -> PathBuf {
        self.ssh_workspace_dir(workspace_hash).join("id_ed25519")
    }

    /// A workspace's sshd host key, `~/.dev/ssh/<workspace-hash>/host_ed25519`.
    /// The public half is the same path plus `.pub`.
    pub fn ssh_host_key(&self, workspace_hash: &str) -> PathBuf {
        self.ssh_workspace_dir(workspace_hash).join("host_ed25519")
    }

    /// Maps a workspace hash back to its workspace,
    /// `~/.dev/ssh/<workspace-hash>/workspace.json`.
    pub fn ssh_workspace_record(&self, workspace_hash: &str) -> PathBuf {
        self.ssh_workspace_dir(workspace_hash)
            .join("workspace.json")
    }

    /// The host keys `dev` pins, `~/.dev/ssh/known_hosts`.
    pub fn ssh_known_hosts(&self) -> PathBuf {
        self.ssh_dir().join("known_hosts")
    }

    /// Serializes rewrites of the known_hosts file,
    /// `~/.dev/ssh/known_hosts.lock`.
    pub fn ssh_known_hosts_lock(&self) -> PathBuf {
        self.ssh_dir().join("known_hosts.lock")
    }

    /// The directory of per-workspace alias files, `~/.dev/ssh/config.d/`.
    pub fn ssh_alias_dir(&self) -> PathBuf {
        self.ssh_dir().join("config.d")
    }

    /// A workspace's ssh alias file, `~/.dev/ssh/config.d/<workspace-hash>`.
    /// No extension, so an `Include ~/.dev/ssh/config.d/*` glob picks it up.
    pub fn ssh_alias_file(&self, workspace_hash: &str) -> PathBuf {
        self.ssh_alias_dir().join(workspace_hash)
    }

    /// Marks that a workspace's T3 hint was shown,
    /// `~/.dev/ssh/hinted/<workspace-hash>`.
    pub fn ssh_hint_marker(&self, workspace_hash: &str) -> PathBuf {
        self.ssh_dir().join("hinted").join(workspace_hash)
    }
}

/// VS Code remote-containers configs directory.
///
/// - macOS: `~/Library/Application Support/Code/User/globalStorage/ms-vscode-remote.remote-containers/configs/`
/// - Linux: `~/.config/Code/User/globalStorage/ms-vscode-remote.remote-containers/configs/`
pub fn vscode_configs_dir() -> PathBuf {
    dirs::config_dir()
        .expect("could not determine config directory")
        .join("Code/User/globalStorage/ms-vscode-remote.remote-containers/configs")
}
