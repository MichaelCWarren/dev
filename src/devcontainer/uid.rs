use std::collections::HashMap;

use crate::devcontainer::DevcontainerConfig;
use crate::runtime::{ContainerRuntime, HostAccess};

/// Dockerfile used to remap a container user's UID/GID to match the host.
/// Sourced from the official devcontainer CLI's `scripts/updateUID.Dockerfile`.
const UPDATE_UID_DOCKERFILE: &str = r#"ARG BASE_IMAGE
FROM $BASE_IMAGE

USER root

ARG REMOTE_USER
ARG NEW_UID
ARG NEW_GID
SHELL ["/bin/sh", "-c"]
RUN eval $(sed -n "s/${REMOTE_USER}:[^:]*:\([^:]*\):\([^:]*\):[^:]*:\([^:]*\).*/OLD_UID=\1;OLD_GID=\2;HOME_FOLDER=\3/p" /etc/passwd); \
	eval $(sed -n "s/\([^:]*\):[^:]*:${NEW_UID}:.*/EXISTING_USER=\1/p" /etc/passwd); \
	eval $(sed -n "s/\([^:]*\):[^:]*:${NEW_GID}:.*/EXISTING_GROUP=\1/p" /etc/group); \
	if [ -z "$OLD_UID" ]; then \
		echo "Remote user not found in /etc/passwd ($REMOTE_USER)."; \
	elif [ "$OLD_UID" = "$NEW_UID" -a "$OLD_GID" = "$NEW_GID" ]; then \
		echo "UIDs and GIDs are the same ($NEW_UID:$NEW_GID)."; \
	elif [ "$OLD_UID" != "$NEW_UID" -a -n "$EXISTING_USER" ]; then \
		echo "User with UID exists ($EXISTING_USER=$NEW_UID)."; \
	else \
		if [ "$OLD_GID" != "$NEW_GID" -a -n "$EXISTING_GROUP" ]; then \
			echo "Group with GID exists ($EXISTING_GROUP=$NEW_GID)."; \
			NEW_GID="$OLD_GID"; \
		fi; \
		echo "Updating UID:GID from $OLD_UID:$OLD_GID to $NEW_UID:$NEW_GID."; \
		sed -i -e "s/\(${REMOTE_USER}:[^:]*:\)[^:]*:[^:]*/\1${NEW_UID}:${NEW_GID}/" /etc/passwd; \
		if [ "$OLD_GID" != "$NEW_GID" ]; then \
			sed -i -e "s/\([^:]*:[^:]*:\)${OLD_GID}:/\1${NEW_GID}:/" /etc/group; \
		fi; \
		chown -R $NEW_UID:$NEW_GID $HOME_FOLDER; \
	fi;

ARG IMAGE_USER
USER $IMAGE_USER
"#;

/// Determine whether UID remapping should be performed.
pub fn should_remap_uid(
    config: &DevcontainerConfig,
    remote_user: Option<&str>,
    update_default: &str,
    host_access: HostAccess,
) -> bool {
    // "never" disables UID remapping entirely.
    if update_default == "never" {
        return false;
    }

    // Check config override, falling back to CLI default.
    let enabled = config
        .update_remote_user_uid
        .unwrap_or(update_default == "on");
    if !enabled {
        return false;
    }

    // Skip where the file sharing layer already squashes bind mount ownership
    // to the container user — remapping would fight it, not fix it.
    if host_access.squashes_ownership {
        return false;
    }

    // Skip if the remote user is root or a numeric UID.
    match remote_user {
        None | Some("root") => false,
        Some(u) => u.parse::<u32>().is_err(),
    }
}

/// The tag the UID-remapping layer is stored under. `dev prune`'s keep set
/// derives current `-uid` tags through this same function, so a change here
/// cannot silently drift prune into deleting the live image.
pub fn uid_image_tag(base_image: &str, folder_image: &str) -> String {
    if base_image.starts_with(folder_image) {
        format!("{base_image}-uid")
    } else {
        format!("{folder_image}-uid")
    }
}

/// Build the UID-remapping image layer.
///
/// Returns the tag of the built image (e.g., `vsc-name-hash-features-uid`).
pub async fn build_uid_image(
    runtime: &dyn ContainerRuntime,
    base_image: &str,
    folder_image: &str,
    remote_user: &str,
    image_user: &str,
    no_cache: bool,
    verbose: bool,
) -> anyhow::Result<String> {
    let tag = uid_image_tag(base_image, folder_image);

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mut build_args = HashMap::new();
    build_args.insert("BASE_IMAGE".to_string(), base_image.to_string());
    build_args.insert("REMOTE_USER".to_string(), remote_user.to_string());
    build_args.insert("NEW_UID".to_string(), uid.to_string());
    build_args.insert("NEW_GID".to_string(), gid.to_string());
    build_args.insert("IMAGE_USER".to_string(), image_user.to_string());

    // Create a temporary empty directory as build context.
    let tmp_dir = std::env::temp_dir().join(format!("dev-uid-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let context = &tmp_dir;

    eprintln!("Building UID remapping image (uid={uid}, gid={gid})...");
    let result = runtime
        .build_image(
            UPDATE_UID_DOCKERFILE,
            context,
            &tag,
            &build_args,
            no_cache,
            verbose,
        )
        .await;
    let _ = std::fs::remove_dir_all(&tmp_dir);
    result.map_err(|e| anyhow::anyhow!("Failed to build UID image: {e}"))?;

    Ok(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built from `all_off` rather than `HostAccess::for_flavor(...)`, so a
    /// later edit to the flavor table cannot silently change what these tests
    /// prove.
    fn access(squashes_ownership: bool) -> HostAccess {
        HostAccess {
            squashes_ownership,
            ..HostAccess::all_off()
        }
    }

    fn test_config(update_uid: Option<bool>) -> DevcontainerConfig {
        DevcontainerConfig {
            name: None,
            image: None,
            build: None,
            docker_compose_file: None,
            service: None,
            workspace_folder: None,
            workspace_mount: None,
            features: None,
            forward_ports: None,
            remote_user: None,
            remote_env: None,
            container_env: None,
            mounts: None,
            volumes: None,
            run_args: None,
            on_create_command: None,
            update_content_command: None,
            post_create_command: None,
            post_start_command: None,
            post_attach_command: None,
            initialize_command: None,
            customize: None,
            caddy: None,
            update_remote_user_uid: update_uid,
            dotfiles: None,
            cmux: None,
            ssh_agent: None,
        }
    }

    #[test]
    fn test_never_mode_disables_remap() {
        let config = test_config(Some(true));
        assert!(!should_remap_uid(
            &config,
            Some("vscode"),
            "never",
            access(false)
        ));
    }

    #[test]
    fn test_root_user_skips_remap() {
        let config = test_config(None);
        assert!(!should_remap_uid(
            &config,
            Some("root"),
            "on",
            access(false)
        ));
        assert!(!should_remap_uid(&config, None, "on", access(false)));
    }

    #[test]
    fn test_numeric_user_skips_remap() {
        let config = test_config(None);
        assert!(!should_remap_uid(
            &config,
            Some("1000"),
            "on",
            access(false)
        ));
    }

    #[test]
    fn test_config_override_off() {
        let config = test_config(Some(false));
        // Config says false, even though default is "on"
        assert!(!should_remap_uid(
            &config,
            Some("vscode"),
            "on",
            access(false)
        ));
    }

    #[test]
    fn test_default_off_no_config() {
        let config = test_config(None);
        // Default is "off" and config doesn't override
        assert!(!should_remap_uid(
            &config,
            Some("vscode"),
            "off",
            access(false)
        ));
    }

    /// The same assertion on every host: remapping now follows the daemon's
    /// own ownership behavior, not which OS `dev` runs on. Fails on macOS if
    /// a platform-keyed skip survives anywhere in the function.
    #[test]
    fn remapping_follows_whether_the_daemon_squashes_ownership() {
        let config = test_config(None);
        assert!(!should_remap_uid(
            &config,
            Some("vscode"),
            "on",
            access(true)
        ));
        assert!(should_remap_uid(
            &config,
            Some("vscode"),
            "on",
            access(false)
        ));
    }

    /// Prune's keep set derives `-uid` tags through this same function; the
    /// two cases are a features tag (extends the folder image) and a plain
    /// base image (does not).
    #[test]
    fn uid_image_tag_extends_the_derived_tag_or_the_folder_image() {
        assert_eq!(
            uid_image_tag("vsc-ws-abc-features-aaaaaaaaaaaa", "vsc-ws-abc"),
            "vsc-ws-abc-features-aaaaaaaaaaaa-uid"
        );
        assert_eq!(
            uid_image_tag("ubuntu:24.04", "vsc-ws-abc"),
            "vsc-ws-abc-uid"
        );
    }
}
