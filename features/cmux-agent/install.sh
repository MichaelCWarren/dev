#!/bin/sh
# Installs the cmux shim and puts its directory ahead of the real claude on
# PATH. Nothing here reaches the network except apt, and nothing runs until a
# `dev shell` session sets DEV_CMUX_RELAY.
set -e

BIN_DIR=/usr/local/share/dev-cmux/bin
MARKER="# dev-cmux"

# cmux's claude wrapper calls uuidgen for the agent's session id and no Ubuntu
# base image ships it. Missing, it produces an empty id with no error, so the
# sidebar tracks every session under the same blank name.
if ! command -v uuidgen >/dev/null 2>&1; then
    apt-get update
    apt-get install -y --no-install-recommends uuid-runtime
    rm -rf /var/lib/apt/lists/*
fi

install -d "$BIN_DIR"
install -m 0755 cmux "$BIN_DIR/cmux"

# `dev shell` writes the wrapper here as the remote user, so that user has to
# own the directory. Leaving it root-owned would fail every copy silently.
chown "${_REMOTE_USER:-root}" "$BIN_DIR"

# `dev shell` lands cmux's wrapper here as `claude`, so this directory has to
# come first for the user's own `claude` to reach it. The wrapper then finds
# the real claude further along PATH, and its sibling `cmux` by directory
# rather than by PATH, which is what survives a shell that rewrites PATH.
printf '%s\nPATH="%s:$PATH"\nexport PATH\n' "$MARKER" "$BIN_DIR" \
    > /etc/profile.d/10-dev-cmux.sh
chmod 0644 /etc/profile.d/10-dev-cmux.sh

# Ubuntu's zsh reads none of /etc/profile.d, and `dev shell` prefers zsh over
# bash, so profile.d alone would leave the common case unwired. zshenv is read
# by every zsh, login or not.
if [ -f /etc/zsh/zshenv ] && ! grep -q "$MARKER" /etc/zsh/zshenv; then
    printf '\n%s\nPATH="%s:$PATH"\nexport PATH\n' "$MARKER" "$BIN_DIR" \
        >> /etc/zsh/zshenv
fi
