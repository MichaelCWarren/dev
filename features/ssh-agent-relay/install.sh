#!/bin/sh
# Lands the shim the base layer's ssh-agent-relay.sh execs into. Nothing here
# reaches the network, and nothing runs until dev up starts a relay and bakes
# DEV_SSH_AGENT_UPSTREAM into the container's environment.
set -e

BIN_DIR=/usr/local/share/dev-ssh/bin

install -d "$BIN_DIR"
install -m 0755 ssh-agent-upstream "$BIN_DIR/ssh-agent-upstream"
