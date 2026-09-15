# ssh-agent-relay

Gives the container a path back to the host's ssh-agent when the base layer's mounted
1Password socket cannot reach it. `dev` starts a loopback listener on the host and hands the
container an address and a token; this feature installs the one piece the container itself
needs to speak to it.

```json
{
  "sshAgent": { "relay": true }
}
```

That key is the project's request; the user's own base config grants it with
`sshAgent.allowRelay`, and the relay needs both.

You do not reference this feature by path. `dev` carries these files in its own binary and
adds the feature to the build itself when both keys are on, staging it to
`~/.dev/features/ssh-agent-relay`. The directory here is the source of those bytes, not
something a project points at. Editing it changes what the next `dev` build ships.

## What it installs

- `/usr/local/share/dev-ssh/bin/ssh-agent-upstream`, a shim that dials the host relay,
  presents the session token, and then pumps raw ssh-agent bytes both ways

Nothing runs at build time beyond the install, and nothing runs afterwards on its own. The
base layer's `ssh-agent-relay.sh` execs this shim in place of `UNIX-CONNECT` only when `dev`
has baked a `tcp:` upstream into the container's environment; every other container, this
feature included, behaves exactly as it did before the key existed.

## Why a relay and not a mount

The base layer's own bind mount works everywhere Docker Desktop surfaces the host socket
directly, but not every flavor can bind a host unix socket into a container. Where it
cannot, `dev` runs a small daemon that fronts the host's `$SSH_AUTH_SOCK` over loopback TCP,
gated by a per-container token minted at `dev up`. This shim is the container's end of that
connection: it never binds anything itself, and socat keeps ownership of the listening
socket, forking and reaping, exactly as it does for the mounted case.

The shim talks to the relay over bash's own `/dev/tcp`, because a stock Ubuntu image has no
`nc`, `socat`, `python3`, `curl`, or `wget` to send a handshake line ahead of the stream with.

## Limits

Does nothing until `dev up` starts a relay and hands the container a `tcp:` upstream, which
is only ever true for a flavor that cannot reach the host's ssh-agent by mount. The socket it
ultimately serves is the base layer's own `/dev/shm/ssh-agent.sock`; this feature adds a
second way to fill it, not a second agent.
