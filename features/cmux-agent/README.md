# cmux-agent

Lets an agent running in this container report to the host's [cmux](https://cmux.dev)
sidebar. Claude Code started inside a `dev shell` shows its session, prompts, and tool use
there, the same as one running on the host.

```json
{
  "cmux": { "agent": true }
}
```

You do not reference this feature by path. `dev` carries these files in its own binary and
adds the feature to the build itself when `cmux.agent` is on, staging it to
`~/.dev/features/cmux-agent`. The directory here is the source of those bytes, not something
a project points at. Editing it changes what the next `dev` build ships.

## What it installs

- `/usr/local/share/dev-cmux/bin/cmux`, a shim standing in for the cmux CLI
- that directory first on `PATH`, through `/etc/profile.d` and `/etc/zsh/zshenv`, since
  Ubuntu's zsh reads neither the other's file
- `uuid-runtime`, which cmux's claude wrapper calls for the agent's session id

Nothing runs at build time beyond the install, and nothing runs afterwards until a
`dev shell` session opens the host's listener and sets `DEV_CMUX_RELAY`. Outside that, the
shim exits non-zero, which cmux's wrapper reads as "no cmux" and runs claude untouched.

## Why a relay and not a socket

cmux only accepts connections from processes descended from one of its own terminals, so no
amount of mounting or credentialing gets a container process through. `dev shell` *is* such
a descendant. It listens on the host's loopback and runs each forwarded verb against the
real CLI there.

The shim talks to it over bash's own `/dev/tcp`, because a stock Ubuntu image has no `nc`,
`socat`, `python3`, `curl`, or `wget` to do it with.

## Claude Code only

cmux supports eighteen agents and ships wrappers for three. Only claude works here, for a
structural reason rather than an unfinished one.

claude is wired up by an inline `--settings` blob whose hook commands travel in argv, so
inside the container they resolve to the shim next to the wrapper. Nothing is written
anywhere. Every other agent is wired up by asking the CLI to generate hook scripts on disk
and pointing the agent at those paths, and over this relay the CLI runs on the host: the
scripts land in the user's home and the paths handed back do not exist in the container.

So the relay refuses `install`, `uninstall`, `setup`, and codex's `inject-args`, which reads
like a query but generates `~/.cmux/hooks/cmux-codex-hook-*.sh` before answering. The rule
is that this relay reports and never writes, and `src/cmux/agent.rs` enforces it by name
rather than by shape.

## Limits

Docker only. Debian and Ubuntu images only, for apt and for `/etc/zsh/zshenv`. `dev exec`
gets nothing; the relay belongs to a `dev shell` session and dies with it. If claude is not
already installed in the container, no wrapper is landed and nothing is opened.
