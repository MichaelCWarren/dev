# ssh-server

Puts OpenSSH's server in the image so `dev` can run `/usr/sbin/sshd -i` once per connection.
No daemon is left running and no host key is left in the image.

```json
{
  "sshServer": { "enabled": true }
}
```

The base config may set this key as well as a project. A project's `enabled: false` beats a
base `true`. Unlike `sshAgent.relay`, enabling it opens no path to host credentials: reaching
sshd takes the per-workspace client key that only the host holds.

You do not reference this feature by path. `dev` carries these files in its own binary and
adds the feature to the build itself when the key is on, staging it to
`~/.dev/features/ssh-server`. The directory here is the source of those bytes, not something
a project points at.

## What it installs

- `openssh-server` and `openssh-sftp-server`, with no recommended packages
- `/run/sshd`, the privilege separation directory sshd needs when it runs as root

## What it leaves out

- No host key. The package generates keys on install; the script deletes
  `/etc/ssh/ssh_host_*` in the same `RUN`, so no layer holds one. `dev` supplies a host key
  per session.
- No running daemon. A build-time `policy-rc.d` stops the package starting sshd, and the
  script touches `/etc/ssh/sshd_not_to_be_run` and disables the `ssh` service, so nothing
  starts it later.

## OpenSSH 8.7 floor

Session environment reaches sshd as `SetEnv`, which needs OpenSSH 8.7 or newer. Debian 12 and
Ubuntu 22.04 and later qualify. On Debian 11 or Ubuntu 20.04 the script fails the layer rather
than fall back.

## Why there is no `installsAfter`

- The feature depends on nothing another feature provides, only apt and the distro archive.
- `dev` matches `installsAfter` against exact resolved ids, so an entry such as
  `ghcr.io/devcontainers/features/common-utils` would never match a project's `...:2`.
- The staged id sorts ahead of declared features anyway, and moving it later would not keep
  keys out of another feature's layer.

## Limits

- Debian and Ubuntu images only (needs `apt-get`), and it must install as root.
- A runtime that mounts a tmpfs on `/run` hides `/run/sshd`.
- A later feature that re-runs `dpkg-reconfigure openssh-server`, or installs another sshd
  feature, can regenerate keys in its own layer. This feature cannot prevent that.
