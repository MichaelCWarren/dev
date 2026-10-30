#!/bin/sh
# Installs OpenSSH's server so dev can run `sshd -i` per connection. Host keys
# are deleted here, in the same RUN, so no layer holds one, and the service is
# disabled: nothing runs on its own.
set -e

if [ "$(id -u)" != "0" ]; then
  echo "ssh-server: this feature must install as root" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ssh-server supports Debian and Ubuntu images only (needs apt-get)" >&2
  exit 1
fi

POLICY=/usr/sbin/policy-rc.d
CREATED_POLICY=
if [ ! -e "$POLICY" ]; then
  printf '#!/bin/sh\nexit 101\n' > "$POLICY"
  chmod 0755 "$POLICY"
  CREATED_POLICY=1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openssh-server openssh-sftp-server
rm -rf /var/lib/apt/lists/*

if [ -n "$CREATED_POLICY" ]; then
  rm -f "$POLICY"
fi

VERSION="$(dpkg-query -W -f='${Version}' openssh-server)"
if dpkg --compare-versions "$VERSION" lt 1:8.7; then
  echo "ssh-server: installed openssh-server $VERSION, but dev's ssh server needs OpenSSH 8.7 or newer for SetEnv (Debian 12+, Ubuntu 22.04+)" >&2
  exit 1
fi

rm -f /etc/ssh/ssh_host_*
if ls /etc/ssh/ssh_host_* >/dev/null 2>&1; then
  echo "ssh-server: a host key remains in /etc/ssh after deletion" >&2
  exit 1
fi

touch /etc/ssh/sshd_not_to_be_run
if command -v update-rc.d >/dev/null 2>&1; then
  update-rc.d ssh disable || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable ssh.service ssh.socket || true
fi

install -d -m 0755 -o root -g root /run/sshd

if [ ! -x /usr/sbin/sshd ]; then
  echo "ssh-server: /usr/sbin/sshd is missing after install" >&2
  exit 1
fi
