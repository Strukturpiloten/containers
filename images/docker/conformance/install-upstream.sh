#!/bin/sh
set -eux
mode="${1:?daemon mode required}"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get --yes upgrade
apt-get install --yes --no-install-recommends busybox ca-certificates iproute2 iptables passwd procps tar
if [ "$mode" = rootless ]; then
    apt-get install --yes --no-install-recommends fuse-overlayfs slirp4netns uidmap
    chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap
else
    rm -f /usr/local/bin/rootlesskit /usr/local/bin/rootlessctl /usr/local/bin/dockerd-rootless.sh /usr/local/bin/dockerd-rootless-setuptool.sh
fi
groupadd --gid 1000 dockertest
useradd --uid 1000 --gid 1000 --create-home --home-dir /home/docker dockertest
printf '%s\n' 'dockertest:100000:65536' > /etc/subuid
printf '%s\n' 'dockertest:100000:65536' > /etc/subgid
mkdir -p /var/lib/docker /home/docker/.local/share/docker
chown -R 1000:1000 /home/docker
rm -rf /var/lib/apt/lists/*
