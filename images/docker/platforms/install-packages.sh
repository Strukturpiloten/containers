#!/bin/sh
set -eux

distro="${1:?distribution ID required}"
engine_package="${2:?native Engine package required}"
run_as_user="${3:?runtime user required}"
if [ "$run_as_user" = root ]; then
    mode=rootful
else
    test "$run_as_user" = 1000:1000
    mode=rootless
fi

mkdir -p /usr/share/strukturpiloten/docker
provenance=/usr/share/strukturpiloten/docker

case "$distro" in
    debian-11|debian-12|debian-13|ubuntu-22.04|ubuntu-24.04|ubuntu-26.04)
        if [ "$distro" = debian-11 ]; then
            # Bullseye's normal main mirror is retired. Keep apt signature checks;
            # the live security index refers to missing .debs, so use archived main.
            rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
            printf '%s\n' \
                'deb [check-valid-until=no] http://archive.debian.org/debian bullseye main' \
                > /etc/apt/sources.list
        fi
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get --yes upgrade
        apt-get install --yes --no-install-recommends \
            busybox ca-certificates "$engine_package" iproute2 iptables passwd procps tar
        if [ "$distro" = debian-13 ]; then
            # Debian 13 splits the vendor CLI from the docker.io daemon package.
            apt-get install --yes --no-install-recommends docker-cli
        fi
        if [ "$mode" = rootless ]; then
            apt-get install --yes --no-install-recommends \
                fuse-overlayfs rootlesskit slirp4netns uidmap
        fi
        apt-cache policy "$engine_package" > "$provenance/vendor-source"
        dpkg-query --show --showformat='${Version}\n' "$engine_package" > "$provenance/package-version"
        dpkg-query --show --showformat='${binary:Package}=${Version}\n' \
            | sort > "$provenance/os-packages"
        rm -rf /var/lib/apt/lists/*
        ;;
    fedora-43|fedora-44)
        dnf --assumeyes --refresh upgrade
        dnf --assumeyes install --setopt=install_weak_deps=False \
            busybox ca-certificates "$engine_package" iproute iptables procps-ng shadow-utils tar
        if [ "$mode" = rootless ]; then
            dnf --assumeyes install --setopt=install_weak_deps=False \
                fuse-overlayfs rootlesskit shadow-utils-subid slirp4netns
        fi
        rpm --query --info "$engine_package" > "$provenance/vendor-source"
        rpm --query --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            "$engine_package" > "$provenance/package-version"
        rpm --query --all --queryformat '%{NAME}=%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            | sort > "$provenance/os-packages"
        dnf clean all
        rm -rf /var/cache/dnf /var/log/dnf* /var/log/hawkey.log /var/log/yum.*
        ;;
    opensuse-leap-16.0|opensuse-tumbleweed)
        zypper --non-interactive refresh
        if [ "$distro" = opensuse-tumbleweed ]; then
            zypper --non-interactive dist-upgrade --no-recommends
        else
            zypper --non-interactive update
        fi
        zypper --non-interactive install --no-recommends \
            busybox ca-certificates "$engine_package" iproute2 iptables procps shadow tar
        if [ "$mode" = rootless ]; then
            zypper --non-interactive install --no-recommends \
                fuse-overlayfs rootlesskit slirp4netns
        fi
        rpm --query --info "$engine_package" > "$provenance/vendor-source"
        rpm --query --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            "$engine_package" > "$provenance/package-version"
        rpm --query --all --queryformat '%{NAME}=%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            | sort > "$provenance/os-packages"
        zypper clean --all
        ;;
    alpine-3.24)
        apk upgrade --no-cache
        apk add --no-cache busybox ca-certificates "$engine_package" iproute2 iptables procps shadow tar
        if [ "$mode" = rootless ]; then
            apk add --no-cache fuse-overlayfs rootlesskit shadow-subids slirp4netns
        fi
        apk policy "$engine_package" > "$provenance/vendor-source"
        apk info --exists --verbose "$engine_package" > "$provenance/package-version"
        apk info --verbose | sort > "$provenance/os-packages"
        ;;
    arch)
        pacman --sync --refresh --sysupgrade --noconfirm
        pacman --sync --noconfirm --needed \
            busybox ca-certificates "$engine_package" iproute2 iptables-nft procps-ng shadow tar
        if [ "$mode" = rootless ]; then
            pacman --sync --noconfirm --needed \
                fuse-overlayfs rootlesskit slirp4netns
        fi
        pacman --sync --info "$engine_package" > "$provenance/vendor-source"
        pacman --query "$engine_package" > "$provenance/package-version"
        pacman --query | sort > "$provenance/os-packages"
        pacman --sync --clean --clean --noconfirm
        rm -rf /var/cache/pacman/pkg/*
        ;;
    *) echo "Unsupported vendor distro: $distro" >&2; exit 1 ;;
esac

command -v busybox
command -v docker
command -v dockerd
command -v containerd
command -v runc
docker --version > "$provenance/docker-version"
dockerd --version > "$provenance/dockerd-version"
sed -E 's/^Docker version ([^,]+),.*/\1/' \
    "$provenance/dockerd-version" > "$provenance/engine-version"
test -s "$provenance/engine-version"
printf '%s\n' distro-package > "$provenance/provenance-kind"
printf 'distribution=%s\nengine-package=%s\nmode=%s\n' \
    "$distro" "$engine_package" "$mode" > "$provenance/components.txt"
cat "$provenance/package-version" >> "$provenance/components.txt"

if [ "$mode" = rootless ]; then
    command -v rootlesskit
    command -v slirp4netns
    command -v newuidmap
    command -v newgidmap
    rootlesskit --version > "$provenance/rootlesskit-version"
    chmod u+s "$(command -v newuidmap)" "$(command -v newgidmap)"
    printf 'rootlesskit=%s\n' "$(cat "$provenance/rootlesskit-version")" \
        >> "$provenance/components.txt"
fi

if ! grep -q '^[^:]*:[^:]*:1000:' /etc/group; then
    groupadd --gid 1000 dockertest
fi
if ! grep -q '^[^:]*:[^:]*:1000:' /etc/passwd; then
    useradd --uid 1000 --gid 1000 --no-create-home \
        --home-dir /home/docker dockertest
fi
user_name=
while IFS=: read -r account_name _ account_id _; do
    if [ "$account_id" = 1000 ]; then
        user_name="$account_name"
        break
    fi
done < /etc/passwd
test -n "$user_name"
printf '%s:100000:65536\n' "$user_name" > /etc/subuid
printf '%s:100000:65536\n' "$user_name" > /etc/subgid
mkdir -p /var/lib/docker /run/docker /run/user/1000 /home/docker/.local/share/docker
chown -R 1000:1000 /run/user/1000 /home/docker
chmod 0700 /run/user/1000
rm -f /etc/machine-id /var/lib/systemd/random-seed
