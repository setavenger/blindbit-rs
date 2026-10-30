#!/usr/bin/env bash
# Install a friglet-tray Linux bundle on the distro this runs on, the way a
# user would, and check it works: the package's dependencies resolve, both
# binaries find their libraries, the daemon runs, and on a first launch (no
# config) the tray starts, opens its setup window and stays up under a
# virtual X display.
#
# Usage (as root inside a throwaway distro container, see release.yml):
#   scripts/linux-install-check.sh deb|rpm|appimage DIST_DIR
#   DIST_DIR holds the bundles for this machine's architecture.
set -euo pipefail

kind=$1
dist=$(cd "$2" && pwd)
. /etc/os-release
echo "== $PRETTY_NAME ($(uname -m)): $kind"

bundle() {
    local f
    f=$(find "$dist" -name "*.$1" | head -n 1)
    [ -n "$f" ] || { echo "no .$1 in $dist" >&2; exit 1; }
    echo "$f"
}

# Install the bundle plus Xvfb, dbus-run-session and xdotool for the launch
# check.
# Recommends stay off so the package's own Depends/Requires must suffice.
case "$kind" in
deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        "$(bundle deb)" xvfb dbus xdotool > /dev/null
    tray=(/usr/bin/friglet-tray)
    daemon=/usr/bin/friglet
    ;;
rpm)
    if command -v dnf > /dev/null; then
        dnf install -y -q --setopt=install_weak_deps=False \
            "$(bundle rpm)" /usr/bin/Xvfb /usr/bin/dbus-run-session /usr/bin/xdotool
    else
        # The rpm is not GPG-signed; zypper refuses it without this flag.
        zypper -n -q install --no-recommends --allow-unsigned-rpm \
            "$(bundle rpm)" /usr/bin/Xvfb /usr/bin/dbus-run-session /usr/bin/xdotool
    fi
    tray=(/usr/bin/friglet-tray)
    daemon=/usr/bin/friglet
    ;;
appimage)
    # A minimal desktop: GTK, which any desktop with a tray has; WebKit
    # comes from the AppImage itself.
    pacman -Syu --noconfirm --needed \
        gtk3 xorg-server-xvfb dbus xdotool > /dev/null
    # Artifacts lose the exec bit and DIST_DIR may be read-only.
    cp "$(bundle AppImage)" /tmp/friglet-tray.AppImage
    chmod +x /tmp/friglet-tray.AppImage
    # Extract instead of mounting: containers have no FUSE.
    (cd /tmp && ./friglet-tray.AppImage --appimage-extract > /dev/null)
    tray=(/tmp/squashfs-root/AppRun)
    daemon=/tmp/squashfs-root/usr/bin/friglet
    ;;
*)
    echo "unknown bundle kind: $kind" >&2
    exit 2
    ;;
esac

# The tray icon talks StatusNotifierItem over D-Bus (tray-icon's ksni
# backend), so there is no dlopen()ed appindicator library to check for.
if [ "$kind" != appimage ] && ldd /usr/bin/friglet-tray /usr/bin/friglet | grep 'not found'; then
    echo "::error::missing shared libraries on $PRETTY_NAME"
    exit 1
fi
"$daemon" --help > /dev/null

Xvfb :99 -screen 0 1280x800x24 -nolisten tcp > /tmp/xvfb.log 2>&1 &
for _ in $(seq 50); do
    [ -S /tmp/.X11-unix/X99 ] && break
    sleep 0.2
done
export DISPLAY=:99
# A first launch: fresh home, no config.
HOME=$(mktemp -d)
export HOME
# WebKit's bubblewrap sandbox cannot start inside an unprivileged container.
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1

dbus-run-session -- "${tray[@]}" > /tmp/tray.log 2>&1 &
pid=$!
# Unconfigured, the tray opens its window on the Settings tab by itself.
window=
for _ in $(seq 60); do
    kill -0 "$pid" 2> /dev/null || break
    window=$(xdotool search --name '^Friglet Status$' 2> /dev/null | head -n 1 || true)
    [ -n "$window" ] && break
    sleep 1
done
if [ -z "$window" ]; then
    echo "::error::friglet-tray did not open its setup window on $PRETTY_NAME"
    cat /tmp/tray.log
    exit 1
fi
sleep 5
if ! kill -0 "$pid" 2> /dev/null; then
    echo "::error::friglet-tray exited after opening its window on $PRETTY_NAME"
    cat /tmp/tray.log
    exit 1
fi
running=$( (cat /proc/[0-9]*/comm 2> /dev/null || true) | grep -E '^friglet' | sort | tr '\n' ' ' || true)
echo "window $window open, running [$running]"
kill "$pid"
tail -n 20 /tmp/tray.log
echo "== OK: $PRETTY_NAME ($(uname -m)) $kind"
