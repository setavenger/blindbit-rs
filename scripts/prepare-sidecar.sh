#!/usr/bin/env bash
# Build the friglet daemon and stage it as a Tauri sidecar (externalBin)
# for friglet-tray. Tauri expects sidecar files to carry the target triple
# as a suffix, e.g. binaries/friglet-x86_64-unknown-linux-gnu.
#
# Usage: scripts/prepare-sidecar.sh [TARGET_TRIPLE]
#   TARGET_TRIPLE defaults to the host triple reported by rustc.
#   When a triple is given, the daemon is built with --target TRIPLE.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

triple="${1:-$(rustc -vV | sed -n 's/^host: //p')}"

exe_suffix=""
case "$triple" in
*windows*) exe_suffix=".exe" ;;
esac

if [ "${1:-}" != "" ]; then
    cargo build --release -p friglet --target "$triple"
    built="target/$triple/release/friglet$exe_suffix"
else
    cargo build --release -p friglet
    built="target/release/friglet$exe_suffix"
fi

dest_dir="friglet-tray/binaries"
dest="$dest_dir/friglet-$triple$exe_suffix"
mkdir -p "$dest_dir"
cp "$built" "$dest"
echo "sidecar staged: $dest"
