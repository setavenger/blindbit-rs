#!/usr/bin/env bash
# Build the friglet daemon and stage it as a Tauri sidecar (externalBin)
# for friglet-tray. Tauri expects sidecar files to carry the target triple
# as a suffix, e.g. binaries/friglet-x86_64-unknown-linux-gnu.
#
# Usage: scripts/prepare-sidecar.sh [TARGET_TRIPLE]
#   TARGET_TRIPLE defaults to the host triple reported by rustc.
#   When a triple is given, the daemon is built with --target TRIPLE.
#   universal-apple-darwin builds both macOS slices and merges them with
#   lipo, matching `tauri build --target universal-apple-darwin`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

triple="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
target_dir="${CARGO_TARGET_DIR:-target}"

exe_suffix=""
case "$triple" in
*windows*) exe_suffix=".exe" ;;
esac

dest_dir="friglet-tray/binaries"
dest="$dest_dir/friglet-$triple$exe_suffix"
mkdir -p "$dest_dir"

if [ "$triple" = "universal-apple-darwin" ]; then
    # One cargo invocation builds both slices concurrently. The universal
    # tauri build compiles the tray once per arch, and tauri-build checks
    # for the per-arch sidecar each time, so stage the slices too.
    cargo build --release -p friglet \
        --target aarch64-apple-darwin --target x86_64-apple-darwin
    slices=()
    for arch in aarch64-apple-darwin x86_64-apple-darwin; do
        cp "$target_dir/$arch/release/friglet" "$dest_dir/friglet-$arch"
        slices+=("$dest_dir/friglet-$arch")
    done
    lipo -create -output "$dest" "${slices[@]}"
elif [ "${1:-}" != "" ]; then
    cargo build --release -p friglet --target "$triple"
    cp "$target_dir/$triple/release/friglet$exe_suffix" "$dest"
else
    cargo build --release -p friglet
    cp "$target_dir/release/friglet$exe_suffix" "$dest"
fi
echo "sidecar staged: $dest"
