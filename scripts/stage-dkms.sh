#!/usr/bin/env bash
# Stage a self-contained DKMS source tree, without local build artifacts.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:?Usage: stage-dkms.sh DESTINATION}"
version="$(bash "$root/scripts/version.sh")"

install -d "$dest/kernel" "$dest/userland/include"
install -m 0644 "$root/kernel/Makefile" "$root/kernel/"*.[ch] "$dest/kernel/"
install -m 0644 "$root/userland/include/"*.h "$dest/userland/include/"
install -m 0755 "$root/scripts/install-dkms-kernels.sh" "$dest/install-kernels.sh"
sed "s|@SNAKEDRV_VERSION@|$version|g" "$root/packaging/dkms/dkms.conf.in" \
    > "$dest/dkms.conf"
