#!/usr/bin/env bash
# Install the exact registered release for the running and prepared kernels.
# Kernel package hooks retain AUTOINSTALL=yes for subsequent kernel releases.
set -euo pipefail
version="${1:?Usage: install-dkms-kernels.sh X.Y.Z}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
running="$(uname -r)"

install_kernel() {
    printf 'Installing snakedrv/%s for kernel %s\n' "$version" "$1"
    dkms install -m snakedrv -v "$version" -k "$1" --force || {
        echo "DKMS failed for $1; inspect /var/lib/dkms/snakedrv/$version/build/make.log" >&2
        exit 1
    }
}

install_kernel "$running"
for build in /lib/modules/*/build; do
    [[ -f "$build/Makefile" ]] || continue
    kernel="${build%/build}"
    kernel="${kernel##*/}"
    [[ "$kernel" = "$running" ]] && continue
    install_kernel "$kernel"
done
