#!/usr/bin/env bash
# Exercise release metadata and the actual DKMS install payload without root.
# Set KDIR to additionally compile that isolated payload against kernel headers.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

version="$(bash "$root/scripts/version.sh")"
abi="$(bash "$root/scripts/version.sh" --abi)"
bash "$root/scripts/version.sh" --check-tag "v$version" >/dev/null
if bash "$root/scripts/version.sh" --check-tag v0.0.0 > /dev/null 2>&1; then
    echo "Mismatched release tag was accepted" >&2
    exit 1
fi

dest="$tmp/snakedrv-$version"
bash "$root/scripts/stage-dkms.sh" "$dest"
test -s "$dest/userland/include/snakedrv.h"
test -s "$dest/userland/include/snakedrv_scanner.h"
test -s "$dest/kernel/snakedrv_backend_process.c"
test -x "$dest/install-kernels.sh"
test -z "$(find "$dest" -type f \( -name '*.o' -o -name '*.ko' -o -name '*.cmd' \) -print)"

# Expand DKMS's commands for a non-running kernel, including the clean path.
kernelver=installation-test-kernel
source "$dest/dkms.conf"
test "$PACKAGE_VERSION" = "$version"
test "$AUTOINSTALL" = yes
[[ "$CLEAN" == *"/lib/modules/$kernelver/build"* ]]
[[ "${MAKE[0]}" == *"/lib/modules/$kernelver/build"* ]]

for hook in postinstall preremove postremove; do
    sed -e "s|@SNAKEDRV_VERSION@|$version|g" \
        -e "s|@SNAKEDRV_ABI_VERSION@|$abi|g" \
        "$root/packaging/nfpm/$hook.sh" > "$tmp/$hook.sh"
    sh -n "$tmp/$hook.sh"
    if grep -Eq '@SNAKEDRV_[A-Z_]+@' "$tmp/$hook.sh"; then
        echo "Unresolved metadata in $hook" >&2
        exit 1
    fi
done

# Upgrade hooks from the old package must leave the replacement untouched.
# Abort if any removal command is reached; nothing here needs root.
mkdir "$tmp/bin"
for command in rm rmmod dkms ldconfig lsmod; do
    printf '#!/bin/sh\necho "Unexpected removal during upgrade" >> "$SNAKEDRV_REMOVAL_LOG"\nexit 99\n' \
        > "$tmp/bin/$command"
    chmod +x "$tmp/bin/$command"
done
for hook in preremove postremove; do
    SNAKEDRV_REMOVAL_LOG="$tmp/removal.log" PATH="$tmp/bin:$PATH" sh "$tmp/$hook.sh" upgrade
    SNAKEDRV_REMOVAL_LOG="$tmp/removal.log" PATH="$tmp/bin:$PATH" sh "$tmp/$hook.sh" 1
done
test ! -e "$tmp/removal.log"

# Exercise the install commands without changing the host's DKMS state.
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$SNAKEDRV_DKMS_LOG"\n' > "$tmp/bin/dkms"
SNAKEDRV_DKMS_LOG="$tmp/dkms.log" PATH="$tmp/bin:$PATH" \
    bash "$dest/install-kernels.sh" "$version"
grep -Fq -- "install -m snakedrv -v $version -k $(uname -r) --force" "$tmp/dkms.log"
for build in /lib/modules/*/build; do
    [[ -f "$build/Makefile" ]] || continue
    kernel="${build%/build}"
    grep -Fq -- "-k ${kernel##*/} --force" "$tmp/dkms.log"
done

if [[ -n "${KDIR:-}" ]]; then
    # This tree has only the files shipped to DKMS, so relative includes and
    # stale local objects cannot hide a broken package/install source layout.
    make -C "$dest/kernel" -j"${JOBS:-2}" KDIR="$KDIR" CC=gcc
    test "$(modinfo -F version "$dest/kernel/snakedrv.ko")" = "$version"
fi
printf 'Installation payload OK: version %s, ABI %s\n' "$version" "$abi"
