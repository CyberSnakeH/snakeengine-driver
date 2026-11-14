#!/bin/sh
#
# Pre-remove hook for snakeengine-driver. Runs BEFORE files are deleted
# so we can cleanly unload the module and tell DKMS to forget about it.

set -eu

VERSION='@SNAKEDRV_VERSION@'

# Debian passes "upgrade"; RPM passes the number of remaining packages.
# An old package's removal hooks must not unload a newly installed driver.
case "${1:-}" in
    upgrade|failed-upgrade|[1-9]*) exit 0 ;;
esac

# Unload the module if it's currently loaded.
if lsmod 2>/dev/null | grep -q '^snakedrv'; then
    rmmod snakedrv 2>/dev/null || true
fi

# Tell DKMS to remove every kernel-version build of this module.
if command -v dkms >/dev/null 2>&1; then
    dkms remove -m snakedrv -v "$VERSION" --all 2>/dev/null || true
fi

exit 0
