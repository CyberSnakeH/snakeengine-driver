#!/bin/sh
#
# Post-remove hook for snakeengine-driver. Cleans up any DKMS staging
# directory that may have lingered after `dkms remove`.

set -eu

VERSION='@SNAKEDRV_VERSION@'

# On upgrades/reinstalls, this source tree may already belong to the new
# package. Only delete it on final removal.
case "${1:-}" in
    upgrade|failed-upgrade|[1-9]*) exit 0 ;;
esac

rm -rf "/usr/src/snakedrv-${VERSION}"

if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi

exit 0
