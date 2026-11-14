#!/bin/sh
#
# Post-install hook for snakeengine-driver native packages (.deb / .rpm).
#
# Responsibilities:
#   1. Refresh udev rules so /dev/snakedrv gets the right group ownership.
#   2. Reload the dynamic linker cache for libsnakedrv.so.
#   3. Compile for the running kernel and installed kernels with headers;
#      DKMS handles subsequent kernel upgrades automatically.
#      RPM runs this hook at %posttrans, after the old package's removal.
#
# This script must remain POSIX-sh compatible: dpkg uses /bin/sh and rpm
# uses /bin/sh — assume neither is bash.

set -eu

VERSION='@SNAKEDRV_VERSION@'
ABI_VERSION='@SNAKEDRV_ABI_VERSION@'
MODULE_NAME='snakedrv'

verify_loaded_driver() {
    if [ ! -d "/sys/module/${MODULE_NAME}" ]; then
        echo "snakeengine-driver: ${MODULE_NAME} is not loaded after install." >&2
        exit 1
    fi

    loaded_version="$(cat "/sys/module/${MODULE_NAME}/version")"
    if [ "${loaded_version}" != "${VERSION}" ]; then
        echo "snakeengine-driver: loaded version is ${loaded_version}, expected ${VERSION}." >&2
        exit 1
    fi

    if [ ! -r "/sys/module/${MODULE_NAME}/parameters/abi_version" ]; then
        echo "snakeengine-driver: ${MODULE_NAME} does not expose abi_version." >&2
        exit 1
    fi

    loaded_abi="$(tr -d '[:space:]' < "/sys/module/${MODULE_NAME}/parameters/abi_version")"
    if [ "${loaded_abi}" != "${ABI_VERSION}" ]; then
        echo "snakeengine-driver: loaded ABI is ${loaded_abi}, expected ${ABI_VERSION}." >&2
        exit 1
    fi

    if command -v udevadm >/dev/null 2>&1; then
        i=0
        while [ "${i}" -lt 5 ] && [ ! -c "/dev/${MODULE_NAME}" ]; do
            udevadm trigger --subsystem-match="${MODULE_NAME}" --action=add 2>/dev/null || true
            udevadm settle --timeout=5 2>/dev/null || true
            i=$((i + 1))
            sleep 1
        done
    fi

    if [ ! -c "/dev/${MODULE_NAME}" ]; then
        echo "snakeengine-driver: /dev/${MODULE_NAME} was not created." >&2
        echo "                   Check devtmpfs/udev and /sys/class/${MODULE_NAME}/${MODULE_NAME}/dev." >&2
        exit 1
    fi
}

# 0) Access group used by the udev rule.
if command -v getent >/dev/null 2>&1 && command -v groupadd >/dev/null 2>&1; then
    if ! getent group snakeengine >/dev/null 2>&1; then
        groupadd --system snakeengine || {
            echo "snakeengine-driver: failed to create snakeengine system group." >&2
            exit 1
        }
    fi
fi

# 1) udev: re-trigger to apply 99-snakedrv.rules right away.
if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules || true
    udevadm trigger || true
fi

# 2) dynamic linker cache.
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi

# 3) DKMS: register + build for prepared kernels. Skip if
#    DKMS isn't installed — the user can still build manually.
if command -v dkms >/dev/null 2>&1; then
    if ! dkms status -m snakedrv -v "$VERSION" 2>/dev/null \
            | grep -q snakedrv; then
        dkms add -m snakedrv -v "$VERSION" || {
            echo "snakeengine-driver: dkms add failed for version $VERSION." >&2
            exit 1
        }
    fi
    # Install this exact release; AUTOINSTALL=yes covers future kernels.
    bash "/usr/src/snakedrv-$VERSION/install-kernels.sh" "$VERSION" || {
        echo "snakeengine-driver: dkms install failed for kernel $(uname -r)." >&2
        exit 1
    }
else
    echo "snakeengine-driver: DKMS not installed; skipping kernel module build." >&2
    echo "                   Install dkms and re-run: sudo dkms autoinstall -m snakedrv -v $VERSION" >&2
fi

# 4) Load the freshly-built module right away. Do not mask failures here:
#    Secure Boot lockdown, missing headers, or kernel/module mismatches must be
#    visible to the package manager instead of leaving userland installed with
#    no matching driver loaded.
if command -v modprobe >/dev/null 2>&1; then
    if [ -d /sys/module/snakedrv ]; then
        rmmod snakedrv || {
            echo "snakeengine-driver: close driver clients so the module can be reloaded." >&2
            exit 1
        }
    fi
    modprobe snakedrv || {
        echo "snakeengine-driver: modprobe snakedrv failed for kernel $(uname -r)." >&2
        echo "                   Check Secure Boot/module signing and DKMS build logs." >&2
        exit 1
    }

    if [ ! -d /sys/module/snakedrv ]; then
        echo "snakeengine-driver: modprobe returned success but snakedrv is not loaded." >&2
        exit 1
    fi
else
    echo "snakeengine-driver: modprobe not found; cannot load snakedrv." >&2
    exit 1
fi

verify_loaded_driver

exit 0
