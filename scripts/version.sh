#!/usr/bin/env bash
# Read release metadata from the public header used by the module and library.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
header="$root/userland/include/snakedrv.h"
read_define() {
    awk -v key="$1" '$1 == "#define" && $2 == key {gsub(/"/, "", $3); print $3}' "$header"
}

major="$(read_define SNAKEDRV_VERSION_MAJOR)"
minor="$(read_define SNAKEDRV_VERSION_MINOR)"
patch="$(read_define SNAKEDRV_VERSION_PATCH)"
version="$major.$minor.$patch"
abi="$(read_define SNAKEDRV_ABI_VERSION)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || ! "$abi" =~ ^[0-9]+$ ]] ||
   [[ "$(read_define SNAKEDRV_VERSION_STRING)" != "$version" ]]; then
    echo "Invalid or inconsistent version metadata in $header" >&2
    exit 1
fi

case "${1:-}" in
    '') printf '%s\n' "$version" ;;
    --abi) printf '%s\n' "$abi" ;;
    --check-tag)
        [[ "${2:-}" = "v$version" ]] || {
            echo "Release tag '${2:-}' must match header version v$version" >&2
            exit 1
        }
        printf '%s\n' "$version"
        ;;
    *) echo "Usage: $0 [--abi | --check-tag vX.Y.Z]" >&2; exit 2 ;;
esac
