#!/usr/bin/env bash
#
# Interactive setup for snakeengine-driver.
#
# This script wraps deploy.sh with a TTY-friendly wizard that walks
# first-time users through: install prefix, DKMS opt-in, group
# membership, and udev/AppArmor/SELinux setup. It performs no
# non-interactive work — for CI / scripted installs use deploy.sh
# directly.
#
# Run as the *unprivileged* user; the script re-invokes deploy.sh via
# sudo only for the steps that need root.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY="${SCRIPT_DIR}/deploy.sh"

# ─── Colours ───────────────────────────────────────────────────────
if [ -t 1 ] && [ "${NO_COLOR:-}" != "1" ]; then
    BOLD=$'\033[1m'  DIM=$'\033[2m'
    RED=$'\033[31m'  GRN=$'\033[32m'  YEL=$'\033[33m'
    CYA=$'\033[36m'  RST=$'\033[0m'
else
    BOLD=''  DIM=''  RED=''  GRN=''  YEL=''  CYA=''  RST=''
fi

# ─── Prompt helpers ────────────────────────────────────────────────
hr() { printf "${DIM}%s${RST}\n" "──────────────────────────────────────────────────────────────"; }

ask() {
    # ask "Question" "default-value"
    local prompt="$1" default="${2:-}" reply
    if [ -n "$default" ]; then
        read -r -p "$(printf '%s [%s%s%s]: ' "$prompt" "$BOLD" "$default" "$RST")" reply
        printf '%s' "${reply:-$default}"
    else
        read -r -p "$prompt: " reply
        printf '%s' "$reply"
    fi
}

yesno() {
    # yesno "Question" "default(yes|no)"  → exit 0 for yes, 1 for no
    local prompt="$1" default="${2:-yes}" reply
    local hint='[Y/n]'
    [ "$default" = "no" ] && hint='[y/N]'
    while true; do
        read -r -p "$(printf '%s %s ' "$prompt" "$hint")" reply
        reply="${reply:-$default}"
        case "$reply" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo])     return 1 ;;
            *) printf '  %splease answer yes or no%s\n' "$YEL" "$RST" ;;
        esac
    done
}

choose() {
    # choose "Prompt" choice1 choice2 …  → prints the chosen string
    local prompt="$1"; shift
    local opts=( "$@" ) i n="$#"
    {
        echo
        printf '  %s%s%s\n' "$BOLD" "$prompt" "$RST"
        for ((i=0; i<n; i++)); do
            printf '    %s%d)%s %s\n' "$CYA" "$((i+1))" "$RST" "${opts[$i]}"
        done
    } >&2
    while true; do
        local pick
        read -r -p "  Choice [1-$n]: " pick >&2
        if [[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= n )); then
            printf '%s' "${opts[$((pick-1))]}"
            return 0
        fi
        printf '  %sinvalid choice%s\n' "$YEL" "$RST" >&2
    done
}

require_user() {
    if [ "$(id -u)" = 0 ]; then
        printf '%sDo not run setup.sh as root.%s It re-invokes deploy.sh via sudo only when needed.\n' "$RED" "$RST" >&2
        exit 1
    fi
}

require_deploy() {
    [ -x "$DEPLOY" ] || {
        printf '%sCannot find deploy.sh at %s%s\n' "$RED" "$DEPLOY" "$RST" >&2
        exit 1
    }
}

# ─── Banner ────────────────────────────────────────────────────────
banner() {
    cat <<EOF
${BOLD}${GRN}
 ╔═══════════════════════════════════════════════════════════╗
 ║          SnakeEngine Driver — Interactive Setup           ║
 ╚═══════════════════════════════════════════════════════════╝${RST}

${DIM}Source: ${SCRIPT_DIR}${RST}
EOF
}

# ─── Distro detection ──────────────────────────────────────────────
detect_distro() {
    local id pretty
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-unknown}"
        pretty="${PRETTY_NAME:-$id}"
    else
        id="unknown"
        pretty="unknown distro"
    fi
    printf '%s\n' "$id|$pretty"
}

# ─── Main wizard ───────────────────────────────────────────────────
main() {
    require_user
    require_deploy
    banner

    IFS='|' read -r distro_id distro_pretty < <(detect_distro)
    printf '  Distro:  %s%s%s\n' "$BOLD" "$distro_pretty" "$RST"
    printf '  Kernel:  %s%s%s\n' "$BOLD" "$(uname -r)" "$RST"
    printf '  User:    %s%s%s\n\n' "$BOLD" "$USER" "$RST"

    # ── Install location ──────────────────────────────────────────
    hr
    printf '\n  %sStep 1 — Install location%s\n\n' "$BOLD" "$RST"

    local choice prefix
    choice="$(choose "Where should libsnakedrv and tools go?" \
        "System-wide  (/usr/local/lib, /usr/local/include)" \
        "Distro-native (/usr/lib*, /usr/include)" \
        "Custom prefix")"

    case "$choice" in
        System-wide*)    prefix="/usr/local" ;;
        Distro-native*)  prefix="/usr" ;;
        Custom*)
            prefix="$(ask "Custom prefix" "$HOME/.local")"
            ;;
    esac
    printf '\n  %s→ install prefix: %s%s%s\n\n' "$DIM" "$BOLD" "$prefix" "$RST"

    # ── DKMS toggle ───────────────────────────────────────────────
    hr
    printf '\n  %sStep 2 — DKMS%s\n\n' "$BOLD" "$RST"
    printf '  DKMS rebuilds the kernel module automatically when you upgrade\n'
    printf '  your kernel. Recommended.\n\n'

    local use_dkms="--no-dkms"
    if command -v dkms >/dev/null 2>&1; then
        if yesno "Register module with DKMS?" yes; then
            use_dkms=""
        fi
    else
        printf '  %sDKMS is not installed on this system — falling back to direct install.%s\n' "$YEL" "$RST"
        printf '  %s(Install the dkms package later if you want auto-rebuild on kernel updates.)%s\n\n' "$DIM" "$RST"
    fi

    # ── Group membership ──────────────────────────────────────────
    hr
    printf '\n  %sStep 3 — Group membership%s\n\n' "$BOLD" "$RST"
    printf '  /dev/snakedrv is owned by group ${BOLD}snakeengine${RST}. Adding\n'
    printf '  your user to that group lets you use SnakeEngine without sudo.\n\n'

    local join_group="no"
    if yesno "Add user '$USER' to the snakeengine group?" yes; then
        join_group="yes"
    fi

    # ── Confirmation ──────────────────────────────────────────────
    hr
    printf '\n  %sSummary%s\n\n' "$BOLD" "$RST"
    printf '    Prefix       : %s%s%s\n' "$BOLD" "$prefix" "$RST"
    printf '    DKMS         : %s%s%s\n' "$BOLD" \
        "$([ -z "$use_dkms" ] && echo "yes" || echo "no")" "$RST"
    printf '    Add to group : %s%s%s\n' "$BOLD" "$join_group" "$RST"
    printf '    Distro       : %s%s%s\n\n' "$BOLD" "$distro_pretty" "$RST"

    if ! yesno "Proceed with installation?" yes; then
        printf '\n%sAborted.%s\n' "$YEL" "$RST"
        exit 0
    fi

    # ── Build ─────────────────────────────────────────────────────
    hr
    printf '\n  %sStep 4 — Build%s\n\n' "$BOLD" "$RST"
    "$DEPLOY" build || {
        printf '\n%sBuild failed. Read the output above and rerun setup.sh once fixed.%s\n' "$RED" "$RST"
        exit 1
    }

    # ── Install (root) ────────────────────────────────────────────
    hr
    printf '\n  %sStep 5 — Install (sudo will prompt)%s\n\n' "$BOLD" "$RST"

    local -a deploy_args=( install --prefix="$prefix" )
    [ -n "$use_dkms" ] && deploy_args+=( "$use_dkms" )

    sudo -k    # force a fresh prompt so user sees what they're auth'ing for
    sudo "$DEPLOY" "${deploy_args[@]}" || {
        printf '\n%sInstall failed. See the messages above.%s\n' "$RED" "$RST"
        exit 1
    }

    # ── Group membership (root) ───────────────────────────────────
    if [ "$join_group" = "yes" ]; then
        if getent group snakeengine >/dev/null 2>&1; then
            sudo usermod -aG snakeengine "$USER" && \
                printf '\n  %s✓ added %s to the snakeengine group%s\n' "$GRN" "$USER" "$RST"
        else
            printf '\n  %sgroup snakeengine does not exist yet — skipping%s\n' "$YEL" "$RST"
        fi
    fi

    # ── Load module ───────────────────────────────────────────────
    hr
    printf '\n  %sStep 6 — Load the module%s\n\n' "$BOLD" "$RST"
    if yesno "Load snakedrv now?" yes; then
        sudo "$DEPLOY" load || \
            printf '%smodprobe snakedrv failed — load it manually after rebooting if needed%s\n' "$YEL" "$RST"
    fi

    # ── Done ──────────────────────────────────────────────────────
    hr
    cat <<EOF

${BOLD}${GRN}  ✓ snakeengine-driver installed successfully${RST}

  Next steps:
    • Log out and back in if you joined the snakeengine group
      (group membership doesn't apply to existing sessions).
    • Install SnakeEngine (the UI):
        ${CYA}https://github.com/CyberSnakeH/SnakeEngine/releases${RST}
    • Pair-update the driver later from inside the UI, or via:
        ${DIM}sudo /usr/lib/snakeengine/snakedrv-updater <version>${RST}

EOF
}

main "$@"
