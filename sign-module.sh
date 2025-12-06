#!/bin/bash
#
# SnakeEngine Module Signing for Secure Boot
# Automatically signs the kernel module with MOK (Machine Owner Key)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="${SCRIPT_DIR}/kernel/snakedrv.ko"
KEY_DIR="${HOME}/.mok"
PRIV_KEY="${KEY_DIR}/MOK.priv"
PUB_KEY="${KEY_DIR}/MOK.der"
KERNEL_VERSION="$(uname -r)"
SIGN_FILE="/usr/src/kernels/${KERNEL_VERSION}/scripts/sign-file"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║   SnakeEngine Module Signing Tool v1.0           ║"
echo "║   Secure Boot Compatible                         ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if module exists
if [ ! -f "$MODULE_PATH" ]; then
    log_error "Module not found: $MODULE_PATH"
    log_info "Please build the module first: cd kernel && make"
    exit 1
fi

# Check if sign-file exists
if [ ! -f "$SIGN_FILE" ]; then
    log_error "Kernel sign-file not found: $SIGN_FILE"
    log_info "Install kernel-devel: sudo dnf install kernel-devel-${KERNEL_VERSION}"
    exit 1
fi

# Check Secure Boot status
if command -v mokutil &> /dev/null; then
    SB_STATUS=$(mokutil --sb-state 2>/dev/null || echo "Unknown")
    log_info "Secure Boot Status: $SB_STATUS"
else
    log_warning "mokutil not found, cannot check Secure Boot status"
fi

# Create key directory
mkdir -p "$KEY_DIR"

# Check if keys exist
if [ ! -f "$PRIV_KEY" ] || [ ! -f "$PUB_KEY" ]; then
    log_step "Generating new signing keys..."
    log_info "This creates a private/public key pair for signing your modules"
    echo ""

    # Generate keys
    openssl req -new -x509 -newkey rsa:2048 \
        -keyout "$PRIV_KEY" \
        -outform DER \
        -out "$PUB_KEY" \
        -days 36500 \
        -subj "/CN=SnakeEngine Module Signing/" \
        -nodes

    if [ $? -ne 0 ]; then
        log_error "Failed to generate keys"
        exit 1
    fi

    log_success "Keys generated:"
    log_info "  Private: $PRIV_KEY"
    log_info "  Public:  $PUB_KEY"
    echo ""

    # Check if MOK is already enrolled
    if command -v mokutil &> /dev/null; then
        if mokutil --list-enrolled 2>/dev/null | grep -q "SnakeEngine"; then
            log_success "MOK already enrolled!"
        else
            log_step "Enrolling public key with MOK..."
            log_warning "You will need to create a password and remember it!"
            echo ""

            echo -e "${YELLOW}╔════════════════════════════════════════════════════╗${NC}"
            echo -e "${YELLOW}║                IMPORTANT INSTRUCTIONS              ║${NC}"
            echo -e "${YELLOW}╠════════════════════════════════════════════════════╣${NC}"
            echo -e "${YELLOW}║ 1. Create a MOK password (8-16 characters)        ║${NC}"
            echo -e "${YELLOW}║ 2. After reboot, MOK Manager will appear (BLUE)   ║${NC}"
            echo -e "${YELLOW}║ 3. Select: Enroll MOK → Continue → Yes            ║${NC}"
            echo -e "${YELLOW}║ 4. Enter the password you create now              ║${NC}"
            echo -e "${YELLOW}║ 5. Select: Reboot                                 ║${NC}"
            echo -e "${YELLOW}║ 6. Run this script again to sign the module       ║${NC}"
            echo -e "${YELLOW}╚════════════════════════════════════════════════════╝${NC}"
            echo ""
            read -p "Press Enter to continue with MOK enrollment..."

            sudo mokutil --import "$PUB_KEY"

            if [ $? -eq 0 ]; then
                log_success "Key enrollment initiated!"
                echo ""
                log_warning "YOU MUST REBOOT NOW!"
                log_info "After reboot, run: $0"
                echo ""
                read -p "Reboot now? (y/N) " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    sudo reboot
                fi
                exit 0
            else
                log_error "Failed to enroll key"
                exit 1
            fi
        fi
    fi
else
    log_success "Using existing keys"
    log_info "  Private: $PRIV_KEY"
    log_info "  Public:  $PUB_KEY"
    echo ""
fi

# Sign the module
log_step "Signing kernel module: $MODULE_PATH"
echo ""

"$SIGN_FILE" sha256 "$PRIV_KEY" "$PUB_KEY" "$MODULE_PATH"

if [ $? -eq 0 ]; then
    log_success "Module signed successfully!"
    echo ""

    # Verify signature
    log_info "Verifying signature..."
    if modinfo "$MODULE_PATH" | grep -q "sig_id"; then
        log_success "Signature verified:"
        modinfo "$MODULE_PATH" | grep -E "sig_id|signer|sig_key|sig_hashalgo" | sed 's/^/  /'
    else
        log_warning "Could not verify signature (modinfo may not show it)"
    fi
    echo ""

    log_success "✓ Module is ready to be loaded!"
    log_info "Load with: sudo insmod $MODULE_PATH"
    log_info "Or use:    sudo ./deploy.sh load"
    echo ""
else
    log_error "Failed to sign module"
    exit 1
fi
