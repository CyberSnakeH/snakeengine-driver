#!/bin/bash
#
# SnakeEngine Module Signing for Secure Boot
# Automatically signs the kernel module with MOK (Machine Owner Key)
#
# Supports both Fedora and Debian/Ubuntu kernel layouts.
#

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="${SCRIPT_DIR}/kernel/snakedrv.ko"
KEY_DIR="${HOME}/.mok"
PRIV_KEY="${KEY_DIR}/MOK.priv"
PUB_KEY="${KEY_DIR}/MOK.der"
KERNEL_VERSION="$(uname -r)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

die() {
    log_error "$1"
    exit 1
}

echo -e "${CYAN}"
echo "================================================================"
echo "   SnakeEngine Module Signing Tool v2.0"
echo "   Secure Boot Compatible (Fedora + Debian/Ubuntu)"
echo "================================================================"
echo -e "${NC}"

# Check if module exists
if [ ! -f "${MODULE_PATH}" ]; then
    die "Module not found: ${MODULE_PATH} -- please build the module first: cd kernel && make"
fi

# Detect sign-file across distros (Fedora vs Debian/Ubuntu)
if [ -f "/usr/src/kernels/${KERNEL_VERSION}/scripts/sign-file" ]; then
    SIGN_FILE="/usr/src/kernels/${KERNEL_VERSION}/scripts/sign-file"
elif [ -f "/usr/src/linux-headers-${KERNEL_VERSION}/scripts/sign-file" ]; then
    SIGN_FILE="/usr/src/linux-headers-${KERNEL_VERSION}/scripts/sign-file"
else
    die "sign-file not found for kernel ${KERNEL_VERSION}. Install kernel-devel (Fedora) or linux-headers (Debian/Ubuntu)."
fi

log_info "Using sign-file: ${SIGN_FILE}"

# Check Secure Boot status
if command -v mokutil &> /dev/null; then
    SB_STATUS=$(mokutil --sb-state 2>/dev/null || echo "Unknown")
    log_info "Secure Boot Status: ${SB_STATUS}"
else
    log_warning "mokutil not found, cannot check Secure Boot status"
fi

# Create key directory with restricted permissions
mkdir -p "${KEY_DIR}"
chmod 700 "${KEY_DIR}"

# Check if keys exist
if [ ! -f "${PRIV_KEY}" ] || [ ! -f "${PUB_KEY}" ]; then
    log_step "Generating new signing keys (RSA-4096, AES-256 encrypted)..."
    log_info "This creates a private/public key pair for signing your modules"
    log_info "You will be prompted for a passphrase to protect the private key."
    echo ""

    # Generate keys with RSA-4096 and AES-256 encryption on the private key
    if ! openssl req -new -x509 -newkey rsa:4096 \
        -keyout "${PRIV_KEY}" \
        -outform DER \
        -out "${PUB_KEY}" \
        -days 36500 \
        -subj "/CN=SnakeEngine Module Signing/" \
        -aes256; then
        die "Failed to generate keys"
    fi

    # Restrict private key permissions
    chmod 600 "${PRIV_KEY}"

    log_success "Keys generated:"
    log_info "  Private: ${PRIV_KEY} (encrypted, mode 600)"
    log_info "  Public:  ${PUB_KEY}"
    echo ""

    # Check if MOK is already enrolled
    if command -v mokutil &> /dev/null; then
        if mokutil --list-enrolled 2>/dev/null | grep -q "SnakeEngine"; then
            log_success "MOK already enrolled!"
        else
            log_step "Enrolling public key with MOK..."
            log_warning "You will need to create a password and remember it!"
            echo ""

            echo -e "${YELLOW}================================================================${NC}"
            echo -e "${YELLOW}                IMPORTANT INSTRUCTIONS                          ${NC}"
            echo -e "${YELLOW}================================================================${NC}"
            echo -e "${YELLOW} 1. Create a MOK password (8-16 characters)                    ${NC}"
            echo -e "${YELLOW} 2. After reboot, MOK Manager will appear (BLUE screen)        ${NC}"
            echo -e "${YELLOW} 3. Select: Enroll MOK -> Continue -> Yes                      ${NC}"
            echo -e "${YELLOW} 4. Enter the password you create now                          ${NC}"
            echo -e "${YELLOW} 5. Select: Reboot                                             ${NC}"
            echo -e "${YELLOW} 6. Run this script again to sign the module                   ${NC}"
            echo -e "${YELLOW}================================================================${NC}"
            echo ""
            read -p "Press Enter to continue with MOK enrollment..."

            if ! sudo mokutil --import "${PUB_KEY}"; then
                die "Failed to enroll key"
            fi

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
        fi
    fi
else
    log_success "Using existing keys"
    log_info "  Private: ${PRIV_KEY}"
    log_info "  Public:  ${PUB_KEY}"
    echo ""
fi

# Sign the module
log_step "Signing kernel module: ${MODULE_PATH}"
echo ""

if ! "${SIGN_FILE}" sha256 "${PRIV_KEY}" "${PUB_KEY}" "${MODULE_PATH}"; then
    die "Failed to sign module"
fi

log_success "Module signed successfully!"
echo ""

# Verify signature
log_info "Verifying signature..."
if modinfo "${MODULE_PATH}" 2>/dev/null | grep -q "sig_id"; then
    log_success "Signature verified:"
    modinfo "${MODULE_PATH}" | grep -E "sig_id|signer|sig_key|sig_hashalgo" | sed 's/^/  /' || true
else
    log_warning "Could not verify signature (modinfo may not show it)"
fi
echo ""

log_success "Module is ready to be loaded!"
log_info "Load with: sudo insmod ${MODULE_PATH}"
log_info "Or use:    sudo ./deploy.sh load"
echo ""
