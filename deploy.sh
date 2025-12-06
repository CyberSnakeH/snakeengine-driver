#!/bin/bash
#
# SnakeEngine Driver - Professional Deployment Script
#
# This script handles:
# - Dependency checking and installation
# - Kernel module compilation and installation
# - DKMS configuration
# - Userland library compilation
# - Security configuration (SELinux/AppArmor)
# - udev rules setup
# - System service configuration
#
# Usage:
#   ./deploy.sh [command] [options]
#
# Commands:
#   build       - Build everything
#   install     - Install everything
#   uninstall   - Remove everything
#   load        - Load kernel module
#   unload      - Unload kernel module
#   status      - Show status
#   clean       - Clean build artifacts
#
# Options:
#   --debug     - Build with debug symbols
#   --no-dkms   - Skip DKMS installation
#   --no-selinux - Skip SELinux configuration
#   --force     - Force installation even if checks fail
#   --prefix=PATH - Installation prefix (default: /usr/local)
#   --help      - Show this help
#

set -e

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="snakeengine"
MODULE_NAME="snakedrv"
VERSION="1.0.0"

# Installation paths
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
LIBDIR="${PREFIX}/lib"
INCLUDEDIR="${PREFIX}/include"
SYSCONFDIR="/etc"
MODULEDIR="/lib/modules/$(uname -r)"
DKMS_SRC="/usr/src/${MODULE_NAME}-${VERSION}"

# Build options
DEBUG=${DEBUG:-0}
USE_DKMS=${USE_DKMS:-1}
USE_SELINUX=${USE_SELINUX:-1}
USE_APPARMOR=${USE_APPARMOR:-1}
FORCE=${FORCE:-0}
JOBS=${JOBS:-$(nproc)}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Utility Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

die() {
    log_error "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

# ============================================================================
# Dependency Management
# ============================================================================

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
    log_info "Detected distribution: $DISTRO"
}

install_dependencies_debian() {
    log_info "Installing dependencies for Debian/Ubuntu..."
    apt-get update
    apt-get install -y \
        build-essential \
        linux-headers-$(uname -r) \
        dkms \
        pkg-config \
        libelf-dev \
        clang \
        llvm \
        cmake \
        git \
        libsdl2-dev \
        libglew-dev
}

install_dependencies_fedora() {
    log_info "Installing dependencies for Fedora/RHEL..."
    dnf install -y \
        kernel-devel-$(uname -r) \
        kernel-headers-$(uname -r) \
        dkms \
        gcc \
        gcc-c++ \
        make \
        clang \
        llvm \
        cmake \
        elfutils-libelf-devel \
        SDL2-devel \
        glew-devel \
        selinux-policy-devel \
        ncurses-devel
}

install_dependencies_arch() {
    log_info "Installing dependencies for Arch Linux..."
    pacman -Sy --noconfirm \
        linux-headers \
        dkms \
        base-devel \
        clang \
        llvm \
        cmake \
        sdl2 \
        glew
}

install_dependencies() {
    detect_distro
    
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            install_dependencies_debian
            ;;
        fedora|rhel|centos|rocky|almalinux)
            install_dependencies_fedora
            ;;
        arch|manjaro|endeavouros)
            install_dependencies_arch
            ;;
        *)
            log_warning "Unknown distribution: $DISTRO"
            log_warning "Please install dependencies manually:"
            log_warning "  - kernel headers"
            log_warning "  - build-essential/gcc/make"
            log_warning "  - dkms"
            log_warning "  - clang/llvm"
            log_warning "  - libelf-dev"
            ;;
    esac
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    # Check kernel headers
    if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
        missing+=("kernel-headers")
    fi
    
    # Check build tools
    check_command gcc || missing+=("gcc")
    check_command make || missing+=("make")
    check_command clang || missing+=("clang")
    
    # Check DKMS if needed
    if [ "$USE_DKMS" -eq 1 ]; then
        check_command dkms || missing+=("dkms")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        return 1
    fi
    
    log_success "All dependencies satisfied"
    return 0
}

# ============================================================================
# Build Functions
# ============================================================================

build_kernel_module() {
    log_info "Building kernel module..."

    cd "${SCRIPT_DIR}/kernel"

    if [ "$DEBUG" -eq 1 ]; then
        make -j${JOBS} DEBUG=1 clean modules
    else
        make -j${JOBS} clean modules
    fi

    if [ -f "${MODULE_NAME}.ko" ]; then
        log_success "Kernel module built successfully"
    else
        die "Failed to build kernel module"
    fi
}

build_userland() {
    log_info "Building userland library..."

    mkdir -p "${SCRIPT_DIR}/build"
    cd "${SCRIPT_DIR}/build"

    # Build with CMake or manual compilation
    if check_command cmake && [ -f "${SCRIPT_DIR}/CMakeLists.txt" ]; then
        cmake .. -DCMAKE_BUILD_TYPE=$([ "$DEBUG" -eq 1 ] && echo "Debug" || echo "Release")
        make -j${JOBS}
    else
        # Manual compilation
        CXX="${CXX:-clang++}"
        CXXFLAGS="-std=c++20 -Wall -Wextra -I${SCRIPT_DIR}/userland/include"
        
        if [ "$DEBUG" -eq 1 ]; then
            CXXFLAGS+=" -g -O0 -DDEBUG"
        else
            CXXFLAGS+=" -O2 -DNDEBUG"
        fi
        
        $CXX $CXXFLAGS -fPIC -c "${SCRIPT_DIR}/userland/src/libsnakedrv.cpp" -o libsnakedrv.o
        $CXX -shared -o libsnakedrv.so libsnakedrv.o
        ar rcs libsnakedrv.a libsnakedrv.o

        log_success "Userland library built successfully"
    fi
}

build_all() {
    log_info "=== Building SnakeEngine Driver v${VERSION} ==="
    
    build_kernel_module
    build_userland
    
    log_success "=== Build completed successfully ==="
}

# ============================================================================
# Installation Functions
# ============================================================================

install_kernel_module() {
    log_info "Installing kernel module..."
    
    if [ "$USE_DKMS" -eq 1 ] && check_command dkms; then
        install_dkms
    else
        install_module_direct
    fi
}

install_module_direct() {
    log_info "Installing module directly..."
    
    # Create directory
    mkdir -p "${MODULEDIR}/extra"
    
    # Copy module
    cp "${SCRIPT_DIR}/kernel/${MODULE_NAME}.ko" "${MODULEDIR}/extra/"
    
    # Update module dependencies
    depmod -a
    
    log_success "Module installed to ${MODULEDIR}/extra/"
}

install_dkms() {
    log_info "Installing with DKMS..."
    
    # Remove old version if exists
    if dkms status | grep -q "${MODULE_NAME}"; then
        log_info "Removing old DKMS installation..."
        dkms remove -m "${MODULE_NAME}" -v "${VERSION}" --all 2>/dev/null || true
    fi
    
    # Copy source to DKMS directory
    rm -rf "${DKMS_SRC}"
    mkdir -p "${DKMS_SRC}"
    cp -r "${SCRIPT_DIR}/kernel" "${DKMS_SRC}/"
    cp -r "${SCRIPT_DIR}/userland" "${DKMS_SRC}/"
    cp "${SCRIPT_DIR}/dkms/dkms.conf" "${DKMS_SRC}/"
    
    # Add to DKMS
    dkms add -m "${MODULE_NAME}" -v "${VERSION}"
    
    # Build for current kernel
    dkms build -m "${MODULE_NAME}" -v "${VERSION}"
    
    # Install
    dkms install -m "${MODULE_NAME}" -v "${VERSION}"
    
    log_success "DKMS installation completed"
}

install_userland() {
    log_info "Installing userland library..."
    
    # Create directories
    mkdir -p "${LIBDIR}/${PROJECT_NAME}"
    mkdir -p "${INCLUDEDIR}/${PROJECT_NAME}"
    
    # Install headers
    cp "${SCRIPT_DIR}/userland/include/"*.h "${INCLUDEDIR}/${PROJECT_NAME}/"
    cp "${SCRIPT_DIR}/userland/include/"*.hpp "${INCLUDEDIR}/${PROJECT_NAME}/"
    
    # Install library
    if [ -f "${SCRIPT_DIR}/build/libsnakedrv.so" ]; then
        cp "${SCRIPT_DIR}/build/libsnakedrv.so" "${LIBDIR}/"
        cp "${SCRIPT_DIR}/build/libsnakedrv.a" "${LIBDIR}/"
    fi
    
    # Update library cache
    ldconfig
    
    log_success "Userland library installed"
}

install_udev_rules() {
    log_info "Installing udev rules..."
    
    cp "${SCRIPT_DIR}/security/99-snakedrv.rules" /etc/udev/rules.d/
    
    # Create group if doesn't exist
    if ! getent group snakeengine > /dev/null; then
        groupadd snakeengine
        log_info "Created group 'snakeengine'"
    fi
    
    # Reload udev rules
    udevadm control --reload-rules
    udevadm trigger
    
    log_success "udev rules installed"
}

install_selinux() {
    if [ "$USE_SELINUX" -ne 1 ]; then
        log_info "Skipping SELinux configuration"
        return
    fi
    
    # Check if SELinux is available
    if ! check_command getenforce; then
        log_info "SELinux not available, skipping"
        return
    fi
    
    if [ "$(getenforce 2>/dev/null)" = "Disabled" ]; then
        log_info "SELinux is disabled, skipping"
        return
    fi
    
    log_info "Installing SELinux policy..."

    cd "${SCRIPT_DIR}/security"

    # Compile policy
    if [ -f /usr/share/selinux/devel/Makefile ]; then
        if make -f /usr/share/selinux/devel/Makefile snakeengine.pp; then
            if [ -f snakeengine.pp ]; then
                semodule -i snakeengine.pp || log_warning "semodule install failed"

                # Apply file contexts
                restorecon -Rv "${BINDIR}/${PROJECT_NAME}" 2>/dev/null || true
                restorecon -Rv "/dev/${MODULE_NAME}" 2>/dev/null || true

                log_success "SELinux policy installed"
            else
                log_warning "Failed to build SELinux policy (pp missing)"
            fi
        else
            log_warning "SELinux policy build failed (syntax error?) - skipping"
        fi
    else
        log_warning "SELinux development tools not found (selinux-policy-devel)."
        log_warning "Skipping SELinux policy installation."
    fi
}

install_apparmor() {
    if [ "$USE_APPARMOR" -ne 1 ]; then
        log_info "Skipping AppArmor configuration"
        return
    fi
    
    # Check if AppArmor is available
    if ! check_command apparmor_parser; then
        log_info "AppArmor not available, skipping"
        return
    fi
    
    if ! systemctl is-active --quiet apparmor 2>/dev/null; then
        log_info "AppArmor is not running, skipping"
        return
    fi
    
    log_info "Installing AppArmor profile..."
    
    cp "${SCRIPT_DIR}/security/snakeengine.apparmor" /etc/apparmor.d/snakeengine
    apparmor_parser -r /etc/apparmor.d/snakeengine
    
    log_success "AppArmor profile installed"
}

install_modprobe_config() {
    log_info "Installing modprobe configuration..."
    
    cat > /etc/modprobe.d/snakedrv.conf << 'EOF'
# SnakeEngine Kernel Driver Configuration
#
# max_attached_processes: Maximum number of processes that can be attached (default: 16)
# event_queue_size: Maximum pending debug events (default: 256)
# debug_level: Logging verbosity 0=off, 1=info, 2=debug, 3=trace (default: 1)

options snakedrv max_attached_processes=16 event_queue_size=256 debug_level=1
EOF
    
    log_success "modprobe configuration installed"
}

install_all() {
    check_root
    
    log_info "=== Installing SnakeEngine Driver v${VERSION} ==="
    
    # Install dependencies if needed
    if ! check_dependencies; then
        log_info "Installing dependencies..."
        install_dependencies
    fi
    
    # Build first
    build_all
    
    # Install components
    install_kernel_module
    install_userland
    install_udev_rules
    install_modprobe_config
    install_selinux
    install_apparmor
    
    log_success "=== Installation completed successfully ==="
    log_info ""
    log_info "To load the module now, run:"
    log_info "  sudo modprobe ${MODULE_NAME}"
    log_info ""
    log_info "To add yourself to the snakeengine group:"
    log_info "  sudo usermod -aG snakeengine \$USER"
    log_info ""
}

# ============================================================================
# Uninstallation
# ============================================================================

uninstall_all() {
    check_root
    
    log_info "=== Uninstalling SnakeEngine Driver ==="
    
    # Unload module if loaded
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_info "Unloading module..."
        rmmod "${MODULE_NAME}" || true
    fi
    
    # Remove DKMS
    if check_command dkms && dkms status | grep -q "${MODULE_NAME}"; then
        log_info "Removing DKMS installation..."
        dkms remove -m "${MODULE_NAME}" -v "${VERSION}" --all || true
    fi
    
    # Remove module
    rm -f "${MODULEDIR}/extra/${MODULE_NAME}.ko"
    rm -f "${MODULEDIR}/updates/${MODULE_NAME}.ko"
    
    # Remove DKMS source
    rm -rf "${DKMS_SRC}"
    
    # Remove userland
    rm -rf "${LIBDIR}/${PROJECT_NAME}"
    rm -rf "${INCLUDEDIR}/${PROJECT_NAME}"
    rm -f "${LIBDIR}/libsnakedrv.so"
    rm -f "${LIBDIR}/libsnakedrv.a"
    
    # Remove configs
    rm -f /etc/modprobe.d/snakedrv.conf
    rm -f /etc/udev/rules.d/99-snakedrv.rules
    
    # Remove SELinux policy
    semodule -r snakeengine 2>/dev/null || true
    
    # Remove AppArmor profile
    rm -f /etc/apparmor.d/snakeengine
    apparmor_parser -R /etc/apparmor.d/snakeengine 2>/dev/null || true
    
    # Update caches
    depmod -a
    ldconfig
    udevadm control --reload-rules
    
    log_success "=== Uninstallation completed ==="
}

# ============================================================================
# Module Control
# ============================================================================

load_module() {
    check_root
    
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_info "Module already loaded"
        return
    fi
    
    log_info "Loading module..."
    
    if [ -f "${SCRIPT_DIR}/kernel/${MODULE_NAME}.ko" ]; then
        insmod "${SCRIPT_DIR}/kernel/${MODULE_NAME}.ko"
    else
        modprobe "${MODULE_NAME}"
    fi
    
    # Wait for device
    sleep 1
    
    if [ -e "/dev/${MODULE_NAME}" ]; then
        log_success "Module loaded, device: /dev/${MODULE_NAME}"
    else
        log_warning "Module loaded but device not created"
    fi
}

unload_module() {
    check_root
    
    if ! lsmod | grep -q "^${MODULE_NAME}"; then
        log_info "Module not loaded"
        return
    fi
    
    log_info "Unloading module..."
    rmmod "${MODULE_NAME}"
    log_success "Module unloaded"
}

# ============================================================================
# Status
# ============================================================================

show_status() {
    echo "=== SnakeEngine Driver Status ==="
    echo ""
    
    # Module status
    echo "Kernel Module:"
    if lsmod | grep -q "^${MODULE_NAME}"; then
        echo "  Status: LOADED"
        echo "  Info:"
        lsmod | grep "^${MODULE_NAME}" | awk '{print "    Size: "$2" bytes, Used by: "$3}'
    else
        echo "  Status: NOT LOADED"
    fi
    echo ""
    
    # Device status
    echo "Device:"
    if [ -e "/dev/${MODULE_NAME}" ]; then
        echo "  Status: EXISTS"
        ls -la "/dev/${MODULE_NAME}"
    else
        echo "  Status: NOT FOUND"
    fi
    echo ""
    
    # DKMS status
    echo "DKMS:"
    if check_command dkms; then
        dkms status | grep "${MODULE_NAME}" || echo "  Not installed via DKMS"
    else
        echo "  DKMS not available"
    fi
    echo ""
    
    # Kernel log
    echo "Recent kernel messages:"
    dmesg | grep -i snakedrv | tail -10 || echo "  No messages found"
}

# ============================================================================
# Clean
# ============================================================================

clean_all() {
    log_info "Cleaning build artifacts..."

    cd "${SCRIPT_DIR}/kernel"
    make clean 2>/dev/null || true

    rm -rf "${SCRIPT_DIR}/build"
    rm -rf "${SCRIPT_DIR}/security/tmp"

    log_success "Clean completed"
}

# ============================================================================
# Deploy to VM (optional helper)
# ============================================================================

deploy_vm() {
    log_info "Deploying to VM..."
    rsync -avz --exclude '.git' --exclude 'build' -e "ssh -p 2222" . cbhserv@localhost:~/kernel_module/snakeengine-driver/
    log_success "Deployed to VM"
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    cat << EOF
SnakeEngine Driver - Deployment Script v${VERSION}

Usage: $0 [command] [options]

Commands:
  deps        Install build dependencies
  build       Build everything
  install     Install everything (requires root)
  uninstall   Remove everything (requires root)
  load        Load kernel module (requires root)
  unload      Unload kernel module (requires root)
  reload      Reload kernel module (requires root)
  status      Show status
  clean       Clean build artifacts
  vm          Deploy to VM via rsync
  help        Show this help

Options:
  --debug       Build with debug symbols
  --no-dkms     Skip DKMS installation
  --no-selinux  Skip SELinux configuration
  --no-apparmor Skip AppArmor configuration
  --force       Force installation
  --prefix=PATH Installation prefix (default: /usr/local)

Examples:
  $0 build                    # Build the driver
  sudo $0 install             # Install everything
  sudo $0 install --no-dkms   # Install without DKMS
  sudo $0 load                # Load the module
  $0 status                   # Check status
  $0 vm                       # Deploy to VM
  sudo $0 uninstall           # Remove everything

Environment variables:
  DEBUG=1       Build with debug symbols
  PREFIX=/path  Installation prefix
  CXX=clang++   C++ compiler to use

EOF
}

# ============================================================================
# Main
# ============================================================================

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            DEBUG=1
            shift
            ;;
        --no-dkms)
            USE_DKMS=0
            shift
            ;;
        --no-selinux)
            USE_SELINUX=0
            shift
            ;;
        --no-apparmor)
            USE_APPARMOR=0
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            shift
            ;;
        deps|build|install|uninstall|load|unload|reload|status|clean|vm|help)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute command
case "${COMMAND:-help}" in
    deps)
        check_root
        install_dependencies
        ;;
    build)
        build_all
        ;;
    install)
        install_all
        ;;
    uninstall)
        uninstall_all
        ;;
    load)
        load_module
        ;;
    unload)
        unload_module
        ;;
    reload)
        unload_module
        load_module
        ;;
    status)
        show_status
        ;;
    clean)
        clean_all
        ;;
    vm)
        deploy_vm
        ;;
    help|*)
        show_help
        ;;
esac

exit 0
