#!/bin/bash
#
# SnakeEngine Driver - Professional Deployment Script v2.0.0
#
# This script handles:
# - Dependency checking and installation
# - Kernel module compilation and installation
# - DKMS configuration
# - Userland library compilation
# - Test suite and payload builds
# - Security configuration (SELinux/AppArmor)
# - udev rules setup
# - System service configuration
# - dlopen injection and shadow memory testing
#
# Usage:
#   ./deploy.sh [command] [options]
#
# Commands:
#   build       - Build everything (kernel, userland, tests, payload)
#   install     - Install everything
#   uninstall   - Remove everything
#   load        - Load kernel module
#   unload      - Unload kernel module
#   reload      - Reload kernel module
#   status      - Show status
#   clean       - Clean build artifacts
#   test        - Run the test suite
#   inject      - Inject a shared object: deploy.sh inject <pid> <payload.so>
#   payload     - Build the ImGui payload only
#   deps        - Install build dependencies
#   help        - Show this help
#
# Options:
#   --debug     - Build with debug symbols
#   --no-dkms   - Skip DKMS installation
#   --no-selinux - Skip SELinux configuration
#   --no-apparmor - Skip AppArmor configuration
#   --force     - Force installation even if checks fail
#   --prefix=PATH - Installation prefix (default: /usr/local)
#   -j|--jobs N - Parallel build jobs
#   --help      - Show this help
#

set -e
set -o pipefail

umask 022

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="snakeengine"
MODULE_NAME="snakedrv"
VERSION="2.0.0"

# Installation paths
PREFIX="${PREFIX:-/usr/local}"

# Sanitize PREFIX: reject paths with spaces or special characters
if [[ "${PREFIX}" =~ [[:space:]] || "${PREFIX}" =~ [^a-zA-Z0-9/_.-] ]]; then
    echo "ERROR: PREFIX contains spaces or special characters: '${PREFIX}'" >&2
    exit 1
fi

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

# Temp files to track for cleanup
TMPFILES=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Cleanup and Utility Functions
# ============================================================================

cleanup() {
    local f
    for f in "${TMPFILES[@]}"; do
        rm -f "${f}" 2>/dev/null || true
    done
}

trap cleanup EXIT

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
    log_info "Detected distribution: ${DISTRO}"
}

install_dependencies_debian() {
    log_info "Installing dependencies for Debian/Ubuntu..."
    apt-get update
    apt-get install -y \
        build-essential \
        "linux-headers-$(uname -r)" \
        dkms \
        pkg-config \
        libelf-dev \
        clang \
        llvm \
        cmake \
        git \
        libsdl2-dev \
        libglew-dev \
        libgl-dev
}

install_dependencies_fedora() {
    log_info "Installing dependencies for Fedora/RHEL..."
    dnf install -y \
        "kernel-devel-$(uname -r)" \
        "kernel-headers-$(uname -r)" \
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
        mesa-libGL-devel \
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

    case "${DISTRO}" in
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
            log_warning "Unknown distribution: ${DISTRO}"
            log_warning "Please install dependencies manually:"
            log_warning "  - kernel headers"
            log_warning "  - build-essential/gcc/make"
            log_warning "  - dkms"
            log_warning "  - clang/llvm"
            log_warning "  - libelf-dev"
            log_warning "  - mesa-libGL-devel / libgl-dev"
            log_warning "  - SDL2-devel / libsdl2-dev"
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
    if [ "${USE_DKMS}" -eq 1 ]; then
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

    cd "${SCRIPT_DIR}/kernel" || die "kernel dir not found"

    # Force GCC compiler (avoid Android clang issues)
    export CC=gcc
    unset CROSS_COMPILE

    if [ "${DEBUG}" -eq 1 ]; then
        make CC=gcc -j"${JOBS}" DEBUG=1 clean modules
    else
        make CC=gcc -j"${JOBS}" clean modules
    fi

    if [ -f "${MODULE_NAME}.ko" ]; then
        log_success "Kernel module built successfully: ${MODULE_NAME}.ko"

        # Show module info
        log_info "Module size: $(du -h "${MODULE_NAME}.ko" | cut -f1)"
        log_info "Module components:"
        log_info "  - snakedrv_main.o (Core driver + IOCTLs + capability checks)"
        log_info "  - snakedrv_scanner.o (Memory scanner + bloom filter)"
        log_info "  - snakedrv_backend_process.o (Process memory backend)"
        log_info "  - snakedrv_injector.o (Manual mapping + shadow memory + dlopen injection)"
    else
        die "Failed to build kernel module"
    fi
}

build_userland() {
    log_info "Building userland library..."

    cd "${SCRIPT_DIR}/userland" || die "userland dir not found"

    # Clean first
    make clean

    # Use the userland Makefile which includes scanner files
    if [ "${DEBUG}" -eq 1 ]; then
        make CXXFLAGS="-std=c++17 -Wall -Wextra -O0 -g -march=native -fPIC" -j"${JOBS}"
    else
        make -j"${JOBS}"
    fi

    if [ -f "libsnakedrv.so" ]; then
        log_success "Userland library built successfully: libsnakedrv.so"
        log_info "Library size: $(du -h "libsnakedrv.so" | cut -f1)"
        log_info "Library includes:"
        log_info "  - libsnakedrv.cpp (Core driver API)"
        log_info "  - libsnakedrv_scanner.cpp (Memory scanner API)"
        log_info "  - snakedrv_injector.cpp (Manual mapper + dlopen injection)"
    else
        die "Failed to build userland library"
    fi
}

build_tests() {
    log_info "Building test suite..."

    cd "${SCRIPT_DIR}/tests" || die "tests dir not found"

    make clean && make

    log_success "Test suite built successfully"
    log_info "Test binaries:"
    log_info "  - test_shadow (shadow memory / VMA-less PTE mapping test)"
    log_info "  - test_hijack (process hijack test)"
    log_info "  - dlopen_inject (dlopen injection tool)"
    log_info "  - inject (manual mapping injection tool)"
    log_info "  - target (simple target process for testing)"
}

build_payload() {
    log_info "Building ImGui payload..."

    cd "${SCRIPT_DIR}/tests/payload_imgui" || die "payload_imgui dir not found"

    mkdir -p build
    cd build || die "could not enter payload_imgui/build"

    # Use cmake3 if available, otherwise cmake
    local CMAKE_CMD="cmake"
    if check_command cmake3; then
        CMAKE_CMD="cmake3"
    fi

    "${CMAKE_CMD}" .. -DCMAKE_BUILD_TYPE=Release
    make -j"${JOBS}"

    log_success "ImGui payload built successfully"
}

build_all() {
    log_info "=== Building SnakeEngine Driver v${VERSION} ==="

    build_kernel_module
    build_userland
    build_tests
    build_payload

    log_success "=== Build completed successfully ==="
}

# ============================================================================
# Installation Functions
# ============================================================================

install_kernel_module() {
    log_info "Installing kernel module..."

    if [ "${USE_DKMS}" -eq 1 ] && check_command dkms; then
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
    if dkms status | grep -q "${MODULE_NAME}" || true; then
        if dkms status 2>/dev/null | grep -q "${MODULE_NAME}"; then
            log_info "Removing old DKMS installation..."
            dkms remove -m "${MODULE_NAME}" -v "${VERSION}" --all 2>/dev/null || true
        fi
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
    mkdir -p "${INCLUDEDIR}/snakeengine"
    mkdir -p "${BINDIR}"
    mkdir -p "${LIBDIR}"

    # Install headers
    log_info "Installing headers to ${INCLUDEDIR}/snakeengine/"
    cp "${SCRIPT_DIR}/userland/include/snakedrv.h" "${INCLUDEDIR}/snakeengine/"
    cp "${SCRIPT_DIR}/userland/include/snakedrv_scanner.h" "${INCLUDEDIR}/snakeengine/" 2>/dev/null || true
    cp "${SCRIPT_DIR}/userland/include/libsnakedrv.hpp" "${INCLUDEDIR}/snakeengine/"
    cp "${SCRIPT_DIR}/userland/include/libsnakedrv_scanner.hpp" "${INCLUDEDIR}/snakeengine/" 2>/dev/null || true
    cp "${SCRIPT_DIR}/userland/include/snakedrv_elf.hpp" "${INCLUDEDIR}/snakeengine/"

    # Install library (built in userland/ directory)
    log_info "Installing library to ${LIBDIR}/"
    if [ -f "${SCRIPT_DIR}/userland/libsnakedrv.so" ]; then
        cp "${SCRIPT_DIR}/userland/libsnakedrv.so" "${LIBDIR}/"
        log_info "Installed: libsnakedrv.so ($(du -h "${SCRIPT_DIR}/userland/libsnakedrv.so" | cut -f1))"
    else
        log_warning "libsnakedrv.so not found in userland/"
    fi

    # Install dlopen injection payload library
    if [ -f "${SCRIPT_DIR}/tests/libpayload_dlopen.so" ]; then
        cp "${SCRIPT_DIR}/tests/libpayload_dlopen.so" "${LIBDIR}/"
        log_info "Installed: libpayload_dlopen.so to ${LIBDIR}/"
    else
        log_warning "libpayload_dlopen.so not found in tests/ (build tests first)"
    fi

    # Install dlopen_inject binary
    if [ -f "${SCRIPT_DIR}/tests/dlopen_inject" ]; then
        cp "${SCRIPT_DIR}/tests/dlopen_inject" "${BINDIR}/"
        chmod 755 "${BINDIR}/dlopen_inject"
        log_info "Installed: dlopen_inject to ${BINDIR}/"
    else
        log_warning "dlopen_inject not found in tests/ (build tests first)"
    fi

    # Update library cache
    ldconfig

    log_success "Userland library installed"
    log_info "Headers available at: ${INCLUDEDIR}/snakeengine/"
    log_info "Library available at: ${LIBDIR}/libsnakedrv.so"
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
    if [ "${USE_SELINUX}" -ne 1 ]; then
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

    cd "${SCRIPT_DIR}/security" || die "security dir not found"

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
    if [ "${USE_APPARMOR}" -ne 1 ]; then
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
    if lsmod | grep -q "^${MODULE_NAME}" || true; then
        if lsmod 2>/dev/null | grep -q "^${MODULE_NAME}"; then
            log_info "Unloading module..."
            rmmod "${MODULE_NAME}" || true
        fi
    fi

    # Remove DKMS
    if check_command dkms; then
        if dkms status 2>/dev/null | grep -q "${MODULE_NAME}" || true; then
            if dkms status 2>/dev/null | grep -q "${MODULE_NAME}"; then
                log_info "Removing DKMS installation..."
                dkms remove -m "${MODULE_NAME}" -v "${VERSION}" --all || true
            fi
        fi
    fi

    # Remove module
    rm -f "${MODULEDIR}/extra/${MODULE_NAME}.ko"
    rm -f "${MODULEDIR}/updates/${MODULE_NAME}.ko"

    # Remove DKMS source
    rm -rf "${DKMS_SRC}"

    # Remove userland
    rm -rf "${LIBDIR}/${PROJECT_NAME}"
    rm -rf "${INCLUDEDIR}/${PROJECT_NAME}"
    rm -rf "${INCLUDEDIR}/snakeengine"
    rm -f "${LIBDIR}/libsnakedrv.so"
    rm -f "${LIBDIR}/libsnakedrv.a"
    rm -f "${LIBDIR}/libpayload_dlopen.so"
    rm -f "${BINDIR}/dlopen_inject"

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

    if lsmod | grep -q "^${MODULE_NAME}" || true; then
        if lsmod 2>/dev/null | grep -q "^${MODULE_NAME}"; then
            log_info "Module already loaded"
            return
        fi
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
# Test and Inject
# ============================================================================

run_tests() {
    log_info "=== Running SnakeEngine Test Suite ==="

    # Ensure test binaries exist
    if [ ! -f "${SCRIPT_DIR}/tests/test_shadow" ]; then
        log_info "Test binaries not found, building..."
        build_tests
    fi

    # Check that module is loaded
    if ! lsmod | grep -q "^${MODULE_NAME}" 2>/dev/null; then
        log_warning "Kernel module is not loaded. Load it first: sudo ./deploy.sh load"
    fi

    cd "${SCRIPT_DIR}/tests" || die "tests dir not found"

    # Launch the target process in background
    log_info "Starting target process..."
    ./target &
    local TARGET_PID=$!
    sleep 1

    if kill -0 "${TARGET_PID}" 2>/dev/null; then
        log_info "Target process running (PID: ${TARGET_PID})"

        # Run shadow memory test
        log_info "Running test_shadow against PID ${TARGET_PID}..."
        if ./test_shadow "${TARGET_PID}"; then
            log_success "test_shadow passed"
        else
            log_warning "test_shadow returned non-zero"
        fi

        # Clean up target
        kill "${TARGET_PID}" 2>/dev/null || true
        wait "${TARGET_PID}" 2>/dev/null || true
    else
        die "Failed to start target process"
    fi

    log_success "=== Test suite completed ==="
}

run_inject() {
    local INJECT_PID="$1"
    local SO_PATH="$2"

    if [ -z "${INJECT_PID}" ] || [ -z "${SO_PATH}" ]; then
        die "Usage: $0 inject <pid> <payload.so>"
    fi

    if [ ! -f "${SO_PATH}" ]; then
        die "Payload not found: ${SO_PATH}"
    fi

    # Prefer installed binary, fall back to build tree
    local DLOPEN_BIN=""
    if [ -f "${BINDIR}/dlopen_inject" ]; then
        DLOPEN_BIN="${BINDIR}/dlopen_inject"
    elif [ -f "${SCRIPT_DIR}/tests/dlopen_inject" ]; then
        DLOPEN_BIN="${SCRIPT_DIR}/tests/dlopen_inject"
    else
        die "dlopen_inject binary not found. Build tests first: ./deploy.sh build"
    fi

    log_info "Injecting ${SO_PATH} into PID ${INJECT_PID}..."
    "${DLOPEN_BIN}" "${INJECT_PID}" "${SO_PATH}"
    log_success "Injection completed"
}

# ============================================================================
# Status
# ============================================================================

show_status() {
    echo "=== SnakeEngine Driver Status (v${VERSION}) ==="
    echo ""

    # Module status
    echo "Kernel Module:"
    if lsmod | grep -q "^${MODULE_NAME}" 2>/dev/null; then
        echo "  Status: LOADED"
        echo "  Info:"
        lsmod | grep "^${MODULE_NAME}" | awk '{print "    Size: "$2" bytes, Used by: "$3}' || true
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

    # Shadow memory allocations
    echo "Shadow Memory:"
    if [ -f "/sys/module/${MODULE_NAME}/parameters/shadow_alloc_count" ]; then
        echo "  Allocations: $(cat "/sys/module/${MODULE_NAME}/parameters/shadow_alloc_count")"
    elif [ -e "/dev/${MODULE_NAME}" ]; then
        local SHADOW_COUNT
        SHADOW_COUNT=$(dmesg | grep -c "snakedrv.*shadow" 2>/dev/null || true)
        echo "  Recent shadow operations in dmesg: ${SHADOW_COUNT:-0}"
    else
        echo "  N/A (module not loaded)"
    fi
    echo ""

    # Attached processes
    echo "Attached Processes:"
    if [ -f "/sys/module/${MODULE_NAME}/parameters/attached_count" ]; then
        echo "  Count: $(cat "/sys/module/${MODULE_NAME}/parameters/attached_count")"
    elif [ -e "/dev/${MODULE_NAME}" ]; then
        local ATTACH_COUNT
        ATTACH_COUNT=$(dmesg | grep -c "snakedrv.*attach" 2>/dev/null || true)
        echo "  Recent attach operations in dmesg: ${ATTACH_COUNT:-0}"
    else
        echo "  N/A (module not loaded)"
    fi
    echo ""

    # DKMS status
    echo "DKMS:"
    if check_command dkms; then
        dkms status | grep "${MODULE_NAME}" || echo "  Not installed via DKMS" || true
    else
        echo "  DKMS not available"
    fi
    echo ""

    # Test suite build status
    echo "Test Suite:"
    if [ -f "${SCRIPT_DIR}/tests/test_shadow" ] && [ -f "${SCRIPT_DIR}/tests/dlopen_inject" ]; then
        echo "  Status: BUILT"
        echo "  Binaries: test_shadow, test_hijack, dlopen_inject, inject, target"
    else
        echo "  Status: NOT BUILT (run: ./deploy.sh build)"
    fi
    echo ""

    # Payload build status
    echo "ImGui Payload:"
    if [ -f "${SCRIPT_DIR}/tests/payload_imgui/build/libpayload_imgui.so" ] || \
       [ -f "${SCRIPT_DIR}/tests/libpayload_imgui.so" ]; then
        echo "  Status: BUILT"
    else
        echo "  Status: NOT BUILT (run: ./deploy.sh payload)"
    fi
    echo ""

    # Kernel log
    echo "Recent kernel messages:"
    dmesg | grep -i snakedrv | tail -10 || echo "  No messages found" || true
}

# ============================================================================
# Clean
# ============================================================================

clean_all() {
    log_info "Cleaning build artifacts..."

    # Clean kernel module
    if [ -d "${SCRIPT_DIR}/kernel" ]; then
        cd "${SCRIPT_DIR}/kernel" || die "cannot enter kernel dir"
        make clean 2>/dev/null || true
    fi

    # Clean userland library
    if [ -d "${SCRIPT_DIR}/userland" ]; then
        cd "${SCRIPT_DIR}/userland" || die "cannot enter userland dir"
        make clean 2>/dev/null || true
    fi

    # Clean tests
    if [ -d "${SCRIPT_DIR}/tests" ]; then
        cd "${SCRIPT_DIR}/tests" || die "cannot enter tests dir"
        make clean 2>/dev/null || true
    fi

    # Clean payload build
    if [ -d "${SCRIPT_DIR}/tests/payload_imgui/build" ]; then
        rm -rf "${SCRIPT_DIR}/tests/payload_imgui/build"
    fi

    # Clean general build directory
    rm -rf "${SCRIPT_DIR}/build"
    rm -rf "${SCRIPT_DIR}/security/tmp"

    log_success "Clean completed"
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
  build       Build everything (kernel module, userland, tests, payload)
  install     Install everything (requires root)
  uninstall   Remove everything (requires root)
  load        Load kernel module (requires root)
  unload      Unload kernel module (requires root)
  reload      Reload kernel module (requires root)
  status      Show driver status, shadow memory, attached processes, test builds
  clean       Clean build artifacts
  test        Run the test suite (test_shadow against a target process)
  inject      Inject a shared object into a process
              Usage: $0 inject <pid> <payload.so>
  payload     Build the ImGui payload only
  help        Show this help

Options:
  --debug       Build with debug symbols
  --no-dkms     Skip DKMS installation
  --no-selinux  Skip SELinux configuration
  --no-apparmor Skip AppArmor configuration
  --force       Force installation
  --prefix=PATH Installation prefix (default: /usr/local)
  -j|--jobs N   Number of parallel build jobs

Examples:
  $0 build                        # Build everything
  sudo $0 install                 # Install everything
  sudo $0 install --no-dkms       # Install without DKMS
  sudo $0 load                    # Load the module
  $0 status                       # Check status
  $0 test                         # Run test suite
  sudo $0 inject 1234 payload.so  # Inject payload into PID 1234
  $0 payload                      # Build ImGui payload
  sudo $0 uninstall               # Remove everything

Environment variables:
  DEBUG=1       Build with debug symbols
  PREFIX=/path  Installation prefix
  CXX=clang++   C++ compiler to use
  JOBS=N        Parallel build jobs

EOF
}

# ============================================================================
# Main
# ============================================================================

COMMAND=""
INJECT_PID=""
INJECT_SO=""

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
            # Re-sanitize PREFIX after override
            if [[ "${PREFIX}" =~ [[:space:]] || "${PREFIX}" =~ [^a-zA-Z0-9/_.-] ]]; then
                die "PREFIX contains spaces or special characters: '${PREFIX}'"
            fi
            BINDIR="${PREFIX}/bin"
            LIBDIR="${PREFIX}/lib"
            INCLUDEDIR="${PREFIX}/include"
            shift
            ;;
        inject)
            COMMAND="inject"
            INJECT_PID="${2:-}"
            INJECT_SO="${3:-}"
            shift
            # Shift additional args if present
            [ -n "${INJECT_PID}" ] && shift
            [ -n "${INJECT_SO}" ] && shift
            ;;
        deps|build|install|uninstall|load|unload|reload|status|clean|test|payload|help)
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
    test)
        run_tests
        ;;
    inject)
        run_inject "${INJECT_PID}" "${INJECT_SO}"
        ;;
    payload)
        build_payload
        ;;
    help|*)
        show_help
        ;;
esac

exit 0
