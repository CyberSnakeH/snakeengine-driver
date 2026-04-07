# SnakeEngine Driver (Linux)

[![CI](https://github.com/CyberSnakeH/snakeengine-driver/actions/workflows/ci.yml/badge.svg)](https://github.com/CyberSnakeH/snakeengine-driver/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-linux--x64-blue)
![Kernel](https://img.shields.io/badge/kernel-6.1%2B-green)
![License](https://img.shields.io/badge/license-GPLv2-red)

Hardened memory-access and hardware-breakpoint driver for Linux, inspired by Cheat Engine's DBK on Windows. Kernel module + modern C++ userland API with dlopen injection, ImGui overlay support, and VMA stealth. Research and educational use only.

## Highlights

- **Kernel driver** (`kernel/`): `/dev/snakedrv`, process attach/detach, forced read/write, memory region enumeration, hardware breakpoints, debug event queue, physical memory access, and VMA unlinking for stealth.
- **Userland library** (`userland/`): typed C/C++ API (`snakedrv.h`, `libsnakedrv.hpp`) plus ELF mapping/injection helpers and remote symbol resolution.
- **Memory scanner** (`libsnakedrv_scanner`): Cheat Engine-style scans (exact/range/changed/pattern/float/string) with bloom filter acceleration and parallel scanning.
- **dlopen injection**: inject any `.so` into a running process via `dlopen` — full C++ runtime, TLS, exception handling, and OpenGL support out of the box.
- **ImGui overlay**: inject a Dear ImGui window into SDL2/OpenGL games (e.g. AssaultCube) with DYNAPI hook.
- **VMA stealth**: hide injected `.so` from `/proc/pid/maps` via maple tree VMA unlinking.
- **Automation** (`deploy.sh`): deps, build, install, load/unload, test, inject, SELinux policy, DKMS integration.
- **Security** (`security/`): udev rules, AppArmor profile, SELinux policy (v2.0 with kernel thread + unconfined_t support), Secure Boot signing.

## Requirements

- Linux kernel 6.1+ on x86_64 (VMA unlinking relies on Maple Tree)
- Kernel headers matching the running kernel
- gcc, g++, make, cmake
- SDL2-devel, mesa-libGL-devel (for ImGui payload)
- DKMS recommended for kernel upgrades
- Secure Boot (optional): `mokutil` and `sign-module.sh`

## Quick start

```bash
# Build everything (driver + library + tests + ImGui payload)
./deploy.sh build

# Install (kernel module, library, tools, SELinux policy)
sudo ./deploy.sh install

# Load the module
sudo ./deploy.sh load

# Check status
./deploy.sh status
```

## Injection (dlopen method)

The recommended injection method uses `dlopen` for full runtime support:

```bash
# Inject a .so into a running process
sudo dlopen_inject <pid> /path/to/payload.so

# Or via deploy.sh
sudo ./deploy.sh inject <pid> /path/to/payload.so
```

The payload must export a `ManualMapEntry(void*)` function. After injection, the `.so` VMAs are automatically hidden from `/proc/pid/maps`.

### ImGui overlay example

```bash
# Build the ImGui payload
./deploy.sh payload

# Launch a game and inject
assaultcube &
sleep 5
sudo dlopen_inject $(pgrep assaultcube) libpayload_dlopen.so
```

This injects a Dear ImGui overlay window into the game via SDL2 DYNAPI hook.

## C++ API usage

```cpp
#include "libsnakedrv.hpp"

int main() {
    snake::Driver drv;
    drv.open();
    drv.attach(target_pid);

    // Read/write memory
    uint32_t hp = drv.read<uint32_t>(health_addr);
    drv.write(health_addr, 9999);

    // Hardware breakpoint
    auto bp = drv.setBreakpoint(addr,
        snake::BreakpointType::ReadWrite,
        snake::BreakpointLength::Byte4);

    // Poll debug events
    for (const auto& ev : drv.pollEvents(16))
        printf("Hit at 0x%lx\n", ev.address);

    drv.clearBreakpoint(*bp);
    drv.detach();
}
```

## SELinux policy

The driver ships a SELinux policy that allows operation under enforcing mode.

### Install via deploy.sh

```bash
sudo ./deploy.sh install    # installs policy automatically
```

### Install manually

```bash
cd security/
sudo dnf install selinux-policy-devel    # Fedora
sudo make -f /usr/share/selinux/devel/Makefile snakeengine.pp
sudo semodule -i snakeengine.pp
sudo restorecon -Rv /dev/snakedrv
```

### Verify

```bash
getenforce                    # should show "Enforcing"
sudo ./deploy.sh status       # should work without setenforce 0
```

### Policy details

The v2.0 policy covers:
- `unconfined_t` (sudo processes) access to `/dev/snakedrv` ioctls
- `kernel_t` threads (`snake_injector`, `snake_shadow`) with `execmem` for `vm_mmap(PROT_EXEC)`
- `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` capability checks
- udev device node creation
- Boolean `snakeengine_can_trace_all` (default: on)

## Project layout

```
kernel/          Kernel driver (snakedrv.ko)
  snakedrv_main.c          Core driver, IOCTLs, capability checks
  snakedrv_scanner.c       Memory scanner with bloom filter
  snakedrv_backend_process.c  Process memory backend
  snakedrv_injector.c      Injection: alloc, stealth, thread hijack, shadow memory
  snakedrv_backend.h       Backend abstraction (VFS-style vtable)
  snakedrv_optimize.h      Cache prefetch, huge page support
  snakedrv_bloom.h         Bloom filter for scan rescans
  snakedrv_memory.h        Slab caches, buffer pooling
  snakedrv_benchmark.h     Performance counters

userland/        C/C++ headers and library
  include/snakedrv.h       IOCTL definitions and ABI
  include/libsnakedrv.hpp  C++ driver API
  include/snakedrv_elf.hpp ELF parser and relocation engine
  src/libsnakedrv.cpp      Driver implementation
  src/snakedrv_injector.cpp  Manual mapper + dlopen injector

security/        Security policies
  snakeengine.te           SELinux type enforcement (v2.0)
  snakeengine.fc           SELinux file contexts
  snakeengine.apparmor     AppArmor profile
  99-snakedrv.rules        udev rules

dkms/            DKMS configuration
deploy.sh        Build, install, test, inject automation
sign-module.sh   Secure Boot module signing (MOK)
```

## Security notes

- Runtime access requires membership in the `snakeengine` group: `sudo usermod -aG snakeengine $USER`
- All sensitive ioctls require `CAP_SYS_PTRACE`; physical memory and injection require `CAP_SYS_ADMIN`
- SELinux policy v2.0 supports enforcing mode out of the box
- Keep `debug_level` low in production; increase only for debugging
- If Secure Boot blocks loading, sign the module with `./sign-module.sh`

## Changelog

### 2.0.0 (2026-04-07)

**Kernel driver security hardening:**
- Added `CAP_SYS_PTRACE` gate on all debug/memory ioctls
- Added `CAP_SYS_ADMIN` gate on physical memory, injection, and shadow memory ioctls
- Fixed use-after-free in process detach: proper `atomic_dec_and_test` refcounting with `kfree` on zero
- Fixed integer overflow in `do_query_regions`: `check_mul_overflow` before `kvzalloc`
- Fixed `page->flags` type for kernel 6.10+ (`memdesc_flags_t` struct wrapper)
- Increased `d_path` buffer from 256 to `PATH_MAX` (4096 bytes)
- Added forward declaration for `cleanup_breakpoints` to fix implicit function error

**Injector improvements:**
- Fixed unsafe `vm_flags` manipulation: uses `vm_flags_set()` on kernel 6.3+ instead of UB pointer cast
- Fixed maple tree VMA unlinking: `mas_set_range(vm_start, vm_end-1)` for correct range coverage
- Added `wait_for_completion_timeout` (5s) on all worker threads instead of unbounded waits
- Fixed thread hijack x86-64 ABI: RSP alignment handled by compiler (`-mincoming-stack-boundary=3`)
- Implemented shadow memory subsystem: pin-and-hide via `get_user_pages_remote` + VMA unlinking
- Implemented `SHADOW_ALLOC`, `SHADOW_WRITE`, `SHADOW_FREE` ioctls (0x68-0x6A)
- Shadow cleanup via `MAP_FIXED` + `vm_munmap` to restore mm consistency on free
- Transparent shadow read interception in `READ_MEMORY` ioctl handler

**Scanner improvements:**
- Hard cap on `scanner_create_result_set`: max 10M results (160 MB)
- Fixed parallel scan worker: separate `alloc_buf`/`scan_buf` to prevent `kvfree` on aligned pointer
- Added `get_unaligned()` for safe unaligned memory access in scan loops
- Added `linux/unaligned.h` / `asm/unaligned.h` compatibility for kernel 6.5+

**Userland library:**
- Fixed `MemoryRegion::end()` overflow: saturates to `UINT64_MAX` instead of wrapping
- Added `static_assert(is_trivially_copyable_v<T>)` on `read<T>`/`write<T>` templates
- Fixed `readString` bounds: clamp `bytesRead` to `maxLength` before null-terminator write
- Fixed `DebugEvent` instruction length: clamp to `sizeof(k.instruction)` to prevent over-read
- Added exception safety in event loop thread (`try/catch` around callback)
- Fixed `followPointerChain` address overflow with `__builtin_add_overflow`
- Made `resolve_imports` strict: returns `false` on unresolved symbols instead of silent continue
- Added `R_X86_64_64` relocation type support in `relocate_base`
- Added `.init_array` discovery and execution via thread hijack
- Implemented dlopen injection path in `ManualMapper` (replaces manual mapping as default)
- Added SDL2 DYNAPI jump table hook for render loop interception

**SELinux policy v2.0:**
- Added `unconfined_t` access to `snakedrv_device_t` (fixes `EPERM` for sudo operations)
- Added `kernel_t execmem` for `vm_mmap(PROT_EXEC)` in injector kernel threads
- Added `sysadm_t` and `unconfined_service_t` device access rules
- Updated file contexts for `dlopen_inject` and `libpayload_dlopen.so`

**Scripts:**
- `deploy.sh` v2.0: added `set -o pipefail`, `trap cleanup`, `cd || die` guards, `umask 022`
- `deploy.sh`: new commands `test`, `inject`, `payload`; installs `dlopen_inject` and payload
- `deploy.sh`: removed hardcoded SSH credentials, removed QEMU/VM references
- `deploy.sh`: sanitized `PREFIX` variable, fixed unquoted expansions
- `sign-module.sh`: RSA 4096-bit keys, AES-256 encrypted private key, `chmod 700/600`
- `sign-module.sh`: cross-distro `sign-file` detection (Fedora + Debian/Ubuntu)

### 1.2 (2026-01-15)
- Stealth manual map injector pipeline (alloc, relocate, write, VMA unlinking)
- Improved remote symbol resolution and IFUNC handling for glibc
- GitHub Actions CI build and release workflows
- Documentation and wiki refresh

### 1.1 (2025-12-06)
- Fixed AppArmor policy errors and improved profile compatibility
- Resolved objtool compilation errors (RETPOLINE) on newer kernels
- Added `sign-module.sh` for Secure Boot module signing (MOK workflow)

### 1.0 (2025-12-01)
- Initial public release
- Kernel module with privileged memory access and hardware breakpoints
- Userland library (C++ API)
- DKMS, udev, AppArmor, SELinux artifacts
- Automation script `deploy.sh`

## Contributing

Contributions are welcome. Please keep kernel changes minimal and auditable.

## License

GPL-2.0

## Disclaimer

This project is for educational and research use.
