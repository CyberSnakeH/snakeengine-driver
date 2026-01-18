# SnakeEngine Driver (Linux)

[![CI](https://github.com/CyberSnakeH/snakeengine-driver/actions/workflows/ci.yml/badge.svg)](https://github.com/CyberSnakeH/snakeengine-driver/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-linux--x64-blue)
![Kernel](https://img.shields.io/badge/kernel-6.1%2B-green)
![License](https://img.shields.io/badge/license-GPLv2-red)

Hardened memory-access and hardware-breakpoint driver for Linux, inspired by Cheat Engine's DBK on Windows. Kernel module + modern C++ userland API with a stealth-capable manual mapper. Research and educational use only.

## Highlights
- Kernel driver (`kernel/`): `/dev/snakedrv`, attach/detach, forced read/write, memory region enumeration, hardware breakpoints, debug event queue, physical memory access, and VMA unlinking for stealth allocations.
- Userland library (`userland/`): typed C/C++ API (`snakedrv.h`, `libsnakedrv.hpp`) plus manual ELF mapping/injection helpers and remote symbol resolution.
- Memory scanner (`libsnakedrv_scanner`): Cheat Engine-style scans (exact/range/changed/pattern/float/string).
- Automation (`deploy.sh`): deps, build, install, load/unload, status, cleanup, DKMS integration.
- Security (`security/`): udev rules, AppArmor profile, optional SELinux policy, and Secure Boot signing helper (`sign-module.sh`).

## Requirements
- Linux kernel 6.1+ on x86_64 (stealth VMA unlinking relies on Maple Tree)
- Kernel headers matching the running kernel
- gcc/clang, make, cmake, libelf
- DKMS recommended for kernel upgrades
- Secure Boot (optional): `mokutil` and `sign-module.sh`

## Quick start
```bash
./deploy.sh build
sudo ./deploy.sh install
sudo ./deploy.sh load
```

## C++ usage (libsnakedrv)
```cpp
#include "libsnakedrv.hpp"
#include <iostream>

int main() {
    snake::Driver drv;
    if (!drv.open()) {
        std::cerr << "Failed to open driver (is /dev/snakedrv present?).\n";
        return 1;
    }

    const snake::ProcessId target = /* your target pid */;
    if (!drv.attach(target)) {
        std::cerr << "Attach failed\n";
        return 1;
    }

    // Read a 32-bit value
    uint32_t value = drv.read<uint32_t>(0x7ffdf000);
    std::cout << "Value: " << value << "\n";

    // Write a 32-bit value
    uint32_t newValue = 1337;
    drv.write(0x7ffdf000, newValue);

    // Set a write watchpoint (4 bytes)
    auto bp = drv.setBreakpoint(0x7ffdf000,
                                snake::BreakpointType::ReadWrite,
                                snake::BreakpointLength::Byte4);
    if (!bp) {
        std::cerr << "Breakpoint set failed\n";
        return 1;
    }

    // Poll events
    for (const auto& ev : drv.pollEvents(16)) {
        std::cout << "Hit at 0x" << std::hex << ev.address
                  << " accessed 0x" << ev.accessedAddress
                  << " size=" << std::dec << ev.accessSize
                  << (ev.isWrite ? " [W]" : " [R]") << "\n";
    }

    drv.clearBreakpoint(*bp);
    drv.detach();
    return 0;
}
```

## Documentation
- `wiki/Home.md`
- `wiki/Installation.md`
- `wiki/Architecture.md`
- `wiki/API.md`
- `wiki/Security.md`
- `wiki/Troubleshooting.md`
- `wiki/FAQ.md`
- `wiki/Contributing.md`
- `wiki/Changelog.md`

## Project layout
```
kernel/     Kernel driver (snakedrv.ko)
userland/   C/C++ headers and library
security/   udev + AppArmor + SELinux policies
dkms/       DKMS config
wiki/       Documentation pages
```

## Security notes
- Runtime access is granted via the `snakeengine` group on `/dev/snakedrv`.
- Keep `debug_level` low in production; increase only for debugging.
- If Secure Boot blocks loading, sign the module with `./sign-module.sh`.

## Changelog
- 1.2 (2026-01-15)
  - Stealth manual map injector pipeline (alloc, relocate, write, VMA unlinking).
  - Improved remote symbol resolution and IFUNC handling for glibc.
  - GitHub Actions CI build and release workflows.
  - Documentation and wiki refresh.
- 1.1 (2025-12-06)
  - Fixed AppArmor policy errors and improved profile compatibility.
  - Resolved objtool compilation errors (RETPOLINE/indirect calls) on newer kernels.
  - Added `sign-module.sh` for Secure Boot module signing (MOK workflow).
- 1.0 (2025-12-01)
  - Initial public release inspired by Cheat Engine's DBK driver on Windows.
  - Kernel module `snakedrv.ko` with privileged memory access and hardware breakpoints.
  - Userland library `libsnakedrv` (C++ API).
  - DKMS support for kernel updates.
  - Security artifacts: udev, AppArmor, SELinux.
  - Automation script `deploy.sh`.

## Contributing
Contributions are welcome. Please follow `wiki/Contributing.md` and keep kernel changes minimal and auditable.

## License
GPL-2.0

## Disclaimer
This project is for educational and research use. 
