#include "snakedrv.h"
#include "snakedrv_scanner.h"

#include <array>
#include <cstddef>
#include <iostream>
#include <sys/ioctl.h>

constexpr std::array<unsigned int, 33> kIoctls = {
    _IOC_NR(SNAKE_IOCTL_READ_MEMORY),
    _IOC_NR(SNAKE_IOCTL_WRITE_MEMORY),
    _IOC_NR(SNAKE_IOCTL_QUERY_MEMORY),
    _IOC_NR(SNAKE_IOCTL_READ_PHYS),
    _IOC_NR(SNAKE_IOCTL_WRITE_PHYS),
    _IOC_NR(SNAKE_IOCTL_VIRT_TO_PHYS),
    _IOC_NR(SNAKE_IOCTL_PROCESS_OP),
    _IOC_NR(SNAKE_IOCTL_GET_PROC_INFO),
    _IOC_NR(SNAKE_IOCTL_DEBUG_ATTACH),
    _IOC_NR(SNAKE_IOCTL_DEBUG_CONTROL),
    _IOC_NR(SNAKE_IOCTL_SET_BREAKPOINT),
    _IOC_NR(SNAKE_IOCTL_CLEAR_BREAKPOINT),
    _IOC_NR(SNAKE_IOCTL_POLL_EVENTS),
    _IOC_NR(SNAKE_IOCTL_GET_REGS),
    _IOC_NR(SNAKE_IOCTL_SET_REGS),
    _IOC_NR(SNAKE_IOCTL_GET_INFO),
    _IOC_NR(SNAKE_IOCTL_INJECT_ALLOC),
    _IOC_NR(SNAKE_IOCTL_INJECT_PROTECT),
    _IOC_NR(SNAKE_IOCTL_INJECT_THREAD),
    _IOC_NR(SNAKE_IOCTL_INJECT_STEALTH),
    _IOC_NR(SNAKE_IOCTL_SHADOW_ALLOC),
    _IOC_NR(SNAKE_IOCTL_SHADOW_WRITE),
    _IOC_NR(SNAKE_IOCTL_SHADOW_FREE),
    _IOC_NR(SNAKE_IOCTL_SCAN_EXECUTE),
    _IOC_NR(SNAKE_IOCTL_SCAN_GET_RESULTS),
    _IOC_NR(SNAKE_IOCTL_SCAN_FREE_RESULTS),
    _IOC_NR(SNAKE_IOCTL_SCAN_GET_INFO),
    _IOC_NR(SNAKE_IOCTL_GET_BACKEND_INFO),
    _IOC_NR(SNAKE_IOCTL_SET_BACKEND),
    _IOC_NR(SNAKE_IOCTL_GET_PERF_STATS),
    _IOC_NR(SNAKE_IOCTL_RESET_PERF_STATS),
    _IOC_NR(SNAKE_IOCTL_GET_SCAN_OPTIONS),
    _IOC_NR(SNAKE_IOCTL_SET_SCAN_OPTIONS),
};

constexpr bool all_unique()
{
    for (std::size_t i = 0; i < kIoctls.size(); ++i) {
        for (std::size_t j = i + 1; j < kIoctls.size(); ++j) {
            if (kIoctls[i] == kIoctls[j]) {
                return false;
            }
        }
    }
    return true;
}

static_assert(all_unique(), "SnakeDrv public IOCTL numbers must be unique");

int main()
{
    std::cout << "SNAKEDRV_ABI_VERSION=" << SNAKEDRV_ABI_VERSION << "\n";
    std::cout << "public IOCTL numbers are unique\n";
    return 0;
}
