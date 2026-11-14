#pragma once
#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace snake::detail {
// Return 0 or a positive errno. Uses native mprotect semantics and permissions.
int protectProcess(pid_t pid, uint64_t address, size_t size, unsigned protection);
}
