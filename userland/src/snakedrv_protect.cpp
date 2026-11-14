#include "snakedrv_protect.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <limits>
#if defined(__x86_64__)
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#endif

namespace snake::detail {
#if defined(__x86_64__)
namespace {
struct Thread {
    pid_t tid;
    bool stopped = false;
    bool groupStopped = false;
    int pendingSignal = 0;
    int stopSignal = 0;
    unsigned stopEvent = 0;
};

// All threads are stopped before shared executable bytes are changed. A tracer
// already owning any thread is never displaced. Cleanup restores text and the
// complete general-register state before detaching, including on syscall errors.
class TraceScope {
public:
    std::vector<Thread> threads;
    pid_t executor = -1;
    user_regs_struct saved{};
    long instruction = 0;
    uint64_t patchAddress = 0;
    bool textChanged = false, regsChanged = false, closed = false;

    static int waitStopped(Thread& t, bool bounded = true) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            int status = 0;
            pid_t got = waitpid(t.tid, &status, __WALL | (bounded ? WNOHANG : 0));
            if (got == t.tid) {
                if (!WIFSTOPPED(status)) { t.tid = -1; return ESRCH; }
                t.stopped = true;
                t.stopSignal = WSTOPSIG(status);
                t.stopEvent = static_cast<unsigned>(status) >> 16;
                if (WSTOPSIG(status) != SIGTRAP && WSTOPSIG(status) != SIGSTOP)
                    t.pendingSignal = WSTOPSIG(status);
                return 0;
            }
            if (got < 0 && errno != EINTR) return errno;
            if (bounded && std::chrono::steady_clock::now() >= deadline)
                return ETIMEDOUT;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    int freeze(pid_t pid) {
        const std::string directory = "/proc/" + std::to_string(pid) + "/task";
        for (unsigned attempt = 0; attempt != 64; ++attempt) {
            DIR* dir = opendir(directory.c_str());
            if (!dir) return errno;
            std::vector<pid_t> tids;
            while (auto* e = readdir(dir)) {
                char* end = nullptr;
                long value = strtol(e->d_name, &end, 10);
                if (end && !*end && value > 0 && value <= std::numeric_limits<pid_t>::max())
                    tids.push_back(static_cast<pid_t>(value));
            }
            closedir(dir);
            bool added = false;
            for (pid_t tid : tids) {
                if (std::any_of(threads.begin(), threads.end(),
                    [tid](const Thread& t) { return t.tid == tid; })) continue;
                Thread t{tid};
                std::ifstream state(directory + "/" + std::to_string(tid) + "/status");
                std::string line;
                while (std::getline(state, line)) {
                    if (line.rfind("State:", 0) == 0) {
                        t.groupStopped = line.find('T', 6) != std::string::npos;
                        break;
                    }
                }
                if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) < 0) {
                    if (errno == ESRCH) continue;
                    return errno;
                }
                threads.push_back(t);
                if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
                    if (errno == ESRCH) { threads.back().tid = -1; continue; }
                    return errno;
                }
                int error = waitStopped(threads.back());
                if (error && error != ESRCH) return error;
                added = true;
            }
            // Re-enumeration closes the race with clones made before parents
            // reached their ptrace stops. No target thread runs during patching.
            if (!added) {
                auto it = std::find_if(threads.begin(), threads.end(),
                    [](const Thread& t) { return t.tid > 0 && t.stopped; });
                if (it == threads.end()) return ESRCH;
                executor = it->tid;
                return 0;
            }
        }
        return EAGAIN;
    }

    int restore() {
        if (closed) return 0;
        int error = 0;
        for (auto& t : threads) {
            if (t.tid <= 0) continue;
            if (!t.stopped) {
                if (ptrace(PTRACE_INTERRUPT, t.tid, nullptr, nullptr) < 0 && errno == ESRCH) {
                    t.tid = -1;
                    continue;
                }
                int e = waitStopped(t);
                // Never return with our instructions still installed. If a
                // syscall cannot reach a stop yet, retain ownership until it does.
                if (e == ETIMEDOUT) e = waitStopped(t, false);
                if (e) { if (!error) error = e; continue; }
            }
            if (t.tid == executor) {
                if (textChanged && ptrace(PTRACE_POKETEXT, t.tid,
                    reinterpret_cast<void*>(patchAddress), instruction) < 0)
                    error = errno;
                if (regsChanged && ptrace(PTRACE_SETREGS, t.tid, nullptr, &saved) < 0)
                    error = errno;
            }
        }
        for (auto& t : threads) {
            if (t.tid <= 0 || !t.stopped) continue;
            int signal = t.pendingSignal ? t.pendingSignal : (t.groupStopped ? SIGSTOP : 0);
            if (ptrace(PTRACE_DETACH, t.tid, nullptr, signal) < 0 && errno != ESRCH && !error)
                error = errno;
        }
        closed = true;
        return error;
    }

    ~TraceScope() { restore(); }
};
}
#endif

int protectProcess(pid_t pid, uint64_t address, size_t size, unsigned protection)
{
    long page = sysconf(_SC_PAGESIZE);
    if (pid <= 0 || page <= 0 || address % static_cast<uint64_t>(page) || !size ||
        (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) ||
        size > std::numeric_limits<uint64_t>::max() - address ||
        size > std::numeric_limits<size_t>::max() - (static_cast<size_t>(page) - 1))
        return EINVAL;
    const size_t roundedSize = (size + static_cast<size_t>(page) - 1) &
        ~(static_cast<size_t>(page) - 1);
    if (roundedSize > std::numeric_limits<uint64_t>::max() - address)
        return EINVAL;
    const uint64_t endAddress = address + roundedSize;
    if (pid == getpid())
        return mprotect(reinterpret_cast<void*>(address), size, protection) ? errno : 0;
#if defined(__x86_64__)
    TraceScope scope;
    int error = scope.freeze(pid);
    if (error) return error;
    auto it = std::find_if(scope.threads.begin(), scope.threads.end(),
        [&scope](const Thread& t) { return t.tid == scope.executor; });
    if (ptrace(PTRACE_GETREGS, scope.executor, nullptr, &scope.saved) < 0) return errno;
    if (scope.saved.cs != 0x33) return EOPNOTSUPP; // No 32-bit/x32 syscall ABI emulation.
    scope.patchAddress = scope.saved.rip;
    if (scope.patchAddress < endAddress &&
        scope.patchAddress + sizeof(long) > address) {
        scope.patchAddress = 0;
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream fields(line);
            std::string range, permissions;
            if (!(fields >> range >> permissions) || permissions != "r-xp") continue;
            auto dash = range.find('-');
            uint64_t start = strtoull(range.substr(0, dash).c_str(), nullptr, 16);
            uint64_t end = strtoull(range.substr(dash + 1).c_str(), nullptr, 16);
            if (end - start >= sizeof(long) &&
                (start + sizeof(long) <= address || start >= endAddress)) {
                scope.patchAddress = start;
                break;
            }
        }
        if (!scope.patchAddress) return EOPNOTSUPP;
    }
    errno = 0;
    scope.instruction = ptrace(PTRACE_PEEKTEXT, scope.executor,
                               reinterpret_cast<void*>(scope.patchAddress), nullptr);
    if (errno) return errno;
    long patch = scope.instruction;
    const unsigned char syscallTrap[] = {0x0f, 0x05, 0xcc};
    memcpy(&patch, syscallTrap, sizeof(syscallTrap));
    if (ptrace(PTRACE_POKETEXT, scope.executor,
        reinterpret_cast<void*>(scope.patchAddress), patch) < 0) return errno;
    scope.textChanged = true;
    user_regs_struct regs = scope.saved;
    regs.rip = scope.patchAddress;
    regs.rax = SYS_mprotect; regs.orig_rax = -1ULL;
    regs.rdi = address; regs.rsi = size; regs.rdx = protection;
    if (ptrace(PTRACE_SETREGS, scope.executor, nullptr, &regs) < 0) return errno;
    scope.regsChanged = true;
    // A pre-existing job-control stop needs SIGCONT before the selected thread
    // can execute. Siblings remain in ptrace stops, and cleanup restores SIGSTOP.
    bool groupStopped = std::any_of(scope.threads.begin(), scope.threads.end(),
        [](const Thread& t) { return t.groupStopped; });
    const int originalPendingSignal = it->pendingSignal;
    if (groupStopped && kill(pid, SIGCONT) < 0) return errno;
    bool completed = false;
    for (unsigned stops = 0; stops != 16; ++stops) {
        if (ptrace(PTRACE_CONT, scope.executor, nullptr, nullptr) < 0) return errno;
        it->stopped = false;
        error = TraceScope::waitStopped(*it);
        if (error) return error;
        if (ptrace(PTRACE_GETREGS, scope.executor, nullptr, &regs) < 0) return errno;
        if (it->stopSignal == SIGTRAP && !it->stopEvent &&
            regs.rip == scope.patchAddress + sizeof(syscallTrap)) {
            completed = true;
            break;
        }
        if (!groupStopped || (it->stopSignal != SIGCONT &&
            it->stopSignal != SIGSTOP && it->stopEvent != PTRACE_EVENT_STOP)) return EINTR;
        it->pendingSignal = originalPendingSignal;
    }
    if (!completed) return EAGAIN;
    long result = static_cast<long>(regs.rax);
    error = result < 0 && result >= -4095 ? static_cast<int>(-result) : 0;
    int restored = scope.restore();
    return restored ? restored : error;
#else
    return EOPNOTSUPP;
#endif
}
}
