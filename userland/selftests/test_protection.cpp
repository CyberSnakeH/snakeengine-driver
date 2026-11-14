#include "snakedrv_protect.hpp"
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>
#include <stdexcept>
#include <fstream>
#include <string>

static void require(bool condition, const char* what) {
    if (!condition) throw std::runtime_error(what);
}
static bool transfer(int fd, void* data, size_t size, bool writing) {
    auto* bytes = static_cast<char*>(data);
    while (size) {
        ssize_t n = writing ? write(fd, bytes, size) : read(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n; size -= static_cast<size_t>(n);
    }
    return true;
}
struct Command { unsigned page; char operation; };

static void runTests() {
    rlimit coreLimit{0, 0};
    require(setrlimit(RLIMIT_CORE, &coreLimit) == 0, "disable probe core dumps");
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<unsigned char*>(mmap(nullptr, page * 3,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    require(memory != MAP_FAILED, "mmap");
    memset(memory, 0x42, page * 3);
#if defined(__x86_64__)
    const unsigned char code[] = {0xb8, 0x2a, 0, 0, 0, 0xc3};
    memcpy(memory + page, code, sizeof(code));
#endif
    require(snake::detail::protectProcess(getpid(), reinterpret_cast<uint64_t>(memory),
        page, PROT_READ) == 0, "self native mprotect");
    require(mprotect(memory, page, PROT_READ | PROT_WRITE) == 0, "restore self mapping");
    int requests[2], responses[2];
    require(pipe(requests) == 0 && pipe(responses) == 0, "pipes");
    pid_t target = fork();
    require(target >= 0, "fork");
    if (!target) {
        close(requests[1]); close(responses[0]);
        std::atomic<unsigned> ready{0};
        std::thread a([&] { ready++; for (;;) std::this_thread::yield(); });
        std::thread b([&] { ready++; for (;;) std::this_thread::yield(); });
        while (ready.load() != 2) std::this_thread::yield();
        int ok = 1;
        transfer(responses[1], &ok, sizeof(ok), true);
        Command command{};
        while (transfer(requests[0], &command, sizeof(command), false)) {
            pid_t probe = fork();
            if (!probe) {
                auto* at = memory + command.page * page;
                if (command.operation == 'r') { volatile unsigned value = *at; (void)value; }
                if (command.operation == 'w') { *reinterpret_cast<volatile unsigned char*>(at + 32) = 0x7f; }
                if (command.operation == 'x') {
                    int value = reinterpret_cast<int(*)()>(at)();
                    if (value != 42) _exit(2);
                }
                _exit(0);
            }
            int status = 0;
            while (waitpid(probe, &status, 0) < 0 && errno == EINTR) {}
            transfer(responses[1], &status, sizeof(status), true);
        }
        _exit(0);
    }
    close(requests[0]); close(responses[1]);
    struct Reap { pid_t pid; ~Reap() { kill(pid, SIGCONT); kill(pid, SIGKILL); waitpid(pid, nullptr, 0); } } reap{target};
    int ready = 0;
    require(transfer(responses[0], &ready, sizeof(ready), false), "target ready");
    auto protect = [&](unsigned flags) {
        int error = snake::detail::protectProcess(target,
            reinterpret_cast<uint64_t>(memory + page), page, flags);
        if (error) std::cerr << "mprotect error=" << error << '\n';
        require(error == 0, "remote native mprotect");
    };
    auto probe = [&](unsigned index, char operation, bool allowed) {
        Command cmd{index, operation}; int status = 0;
        require(transfer(requests[1], &cmd, sizeof(cmd), true), "send probe");
        require(transfer(responses[0], &status, sizeof(status), false), "read probe");
        require(allowed ? WIFEXITED(status) && WEXITSTATUS(status) == 0 :
            WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV, "real page permissions");
    };
    protect(PROT_READ);
    probe(1, 'r', true); probe(1, 'w', false); probe(1, 'x', false);
    probe(0, 'w', true); probe(2, 'w', true);
    protect(PROT_READ | PROT_WRITE);
    probe(1, 'r', true); probe(1, 'w', true); probe(1, 'x', false);
    protect(PROT_READ | PROT_EXEC);
    probe(1, 'r', true); probe(1, 'w', false); probe(1, 'x', true);
    protect(PROT_NONE);
    probe(1, 'r', false); probe(1, 'w', false); probe(1, 'x', false);
    require(snake::detail::protectProcess(target,
        reinterpret_cast<uint64_t>(memory + page), 1, PROT_READ) == 0,
        "native page rounding for a byte-sized range");
    probe(1, 'r', true); probe(1, 'w', false); probe(2, 'w', true);
    protect(PROT_READ | PROT_WRITE);
    require(snake::detail::protectProcess(target, 1, page, PROT_READ) == EINVAL,
        "reject unaligned address");
    require(snake::detail::protectProcess(target, 0, page, PROT_READ) == ENOMEM,
        "native unmapped-address failure and tracer rollback");
    probe(1, 'r', true);
    kill(target, SIGSTOP);
    int status = 0;
    require(waitpid(target, &status, WUNTRACED) == target && WIFSTOPPED(status), "job stop");
    protect(PROT_READ);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    {
        std::ifstream state("/proc/" + std::to_string(target) + "/status");
        std::string line; bool stillStopped = false;
        while (std::getline(state, line))
            if (line.rfind("State:", 0) == 0) stillStopped = line.find('T', 6) != std::string::npos;
        require(stillStopped, "original job-control stop restored");
    }
    kill(target, SIGCONT);
    probe(1, 'r', true);
    require(ptrace(PTRACE_SEIZE, target, nullptr, nullptr) == 0, "establish another trace owner");
    require(snake::detail::protectProcess(target, reinterpret_cast<uint64_t>(memory),
        page, PROT_READ) == EPERM, "do not steal an existing trace relationship");
    require(ptrace(PTRACE_INTERRUPT, target, nullptr, nullptr) == 0, "trace ownership preserved");
    require(waitpid(target, &status, __WALL) == target, "wait for existing tracer");
    require(ptrace(PTRACE_DETACH, target, nullptr, nullptr) == 0, "detach existing tracer");
    probe(1, 'r', true);
    close(requests[1]); close(responses[0]);
    munmap(memory, page * 3);
    std::cout << "PASS native protection: R/RW/RX/NONE, subranges, errors, threads and restoration\n";
}

int main() {
    try { runTests(); return 0; }
    catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << " errno=" << errno << '\n';
        return 1;
    }
}
