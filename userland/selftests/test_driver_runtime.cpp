#include "libsnakedrv.hpp"
#include "snakedrv_scanner.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/klog.h>
#include <sys/stat.h>
#include <linux/reboot.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
#include <sstream>

static void check(bool ok, const char* what) {
    if (!ok) throw std::runtime_error(std::string(what) + ": " + strerror(errno));
}
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) { check(fd >= 0, "open fd"); }
    ~Fd() { if (value >= 0) close(value); }
    void reset() { if (value >= 0) close(value); value = -1; }
};
struct JoinWorker {
    std::thread& thread;
    std::atomic<bool>& running;
    ~JoinWorker() { running = false; if (thread.joinable()) thread.join(); }
};
alignas(8) static volatile uint64_t watched = 0;
alignas(8) static volatile uint64_t scanValue = 0x12345678fedcba98ULL;
static void transfer(int fd, void* buffer, size_t size, bool writing) {
    auto* p = static_cast<char*>(buffer);
    while (size) {
        if (!writing) {
            pollfd ready{fd, POLLIN, 0};
            check(poll(&ready, 1, 20000) == 1, "target response timeout");
        }
        ssize_t n = writing ? write(fd, p, size) : read(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        check(n > 0, "target channel");
        p += n; size -= static_cast<size_t>(n);
    }
}
struct Target {
    pid_t pid;
    int request, response;
    void* region;
    Target() {
        region = mmap(nullptr, 3 * 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(region != MAP_FAILED, "target mapping");
        int a[2], b[2];
        check(pipe(a) == 0 && pipe(b) == 0, "target pipes");
        pid = fork(); check(pid >= 0, "fork target");
        if (!pid) {
            close(a[1]); close(b[0]);
            char command;
            while (read(a[0], &command, 1) == 1) {
                pid_t tid = static_cast<pid_t>(syscall(SYS_gettid));
                if (command == 'l') {
                    std::thread survivor([readFd=a[0], writeFd=b[1]] {
                        pid_t childTid = syscall(SYS_gettid);
                        write(writeFd, &childTid, sizeof(childTid));
                        char command;
                        while (read(readFd, &command, 1) == 1) {
                            watched = 17;
                            write(writeFd, &childTid, sizeof(childTid));
                        }
                    });
                    survivor.detach();
                    // Exit only this thread, without unwinding RAII objects
                    // copied from the test supervisor by fork().
                    syscall(SYS_exit, 0);
                    __builtin_unreachable();
                }
                if (command == 'n') {
                    std::thread child([&] { tid = syscall(SYS_gettid); watched = 9; });
                    child.join();
                } else {
                    unsigned writes = command == 'w' ? 64 : 1;
                    for (unsigned i = 0; i < writes; ++i) watched = i;
                }
                if (write(b[1], &tid, sizeof(tid)) != sizeof(tid)) _exit(2);
            }
            _exit(0);
        }
        close(a[0]); close(b[1]); request = a[1]; response = b[0];
    }
    void send(char command) { transfer(request, &command, 1, true); }
    pid_t receive() { pid_t tid; transfer(response, &tid, sizeof(tid), false); return tid; }
    pid_t command(char command) { send(command); return receive(); }
    ~Target() {
        kill(pid, SIGCONT); kill(pid, SIGKILL); waitpid(pid, nullptr, 0);
        close(request); close(response); munmap(region, 3 * 4096);
    }
};
static void attach(int fd, pid_t pid) {
    snake_debug_attach op{}; op.pid = pid;
    check(ioctl(fd, SNAKE_IOCTL_DEBUG_ATTACH, &op) == 0, "attach");
}
static void detach(int fd, pid_t pid) {
    snake_debug_control op{}; op.pid = pid; op.operation = SNAKE_DBG_CTRL_DETACH;
    check(ioctl(fd, SNAKE_IOCTL_DEBUG_CONTROL, &op) == 0, "detach");
}
static snake_hw_breakpoint breakpoint(int fd, pid_t pid, bool stop = false) {
    snake_hw_breakpoint bp{};
    bp.pid = pid; bp.address = reinterpret_cast<uint64_t>(&watched);
    bp.type = SNAKE_BP_TYPE_WRITE; bp.length = SNAKE_BP_LEN_8;
    bp.enabled = SNAKE_BP_FLAG_ENABLED | (stop ? SNAKE_BP_FLAG_STOP_ON_HIT : 0);
    check(ioctl(fd, SNAKE_IOCTL_SET_BREAKPOINT, &bp) == 0, "set breakpoint");
    return bp;
}
static std::vector<snake_debug_event> drain(int fd) {
    std::vector<snake_debug_event> events(256);
    snake_event_poll op{};
    op.events_buffer = reinterpret_cast<uint64_t>(events.data()); op.max_events = events.size();
    check(ioctl(fd, SNAKE_IOCTL_POLL_EVENTS, &op) == 0, "poll events");
    events.resize(op.events_ready); return events;
}
static snake_scan_execute scan(int fd, pid_t pid) {
    snake_scan_result result{};
    snake_scan_execute scan{};
    scan.params.pid = pid; scan.params.value_type = 8; scan.params.max_results = 8;
    scan.params.start_address = reinterpret_cast<uint64_t>(&scanValue);
    scan.params.end_address = scan.params.start_address + 8;
    scan.params.search_value = scanValue;
    scan.results = reinterpret_cast<uint64_t>(&result); scan.results_capacity = 1;
    check(ioctl(fd, SNAKE_IOCTL_SCAN_EXECUTE, &scan) == 0 && scan.total_matches == 1,
          "exact scan");
    return scan;
}
static std::string maps(pid_t pid) {
    std::ifstream file("/proc/" + std::to_string(pid) + "/maps");
    return std::string(std::istreambuf_iterator<char>(file), {});
}
static bool mapped(pid_t pid, uint64_t address) {
    std::istringstream rows(maps(pid));
    std::string line;
    while (std::getline(rows, line)) {
        unsigned long first, last;
        if (sscanf(line.c_str(), "%lx-%lx", &first, &last) == 2 &&
            address >= first && address < last) return true;
    }
    return false;
}

static void runtimeTests() {
    Target target;
    Fd fd(open("/dev/snakedrv", O_RDWR | O_CLOEXEC));
    Fd other(open("/dev/snakedrv", O_RDWR | O_CLOEXEC));
    attach(fd.value, target.pid);
    auto bp = breakpoint(fd.value, target.pid);
    target.command('w');
    snake_debug_stats stats{}, isolated{};
    check(ioctl(fd.value, SNAKE_IOCTL_GET_DEBUG_STATS, &stats) == 0, "debug stats");
    check(stats.queued == 4 && stats.dropped > 0, "bounded queue and visible overflow");
    check(ioctl(other.value, SNAKE_IOCTL_GET_DEBUG_STATS, &isolated) == 0 &&
        isolated.queued == 0 && isolated.dropped == 0, "client event isolation");
    auto events = drain(fd.value);
    check(!events.empty() && events[0].accessed_address == bp.address &&
          events[0].access_size == 8, "watchpoint event metadata");
    check(ioctl(fd.value, SNAKE_IOCTL_CLEAR_BREAKPOINT, &bp) == 0, "clear breakpoint");
    target.command('w'); check(drain(fd.value).empty(), "cleared breakpoint inactive");
    bp = breakpoint(fd.value, target.pid);
    pid_t tid = target.command('n'); events = drain(fd.value);
    bool inherited = false;
    for (auto& e : events) inherited |= e.tid == tid;
    check(inherited, "new thread inherits process breakpoint");
    check(ioctl(fd.value, SNAKE_IOCTL_CLEAR_BREAKPOINT, &bp) == 0,
          "release parent after child thread exit");
    bp = breakpoint(fd.value, target.pid, true);
    target.send('s');
    int status = 0; bool stopped = false;
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < until) {
        if (waitpid(target.pid, &status, WUNTRACED | WNOHANG) == target.pid) {
            stopped = WIFSTOPPED(status); break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(stopped && WSTOPSIG(status) == SIGSTOP, "stop-on-hit");
    check(ioctl(fd.value, SNAKE_IOCTL_CLEAR_BREAKPOINT, &bp) == 0, "clear stopped breakpoint");
    kill(target.pid, SIGCONT); target.receive(); drain(fd.value);
    std::cout << "PASS breakpoints: queue isolation, overflow, new/exit threads, stop and clear\n";

    {
        Target orphan;
        attach(fd.value, orphan.pid);
        auto inheritedBp = breakpoint(fd.value, orphan.pid);
        pid_t survivor = orphan.command('l');
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        orphan.command('w');
        bool recorded = false;
        for (auto& e : drain(fd.value)) recorded |= e.tid == survivor;
        check(recorded, "inherited callback survives leader exit");
        check(ioctl(fd.value, SNAKE_IOCTL_CLEAR_BREAKPOINT, &inheritedBp) == 0,
              "release inherited events after parent exit");
        detach(fd.value, orphan.pid);
    }
    std::cout << "PASS inherited breakpoint lifetime after group leader exit\n";
    detach(fd.value, target.pid);
    {
        Fd closing(open("/dev/snakedrv", O_RDWR | O_CLOEXEC));
        attach(closing.value, target.pid);
        breakpoint(closing.value, target.pid, true);
        target.send('s');
        check(waitpid(target.pid, &status, WUNTRACED) == target.pid && WIFSTOPPED(status),
              "stop before closing debugger");
        closing.reset();
        target.receive();
    }
    attach(fd.value, target.pid);
    std::cout << "PASS closing the debugger releases its own stop\n";

    std::atomic<bool> racing{true};
    std::thread setter([&] {
        while (racing.load()) {
            snake_hw_breakpoint op{}; op.pid = target.pid;
            op.address = reinterpret_cast<uint64_t>(&watched);
            op.type = SNAKE_BP_TYPE_WRITE; op.length = SNAKE_BP_LEN_8; op.enabled = 1;
            if (ioctl(fd.value, SNAKE_IOCTL_SET_BREAKPOINT, &op) == 0)
                ioctl(fd.value, SNAKE_IOCTL_CLEAR_BREAKPOINT, &op);
        }
    });
    JoinWorker joinSetter{setter, racing};
    for (unsigned i = 0; i != 40; ++i) {
        target.command('w'); detach(fd.value, target.pid); attach(fd.value, target.pid);
    }
    racing = false; setter.join();
    // Ensure no residual slots survive the concurrent operations.
    detach(fd.value, target.pid); attach(fd.value, target.pid); drain(fd.value);
    std::cout << "PASS concurrent breakpoint registration, detach and cleanup\n";

    auto cached = scan(fd.value, target.pid);
    snake_scan_result_set_info info{}; info.result_set_id = cached.result_set_id;
    errno = 0;
    check(ioctl(other.value, SNAKE_IOCTL_SCAN_GET_INFO, &info) == -1 && errno == ENOENT,
          "result set owner isolation");
    std::atomic<uint32_t> current{cached.result_set_id};
    racing = true;
    std::thread reader([&] {
        while (racing.load()) {
            snake_scan_result value{}; snake_scan_execute read{};
            read.params.result_set_id = current.load(); read.results_capacity = 1;
            read.results = reinterpret_cast<uint64_t>(&value);
            ioctl(fd.value, SNAKE_IOCTL_SCAN_GET_RESULTS, &read);
        }
    });
    JoinWorker joinReader{reader, racing};
    for (unsigned i = 0; i != 100; ++i) {
        uint32_t old = current.load();
        check(ioctl(fd.value, SNAKE_IOCTL_SCAN_FREE_RESULTS, &old) == 0, "free cached result");
        auto next = scan(fd.value, target.pid); current = next.result_set_id;
    }
    racing = false; reader.join();
    uint32_t last = current.load(); ioctl(fd.value, SNAKE_IOCTL_SCAN_FREE_RESULTS, &last);
    std::cout << "PASS cached-result read/free races and owner isolation\n";

    snake_shadow_alloc allocation{};
    allocation.pid = target.pid; allocation.size = 8192;
    allocation.protection = SNAKE_PROT_READ | SNAKE_PROT_WRITE;
    check(ioctl(fd.value, SNAKE_IOCTL_SHADOW_ALLOC, &allocation) == 0, "pinned mapping");
    uint64_t value = 42;
    snake_shadow_write write{}; write.pid = target.pid; write.address = allocation.address;
    write.size = sizeof(value); write.user_buffer = reinterpret_cast<uint64_t>(&value);
    errno = 0;
    check(ioctl(other.value, SNAKE_IOCTL_SHADOW_WRITE, &write) == -1 && errno == ENOENT,
          "pinned allocation owner isolation");
    racing = true;
    std::thread writer([&] {
        while (racing.load()) ioctl(fd.value, SNAKE_IOCTL_SHADOW_WRITE, &write);
    });
    JoinWorker joinWriter{writer, racing};
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    check(ioctl(fd.value, SNAKE_IOCTL_SHADOW_FREE, &allocation) == 0, "concurrent pinned free");
    racing = false; writer.join();
    std::cout << "PASS pinned mapping write/free lifetime and owner isolation\n";

    snake::Driver sdk;
    check(sdk.open(), "SDK ABI handshake");
    auto protect = sdk.injectProtect(target.pid, reinterpret_cast<uint64_t>(target.region),
                                    4096, snake::Protection::Read);
    check(protect.success, "SDK native protection fallback");
    protect = sdk.injectProtect(target.pid, reinterpret_cast<uint64_t>(target.region),
                               4096, snake::Protection::ReadWrite);
    check(protect.success, "SDK restore writable protection");
    sdk.close();
    std::cout << "PASS SDK native mprotect and register/code restoration\n";

    check(ioctl(fd.value, SNAKE_IOCTL_SHADOW_ALLOC, &allocation) == 0,
          "client-lifetime pinned allocation");
    check(mapped(target.pid, allocation.address), "pinned mapping retains a normal VMA");
    fd.reset(); other.reset();
    check(!mapped(target.pid, allocation.address), "close releases the pinned mapping");
    for (unsigned i = 0; i != 70; ++i) {
        Fd client(open("/dev/snakedrv", O_RDWR | O_CLOEXEC));
        attach(client.value, target.pid); scan(client.value, target.pid);
    }
    std::cout << "PASS close cleans cached results and attachments\n";
    {
        std::ofstream delay("/sys/module/snakedrv/parameters/test_worker_delay_ms"); delay << 6000;
    }
    Fd timeoutClient(open("/dev/snakedrv", O_RDWR | O_CLOEXEC));
    snake_inject_alloc alloc{}; alloc.pid = target.pid; alloc.size = 4096;
    alloc.protection = SNAKE_PROT_READ | SNAKE_PROT_WRITE;
    const auto originalMaps = maps(target.pid);
    errno = 0;
    check(ioctl(timeoutClient.value, SNAKE_IOCTL_INJECT_ALLOC, &alloc) == -1 && errno == ETIMEDOUT,
          "worker timeout");
    { std::ofstream delay("/sys/module/snakedrv/parameters/test_worker_delay_ms"); delay << 0; }
    timeoutClient.reset();
    check(syscall(SYS_delete_module, "snakedrv", 0) == 0, "drain abandoned worker on unload");
    check(maps(target.pid) == originalMaps, "abandoned mapping is reclaimed");
    std::cout << "PASS worker timeout, abandoned mapping cleanup and module unload\n";
}

int main() {
    if (getpid() != 1) {
        std::cerr << "Run only through scripts/test-kernel-runtime.py in an isolated VM\n";
        return 77;
    }
    mount("proc", "/proc", "proc", 0, nullptr);
    mount("sysfs", "/sys", "sysfs", 0, nullptr);
    mount("devtmpfs", "/dev", "devtmpfs", 0, nullptr);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    int result = 1;
    try {
        Fd module(open("/snakedrv.ko", O_RDONLY));
        check(syscall(SYS_finit_module, module.value, "event_queue_size=4 debug_level=0", 0) == 0, "load module");
        runtimeTests();
        pid_t native = fork();
        check(native >= 0, "fork native permissions test");
        if (!native) { execl("/test_protection", "/test_protection", nullptr); _exit(127); }
        int status = 0;
        check(waitpid(native, &status, 0) == native && WIFEXITED(status) && !WEXITSTATUS(status),
              "native page permission tests");
        result = 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL runtime: " << error.what() << '\n';
    }
    std::vector<char> log(1024 * 1024);
    int count = klogctl(3, log.data(), log.size() - 1);
    if (count > 0) {
        std::string messages(log.data(), count);
        for (const char* bad : {"BUG:", "Oops:", "use-after-free", "refcount_t:",
                                "sleeping function called", "list_del corruption"}) {
            if (messages.find(bad) != std::string::npos) result = 1;
        }
        if (result) std::cerr << messages;
    }
    std::cout << (result ? "SNAKEDRV_RUNTIME_FAIL\n" : "SNAKEDRV_RUNTIME_PASS\n");
    sync();
    syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_CMD_POWER_OFF, nullptr);
    for (;;) pause();
}
