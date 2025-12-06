/*
 * SnakeEngine Userland Library - Implementation
 * 
 * Copyright (c) 2024 SnakeEngine Project
 * Licensed under GPL v2
 */

#include "libsnakedrv.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <dirent.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>

namespace snake {

/* ============================================================================
 * Registers Implementation
 * ============================================================================ */

Registers Registers::from_kernel(const snake_cpu_regs& k) {
    Registers r;
    r.rax = k.rax; r.rbx = k.rbx; r.rcx = k.rcx; r.rdx = k.rdx;
    r.rsi = k.rsi; r.rdi = k.rdi; r.rbp = k.rbp; r.rsp = k.rsp;
    r.r8 = k.r8; r.r9 = k.r9; r.r10 = k.r10; r.r11 = k.r11;
    r.r12 = k.r12; r.r13 = k.r13; r.r14 = k.r14; r.r15 = k.r15;
    r.rip = k.rip;
    r.rflags = k.rflags;
    r.cs = k.cs; r.ss = k.ss; r.ds = k.ds; r.es = k.es; r.fs = k.fs; r.gs = k.gs;
    r.fs_base = k.fs_base; r.gs_base = k.gs_base;
    r.dr0 = k.dr0; r.dr1 = k.dr1; r.dr2 = k.dr2; r.dr3 = k.dr3;
    r.dr6 = k.dr6; r.dr7 = k.dr7;
    
    for(int i=0; i<16; i++) {
        r.xmm[i].low = k.xmm[i].low;
        r.xmm[i].high = k.xmm[i].high;
    }
    return r;
}

void Registers::to_kernel(snake_cpu_regs& k) const {
    k.rax = rax; k.rbx = rbx; k.rcx = rcx; k.rdx = rdx;
    k.rsi = rsi; k.rdi = rdi; k.rbp = rbp; k.rsp = rsp;
    k.r8 = r8; k.r9 = r9; k.r10 = r10; k.r11 = r11;
    k.r12 = r12; k.r13 = r13; k.r14 = r14; k.r15 = r15;
    k.rip = rip;
    k.rflags = rflags;
    k.cs = cs; k.ss = ss; k.ds = ds; k.es = es; k.fs = fs; k.gs = gs;
    k.fs_base = fs_base; k.gs_base = gs_base;
    k.dr0 = dr0; k.dr1 = dr1; k.dr2 = dr2; k.dr3 = dr3;
    k.dr6 = dr6; k.dr7 = dr7;
    
    for(int i=0; i<16; i++) {
        k.xmm[i].low = xmm[i].low;
        k.xmm[i].high = xmm[i].high;
    }
}

uint64_t Registers::get(const std::string& name) const {
    if (name == "rax") return rax;
    if (name == "rbx") return rbx;
    if (name == "rcx") return rcx;
    if (name == "rdx") return rdx;
    if (name == "rsi") return rsi;
    if (name == "rdi") return rdi;
    if (name == "rbp") return rbp;
    if (name == "rsp") return rsp;
    if (name == "r8") return r8;
    if (name == "r9") return r9;
    if (name == "r10") return r10;
    if (name == "r11") return r11;
    if (name == "r12") return r12;
    if (name == "r13") return r13;
    if (name == "r14") return r14;
    if (name == "r15") return r15;
    if (name == "rip") return rip;
    if (name == "rflags") return rflags;
    throw DriverException("Unknown register: " + name);
}

void Registers::set(const std::string& name, uint64_t value) {
    if (name == "rax") { rax = value; return; }
    if (name == "rbx") { rbx = value; return; }
    if (name == "rcx") { rcx = value; return; }
    if (name == "rdx") { rdx = value; return; }
    if (name == "rsi") { rsi = value; return; }
    if (name == "rdi") { rdi = value; return; }
    if (name == "rbp") { rbp = value; return; }
    if (name == "rsp") { rsp = value; return; }
    if (name == "r8") { r8 = value; return; }
    if (name == "r9") { r9 = value; return; }
    if (name == "r10") { r10 = value; return; }
    if (name == "r11") { r11 = value; return; }
    if (name == "r12") { r12 = value; return; }
    if (name == "r13") { r13 = value; return; }
    if (name == "r14") { r14 = value; return; }
    if (name == "r15") { r15 = value; return; }
    if (name == "rip") { rip = value; return; }
    if (name == "rflags") { rflags = value; return; }
    throw DriverException("Unknown register: " + name);
}

/* ============================================================================
 * DebugEvent Implementation
 * ============================================================================ */

DebugEvent DebugEvent::from_kernel(const snake_debug_event& k) {
    DebugEvent e;
    e.type = static_cast<EventType>(k.type);
    e.pid = k.pid;
    e.tid = k.tid;
    e.address = k.address;
    e.accessedAddress = k.accessed_address;
    e.bpSlot = k.bp_slot;
    e.bpId = k.bp_id;
    e.isWrite = (k.access_type == SNAKE_BP_TYPE_WRITE);
    e.accessSize = k.access_size;
    e.registers = Registers::from_kernel(k.regs);
    e.instruction.assign(k.instruction, k.instruction + k.instruction_len);
    e.timestamp = std::chrono::nanoseconds(k.timestamp);
    e.sequence = k.sequence;
    return e;
}

/* ============================================================================
 * Driver Implementation
 * ============================================================================ */

class Driver::Impl {
public:
    int fd = -1;
    ProcessId attached_pid = 0;
    std::atomic<bool> event_loop_running{false};
    std::thread event_thread;
    std::mutex callback_mutex;
    EventCallback event_callback;
    
    ~Impl() {
        stopEventLoop();
        if (fd >= 0) {
            ::close(fd);
        }
    }
    
    void stopEventLoop() {
        event_loop_running = false;
        if (event_thread.joinable()) {
            event_thread.join();
        }
    }
};

Driver::Driver() : impl_(std::make_unique<Impl>()) {}

Driver::~Driver() {
    if (impl_ && impl_->attached_pid > 0) {
        try { detach(); } catch (...) {}
    }
}

Driver::Driver(Driver&& other) noexcept = default;
Driver& Driver::operator=(Driver&& other) noexcept = default;

bool Driver::open() {
    if (impl_->fd >= 0) return true;
    
    impl_->fd = ::open(SNAKEDRV_DEVICE_PATH, O_RDWR);
    if (impl_->fd < 0) {
        return false;
    }
    return true;
}

void Driver::close() {
    if (impl_->attached_pid > 0) {
        detach();
    }
    if (impl_->fd >= 0) {
        ::close(impl_->fd);
        impl_->fd = -1;
    }
}

bool Driver::isOpen() const {
    return impl_->fd >= 0;
}

DriverInfo Driver::getInfo() const {
    if (!isOpen()) {
        throw DriverException("Driver not open");
    }
    
    snake_driver_info kinfo{};
    if (ioctl(impl_->fd, SNAKE_IOCTL_GET_INFO, &kinfo) < 0) {
        throw DriverException("Failed to get driver info", errno);
    }
    
    DriverInfo info;
    info.versionMajor = kinfo.version_major;
    info.versionMinor = kinfo.version_minor;
    info.versionPatch = kinfo.version_patch;
    info.versionString = kinfo.version_string;
    info.capabilities = kinfo.capabilities;
    info.maxBreakpoints = kinfo.max_breakpoints;
    info.maxAttached = kinfo.max_attached;
    info.kernelRelease = kinfo.kernel_release;
    info.pageSize = kinfo.page_size;
    
    return info;
}

bool Driver::attach(ProcessId pid) {
    if (!isOpen()) {
        throw DriverException("Driver not open");
    }
    
    if (impl_->attached_pid > 0) {
        detach();
    }
    
    snake_debug_attach attach{};
    attach.pid = pid;
    attach.flags = SNAKE_ATTACH_FLAG_ALL_THREADS;
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_DEBUG_ATTACH, &attach) < 0) {
        return false;
    }
    
    if (attach.result != SNAKEDRV_SUCCESS) {
        return false;
    }
    
    impl_->attached_pid = pid;
    return true;
}

void Driver::detach() {
    if (!isOpen() || impl_->attached_pid <= 0) return;
    
    impl_->stopEventLoop();
    
    snake_debug_control ctrl{};
    ctrl.pid = impl_->attached_pid;
    ctrl.operation = SNAKE_DBG_CTRL_DETACH;
    
    ioctl(impl_->fd, SNAKE_IOCTL_DEBUG_CONTROL, &ctrl);
    
    impl_->attached_pid = 0;
}

bool Driver::continueExecution(ThreadId tid) {
    if (!isAttached()) return false;
    snake_debug_control ctrl{};
    ctrl.pid = impl_->attached_pid;
    ctrl.tid = tid;
    ctrl.operation = SNAKE_DBG_CTRL_CONTINUE;
    return ioctl(impl_->fd, SNAKE_IOCTL_DEBUG_CONTROL, &ctrl) == 0;
}

bool Driver::singleStep(ThreadId tid) {
    if (!isAttached()) return false;
    snake_debug_control ctrl{};
    ctrl.pid = impl_->attached_pid;
    ctrl.tid = tid;
    ctrl.operation = SNAKE_DBG_CTRL_STEP;
    return ioctl(impl_->fd, SNAKE_IOCTL_DEBUG_CONTROL, &ctrl) == 0;
}

bool Driver::isAttached() const {
    return impl_->attached_pid > 0;
}

ProcessId Driver::attachedPid() const {
    return impl_->attached_pid;
}

size_t Driver::readMemory(Address address, void* buffer, size_t size) {
    if (!isAttached()) {
        throw NotAttachedException();
    }
    
    snake_memory_op op{};
    op.pid = impl_->attached_pid;
    op.address = address;
    op.size = size;
    op.user_buffer = reinterpret_cast<uint64_t>(buffer);
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_READ_MEMORY, &op) < 0) {
        return 0;
    }
    
    return op.result > 0 ? static_cast<size_t>(op.result) : 0;
}

size_t Driver::writeMemory(Address address, const void* buffer, size_t size) {
    if (!isAttached()) {
        throw NotAttachedException();
    }
    
    snake_memory_op op{};
    op.pid = impl_->attached_pid;
    op.address = address;
    op.size = size;
    op.user_buffer = reinterpret_cast<uint64_t>(buffer);
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_WRITE_MEMORY, &op) < 0) {
        return 0;
    }
    
    return op.result > 0 ? static_cast<size_t>(op.result) : 0;
}

std::vector<uint8_t> Driver::readBytes(Address address, size_t size) {
    std::vector<uint8_t> buffer(size);
    size_t read = readMemory(address, buffer.data(), size);
    buffer.resize(read);
    return buffer;
}

bool Driver::writeBytes(Address address, const std::vector<uint8_t>& data) {
    return writeMemory(address, data.data(), data.size()) == data.size();
}

std::string Driver::readString(Address address, size_t maxLength) {
    std::vector<char> buffer(maxLength + 1);
    size_t read = readMemory(address, buffer.data(), maxLength);
    buffer[read] = '\0';
    return std::string(buffer.data());
}

bool Driver::writeString(Address address, const std::string& str) {
    return writeMemory(address, str.c_str(), str.size() + 1) == str.size() + 1;
}

std::vector<uint8_t> Driver::readPhys(Address phys, size_t size) {
    std::vector<uint8_t> buffer(size);
    snake_phys_op op{};
    op.phys_address = phys;
    op.size = size;
    op.user_buffer = reinterpret_cast<uint64_t>(buffer.data());

    if (ioctl(impl_->fd, SNAKE_IOCTL_READ_PHYS, &op) < 0) {
        buffer.clear();
        return buffer;
    }
    buffer.resize(op.result > 0 ? static_cast<size_t>(op.result) : 0);
    return buffer;
}

bool Driver::writePhys(Address phys, const std::vector<uint8_t>& data) {
    snake_phys_op op{};
    op.phys_address = phys;
    op.size = data.size();
    op.user_buffer = reinterpret_cast<uint64_t>(data.data());
    return ioctl(impl_->fd, SNAKE_IOCTL_WRITE_PHYS, &op) == 0 && op.result == (int)data.size();
}

std::optional<snake_virt_to_phys> Driver::virtToPhys(Address virt) {
    if (!isAttached()) return std::nullopt;
    snake_virt_to_phys vtp{};
    vtp.pid = impl_->attached_pid;
    vtp.virt_address = virt;
    if (ioctl(impl_->fd, SNAKE_IOCTL_VIRT_TO_PHYS, &vtp) < 0) return std::nullopt;
    return vtp;
}

std::vector<MemoryRegion> Driver::queryMemoryRegions(Address start) {
    if (!isAttached()) {
        throw NotAttachedException();
    }
    
    std::vector<MemoryRegion> result;
    constexpr size_t MAX_REGIONS = 1024;
    
    std::vector<snake_memory_region> kregions(MAX_REGIONS);
    
    snake_memory_query query{};
    query.pid = impl_->attached_pid;
    query.start_address = start;
    query.max_regions = MAX_REGIONS;
    query.regions_buffer = reinterpret_cast<uint64_t>(kregions.data());
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_QUERY_MEMORY, &query) < 0) {
        return result;
    }
    
    // Cap on regions_found to avoid bad kernel data
    if (query.regions_found > MAX_REGIONS) {
        query.regions_found = MAX_REGIONS;
    }
    if (query.regions_found == 0) {
        return result;
    }
    
    result.reserve(query.regions_found);
    for (uint32_t i = 0; i < query.regions_found; i++) {
MemoryRegion region;
        region.base = kregions[i].base_address;
        region.size = kregions[i].size;
        region.protection = static_cast<Protection>(kregions[i].protection);
        region.type = kregions[i].type;
        region.offset = kregions[i].offset;
        region.inode = kregions[i].inode;
        region.pathname = kregions[i].pathname;
        result.push_back(region);
    }
    
    return result;
}

std::optional<MemoryRegion> Driver::findRegion(Address address) {
    auto regions = queryMemoryRegions();
    for (const auto& region : regions) {
        if (region.contains(address)) {
            return region;
        }
    }
    return std::nullopt;
}

std::optional<Breakpoint> Driver::setBreakpoint(Address address,
                                                BreakpointType type,
                                                BreakpointLength length) {
    if (!isAttached()) {
        throw NotAttachedException();
    }
    
    snake_hw_breakpoint kbp{};
    kbp.pid = impl_->attached_pid;
    kbp.address = address;
    kbp.type = static_cast<uint32_t>(type);
    kbp.length = static_cast<uint32_t>(length);
    kbp.enabled = 1;
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_SET_BREAKPOINT, &kbp) < 0) {
        return std::nullopt;
    }
    
    if (kbp.result != SNAKEDRV_SUCCESS) {
        return std::nullopt;
    }
    
    return Breakpoint(kbp.id, kbp.slot, address, type);
}

bool Driver::clearBreakpoint(const Breakpoint& bp) {
    return clearBreakpoint(bp.slot());
}

bool Driver::clearBreakpoint(uint32_t slot) {
    if (!isAttached()) {
        throw NotAttachedException();
    }
    
    snake_hw_breakpoint kbp{};
    kbp.pid = impl_->attached_pid;
    kbp.slot = slot;
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_CLEAR_BREAKPOINT, &kbp) < 0) {
        return false;
    }
    
    return kbp.result == SNAKEDRV_SUCCESS;
}

void Driver::clearAllBreakpoints() {
    for (uint32_t i = 0; i < 4; i++) {
        clearBreakpoint(i);
    }
}

bool Driver::suspend() {
    snake_process_op op{};
    op.pid = impl_->attached_pid;
    op.operation = SNAKE_PROC_OP_SUSPEND;
    return ioctl(impl_->fd, SNAKE_IOCTL_PROCESS_OP, &op) == 0 && op.result == SNAKEDRV_SUCCESS;
}

bool Driver::resume() {
    snake_process_op op{};
    op.pid = impl_->attached_pid;
    op.operation = SNAKE_PROC_OP_RESUME;
    return ioctl(impl_->fd, SNAKE_IOCTL_PROCESS_OP, &op) == 0 && op.result == SNAKEDRV_SUCCESS;
}

bool Driver::kill() {
    snake_process_op op{};
    op.pid = impl_->attached_pid;
    op.operation = SNAKE_PROC_OP_KILL;
    return ioctl(impl_->fd, SNAKE_IOCTL_PROCESS_OP, &op) == 0 && op.result == SNAKEDRV_SUCCESS;
}

std::optional<Registers> Driver::getRegisters(ThreadId tid) {
    if (!isAttached()) {
        return std::nullopt;
    }

    snake_regs_op op{};
    op.pid = impl_->attached_pid;
    op.tid = tid;

    if (ioctl(impl_->fd, SNAKE_IOCTL_GET_REGS, &op) < 0) {
        return std::nullopt;
    }

    return Registers::from_kernel(op.regs);
}

bool Driver::setRegisters(ThreadId tid, const Registers& regs) {
    if (!isAttached()) {
        return false;
    }

    snake_regs_op op{};
    op.pid = impl_->attached_pid;
    op.tid = tid;
    regs.to_kernel(op.regs);

    return ioctl(impl_->fd, SNAKE_IOCTL_SET_REGS, &op) == 0 && op.result == SNAKEDRV_SUCCESS;
}

std::vector<DebugEvent> Driver::pollEvents(uint32_t maxEvents,
                                           std::chrono::milliseconds timeout) {
    if (!isOpen()) {
        throw DriverException("Driver not open");
    }
    
    std::vector<DebugEvent> result;
    std::vector<snake_debug_event> kevents(maxEvents);
    
    snake_event_poll poll{};
    poll.max_events = maxEvents;
    poll.timeout_ms = static_cast<uint32_t>(timeout.count());
    poll.events_buffer = reinterpret_cast<uint64_t>(kevents.data());
    
    if (ioctl(impl_->fd, SNAKE_IOCTL_POLL_EVENTS, &poll) < 0) {
        return result;
    }
    
    result.reserve(poll.events_ready);
    for (uint32_t i = 0; i < poll.events_ready; i++) {
        result.push_back(DebugEvent::from_kernel(kevents[i]));
    }
    
    return result;
}

void Driver::setEventCallback(EventCallback callback) {
    std::lock_guard<std::mutex> lock(impl_->callback_mutex);
    impl_->event_callback = std::move(callback);
}

void Driver::clearEventCallback() {
    std::lock_guard<std::mutex> lock(impl_->callback_mutex);
    impl_->event_callback = nullptr;
}

void Driver::startEventLoop() {
    if (impl_->event_loop_running) return;
    
    impl_->event_loop_running = true;
    impl_->event_thread = std::thread([this]() {
        while (impl_->event_loop_running) {
            auto events = pollEvents(16, std::chrono::milliseconds(100));
            
            std::lock_guard<std::mutex> lock(impl_->callback_mutex);
            if (impl_->event_callback) {
                for (const auto& event : events) {
                    impl_->event_callback(event);
                }
            }
        }
    });
}

void Driver::stopEventLoop() {
    impl_->stopEventLoop();
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

bool isDriverAvailable() {
    return access(SNAKEDRV_DEVICE_PATH, F_OK) == 0;
}

std::optional<std::string> getDriverVersion() {
    int fd = ::open(SNAKEDRV_DEVICE_PATH, O_RDWR);
    if (fd < 0) return std::nullopt;
    
    snake_driver_info info{};
    int ret = ioctl(fd, SNAKE_IOCTL_GET_INFO, &info);
    ::close(fd);
    
    if (ret < 0) return std::nullopt;
    
    return std::string(info.version_string);
}

std::vector<ProcessInfo> listProcesses() {
    std::vector<ProcessInfo> result;
    
    DIR* dir = opendir("/proc");
    if (!dir) return result;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Check if this is a PID directory
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;
        
        ProcessInfo info;
        info.pid = static_cast<ProcessId>(pid);
        
        // Read process name
        std::string comm_path = "/proc/" + std::string(entry->d_name) + "/comm";
        std::ifstream comm_file(comm_path);
        if (comm_file.is_open()) {
            std::getline(comm_file, info.name);
        }
        
        // Read command line
        std::string cmdline_path = "/proc/" + std::string(entry->d_name) + "/cmdline";
        std::ifstream cmdline_file(cmdline_path);
        if (cmdline_file.is_open()) {
            std::getline(cmdline_file, info.cmdline);
            // Replace null bytes with spaces
            std::replace(info.cmdline.begin(), info.cmdline.end(), '\0', ' ');
        }
        
        result.push_back(info);
    }
    
    closedir(dir);
    return result;
}

std::vector<ProcessId> findProcessByName(const std::string& name) {
    std::vector<ProcessId> result;
    
    for (const auto& proc : listProcesses()) {
        if (proc.name.find(name) != std::string::npos ||
            proc.cmdline.find(name) != std::string::npos) {
            result.push_back(proc.pid);
        }
    }
    
    return result;
}

} // namespace snake
