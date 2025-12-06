/*
 * SnakeEngine Userland Library
 * 
 * C++ interface for communicating with the kernel driver
 * 
 * Copyright (c) 2024 SnakeEngine Project
 * Licensed under GPL v2
 */

#ifndef _LIBSNAKEDRV_HPP_
#define _LIBSNAKEDRV_HPP_

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <cstdint>

#include "snakedrv.h"

namespace snake {

/* ============================================================================
 * Exception Classes
 * ============================================================================ */

class DriverException : public std::exception {
public:
    explicit DriverException(const std::string& msg, int error_code = 0)
        : message_(msg), error_code_(error_code) {}
    
    const char* what() const noexcept override { return message_.c_str(); }
    int error_code() const noexcept { return error_code_; }
    
private:
    std::string message_;
    int error_code_;
};

class NotAttachedException : public DriverException {
public:
    NotAttachedException() : DriverException("Not attached to any process") {}
};

class PermissionException : public DriverException {
public:
    explicit PermissionException(const std::string& msg)
        : DriverException(msg, -EACCES) {}
};

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

using Address = uint64_t;
using ProcessId = pid_t;
using ThreadId = pid_t;

/**
 * Memory protection flags
 */
enum class Protection : uint32_t {
    None     = 0,
    Read     = SNAKE_PROT_READ,
    Write    = SNAKE_PROT_WRITE,
    Execute  = SNAKE_PROT_EXEC,
    Shared   = SNAKE_PROT_SHARED,
    Private  = SNAKE_PROT_PRIVATE,
    
    ReadWrite = Read | Write,
    ReadExecute = Read | Execute,
    ReadWriteExecute = Read | Write | Execute
};

inline Protection operator|(Protection a, Protection b) {
    return static_cast<Protection>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline Protection operator&(Protection a, Protection b) {
    return static_cast<Protection>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * Breakpoint types
 */
enum class BreakpointType : uint32_t {
    Execute   = SNAKE_BP_TYPE_EXEC,
    Write     = SNAKE_BP_TYPE_WRITE,
    ReadWrite = SNAKE_BP_TYPE_RW
};

/**
 * Breakpoint length
 */
enum class BreakpointLength : uint32_t {
    Byte1 = SNAKE_BP_LEN_1,
    Byte2 = SNAKE_BP_LEN_2,
    Byte4 = SNAKE_BP_LEN_4,
    Byte8 = SNAKE_BP_LEN_8
};

/**
 * Debug event types
 */
enum class EventType : uint32_t {
    None          = SNAKE_DBG_EVENT_NONE,
    Breakpoint    = SNAKE_DBG_EVENT_BREAKPOINT,
    Watchpoint    = SNAKE_DBG_EVENT_WATCHPOINT,
    SingleStep    = SNAKE_DBG_EVENT_SINGLESTEP,
    Exception     = SNAKE_DBG_EVENT_EXCEPTION,
    SyscallEnter  = SNAKE_DBG_EVENT_SYSCALL_ENTER,
    SyscallExit   = SNAKE_DBG_EVENT_SYSCALL_EXIT,
    Fork          = SNAKE_DBG_EVENT_FORK,
    Exec          = SNAKE_DBG_EVENT_EXEC,
    Exit          = SNAKE_DBG_EVENT_EXIT,
    Signal        = SNAKE_DBG_EVENT_SIGNAL
};

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Memory region information
 */
struct MemoryRegion {
    Address     base;
    uint64_t    size;
    Protection  protection;
    uint32_t    type;
    uint64_t    offset = 0;
    uint32_t    inode = 0;
    std::string pathname;
    
    Address end() const { return base + size; }
    bool contains(Address addr) const { return addr >= base && addr < end(); }
    bool isReadable() const {
        return (static_cast<uint32_t>(protection) & SNAKE_PROT_READ) != 0;
    }
    bool isWritable() const {
        return (static_cast<uint32_t>(protection) & SNAKE_PROT_WRITE) != 0;
    }
    bool isExecutable() const {
        return (static_cast<uint32_t>(protection) & SNAKE_PROT_EXEC) != 0;
    }
};

struct XmmRegister {
    uint64_t low;
    uint64_t high;
};

/**
 * CPU Register state
 */
struct Registers {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cs, ss, ds, es, fs, gs;
    uint64_t fs_base, gs_base;
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
    
    XmmRegister xmm[16];
    
    static Registers from_kernel(const snake_cpu_regs& kregs);
    void to_kernel(snake_cpu_regs& kregs) const;
    
    uint64_t get(const std::string& name) const;
    void set(const std::string& name, uint64_t value);
};

/**
 * Debug event
 */
struct DebugEvent {
    EventType       type;
    ProcessId       pid;
    ThreadId        tid;
    
    Address         address;         // Instruction address
    Address         accessedAddress; // Memory address (for watchpoints)
    
    uint32_t        bpSlot;
    uint32_t        bpId;
    bool            isWrite;
    uint32_t        accessSize;
    
    Registers       registers;
    std::vector<uint8_t> instruction;
    
    std::chrono::nanoseconds timestamp;
    uint32_t        sequence;
    
    static DebugEvent from_kernel(const snake_debug_event& kevent);
};

/**
 * Hardware breakpoint handle
 */
class Breakpoint {
public:
    Breakpoint() = default;
    Breakpoint(uint32_t id, uint32_t slot, Address addr, BreakpointType type)
        : id_(id), slot_(slot), address_(addr), type_(type), enabled_(true) {}
    
    uint32_t id() const { return id_; }
    uint32_t slot() const { return slot_; }
    Address address() const { return address_; }
    BreakpointType type() const { return type_; }
    bool isEnabled() const { return enabled_; }
    
private:
    friend class Driver;
    uint32_t id_ = 0;
    uint32_t slot_ = 0;
    Address address_ = 0;
    BreakpointType type_ = BreakpointType::Execute;
    bool enabled_ = false;
};

/**
 * Driver information
 */
struct DriverInfo {
    uint32_t versionMajor;
    uint32_t versionMinor;
    uint32_t versionPatch;
    std::string versionString;
    
    uint32_t capabilities;
    uint32_t maxBreakpoints;
    uint32_t maxAttached;
    
    std::string kernelRelease;
    uint32_t pageSize;
    
    bool hasCapability(uint32_t cap) const {
        return (capabilities & cap) != 0;
    }
};

/* ============================================================================
 * Main Driver Interface
 * ============================================================================ */

/**
 * Event callback type
 */
using EventCallback = std::function<void(const DebugEvent&)>;

/**
 * Main driver interface class
 */
class Driver {
public:
    Driver();
    ~Driver();
    
    // Non-copyable, movable
    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;
    Driver(Driver&& other) noexcept;
    Driver& operator=(Driver&& other) noexcept;
    
    /* Connection */
    bool open();
    void close();
    bool isOpen() const;
    
    /* Driver information */
    DriverInfo getInfo() const;
    
    /* Process attachment */
    bool attach(ProcessId pid);
    void detach();
    bool isAttached() const;
    ProcessId attachedPid() const;
    
    /* Memory operations */
    size_t readMemory(Address address, void* buffer, size_t size);
    size_t writeMemory(Address address, const void* buffer, size_t size);
    
    template<typename T>
    T read(Address address) {
        T value{};
        readMemory(address, &value, sizeof(T));
        return value;
    }
    
    template<typename T>
    bool write(Address address, const T& value) {
        return writeMemory(address, &value, sizeof(T)) == sizeof(T);
    }
    
    std::vector<uint8_t> readBytes(Address address, size_t size);
    bool writeBytes(Address address, const std::vector<uint8_t>& data);
    
    std::string readString(Address address, size_t maxLength = 256);
    bool writeString(Address address, const std::string& str);

    /* Physical memory */
    std::vector<uint8_t> readPhys(Address phys, size_t size);
    bool writePhys(Address phys, const std::vector<uint8_t>& data);

    /* Virtual to physical translation */
    std::optional<snake_virt_to_phys> virtToPhys(Address virt);
    
    /* Memory query */
    std::vector<MemoryRegion> queryMemoryRegions(Address start = 0);
    std::optional<MemoryRegion> findRegion(Address address);
    
    /* Hardware breakpoints */
    std::optional<Breakpoint> setBreakpoint(Address address, 
                                            BreakpointType type = BreakpointType::Execute,
                                            BreakpointLength length = BreakpointLength::Byte1);
    bool clearBreakpoint(const Breakpoint& bp);
    bool clearBreakpoint(uint32_t slot);
    void clearAllBreakpoints();
    
    /* Debug control */
    bool continueExecution(ThreadId tid = 0);
    bool singleStep(ThreadId tid = 0);
    bool suspend();
    bool resume();
    bool kill();
    
    /* Register access */
    std::optional<Registers> getRegisters(ThreadId tid = 0);
    bool setRegisters(ThreadId tid, const Registers& regs);
    
    /* Event polling */
    std::vector<DebugEvent> pollEvents(uint32_t maxEvents = 16,
                                       std::chrono::milliseconds timeout = std::chrono::milliseconds(0));
    
    /* Event callback (alternative to polling) */
    void setEventCallback(EventCallback callback);
    void clearEventCallback();
    void startEventLoop();
    void stopEventLoop();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Check if the driver is installed and accessible
 */
bool isDriverAvailable();

/**
 * Get driver version without opening it
 */
std::optional<std::string> getDriverVersion();

/**
 * List all processes
 */
struct ProcessInfo {
    ProcessId pid;
    std::string name;
    std::string cmdline;
};

std::vector<ProcessInfo> listProcesses();

/**
 * Find process by name
 */
std::vector<ProcessId> findProcessByName(const std::string& name);

} // namespace snake

#endif // _LIBSNAKEDRV_HPP_
