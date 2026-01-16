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

/**
 * class DriverException - Base exception type for driver errors
 */
class DriverException : public std::exception {
public:
    /**
     * DriverException - Create an exception with message and optional error code
     * @msg: Human-readable message
     * @error_code: Optional errno-style code
     */
    explicit DriverException(const std::string& msg, int error_code = 0)
        : message_(msg), error_code_(error_code) {}
    
    /**
     * what - Return the exception message
     * @return C-string message pointer
     */
    const char* what() const noexcept override { return message_.c_str(); }
    /**
     * error_code - Return the associated error code
     * @return errno-style error code
     */
    int error_code() const noexcept { return error_code_; }
    
private:
    std::string message_;
    int error_code_;
};

/**
 * class NotAttachedException - Thrown when no process is attached
 */
class NotAttachedException : public DriverException {
public:
    /**
     * NotAttachedException - Construct with a default message
     */
    NotAttachedException() : DriverException("Not attached to any process") {}
};

/**
 * class PermissionException - Thrown on permission-related failures
 */
class PermissionException : public DriverException {
public:
    /**
     * PermissionException - Construct with message and EACCES code
     * @msg: Human-readable message
     */
    explicit PermissionException(const std::string& msg)
        : DriverException(msg, -EACCES) {}
};

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

/**
 * Address - 64-bit virtual or physical address type
 */
using Address = uint64_t;
/**
 * ProcessId - Process identifier type
 */
using ProcessId = pid_t;
/**
 * ThreadId - Thread identifier type
 */
using ThreadId = pid_t;

/**
 * enum class Protection - Memory protection flags
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

/**
 * operator| - Combine protection flags
 * @a: First flag
 * @b: Second flag
 * @return Combined flags
 */
inline Protection operator|(Protection a, Protection b) {
    return static_cast<Protection>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * operator& - Intersect protection flags
 * @a: First flag
 * @b: Second flag
 * @return Intersection of flags
 */
inline Protection operator&(Protection a, Protection b) {
    return static_cast<Protection>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * enum class BreakpointType - Hardware breakpoint type
 */
enum class BreakpointType : uint32_t {
    Execute   = SNAKE_BP_TYPE_EXEC,
    Write     = SNAKE_BP_TYPE_WRITE,
    ReadWrite = SNAKE_BP_TYPE_RW
};

/**
 * enum class BreakpointLength - Hardware breakpoint length
 */
enum class BreakpointLength : uint32_t {
    Byte1 = SNAKE_BP_LEN_1,
    Byte2 = SNAKE_BP_LEN_2,
    Byte4 = SNAKE_BP_LEN_4,
    Byte8 = SNAKE_BP_LEN_8
};

/**
 * enum class EventType - Debug event type emitted by the driver
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
 * struct MemoryRegion - High-level memory region metadata
 * @base: Base address of the region
 * @size: Size of the region in bytes
 * @protection: Protection flags
 * @type: Region type (heap/stack/mmap/etc)
 * @offset: File offset for mapped files
 * @inode: Inode for file-backed regions
 * @pathname: Path of the mapped file (if any)
 */
struct MemoryRegion {
    Address     base;
    uint64_t    size;
    Protection  protection;
    uint32_t    type;
    uint64_t    offset = 0;
    uint32_t    inode = 0;
    std::string pathname;
    
    /**
     * end - Return the end address of the region (exclusive)
     * @return base + size
     */
    Address end() const { return base + size; }
    /**
     * contains - Check whether an address lies inside the region
     * @addr: Address to test
     * @return true if addr is within [base, end)
     */
    bool contains(Address addr) const { return addr >= base && addr < end(); }
    /**
     * isReadable - Check whether the region is readable
     * @return true if readable
     */
    bool isReadable() const {
        return (static_cast<uint32_t>(protection) & SNAKE_PROT_READ) != 0;
    }
    /**
     * isWritable - Check whether the region is writable
     * @return true if writable
     */
    bool isWritable() const {
        return (static_cast<uint32_t>(protection) & SNAKE_PROT_WRITE) != 0;
    }
    /**
     * isExecutable - Check whether the region is executable
     * @return true if executable
     */
    bool isExecutable() const {
        return (static_cast<uint32_t>(protection) & SNAKE_PROT_EXEC) != 0;
    }
};

/**
 * struct XmmRegister - 128-bit SIMD register (low/high parts)
 * @low: Lower 64 bits
 * @high: Upper 64 bits
 */
struct XmmRegister {
    uint64_t low;
    uint64_t high;
};

/**
 * struct Registers - Snapshot of x86_64 register state
 * @rax-r15: General purpose registers
 * @rip: Instruction pointer
 * @rflags: Flags register
 * @cs-ss-ds-es-fs-gs: Segment registers
 * @fs_base/gs_base: Segment base addresses
 * @dr0-dr7: Debug registers
 * @xmm: SIMD registers
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
    
    /**
     * from_kernel - Convert kernel register struct to C++ representation
     * @kregs: Kernel register payload
     * @return Converted Registers instance
     */
    static Registers from_kernel(const snake_cpu_regs& kregs);
    /**
     * to_kernel - Convert C++ registers to kernel wire format
     * @kregs: Destination kernel struct
     */
    void to_kernel(snake_cpu_regs& kregs) const;
    
    /**
     * get - Read a register by name (e.g. "rax", "rip")
     * @name: Register name
     * @return Register value
     */
    uint64_t get(const std::string& name) const;
    /**
     * set - Set a register by name (e.g. "rax", "rip")
     * @name: Register name
     * @value: New value
     */
    void set(const std::string& name, uint64_t value);
};

/**
 * struct DebugEvent - Driver debug/breakpoint event
 * @type: Event type
 * @pid: Process ID that triggered the event
 * @tid: Thread ID that triggered the event
 * @address: Instruction address
 * @accessedAddress: Accessed memory address (watchpoints)
 * @bpSlot: Hardware breakpoint slot (0-3)
 * @bpId: Breakpoint identifier
 * @isWrite: Whether the access was a write
 * @accessSize: Size of the memory access in bytes
 * @registers: CPU register snapshot at the event
 * @instruction: Instruction bytes (if provided)
 * @timestamp: Kernel timestamp
 * @sequence: Monotonic sequence number
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
    
    /**
     * from_kernel - Convert kernel event struct to C++ event
     * @kevent: Kernel event payload
     * @return Converted DebugEvent instance
     */
    static DebugEvent from_kernel(const snake_debug_event& kevent);
};

/**
 * class Breakpoint - Handle for a configured hardware breakpoint
 */
class Breakpoint {
public:
    /**
     * Breakpoint - Default constructor (invalid handle)
     */
    Breakpoint() = default;
    /**
     * Breakpoint - Construct an enabled breakpoint handle
     * @id: Breakpoint ID
     * @slot: Debug register slot (0-3)
     * @addr: Breakpoint address
     * @type: Breakpoint type
     */
    Breakpoint(uint32_t id, uint32_t slot, Address addr, BreakpointType type)
        : id_(id), slot_(slot), address_(addr), type_(type), enabled_(true) {}
    
    /**
     * id - Return breakpoint ID
     * @return Breakpoint ID
     */
    uint32_t id() const { return id_; }
    /**
     * slot - Return hardware slot index
     * @return DR slot index
     */
    uint32_t slot() const { return slot_; }
    /**
     * address - Return breakpoint address
     * @return Address
     */
    Address address() const { return address_; }
    /**
     * type - Return breakpoint type
     * @return BreakpointType
     */
    BreakpointType type() const { return type_; }
    /**
     * isEnabled - Check if breakpoint is enabled
     * @return true if enabled
     */
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
 * struct DriverInfo - Driver version and capability metadata
 * @versionMajor/versionMinor/versionPatch: Semantic version
 * @versionString: Version string from the driver
 * @capabilities: Bitmask of SNAKE_CAP_* capabilities
 * @maxBreakpoints: Maximum hardware breakpoints
 * @maxAttached: Maximum concurrent attachments
 * @kernelRelease: Kernel release string
 * @pageSize: System page size
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
    
    /**
     * hasCapability - Check for a capability bit
     * @cap: Capability bitmask
     * @return true if supported
     */
    bool hasCapability(uint32_t cap) const {
        return (capabilities & cap) != 0;
    }
};

/* ============================================================================
 * Main Driver Interface
 * ============================================================================ */

/**
 * EventCallback - Callback invoked for each DebugEvent
 */
using EventCallback = std::function<void(const DebugEvent&)>;

/**
 * struct InjectionResult - Result of an injection operation
 * @success: true on success
 * @address: Result address (if applicable)
 * @errorCode: Error code (0 or negative errno-style)
 * @errorMsg: Optional human-readable error message
 */
struct InjectionResult {
    bool success;
    Address address;
    int errorCode;
    std::string errorMsg;
};

/**
 * struct ExtendedProcessInfo - Process metadata collected by the driver
 * @pid: Process ID
 * @tgid: Thread group ID
 * @ppid: Parent PID
 * @startTime: Process start time (kernel units)
 * @startCode/endCode: Code segment bounds
 * @startStack: Stack start address
 * @name: Process name
 * @exePath: Executable path
 */
struct ExtendedProcessInfo {
    ProcessId pid;
    ProcessId tgid;
    ProcessId ppid;
    uint64_t startTime;
    uint64_t startCode;
    uint64_t endCode;
    uint64_t startStack;
    std::string name;
    std::string exePath;
};

/**
 * struct KernelThreadInfo - Thread metadata returned by the driver
 * @tid: Thread ID
 * @name: Thread name (comm)
 * @state: Thread state value (kernel-defined)
 * @kernelStack: Kernel stack pointer (if available)
 */
struct KernelThreadInfo {
    ThreadId tid;
    std::string name;
    uint64_t state;
    uint64_t kernelStack;
};

/**
 * class Driver - Main userland interface for the kernel driver
 */
class Driver {
public:
    // Nested type aliases for backward compatibility
    using InjectionResult = ::snake::InjectionResult;
    using ExtendedProcessInfo = ::snake::ExtendedProcessInfo;
    using KernelThreadInfo = ::snake::KernelThreadInfo;

    /**
     * Driver - Construct a driver handle (closed by default)
     */
    Driver();
    /**
     * ~Driver - Close driver handle and cleanup
     */
    ~Driver();

    // Non-copyable, movable
    /**
     * Driver - Copy is disabled to enforce single owner of the FD
     */
    Driver(const Driver&) = delete;
    /**
     * operator= - Copy assignment disabled
     */
    Driver& operator=(const Driver&) = delete;
    /**
     * Driver - Move constructor
     * @other: Source instance
     */
    Driver(Driver&& other) noexcept;
    /**
     * operator= - Move assignment
     * @other: Source instance
     * @return Reference to this
     */
    Driver& operator=(Driver&& other) noexcept;

    /* Connection */
    /**
     * open - Open /dev/snakedrv and validate availability
     * @return true on success
     */
    bool open();
    /**
     * close - Close the driver handle
     */
    void close();
    /**
     * isOpen - Check whether the handle is open
     * @return true if open
     */
    bool isOpen() const;
    
    /* Driver information */
    /**
     * getInfo - Query driver version and capabilities
     * @return DriverInfo structure
     */
    DriverInfo getInfo() const;
    
    /* Process attachment */
    /**
     * attach - Attach to a target process for subsequent operations
     * @pid: Target process ID
     * @return true on success
     */
    bool attach(ProcessId pid);
    /**
     * detach - Detach from the currently attached process
     */
    void detach();
    /**
     * isAttached - Check whether a process is attached
     * @return true if attached
     */
    bool isAttached() const;
    /**
     * attachedPid - Return the attached PID (0 if none)
     * @return Attached PID
     */
    ProcessId attachedPid() const;
    
    /* Memory operations */
    /**
     * readMemory - Read memory from the attached process
     * @address: Target address
     * @buffer: Destination buffer
     * @size: Number of bytes to read
     * @return Number of bytes read
     */
    size_t readMemory(Address address, void* buffer, size_t size);
    /**
     * writeMemory - Write memory to the attached process
     * @address: Target address
     * @buffer: Source buffer
     * @size: Number of bytes to write
     * @return Number of bytes written
     */
    size_t writeMemory(Address address, const void* buffer, size_t size);
    
    template<typename T>
    /**
     * read - Read a typed value from the attached process
     * @address: Target address
     * @return Value read
     */
    T read(Address address) {
        T value{};
        readMemory(address, &value, sizeof(T));
        return value;
    }
    
    template<typename T>
    /**
     * write - Write a typed value to the attached process
     * @address: Target address
     * @value: Value to write
     * @return true if all bytes were written
     */
    bool write(Address address, const T& value) {
        return writeMemory(address, &value, sizeof(T)) == sizeof(T);
    }
    
    /**
     * readBytes - Read a raw byte vector from the attached process
     * @address: Target address
     * @size: Number of bytes to read
     * @return Vector of bytes
     */
    std::vector<uint8_t> readBytes(Address address, size_t size);
    /**
     * writeBytes - Write raw bytes to the attached process
     * @address: Target address
     * @data: Bytes to write
     * @return true on success
     */
    bool writeBytes(Address address, const std::vector<uint8_t>& data);
    
    /**
     * readString - Read a null-terminated string
     * @address: Target address
     * @maxLength: Maximum bytes to read
     * @return String (possibly truncated)
     */
    std::string readString(Address address, size_t maxLength = 256);
    /**
     * writeString - Write a null-terminated string
     * @address: Target address
     * @str: String to write
     * @return true on success
     */
    bool writeString(Address address, const std::string& str);

    /* Physical memory */
    /**
     * readPhys - Read physical memory (requires capability)
     * @phys: Physical address
     * @size: Number of bytes
     * @return Vector of bytes
     */
    std::vector<uint8_t> readPhys(Address phys, size_t size);
    /**
     * writePhys - Write physical memory (requires capability)
     * @phys: Physical address
     * @data: Bytes to write
     * @return true on success
     */
    bool writePhys(Address phys, const std::vector<uint8_t>& data);

    /* Virtual to physical translation */
    /**
     * virtToPhys - Translate a virtual address to physical
     * @virt: Virtual address
     * @return Translation result or nullopt
     */
    std::optional<snake_virt_to_phys> virtToPhys(Address virt);
    
    /* Memory query */
    /**
     * queryMemoryRegions - Enumerate memory regions for the attached process
     * @start: Starting address (0 = from lowest mapping)
     * @return Vector of MemoryRegion entries
     */
    std::vector<MemoryRegion> queryMemoryRegions(Address start = 0);
    /**
     * findRegion - Find the region containing an address
     * @address: Address to locate
     * @return Region or nullopt if not found
     */
    std::optional<MemoryRegion> findRegion(Address address);
    
    /* Hardware breakpoints */
    /**
     * setBreakpoint - Configure a hardware breakpoint
     * @address: Target address
     * @type: Breakpoint type
     * @length: Breakpoint length
     * @return Breakpoint handle or nullopt on failure
     */
    std::optional<Breakpoint> setBreakpoint(Address address, 
                                            BreakpointType type = BreakpointType::Execute,
                                            BreakpointLength length = BreakpointLength::Byte1);
    /**
     * clearBreakpoint - Clear a breakpoint by handle
     * @bp: Breakpoint handle
     * @return true on success
     */
    bool clearBreakpoint(const Breakpoint& bp);
    /**
     * clearBreakpoint - Clear a breakpoint by slot index
     * @slot: DR slot index
     * @return true on success
     */
    bool clearBreakpoint(uint32_t slot);
    /**
     * clearAllBreakpoints - Remove all breakpoints for this process
     */
    void clearAllBreakpoints();
    
    /* Debug control */
    /**
     * continueExecution - Continue execution after a debug stop
     * @tid: Thread ID (0 = all)
     * @return true on success
     */
    bool continueExecution(ThreadId tid = 0);
    /**
     * singleStep - Single-step a thread
     * @tid: Thread ID (0 = leader)
     * @return true on success
     */
    bool singleStep(ThreadId tid = 0);
    /**
     * suspend - Suspend the attached process
     * @return true on success
     */
    bool suspend();
    /**
     * resume - Resume the attached process
     * @return true on success
     */
    bool resume();
    /**
     * kill - Terminate the attached process
     * @return true on success
     */
    bool kill();
    
    /* Register access */
    /**
     * getRegisters - Read registers from a thread
     * @tid: Thread ID (0 = leader)
     * @return Registers or nullopt on failure
     */
    std::optional<Registers> getRegisters(ThreadId tid = 0);
    /**
     * setRegisters - Write registers to a thread
     * @tid: Thread ID
     * @regs: Register values to write
     * @return true on success
     */
    bool setRegisters(ThreadId tid, const Registers& regs);
    
    /* Event polling */
    /**
     * pollEvents - Poll for debug events
     * @maxEvents: Maximum events to read
     * @timeout: Poll timeout (0 = non-blocking)
     * @return Vector of events
     */
    std::vector<DebugEvent> pollEvents(uint32_t maxEvents = 16,
                                       std::chrono::milliseconds timeout = std::chrono::milliseconds(0));
    
    /* Event callback (alternative to polling) */
    /**
     * setEventCallback - Set a callback for event loop delivery
     * @callback: Callback function
     */
    void setEventCallback(EventCallback callback);
    /**
     * clearEventCallback - Clear the event callback
     */
    void clearEventCallback();
    /**
     * startEventLoop - Start the background event loop
     */
    void startEventLoop();
    /**
     * stopEventLoop - Stop the background event loop
     */
    void stopEventLoop();

    /* Injection / Manual Mapping */
    /**
     * injectAlloc - Allocate memory in a remote process
     * @pid: Target process ID
     * @size: Allocation size in bytes
     * @prot: Initial protection flags
     * @return InjectionResult
     */
    InjectionResult injectAlloc(ProcessId pid, size_t size, Protection prot);
    /**
     * injectProtect - Change protection on a remote region
     * @pid: Target process ID
     * @address: Base address
     * @size: Size of the region
     * @prot: New protection flags
     * @return InjectionResult
     */
    InjectionResult injectProtect(ProcessId pid, Address address, size_t size, Protection prot);
    /**
     * injectThread - Start a thread in the target process
     * @pid: Target process ID
     * @entryPoint: Remote entry point address
     * @argument: Argument passed in RDI
     * @return InjectionResult
     */
    InjectionResult injectThread(ProcessId pid, Address entryPoint, uint64_t argument);
    /**
     * manualMapLibrary - Manual map an ELF shared object in the target
     * @pid: Target process ID
     * @libraryPath: Path to the shared library
     * @return InjectionResult
     */
    InjectionResult manualMapLibrary(ProcessId pid, const std::string& libraryPath);
    /**
     * executeShellcode - Allocate and execute raw shellcode
     * @pid: Target process ID
     * @shellcode: Byte buffer to execute
     * @argument: Argument passed to the entry
     * @return InjectionResult
     */
    InjectionResult executeShellcode(ProcessId pid, const std::vector<uint8_t>& shellcode, uint64_t argument);

    /* Process control */
    /**
     * suspendProcess - Suspend a process by PID
     * @pid: Target PID
     * @return true on success
     */
    bool suspendProcess(ProcessId pid);
    /**
     * resumeProcess - Resume a process by PID
     * @pid: Target PID
     * @return true on success
     */
    bool resumeProcess(ProcessId pid);
    /**
     * killProcess - Terminate a process by PID
     * @pid: Target PID
     * @return true on success
     */
    bool killProcess(ProcessId pid);

    /* Process information */
    /**
     * getProcessInfo - Query process metadata from the driver
     * @pid: Target PID
     * @return ExtendedProcessInfo or nullopt on failure
     */
    std::optional<ExtendedProcessInfo> getProcessInfo(ProcessId pid);
    /**
     * getKernelThreads - Query thread list from the driver
     *
     * Note: This is currently a stub and returns an empty list until
     * the kernel-side implementation is added.
     *
     * @pid: Target PID
     * @return Vector of KernelThreadInfo (currently empty)
     */
    std::vector<KernelThreadInfo> getKernelThreads(ProcessId pid);

    /* Internal - for Scanner access */
    /**
     * getFd - Return the underlying driver file descriptor
     * @return File descriptor (or -1 if closed)
     */
    int getFd() const;

private:
    friend class Scanner;  // Allow Scanner to access internals

    class Impl;
    std::unique_ptr<Impl> impl_;
};

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * isDriverAvailable - Check whether /dev/snakedrv exists
 * @return true if the device node is present
 */
bool isDriverAvailable();

/**
 * getDriverVersion - Query driver version without attaching
 * @return Version string if available
 */
std::optional<std::string> getDriverVersion();

/**
 * struct ProcessInfo - Minimal process metadata from /proc
 * @pid: Process ID
 * @name: Process comm value
 * @cmdline: Command line (space-normalized)
 */
struct ProcessInfo {
    ProcessId pid;
    std::string name;
    std::string cmdline;
};

/**
 * listProcesses - Enumerate processes via /proc
 * @return Vector of ProcessInfo entries
 */
std::vector<ProcessInfo> listProcesses();

/**
 * findProcessByName - Find PIDs with matching name
 * @name: Substring or exact process name to search for
 * @return Vector of PIDs
 */
std::vector<ProcessId> findProcessByName(const std::string& name);

} // namespace snake

#endif // _LIBSNAKEDRV_HPP_
