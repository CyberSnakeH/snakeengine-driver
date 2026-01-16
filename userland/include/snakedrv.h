/*
 * SnakeEngine Kernel Driver - Shared Header
 * 
 * Equivalent Linux de CheatEngine DBK Driver
 * 
 * Copyright (c) 2024 SnakeEngine Project
 * Licensed under GPL v2
 */

#ifndef _SNAKEDRV_H_
#define _SNAKEDRV_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#endif

/* ============================================================================
 * Version & Device Information
 * ============================================================================ */

#define SNAKEDRV_VERSION_MAJOR      1
#define SNAKEDRV_VERSION_MINOR      0
#define SNAKEDRV_VERSION_PATCH      0
#define SNAKEDRV_VERSION_STRING     "1.0.0"

#define SNAKEDRV_DEVICE_NAME        "snakedrv"
#define SNAKEDRV_DEVICE_PATH        "/dev/snakedrv"
#define SNAKEDRV_CLASS_NAME         "snakedrv"

/* Magic number for IOCTL - 0xSE for SnakeEngine */
#define SNAKEDRV_IOCTL_MAGIC        0x53

/* ============================================================================
 * Error Codes
 * ============================================================================ */

#define SNAKEDRV_SUCCESS            0
#define SNAKEDRV_ERROR_GENERIC      -1
#define SNAKEDRV_ERROR_NO_PROCESS   -2
#define SNAKEDRV_ERROR_NO_MEMORY    -3
#define SNAKEDRV_ERROR_PERMISSION   -4
#define SNAKEDRV_ERROR_INVALID_ARGS -5
#define SNAKEDRV_ERROR_NO_BP_SLOT   -6
#define SNAKEDRV_ERROR_NOT_ATTACHED -7
#define SNAKEDRV_ERROR_BUSY         -8
#define SNAKEDRV_ERROR_TIMEOUT      -9

/* ============================================================================
 * Memory Operations Structures
 * ============================================================================ */

/**
 * @struct snake_memory_op
 * @brief Memory read/write operation structure
 */
struct snake_memory_op {
    pid_t           pid;            /* Target process ID */
    uint64_t        address;        /* Target virtual address */
    uint64_t        size;           /* Size of operation in bytes */
    uint64_t        user_buffer;    /* Userland buffer pointer */
    int32_t         result;         /* Result: bytes read/written or error */
    uint32_t        flags;          /* Operation flags (see below) */
} __attribute__((packed));

/* Memory operation flags */
#define SNAKE_MEM_FLAG_FORCE        (1 << 0)    /* Bypass protection */
#define SNAKE_MEM_FLAG_PHYSICAL     (1 << 1)    /* Physical memory access */
#define SNAKE_MEM_FLAG_NO_CACHE     (1 << 2)    /* Non-cached access */
#define SNAKE_MEM_FLAG_ATOMIC       (1 << 3)    /* Atomic operation */

/**
 * @struct snake_memory_region
 * @brief Memory region information (like VirtualQueryEx)
 */
struct snake_memory_region {
    uint64_t        base_address;   /* Region base address */
    uint64_t        size;           /* Region size */
    uint32_t        protection;     /* Protection flags */
    uint32_t        type;           /* Region type */
    uint64_t        offset;         /* File offset if mapped */
    uint32_t        inode;          /* Inode if file-backed */
    char            pathname[256];  /* Pathname if mapped file */
} __attribute__((packed));

/* Protection flags */
#define SNAKE_PROT_READ             (1 << 0)
#define SNAKE_PROT_WRITE            (1 << 1)
#define SNAKE_PROT_EXEC             (1 << 2)
#define SNAKE_PROT_SHARED           (1 << 3)
#define SNAKE_PROT_PRIVATE          (1 << 4)
#define SNAKE_PROT_STEALTH          (1 << 5)    /* Remove from /proc/maps */

/* Region types */
#define SNAKE_REGION_UNKNOWN        0
#define SNAKE_REGION_HEAP           1
#define SNAKE_REGION_STACK          2
#define SNAKE_REGION_MMAP           3
#define SNAKE_REGION_VDSO           4
#define SNAKE_REGION_VSYSCALL       5

/**
 * @struct snake_memory_query
 * @brief Query memory regions of a process
 */
struct snake_memory_query {
    pid_t           pid;            /* Target process ID */
    uint64_t        start_address;  /* Start scanning from this address */
    uint32_t        max_regions;    /* Maximum regions to return */
    uint32_t        regions_found;  /* Actual regions found */
    uint64_t        regions_buffer; /* Pointer to array of snake_memory_region */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/* ============================================================================
 * Process Operations Structures
 * ============================================================================ */

/**
 * @struct snake_process_info
 * @brief Process information structure
 */
struct snake_process_info {
    pid_t           pid;            /* Process ID */
    pid_t           tgid;           /* Thread group ID */
    pid_t           ppid;           /* Parent PID */
    uid_t           uid;            /* User ID */
    gid_t           gid;            /* Group ID */
    uint64_t        start_time;     /* Process start time */
    uint64_t        mm_start_code;  /* Code segment start */
    uint64_t        mm_end_code;    /* Code segment end */
    uint64_t        mm_start_data;  /* Data segment start */
    uint64_t        mm_end_data;    /* Data segment end */
    uint64_t        mm_start_brk;   /* Heap start */
    uint64_t        mm_brk;         /* Current heap end */
    uint64_t        mm_start_stack; /* Stack start */
    char            comm[16];       /* Process name */
    char            exe_path[256];  /* Executable path */
} __attribute__((packed));

/**
 * @struct snake_process_op
 * @brief Process operation request
 */
struct snake_process_op {
    pid_t           pid;            /* Target process ID */
    uint32_t        operation;      /* Operation type */
    int32_t         result;         /* Result code */
    uint64_t        data;           /* Operation-specific data */
} __attribute__((packed));

/* Process operations */
#define SNAKE_PROC_OP_SUSPEND       1
#define SNAKE_PROC_OP_RESUME        2
#define SNAKE_PROC_OP_KILL          3
#define SNAKE_PROC_OP_GET_INFO      4
#define SNAKE_PROC_OP_LIST_THREADS  5

/**
 * @struct snake_thread_info
 * @brief Thread information structure
 */
struct snake_thread_info {
    pid_t           tid;            /* Thread ID */
    pid_t           tgid;           /* Thread group ID (PID) */
    uint32_t        state;          /* Thread state */
    int32_t         priority;       /* Thread priority */
    uint64_t        user_time;      /* User CPU time */
    uint64_t        system_time;    /* System CPU time */
    char            name[16];       /* Thread name */
} __attribute__((packed));

/* ============================================================================
 * Debug/Breakpoint Structures
 * ============================================================================ */

/* Hardware breakpoint types */
#define SNAKE_BP_TYPE_EXEC          0   /* Execute breakpoint */
#define SNAKE_BP_TYPE_WRITE         1   /* Write watchpoint */
#define SNAKE_BP_TYPE_RW            2   /* Read/Write watchpoint */
#define SNAKE_BP_TYPE_IO            3   /* I/O breakpoint (x86 specific) */

/* Hardware breakpoint lengths */
#define SNAKE_BP_LEN_1              0   /* 1 byte */
#define SNAKE_BP_LEN_2              1   /* 2 bytes */
#define SNAKE_BP_LEN_4              2   /* 4 bytes */
#define SNAKE_BP_LEN_8              3   /* 8 bytes */

/**
 * @struct snake_hw_breakpoint
 * @brief Hardware breakpoint configuration
 */
struct snake_hw_breakpoint {
    pid_t           pid;            /* Target process ID */
    pid_t           tid;            /* Target thread ID (0 = all threads) */
    uint64_t        address;        /* Breakpoint address */
    uint32_t        type;           /* Breakpoint type (SNAKE_BP_TYPE_*) */
    uint32_t        length;         /* Breakpoint length (SNAKE_BP_LEN_*) */
    uint32_t        slot;           /* DR slot (0-3, output) */
    uint32_t        enabled;        /* Enable/disable flag */
    int32_t         result;         /* Result code */
    uint32_t        id;             /* Unique breakpoint ID (output) */
} __attribute__((packed));

/**
 * @struct snake_xmm_reg
 * @brief 128-bit XMM register
 */
struct snake_xmm_reg {
    uint64_t low;
    uint64_t high;
} __attribute__((packed));

/**
 * @struct snake_cpu_regs
 * @brief Complete x86_64 CPU register state
 */
struct snake_cpu_regs {
    /* General purpose registers */
    uint64_t        rax, rbx, rcx, rdx;
    uint64_t        rsi, rdi, rbp, rsp;
    uint64_t        r8, r9, r10, r11;
    uint64_t        r12, r13, r14, r15;
    
    /* Instruction pointer & flags */
    uint64_t        rip;
    uint64_t        rflags;
    
    /* Segment registers */
    uint64_t        cs, ss, ds, es, fs, gs;
    uint64_t        fs_base, gs_base;
    
    /* Debug registers */
    uint64_t        dr0, dr1, dr2, dr3, dr6, dr7;
    
    /* Control registers (read-only from userland) */
    uint64_t        cr0, cr2, cr3, cr4;
    
    /* Original AX (for syscall restart) */
    uint64_t        orig_rax;
    
    /* FPU / SIMD Registers */
    struct snake_xmm_reg xmm[16];
} __attribute__((packed));

/**
 * @struct snake_regs_op
 * @brief Register operation wrapper (pid/tid + registers)
 */
struct snake_regs_op {
    pid_t               pid;    /* Target process ID */
    pid_t               tid;    /* Target thread ID (0 = leader) */
    struct snake_cpu_regs regs; /* Register payload */
    int32_t             result; /* Result code */
} __attribute__((packed));

/**
 * @struct snake_debug_event
 * @brief Debug event notification structure
 */
struct snake_debug_event {
    uint32_t        type;               /* Event type */
    pid_t           pid;                /* Process that triggered event */
    pid_t           tid;                /* Thread that triggered event */
    
    uint64_t        address;            /* Instruction address */
    uint64_t        accessed_address;   /* Memory address accessed (for watchpoints) */
    
    uint32_t        bp_slot;            /* Which DR slot triggered (0-3) */
    uint32_t        bp_id;              /* Breakpoint ID */
    uint32_t        access_type;        /* Read/Write/Execute */
    uint32_t        access_size;        /* Size of memory access */
    
    struct snake_cpu_regs   regs;       /* CPU state at event */
    
    uint8_t         instruction[16];    /* Instruction bytes */
    uint32_t        instruction_len;    /* Instruction length */
    
    uint64_t        timestamp;          /* Event timestamp (nanoseconds) */
    uint32_t        sequence;           /* Event sequence number */
    
    int32_t         result;             /* Reserved */
} __attribute__((packed));

/* Debug event types */
#define SNAKE_DBG_EVENT_NONE            0
#define SNAKE_DBG_EVENT_BREAKPOINT      1   /* Hardware breakpoint hit */
#define SNAKE_DBG_EVENT_WATCHPOINT      2   /* Watchpoint triggered */
#define SNAKE_DBG_EVENT_SINGLESTEP      3   /* Single step completed */
#define SNAKE_DBG_EVENT_EXCEPTION       4   /* Exception occurred */
#define SNAKE_DBG_EVENT_SYSCALL_ENTER   5   /* Syscall entry */
#define SNAKE_DBG_EVENT_SYSCALL_EXIT    6   /* Syscall exit */
#define SNAKE_DBG_EVENT_FORK            7   /* Fork/clone occurred */
#define SNAKE_DBG_EVENT_EXEC            8   /* Exec occurred */
#define SNAKE_DBG_EVENT_EXIT            9   /* Thread/process exit */
#define SNAKE_DBG_EVENT_SIGNAL          10  /* Signal delivered */

/**
 * @struct snake_debug_attach
 * @brief Attach to process for debugging
 */
struct snake_debug_attach {
    pid_t           pid;            /* Target process ID */
    uint32_t        flags;          /* Attach flags */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/* Attach flags */
#define SNAKE_ATTACH_FLAG_SUSPEND       (1 << 0)    /* Suspend on attach */
#define SNAKE_ATTACH_FLAG_NOSUSPEND     (1 << 1)    /* Don't suspend */
#define SNAKE_ATTACH_FLAG_ALL_THREADS   (1 << 2)    /* Attach all threads */
#define SNAKE_ATTACH_FLAG_KERNEL_MODE   (1 << 3)    /* Enable kernel mode features */

/**
 * @struct snake_debug_control
 * @brief Debug control operations
 */
struct snake_debug_control {
    pid_t           pid;            /* Target process */
    pid_t           tid;            /* Target thread (0 = all) */
    uint32_t        operation;      /* Control operation */
    uint32_t        flags;          /* Operation flags */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/* Debug control operations */
#define SNAKE_DBG_CTRL_CONTINUE         1   /* Continue execution */
#define SNAKE_DBG_CTRL_STEP             2   /* Single step */
#define SNAKE_DBG_CTRL_STOP             3   /* Stop/pause */
#define SNAKE_DBG_CTRL_DETACH           4   /* Detach from process */
#define SNAKE_DBG_CTRL_GET_REGS         5   /* Get registers */
#define SNAKE_DBG_CTRL_SET_REGS         6   /* Set registers */

/**
 * @struct snake_event_poll
 * @brief Poll for debug events
 */
struct snake_event_poll {
    uint32_t        max_events;     /* Max events to return */
    uint32_t        timeout_ms;     /* Timeout in milliseconds (0 = non-blocking) */
    uint32_t        events_ready;   /* Number of events ready */
    uint64_t        events_buffer;  /* Pointer to array of snake_debug_event */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/* ============================================================================
 * Physical Memory Operations
 * ============================================================================ */

/**
 * @struct snake_phys_op
 * @brief Physical memory operation
 */
struct snake_phys_op {
    uint64_t        phys_address;   /* Physical address */
    uint64_t        size;           /* Size of operation */
    uint64_t        user_buffer;    /* Userland buffer */
    uint32_t        flags;          /* Operation flags */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/**
 * @struct snake_virt_to_phys
 * @brief Virtual to physical address translation
 */
struct snake_virt_to_phys {
    pid_t           pid;            /* Process ID */
    uint64_t        virt_address;   /* Virtual address */
    uint64_t        phys_address;   /* Physical address (output) */
    uint64_t        page_offset;    /* Offset within page */
    uint32_t        page_size;      /* Page size */
    uint32_t        flags;          /* Page flags (present, writable, etc.) */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/* ============================================================================
 * Driver Information
 * ============================================================================ */

/**
 * @struct snake_driver_info
 * @brief Driver information and capabilities
 */
struct snake_driver_info {
    uint32_t        version_major;
    uint32_t        version_minor;
    uint32_t        version_patch;
    char            version_string[32];
    
    uint32_t        capabilities;   /* Capability flags */
    uint32_t        max_breakpoints;/* Maximum hardware breakpoints */
    uint32_t        max_attached;   /* Maximum attached processes */
    
    uint64_t        kernel_version; /* Running kernel version */
    char            kernel_release[64];
    
    uint32_t        arch;           /* Architecture (x86_64 = 1) */
    uint32_t        page_size;      /* System page size */
    
    int32_t         result;
} __attribute__((packed));

/* Capability flags */
#define SNAKE_CAP_HW_BREAKPOINTS    (1 << 0)    /* Hardware breakpoints */
#define SNAKE_CAP_PHYS_MEMORY       (1 << 1)    /* Physical memory access */
#define SNAKE_CAP_KERNEL_SYMBOLS    (1 << 2)    /* Kernel symbol resolution */
#define SNAKE_CAP_PAGE_TABLE_WALK   (1 << 3)    /* Page table walking */
#define SNAKE_CAP_MSR_ACCESS        (1 << 4)    /* MSR read/write */
#define SNAKE_CAP_PROCESS_SUSPEND   (1 << 5)    /* Process suspend/resume */
#define SNAKE_CAP_SYSCALL_TRACE     (1 << 6)    /* Syscall tracing */
#define SNAKE_CAP_MULTITHREAD       (1 << 7)    /* Multi-thread support */

/* ============================================================================
 * IOCTL Definitions
 * ============================================================================ */

/* Memory operations */
#define SNAKE_IOCTL_READ_MEMORY     _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x01, struct snake_memory_op)
#define SNAKE_IOCTL_WRITE_MEMORY    _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x02, struct snake_memory_op)
#define SNAKE_IOCTL_QUERY_MEMORY    _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x03, struct snake_memory_query)

/* Physical memory operations */
#define SNAKE_IOCTL_READ_PHYS       _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x10, struct snake_phys_op)
#define SNAKE_IOCTL_WRITE_PHYS      _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x11, struct snake_phys_op)
#define SNAKE_IOCTL_VIRT_TO_PHYS    _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x12, struct snake_virt_to_phys)

/* Process operations */
#define SNAKE_IOCTL_PROCESS_OP      _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x20, struct snake_process_op)
#define SNAKE_IOCTL_GET_PROC_INFO   _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x21, struct snake_process_info)

/* Debug operations */
#define SNAKE_IOCTL_DEBUG_ATTACH    _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x30, struct snake_debug_attach)
#define SNAKE_IOCTL_DEBUG_CONTROL   _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x31, struct snake_debug_control)
#define SNAKE_IOCTL_SET_BREAKPOINT  _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x32, struct snake_hw_breakpoint)
#define SNAKE_IOCTL_CLEAR_BREAKPOINT _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x33, struct snake_hw_breakpoint)
#define SNAKE_IOCTL_POLL_EVENTS     _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x34, struct snake_event_poll)
#define SNAKE_IOCTL_GET_REGS        _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x35, struct snake_regs_op)
#define SNAKE_IOCTL_SET_REGS        _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x36, struct snake_regs_op)

/* Driver info */
#define SNAKE_IOCTL_GET_INFO        _IOR(SNAKEDRV_IOCTL_MAGIC, 0x40, struct snake_driver_info)

/* ============================================================================
 * Injection Operations (Manual Mapping)
 * ============================================================================ */

/**
 * @struct snake_inject_alloc
 * @brief Allocate memory in target process (stealth)
 */
struct snake_inject_alloc {
    pid_t           pid;            /* Target process ID */
    uint64_t        size;           /* Size to allocate */
    uint32_t        protection;     /* Initial protection (usually RW) */
    uint64_t        address;        /* Output: Allocated address */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/**
 * @struct snake_inject_protect
 * @brief Change memory protection (e.g., RW -> RX)
 */
struct snake_inject_protect {
    pid_t           pid;            /* Target process ID */
    uint64_t        address;        /* Address to protect */
    uint64_t        size;           /* Size of region */
    uint32_t        protection;     /* New protection flags */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/**
 * @struct snake_inject_thread
 * @brief Create a remote thread to execute code
 */
struct snake_inject_thread {
    pid_t           pid;            /* Target process ID */
    uint64_t        start_address;  /* Code entry point */
    uint64_t        argument;       /* Argument for function (RDI) */
    int32_t         result;         /* Result code */
} __attribute__((packed));

/* Injection operations */
#define SNAKE_IOCTL_INJECT_ALLOC    _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x60, struct snake_inject_alloc)
#define SNAKE_IOCTL_INJECT_PROTECT  _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x61, struct snake_inject_protect)
#define SNAKE_IOCTL_INJECT_THREAD   _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x62, struct snake_inject_thread)
#define SNAKE_IOCTL_INJECT_STEALTH  _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x63, struct snake_inject_protect)

/* ============================================================================
 * Netlink Protocol for Async Events
 * ============================================================================ */

#define SNAKE_NETLINK_FAMILY_NAME   "SNAKEDRV"
#define SNAKE_NETLINK_VERSION       1

/**
 * enum snake_netlink_cmd - Netlink command identifiers
 */
enum snake_netlink_cmd {
    SNAKE_NL_CMD_UNSPEC = 0,
    SNAKE_NL_CMD_SUBSCRIBE,         /* Subscribe to events */
    SNAKE_NL_CMD_UNSUBSCRIBE,       /* Unsubscribe from events */
    SNAKE_NL_CMD_EVENT,             /* Event notification (kernel -> user) */
    __SNAKE_NL_CMD_MAX,
};

/**
 * enum snake_netlink_attr - Netlink attribute identifiers
 */
enum snake_netlink_attr {
    SNAKE_NL_ATTR_UNSPEC = 0,
    SNAKE_NL_ATTR_PID,              /* Target PID */
    SNAKE_NL_ATTR_EVENT_TYPE,       /* Event type */
    SNAKE_NL_ATTR_EVENT_DATA,       /* Event data (snake_debug_event) */
    SNAKE_NL_ATTR_SUBSCRIBE_MASK,   /* Event subscription mask */
    __SNAKE_NL_ATTR_MAX,
};

#define SNAKE_NL_ATTR_MAX (__SNAKE_NL_ATTR_MAX - 1)

#endif /* _SNAKEDRV_H_ */
