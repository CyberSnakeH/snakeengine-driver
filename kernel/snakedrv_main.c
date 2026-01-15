// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver
 * Linux equivalent of CheatEngine DBK Driver
 * 
 * Provides kernel-level memory access and hardware debugging
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/utsname.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <asm/ptrace.h>
#include <linux/pagewalk.h>
#include <linux/mm_types.h>
#include <linux/mmzone.h>
#include <linux/mmu_notifier.h>
#include <linux/mm_inline.h>
#include <linux/mmu_context.h>
#include <linux/cred.h>
#include <linux/thread_info.h>
#include <asm/processor.h>

/* Include shared headers with userland */
#include "../userland/include/snakedrv.h"
#include "../userland/include/snakedrv_scanner.h"

/* Include kernel headers */
#include "snakedrv_backend.h"
#include "snakedrv_scanner.h"
#include "snakedrv_injector.h"

/* Forward declarations for backend private data */
struct process_context {
    pid_t pid;
    struct task_struct *task;
    struct mm_struct *mm;
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SnakeEngine Project");
MODULE_DESCRIPTION("SnakeEngine Kernel Driver - Memory and Debug Operations");
MODULE_VERSION(SNAKEDRV_VERSION_STRING);

/* ============================================================================
 * Kernel Version Compatibility
 * ============================================================================ */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_lock(mm)      down_read(&(mm)->mmap_sem)
#define mmap_read_unlock(mm)    up_read(&(mm)->mmap_sem)
#endif

/* Hardware breakpoint count (x86 has 4: DR0-DR3) */
#ifndef HBP_NUM
#define HBP_NUM 4
#endif

/* ============================================================================
 * Module Parameters
 * ============================================================================ */

static int param_max_attached = 16;
module_param_named(max_attached_processes, param_max_attached, int, 0644);
MODULE_PARM_DESC(param_max_attached, "Maximum attached processes (default: 16)");

static int param_debug = 1;
module_param_named(debug_level, param_debug, int, 0644);
MODULE_PARM_DESC(param_debug, "Debug level 0-3 (default: 1)");

static int param_event_queue_size = 256;
module_param_named(event_queue_size, param_event_queue_size, int, 0644);
MODULE_PARM_DESC(param_event_queue_size, "Maximum pending debug events (default: 256)");

/* ============================================================================
 * Debug Macros
 * ============================================================================ */

#define SDRV_INFO(fmt, ...) \
    do { if (param_debug >= 1) pr_info("snakedrv: " fmt, ##__VA_ARGS__); } while (0)

#define SDRV_DEBUG(fmt, ...) \
    do { if (param_debug >= 2) pr_info("snakedrv: [DBG] " fmt, ##__VA_ARGS__); } while (0)

#define SDRV_ERR(fmt, ...) \
    pr_err("snakedrv: [ERR] " fmt, ##__VA_ARGS__)

/* ============================================================================
 * Global State
 * ============================================================================ */

static dev_t snakedrv_devnum;
static struct cdev snakedrv_cdev;
static struct class *snakedrv_class;
static struct device *snakedrv_device;

/* Attached processes */
static DEFINE_MUTEX(attach_mutex);
static LIST_HEAD(attached_list);
static atomic_t attached_count = ATOMIC_INIT(0);

/* Debug events */
static DEFINE_SPINLOCK(event_lock);
static LIST_HEAD(event_list);
static DECLARE_WAIT_QUEUE_HEAD(event_waitq);
static atomic_t event_count = ATOMIC_INIT(0);
static uint32_t event_sequence;

/* ============================================================================
 * Data Structures
 * ============================================================================ */

struct bp_slot {
    bool used;
    uint32_t id;
    uint64_t address;
    uint32_t type;
    uint32_t length;
    pid_t tid;
    bool enabled;
    struct perf_event *perf_bp;
};

struct attached_proc {
    struct list_head list;
    pid_t pid;
    struct file *owner;

    /* Unified backend abstraction */
    struct memory_backend *backend;

    struct bp_slot bp_slots[HBP_NUM];
    atomic_t refcount;
    uint64_t read_ops;
    uint64_t write_ops;
};

struct event_entry {
    struct list_head list;
    struct snake_debug_event event;
};

/* ============================================================================
 * Process Management
 * ============================================================================ */

static struct attached_proc *find_proc_locked(pid_t pid)
{
    struct attached_proc *p;
    list_for_each_entry(p, &attached_list, list) {
        if (p->pid == pid)
            return p;
    }
    return NULL;
}

static struct attached_proc *get_proc(pid_t pid)
{
    struct attached_proc *p;
    mutex_lock(&attach_mutex);
    p = find_proc_locked(pid);
    if (p)
        atomic_inc(&p->refcount);
    mutex_unlock(&attach_mutex);
    return p;
}

static void put_proc(struct attached_proc *p)
{
    if (p)
        atomic_dec(&p->refcount);
}

static void cleanup_breakpoints(struct attached_proc *p)
{
    int i;
    
    for (i = 0; i < HBP_NUM; i++) {
        if (!p->bp_slots[i].used)
            continue;
        
        if (p->bp_slots[i].perf_bp) {
            unregister_hw_breakpoint(p->bp_slots[i].perf_bp);
            p->bp_slots[i].perf_bp = NULL;
        }
        p->bp_slots[i].used = false;
    }
}

/* ============================================================================
 * Memory Operations
 * ============================================================================ */

static ssize_t do_read_memory(struct attached_proc *p, uint64_t addr,
                              void *buf, size_t len)
{
    ssize_t ret;

    if (!p->backend)
        return -EINVAL;

    ret = backend_read(p->backend, addr, buf, len);

    if (ret > 0)
        p->read_ops++;

    return ret;
}

static ssize_t do_write_memory(struct attached_proc *p, uint64_t addr,
                               const void *buf, size_t len)
{
    ssize_t ret;

    if (!p->backend)
        return -EINVAL;

    ret = backend_write(p->backend, addr, buf, len);

    if (ret > 0)
        p->write_ops++;

    return ret;
}

static int do_query_regions(pid_t pid, struct snake_memory_query __user *uquery)
{
    struct snake_memory_query query;
    struct snake_memory_region *regions;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uint32_t count = 0;
    int ret = 0;
    
    if (copy_from_user(&query, uquery, sizeof(query)))
        return -EFAULT;
    
    if (query.max_regions == 0 || query.max_regions > 4096)
        return -EINVAL;
    
    regions = kvzalloc(sizeof(*regions) * query.max_regions, GFP_KERNEL);
    if (!regions)
        return -ENOMEM;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        kvfree(regions);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();
    
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        kvfree(regions);
        return -EINVAL;
    }
    
    mmap_read_lock(mm);
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, query.start_address);
        for_each_vma(vmi, vma) {
            if (count >= query.max_regions)
                break;
            
            regions[count].base_address = vma->vm_start;
            regions[count].size = vma->vm_end - vma->vm_start;
            regions[count].protection = 0;
            
            if (vma->vm_flags & VM_READ)
                regions[count].protection |= SNAKE_PROT_READ;
            if (vma->vm_flags & VM_WRITE)
                regions[count].protection |= SNAKE_PROT_WRITE;
            if (vma->vm_flags & VM_EXEC)
                regions[count].protection |= SNAKE_PROT_EXEC;
            if (vma->vm_flags & VM_SHARED)
                regions[count].protection |= SNAKE_PROT_SHARED;
            else
                regions[count].protection |= SNAKE_PROT_PRIVATE;
            
            regions[count].type = SNAKE_REGION_UNKNOWN;
            regions[count].offset = (uint64_t)vma->vm_pgoff << PAGE_SHIFT;
            regions[count].inode = 0;
            
            if (vma->vm_file) {
                char *tmp = kmalloc(256, GFP_KERNEL);
                if (tmp) {
                    char *path = d_path(&vma->vm_file->f_path, tmp, 256);
                    if (!IS_ERR(path))
                        strscpy(regions[count].pathname, path,
                               sizeof(regions[count].pathname));
                    kfree(tmp);
                }
                regions[count].inode = (uint32_t)vma->vm_file->f_inode->i_ino;
                regions[count].type = SNAKE_REGION_MMAP;
            } else if (is_vmalloc_addr((void *)vma->vm_start)) {
                regions[count].type = SNAKE_REGION_UNKNOWN;
            } else if (vma->vm_flags & VM_GROWSDOWN) {
                regions[count].type = SNAKE_REGION_STACK;
                strscpy(regions[count].pathname, "[stack]", sizeof(regions[count].pathname));
            } else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
                regions[count].type = SNAKE_REGION_HEAP;
                strscpy(regions[count].pathname, "[heap]", sizeof(regions[count].pathname));
            } else if (vma->vm_flags & VM_SPECIAL) {
                strscpy(regions[count].pathname, "[vdso]", sizeof(regions[count].pathname));
                regions[count].type = SNAKE_REGION_VDSO;
            }
            count++;
        }
    }
#else
    for (vma = mm->mmap; vma && count < query.max_regions; vma = vma->vm_next) {
        if (vma->vm_start < query.start_address)
            continue;
        
        regions[count].base_address = vma->vm_start;
        regions[count].size = vma->vm_end - vma->vm_start;
        regions[count].protection = 0;
        
        if (vma->vm_flags & VM_READ)
            regions[count].protection |= SNAKE_PROT_READ;
        if (vma->vm_flags & VM_WRITE)
            regions[count].protection |= SNAKE_PROT_WRITE;
        if (vma->vm_flags & VM_EXEC)
            regions[count].protection |= SNAKE_PROT_EXEC;
        if (vma->vm_flags & VM_SHARED)
            regions[count].protection |= SNAKE_PROT_SHARED;
        else
            regions[count].protection |= SNAKE_PROT_PRIVATE;
        
        regions[count].offset = (uint64_t)vma->vm_pgoff << PAGE_SHIFT;
        regions[count].inode = 0;
        regions[count].type = SNAKE_REGION_UNKNOWN;
        if (vma->vm_file) {
            char *tmp = kmalloc(256, GFP_KERNEL);
            if (tmp) {
                char *path = d_path(&vma->vm_file->f_path, tmp, 256);
                if (!IS_ERR(path))
                    strscpy(regions[count].pathname, path,
                           sizeof(regions[count].pathname));
                kfree(tmp);
            }
            regions[count].inode = (uint32_t)vma->vm_file->f_inode->i_ino;
            regions[count].type = SNAKE_REGION_MMAP;
        } else if (vma->vm_flags & VM_GROWSDOWN) {
            regions[count].type = SNAKE_REGION_STACK;
            strscpy(regions[count].pathname, "[stack]", sizeof(regions[count].pathname));
        } else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
            regions[count].type = SNAKE_REGION_HEAP;
            strscpy(regions[count].pathname, "[heap]", sizeof(regions[count].pathname));
        } else if (vma->vm_flags & VM_SPECIAL) {
            regions[count].type = SNAKE_REGION_VDSO;
            strscpy(regions[count].pathname, "[vdso]", sizeof(regions[count].pathname));
        }
        count++;
    }
#endif
    
    mmap_read_unlock(mm);
    mmput(mm);
    
    if (copy_to_user((void __user *)query.regions_buffer, regions,
                     sizeof(*regions) * count)) {
        ret = -EFAULT;
    } else {
        query.regions_found = count;
        query.result = SNAKEDRV_SUCCESS;
        if (copy_to_user(uquery, &query, sizeof(query)))
            ret = -EFAULT;
    }
    
    kvfree(regions);
    return ret;
}

/* ============================================================================
 * Helpers for attached tasks / threads
 * ============================================================================ */

static struct task_struct *get_thread_task(struct attached_proc *p, pid_t tid)
{
    struct task_struct *task = NULL;
    pid_t target = tid ? tid : p->pid;

    rcu_read_lock();
    task = pid_task(find_vpid(target), PIDTYPE_PID);
    if (task && task->tgid != p->pid)
        task = NULL;
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    return task;
}

/* ============================================================================
 * Physical memory and translation
 * ============================================================================ */

static ssize_t do_read_phys(uint64_t phys, void *buf, size_t size)
{
    void __iomem *io = memremap(phys, size, MEMREMAP_WB);
    if (!io)
        return -ENOMEM;
    memcpy_fromio(buf, io, size);
    memunmap(io);
    return size;
}

static ssize_t do_write_phys(uint64_t phys, const void *buf, size_t size)
{
    void __iomem *io = memremap(phys, size, MEMREMAP_WB);
    if (!io)
        return -ENOMEM;
    memcpy_toio(io, buf, size);
    memunmap(io);
    return size;
}

static int do_virt_to_phys(struct attached_proc *p, struct snake_virt_to_phys *vtp)
{
    struct mm_struct *mm;
    struct page *page = NULL;
    unsigned long addr = vtp->virt_address & PAGE_MASK;
    struct process_context *proc_ctx;
    int ret = 0;

    if (!p || !p->backend)
        return -EINVAL;

    /* Only process backend supports VA->PA translation */
    if (p->backend->type != BACKEND_TYPE_PROCESS)
        return -ENOSYS;

    /* Get process context from backend */
    proc_ctx = (struct process_context *)p->backend->private_data;
    if (!proc_ctx || !proc_ctx->task)
        return -EINVAL;

    mm = get_task_mm(proc_ctx->task);
    if (!mm)
        return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    {
        long pinned = get_user_pages_remote(mm, addr, 1,
                                            FOLL_GET, &page, NULL);
        if (pinned != 1) {
            mmput(mm);
            return -EFAULT;
        }
    }
#else
    {
        int pinned = get_user_pages_remote(mm, addr, 1, 1, 0, &page, NULL);
        if (pinned != 1) {
            mmput(mm);
            return -EFAULT;
        }
    }
#endif

    vtp->phys_address = page_to_phys(page) + (vtp->virt_address & (PAGE_SIZE - 1));
    vtp->page_offset = vtp->virt_address & (PAGE_SIZE - 1);
    vtp->page_size = PAGE_SIZE;
    vtp->flags = page->flags;
    vtp->result = SNAKEDRV_SUCCESS;

    put_page(page);
    mmput(mm);
    return ret;
}

/* ============================================================================
 * Register access
 * ============================================================================ */

static void fill_regs_from_task(struct task_struct *task, struct snake_cpu_regs *out)
{
    struct pt_regs *regs = task_pt_regs(task);
    if (!regs || !out)
        return;

    out->rax = regs->ax;
    out->rbx = regs->bx;
    out->rcx = regs->cx;
    out->rdx = regs->dx;
    out->rsi = regs->si;
    out->rdi = regs->di;
    out->rbp = regs->bp;
    out->rsp = regs->sp;
    out->rip = regs->ip;
    out->rflags = regs->flags;
#ifdef CONFIG_X86_64
    out->r8  = regs->r8;
    out->r9  = regs->r9;
    out->r10 = regs->r10;
    out->r11 = regs->r11;
    out->r12 = regs->r12;
    out->r13 = regs->r13;
    out->r14 = regs->r14;
    out->r15 = regs->r15;
#endif
    out->cs = regs->cs;
    out->ss = regs->ss;
    out->ds = 0;
    out->es = 0;
    out->fs = 0;
    out->gs = 0;
    out->fs_base = 0;
    out->gs_base = 0;

    out->dr0 = 0;
    out->dr1 = 0;
    out->dr2 = 0;
    out->dr3 = 0;
    out->dr6 = 0;
    out->dr7 = 0;

    out->cr0 = 0;
    out->cr2 = 0;
    out->cr3 = 0;
    out->cr4 = 0;
    out->orig_rax = regs->orig_ax;
    
    /* FPU / XMM Placeholder - Reading FPU in kernel is complex and version dependent */
    memset(out->xmm, 0, sizeof(out->xmm));
}

static int do_get_regs(struct attached_proc *p, struct snake_cpu_regs *uregs, pid_t tid)
{
    struct task_struct *task = get_thread_task(p, tid);
    if (!task)
        return -ESRCH;

    fill_regs_from_task(task, uregs);
    put_task_struct(task);
    return 0;
}

static int do_set_regs(struct attached_proc *p, const struct snake_cpu_regs *uregs, pid_t tid)
{
    struct task_struct *task = get_thread_task(p, tid);
    struct pt_regs *regs;

    if (!task)
        return -ESRCH;

    if (!task_is_stopped(task)) {
        put_task_struct(task);
        return -EBUSY;
    }

    regs = task_pt_regs(task);
    if (!regs) {
        put_task_struct(task);
        return -EINVAL;
    }

    regs->ax = uregs->rax;
    regs->bx = uregs->rbx;
    regs->cx = uregs->rcx;
    regs->dx = uregs->rdx;
    regs->si = uregs->rsi;
    regs->di = uregs->rdi;
    regs->bp = uregs->rbp;
    regs->sp = uregs->rsp;
    regs->ip = uregs->rip;
    regs->flags = uregs->rflags;
#ifdef CONFIG_X86_64
    regs->r8  = uregs->r8;
    regs->r9  = uregs->r9;
    regs->r10 = uregs->r10;
    regs->r11 = uregs->r11;
    regs->r12 = uregs->r12;
    regs->r13 = uregs->r13;
    regs->r14 = uregs->r14;
    regs->r15 = uregs->r15;
#endif
    regs->cs = uregs->cs;
    regs->ss = uregs->ss;
    regs->orig_ax = uregs->orig_rax;

    /* Debug registers not set in this build (kernel helper not exported) */

    put_task_struct(task);
    return 0;
}

/* ============================================================================
 * Process helpers
 * ============================================================================ */

static int fill_process_info(pid_t pid, struct snake_process_info *info)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);

    info->pid = pid;
    info->tgid = task->tgid;
    info->ppid = task_ppid_nr(task);
    info->uid = from_kuid(&init_user_ns, task_uid(task));
    info->gid = from_kgid(&init_user_ns, task->cred->gid);
    info->start_time = task->start_time;
    strscpy(info->comm, task->comm, sizeof(info->comm));

    if (mm) {
        info->mm_start_code = mm->start_code;
        info->mm_end_code = mm->end_code;
        info->mm_start_data = mm->start_data;
        info->mm_end_data = mm->end_data;
        info->mm_start_brk = mm->start_brk;
        info->mm_brk = mm->brk;
        info->mm_start_stack = mm->start_stack;

        if (mm->exe_file) {
            char *tmp = kmalloc(256, GFP_KERNEL);
            if (tmp) {
                char *path = d_path(&mm->exe_file->f_path, tmp, 256);
                if (!IS_ERR(path))
                    strscpy(info->exe_path, path, sizeof(info->exe_path));
                kfree(tmp);
            }
        }
    } else {
        ret = -EINVAL;
    }

    if (mm)
        mmput(mm);
    put_task_struct(task);
    return ret;
}

static int process_signal_op(pid_t pid, int sig)
{
    struct task_struct *task;
    int ret = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    ret = send_sig(sig, task, 0);
    put_task_struct(task);
    return ret;
}

static int do_single_step(struct attached_proc *p, pid_t tid)
{
#ifdef TIF_SINGLESTEP
    struct task_struct *task = get_thread_task(p, tid);
    int ret;

    if (!task)
        return -ESRCH;

    set_tsk_thread_flag(task, TIF_SINGLESTEP);
    ret = process_signal_op(task->pid, SIGCONT);
    put_task_struct(task);
    return ret;
#else
    return -ENOTSUPP;
#endif
}

/* ============================================================================
 * Hardware Breakpoint Support
 * ============================================================================ */

static void read_xmm_regs(struct snake_xmm_reg *out)
{
    /* Use movdqu to avoid alignment issues if struct is packed/unaligned */
    asm volatile(
        "movdqu %%xmm0, 0x00(%0)\n"
        "movdqu %%xmm1, 0x10(%0)\n"
        "movdqu %%xmm2, 0x20(%0)\n"
        "movdqu %%xmm3, 0x30(%0)\n"
        "movdqu %%xmm4, 0x40(%0)\n"
        "movdqu %%xmm5, 0x50(%0)\n"
        "movdqu %%xmm6, 0x60(%0)\n"
        "movdqu %%xmm7, 0x70(%0)\n"
        "movdqu %%xmm8, 0x80(%0)\n"
        "movdqu %%xmm9, 0x90(%0)\n"
        "movdqu %%xmm10, 0xA0(%0)\n"
        "movdqu %%xmm11, 0xB0(%0)\n"
        "movdqu %%xmm12, 0xC0(%0)\n"
        "movdqu %%xmm13, 0xD0(%0)\n"
        "movdqu %%xmm14, 0xE0(%0)\n"
        "movdqu %%xmm15, 0xF0(%0)\n"
        : /* no output operands directly, memory is modified via pointer */
        : "r" (out)
        : "memory"
    );
}

static void bp_handler(struct perf_event *bp,
                      struct perf_sample_data *data,
                      struct pt_regs *regs)
{
    struct event_entry *entry;
    struct attached_proc *p;
    unsigned long flags;
    pid_t pid = current->tgid;
    int slot = -1;
    
    p = get_proc(pid);
    if (!p)
        return;

    if (atomic_read(&event_count) >= param_event_queue_size) {
        put_proc(p);
        return;
    }
    
    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        put_proc(p);
        return;
    }

    for (slot = 0; slot < HBP_NUM; slot++) {
        if (!p->bp_slots[slot].used)
            continue;
        if (p->bp_slots[slot].perf_bp == bp) {
            goto slot_found;
        }
    }
slot_found:
    if (slot >= HBP_NUM)
        slot = -1;
    
    entry->event.type = SNAKE_DBG_EVENT_BREAKPOINT;
    entry->event.pid = pid;
    entry->event.tid = current->pid;
    entry->event.address = regs->ip;
    entry->event.timestamp = ktime_get_ns();
    entry->event.bp_slot = (slot >= 0) ? slot : 0;
    entry->event.bp_id = (slot >= 0) ? p->bp_slots[slot].id : 0;
    entry->event.access_size = (slot >= 0) ? p->bp_slots[slot].length : 0;
    entry->event.access_type = (slot >= 0) ? p->bp_slots[slot].type : 0;
    
    /* Copy registers */
    entry->event.regs.rax = regs->ax;
    entry->event.regs.rbx = regs->bx;
    entry->event.regs.rcx = regs->cx;
    entry->event.regs.rdx = regs->dx;
    entry->event.regs.rsi = regs->si;
    entry->event.regs.rdi = regs->di;
    entry->event.regs.rbp = regs->bp;
    entry->event.regs.rsp = regs->sp;
    entry->event.regs.rip = regs->ip;
    entry->event.regs.rflags = regs->flags;
#ifdef CONFIG_X86_64
    entry->event.regs.r8 = regs->r8;
    entry->event.regs.r9 = regs->r9;
    entry->event.regs.r10 = regs->r10;
    entry->event.regs.r11 = regs->r11;
    entry->event.regs.r12 = regs->r12;
    entry->event.regs.r13 = regs->r13;
    entry->event.regs.r14 = regs->r14;
    entry->event.regs.r15 = regs->r15;
#endif
    
    /* Capture XMM registers directly from hardware */
    read_xmm_regs(entry->event.regs.xmm);
    
    spin_lock_irqsave(&event_lock, flags);
    entry->event.sequence = event_sequence++;
    list_add_tail(&entry->list, &event_list);
    atomic_inc(&event_count);
    spin_unlock_irqrestore(&event_lock, flags);
    
    wake_up_interruptible(&event_waitq);
    put_proc(p);
}



static int do_set_breakpoint(struct attached_proc *p, struct snake_hw_breakpoint *bp)

{

    struct perf_event_attr attr;

    struct perf_event *perf_bp;

    struct task_struct *target;

    int slot = -1;

    int i;

    int bp_type;

    int bp_len;

    

    /* Find free slot */

    for (i = 0; i < HBP_NUM; i++) {

        if (!p->bp_slots[i].used) {

            slot = i;

            break;

        }

    }

    

    if (slot < 0) {

        bp->result = SNAKEDRV_ERROR_NO_BP_SLOT;

        return -ENOSPC;

    }

    

    switch (bp->type) {

    case SNAKE_BP_TYPE_EXEC:

        bp_type = HW_BREAKPOINT_X;

        break;

    case SNAKE_BP_TYPE_WRITE:

        bp_type = HW_BREAKPOINT_W;

        break;

    case SNAKE_BP_TYPE_RW:

        bp_type = HW_BREAKPOINT_RW;

        break;

    default:

        return -EINVAL;

    }



    switch (bp->length) {

    case SNAKE_BP_LEN_1:

        bp_len = HW_BREAKPOINT_LEN_1;

        break;

    case SNAKE_BP_LEN_2:

        bp_len = HW_BREAKPOINT_LEN_2;

        break;

    case SNAKE_BP_LEN_8:

        bp_len = HW_BREAKPOINT_LEN_8;

        break;

    case SNAKE_BP_LEN_4:

    default:

        bp_len = HW_BREAKPOINT_LEN_4;

        break;

    }



    if (!bp->enabled) {

        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;

        return -EINVAL;

    }



    target = get_thread_task(p, bp->tid);

    if (!target) {

        bp->result = SNAKEDRV_ERROR_NO_PROCESS;

        return -ESRCH;

    }

    

    hw_breakpoint_init(&attr);

    attr.bp_addr = bp->address;

    attr.bp_len = bp_len;

    attr.bp_type = bp_type;

    

    perf_bp = register_user_hw_breakpoint(&attr, bp_handler, NULL, target);

    if (IS_ERR(perf_bp)) {

        SDRV_ERR("Failed to register BP: %ld\n", PTR_ERR(perf_bp));

        put_task_struct(target);

        return PTR_ERR(perf_bp);

    }

    p->bp_slots[slot].perf_bp = perf_bp;

    

    p->bp_slots[slot].used = true;

    p->bp_slots[slot].id = slot + (p->pid << 8);

    p->bp_slots[slot].address = bp->address;

    p->bp_slots[slot].type = bp->type;

    p->bp_slots[slot].length = bp_len;

    p->bp_slots[slot].tid = bp->tid;

    p->bp_slots[slot].enabled = true;

    

    bp->slot = slot;

    bp->id = p->bp_slots[slot].id;

    bp->result = SNAKEDRV_SUCCESS;

    

    SDRV_INFO("Set BP: pid=%d slot=%d addr=0x%llx\n", p->pid, slot, bp->address);

    put_task_struct(target);

    return 0;

}



static int do_clear_breakpoint(struct attached_proc *p, struct snake_hw_breakpoint *bp)

{

    int slot = bp->slot;

    

    if (slot < 0 || slot >= HBP_NUM || !p->bp_slots[slot].used)

        return -ENOENT;

    

    if (p->bp_slots[slot].perf_bp) {

        unregister_hw_breakpoint(p->bp_slots[slot].perf_bp);

        p->bp_slots[slot].perf_bp = NULL;

    }

    

    p->bp_slots[slot].used = false;

    p->bp_slots[slot].enabled = false;

    p->bp_slots[slot].length = 0;

    p->bp_slots[slot].tid = 0;

    bp->result = SNAKEDRV_SUCCESS;

    

    SDRV_INFO("Cleared BP: pid=%d slot=%d\n", p->pid, slot);

    return 0;

}

/* ============================================================================
 * IOCTL Handler
 * ============================================================================ */

static long snakedrv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *uarg = (void __user *)arg;
    int ret = 0;
    
    switch (cmd) {
    
    case SNAKE_IOCTL_GET_INFO: {
        struct snake_driver_info info = {0};
        
        info.version_major = SNAKEDRV_VERSION_MAJOR;
        info.version_minor = SNAKEDRV_VERSION_MINOR;
        info.version_patch = SNAKEDRV_VERSION_PATCH;
        strscpy(info.version_string, SNAKEDRV_VERSION_STRING,
               sizeof(info.version_string));
        strscpy(info.kernel_release, init_uts_ns.name.release,
               sizeof(info.kernel_release));
        
        info.capabilities = SNAKE_CAP_HW_BREAKPOINTS |
                            SNAKE_CAP_MULTITHREAD |
                            SNAKE_CAP_PHYS_MEMORY |
                            SNAKE_CAP_PAGE_TABLE_WALK |
                            SNAKE_CAP_PROCESS_SUSPEND;
        info.max_breakpoints = HBP_NUM;
        info.max_attached = param_max_attached;
        info.page_size = PAGE_SIZE;
        info.result = SNAKEDRV_SUCCESS;
        
        if (copy_to_user(uarg, &info, sizeof(info)))
            ret = -EFAULT;
        break;
    }
    
    case SNAKE_IOCTL_DEBUG_ATTACH: {
        struct snake_debug_attach attach;
        struct attached_proc *p;
        struct memory_backend *backend;

        if (copy_from_user(&attach, uarg, sizeof(attach)))
            return -EFAULT;

        mutex_lock(&attach_mutex);

        if (find_proc_locked(attach.pid)) {
            mutex_unlock(&attach_mutex);
            attach.result = SNAKEDRV_ERROR_BUSY;
            if (copy_to_user(uarg, &attach, sizeof(attach)))
                return -EFAULT;
            return -EBUSY;
        }

        if (atomic_read(&attached_count) >= param_max_attached) {
            mutex_unlock(&attach_mutex);
            attach.result = SNAKEDRV_ERROR_BUSY;
            if (copy_to_user(uarg, &attach, sizeof(attach)))
                return -EFAULT;
            return -EBUSY;
        }

        /* Create process backend */
        backend = backend_create_process(attach.pid);
        if (!backend) {
            mutex_unlock(&attach_mutex);
            attach.result = SNAKEDRV_ERROR_NO_PROCESS;
            if (copy_to_user(uarg, &attach, sizeof(attach)))
                return -EFAULT;
            return -ESRCH;
        }

        p = kzalloc(sizeof(*p), GFP_KERNEL);
        if (!p) {
            backend_put(backend);
            mutex_unlock(&attach_mutex);
            return -ENOMEM;
        }

        p->pid = attach.pid;
        p->backend = backend;
        p->owner = file;
        atomic_set(&p->refcount, 1);

        list_add(&p->list, &attached_list);
        atomic_inc(&attached_count);
        mutex_unlock(&attach_mutex);

        attach.result = SNAKEDRV_SUCCESS;
        if (copy_to_user(uarg, &attach, sizeof(attach)))
            ret = -EFAULT;

        SDRV_INFO("Attached to PID %d (Process Backend)\n", attach.pid);
        break;
    }
    
    case SNAKE_IOCTL_DEBUG_CONTROL: {
        struct snake_debug_control ctrl;
        struct attached_proc *p;
        
        if (copy_from_user(&ctrl, uarg, sizeof(ctrl)))
            return -EFAULT;
        
        if (ctrl.operation == SNAKE_DBG_CTRL_DETACH) {
            mutex_lock(&attach_mutex);
            p = find_proc_locked(ctrl.pid);
            if (p) {
                list_del(&p->list);
                atomic_dec(&attached_count);
                mutex_unlock(&attach_mutex);

                cleanup_breakpoints(p);

                /* Release backend */
                if (p->backend)
                    backend_put(p->backend);

                kfree(p);

                ctrl.result = SNAKEDRV_SUCCESS;
                SDRV_INFO("Detached from PID %d\n", ctrl.pid);
            } else {
                mutex_unlock(&attach_mutex);
                ctrl.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            }

            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
        } else if (ctrl.operation == SNAKE_DBG_CTRL_CONTINUE) {
            ret = process_signal_op(ctrl.pid, SIGCONT);
            ctrl.result = ret ? ret : SNAKEDRV_SUCCESS;
            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
        } else if (ctrl.operation == SNAKE_DBG_CTRL_STOP) {
            ret = process_signal_op(ctrl.pid, SIGSTOP);
            ctrl.result = ret ? ret : SNAKEDRV_SUCCESS;
            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
        } else if (ctrl.operation == SNAKE_DBG_CTRL_STEP) {
            p = get_proc(ctrl.pid);
            if (!p) {
                ctrl.result = SNAKEDRV_ERROR_NOT_ATTACHED;
                if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                    ret = -EFAULT;
                return -ESRCH;
            }
            ret = do_single_step(p, ctrl.tid);
            ctrl.result = ret ? ret : SNAKEDRV_SUCCESS;
            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
            put_proc(p);
        }
        break;
    }
    
    case SNAKE_IOCTL_READ_MEMORY: {
        struct snake_memory_op op;
        struct attached_proc *p;
        void *kbuf;
        ssize_t bytes;
        
        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;
        
        if (op.size == 0 || op.size > (1 << 20))
            return -EINVAL;
        
        p = get_proc(op.pid);
        if (!p) {
            op.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &op, sizeof(op)))
                return -EFAULT;
            return -ESRCH;
        }
        
        kbuf = kvmalloc(op.size, GFP_KERNEL);
        if (!kbuf) {
            put_proc(p);
            return -ENOMEM;
        }
        
        bytes = do_read_memory(p, op.address, kbuf, op.size);
        
        if (bytes > 0) {
            if (copy_to_user((void __user *)op.user_buffer, kbuf, bytes))
                bytes = -EFAULT;
        }
        
        op.result = (int)bytes;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        else
            ret = (bytes > 0) ? 0 : (int)bytes;
        
        kvfree(kbuf);
        put_proc(p);
        break;
    }
    
    case SNAKE_IOCTL_WRITE_MEMORY: {
        struct snake_memory_op op;
        struct attached_proc *p;
        void *kbuf;
        ssize_t bytes;
        
        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;
        
        if (op.size == 0 || op.size > (1 << 20))
            return -EINVAL;
        
        p = get_proc(op.pid);
        if (!p) {
            op.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &op, sizeof(op)))
                return -EFAULT;
            return -ESRCH;
        }
        
        kbuf = kvmalloc(op.size, GFP_KERNEL);
        if (!kbuf) {
            put_proc(p);
            return -ENOMEM;
        }
        
        if (copy_from_user(kbuf, (void __user *)op.user_buffer, op.size)) {
            kvfree(kbuf);
            put_proc(p);
            return -EFAULT;
        }
        
        bytes = do_write_memory(p, op.address, kbuf, op.size);
        op.result = (int)bytes;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        else
            ret = (bytes > 0) ? 0 : (int)bytes;
        
        kvfree(kbuf);
        put_proc(p);
        break;
    }
    
    case SNAKE_IOCTL_QUERY_MEMORY: {
        struct snake_memory_query query;
        
        if (copy_from_user(&query, uarg, sizeof(query)))
            return -EFAULT;
        
        ret = do_query_regions(query.pid, uarg);
        break;
    }

    case SNAKE_IOCTL_READ_PHYS: {
        struct snake_phys_op op;
        void *kbuf;
        ssize_t bytes;

        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;
        if (op.size == 0 || op.size > (1 << 20))
            return -EINVAL;

        kbuf = kvmalloc(op.size, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        bytes = do_read_phys(op.phys_address, kbuf, op.size);
        if (bytes > 0) {
            if (copy_to_user((void __user *)op.user_buffer, kbuf, bytes))
                bytes = -EFAULT;
        }

        op.result = (int)bytes;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        else
            ret = (bytes > 0) ? 0 : (int)bytes;

        kvfree(kbuf);
        break;
    }

    case SNAKE_IOCTL_WRITE_PHYS: {
        struct snake_phys_op op;
        void *kbuf;
        ssize_t bytes;

        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;
        if (op.size == 0 || op.size > (1 << 20))
            return -EINVAL;

        kbuf = kvmalloc(op.size, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        if (copy_from_user(kbuf, (void __user *)op.user_buffer, op.size)) {
            kvfree(kbuf);
            return -EFAULT;
        }

        bytes = do_write_phys(op.phys_address, kbuf, op.size);
        op.result = (int)bytes;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        else
            ret = (bytes > 0) ? 0 : (int)bytes;

        kvfree(kbuf);
        break;
    }

    case SNAKE_IOCTL_VIRT_TO_PHYS: {
        struct snake_virt_to_phys vtp;
        struct attached_proc *p;

        if (copy_from_user(&vtp, uarg, sizeof(vtp)))
            return -EFAULT;

        p = get_proc(vtp.pid);
        if (!p) {
            vtp.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &vtp, sizeof(vtp)))
                return -EFAULT;
            return -ESRCH;
        }

        ret = do_virt_to_phys(p, &vtp);
        vtp.result = ret ? ret : SNAKEDRV_SUCCESS;
        if (copy_to_user(uarg, &vtp, sizeof(vtp)))
            ret = -EFAULT;
        put_proc(p);
        break;
    }

    case SNAKE_IOCTL_PROCESS_OP: {
        struct snake_process_op op;

        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;

        switch (op.operation) {
        case SNAKE_PROC_OP_SUSPEND:
            ret = process_signal_op(op.pid, SIGSTOP);
            break;
        case SNAKE_PROC_OP_RESUME:
            ret = process_signal_op(op.pid, SIGCONT);
            break;
        case SNAKE_PROC_OP_KILL:
            ret = process_signal_op(op.pid, SIGKILL);
            break;
        default:
            ret = -ENOTTY;
            break;
        }

        op.result = ret ? ret : SNAKEDRV_SUCCESS;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        break;
    }

    case SNAKE_IOCTL_GET_PROC_INFO: {
        struct snake_process_info info;

        if (copy_from_user(&info, uarg, sizeof(info)))
            return -EFAULT;

        ret = fill_process_info(info.pid, &info);
        if (copy_to_user(uarg, &info, sizeof(info)))
            ret = -EFAULT;
        break;
    }
    
    case SNAKE_IOCTL_SET_BREAKPOINT: {
        struct snake_hw_breakpoint bp;
        struct attached_proc *p;
        
        if (copy_from_user(&bp, uarg, sizeof(bp)))
            return -EFAULT;
        
        p = get_proc(bp.pid);
        if (!p) {
            bp.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &bp, sizeof(bp)))
                return -EFAULT;
            return -ESRCH;
        }
        
        ret = do_set_breakpoint(p, &bp);
        if (copy_to_user(uarg, &bp, sizeof(bp)))
            ret = -EFAULT;
        put_proc(p);
        break;
    }

    case SNAKE_IOCTL_GET_REGS: {
        struct snake_regs_op op;
        struct attached_proc *p;

        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;

        p = get_proc(op.pid);
        if (!p) {
            op.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &op, sizeof(op)))
                return -EFAULT;
            return -ESRCH;
        }

        ret = do_get_regs(p, &op.regs, op.tid);
        op.result = ret ? ret : SNAKEDRV_SUCCESS;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        put_proc(p);
        break;
    }

    case SNAKE_IOCTL_SET_REGS: {
        struct snake_regs_op op;
        struct attached_proc *p;

        if (copy_from_user(&op, uarg, sizeof(op)))
            return -EFAULT;

        p = get_proc(op.pid);
        if (!p) {
            op.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &op, sizeof(op)))
                return -EFAULT;
            return -ESRCH;
        }

        ret = do_set_regs(p, &op.regs, op.tid);
        op.result = ret ? ret : SNAKEDRV_SUCCESS;
        if (copy_to_user(uarg, &op, sizeof(op)))
            ret = -EFAULT;
        put_proc(p);
        break;
    }
    
    case SNAKE_IOCTL_CLEAR_BREAKPOINT: {
        struct snake_hw_breakpoint bp;
        struct attached_proc *p;
        
        if (copy_from_user(&bp, uarg, sizeof(bp)))
            return -EFAULT;
        
        p = get_proc(bp.pid);
        if (!p) {
            bp.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            if (copy_to_user(uarg, &bp, sizeof(bp)))
                return -EFAULT;
            return -ESRCH;
        }
        
        ret = do_clear_breakpoint(p, &bp);
        if (copy_to_user(uarg, &bp, sizeof(bp)))
            ret = -EFAULT;
        put_proc(p);
        break;
    }
    
    case SNAKE_IOCTL_POLL_EVENTS: {
        struct snake_event_poll poll;
        struct snake_debug_event *events;
        struct event_entry *entry, *tmp;
        unsigned long flags;
        uint32_t copied = 0;
        
        if (copy_from_user(&poll, uarg, sizeof(poll)))
            return -EFAULT;
        
        if (poll.max_events == 0 || poll.max_events > 256)
            return -EINVAL;
        
        events = kvmalloc(sizeof(*events) * poll.max_events, GFP_KERNEL);
        if (!events)
            return -ENOMEM;
        
        if (poll.timeout_ms > 0 && atomic_read(&event_count) == 0) {
            ret = wait_event_interruptible_timeout(event_waitq,
                atomic_read(&event_count) > 0,
                msecs_to_jiffies(poll.timeout_ms));
            if (ret < 0) {
                kvfree(events);
                return ret;
            }
        }
        
        spin_lock_irqsave(&event_lock, flags);
        list_for_each_entry_safe(entry, tmp, &event_list, list) {
            if (copied >= poll.max_events)
                break;
            memcpy(&events[copied], &entry->event, sizeof(entry->event));
            list_del(&entry->list);
            atomic_dec(&event_count);
            kfree(entry);
            copied++;
        }
        spin_unlock_irqrestore(&event_lock, flags);
        
        if (copied > 0) {
            if (copy_to_user((void __user *)poll.events_buffer, events,
                            sizeof(*events) * copied)) {
                kvfree(events);
                return -EFAULT;
            }
        }
        
        poll.events_ready = copied;
        poll.result = SNAKEDRV_SUCCESS;
        if (copy_to_user(uarg, &poll, sizeof(poll)))
            ret = -EFAULT;
        else
            ret = 0;
        
        kvfree(events);
        break;
    }

    /* ========================================================================
     * Scanner Operations
     * ======================================================================== */

    case SNAKE_IOCTL_SCAN_EXECUTE: {
        struct snake_scan_execute exec;
        struct attached_proc *p;
        struct scan_params params;
        struct scan_result_set *result_set;
        ssize_t scan_result;

        if (copy_from_user(&exec, uarg, sizeof(exec)))
            return -EFAULT;

        p = get_proc(exec.params.pid);
        if (!p) {
            exec.result = -ESRCH;
            if (copy_to_user(uarg, &exec, sizeof(exec)))
                return -EFAULT;
            return -ESRCH;
        }

        /* Convert userland params to kernel params */
        params.scan_type = exec.params.scan_type;
        params.start_address = exec.params.start_address;
        params.end_address = exec.params.end_address;
        params.search_value = exec.params.search_value;
        params.value_size = exec.params.value_type;
        params.aligned = exec.params.aligned;
        params.parallel = exec.params.parallel;
        params.num_threads = exec.params.num_threads;

        /* Create result set for scan results */
        result_set = scanner_create_result_set(exec.params.max_results > 0 ?
                                               exec.params.max_results : 10000);
        if (!result_set) {
            put_proc(p);
            exec.result = -ENOMEM;
            if (copy_to_user(uarg, &exec, sizeof(exec)))
                return -EFAULT;
            return -ENOMEM;
        }

        /* If no address range specified, scan each VMA individually (FirstScan only) */
        if (params.start_address == 0 && params.end_address == 0 &&
            p->backend->type == BACKEND_TYPE_PROCESS &&
            exec.params.scan_type == SCAN_TYPE_EXACT_VALUE &&
            exec.params.result_set_id == 0) {
            struct process_context *ctx;
            struct mm_struct *mm;
            struct vm_area_struct *vma;
            ssize_t total_matches = 0;

            /* Safety checks */
            if (!p->backend->private_data) {
                pr_err("snakedrv: Backend has no private data\n");
                scan_result = -EINVAL;
                goto skip_vma_scan;
            }

            ctx = (struct process_context *)p->backend->private_data;
            if (!ctx->mm) {
                pr_err("snakedrv: Process has no mm_struct\n");
                scan_result = -EINVAL;
                goto skip_vma_scan;
            }

            mm = ctx->mm;
            VMA_ITERATOR(vmi, mm, 0);

            if (mmap_read_lock_killable(mm)) {
                scanner_free_result_set(result_set);
                put_proc(p);
                exec.result = -EINTR;
                if (copy_to_user(uarg, &exec, sizeof(exec)))
                    return -EFAULT;
                return -EINTR;
            }

            pr_info("snakedrv: Scanning all readable VMAs for PID %d\n", exec.params.pid);

            /* Scan each readable VMA individually */
            for_each_vma(vmi, vma) {
                /* Safety check */
                if (!vma) {
                    pr_warn("snakedrv: NULL VMA\n");
                    break;
                }

                if (!(vma->vm_flags & VM_READ))
                    continue;

                /* Skip if result set is full */
                if (result_set->count >= result_set->max_results) {
                    pr_debug("snakedrv: Result set full\n");
                    break;
                }

                /* Validate VMA range */
                if (vma->vm_start >= vma->vm_end)
                    continue;

                /* Setup params for this VMA */
                params.start_address = vma->vm_start;
                params.end_address = vma->vm_end;

                pr_debug("snakedrv: Scanning VMA 0x%llx - 0x%llx\n",
                        params.start_address, params.end_address);

                /* Execute scan on this VMA */
                scan_result = scanner_exact_value(p->backend, &params, result_set);

                if (scan_result < 0) {
                    pr_debug("snakedrv: Scan failed for VMA: %zd\n", scan_result);
                    continue;
                }

                total_matches += scan_result;
            }
            mmap_read_unlock(mm);

            scan_result = total_matches;
            pr_info("snakedrv: VMA scan complete: %zd matches\n", total_matches);

skip_vma_scan:
            /* Fall through to normal scan if VMA scan was skipped */
            ;
        } else {
            /* Execute the appropriate scan type with explicit range */
            switch (exec.params.scan_type) {
            case SCAN_TYPE_EXACT_VALUE:
                /* Check if this is a rescan (result_set_id provided) */
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_exact_value_rescan(p->backend, prev_set, result_set,
                                                                 params.search_value, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    /* FirstScan with explicit range */
                    scan_result = scanner_exact_value(p->backend, &params, result_set);
                }
                break;
            case SCAN_TYPE_CHANGED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_changed_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_UNCHANGED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_unchanged_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_INCREASED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_increased_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_DECREASED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_decreased_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_INCREASED_BY:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_increased_by(p->backend, prev_set, result_set,
                                                           exec.params.search_value,
                                                           params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_DECREASED_BY:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_decreased_by(p->backend, prev_set, result_set,
                                                           exec.params.search_value,
                                                           params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_RANGE:
                /* Value between min and max */
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id);
                    if (prev_set) {
                        scan_result = scanner_value_between(p->backend, prev_set, result_set,
                                                            exec.params.search_value,
                                                            exec.params.search_value_2,
                                                            params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -ENOSYS;  /* Range FirstScan not implemented */
                }
                break;
            default:
                /* Unsupported scan type */
                pr_warn("snakedrv: Unsupported scan type %u\n", exec.params.scan_type);
                scan_result = -ENOTTY;
                break;
            }
        }

        put_proc(p);

        if (scan_result < 0) {
            scanner_free_result_set(result_set);
            exec.result = (int)scan_result;
            if (copy_to_user(uarg, &exec, sizeof(exec)))
                return -EFAULT;
            return (int)scan_result;
        }

        /* Copy results to userspace */
        exec.total_matches = result_set->count;
        exec.results_count = min((uint32_t)result_set->count, exec.results_capacity);

        if (exec.results_count > 0 && exec.results) {
            /* Convert kernel scan_result to userland snake_scan_result */
            struct snake_scan_result *user_results = kvmalloc(
                exec.results_count * sizeof(struct snake_scan_result), GFP_KERNEL);
            if (user_results) {
                uint32_t i;
                for (i = 0; i < exec.results_count; i++) {
                    user_results[i].address = result_set->results[i].address;
                    user_results[i].value = result_set->results[i].value;
                    user_results[i].size = params.value_size;
                    user_results[i].region_index = 0;
                }

                if (copy_to_user((void __user *)exec.results, user_results,
                                exec.results_count * sizeof(struct snake_scan_result))) {
                    kvfree(user_results);
                    scanner_free_result_set(result_set);
                    return -EFAULT;
                }
                kvfree(user_results);
            }
        }

        /* Cache the result set for potential rescans */
        exec.result_set_id = scanner_cache_add(result_set);
        exec.result = 0;

        if (copy_to_user(uarg, &exec, sizeof(exec)))
            ret = -EFAULT;

        break;
    }

    case SNAKE_IOCTL_SCAN_FREE_RESULTS: {
        uint32_t result_set_id;

        if (copy_from_user(&result_set_id, uarg, sizeof(result_set_id)))
            return -EFAULT;

        if (result_set_id > 0)
            scanner_cache_remove(result_set_id);

        break;
    }

    /* ========================================================================
     * Injection Operations (Manual Mapping)
     * ======================================================================== */

    case SNAKE_IOCTL_INJECT_ALLOC: {
        struct snake_inject_alloc alloc;

        if (copy_from_user(&alloc, uarg, sizeof(alloc)))
            return -EFAULT;

        ret = injector_allocate(&alloc);
        alloc.result = ret;

        if (copy_to_user(uarg, &alloc, sizeof(alloc)))
            return -EFAULT;
        break;
    }

    case SNAKE_IOCTL_INJECT_PROTECT: {
        struct snake_inject_protect prot;

        if (copy_from_user(&prot, uarg, sizeof(prot)))
            return -EFAULT;

        ret = injector_protect(&prot);
        prot.result = ret;

        if (copy_to_user(uarg, &prot, sizeof(prot)))
            return -EFAULT;
        break;
    }

    case SNAKE_IOCTL_INJECT_THREAD: {
        struct snake_inject_thread thread;

        if (copy_from_user(&thread, uarg, sizeof(thread)))
            return -EFAULT;

        ret = injector_create_thread(&thread);
        thread.result = ret;

        if (copy_to_user(uarg, &thread, sizeof(thread)))
            return -EFAULT;
        break;
    }

    case SNAKE_IOCTL_INJECT_STEALTH: {
        struct snake_inject_protect prot;

        if (copy_from_user(&prot, uarg, sizeof(prot)))
            return -EFAULT;

        ret = injector_apply_stealth(&prot);
        prot.result = ret;

        if (copy_to_user(uarg, &prot, sizeof(prot)))
            return -EFAULT;
        break;
    }

    default:
        SDRV_ERR("Unknown IOCTL: 0x%x\n", cmd);
        ret = -ENOTTY;
    }
    
    return ret;
}

/* ============================================================================
 * File Operations
 * ============================================================================ */

static int snakedrv_open(struct inode *inode, struct file *file)
{
    SDRV_DEBUG("Device opened\n");
    return 0;
}

static int snakedrv_release(struct inode *inode, struct file *file)
{
    struct attached_proc *p;
    
    /* Auto-detach processes owned by this file descriptor */
    while (1) {
        struct attached_proc *victim = NULL;
        
        mutex_lock(&attach_mutex);
        list_for_each_entry(p, &attached_list, list) {
            if (p->owner == file) {
                victim = p;
                list_del(&p->list);
                atomic_dec(&attached_count);
                break;
            }
        }
        mutex_unlock(&attach_mutex);
        
        if (!victim)
            break;

        cleanup_breakpoints(victim);

        /* Release backend */
        if (victim->backend)
            backend_put(victim->backend);

        kfree(victim);
        SDRV_INFO("Auto-detached from PID %d on close\n", victim->pid);
    }

    SDRV_DEBUG("Device closed\n");
    return 0;
}

/* poll() removed - not used by userland library and causes objtool issues on Ubuntu 6.14+ */

static const struct file_operations snakedrv_fops __ro_after_init = {
    .owner          = THIS_MODULE,
    .open           = snakedrv_open,
    .release        = snakedrv_release,
    .unlocked_ioctl = snakedrv_ioctl,
    .compat_ioctl   = snakedrv_ioctl,
};

/* ============================================================================
 * Module Init/Exit
 * ============================================================================ */

static int __init snakedrv_init(void)
{
    int ret;
    
    SDRV_INFO("Loading SnakeEngine Driver v%s\n", SNAKEDRV_VERSION_STRING);
    
    ret = alloc_chrdev_region(&snakedrv_devnum, 0, 1, SNAKEDRV_DEVICE_NAME);
    if (ret < 0) {
        SDRV_ERR("Failed to alloc chrdev: %d\n", ret);
        return ret;
    }
    
    cdev_init(&snakedrv_cdev, &snakedrv_fops);
    snakedrv_cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&snakedrv_cdev, snakedrv_devnum, 1);
    if (ret < 0) {
        SDRV_ERR("Failed to add cdev: %d\n", ret);
        goto err_cdev;
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    snakedrv_class = class_create(SNAKEDRV_CLASS_NAME);
#else
    snakedrv_class = class_create(THIS_MODULE, SNAKEDRV_CLASS_NAME);
#endif
    if (IS_ERR(snakedrv_class)) {
        ret = PTR_ERR(snakedrv_class);
        SDRV_ERR("Failed to create class: %d\n", ret);
        goto err_class;
    }
    
    snakedrv_device = device_create(snakedrv_class, NULL, snakedrv_devnum,
                                    NULL, SNAKEDRV_DEVICE_NAME);
    if (IS_ERR(snakedrv_device)) {
        ret = PTR_ERR(snakedrv_device);
        SDRV_ERR("Failed to create device: %d\n", ret);
        goto err_device;
    }

    /* Initialize scanner subsystem */
    ret = snakedrv_scanner_init();
    if (ret < 0) {
        SDRV_ERR("Failed to initialize scanner: %d\n", ret);
        goto err_scanner;
    }

    SDRV_INFO("Driver loaded: /dev/%s (major=%d)\n",
              SNAKEDRV_DEVICE_NAME, MAJOR(snakedrv_devnum));

    return 0;

err_scanner:
    device_destroy(snakedrv_class, snakedrv_devnum);

err_device:
    class_destroy(snakedrv_class);
err_class:
    cdev_del(&snakedrv_cdev);
err_cdev:
    unregister_chrdev_region(snakedrv_devnum, 1);
    return ret;
}

static void __exit snakedrv_exit(void)
{
    struct attached_proc *p, *tmp;
    struct event_entry *e, *etmp;

    SDRV_INFO("Unloading driver\n");

    /* Cleanup all attached processes */
    mutex_lock(&attach_mutex);
    list_for_each_entry_safe(p, tmp, &attached_list, list) {
        list_del(&p->list);
        cleanup_breakpoints(p);

        /* Release backend */
        if (p->backend)
            backend_put(p->backend);

        kfree(p);
    }
    mutex_unlock(&attach_mutex);
    
    /* Clear event queue */
    spin_lock(&event_lock);
    list_for_each_entry_safe(e, etmp, &event_list, list) {
        list_del(&e->list);
        kfree(e);
    }
    spin_unlock(&event_lock);

    /* Cleanup scanner subsystem */
    snakedrv_scanner_cleanup();

    /* Destroy device */
    device_destroy(snakedrv_class, snakedrv_devnum);
    class_destroy(snakedrv_class);
    cdev_del(&snakedrv_cdev);
    unregister_chrdev_region(snakedrv_devnum, 1);

    SDRV_INFO("Driver unloaded\n");
}

module_init(snakedrv_init);
module_exit(snakedrv_exit);
