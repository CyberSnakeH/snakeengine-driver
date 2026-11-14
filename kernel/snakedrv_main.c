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
#include <linux/capability.h>
#include <linux/security.h>
#include <linux/overflow.h>
#include <linux/refcount.h>
#include <linux/irq_work.h>
#include <asm/processor.h>

/* Include shared headers with userland */
#include "../userland/include/snakedrv.h"
#include "../userland/include/snakedrv_scanner.h"

/* Include kernel headers */
#include "snakedrv_backend.h"
#include "snakedrv_scanner.h"
#include "snakedrv_injector.h"
#include "snakedrv_benchmark.h"

/* Forward declarations for backend private data */
struct process_context {
    pid_t pid;
    struct task_struct *task;
    struct mm_struct *mm;
};

static struct snake_scan_options global_scan_options = {
    .enable_parallel = 0,
    .enable_bloom = 1,
    .enable_prefetch = 1,
    .enable_huge_pages = 1,
    .default_threads = 0,
    .bloom_fpr = 10,
};
static DEFINE_MUTEX(scan_options_mutex);

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

static int snakedrv_abi_version_get(char *buffer, const struct kernel_param *kp)
{
    (void)kp;
    return scnprintf(buffer, PAGE_SIZE, "%u\n", SNAKEDRV_ABI_VERSION);
}

static const struct kernel_param_ops snakedrv_abi_version_ops = {
    .get = snakedrv_abi_version_get,
};

module_param_cb(abi_version, &snakedrv_abi_version_ops, NULL, 0444);
MODULE_PARM_DESC(abi_version, "SnakeEngine driver ABI version");

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

/* Each open file owns a bounded, preallocated event ring. */
struct snakedrv_session {
    raw_spinlock_t event_lock;
    wait_queue_head_t event_waitq;
    struct snake_debug_event *events;
    unsigned int capacity, head, tail, count;
    u32 sequence;
    atomic64_t dropped, contention;
};

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
    struct list_head perf_events;
    u32 flags;
};

struct bp_perf_event {
    struct list_head list;
    struct perf_event *perf_bp;
    pid_t tid;
    struct snakedrv_session *session;
    struct pid *tgid;
    struct irq_work notify;
    u64 address;
    u32 id, slot, type, length;
    bool stop_on_hit;
    struct attached_proc *process;
};

struct attached_proc {
    struct list_head list;
    pid_t pid;
    struct file *owner;
    struct pid *pid_handle;
    atomic_t stopped_by_driver;

    /* Unified backend abstraction */
    struct memory_backend *backend;

    struct bp_slot bp_slots[HBP_NUM];
    refcount_t refcount;
    struct mutex bp_mutex;
    bool detached;
    atomic64_t read_ops;
    atomic64_t write_ops;
};

/* Forward declaration — used by put_proc before definition */
static void cleanup_breakpoints(struct attached_proc *p);

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

static struct attached_proc *get_proc(struct file *file, pid_t pid)
{
    struct attached_proc *p;
    mutex_lock(&attach_mutex);
    p = find_proc_locked(pid);
    if (p && p->owner == file && !p->detached)
        refcount_inc(&p->refcount);
    else
        p = NULL;
    mutex_unlock(&attach_mutex);
    return p;
}

static void put_proc(struct attached_proc *p)
{
    if (!p)
        return;

    if (refcount_dec_and_test(&p->refcount)) {
        cleanup_breakpoints(p);
        if (p->backend)
            backend_put(p->backend);
        put_pid(p->pid_handle);
        kfree(p);
    }
}

static void clear_bp_slot(struct bp_slot *slot)
{
    struct bp_perf_event *bpe, *tmp;

    list_for_each_entry_safe(bpe, tmp, &slot->perf_events, list) {
        list_del(&bpe->list);
        if (bpe->perf_bp)
            unregister_hw_breakpoint(bpe->perf_bp);
        /* perf releases inherited events before the callback context dies. */
        irq_work_sync(&bpe->notify);
        put_pid(bpe->tgid);
        kfree(bpe);
    }

    slot->used = false;
    slot->enabled = false;
    slot->id = 0;
    slot->address = 0;
    slot->type = 0;
    slot->length = 0;
    slot->tid = 0;
}

static void cleanup_breakpoints(struct attached_proc *p)
{
    int i;
    
    mutex_lock(&p->bp_mutex);
    for (i = 0; i < HBP_NUM; i++) {
        if (p->bp_slots[i].used)
            clear_bp_slot(&p->bp_slots[i]);
    }
    mutex_unlock(&p->bp_mutex);
    if (atomic_xchg(&p->stopped_by_driver, 0))
        kill_pid(p->pid_handle, SIGCONT, 1);
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
        atomic64_inc(&p->read_ops);

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
        atomic64_inc(&p->write_ops);

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

    {
        size_t alloc_size;

        if (check_mul_overflow(sizeof(*regions),
                               (size_t)query.max_regions, &alloc_size))
            return -EOVERFLOW;

        regions = kvzalloc(alloc_size, GFP_KERNEL);
    }
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
                char *tmp = kmalloc(PATH_MAX, GFP_KERNEL);
                if (tmp) {
                    char *path = d_path(&vma->vm_file->f_path,
                                        tmp, PATH_MAX);
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

static void put_thread_snapshot(struct task_struct **tasks, unsigned int count)
{
    unsigned int i;

    if (!tasks)
        return;

    for (i = 0; i < count; i++)
        if (tasks[i])
            put_task_struct(tasks[i]);
    kvfree(tasks);
}

static int collect_process_threads(pid_t pid, struct task_struct ***out_tasks,
                                   unsigned int *out_count)
{
    struct task_struct *leader;
    struct task_struct *task;
    struct task_struct **tasks;
    unsigned int count = 0;
    unsigned int index = 0;

    *out_tasks = NULL;
    *out_count = 0;

    rcu_read_lock();
    leader = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!leader || leader->tgid != pid) {
        rcu_read_unlock();
        return -ESRCH;
    }

    for_each_thread(leader, task)
        count++;
    rcu_read_unlock();

    if (count == 0)
        return -ESRCH;

    tasks = kvmalloc_array(count, sizeof(*tasks), GFP_KERNEL | __GFP_ZERO);
    if (!tasks)
        return -ENOMEM;

    rcu_read_lock();
    leader = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!leader || leader->tgid != pid) {
        rcu_read_unlock();
        kvfree(tasks);
        return -ESRCH;
    }

    for_each_thread(leader, task) {
        if (index >= count)
            break;
        get_task_struct(task);
        tasks[index++] = task;
    }
    rcu_read_unlock();

    if (index == 0) {
        kvfree(tasks);
        return -ESRCH;
    }

    *out_tasks = tasks;
    *out_count = index;
    return 0;
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
    /*
     * struct page->flags typing has changed across kernels:
     *   - Before the memdesc cleanup series (most kernels ≤ 6.16 and
     *     every distro that didn't backport it): flags is a raw
     *     `unsigned long`.
     *   - After the cleanup (mainline ~6.17+ and Fedora 43's 6.19):
     *     flags is `memdesc_flags_t`, a struct wrapping one
     *     `unsigned long f` field.
     *
     * Using a LINUX_VERSION_CODE check is unreliable because distros
     * (Ubuntu 6.17 in particular) cherry-pick the feature independently
     * from the version bump.  Instead, read the first `unsigned long`
     * at `&page->flags` — identical layout in both cases because
     * memdesc_flags_t contains exactly one unsigned long.
     */
    vtp->flags = (uint32_t)(*(unsigned long *)&page->flags);
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
            char *tmp = kmalloc(PATH_MAX, GFP_KERNEL);
            if (tmp) {
                char *path = d_path(&mm->exe_file->f_path,
                                    tmp, PATH_MAX);
                if (!IS_ERR(path))
                    strscpy(info->exe_path, path,
                           sizeof(info->exe_path));
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

static int process_resume(struct file *file, pid_t pid)
{
    struct attached_proc *p = get_proc(file, pid);
    int ret, owned_stop;

    if (!p)
        return process_signal_op(pid, SIGCONT);

    /* Clear before signaling: a new breakpoint stop must not be erased. */
    owned_stop = atomic_xchg(&p->stopped_by_driver, 0);
    ret = kill_pid(p->pid_handle, SIGCONT, 1);
    if (ret && owned_stop)
        atomic_cmpxchg(&p->stopped_by_driver, 0, 1);
    put_proc(p);
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

/* Signals and waiter wakeups run after the debug/NMI callback returns. */
static void bp_notify(struct irq_work *work)
{
    struct bp_perf_event *bpe = container_of(work, struct bp_perf_event, notify);
    if (bpe->stop_on_hit && !kill_pid(bpe->tgid, SIGSTOP, 1))
        atomic_set(&bpe->process->stopped_by_driver, 1);
    wake_up_interruptible(&bpe->session->event_waitq);
}

static void bp_handler(struct perf_event *bp,
                       struct perf_sample_data *data, struct pt_regs *regs)
{
    struct bp_perf_event *bpe = bp->overflow_handler_context;
    struct snakedrv_session *s = bpe->session;
    struct snake_debug_event *e;
    unsigned long flags;

    /* Never allocate, sleep, walk mutable lists or wait for an interrupted lock. */
    if (!raw_spin_trylock_irqsave(&s->event_lock, flags)) {
        atomic64_inc(&s->contention);
        atomic64_inc(&s->dropped);
        goto notify;
    }
    if (s->count == s->capacity) {
        atomic64_inc(&s->dropped);
        raw_spin_unlock_irqrestore(&s->event_lock, flags);
        goto notify;
    }
    e = &s->events[s->head];
    memset(e, 0, sizeof(*e));
    e->type = bpe->type == SNAKE_BP_TYPE_EXEC ?
        SNAKE_DBG_EVENT_BREAKPOINT : SNAKE_DBG_EVENT_WATCHPOINT;
    e->pid = current->tgid;
    e->tid = current->pid;
    e->address = regs->ip;
    e->accessed_address = bpe->address;
    e->timestamp = ktime_get_ns();
    e->bp_slot = bpe->slot;
    e->bp_id = bpe->id;
    e->access_size = bpe->length;
    e->access_type = bpe->type;
    e->sequence = s->sequence++;
    e->regs.rax = regs->ax; e->regs.rbx = regs->bx;
    e->regs.rcx = regs->cx; e->regs.rdx = regs->dx;
    e->regs.rsi = regs->si; e->regs.rdi = regs->di;
    e->regs.rbp = regs->bp; e->regs.rsp = regs->sp;
    e->regs.rip = regs->ip; e->regs.rflags = regs->flags;
#ifdef CONFIG_X86_64
    e->regs.r8 = regs->r8; e->regs.r9 = regs->r9;
    e->regs.r10 = regs->r10; e->regs.r11 = regs->r11;
    e->regs.r12 = regs->r12; e->regs.r13 = regs->r13;
    e->regs.r14 = regs->r14; e->regs.r15 = regs->r15;
#endif
    /* FPU state is not safe to sample with ad-hoc SIMD instructions here. */
    s->head = (s->head + 1) % s->capacity;
    s->count++;
    raw_spin_unlock_irqrestore(&s->event_lock, flags);
notify:
    irq_work_queue(&bpe->notify);
}

static int validate_breakpoint_address(struct task_struct *target,
                                       struct snake_hw_breakpoint *bp,
                                       unsigned int bp_len_bytes)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long start;
    unsigned long end;
    int ret = 0;

    if (bp->address != (uint64_t)(unsigned long)bp->address ||
        bp->address == 0) {
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        return -EINVAL;
    }

    start = (unsigned long)bp->address;
    if (check_add_overflow(start, (unsigned long)bp_len_bytes, &end) ||
        end <= start || !IS_ALIGNED(start, bp_len_bytes)) {
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        return -EINVAL;
    }

    mm = get_task_mm(target);
    if (!mm) {
        bp->result = SNAKEDRV_ERROR_NO_PROCESS;
        return -EINVAL;
    }

    mmap_read_lock(mm);
    vma = find_vma(mm, start);
    if (!vma || vma->vm_start > start || vma->vm_end < end) {
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        ret = -EFAULT;
    }
    mmap_read_unlock(mm);
    mmput(mm);

    return ret;
}

static int register_bp_for_task(struct attached_proc *p, unsigned int index,
                                struct perf_event_attr *attr,
                                struct task_struct *target)
{
    struct bp_slot *slot = &p->bp_slots[index];
    struct bp_perf_event *bpe;
    struct perf_event *perf_bp;
    int ret;

    bpe = kzalloc(sizeof(*bpe), GFP_KERNEL);
    if (!bpe)
        return -ENOMEM;

    bpe->session = p->owner->private_data;
    bpe->process = p;
    bpe->tgid = get_pid(p->pid_handle);
    bpe->address = slot->address;
    bpe->id = slot->id; bpe->slot = index;
    bpe->type = slot->type; bpe->length = slot->length;
    bpe->stop_on_hit = !!(slot->flags & SNAKE_BP_FLAG_STOP_ON_HIT);
    init_irq_work(&bpe->notify, bp_notify);
    perf_bp = register_user_hw_breakpoint(attr, bp_handler, bpe, target);
    if (IS_ERR(perf_bp)) {
        ret = PTR_ERR(perf_bp);
        put_pid(bpe->tgid);
        kfree(bpe);
        return ret;
    }

    bpe->perf_bp = perf_bp;
    bpe->tid = target->pid;
    list_add_tail(&bpe->list, &slot->perf_events);
    return 0;
}

static int __do_set_breakpoint(struct attached_proc *p, struct snake_hw_breakpoint *bp)
{
    struct perf_event_attr attr;
    struct task_struct *target;
    struct task_struct **tasks = NULL;
    unsigned int task_count = 0;
    unsigned int registered = 0;
    int slot = -1;
    int i;
    int bp_type;
    int bp_len;
    unsigned int bp_len_bytes;
    int ret;

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
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        return -EINVAL;
    }

    switch (bp->length) {
    case SNAKE_BP_LEN_1:
        bp_len = HW_BREAKPOINT_LEN_1;
        bp_len_bytes = 1;
        break;
    case SNAKE_BP_LEN_2:
        bp_len = HW_BREAKPOINT_LEN_2;
        bp_len_bytes = 2;
        break;
    case SNAKE_BP_LEN_4:
        bp_len = HW_BREAKPOINT_LEN_4;
        bp_len_bytes = 4;
        break;
    case SNAKE_BP_LEN_8:
        bp_len = HW_BREAKPOINT_LEN_8;
        bp_len_bytes = 8;
        break;
    default:
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        return -EINVAL;
    }

    if (bp->type == SNAKE_BP_TYPE_EXEC && bp_len_bytes != 1) {
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        return -EINVAL;
    }

    if (!(bp->enabled & SNAKE_BP_FLAG_ENABLED) ||
        (bp->enabled & ~(SNAKE_BP_FLAG_ENABLED | SNAKE_BP_FLAG_STOP_ON_HIT))) {
        bp->result = SNAKEDRV_ERROR_INVALID_ARGS;
        return -EINVAL;
    }

    target = get_thread_task(p, bp->tid);
    if (!target) {
        bp->result = SNAKEDRV_ERROR_NO_PROCESS;
        return -ESRCH;
    }

    ret = validate_breakpoint_address(target, bp, bp_len_bytes);
    if (ret) {
        put_task_struct(target);
        return ret;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = bp->address;
    attr.bp_len = bp_len;
    attr.bp_type = bp_type;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    /* The perf core propagates callbacks/context to new threads and reaps them. */
    attr.inherit = !bp->tid;
    attr.inherit_thread = !bp->tid;
    attr.remove_on_exec = 1;

    p->bp_slots[slot].used = true;
    p->bp_slots[slot].id = slot + (p->pid << 8);
    p->bp_slots[slot].address = bp->address;
    p->bp_slots[slot].type = bp->type;
    p->bp_slots[slot].length = bp_len_bytes;
    p->bp_slots[slot].tid = bp->tid;
    p->bp_slots[slot].enabled = true;
    p->bp_slots[slot].flags = bp->enabled;

    if (bp->tid) {
        ret = register_bp_for_task(p, slot, &attr, target);
        put_task_struct(target);
        if (ret) {
            bp->result = ret;
            clear_bp_slot(&p->bp_slots[slot]);
            SDRV_ERR("Failed to register BP: %d\n", ret);
            return ret;
        }
        registered = 1;
    } else {
        put_task_struct(target);
        target = NULL;

        ret = collect_process_threads(p->pid, &tasks, &task_count);
        if (ret) {
            bp->result = SNAKEDRV_ERROR_NO_PROCESS;
            clear_bp_slot(&p->bp_slots[slot]);
            return ret;
        }

        for (i = 0; i < task_count; i++) {
            ret = register_bp_for_task(p, slot, &attr, tasks[i]);
            if (ret) {
                bp->result = ret;
                clear_bp_slot(&p->bp_slots[slot]);
                put_thread_snapshot(tasks, task_count);
                SDRV_ERR("Failed to register process-wide BP: %d\n", ret);
                return ret;
            }
            registered++;
        }
        put_thread_snapshot(tasks, task_count);
    }

    if (!registered) {
        bp->result = SNAKEDRV_ERROR_NO_PROCESS;
        clear_bp_slot(&p->bp_slots[slot]);
        return -ESRCH;
    }

    bp->slot = slot;
    bp->id = p->bp_slots[slot].id;
    bp->result = SNAKEDRV_SUCCESS;

    SDRV_INFO("Set BP: pid=%d slot=%d addr=0x%llx threads=%u\n",
              p->pid, slot, bp->address, registered);

    return 0;
}



static int __do_clear_breakpoint(struct attached_proc *p, struct snake_hw_breakpoint *bp)

{

    int slot = bp->slot;

    

    if (slot < 0 || slot >= HBP_NUM || !p->bp_slots[slot].used)

        return -ENOENT;

    clear_bp_slot(&p->bp_slots[slot]);

    bp->result = SNAKEDRV_SUCCESS;

    

    SDRV_INFO("Cleared BP: pid=%d slot=%d\n", p->pid, slot);

    return 0;

}

static int do_set_breakpoint(struct attached_proc *p, struct snake_hw_breakpoint *bp)
{
    int ret;
    mutex_lock(&p->bp_mutex);
    ret = READ_ONCE(p->detached) ? -ENODEV : __do_set_breakpoint(p, bp);
    mutex_unlock(&p->bp_mutex);
    return ret;
}

static int do_clear_breakpoint(struct attached_proc *p, struct snake_hw_breakpoint *bp)
{
    int ret;
    mutex_lock(&p->bp_mutex);
    ret = READ_ONCE(p->detached) ? -ENODEV : __do_clear_breakpoint(p, bp);
    mutex_unlock(&p->bp_mutex);
    return ret;
}

static void add_perf_counters(struct snake_perf_stats *out,
                              struct scan_perf_counters *counters)
{
    u64 scans = atomic64_read(&counters->total_scans);
    u64 bytes = atomic64_read(&counters->total_bytes);
    u64 matches = atomic64_read(&counters->total_matches);
    u64 time_ns = atomic64_read(&counters->total_time_ns);
    s64 min_ns = atomic64_read(&counters->min_time_ns);
    u64 max_ns = atomic64_read(&counters->max_time_ns);
    u64 parallel = atomic64_read(&counters->parallel_scans);
    u64 cache_hits = atomic64_read(&counters->cache_hits);
    u64 cache_misses = atomic64_read(&counters->cache_misses);

    out->total_scans += scans;
    out->total_bytes += bytes;
    out->total_matches += matches;
    out->total_time_ns += time_ns;
    out->huge_page_scans += atomic64_read(&counters->huge_page_scans);

    if (scans) {
        out->avg_latency_us += (time_ns / scans) / 1000;
        if (min_ns != LLONG_MAX &&
            (out->min_latency_us == 0 || (u64)min_ns / 1000 < out->min_latency_us))
            out->min_latency_us = (u64)min_ns / 1000;
        if (max_ns / 1000 > out->max_latency_us)
            out->max_latency_us = max_ns / 1000;
        out->parallel_ratio += (parallel * 100) / scans;
    }

    if (time_ns) {
        out->throughput_mbps += (bytes * 1000) / (time_ns / 1000000 + 1);
        out->matches_per_sec += (matches * 1000000000) / time_ns;
    }

    if (cache_hits + cache_misses)
        out->cache_hit_rate += (cache_hits * 100) / (cache_hits + cache_misses);
}

static void fill_scanner_perf_stats(struct snake_perf_stats *out)
{
    u64 measured_groups = 0;

    memset(out, 0, sizeof(*out));

#define ADD_GROUP(counters) do {                                      \
    if (atomic64_read(&(counters).total_scans))                       \
        measured_groups++;                                            \
    add_perf_counters(out, &(counters));                              \
} while (0)

    ADD_GROUP(global_perf_stats.exact_value);
    ADD_GROUP(global_perf_stats.pattern);
    ADD_GROUP(global_perf_stats.changed);
    ADD_GROUP(global_perf_stats.unchanged);
    ADD_GROUP(global_perf_stats.float_scan);
    ADD_GROUP(global_perf_stats.double_scan);
    ADD_GROUP(global_perf_stats.string_ascii);
    ADD_GROUP(global_perf_stats.string_unicode);
    ADD_GROUP(global_perf_stats.pointer_chain);

#undef ADD_GROUP

    if (measured_groups) {
        out->avg_latency_us /= measured_groups;
        out->throughput_mbps /= measured_groups;
        out->matches_per_sec /= measured_groups;
        out->cache_hit_rate /= measured_groups;
        out->parallel_ratio /= measured_groups;
    }
}

/* ============================================================================
 * IOCTL Handler
 * ============================================================================ */

/* Keep the large register payload out of the main ioctl stack frame. */
static noinline long snakedrv_regs_ioctl(struct file *file, unsigned int cmd, void __user *uarg)
{
    struct snake_regs_op op;
    struct attached_proc *p;
    int ret;

    if (copy_from_user(&op, uarg, sizeof(op)))
        return -EFAULT;

    p = get_proc(file, op.pid);
    if (!p) {
        op.result = SNAKEDRV_ERROR_NOT_ATTACHED;
        if (copy_to_user(uarg, &op, sizeof(op)))
            return -EFAULT;
        return -ESRCH;
    }

    if (cmd == SNAKE_IOCTL_GET_REGS)
        ret = do_get_regs(p, &op.regs, op.tid);
    else
        ret = do_set_regs(p, &op.regs, op.tid);
    op.result = ret ? ret : SNAKEDRV_SUCCESS;
    if (copy_to_user(uarg, &op, sizeof(op)))
        ret = -EFAULT;
    put_proc(p);
    return ret;
}

static long snakedrv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *uarg = (void __user *)arg;
    int ret = 0;

    /*
     * Capability gate: all operations except GET_INFO require
     * CAP_SYS_PTRACE. Physical memory and injection additionally
     * require CAP_SYS_ADMIN (ring-0 equivalent operations).
     */
    switch (cmd) {
    case SNAKE_IOCTL_GET_INFO:
        break; /* read-only metadata, no capability needed */
    case SNAKE_IOCTL_READ_PHYS:
    case SNAKE_IOCTL_WRITE_PHYS:
    case SNAKE_IOCTL_INJECT_ALLOC:
    case SNAKE_IOCTL_INJECT_PROTECT:
    case SNAKE_IOCTL_INJECT_THREAD:
    case SNAKE_IOCTL_INJECT_STEALTH:
    case SNAKE_IOCTL_SHADOW_ALLOC:
    case SNAKE_IOCTL_SHADOW_WRITE:
    case SNAKE_IOCTL_SHADOW_FREE:
        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;
        break;
    default:
        if (!capable(CAP_SYS_PTRACE))
            return -EPERM;
        break;
    }

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
        info.abi_version = SNAKEDRV_ABI_VERSION;
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
        p->pid_handle = get_task_pid(((struct process_context *)backend->private_data)->task,
                                     PIDTYPE_TGID);
        if (!p->pid_handle) {
            kfree(p);
            backend_put(backend);
            mutex_unlock(&attach_mutex);
            return -ESRCH;
        }
        atomic_set(&p->stopped_by_driver, 0);
        refcount_set(&p->refcount, 1);
        mutex_init(&p->bp_mutex);
        for (int i = 0; i < HBP_NUM; i++)
            INIT_LIST_HEAD(&p->bp_slots[i].perf_events);

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
            if (p && p->owner == file) {
                WRITE_ONCE(p->detached, true);
                list_del(&p->list);
                atomic_dec(&attached_count);
            } else {
                p = NULL;
            }
            mutex_unlock(&attach_mutex);

            if (p) {
                /*
                 * Drop the list's reference. put_proc handles
                 * cleanup_breakpoints + backend_put + kfree
                 * atomically when refcount reaches zero.
                 * If a concurrent ioctl still holds a reference,
                 * the actual free is deferred until that put_proc.
                 */
                cleanup_breakpoints(p);
                put_proc(p);

                ctrl.result = SNAKEDRV_SUCCESS;
                SDRV_INFO("Detached from PID %d\n", ctrl.pid);
            } else {
                ctrl.result = SNAKEDRV_ERROR_NOT_ATTACHED;
            }

            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
        } else if (ctrl.operation == SNAKE_DBG_CTRL_CONTINUE) {
            ret = process_resume(file, ctrl.pid);
            ctrl.result = ret ? ret : SNAKEDRV_SUCCESS;
            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
        } else if (ctrl.operation == SNAKE_DBG_CTRL_STOP) {
            ret = process_signal_op(ctrl.pid, SIGSTOP);
            ctrl.result = ret ? ret : SNAKEDRV_SUCCESS;
            if (copy_to_user(uarg, &ctrl, sizeof(ctrl)))
                ret = -EFAULT;
        } else if (ctrl.operation == SNAKE_DBG_CTRL_STEP) {
            p = get_proc(file, ctrl.pid);
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
        
        p = get_proc(file, op.pid);
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

        /*
         * Try shadow read first — if the address falls in a
         * shadow allocation, access_process_vm won't work
         * (no VMA).  Fall back to the normal backend path.
         */
        bytes = injector_shadow_read(file, op.pid, op.address, kbuf, op.size);
        if (bytes == -ENOENT)
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
        
        p = get_proc(file, op.pid);
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

        p = get_proc(file, vtp.pid);
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
            ret = process_resume(file, op.pid);
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
        
        p = get_proc(file, bp.pid);
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

    case SNAKE_IOCTL_GET_REGS:
    case SNAKE_IOCTL_SET_REGS:
        return snakedrv_regs_ioctl(file, cmd, uarg);
    
    case SNAKE_IOCTL_CLEAR_BREAKPOINT: {
        struct snake_hw_breakpoint bp;
        struct attached_proc *p;
        
        if (copy_from_user(&bp, uarg, sizeof(bp)))
            return -EFAULT;
        
        p = get_proc(file, bp.pid);
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
        struct snakedrv_session *s = file->private_data;
        struct snake_event_poll poll;
        struct snake_debug_event *events;
        unsigned long flags;
        u32 copied = 0;

        if (copy_from_user(&poll, uarg, sizeof(poll)))
            return -EFAULT;
        if (!poll.max_events || poll.max_events > 256)
            return -EINVAL;
        events = kvmalloc_array(poll.max_events, sizeof(*events), GFP_KERNEL);
        if (!events)
            return -ENOMEM;
        if (poll.timeout_ms && !READ_ONCE(s->count)) {
            ret = wait_event_interruptible_timeout(s->event_waitq,
                READ_ONCE(s->count), msecs_to_jiffies(poll.timeout_ms));
            if (ret < 0) {
                kvfree(events);
                return ret;
            }
        }
        raw_spin_lock_irqsave(&s->event_lock, flags);
        while (s->count && copied < poll.max_events) {
            events[copied++] = s->events[s->tail];
            s->tail = (s->tail + 1) % s->capacity;
            s->count--;
        }
        raw_spin_unlock_irqrestore(&s->event_lock, flags);
        if (copied && copy_to_user((void __user *)poll.events_buffer, events,
                                  copied * sizeof(*events))) {
            atomic64_add(copied, &s->dropped);
            kvfree(events);
            return -EFAULT;
        }
        kvfree(events);
        poll.events_ready = copied;
        poll.result = 0;
        return copy_to_user(uarg, &poll, sizeof(poll)) ? -EFAULT : 0;
    }
    case SNAKE_IOCTL_GET_DEBUG_STATS: {
        struct snakedrv_session *s = file->private_data;
        struct snake_debug_stats stats = {0};
        unsigned long flags;
        raw_spin_lock_irqsave(&s->event_lock, flags);
        stats.queued = s->count;
        stats.capacity = s->capacity;
        raw_spin_unlock_irqrestore(&s->event_lock, flags);
        stats.dropped = atomic64_read(&s->dropped);
        stats.contention = atomic64_read(&s->contention);
        return copy_to_user(uarg, &stats, sizeof(stats)) ? -EFAULT : 0;
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

        p = get_proc(file, exec.params.pid);
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
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_exact_value_rescan(p->backend, prev_set, result_set,
                                                                 params.search_value, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    /* FirstScan with explicit range */
                    scan_result = scanner_exact_value(p->backend, &params, result_set);
                }
                break;
            case SCAN_TYPE_CHANGED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_changed_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_UNCHANGED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_unchanged_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_INCREASED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_increased_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_DECREASED_VALUE:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_decreased_values(p->backend, prev_set, result_set, params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_INCREASED_BY:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_increased_by(p->backend, prev_set, result_set,
                                                           exec.params.search_value,
                                                           params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_DECREASED_BY:
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_decreased_by(p->backend, prev_set, result_set,
                                                           exec.params.search_value,
                                                           params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
                        scan_result = -EINVAL;
                    }
                } else {
                    scan_result = -EINVAL;
                }
                break;
            case SCAN_TYPE_RANGE:
                /* Value between min and max */
                if (exec.params.result_set_id > 0) {
                    struct scan_result_set *prev_set = scanner_cache_get(exec.params.result_set_id, file);
                    if (prev_set && prev_set->pid == exec.params.pid) {
                        scan_result = scanner_value_between(p->backend, prev_set, result_set,
                                                            exec.params.search_value,
                                                            exec.params.search_value_2,
                                                            params.value_size);
                        scanner_cache_put(prev_set);
                    } else {
                        scanner_cache_put(prev_set);
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
            if (!user_results) {
                scanner_cache_put(result_set);
                return -ENOMEM;
            }
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
        result_set->scan_type = exec.params.scan_type;
        exec.result_set_id = scanner_cache_add(result_set, file, exec.params.pid);
        if (!exec.result_set_id) {
            scanner_cache_put(result_set);
            return -ENOSPC;
        }
        exec.result = 0;
        if (copy_to_user(uarg, &exec, sizeof(exec))) {
            scanner_cache_remove(exec.result_set_id, file);
            ret = -EFAULT;
        }
        scanner_cache_put(result_set);
        break;
    }

    case SNAKE_IOCTL_SCAN_GET_RESULTS: {
        struct snake_scan_execute exec;
        struct scan_result_set *set;
        uint32_t count, i;

        if (copy_from_user(&exec, uarg, sizeof(exec)))
            return -EFAULT;

        set = scanner_cache_get(exec.params.result_set_id, file);
        if (!set) {
            exec.result = -ENOENT;
            if (copy_to_user(uarg, &exec, sizeof(exec)))
                return -EFAULT;
            return -ENOENT;
        }

        count = min(set->count, exec.results_capacity);
        exec.results_count = count;
        exec.total_matches = set->count;
        exec.result_set_id = set->id;
        exec.result = 0;

        if (count > 0 && exec.results) {
            struct snake_scan_result *user_results;

            user_results = kvmalloc_array(count, sizeof(*user_results),
                                          GFP_KERNEL | __GFP_ZERO);
            if (!user_results) {
                scanner_cache_put(set);
                return -ENOMEM;
            }

            for (i = 0; i < count; i++) {
                user_results[i].address = set->results[i].address;
                user_results[i].value = set->results[i].value;
                user_results[i].size = exec.params.value_type;
                user_results[i].region_index = 0;
            }

            if (copy_to_user((void __user *)exec.results, user_results,
                             count * sizeof(*user_results))) {
                kvfree(user_results);
                scanner_cache_put(set);
                return -EFAULT;
            }
            kvfree(user_results);
        }

        scanner_cache_put(set);

        if (copy_to_user(uarg, &exec, sizeof(exec)))
            ret = -EFAULT;
        break;
    }

    case SNAKE_IOCTL_SCAN_FREE_RESULTS: {
        uint32_t result_set_id;

        if (copy_from_user(&result_set_id, uarg, sizeof(result_set_id)))
            return -EFAULT;

        if (result_set_id > 0)
            scanner_cache_remove(result_set_id, file);

        break;
    }

    case SNAKE_IOCTL_SCAN_GET_INFO: {
        struct snake_scan_result_set_info info;
        struct scan_result_set *set;

        if (copy_from_user(&info, uarg, sizeof(info)))
            return -EFAULT;

        set = scanner_cache_get(info.result_set_id, file);
        if (!set)
            return -ENOENT;

        info.count = set->count;
        info.scan_type = set->scan_type;
        info.has_bloom = set->use_bloom ? 1 : 0;
        info.memory_usage = sizeof(*set) +
            ((u64)set->max_results * sizeof(*set->results));

        scanner_cache_put(set);

        if (copy_to_user(uarg, &info, sizeof(info)))
            ret = -EFAULT;
        break;
    }

    case SNAKE_IOCTL_GET_BACKEND_INFO: {
        struct snake_backend_info info = {0};

        info.backend_type = BACKEND_PROCESS;
        info.supports_huge_pages = 0;
        info.supports_parallel = 1;
        info.page_size = PAGE_SIZE;
        strscpy(info.name, "process", sizeof(info.name));

        if (copy_to_user(uarg, &info, sizeof(info)))
            ret = -EFAULT;
        break;
    }

    case SNAKE_IOCTL_SET_BACKEND: {
        uint32_t backend;

        if (copy_from_user(&backend, uarg, sizeof(backend)))
            return -EFAULT;

        if (backend != BACKEND_AUTO && backend != BACKEND_PROCESS)
            return -EINVAL;
        break;
    }

    case SNAKE_IOCTL_GET_PERF_STATS: {
        struct snake_perf_stats stats;

        fill_scanner_perf_stats(&stats);
        if (copy_to_user(uarg, &stats, sizeof(stats)))
            ret = -EFAULT;
        break;
    }

    case SNAKE_IOCTL_RESET_PERF_STATS:
        snakedrv_perf_init(&global_perf_stats);
        break;

    case SNAKE_IOCTL_GET_SCAN_OPTIONS: {
        struct snake_scan_options options;

        mutex_lock(&scan_options_mutex);
        options = global_scan_options;
        mutex_unlock(&scan_options_mutex);

        if (copy_to_user(uarg, &options, sizeof(options)))
            ret = -EFAULT;
        break;
    }

    case SNAKE_IOCTL_SET_SCAN_OPTIONS: {
        struct snake_scan_options options;

        if (copy_from_user(&options, uarg, sizeof(options)))
            return -EFAULT;

        if (options.bloom_fpr > 1000)
            return -EINVAL;

        mutex_lock(&scan_options_mutex);
        global_scan_options.enable_parallel = options.enable_parallel ? 1 : 0;
        global_scan_options.enable_bloom = options.enable_bloom ? 1 : 0;
        global_scan_options.enable_prefetch = options.enable_prefetch ? 1 : 0;
        global_scan_options.enable_huge_pages = options.enable_huge_pages ? 1 : 0;
        global_scan_options.default_threads = options.default_threads;
        global_scan_options.bloom_fpr = options.bloom_fpr;
        mutex_unlock(&scan_options_mutex);
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

    /* ================================================================
     * Shadow Memory (VMA-less PTE mapping)
     * ================================================================ */

    case SNAKE_IOCTL_SHADOW_ALLOC: {
        struct snake_shadow_alloc sa;

        if (copy_from_user(&sa, uarg, sizeof(sa)))
            return -EFAULT;
        ret = injector_shadow_alloc(&sa, file);
        sa.result = ret;
        if (copy_to_user(uarg, &sa, sizeof(sa)))
            return -EFAULT;
        break;
    }

    case SNAKE_IOCTL_SHADOW_WRITE: {
        struct snake_shadow_write sw;
        ssize_t written;

        if (copy_from_user(&sw, uarg, sizeof(sw)))
            return -EFAULT;
        written = injector_shadow_write(&sw, file);
        sw.result = (int32_t)written;
        if (copy_to_user(uarg, &sw, sizeof(sw)))
            return -EFAULT;
        ret = (written >= 0) ? 0 : (int)written;
        break;
    }

    case SNAKE_IOCTL_SHADOW_FREE: {
        struct snake_shadow_alloc sa;

        if (copy_from_user(&sa, uarg, sizeof(sa)))
            return -EFAULT;
        ret = injector_shadow_free(&sa, file);
        sa.result = ret;
        if (copy_to_user(uarg, &sa, sizeof(sa)))
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
    struct snakedrv_session *s;
    unsigned int capacity = READ_ONCE(param_event_queue_size);
    if (!capacity || capacity > 4096)
        return -EINVAL;
    s = kzalloc(sizeof(*s), GFP_KERNEL);
    if (!s)
        return -ENOMEM;
    s->events = kvcalloc(capacity, sizeof(*s->events), GFP_KERNEL);
    if (!s->events) {
        kfree(s);
        return -ENOMEM;
    }
    s->capacity = capacity;
    raw_spin_lock_init(&s->event_lock);
    init_waitqueue_head(&s->event_waitq);
    atomic64_set(&s->dropped, 0);
    atomic64_set(&s->contention, 0);
    file->private_data = s;
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
                WRITE_ONCE(p->detached, true);
                list_del(&p->list);
                atomic_dec(&attached_count);
                break;
            }
        }
        mutex_unlock(&attach_mutex);
        
        if (!victim)
            break;

        SDRV_INFO("Auto-detached from PID %d on close\n", victim->pid);
        cleanup_breakpoints(victim);
        put_proc(victim);
    }

    scanner_cache_remove_owner(file);
    injector_shadow_cleanup_owner(file);
    if (file->private_data) {
        struct snakedrv_session *s = file->private_data;
        kvfree(s->events);
        kfree(s);
    }
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
    
    ret = injector_init();
    if (ret)
        return ret;
    ret = alloc_chrdev_region(&snakedrv_devnum, 0, 1, SNAKEDRV_DEVICE_NAME);
    if (ret < 0) {
        SDRV_ERR("Failed to alloc chrdev: %d\n", ret);
        injector_cleanup();
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
    injector_cleanup();
    return ret;
}

static void __exit snakedrv_exit(void)
{
    struct attached_proc *p, *tmp;

    SDRV_INFO("Unloading driver\n");

    /* No open file can remain on a normal module unload. Keep the defensive
     * cleanup consistent with detach and close, including all owned references. */
    LIST_HEAD(retired);
    mutex_lock(&attach_mutex);
    list_splice_init(&attached_list, &retired);
    list_for_each_entry(p, &retired, list)
        WRITE_ONCE(p->detached, true);
    atomic_set(&attached_count, 0);
    mutex_unlock(&attach_mutex);
    list_for_each_entry_safe(p, tmp, &retired, list) {
        list_del_init(&p->list);
        cleanup_breakpoints(p);
        put_proc(p);
    }
    
    /* Drain owned workers before module text and mappings disappear. */
    injector_cleanup();

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
