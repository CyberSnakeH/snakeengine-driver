// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Manual Mapping Injector Implementation
 *
 * "The precise application of force."
 *
 * Implements low-level memory primitives for manual mapping.
 * Uses owned workers for mapped memory and independent references for readers.
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <asm/mman.h>
#include <asm/processor-flags.h>

#include "../userland/include/snakedrv.h"
#include "snakedrv_injector.h"

#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#define INJECTOR_WORKER_TIMEOUT_MS 5000
#define INJECTOR_MAX_SIZE (256UL << 20)

static struct workqueue_struct *injector_wq;
#ifdef SNAKEDRV_SELFTEST
static unsigned int test_worker_delay_ms;
module_param(test_worker_delay_ms, uint, 0600);
#endif

enum memory_job_op { MEMORY_MAP, MEMORY_UNMAP };
struct memory_job {
    struct work_struct work;
    struct completion done;
    refcount_t refs;
    spinlock_t lock;
    struct mm_struct *mm;
    enum memory_job_op op;
    unsigned long address, size, prot;
    int result;
    bool finished, abandoned;
};

static void memory_job_put(struct memory_job *job)
{
    if (refcount_dec_and_test(&job->refs)) {
        mmput(job->mm);
        kfree(job);
    }
}

static void memory_job_run(struct work_struct *work)
{
    struct memory_job *job = container_of(work, struct memory_job, work);
    unsigned long address = 0, flags;
    int ret;
#ifdef SNAKEDRV_SELFTEST
    if (READ_ONCE(test_worker_delay_ms))
        msleep(READ_ONCE(test_worker_delay_ms));
#endif
    kthread_use_mm(job->mm);
    if (job->op == MEMORY_MAP) {
        address = vm_mmap(NULL, 0, job->size, job->prot,
                          MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, 0);
        ret = IS_ERR_VALUE(address) ? (int)address : 0;
    } else {
        ret = vm_munmap(job->address, job->size);
    }
    spin_lock_irqsave(&job->lock, flags);
    /* Ownership is handed off under the same lock as the timeout decision. */
    if (job->abandoned && job->op == MEMORY_MAP && !ret) {
        spin_unlock_irqrestore(&job->lock, flags);
        vm_munmap(address, job->size);
        spin_lock_irqsave(&job->lock, flags);
        ret = -ETIMEDOUT;
    }
    job->address = ret ? 0 : address;
    job->result = ret;
    job->finished = true;
    spin_unlock_irqrestore(&job->lock, flags);
    kthread_unuse_mm(job->mm);
    complete_all(&job->done);
    memory_job_put(job);
}

static int memory_job_submit(struct mm_struct *mm, enum memory_job_op op,
                             unsigned long size, unsigned long prot,
                             unsigned long *address)
{
    struct memory_job *job;
    unsigned long flags;
    int ret;

    if (!mmget_not_zero(mm))
        return -ESRCH;
    job = kzalloc(sizeof(*job), GFP_KERNEL);
    if (!job) {
        mmput(mm);
        return -ENOMEM;
    }
    job->mm = mm; job->op = op; job->size = size; job->prot = prot;
    job->address = *address;
    refcount_set(&job->refs, 2);
    spin_lock_init(&job->lock);
    init_completion(&job->done);
    INIT_WORK(&job->work, memory_job_run);
    queue_work(injector_wq, &job->work);
    wait_for_completion_timeout(&job->done,
                                msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS));
    spin_lock_irqsave(&job->lock, flags);
    if (!job->finished) {
        job->abandoned = true;
        ret = -ETIMEDOUT;
    } else {
        ret = job->result;
        if (!ret && op == MEMORY_MAP)
            *address = job->address;
    }
    spin_unlock_irqrestore(&job->lock, flags);
    memory_job_put(job);
    return ret;
}

static struct mm_struct *injector_get_mm(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm = NULL;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (task) {
        mm = get_task_mm(task);
        put_task_struct(task);
    }
    return mm;
}

static int injector_map_args(u64 requested, u32 protection,
                             unsigned long *size, unsigned long *prot)
{
    unsigned long rounded;
    if (!requested || requested > INJECTOR_MAX_SIZE ||
        (protection & ~(SNAKE_PROT_READ | SNAKE_PROT_WRITE | SNAKE_PROT_EXEC)) ||
        check_add_overflow((unsigned long)requested, PAGE_SIZE - 1, &rounded))
        return -EINVAL;
    *size = rounded & PAGE_MASK;
    *prot = ((protection & SNAKE_PROT_READ) ? PROT_READ : 0) |
            ((protection & SNAKE_PROT_WRITE) ? PROT_WRITE : 0) |
            ((protection & SNAKE_PROT_EXEC) ? PROT_EXEC : 0);
    return 0;
}

int injector_allocate(struct snake_inject_alloc *info)
{
    struct mm_struct *mm;
    unsigned long size, prot, address = 0;
    int ret = injector_map_args(info->size, info->protection, &size, &prot);
    if (ret)
        return ret;
    mm = injector_get_mm(info->pid);
    if (!mm)
        return -ESRCH;
    ret = memory_job_submit(mm, MEMORY_MAP, size, prot, &address);
    mmput(mm);
    if (!ret)
        info->address = address;
    return ret;
}

/* mprotect_fixup/do_mprotect_pkey are not exported module interfaces. The SDK
 * uses the target's native syscall instead of falsely modifying only VMA flags.
 * VMA unlinking likewise cannot provide a supported, safe mapping lifetime. */
int injector_protect(struct snake_inject_protect *info)
{
    return -EOPNOTSUPP;
}

int injector_apply_stealth(struct snake_inject_protect *info)
{
    return -EOPNOTSUPP;
}

static int injector_resume_task(struct task_struct *task)
{
    int wait_count;
    int ret;

    wake_up_process(task);
    ret = send_sig(SIGCONT, task, 1);
    if (ret < 0) {
        pr_err("snakedrv: Failed to send SIGCONT: %d\n", ret);
        return ret;
    }

    for (wait_count = 0; wait_count < 200; wait_count++) {
        if (!task_is_stopped(task) && !task_is_traced(task))
            return 0;
        msleep(5);
    }

    pr_err("snakedrv: Task remained stopped after SIGCONT, state=0x%x\n",
           READ_ONCE(task->__state));
    return -EAGAIN;
}

/*
 * Hijack an existing thread to run our payload.
 *
 * Uses a robust approach:
 * 1. Send SIGSTOP to freeze the task
 * 2. Wait for it to be in a stoppable state
 * 3. Directly manipulate the user-mode return path
 * 4. Resume execution with SIGCONT
 */
int injector_create_thread(struct snake_inject_thread *thread_info)
{
    struct task_struct *task;
    struct pt_regs *regs;
    unsigned long original_rip, original_rsp;
    int wait_count = 0;
    int stopped = 0;
    int ret;

    /* Find the target task */
    rcu_read_lock();
    task = pid_task(find_vpid(thread_info->pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    pr_info("snakedrv: Target task state before SIGSTOP: 0x%x\n",
            READ_ONCE(task->__state));

    /* Step 1: Send SIGSTOP to the task */
    ret = send_sig(SIGSTOP, task, 1);
    if (ret < 0) {
        pr_err("snakedrv: Failed to send SIGSTOP: %d\n", ret);
        put_task_struct(task);
        return ret;
    }

    /* Step 2: Wait for task to actually stop */
    for (wait_count = 0; wait_count < 200; wait_count++) {
        if (task_is_stopped(task) || task_is_traced(task)) {
            stopped = 1;
            break;
        }
        msleep(5);
    }

    pr_info("snakedrv: Task state after wait: 0x%x (waited %d ms)\n",
            READ_ONCE(task->__state), wait_count * 5);
    if (!stopped) {
        pr_err("snakedrv: Task did not stop in time\n");
        injector_resume_task(task);
        put_task_struct(task);
        return -EAGAIN;
    }

    /* Step 3: Get registers */
    regs = task_pt_regs(task);
    if (!regs) {
        pr_err("snakedrv: Cannot get pt_regs\n");
        injector_resume_task(task);
        put_task_struct(task);
        return -EINVAL;
    }

    /* Save original values */
    original_rip = regs->ip;
    original_rsp = regs->sp;

    pr_info("snakedrv: Original RIP: 0x%lx\n", original_rip);
    pr_info("snakedrv: Original RSP: 0x%lx\n", original_rsp);
    pr_info("snakedrv: Shellcode at: 0x%llx\n", thread_info->start_address);
    pr_info("snakedrv: Path arg at: 0x%llx\n", thread_info->argument);

#ifdef CONFIG_X86_64
    /*
     * Set up for shellcode execution:
     * - RIP points to shellcode
     * - RDI = path string (first argument)
     * - Stack has original RIP as return address
     * - Stack alignment handled by shellcode (do not clobber original RSP)
     */
    /*
     * If we interrupted a syscall, the kernel may attempt a restart and
     * subtract 2 from RIP. Clear restart state to prevent RIP skew.
     */
    regs->ax = 0;
    regs->orig_ax = ~0UL;
    {
        /*
         * Simulate a CALL: push the return address onto the stack.
         * RSP after ret will be exactly original_rsp (no shift).
         *
         * The payload is compiled with -mincoming-stack-boundary=3
         * so the compiler handles 16-byte alignment in the prologue
         * itself (and rsp, -16).  This avoids corrupting the game
         * thread's stack frame.
         */
        unsigned long new_sp = original_rsp - 8;
        int written = access_process_vm(task, new_sp,
                                        &original_rip,
                                        sizeof(original_rip),
                                        1);
        if (written != sizeof(original_rip)) {
            pr_err("snakedrv: Failed to write return address (%d)\n", written);
            injector_resume_task(task);
            put_task_struct(task);
            return -EFAULT;
        }
        regs->sp = new_sp;
    }
    regs->ip = thread_info->start_address;
    regs->cx = thread_info->start_address;
    regs->di = thread_info->argument;

    /* Clear trap and direction flags */
    regs->flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_DF);
    regs->r11 = regs->flags;

    pr_info("snakedrv: New RIP: 0x%lx\n", regs->ip);
    pr_info("snakedrv: New RSP: 0x%lx\n", regs->sp);
    pr_info("snakedrv: New RDI: 0x%lx\n", regs->di);
#elif defined(CONFIG_ARM64)
    regs->pc = thread_info->start_address;
    regs->regs[0] = thread_info->argument;
    regs->regs[19] = original_rip;
#endif

    /* Memory barrier */
    smp_wmb();

    /* Step 4: Resume the task and fail if it remains stopped. */
    ret = injector_resume_task(task);
    if (ret < 0) {
        put_task_struct(task);
        return ret;
    }

    pr_info("snakedrv: Task resumed, state: 0x%x\n", READ_ONCE(task->__state));

    put_task_struct(task);
    return 0;
}

/* Pinned mappings retain a normal VMA so the kernel can manage PTEs, faults,
 * accounting and exit. Each client owns its entries, with independent readers. */
struct shadow_alloc_entry {
    struct list_head list;
    struct mm_struct *mm;
    void *owner;
    pid_t pid;
    unsigned long address, size;
    unsigned int nr_pages;
    struct page **pages;
    refcount_t refs;
    struct mutex io_mutex;
    bool dead;
};
static DEFINE_MUTEX(shadow_mutex);
static LIST_HEAD(shadow_list);

static void shadow_put(struct shadow_alloc_entry *sa)
{
    unsigned int i;
    if (!refcount_dec_and_test(&sa->refs))
        return;
    for (i = 0; i < sa->nr_pages; i++)
        put_page(sa->pages[i]);
    kvfree(sa->pages);
    mmdrop(sa->mm);
    kfree(sa);
}

static struct shadow_alloc_entry *shadow_get(void *owner, pid_t pid, u64 address)
{
    struct shadow_alloc_entry *sa, *found = NULL;
    mutex_lock(&shadow_mutex);
    list_for_each_entry(sa, &shadow_list, list) {
        if (sa->owner == owner && sa->pid == pid && address >= sa->address &&
            address - sa->address < sa->size) {
            refcount_inc(&sa->refs);
            found = sa;
            break;
        }
    }
    mutex_unlock(&shadow_mutex);
    return found;
}

static void shadow_teardown(struct shadow_alloc_entry *sa)
{
    unsigned long address = sa->address;
    mutex_lock(&sa->io_mutex);
    sa->dead = true;
    memory_job_submit(sa->mm, MEMORY_UNMAP, sa->size, 0, &address);
    mutex_unlock(&sa->io_mutex);
    shadow_put(sa);
}

int injector_shadow_alloc(struct snake_shadow_alloc *info, void *owner)
{
    struct shadow_alloc_entry *sa;
    struct mm_struct *mm;
    unsigned long size, prot, address = 0;
    long pinned;
    int ret = injector_map_args(info->size, info->protection, &size, &prot);
    if (ret)
        return ret;
    mm = injector_get_mm(info->pid);
    if (!mm)
        return -ESRCH;
    sa = kzalloc(sizeof(*sa), GFP_KERNEL);
    if (!sa) { mmput(mm); return -ENOMEM; }
    sa->pages = kvmalloc_array(size >> PAGE_SHIFT, sizeof(*sa->pages),
                               GFP_KERNEL | __GFP_ZERO);
    if (!sa->pages) { kfree(sa); mmput(mm); return -ENOMEM; }
    ret = memory_job_submit(mm, MEMORY_MAP, size, prot, &address);
    if (ret)
        goto fail;
    mmap_read_lock(mm);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    pinned = get_user_pages_remote(mm, address, size >> PAGE_SHIFT,
                                   FOLL_WRITE | FOLL_FORCE, sa->pages, NULL);
#else
    pinned = get_user_pages_remote(mm, address, size >> PAGE_SHIFT,
                                   FOLL_WRITE | FOLL_FORCE, sa->pages, NULL, NULL);
#endif
    mmap_read_unlock(mm);
    if (pinned != (long)(size >> PAGE_SHIFT)) {
        unsigned int i;
        for (i = 0; i < (pinned > 0 ? pinned : 0); i++)
            put_page(sa->pages[i]);
        memory_job_submit(mm, MEMORY_UNMAP, size, 0, &address);
        ret = -EFAULT;
        goto fail;
    }
    sa->mm = mm;
    mmgrab(mm);
    sa->owner = owner; sa->pid = info->pid;
    sa->address = address; sa->size = size; sa->nr_pages = size >> PAGE_SHIFT;
    refcount_set(&sa->refs, 1);
    mutex_init(&sa->io_mutex);
    mutex_lock(&shadow_mutex);
    list_add_tail(&sa->list, &shadow_list);
    mutex_unlock(&shadow_mutex);
    info->address = address;
    mmput(mm);
    return 0;
fail:
    kvfree(sa->pages);
    kfree(sa);
    mmput(mm);
    return ret;
}

ssize_t injector_shadow_write(struct snake_shadow_write *info, void *owner)
{
    struct shadow_alloc_entry *sa = shadow_get(owner, info->pid, info->address);
    unsigned long offset;
    ssize_t written = 0;
    if (!sa)
        return -ENOENT;
    mutex_lock(&sa->io_mutex);
    offset = info->address - sa->address;
    if (sa->dead) { written = -ENOENT; goto out; }
    if (info->size > sa->size - offset) { written = -ERANGE; goto out; }
    while (written < (ssize_t)info->size) {
        unsigned long pos = offset + written;
        size_t chunk = min_t(size_t, PAGE_SIZE - offset_in_page(pos),
                             info->size - written);
        void *mapped = kmap_local_page(sa->pages[pos >> PAGE_SHIFT]);
        if (copy_from_user(mapped + offset_in_page(pos),
                           (void __user *)(info->user_buffer + written), chunk)) {
            kunmap_local(mapped);
            if (!written) written = -EFAULT;
            break;
        }
        kunmap_local(mapped);
        written += chunk;
    }
out:
    mutex_unlock(&sa->io_mutex);
    shadow_put(sa);
    return written;
}

ssize_t injector_shadow_read(void *owner, pid_t pid, u64 address, void *buf, size_t len)
{
    struct shadow_alloc_entry *sa = shadow_get(owner, pid, address);
    unsigned long offset;
    ssize_t done = 0;
    if (!sa)
        return -ENOENT;
    mutex_lock(&sa->io_mutex);
    if (sa->dead) { done = -ENOENT; goto out; }
    offset = address - sa->address;
    len = min_t(size_t, len, sa->size - offset);
    while (done < (ssize_t)len) {
        unsigned long pos = offset + done;
        size_t chunk = min_t(size_t, PAGE_SIZE - offset_in_page(pos), len - done);
        void *mapped = kmap_local_page(sa->pages[pos >> PAGE_SHIFT]);
        memcpy((char *)buf + done, mapped + offset_in_page(pos), chunk);
        kunmap_local(mapped);
        done += chunk;
    }
out:
    mutex_unlock(&sa->io_mutex);
    shadow_put(sa);
    return done;
}

int injector_shadow_free(struct snake_shadow_alloc *info, void *owner)
{
    struct shadow_alloc_entry *sa, *found = NULL;
    mutex_lock(&shadow_mutex);
    list_for_each_entry(sa, &shadow_list, list) {
        if (sa->owner == owner && sa->pid == info->pid && sa->address == info->address) {
            list_del_init(&sa->list);
            found = sa;
            break;
        }
    }
    mutex_unlock(&shadow_mutex);
    if (!found)
        return -ENOENT;
    shadow_teardown(found);
    return 0;
}

void injector_shadow_cleanup_owner(void *owner)
{
    struct shadow_alloc_entry *sa, *tmp;
    LIST_HEAD(retired);
    mutex_lock(&shadow_mutex);
    list_for_each_entry_safe(sa, tmp, &shadow_list, list) {
        if (!owner || sa->owner == owner)
            list_move_tail(&sa->list, &retired);
    }
    mutex_unlock(&shadow_mutex);
    list_for_each_entry_safe(sa, tmp, &retired, list) {
        list_del_init(&sa->list);
        shadow_teardown(sa);
    }
}

int injector_init(void)
{
    injector_wq = alloc_workqueue("snakedrv_mem", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    return injector_wq ? 0 : -ENOMEM;
}

void injector_cleanup(void)
{
    /* The module text and worker contexts remain alive until all jobs finish. */
    flush_workqueue(injector_wq);
    injector_shadow_cleanup_owner(NULL);
    destroy_workqueue(injector_wq);
}
