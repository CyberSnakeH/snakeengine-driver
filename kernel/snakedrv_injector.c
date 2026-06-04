// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Manual Mapping Injector Implementation
 *
 * "The precise application of force."
 *
 * Implements low-level memory primitives for manual mapping.
 * Uses advanced context switching techniques to allocate/protect memory
 * in foreign address spaces without ptrace.
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
#include <linux/maple_tree.h>

#include "../userland/include/snakedrv.h"
#include "snakedrv_injector.h"

/* Completion timeout for worker threads (5 seconds) */
#define INJECTOR_WORKER_TIMEOUT_MS  5000

#ifndef SDRV_DEBUG
#define SDRV_DEBUG(fmt, ...) \
    pr_debug("snakedrv: [DBG] " fmt, ##__VA_ARGS__)
#endif

/* Helper to map snake protection flags to kernel vm_flags */
static unsigned long map_prot_flags(uint32_t snake_prot)
{
    unsigned long prot = 0;
    if (snake_prot & SNAKE_PROT_READ)   prot |= PROT_READ;
    if (snake_prot & SNAKE_PROT_WRITE)  prot |= PROT_WRITE;
    if (snake_prot & SNAKE_PROT_EXEC)   prot |= PROT_EXEC;
    return prot;
}

/* 
 * Allocation Context
 * Used to pass data to the worker thread that performs allocation
 */
struct alloc_ctx {
    struct mm_struct *target_mm;
    unsigned long length;
    unsigned long prot;
    unsigned long addr_out;
    struct completion done;
    int ret;
};

/*
 * Hide VMA from /proc/maps by unlinking it from the MM structure.
 * WARNING: This makes the memory invisible to the kernel's VMA tracking.
 * Pages remain allocated but might be leaked if not carefully managed.
 */
static void injector_hide_vma(struct mm_struct *mm, unsigned long addr)
{
    struct vm_area_struct *vma;

    if (mmap_write_lock_killable(mm))
        return;

    vma = find_vma(mm, addr);
    if (!vma || vma->vm_start != addr) {
        mmap_write_unlock(mm);
        return;
    }

    /*
     * Modify VMA flags to disable dumping and merging before unlinking.
     * VM_IO | VM_PFNMAP prevents core dumping and some access checks.
     * VM_DONTEXPAND prevents growing.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
#else
    vma->vm_flags |= (VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    /* 
     * Kernel 6.1+ uses Maple Trees (MA_STATE) 
     * We use the VMA iterator API (or direct Maple State) to remove the entry.
     */
    {
        struct vma_iterator vmi;

        vma_iter_init(&vmi, mm, vma->vm_start);

        /*
         * mas_store needs the FULL range of the VMA, not just a
         * single address.  vma_iter_init sets mas.index=mas.last=addr
         * which would only clear a point.  We must cover [vm_start,
         * vm_end-1] so the entire maple tree entry is replaced with
         * NULL (gap).
         */
        mas_set_range(&vmi.mas, vma->vm_start, vma->vm_end - 1);
        mas_store_gfp(&vmi.mas, NULL, GFP_KERNEL);

        if (mas_is_err(&vmi.mas)) {
            pr_warn("snakedrv: maple tree store failed, "
                    "VMA at 0x%lx remains visible\n", addr);
            mas_reset(&vmi.mas);
        } else {
            mm->map_count--;
            pr_info("snakedrv: VMA hidden: 0x%lx-0x%lx removed "
                    "from maple tree\n",
                    vma->vm_start, vma->vm_end);
        }
    }
#else
    /*
     * Legacy Kernel (< 6.1) uses RB-Tree and Linked List
     */
    {
        /* Remove from RB-Tree */
        // if (vma->vm_rb.rb_node)
        //    rb_erase(&vma->vm_rb, &mm->mm_rb);

        /* Remove from Linked List */
        /* Note: We need to handle mm->mmap_cache if it exists in this kernel version */
        
        // if (vma->vm_prev)
        //    vma->vm_prev->vm_next = vma->vm_next;
        // else
        //    mm->mmap = vma->vm_next;

        // if (vma->vm_next)
        //    vma->vm_next->vm_prev = vma->vm_prev;

        // mm->map_count--;
        pr_info("snakedrv: VMA unlinked (RB-Tree/List) SKIPPED\n");
    }
#endif

    mmap_write_unlock(mm);
}

/*
 * Worker thread to perform allocation in target context.
 * We use a kernel thread because we need to switch mm context,
 * which is safest done from a kthread.
 */
static int injector_alloc_worker(void *data)
{
    struct alloc_ctx *ctx = (struct alloc_ctx *)data;
    struct mm_struct *mm = ctx->target_mm;
    unsigned long addr;

    /* Switch to target process memory context */
    kthread_use_mm(mm);

    /* 
     * vm_mmap is the kernel-side wrapper for mmap.
     * We allocate as anonymous memory (MAP_ANONYMOUS | MAP_PRIVATE).
     * This looks like a standard malloc() or mmap() from the process itself.
     * 
     * CRITICAL: We use MAP_POPULATE to force page allocation immediately.
     * Removed MAP_LOCKED to avoid locking limits issues.
     */
    addr = vm_mmap(NULL, 0, ctx->length, ctx->prot,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, 0);

    if (IS_ERR_VALUE(addr)) {
        ctx->ret = (int)addr;
        ctx->addr_out = 0;
    } else {
        ctx->ret = 0;
        ctx->addr_out = addr;
    }

    /* Restore kernel memory context */
    kthread_unuse_mm(mm);
    
    complete(&ctx->done);
    return 0;
}

int injector_allocate(struct snake_inject_alloc *alloc_info)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct alloc_ctx ctx;
    struct task_struct *worker;

    /* Find target task */
    rcu_read_lock();
    task = pid_task(find_vpid(alloc_info->pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    /* Setup context for worker */
    ctx.target_mm = mm;
    ctx.length = PAGE_ALIGN(alloc_info->size);
    ctx.prot = map_prot_flags(alloc_info->protection);
    init_completion(&ctx.done);

    /* Spawn worker thread */
    worker = kthread_run(injector_alloc_worker, &ctx, "snake_injector");
    if (IS_ERR(worker)) {
        mmput(mm);
        put_task_struct(task);
        return PTR_ERR(worker);
    }

    /* Wait for allocation to complete — bounded */
    if (!wait_for_completion_timeout(&ctx.done,
            msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS))) {
        pr_err("snakedrv: alloc worker timed out\n");
        mmput(mm);
        put_task_struct(task);
        return -ETIMEDOUT;
    }

    alloc_info->address = ctx.addr_out;

    mmput(mm);
    put_task_struct(task);
    return ctx.ret;
}

/*
 * Stealth worker context
 */
struct stealth_ctx {
    struct mm_struct *target_mm;
    unsigned long address;
    struct completion done;
};

static int injector_stealth_worker(void *data)
{
    struct stealth_ctx *ctx = (struct stealth_ctx *)data;
    
    /* We don't strictly need kthread_use_mm for VMA unlinking if we have the mm struct,
       but it's safer to follow established patterns if we touch VM internals.
       However, injector_hide_vma takes mm and handles locking. */
    
    injector_hide_vma(ctx->target_mm, ctx->address);
    
    complete(&ctx->done);
    return 0;
}

int injector_apply_stealth(struct snake_inject_protect *info)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct stealth_ctx ctx;
    struct task_struct *worker;

    rcu_read_lock();
    task = pid_task(find_vpid(info->pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    ctx.target_mm = mm;
    ctx.address = info->address;
    init_completion(&ctx.done);

    worker = kthread_run(injector_stealth_worker, &ctx, "snake_stealth");
    if (IS_ERR(worker)) {
        mmput(mm);
        put_task_struct(task);
        return PTR_ERR(worker);
    }

    if (!wait_for_completion_timeout(&ctx.done,
            msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS))) {
        pr_err("snakedrv: stealth worker timed out\n");
        mmput(mm);
        put_task_struct(task);
        return -ETIMEDOUT;
    }

    mmput(mm);
    put_task_struct(task);
    return 0;
}

/*
 * Protection worker context
 */
struct protect_ctx {
    struct mm_struct *target_mm;
    unsigned long start;
    unsigned long len;
    unsigned long prot;
    struct completion done;
    int ret;
};

/*
 * Worker to change protection.
 * mprotect requires the mmap_lock and operating in the correct mm context.
 */
static int injector_protect_worker(void *data)
{
    struct protect_ctx *ctx = (struct protect_ctx *)data;
    struct mm_struct *mm = ctx->target_mm;
    unsigned long nstart, end, tmp;
    struct vm_area_struct *vma;
    int ret = 0;
    unsigned long vm_flags;

    kthread_use_mm(mm);

    if (mmap_write_lock_killable(mm)) {
        kthread_unuse_mm(mm);
        ctx->ret = -EINTR;
        complete(&ctx->done);
        return 0;
    }

    /* Calculate vm_flags from protection */
    vm_flags = calc_vm_prot_bits(ctx->prot, 0);

    /* 
     * Logic adapted from do_mprotect_pkey.
     * We iterate VMAs in the range and modify their flags.
     */
    nstart = ctx->start;
    end = ctx->start + ctx->len;
    
    /* Find the first VMA */
    vma = find_vma(mm, nstart);
    if (!vma) {
        ret = -ENOMEM;
        goto out_unlock;
    }

    /* Iterate through affected VMAs */
    for (nstart = ctx->start; nstart < end; nstart = tmp) {
        if (nstart < vma->vm_start) {
            ret = -ENOMEM;
            goto out_unlock;
        }

        tmp = vma->vm_end;
        if (tmp > end)
            tmp = end;

        /* Minimal implementation: Check if we just want to make it executable */
        /* For kernel >= 6.3, vm_flags modification should use helpers */
        /* We use a cast to bypass const if needed, or simple assignment if allowed by macro */
        {
            unsigned long set_flags = 0;

            if (ctx->prot & PROT_EXEC)
                set_flags |= VM_EXEC;
            if (ctx->prot & PROT_WRITE)
                set_flags |= VM_WRITE;
            if (ctx->prot & PROT_READ)
                set_flags |= VM_READ;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
            vm_flags_set(vma, set_flags);
#else
            vma->vm_flags |= set_flags;
#endif
        }
        
        /* Find next VMA */
        {
            struct vm_area_struct *next_vma = find_vma(mm, vma->vm_end);
            /* Ensure it is actually the next one (contiguous) or handle gaps? 
               The loop logic handles gaps by checking nstart < vma->vm_start above. 
               But find_vma returns the first VMA *after* or *at* the address. */
            vma = next_vma;
        }

        if (!vma)
            break;
    }

out_unlock:
    mmap_write_unlock(mm);
    kthread_unuse_mm(mm);
    
    ctx->ret = ret;
    complete(&ctx->done);
    return 0;
}

int injector_protect(struct snake_inject_protect *protect_info)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct protect_ctx ctx;
    struct task_struct *worker;

    rcu_read_lock();
    task = pid_task(find_vpid(protect_info->pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    ctx.target_mm = mm;
    ctx.start = protect_info->address;
    ctx.len = PAGE_ALIGN(protect_info->size);
    ctx.prot = map_prot_flags(protect_info->protection);
    init_completion(&ctx.done);

    worker = kthread_run(injector_protect_worker, &ctx, "snake_protect");
    if (IS_ERR(worker)) {
        mmput(mm);
        put_task_struct(task);
        return PTR_ERR(worker);
    }

    if (!wait_for_completion_timeout(&ctx.done,
            msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS))) {
        pr_err("snakedrv: protect worker timed out\n");
        mmput(mm);
        put_task_struct(task);
        return -ETIMEDOUT;
    }

    mmput(mm);
    put_task_struct(task);
    return ctx.ret;
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

/* ============================================================================
 * Shadow Memory: Pin-and-Hide Approach
 *
 * Strategy:
 *   1. vm_mmap(MAP_POPULATE) creates VMA + PTEs + resident pages
 *   2. get_user_pages_remote() pins every page (refcount++)
 *   3. injector_hide_vma() removes VMA from maple tree
 *   4. Pages stay resident (pinned), PTEs intact, no /proc visibility
 *   5. Writes go directly to pinned pages via kmap_local_page
 *
 * All functions used (vm_mmap, get_user_pages_remote, kthread_use_mm,
 * kmap_local_page) are EXPORT_SYMBOL — no unexported symbol hacks.
 * ============================================================================ */

#include <linux/highmem.h>

#define SHADOW_MAX_SIZE		(256UL << 20)

struct shadow_alloc_entry {
	struct list_head list;
	struct mm_struct *mm;
	pid_t pid;
	unsigned long vaddr;
	unsigned long size;
	unsigned int nr_pages;
	struct page **pages;   /* pinned pages from get_user_pages */
};

static DEFINE_MUTEX(shadow_mutex);
static LIST_HEAD(shadow_list);

/* Worker context for vm_mmap in target mm */
struct shadow_mmap_ctx {
	struct mm_struct *mm;
	unsigned long size;
	unsigned long prot;
	unsigned long addr_out;
	struct completion done;
	int ret;
};

static int shadow_mmap_worker(void *data)
{
	struct shadow_mmap_ctx *ctx = data;

	kthread_use_mm(ctx->mm);

	ctx->addr_out = vm_mmap(NULL, 0, ctx->size, ctx->prot,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
				0);
	if (IS_ERR_VALUE(ctx->addr_out)) {
		ctx->ret = (int)ctx->addr_out;
		ctx->addr_out = 0;
	} else {
		ctx->ret = 0;
	}

	kthread_unuse_mm(ctx->mm);
	complete(&ctx->done);
	return 0;
}

struct shadow_unmap_ctx {
	struct mm_struct *mm;
	unsigned long addr;
	unsigned long size;
	struct completion done;
	int ret;
};

static int shadow_unmap_worker(void *data)
{
	struct shadow_unmap_ctx *ctx = data;

	kthread_use_mm(ctx->mm);
	ctx->ret = vm_munmap(ctx->addr, ctx->size);
	kthread_unuse_mm(ctx->mm);

	complete(&ctx->done);
	return 0;
}

static void shadow_unmap_allocation(struct mm_struct *mm,
				    unsigned long addr,
				    unsigned long size)
{
	struct shadow_unmap_ctx ctx;
	struct task_struct *worker;

	if (!addr || !size)
		return;

	ctx.mm = mm;
	ctx.addr = addr;
	ctx.size = size;
	init_completion(&ctx.done);

	worker = kthread_run(shadow_unmap_worker, &ctx, "snake_sh_unmap");
	if (IS_ERR(worker)) {
		pr_warn("snakedrv: shadow unmap worker failed: %ld\n",
			PTR_ERR(worker));
		return;
	}

	if (!wait_for_completion_timeout(&ctx.done,
			msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS))) {
		pr_warn("snakedrv: shadow unmap timed out\n");
		return;
	}

	if (ctx.ret)
		pr_warn("snakedrv: shadow unmap failed: %d\n", ctx.ret);
}

static struct shadow_alloc_entry *
shadow_find_entry(pid_t pid, unsigned long addr)
{
	struct shadow_alloc_entry *sa;

	list_for_each_entry(sa, &shadow_list, list) {
		if (sa->pid == pid &&
		    addr >= sa->vaddr && addr < sa->vaddr + sa->size)
			return sa;
	}
	return NULL;
}

static void shadow_unpin_pages(struct shadow_alloc_entry *sa)
{
	unsigned int i;

	for (i = 0; i < sa->nr_pages; i++) {
		if (sa->pages[i])
			put_page(sa->pages[i]);
	}
}

/*
 * shadow_reclaim_ctx - Worker to re-create VMA at the shadow address
 * via MAP_FIXED, then immediately vm_munmap it.  This forces the
 * kernel to properly tear down orphaned PTEs and restore mm accounting.
 */
struct shadow_reclaim_ctx {
	struct mm_struct *mm;
	unsigned long addr;
	unsigned long size;
	struct completion done;
	int ret;
};

static int shadow_reclaim_worker(void *data)
{
	struct shadow_reclaim_ctx *ctx = data;
	unsigned long addr;

	kthread_use_mm(ctx->mm);

	/*
	 * MAP_FIXED at the shadow address forces the kernel to:
	 *  1. Create a new VMA covering [addr, addr+size)
	 *  2. Tear down any existing PTEs in that range (zap_page_range)
	 *  3. Map fresh anonymous pages
	 * This cleans up our orphaned PTEs from the hidden VMA.
	 */
	addr = vm_mmap(NULL, ctx->addr, ctx->size,
		       PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0);
	if (!IS_ERR_VALUE(addr)) {
		/* Now munmap to release everything cleanly */
		vm_munmap(addr, ctx->size);
		ctx->ret = 0;
	} else {
		ctx->ret = (int)addr;
	}

	kthread_unuse_mm(ctx->mm);
	complete(&ctx->done);
	return 0;
}

static void shadow_restore_and_cleanup(struct shadow_alloc_entry *sa)
{
	struct shadow_reclaim_ctx ctx;
	struct task_struct *worker;

	if (atomic_read(&sa->mm->mm_users) == 0)
		return;

	ctx.mm   = sa->mm;
	ctx.addr = sa->vaddr;
	ctx.size = sa->size;
	init_completion(&ctx.done);

	worker = kthread_run(shadow_reclaim_worker, &ctx, "snake_sh_clean");
	if (IS_ERR(worker))
		return;

	if (!wait_for_completion_timeout(&ctx.done,
			msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS))) {
		pr_warn("snakedrv: shadow reclaim timed out\n");
		return;
	}

	if (ctx.ret)
		pr_warn("snakedrv: shadow reclaim failed: %d\n", ctx.ret);
}

static void shadow_teardown_entry(struct shadow_alloc_entry *sa)
{
	/*
	 * 1. Unpin pages (drop the get_user_pages reference)
	 * 2. MAP_FIXED + vm_munmap to reclaim the address range,
	 *    zap orphaned PTEs, and restore mm_struct accounting
	 * 3. Release mm reference and free tracking structures
	 */
	shadow_unpin_pages(sa);
	shadow_restore_and_cleanup(sa);
	mmput(sa->mm);
	kvfree(sa->pages);
	kfree(sa);
}

/* ---- public API ---- */

/**
 * injector_shadow_alloc - Allocate invisible memory in target process
 *
 * 1. vm_mmap(MAP_POPULATE) in target mm context (creates VMA + pages)
 * 2. Pin all pages with get_user_pages_remote (prevents reclaim)
 * 3. Hide VMA from maple tree (removes /proc/pid/maps visibility)
 * 4. Pages stay resident via pin, PTEs intact, invisible
 */
int injector_shadow_alloc(struct snake_shadow_alloc *info)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct shadow_alloc_entry *sa;
	struct shadow_mmap_ctx ctx;
	struct task_struct *worker;
	unsigned long size;
	unsigned int nr_pages;
	long pinned;

	size = PAGE_ALIGN(info->size);
	if (size == 0 || size > SHADOW_MAX_SIZE)
		return -EINVAL;
	nr_pages = size >> PAGE_SHIFT;

	/* Resolve target */
	rcu_read_lock();
	task = pid_task(find_vpid(info->pid), PIDTYPE_PID);
	if (!task) { rcu_read_unlock(); return -ESRCH; }
	get_task_struct(task);
	rcu_read_unlock();

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -EINVAL;

	/* Step 1: allocate in target mm via worker thread */
	ctx.mm       = mm;
	ctx.size     = size;
	ctx.prot     = 0;
	if (info->protection & SNAKE_PROT_READ)  ctx.prot |= PROT_READ;
	if (info->protection & SNAKE_PROT_WRITE) ctx.prot |= PROT_WRITE;
	if (info->protection & SNAKE_PROT_EXEC)  ctx.prot |= PROT_EXEC;
	init_completion(&ctx.done);

	worker = kthread_run(shadow_mmap_worker, &ctx, "snake_shadow");
	if (IS_ERR(worker)) {
		mmput(mm);
		return PTR_ERR(worker);
	}

	if (!wait_for_completion_timeout(&ctx.done,
			msecs_to_jiffies(INJECTOR_WORKER_TIMEOUT_MS))) {
		mmput(mm);
		return -ETIMEDOUT;
	}

	if (ctx.ret) {
		mmput(mm);
		return ctx.ret;
	}

	/* Tracking structure */
	sa = kzalloc(sizeof(*sa), GFP_KERNEL);
	if (!sa) {
		shadow_unmap_allocation(mm, ctx.addr_out, size);
		mmput(mm);
		return -ENOMEM;
	}

	sa->pages = kvmalloc_array(nr_pages, sizeof(struct page *),
				   GFP_KERNEL | __GFP_ZERO);
	if (!sa->pages) {
		shadow_unmap_allocation(mm, ctx.addr_out, size);
		kfree(sa);
		mmput(mm);
		return -ENOMEM;
	}

	/* Step 2: pin every page so they survive VMA removal */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	pinned = get_user_pages_remote(mm, ctx.addr_out, nr_pages,
				       FOLL_GET | FOLL_WRITE,
				       sa->pages, NULL);
#else
	pinned = get_user_pages_remote(mm, ctx.addr_out, nr_pages,
				       FOLL_GET | FOLL_WRITE, 0,
				       sa->pages, NULL);
#endif
	if (pinned != (long)nr_pages) {
		unsigned int i;

		pr_err("snakedrv: shadow pin failed: got %ld/%u pages\n",
		       pinned, nr_pages);
		for (i = 0; i < (pinned > 0 ? pinned : 0); i++)
			put_page(sa->pages[i]);
		shadow_unmap_allocation(mm, ctx.addr_out, size);
		kvfree(sa->pages);
		kfree(sa);
		mmput(mm);
		return -EFAULT;
	}

	/* Step 3: hide VMA — pages stay mapped via PTEs + pin */
	injector_hide_vma(mm, ctx.addr_out);

	sa->mm       = mm;   /* hold mm ref for lifetime */
	sa->pid      = info->pid;
	sa->vaddr    = ctx.addr_out;
	sa->size     = size;
	sa->nr_pages = nr_pages;

	mutex_lock(&shadow_mutex);
	list_add(&sa->list, &shadow_list);
	mutex_unlock(&shadow_mutex);

	info->address = ctx.addr_out;
	info->result  = 0;

	pr_info("snakedrv: shadow alloc %u pages at 0x%lx pid=%d (pinned+hidden)\n",
		nr_pages, ctx.addr_out, info->pid);
	return 0;
}

/**
 * injector_shadow_write - Write data directly to pinned pages via kmap
 *
 * Bypasses access_process_vm (which needs a VMA).
 */
ssize_t injector_shadow_write(struct snake_shadow_write *info)
{
	struct shadow_alloc_entry *sa;
	unsigned long offset;
	void __user *ubuf;
	ssize_t written = 0;

	mutex_lock(&shadow_mutex);
	sa = shadow_find_entry(info->pid, info->address);
	mutex_unlock(&shadow_mutex);
	if (!sa)
		return -ENOENT;

	offset = info->address - sa->vaddr;
	ubuf   = (void __user *)info->user_buffer;
	if (offset + info->size > sa->size)
		return -ERANGE;

	while (written < (ssize_t)info->size) {
		unsigned int pidx = (offset + written) >> PAGE_SHIFT;
		unsigned int poff = (offset + written) & (PAGE_SIZE - 1);
		size_t chunk = min_t(size_t, PAGE_SIZE - poff,
				     info->size - written);
		void *kaddr;

		if (pidx >= sa->nr_pages)
			break;

		kaddr = kmap_local_page(sa->pages[pidx]);
		if (copy_from_user(kaddr + poff, ubuf + written, chunk)) {
			kunmap_local(kaddr);
			return written ? written : -EFAULT;
		}
		kunmap_local(kaddr);
		written += chunk;
	}

	return written;
}

/**
 * injector_shadow_read - Read from pinned pages (kernel-internal)
 *
 * Returns -ENOENT if addr is not in any shadow allocation.
 */
ssize_t injector_shadow_read(pid_t pid, uint64_t addr, void *buf, size_t len)
{
	struct shadow_alloc_entry *sa;
	unsigned long offset;
	ssize_t done = 0;

	mutex_lock(&shadow_mutex);
	sa = shadow_find_entry(pid, (unsigned long)addr);
	mutex_unlock(&shadow_mutex);
	if (!sa)
		return -ENOENT;

	offset = (unsigned long)addr - sa->vaddr;
	if (offset + len > sa->size)
		len = sa->size - offset;

	while (done < (ssize_t)len) {
		unsigned int pidx = (offset + done) >> PAGE_SHIFT;
		unsigned int poff = (offset + done) & (PAGE_SIZE - 1);
		size_t chunk = min_t(size_t, PAGE_SIZE - poff, len - done);
		void *kaddr;

		if (pidx >= sa->nr_pages)
			break;

		kaddr = kmap_local_page(sa->pages[pidx]);
		memcpy(buf + done, kaddr + poff, chunk);
		kunmap_local(kaddr);
		done += chunk;
	}

	return done;
}

/**
 * injector_shadow_free - Unpin pages and release tracking
 */
int injector_shadow_free(struct snake_shadow_alloc *info)
{
	struct shadow_alloc_entry *sa = NULL, *iter;

	mutex_lock(&shadow_mutex);
	list_for_each_entry(iter, &shadow_list, list) {
		if (iter->pid == info->pid &&
		    iter->vaddr == info->address) {
			sa = iter;
			list_del(&sa->list);
			break;
		}
	}
	mutex_unlock(&shadow_mutex);
	if (!sa)
		return -ENOENT;

	shadow_teardown_entry(sa);
	pr_info("snakedrv: shadow free 0x%llx pid=%d\n",
		info->address, info->pid);
	return 0;
}

void injector_shadow_cleanup_pid(pid_t pid)
{
	struct shadow_alloc_entry *sa, *tmp;
	LIST_HEAD(condemned);

	mutex_lock(&shadow_mutex);
	list_for_each_entry_safe(sa, tmp, &shadow_list, list) {
		if (sa->pid == pid) {
			list_del(&sa->list);
			list_add(&sa->list, &condemned);
		}
	}
	mutex_unlock(&shadow_mutex);

	list_for_each_entry_safe(sa, tmp, &condemned, list) {
		list_del(&sa->list);
		pr_info("snakedrv: shadow cleanup 0x%lx pid=%d\n",
			sa->vaddr, sa->pid);
		shadow_teardown_entry(sa);
	}
}

void injector_shadow_cleanup_all(void)
{
	struct shadow_alloc_entry *sa, *tmp;

	mutex_lock(&shadow_mutex);
	list_for_each_entry_safe(sa, tmp, &shadow_list, list) {
		list_del(&sa->list);
		shadow_teardown_entry(sa);
	}
	mutex_unlock(&shadow_mutex);
}
