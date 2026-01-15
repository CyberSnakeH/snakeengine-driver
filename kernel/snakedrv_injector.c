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
     * We modify the VMA flags to disable dumping and merging before unlinking.
     * VM_IO | VM_PFNMAP prevents core dumping and some access checks.
     * VM_DONTEXPAND prevents growing.
     */
    {
        /* Use raw pointer access to bypass const qualifiers in newer kernels */
        unsigned long *flags_ptr = (unsigned long *)&vma->vm_flags;
        *flags_ptr |= (VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    /* 
     * Kernel 6.1+ uses Maple Trees (MA_STATE) 
     * We use the VMA iterator API (or direct Maple State) to remove the entry.
     */
    {
        struct vma_iterator vmi;
        
        /* Initialize iterator at address */
        vma_iter_init(&vmi, mm, addr);
        
        /* 
         * Store NULL at the current range to remove it.
         * using mas_store directly as vma_iter_store might not be exported/visible.
         */
        /* 
         * Store NULL at the current range to remove it.
         * using mas_store directly as vma_iter_store might not be exported/visible.
         */
        mas_store(&vmi.mas, NULL);
        if (mas_is_err(&vmi.mas)) {
             pr_warn("snakedrv: Failed to unlink VMA (maple tree error)\n");
        } else {
             mm->map_count--;
             pr_info("snakedrv: VMA unlinked (Maple Tree)\n");
        }
        // pr_info("snakedrv: VMA stealth skipped for debugging\n");
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

    /* Wait for allocation to complete */
    wait_for_completion(&ctx.done);

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

    /* Use kthread to ensure we are in a clean context */
    worker = kthread_run(injector_stealth_worker, &ctx, "snake_stealth");
    if (IS_ERR(worker)) {
        mmput(mm);
        put_task_struct(task);
        return PTR_ERR(worker);
    }

    wait_for_completion(&ctx.done);
    
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
            unsigned long new_flags = vma->vm_flags;
            
            if (ctx->prot & PROT_EXEC) {
                new_flags |= VM_EXEC;
            }
            if (ctx->prot & PROT_WRITE) {
                new_flags |= VM_WRITE;
            }
            if (ctx->prot & PROT_READ) {
                new_flags |= VM_READ;
            }
            
            /* Force update flags (Kernel hack) */
            /* In newer kernels vm_flags might be const or require special accessors */
            /* We use a pointer cast to write to it regardless */
            *(unsigned long *)&vma->vm_flags = new_flags;
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

    wait_for_completion(&ctx.done);
    
    mmput(mm);
    put_task_struct(task);
    return ctx.ret;
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
        send_sig(SIGCONT, task, 1);
        put_task_struct(task);
        return -EAGAIN;
    }

    /* Step 3: Get registers */
    regs = task_pt_regs(task);
    if (!regs) {
        pr_err("snakedrv: Cannot get pt_regs\n");
        send_sig(SIGCONT, task, 1);
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
        unsigned long new_sp = original_rsp - 8;
        int written = access_process_vm(task, new_sp,
                                        &original_rip,
                                        sizeof(original_rip),
                                        1);
        if (written != sizeof(original_rip)) {
            pr_err("snakedrv: Failed to write return address (%d)\n", written);
            send_sig(SIGCONT, task, 1);
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

    /* Step 4: Resume the task */
    wake_up_process(task);
    send_sig(SIGCONT, task, 1);

    pr_info("snakedrv: Task resumed, state: 0x%x\n", READ_ONCE(task->__state));

    put_task_struct(task);
    return 0;
}
