// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Process Backend Implementation
 *
 * High-performance Linux process memory access backend.
 * Implements the generic backend interface for traditional process attachment.
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>

/* Include userland header for shared types */
#include "../userland/include/snakedrv_scanner.h"

#include "snakedrv_backend.h"

/* ============================================================================
 * Process Context (Private Data)
 * ============================================================================ */

/**
 * struct process_context - Process backend private data
 * @pid: Process ID
 * @task: Task struct pointer
 * @mm: Memory map struct pointer
 */
struct process_context {
	pid_t pid;
	struct task_struct *task;
	struct mm_struct *mm;
};

/* ============================================================================
 * Process Backend Operations
 * ============================================================================ */

/**
 * process_backend_read - Read memory from Linux process
 */
static ssize_t process_backend_read(struct memory_backend *backend,
                                    uint64_t address, void *buffer,
                                    size_t size)
{
	struct process_context *ctx;
	ssize_t ret;

	if (!backend || !backend->private_data)
		return -EINVAL;

	ctx = (struct process_context *)backend->private_data;

	/* Validate task is still alive */
	if (!ctx->task || !ctx->mm) {
		pr_debug("snakedrv: Process backend: task/mm is NULL\n");
		return -ESRCH;
	}

	/* Use access_process_vm for direct memory access */
	ret = access_process_vm(ctx->task, address, buffer, size, FOLL_FORCE);

	if (ret != size) {
		pr_debug("snakedrv: Process read at 0x%llx: wanted %zu, got %zd\n",
		         address, size, ret);
	}

	return ret;
}

/**
 * process_backend_write - Write memory to Linux process
 */
static ssize_t process_backend_write(struct memory_backend *backend,
                                     uint64_t address, const void *buffer,
                                     size_t size)
{
	struct process_context *ctx;
	ssize_t ret;

	if (!backend || !backend->private_data)
		return -EINVAL;

	ctx = (struct process_context *)backend->private_data;

	/* Validate task is still alive */
	if (!ctx->task || !ctx->mm) {
		pr_debug("snakedrv: Process backend: task/mm is NULL\n");
		return -ESRCH;
	}

	/* Use access_process_vm with write flag */
	ret = access_process_vm(ctx->task, address, (void *)buffer, size,
	                       FOLL_FORCE | FOLL_WRITE);

	if (ret != size) {
		pr_debug("snakedrv: Process write at 0x%llx: wanted %zu, got %zd\n",
		         address, size, ret);
	}

	return ret;
}

/**
 * process_backend_translate - Translate virtual to physical address
 *
 * For process backend, we don't do VA→PA translation as we work directly
 * with virtual addresses. This function returns -ENOSYS.
 */
static int process_backend_translate(struct memory_backend *backend,
                                     uint64_t vaddr, uint64_t *paddr)
{
	/* Process backend doesn't support VA→PA translation */
	return -ENOSYS;
}

/**
 * process_backend_flush_cache - Flush process backend caches
 *
 * For process backend, there's no TLB to flush. This is a no-op.
 */
static void process_backend_flush_cache(struct memory_backend *backend)
{
	/* No-op for process backend */
	pr_debug("snakedrv: Process backend cache flush (no-op)\n");
}

/**
 * process_backend_get_info - Get process backend information
 */
static ssize_t process_backend_get_info(struct memory_backend *backend,
                                       char *buf, size_t size)
{
	struct process_context *ctx;
	struct task_struct *task;
	char comm[TASK_COMM_LEN];
	unsigned long vm_size = 0;

	if (!backend || !backend->private_data || !buf)
		return -EINVAL;

	ctx = (struct process_context *)backend->private_data;
	task = ctx->task;

	if (task) {
		get_task_comm(comm, task);
		if (ctx->mm)
			vm_size = ctx->mm->total_vm << PAGE_SHIFT;
	} else {
		strncpy(comm, "<dead>", sizeof(comm));
	}

	return scnprintf(buf, size,
		"Process Backend\n"
		"  PID:          %d\n"
		"  Command:      %s\n"
		"  VM Size:      %lu MB\n"
		"  Status:       %s\n",
		ctx->pid,
		comm,
		vm_size / (1024 * 1024),
		task ? "Alive" : "Dead");
}

/**
 * process_backend_destroy - Cleanup process backend
 */
static void process_backend_destroy(struct memory_backend *backend)
{
	struct process_context *ctx;

	if (!backend || !backend->private_data)
		return;

	ctx = (struct process_context *)backend->private_data;

	pr_info("snakedrv: Destroying process backend (PID %d)\n", ctx->pid);

	/* Release mm_struct reference */
	if (ctx->mm) {
		mmput(ctx->mm);
		ctx->mm = NULL;
	}

	/* Release task_struct reference */
	if (ctx->task) {
		put_task_struct(ctx->task);
		ctx->task = NULL;
	}

	/* Free context */
	kfree(ctx);
	backend->private_data = NULL;
}

/* ============================================================================
 * Process Backend Operations Table
 * ============================================================================ */

static const struct backend_ops process_backend_ops = {
	.read        = process_backend_read,
	.write       = process_backend_write,
	.translate   = process_backend_translate,
	.flush_cache = process_backend_flush_cache,
	.get_info    = process_backend_get_info,
	.destroy     = process_backend_destroy,
};

/* ============================================================================
 * Process Backend Factory
 * ============================================================================ */

/**
 * backend_create_process - Create a new process backend instance
 * @process_pid: PID of process to attach to
 *
 * Creates and initializes a process backend instance for traditional
 * Linux process memory access.
 *
 * Return: Pointer to backend, or NULL on failure
 */
struct memory_backend *backend_create_process(pid_t process_pid)
{
	struct memory_backend *backend;
	struct process_context *ctx;
	struct task_struct *task;
	struct mm_struct *mm;

	/* Find the task struct */
	rcu_read_lock();
	task = pid_task(find_vpid(process_pid), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		pr_err("snakedrv: Process PID %d not found\n", process_pid);
		return NULL;
	}
	get_task_struct(task);
	rcu_read_unlock();

	/* Get the mm struct */
	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		pr_err("snakedrv: Process PID %d has no mm struct (kernel thread?)\n",
		       process_pid);
		return NULL;
	}

	/* Allocate backend structure */
	backend = kzalloc(sizeof(*backend), GFP_KERNEL);
	if (!backend) {
		mmput(mm);
		put_task_struct(task);
		return NULL;
	}

	/* Allocate process context */
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		mmput(mm);
		put_task_struct(task);
		kfree(backend);
		return NULL;
	}

	/* Initialize context */
	ctx->pid = process_pid;
	ctx->task = task;
	ctx->mm = mm;

	/* Initialize backend */
	backend->ops = &process_backend_ops;
	backend->type = BACKEND_TYPE_PROCESS;
	backend->private_data = ctx;
	spin_lock_init(&backend->lock);
	atomic_set(&backend->refcount, 1);
	snprintf(backend->name, sizeof(backend->name),
	         "Process-PID-%d", process_pid);

	/* Initialize statistics */
	atomic64_set(&backend->stats.reads, 0);
	atomic64_set(&backend->stats.writes, 0);
	atomic64_set(&backend->stats.bytes_read, 0);
	atomic64_set(&backend->stats.bytes_written, 0);
	atomic64_set(&backend->stats.read_errors, 0);
	atomic64_set(&backend->stats.write_errors, 0);
	atomic64_set(&backend->stats.total_read_ns, 0);
	atomic64_set(&backend->stats.total_write_ns, 0);

	pr_info("snakedrv: Created process backend for PID %d (%s)\n",
	        process_pid, task->comm);

	return backend;
}
