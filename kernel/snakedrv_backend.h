// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Memory Backend Interface
 *
 * World-class abstraction layer for memory access operations.
 * Supports process attachment with zero-overhead virtual dispatch.
 *
 * Architecture inspired by:
 * - Linux Kernel VFS (Virtual File System)
 * - Windows Driver Framework
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_BACKEND_H_
#define _SNAKEDRV_BACKEND_H_

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

/* ============================================================================
 * Backend Types
 * ============================================================================ */

/* Note: enum backend_type is defined in userland/include/snakedrv_scanner.h */
#define BACKEND_TYPE_PROCESS BACKEND_PROCESS
#ifndef BACKEND_TYPE_MAX
#define BACKEND_TYPE_MAX 3
#endif

/* ============================================================================
 * Performance Statistics
 * ============================================================================ */

/**
 * struct backend_stats - Performance metrics for backend
 * @reads: Number of read operations
 * @writes: Number of write operations
 * @bytes_read: Total bytes read
 * @bytes_written: Total bytes written
 * @read_errors: Number of failed reads
 * @write_errors: Number of failed writes
 * @tlb_hits: TLB cache hits (if applicable)
 * @tlb_misses: TLB cache misses (if applicable)
 * @page_walks: Number of page table walks
 * @avg_read_ns: Average read latency in nanoseconds
 * @avg_write_ns: Average write latency in nanoseconds
 *
 * Real-time performance monitoring for optimization.
 * Uses atomic operations for thread-safety without locks.
 */
struct backend_stats {
	atomic64_t reads;
	atomic64_t writes;
	atomic64_t bytes_read;
	atomic64_t bytes_written;
	atomic64_t read_errors;
	atomic64_t write_errors;
	atomic64_t total_read_ns;
	atomic64_t total_write_ns;
};

/* ============================================================================
 * Backend Operations (Virtual Function Table)
 * ============================================================================ */

struct memory_backend;  /* Forward declaration */

/**
 * struct backend_ops - Virtual function table for backend operations
 * @read: Read memory from target
 * @write: Write memory to target
 * @translate: Translate virtual address to physical (optional)
 * @flush_cache: Flush any internal caches
 * @get_info: Get backend information string
 * @destroy: Cleanup backend resources
 *
 * This vtable pattern enables polymorphic behavior with zero runtime overhead
 * when used with inline functions. The compiler can optimize away the indirect
 * calls in most cases.
 */
struct backend_ops {
	/**
	 * read - Read memory from backend
	 * @backend: Backend instance
	 * @address: Virtual address to read from
	 * @buffer: Destination buffer
	 * @size: Number of bytes to read
	 *
	 * Return: Number of bytes read, or negative error code
	 */
	ssize_t (*read)(struct memory_backend *backend, uint64_t address,
	                void *buffer, size_t size);

	/**
	 * write - Write memory to backend
	 * @backend: Backend instance
	 * @address: Virtual address to write to
	 * @buffer: Source buffer
	 * @size: Number of bytes to write
	 *
	 * Return: Number of bytes written, or negative error code
	 */
	ssize_t (*write)(struct memory_backend *backend, uint64_t address,
	                 const void *buffer, size_t size);

	/**
	 * translate - Translate virtual to physical address
	 * @backend: Backend instance
	 * @vaddr: Virtual address
	 * @paddr: Output physical address
	 *
	 * Optional operation for backends that support address translation.
	 *
	 * Return: 0 on success, negative error code on failure
	 */
	int (*translate)(struct memory_backend *backend, uint64_t vaddr,
	                 uint64_t *paddr);

	/**
	 * flush_cache - Flush backend caches
	 * @backend: Backend instance
	 *
	 * Flush TLB and other caches. Used when page tables change.
	 */
	void (*flush_cache)(struct memory_backend *backend);

	/**
	 * get_info - Get human-readable backend information
	 * @backend: Backend instance
	 * @buf: Output buffer
	 * @size: Buffer size
	 *
	 * Return: Number of bytes written to buffer
	 */
	ssize_t (*get_info)(struct memory_backend *backend, char *buf,
	                    size_t size);

	/**
	 * destroy - Cleanup backend resources
	 * @backend: Backend instance
	 *
	 * Called when backend is being destroyed. Should free all resources.
	 */
	void (*destroy)(struct memory_backend *backend);
};

/* ============================================================================
 * Memory Backend Structure
 * ============================================================================ */

/**
 * struct memory_backend - Generic memory backend instance
 * @ops: Virtual function table
 * @type: Backend type
 * @stats: Performance statistics
 * @private_data: Backend-specific data (process_context)
 * @lock: Spinlock for thread-safe operations
 * @refcount: Reference count for lifetime management
 * @name: Human-readable backend name
 *
 * This is the main abstraction for memory backends.
 * The vtable pattern provides polymorphism while maintaining performance.
 */
struct memory_backend {
	const struct backend_ops *ops;
	enum backend_type type;
	struct backend_stats stats;
	void *private_data;
	spinlock_t lock;
	atomic_t refcount;
	char name[64];
};

/* ============================================================================
 * Backend API - Inline for Zero-Cost Abstraction
 * ============================================================================ */

/**
 * backend_read - Read memory through backend
 *
 * Inline wrapper that enables compiler optimization while maintaining
 * clean abstraction. The indirect call can often be optimized away.
 */
static inline ssize_t backend_read(struct memory_backend *backend,
                                   uint64_t address, void *buffer,
                                   size_t size)
{
	ssize_t ret;
	ktime_t start, end;

	if (!backend || !backend->ops || !backend->ops->read)
		return -EINVAL;

	/* Performance monitoring */
	start = ktime_get();
	ret = backend->ops->read(backend, address, buffer, size);
	end = ktime_get();

	/* Update statistics */
	atomic64_inc(&backend->stats.reads);
	if (ret > 0) {
		atomic64_add(ret, &backend->stats.bytes_read);
		atomic64_add(ktime_to_ns(ktime_sub(end, start)),
		            &backend->stats.total_read_ns);
	} else {
		atomic64_inc(&backend->stats.read_errors);
	}

	return ret;
}

/**
 * backend_write - Write memory through backend
 */
static inline ssize_t backend_write(struct memory_backend *backend,
                                    uint64_t address, const void *buffer,
                                    size_t size)
{
	ssize_t ret;
	ktime_t start, end;

	if (!backend || !backend->ops || !backend->ops->write)
		return -EINVAL;

	/* Performance monitoring */
	start = ktime_get();
	ret = backend->ops->write(backend, address, buffer, size);
	end = ktime_get();

	/* Update statistics */
	atomic64_inc(&backend->stats.writes);
	if (ret > 0) {
		atomic64_add(ret, &backend->stats.bytes_written);
		atomic64_add(ktime_to_ns(ktime_sub(end, start)),
		            &backend->stats.total_write_ns);
	} else {
		atomic64_inc(&backend->stats.write_errors);
	}

	return ret;
}

/**
 * backend_translate - Translate virtual to physical address
 */
static inline int backend_translate(struct memory_backend *backend,
                                    uint64_t vaddr, uint64_t *paddr)
{
	if (!backend || !backend->ops)
		return -EINVAL;

	/* Translation is optional */
	if (!backend->ops->translate)
		return -ENOSYS;

	return backend->ops->translate(backend, vaddr, paddr);
}

/**
 * backend_flush_cache - Flush backend caches
 */
static inline void backend_flush_cache(struct memory_backend *backend)
{
	if (backend && backend->ops && backend->ops->flush_cache)
		backend->ops->flush_cache(backend);
}

/**
 * backend_get_info - Get backend information
 */
static inline ssize_t backend_get_info(struct memory_backend *backend,
                                       char *buf, size_t size)
{
	if (!backend || !backend->ops || !backend->ops->get_info)
		return -EINVAL;

	return backend->ops->get_info(backend, buf, size);
}

/**
 * backend_get_stats - Get performance statistics
 * @backend: Backend instance
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Return: Number of bytes written
 */
static inline ssize_t backend_get_stats(struct memory_backend *backend,
                                       char *buf, size_t size)
{
	uint64_t reads, writes, read_bytes, write_bytes;
	uint64_t read_errors, write_errors;
	uint64_t total_read_ns, total_write_ns;
	uint64_t avg_read_ns, avg_write_ns;

	if (!backend || !buf)
		return -EINVAL;

	/* Atomically read statistics */
	reads = atomic64_read(&backend->stats.reads);
	writes = atomic64_read(&backend->stats.writes);
	read_bytes = atomic64_read(&backend->stats.bytes_read);
	write_bytes = atomic64_read(&backend->stats.bytes_written);
	read_errors = atomic64_read(&backend->stats.read_errors);
	write_errors = atomic64_read(&backend->stats.write_errors);
	total_read_ns = atomic64_read(&backend->stats.total_read_ns);
	total_write_ns = atomic64_read(&backend->stats.total_write_ns);

	/* Calculate averages */
	avg_read_ns = reads ? total_read_ns / reads : 0;
	avg_write_ns = writes ? total_write_ns / writes : 0;

	return scnprintf(buf, size,
		"Backend: %s (Process)\n"
		"Reads:          %llu (%llu bytes, %llu errors)\n"
		"Writes:         %llu (%llu bytes, %llu errors)\n"
		"Avg Latency:    %llu ns read, %llu ns write\n",
		backend->name,
		reads, read_bytes, read_errors,
		writes, write_bytes, write_errors,
		avg_read_ns, avg_write_ns);
}

/* ============================================================================
 * Backend Lifecycle Management
 * ============================================================================ */

/**
 * backend_get - Increment reference count
 */
static inline void backend_get(struct memory_backend *backend)
{
	if (backend)
		atomic_inc(&backend->refcount);
}

/**
 * backend_put - Decrement reference count and destroy if zero
 */
static inline void backend_put(struct memory_backend *backend)
{
	if (!backend)
		return;

	if (atomic_dec_and_test(&backend->refcount)) {
		if (backend->ops && backend->ops->destroy)
			backend->ops->destroy(backend);
		kfree(backend);
	}
}

/* ============================================================================
 * Backend Factory Functions
 * ============================================================================ */

/* Implemented in backend-specific files */
struct memory_backend *backend_create_process(pid_t process_pid);

#endif /* _SNAKEDRV_BACKEND_H_ */
