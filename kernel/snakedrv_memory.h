// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Memory Management & Optimization
 *
 * Advanced memory management for high-performance scanning:
 * - Slab caches for frequently allocated objects
 * - Object pooling to reduce alloc/free overhead
 * - Dynamic resizing to minimize waste
 * - Memory limits to prevent OOM
 *
 * Inspired by:
 * - Linux kernel slab allocator
 * - SLUB allocator design
 * - High-performance database memory pools
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_MEMORY_H_
#define _SNAKEDRV_MEMORY_H_

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>

/* ============================================================================
 * Memory Configuration
 * ============================================================================ */

/* Maximum memory usage per session (256 MB default) */
#define SNAKEDRV_MAX_MEMORY_PER_SESSION  (256 * 1024 * 1024)

/* Result set pool size (number of cached result sets) */
#define SNAKEDRV_RESULT_SET_POOL_SIZE    8

/* Scan buffer pool size (number of cached buffers) */
#define SNAKEDRV_SCAN_BUFFER_POOL_SIZE   16

/* Initial result set capacity (grows dynamically) */
#define SNAKEDRV_INITIAL_RESULT_CAPACITY 1024

/* Growth factor for dynamic resizing (2x) */
#define SNAKEDRV_GROWTH_FACTOR           2

/* ============================================================================
 * Slab Caches
 * ============================================================================ */

/**
 * struct snakedrv_slab_caches - Kernel slab caches for fast allocation
 * @scan_result_cache: Cache for scan_result structures
 * @result_set_cache: Cache for scan_result_set structures
 *
 * Slab caches provide:
 * - Fast allocation (O(1) in most cases)
 * - Better cache locality (objects aligned)
 * - Reduced fragmentation (fixed-size objects)
 * - Memory reuse (objects pooled)
 */
struct snakedrv_slab_caches {
	struct kmem_cache *scan_result_cache;
	struct kmem_cache *result_set_cache;
};

/* Global slab caches */
extern struct snakedrv_slab_caches *snakedrv_caches;

/**
 * snakedrv_init_slab_caches - Initialize slab caches
 *
 * Creates kernel slab caches for frequently allocated objects.
 * Call once during module initialization.
 *
 * Return: 0 on success, negative error code on failure
 */
static inline int snakedrv_init_slab_caches(void)
{
	snakedrv_caches = kzalloc(sizeof(*snakedrv_caches), GFP_KERNEL);
	if (!snakedrv_caches)
		return -ENOMEM;

	/* Create cache for scan_result structures */
	snakedrv_caches->scan_result_cache = kmem_cache_create(
		"snakedrv_scan_result",
		sizeof(struct scan_result),
		0,
		SLAB_HWCACHE_ALIGN,  /* Align to cache line */
		NULL
	);
	if (!snakedrv_caches->scan_result_cache)
		goto fail_result;

	/* Create cache for scan_result_set structures */
	snakedrv_caches->result_set_cache = kmem_cache_create(
		"snakedrv_result_set",
		sizeof(struct scan_result_set),
		0,
		SLAB_HWCACHE_ALIGN,
		NULL
	);
	if (!snakedrv_caches->result_set_cache)
		goto fail_set;

	pr_info("snakedrv: Slab caches initialized (2 caches)\n");
	return 0;

fail_set:
	kmem_cache_destroy(snakedrv_caches->scan_result_cache);
fail_result:
	kfree(snakedrv_caches);
	snakedrv_caches = NULL;
	return -ENOMEM;
}

/**
 * snakedrv_destroy_slab_caches - Destroy slab caches
 *
 * Destroys all slab caches and frees memory.
 * Call once during module cleanup.
 */
static inline void snakedrv_destroy_slab_caches(void)
{
	if (!snakedrv_caches)
		return;

	if (snakedrv_caches->result_set_cache)
		kmem_cache_destroy(snakedrv_caches->result_set_cache);

	if (snakedrv_caches->scan_result_cache)
		kmem_cache_destroy(snakedrv_caches->scan_result_cache);

	kfree(snakedrv_caches);
	snakedrv_caches = NULL;

	pr_info("snakedrv: Slab caches destroyed\n");
}

/* ============================================================================
 * Scan Buffer Pool
 * ============================================================================ */

/**
 * struct scan_buffer - Pooled scan buffer
 * @data: Buffer data (cache-aligned)
 * @size: Buffer size in bytes
 * @in_use: Whether buffer is currently in use
 * @list: List linkage for pool
 */
struct scan_buffer {
	uint8_t *data;
	size_t size;
	bool in_use;
	struct list_head list;
};

/**
 * struct scan_buffer_pool - Pool of reusable scan buffers
 * @buffers: List of scan_buffer structures
 * @lock: Spinlock for thread-safe access
 * @count: Number of buffers in pool
 * @hits: Number of buffer pool hits (statistics)
 * @misses: Number of buffer pool misses (statistics)
 */
struct scan_buffer_pool {
	struct list_head buffers;
	spinlock_t lock;
	uint32_t count;
	atomic64_t hits;
	atomic64_t misses;
};

/**
 * snakedrv_buffer_pool_init - Initialize scan buffer pool
 * @pool: Buffer pool to initialize
 * @buffer_size: Size of each buffer
 * @buffer_count: Number of buffers to pre-allocate
 *
 * Return: 0 on success, negative error code on failure
 */
static inline int snakedrv_buffer_pool_init(struct scan_buffer_pool *pool,
                                            size_t buffer_size,
                                            uint32_t buffer_count)
{
	uint32_t i;

	INIT_LIST_HEAD(&pool->buffers);
	spin_lock_init(&pool->lock);
	pool->count = 0;
	atomic64_set(&pool->hits, 0);
	atomic64_set(&pool->misses, 0);

	/* Pre-allocate buffers */
	for (i = 0; i < buffer_count; i++) {
		struct scan_buffer *buf;

		buf = kzalloc(sizeof(*buf), GFP_KERNEL);
		if (!buf)
			continue;

		buf->data = kvmalloc(buffer_size, GFP_KERNEL);
		if (!buf->data) {
			kfree(buf);
			continue;
		}

		buf->size = buffer_size;
		buf->in_use = false;
		list_add_tail(&buf->list, &pool->buffers);
		pool->count++;
	}

	pr_info("snakedrv: Buffer pool initialized: %u buffers × %zu KB\n",
	        pool->count, buffer_size / 1024);

	return 0;
}

/**
 * snakedrv_buffer_pool_acquire - Get buffer from pool
 * @pool: Buffer pool
 * @size: Desired buffer size
 *
 * Tries to get a free buffer from the pool. If none available or
 * size doesn't match, allocates a new buffer.
 *
 * Return: Pointer to buffer data, or NULL on failure
 */
static inline uint8_t *snakedrv_buffer_pool_acquire(struct scan_buffer_pool *pool,
                                                    size_t size)
{
	struct scan_buffer *buf;
	unsigned long flags;
	uint8_t *data = NULL;

	spin_lock_irqsave(&pool->lock, flags);

	/* Try to find free buffer of appropriate size */
	list_for_each_entry(buf, &pool->buffers, list) {
		if (!buf->in_use && buf->size >= size) {
			buf->in_use = true;
			data = buf->data;
			atomic64_inc(&pool->hits);
			goto out;
		}
	}

	spin_unlock_irqrestore(&pool->lock, flags);

	/* No suitable buffer found - allocate new one */
	atomic64_inc(&pool->misses);
	return kvmalloc(size, GFP_KERNEL);

out:
	spin_unlock_irqrestore(&pool->lock, flags);
	return data;
}

/**
 * snakedrv_buffer_pool_release - Return buffer to pool
 * @pool: Buffer pool
 * @data: Buffer data pointer
 *
 * Returns buffer to pool for reuse. If buffer was not from pool,
 * frees it normally.
 */
static inline void snakedrv_buffer_pool_release(struct scan_buffer_pool *pool,
                                                uint8_t *data)
{
	struct scan_buffer *buf;
	unsigned long flags;
	bool found = false;

	if (!data)
		return;

	spin_lock_irqsave(&pool->lock, flags);

	/* Check if buffer belongs to pool */
	list_for_each_entry(buf, &pool->buffers, list) {
		if (buf->data == data) {
			buf->in_use = false;
			found = true;
			break;
		}
	}

	spin_unlock_irqrestore(&pool->lock, flags);

	/* If not from pool, free it */
	if (!found)
		kvfree(data);
}

/**
 * snakedrv_buffer_pool_destroy - Destroy buffer pool
 * @pool: Buffer pool to destroy
 */
static inline void snakedrv_buffer_pool_destroy(struct scan_buffer_pool *pool)
{
	struct scan_buffer *buf, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);

	list_for_each_entry_safe(buf, tmp, &pool->buffers, list) {
		list_del(&buf->list);
		if (buf->data)
			kvfree(buf->data);
		kfree(buf);
	}

	pool->count = 0;

	spin_unlock_irqrestore(&pool->lock, flags);

	pr_info("snakedrv: Buffer pool destroyed (hits: %lld, misses: %lld, hit_rate: %lld%%)\n",
	        atomic64_read(&pool->hits),
	        atomic64_read(&pool->misses),
	        atomic64_read(&pool->hits) * 100 /
	        (atomic64_read(&pool->hits) + atomic64_read(&pool->misses) + 1));
}

/* ============================================================================
 * Memory Tracking
 * ============================================================================ */

/**
 * struct snakedrv_memory_stats - Memory usage statistics
 * @allocated_bytes: Total bytes allocated
 * @peak_bytes: Peak memory usage
 * @allocation_count: Number of allocations
 * @free_count: Number of frees
 */
struct snakedrv_memory_stats {
	atomic64_t allocated_bytes;
	atomic64_t peak_bytes;
	atomic64_t allocation_count;
	atomic64_t free_count;
};

/**
 * snakedrv_track_alloc - Track memory allocation
 * @stats: Memory statistics structure
 * @size: Size of allocation in bytes
 */
static inline void snakedrv_track_alloc(struct snakedrv_memory_stats *stats,
                                        size_t size)
{
	int64_t current_mem, peak_mem;

	atomic64_add(size, &stats->allocated_bytes);
	atomic64_inc(&stats->allocation_count);

	/* Update peak if necessary */
	current_mem = atomic64_read(&stats->allocated_bytes);
	do {
		peak_mem = atomic64_read(&stats->peak_bytes);
		if (current_mem <= peak_mem)
			break;
	} while (atomic64_cmpxchg(&stats->peak_bytes, peak_mem, current_mem) != peak_mem);
}

/**
 * snakedrv_track_free - Track memory free
 * @stats: Memory statistics structure
 * @size: Size of freed memory in bytes
 */
static inline void snakedrv_track_free(struct snakedrv_memory_stats *stats,
                                       size_t size)
{
	atomic64_sub(size, &stats->allocated_bytes);
	atomic64_inc(&stats->free_count);
}

#endif /* _SNAKEDRV_MEMORY_H_ */
