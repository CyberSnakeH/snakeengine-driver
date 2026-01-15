// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Memory Scanner
 *
 * CheatEngine-equivalent memory scanning functionality.
 * Supports exact value, changed/unchanged, increased/decreased scans.
 *
 * PERFORMANCE OPTIMIZED: Cache-friendly chunking, prefetching, branch hints
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/cpumask.h>

/* Include userland header for shared types */
#include "../userland/include/snakedrv_scanner.h"

#include "snakedrv_backend.h"
#include "snakedrv_scanner.h"
#include "snakedrv_optimize.h"
#include "snakedrv_bloom.h"
#include "snakedrv_memory.h"
#include "snakedrv_benchmark.h"

/* ============================================================================
 * Global Memory Management
 * ============================================================================ */

/* Slab caches for fast allocation */
struct snakedrv_slab_caches *snakedrv_caches = NULL;

/* Global scan buffer pool */
static struct scan_buffer_pool global_buffer_pool;

/* Global memory statistics */
static struct snakedrv_memory_stats global_memory_stats = {
	.allocated_bytes = ATOMIC64_INIT(0),
	.peak_bytes = ATOMIC64_INIT(0),
	.allocation_count = ATOMIC64_INIT(0),
	.free_count = ATOMIC64_INIT(0),
};

/* Global performance statistics */
struct snakedrv_perf_stats global_perf_stats;

/* ============================================================================
 * Result Set Cache
 * ============================================================================ */

/**
 * struct result_set_cache - Global cache for scan result sets
 * @lock: Protects the entire cache
 * @list: List of all cached result sets
 * @next_id: Next available ID (auto-increment)
 * @count: Number of cached result sets
 * @max_cached: Maximum number of result sets to cache
 */
struct result_set_cache {
	spinlock_t lock;
	struct list_head list;
	uint32_t next_id;
	uint32_t count;
	uint32_t max_cached;
};

static struct result_set_cache global_result_cache;

/**
 * snakedrv_scanner_init - Initialize scanner memory subsystem
 *
 * Initializes slab caches and buffer pools for optimized memory usage.
 * Call once during module initialization.
 *
 * Return: 0 on success, negative error code on failure
 */
int snakedrv_scanner_init(void)
{
	int ret;

	/* Initialize performance statistics */
	snakedrv_perf_init(&global_perf_stats);

	/* Initialize slab caches */
	ret = snakedrv_init_slab_caches();
	if (ret < 0) {
		pr_err("snakedrv: Failed to initialize slab caches\n");
		return ret;
	}

	/* Initialize buffer pool (16 buffers × 256KB each = 4MB pre-allocated) */
	ret = snakedrv_buffer_pool_init(&global_buffer_pool,
	                                256 * 1024,
	                                SNAKEDRV_SCAN_BUFFER_POOL_SIZE);
	if (ret < 0) {
		pr_warn("snakedrv: Failed to initialize buffer pool (non-fatal)\n");
		/* Non-fatal - scanner will allocate buffers on-demand */
	}

	/* Initialize result set cache */
	ret = scanner_cache_init();
	if (ret < 0) {
		pr_err("snakedrv: Failed to initialize result set cache\n");
		snakedrv_destroy_slab_caches();
		return ret;
	}

	pr_info("snakedrv: Scanner memory subsystem initialized\n");
	pr_info("snakedrv: Memory tracking enabled (limit: %u MB per session)\n",
	        SNAKEDRV_MAX_MEMORY_PER_SESSION / (1024 * 1024));
	pr_info("snakedrv: Performance benchmarking enabled\n");

	return 0;
}

/**
 * snakedrv_scanner_cleanup - Cleanup scanner memory subsystem
 *
 * Destroys slab caches and buffer pools.
 * Call once during module cleanup.
 */
void snakedrv_scanner_cleanup(void)
{
	char *perf_buf;

	/* Cleanup result set cache */
	scanner_cache_cleanup();

	/* Destroy buffer pool */
	snakedrv_buffer_pool_destroy(&global_buffer_pool);

	/* Destroy slab caches */
	snakedrv_destroy_slab_caches();

	/* Print memory statistics */
	pr_info("snakedrv: Scanner memory statistics:\n");
	pr_info("snakedrv:   Allocations: %lld\n",
	        atomic64_read(&global_memory_stats.allocation_count));
	pr_info("snakedrv:   Frees:       %lld\n",
	        atomic64_read(&global_memory_stats.free_count));
	pr_info("snakedrv:   Peak usage:  %lld KB\n",
	        atomic64_read(&global_memory_stats.peak_bytes) / 1024);
	pr_info("snakedrv:   Final usage: %lld KB\n",
	        atomic64_read(&global_memory_stats.allocated_bytes) / 1024);

	/* Print performance statistics */
	pr_info("snakedrv: Performance statistics:\n");
	perf_buf = kmalloc(2048, GFP_KERNEL);
	if (perf_buf) {
		snakedrv_perf_report_all(perf_buf, 2048, &global_perf_stats);
		pr_info("%s", perf_buf);
		kfree(perf_buf);
	}

	pr_info("snakedrv: Scanner memory subsystem cleaned up\n");
}

/* ============================================================================
 * Result Set Cache Management
 * ============================================================================ */

/**
 * scanner_cache_init - Initialize result set cache
 *
 * Return: 0 on success
 */
int scanner_cache_init(void)
{
	spin_lock_init(&global_result_cache.lock);
	INIT_LIST_HEAD(&global_result_cache.list);
	global_result_cache.next_id = 1;  /* Start from 1, 0 = invalid */
	global_result_cache.count = 0;
	global_result_cache.max_cached = 64;  /* Max 64 cached result sets */

	pr_info("snakedrv: Result set cache initialized (max %u sets)\n",
	        global_result_cache.max_cached);
	return 0;
}

/**
 * scanner_cache_cleanup - Cleanup result set cache
 *
 * Frees all cached result sets.
 */
void scanner_cache_cleanup(void)
{
	struct scan_result_set *set, *tmp;
	unsigned long flags;
	uint32_t freed = 0;

	spin_lock_irqsave(&global_result_cache.lock, flags);

	list_for_each_entry_safe(set, tmp, &global_result_cache.list, list) {
		list_del(&set->list);
		spin_unlock_irqrestore(&global_result_cache.lock, flags);

		scanner_free_result_set(set);
		freed++;

		spin_lock_irqsave(&global_result_cache.lock, flags);
	}

	global_result_cache.count = 0;
	spin_unlock_irqrestore(&global_result_cache.lock, flags);

	pr_info("snakedrv: Result set cache cleaned up (%u sets freed)\n", freed);
}

/**
 * scanner_cache_add - Add a result set to cache and assign ID
 * @set: Result set to cache
 *
 * Return: Unique ID for the result set, or 0 on error
 */
uint32_t scanner_cache_add(struct scan_result_set *set)
{
	unsigned long flags;
	uint32_t id;

	if (!set)
		return 0;

	spin_lock_irqsave(&global_result_cache.lock, flags);

	/* Check cache limit */
	if (global_result_cache.count >= global_result_cache.max_cached) {
		spin_unlock_irqrestore(&global_result_cache.lock, flags);
		pr_warn("snakedrv: Result set cache full (%u sets)\n",
		        global_result_cache.max_cached);
		return 0;
	}

	/* Assign unique ID */
	id = global_result_cache.next_id++;
	if (global_result_cache.next_id == 0)  /* Wraparound protection */
		global_result_cache.next_id = 1;

	set->id = id;
	atomic_set(&set->ref_count, 1);  /* Initial reference */

	/* Add to cache */
	list_add_tail(&set->list, &global_result_cache.list);
	global_result_cache.count++;

	spin_unlock_irqrestore(&global_result_cache.lock, flags);

	pr_debug("snakedrv: Cached result set ID %u (%u results, %u total cached)\n",
	         id, set->count, global_result_cache.count);

	return id;
}

/**
 * scanner_cache_get - Get a result set from cache by ID
 * @id: Result set ID
 *
 * Increments reference count. Must call scanner_cache_put() when done.
 *
 * Return: Pointer to result set, or NULL if not found
 */
struct scan_result_set *scanner_cache_get(uint32_t id)
{
	struct scan_result_set *set = NULL;
	struct scan_result_set *iter;
	unsigned long flags;

	if (id == 0)
		return NULL;

	spin_lock_irqsave(&global_result_cache.lock, flags);

	list_for_each_entry(iter, &global_result_cache.list, list) {
		if (iter->id == id) {
			set = iter;
			atomic_inc(&set->ref_count);
			break;
		}
	}

	spin_unlock_irqrestore(&global_result_cache.lock, flags);

	if (set)
		pr_debug("snakedrv: Retrieved cached result set ID %u (refcount=%d)\n",
		         id, atomic_read(&set->ref_count));
	else
		pr_warn("snakedrv: Result set ID %u not found in cache\n", id);

	return set;
}

/**
 * scanner_cache_put - Release reference to cached result set
 * @set: Result set to release
 *
 * Decrements reference count. If reaches 0, the set remains cached but
 * can be evicted later.
 */
void scanner_cache_put(struct scan_result_set *set)
{
	if (!set || set->id == 0)
		return;

	if (atomic_dec_and_test(&set->ref_count)) {
		pr_debug("snakedrv: Result set ID %u reference count reached 0\n",
		         set->id);
	}
}

/**
 * scanner_cache_remove - Remove a result set from cache
 * @id: Result set ID to remove
 *
 * Removes from cache and frees the result set.
 */
void scanner_cache_remove(uint32_t id)
{
	struct scan_result_set *set = NULL;
	struct scan_result_set *iter;
	unsigned long flags;

	if (id == 0)
		return;

	spin_lock_irqsave(&global_result_cache.lock, flags);

	list_for_each_entry(iter, &global_result_cache.list, list) {
		if (iter->id == id) {
			set = iter;
			list_del(&set->list);
			global_result_cache.count--;
			break;
		}
	}

	spin_unlock_irqrestore(&global_result_cache.lock, flags);

	if (set) {
		pr_debug("snakedrv: Removed result set ID %u from cache\n", id);
		scanner_free_result_set(set);
	} else {
		pr_warn("snakedrv: Attempted to remove non-existent result set ID %u\n",
		        id);
	}
}

/* ============================================================================
 * Parallel Scanning Infrastructure
 * ============================================================================ */

/**
 * struct parallel_scan_work - Work unit for parallel scanning
 * @work: Kernel work structure
 * @backend: Memory backend to scan
 * @params: Scan parameters (cloned for this worker)
 * @results: Shared result set (thread-safe)
 * @start_addr: Start address for this worker's chunk
 * @end_addr: End address for this worker's chunk
 * @matches: Number of matches found by this worker
 * @completion: Completion signal when work is done
 * @worker_id: ID of this worker (for debugging)
 */
struct parallel_scan_work {
	struct work_struct work;
	struct memory_backend *backend;
	struct scan_params params;
	struct scan_result_set *results;
	uint64_t start_addr;
	uint64_t end_addr;
	ssize_t matches;
	struct completion *completion;
	int worker_id;
};

/* ============================================================================
 * Scan Result Management
 * ============================================================================ */

/**
 * scanner_create_result_set - Create a new scan result set
 * @max_results: Maximum number of results to store
 *
 * Allocates and initializes a scan result set structure.
 * Optionally creates a Bloom filter for large result sets (rescans).
 *
 * Return: Pointer to result set, or NULL on failure
 */
struct scan_result_set *scanner_create_result_set(uint32_t max_results)
{
	struct scan_result_set *set;
	bool use_bloom = false;

	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return NULL;

	set->results = kvmalloc_array(max_results, sizeof(struct scan_result),
	                              GFP_KERNEL | __GFP_ZERO);
	if (!set->results) {
		kfree(set);
		return NULL;
	}

	set->max_results = max_results;
	set->count = 0;
	spin_lock_init(&set->lock);

	/* Initialize cache fields */
	set->id = 0;  /* Not cached yet */
	atomic_set(&set->ref_count, 0);
	INIT_LIST_HEAD(&set->list);

	/* Enable Bloom filter for large result sets (>10K results) */
	/* This saves ~90% memory for rescans */
	if (max_results > 10000) {
		set->bloom = bloom_create(max_results, 0.01);  /* 1% FPR */
		if (set->bloom) {
			set->use_bloom = true;
			use_bloom = true;
		}
	} else {
		set->bloom = NULL;
		set->use_bloom = false;
	}

	pr_info("snakedrv: Created scan result set (max %u results, bloom=%s)\n",
	        max_results, use_bloom ? "enabled" : "disabled");
	return set;
}

/**
 * scanner_free_result_set - Free a scan result set
 * @set: Result set to free
 */
void scanner_free_result_set(struct scan_result_set *set)
{
	if (!set)
		return;

	if (set->results)
		kvfree(set->results);

	/* Free Bloom filter if present */
	if (set->bloom)
		bloom_destroy(set->bloom);

	kfree(set);
	pr_debug("snakedrv: Freed scan result set\n");
}

/**
 * scanner_add_result - Add a result to the set
 * @set: Result set
 * @address: Address where value was found
 * @value: Value found at address
 *
 * Also adds address to Bloom filter if enabled (for fast rescan lookups).
 *
 * Return: 0 on success, -ENOMEM if result set is full
 */
static int scanner_add_result(struct scan_result_set *set, uint64_t address,
                              uint64_t value)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&set->lock, flags);

	if (set->count >= set->max_results) {
		ret = -ENOMEM;
		goto out;
	}

	set->results[set->count].address = address;
	set->results[set->count].value = value;
	set->count++;

	/* Add address to Bloom filter for fast rescan lookups */
	if (set->use_bloom && set->bloom) {
		bloom_add(set->bloom, address);
	}

out:
	spin_unlock_irqrestore(&set->lock, flags);
	return ret;
}

/**
 * scanner_address_in_set - Check if address is in result set (fast)
 * @set: Result set to check
 * @address: Address to test
 *
 * Uses Bloom filter for O(1) fast lookup if available.
 * Otherwise falls back to linear search.
 *
 * Note: May return false positives (~1%) if Bloom filter is used.
 * Use for optimization, not for exact membership testing.
 *
 * Available for future optimizations (filtered scans, hybrid rescans, etc.)
 *
 * Return: true if address MIGHT be in set, false if DEFINITELY NOT
 */
static bool __maybe_unused scanner_address_in_set(struct scan_result_set *set, uint64_t address)
{
	uint32_t i;

	if (!set)
		return false;

	/* Fast path: Bloom filter lookup (O(1)) */
	if (set->use_bloom && set->bloom) {
		return bloom_test(set->bloom, address);
	}

	/* Slow path: Linear search (O(n)) */
	for (i = 0; i < set->count; i++) {
		if (set->results[i].address == address)
			return true;
	}

	return false;
}

/**
 * parallel_scan_worker - Worker function for parallel exact value scanning
 * @work: Work structure (contains parallel_scan_work)
 *
 * This worker scans a specific address range chunk and adds results
 * to the shared result set. Runs on a separate CPU core.
 */
static void parallel_scan_worker(struct work_struct *work)
{
	struct parallel_scan_work *psw = container_of(work, struct parallel_scan_work, work);
	uint64_t addr = psw->start_addr;
	uint64_t end_addr = psw->end_addr;
	uint8_t *scan_buf;
	size_t buf_size;
	ssize_t bytes_read;
	ssize_t matches = 0;

	/* Allocate worker-local scan buffer */
	buf_size = select_optimal_chunk_size(end_addr - addr);
	scan_buf = kvmalloc(buf_size + SNAKEDRV_CACHE_LINE_SIZE, GFP_KERNEL);
	if (!scan_buf) {
		pr_err("snakedrv: Worker %d failed to allocate buffer\n", psw->worker_id);
		psw->matches = -ENOMEM;
		complete(psw->completion);
		return;
	}

	scan_buf = (uint8_t *)cache_align_up((unsigned long)scan_buf);

	pr_debug("snakedrv: Worker %d scanning 0x%llx to 0x%llx\n",
	         psw->worker_id, addr, end_addr);

	/* Scan assigned chunk */
	while (addr < end_addr) {
		size_t chunk_size = min_t(size_t, buf_size, end_addr - addr);
		size_t i;

		/* Read chunk from memory */
		bytes_read = backend_read(psw->backend, addr, scan_buf, chunk_size);
		if (bytes_read <= 0) {
			addr += PAGE_SIZE;
			continue;
		}

		/* Prefetch and scan */
		prefetch_scan_data(scan_buf);

		for (i = 0; i < bytes_read; i += (psw->params.aligned ? psw->params.value_size : 1)) {
			uint64_t current_value = 0;
			bool match = false;

			/* Prefetch next cache line */
			if ((i & (SNAKEDRV_CACHE_LINE_SIZE - 1)) == 0) {
				prefetch_scan_data(scan_buf + i + SNAKEDRV_PREFETCH_DISTANCE);
			}

			/* Extract value based on size */
			switch (psw->params.value_size) {
			case 1:
				current_value = scan_buf[i];
				break;
			case 2:
				if (i + 2 <= bytes_read)
					current_value = *(uint16_t *)(scan_buf + i);
				break;
			case 4:
				if (i + 4 <= bytes_read)
					current_value = *(uint32_t *)(scan_buf + i);
				break;
			case 8:
				if (i + 8 <= bytes_read)
					current_value = *(uint64_t *)(scan_buf + i);
				break;
			}

			/* Check for match */
			match = (current_value == psw->params.search_value);

			if (match) {
				/* Add to shared result set (thread-safe) */
				if (scanner_add_result(psw->results, addr + i, current_value) < 0) {
					/* Result set full, stop scanning */
					goto worker_done;
				}
				matches++;
			}
		}

		addr += bytes_read;
	}

worker_done:
	kvfree(scan_buf);
	psw->matches = matches;

	pr_debug("snakedrv: Worker %d completed: %zd matches\n", psw->worker_id, matches);

	/* Signal completion */
	complete(psw->completion);
}

/* ============================================================================
 * Huge Page Detection and Optimization
 * ============================================================================ */

/**
 * scanner_exact_value_parallel - Parallel multi-threaded exact value scan
 * @backend: Memory backend
 * @params: Scan parameters
 * @results: Result set to store matches
 *
 * Distributes scan workload across multiple CPU cores using workqueues.
 * Each worker scans a contiguous chunk of the address range.
 *
 * Performance: ~4-16x speedup on multi-core systems (8-16 cores)
 *
 * Return: Total number of matches found, or negative error code
 */
static ssize_t scanner_exact_value_parallel(struct memory_backend *backend,
                                            struct scan_params *params,
                                            struct scan_result_set *results)
{
	struct parallel_scan_work *workers;
	struct completion *completions;
	uint32_t num_workers;
	uint64_t total_size, chunk_size, addr;
	ssize_t total_matches = 0;
	int i, ret;

	/* Determine optimal number of workers */
	if (params->num_threads > 0) {
		num_workers = min_t(uint32_t, params->num_threads, num_online_cpus());
	} else {
		/* Auto-detect: use all online CPUs */
		num_workers = num_online_cpus();
	}

	/* For very small scans, don't bother with parallelism */
	total_size = params->end_address - params->start_address;
	if (total_size < (256 * 1024 * num_workers)) {
		pr_debug("snakedrv: Scan too small for parallelism, using sequential\n");
		return -EAGAIN;  /* Caller should fall back to sequential */
	}

	/* Limit to reasonable number of workers */
	num_workers = min_t(uint32_t, num_workers, 32);

	pr_info("snakedrv: Parallel scan with %u workers (CPUs: %u online)\n",
	        num_workers, num_online_cpus());

	/* Allocate worker structures */
	workers = kzalloc(sizeof(*workers) * num_workers, GFP_KERNEL);
	if (!workers)
		return -ENOMEM;

	completions = kzalloc(sizeof(*completions) * num_workers, GFP_KERNEL);
	if (!completions) {
		kfree(workers);
		return -ENOMEM;
	}

	/* Initialize workers and divide address range */
	chunk_size = total_size / num_workers;
	addr = params->start_address;

	for (i = 0; i < num_workers; i++) {
		uint64_t worker_start = addr;
		uint64_t worker_end = (i == num_workers - 1) ? params->end_address : addr + chunk_size;

		/* Initialize completion */
		init_completion(&completions[i]);

		/* Setup worker */
		workers[i].backend = backend;
		workers[i].params = *params;  /* Clone params */
		workers[i].results = results;
		workers[i].start_addr = worker_start;
		workers[i].end_addr = worker_end;
		workers[i].matches = 0;
		workers[i].completion = &completions[i];
		workers[i].worker_id = i;

		/* Initialize and queue work */
		INIT_WORK(&workers[i].work, parallel_scan_worker);
		schedule_work(&workers[i].work);

		pr_debug("snakedrv: Worker %d: 0x%llx -> 0x%llx (%llu MB)\n",
		         i, worker_start, worker_end,
		         (worker_end - worker_start) / (1024 * 1024));

		addr += chunk_size;
	}

	/* Wait for all workers to complete */
	pr_debug("snakedrv: Waiting for %u workers to complete...\n", num_workers);
	for (i = 0; i < num_workers; i++) {
		ret = wait_for_completion_interruptible(&completions[i]);
		if (ret < 0) {
			pr_warn("snakedrv: Worker %d interrupted\n", i);
			/* Still wait for remaining workers to avoid leaks */
		}

		if (workers[i].matches > 0) {
			total_matches += workers[i].matches;
		}

		pr_debug("snakedrv: Worker %d: %zd matches\n", i, workers[i].matches);
	}

	pr_info("snakedrv: Parallel scan complete: %zd total matches from %u workers\n",
	        total_matches, num_workers);

	/* Cleanup */
	kfree(completions);
	kfree(workers);

	return total_matches;
}

/* ============================================================================
 * Exact Value Scanning
 * ============================================================================ */

/**
 * scanner_exact_value - Scan for exact value in memory range
 * @backend: Memory backend
 * @params: Scan parameters
 * @results: Result set to store matches
 *
 * Scans a memory range for exact value matches.
 * Supports 1, 2, 4, and 8-byte values with optional alignment.
 *
 * OPTIMIZED: Adaptive chunk sizing, prefetching, cache-aligned buffers,
 *            huge page awareness (2MB/1GB pages)
 *
 * Return: Number of matches found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_exact_value(struct memory_backend *backend,
                            struct scan_params *params,
                            struct scan_result_set *results)
{
	uint64_t addr;
	uint64_t end_addr;
	uint8_t *scan_buf;
	size_t buf_size, max_buf_size;
	uint64_t total_size;
	ssize_t bytes_read;
	ssize_t matches = 0;
	struct scan_timer perf_timer;

	/* Start performance measurement */
	snakedrv_timer_start(&perf_timer, &global_perf_stats.exact_value);

	if (unlikely(!backend || !params || !results))
		return -EINVAL;

	/* Validate scan type and size */
	if (unlikely(params->value_size != 1 && params->value_size != 2 &&
	             params->value_size != 4 && params->value_size != 8)) {
		pr_err("snakedrv: Invalid scan value size %u\n", params->value_size);
		return -EINVAL;
	}

	/* Try parallel scan if requested */
	if (params->parallel) {
		ssize_t parallel_result = scanner_exact_value_parallel(backend, params, results);
		if (parallel_result != -EAGAIN) {
			/* Parallel scan succeeded or failed with real error */
			return parallel_result;
		}
		/* parallel_result == -EAGAIN: fall through to sequential scan */
		pr_debug("snakedrv: Falling back to sequential scan\n");
	}

	/* Adaptive chunk sizing based on total scan size */
	total_size = params->end_address - params->start_address;
	buf_size = select_optimal_chunk_size(total_size);
	max_buf_size = buf_size;

	/* Try to get buffer from pool (fast path) */
	scan_buf = snakedrv_buffer_pool_acquire(&global_buffer_pool,
	                                        max_buf_size + SNAKEDRV_CACHE_LINE_SIZE);
	if (unlikely(!scan_buf))
		return -ENOMEM;

	/* Track memory allocation */
	snakedrv_track_alloc(&global_memory_stats, max_buf_size);

	/* Align buffer to cache line boundary */
	scan_buf = (uint8_t *)cache_align_up((unsigned long)scan_buf);

	pr_info("snakedrv: Starting exact value scan: 0x%llx to 0x%llx (value=0x%llx, size=%u)\n",
	        params->start_address, params->end_address, params->search_value,
	        params->value_size);

	addr = params->start_address;
	end_addr = params->end_address;

	/* Align start address if requested */
	if (params->aligned && params->value_size > 1) {
		addr = ALIGN(addr, params->value_size);
	}

	/* Scan memory in chunks */
	while (addr < end_addr) {
		size_t chunk_size;

		chunk_size = min_t(size_t, buf_size, end_addr - addr);

		/* Read chunk from memory */
		bytes_read = backend_read(backend, addr, scan_buf, chunk_size);
		if (unlikely(bytes_read <= 0)) {
			/* Skip inaccessible memory */
			addr += PAGE_SIZE;
			continue;
		}

		/* Prefetch first cache line of chunk */
		prefetch_scan_data(scan_buf);

		/* Scan chunk for value with prefetching */
		{
			size_t i;
			for (i = 0; i < bytes_read; i += (params->aligned ? params->value_size : 1)) {
				uint64_t current_value = 0;
				bool match = false;

			/* Prefetch next cache line ahead of time */
			if (unlikely((i & (SNAKEDRV_CACHE_LINE_SIZE - 1)) == 0)) {
				prefetch_scan_data(scan_buf + i + SNAKEDRV_PREFETCH_DISTANCE);
			}

			/* Extract value based on size */
			switch (params->value_size) {
			case 1:
				current_value = scan_buf[i];
				break;
			case 2:
				if (likely(i + 2 <= bytes_read))
					current_value = *(uint16_t *)(scan_buf + i);
				break;
			case 4:
				if (likely(i + 4 <= bytes_read))
					current_value = *(uint32_t *)(scan_buf + i);
				break;
			case 8:
				if (likely(i + 8 <= bytes_read))
					current_value = *(uint64_t *)(scan_buf + i);
				break;
			}

			/* Check for match */
			match = (current_value == params->search_value);

			if (unlikely(match)) {
				if (unlikely(scanner_add_result(results, addr + i, current_value) < 0)) {
					pr_warn("snakedrv: Scan result set full (%u matches)\n",
					        results->max_results);
					goto out;
				}
				matches++;
			}
		}
		}  /* End of scan chunk block */

		addr += bytes_read;
	}

out:
	/* Return buffer to pool for reuse */
	snakedrv_buffer_pool_release(&global_buffer_pool, scan_buf);

	/* Track memory free */
	snakedrv_track_free(&global_memory_stats, max_buf_size);

	/* Stop performance measurement and update stats */
	perf_timer.bytes_scanned = total_size;
	perf_timer.matches_found = matches;
	perf_timer.is_parallel = params->parallel;
	perf_timer.is_huge_page = false;
	snakedrv_timer_stop(&perf_timer);

	pr_info("snakedrv: Exact value scan complete: %zd matches found\n", matches);
	return matches;
}

/* ============================================================================
 * Pattern/AOB (Array of Bytes) Scanning
 * ============================================================================ */

/**
 * scanner_pattern - Scan for byte pattern in memory
 * @backend: Memory backend
 * @params: Scan parameters
 * @pattern: Pattern to search for
 * @mask: Mask for wildcard bytes (0xFF = must match, 0x00 = wildcard)
 * @pattern_len: Length of pattern in bytes
 * @results: Result set to store matches
 *
 * Scans memory for a byte pattern with optional wildcards.
 * Example: "\x48\x8B\x??\x??\x48\x89" with mask "\xFF\xFF\x00\x00\xFF\xFF"
 *
 * OPTIMIZED: Adaptive chunk sizing, prefetching, cache-aligned buffers
 *
 * Return: Number of matches found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_pattern(struct memory_backend *backend,
                       struct scan_params *params,
                       const uint8_t *pattern,
                       const uint8_t *mask,
                       size_t pattern_len,
                       struct scan_result_set *results)
{
	uint64_t addr;
	uint64_t end_addr;
	uint8_t *scan_buf;
	size_t buf_size;
	uint64_t total_size;
	ssize_t bytes_read;
	ssize_t matches = 0;

	if (unlikely(!backend || !params || !pattern || !results))
		return -EINVAL;

	if (unlikely(pattern_len == 0 || pattern_len > 256)) {
		pr_err("snakedrv: Invalid pattern length %zu\n", pattern_len);
		return -EINVAL;
	}

	/* Adaptive chunk sizing */
	total_size = params->end_address - params->start_address;
	buf_size = select_optimal_chunk_size(total_size);

	/* Allocate cache-aligned scan buffer */
	scan_buf = kvmalloc(buf_size + SNAKEDRV_CACHE_LINE_SIZE, GFP_KERNEL);
	if (unlikely(!scan_buf))
		return -ENOMEM;

	scan_buf = (uint8_t *)cache_align_up((unsigned long)scan_buf);

	pr_info("snakedrv: Starting pattern scan: 0x%llx to 0x%llx (pattern_len=%zu)\n",
	        params->start_address, params->end_address, pattern_len);

	addr = params->start_address;
	end_addr = params->end_address;

	/* Scan memory in chunks */
	while (addr < end_addr) {
		size_t chunk_size = min_t(size_t, buf_size, end_addr - addr);
		size_t i;

		/* Read chunk from memory */
		bytes_read = backend_read(backend, addr, scan_buf, chunk_size);
		if (unlikely(bytes_read <= 0)) {
			/* Skip inaccessible memory */
			addr += PAGE_SIZE;
			continue;
		}

		/* Prefetch first cache line */
		prefetch_scan_data(scan_buf);

		/* Scan chunk for pattern with prefetching */
		for (i = 0; i <= bytes_read - pattern_len; i++) {
			size_t j;
			bool match = true;

			/* Prefetch next cache line */
			if (unlikely((i & (SNAKEDRV_CACHE_LINE_SIZE - 1)) == 0)) {
				prefetch_scan_data(scan_buf + i + SNAKEDRV_PREFETCH_DISTANCE);
			}

			/* Check pattern with mask */
			for (j = 0; j < pattern_len; j++) {
				uint8_t byte_mask = mask ? mask[j] : 0xFF;
				if (unlikely((scan_buf[i + j] & byte_mask) != (pattern[j] & byte_mask))) {
					match = false;
					break;
				}
			}

			if (unlikely(match)) {
				if (unlikely(scanner_add_result(results, addr + i, 0) < 0)) {
					pr_warn("snakedrv: Scan result set full\n");
					goto out;
				}
				matches++;
			}
		}

		addr += bytes_read;
	}

out:
	kvfree(scan_buf);
	pr_info("snakedrv: Pattern scan complete: %zd matches found\n", matches);
	return matches;
}

/* ============================================================================
 * Changed/Unchanged Value Scanning
 * ============================================================================ */

/**
 * scanner_changed_values - Rescan for changed values
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for changed values
 * @value_size: Size of values to compare
 *
 * Rescans addresses from previous scan and keeps only those where
 * the value has changed.
 *
 * OPTIMIZED: Prefetching result arrays for better cache performance
 *
 * Return: Number of changed values found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_changed_values(struct memory_backend *backend,
                               struct scan_result_set *prev_results,
                               struct scan_result_set *new_results,
                               uint32_t value_size)
{
	uint32_t i;
	ssize_t changes = 0;
	ssize_t bytes_read;
	uint64_t current_value;
	uint32_t read_failures = 0;
	uint32_t debug_sample = 0;

	if (unlikely(!backend || !prev_results || !new_results))
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for changed values (value_size=%u)\n",
	        prev_results->count, value_size);

	/* Prefetch first result entry */
	if (likely(prev_results->count > 0))
		prefetch_scan_data(&prev_results->results[0]);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;
		uint64_t old_value = prev_results->results[i].value;

		/* Prefetch next result entry (8 entries ahead) */
		if (likely(i + 8 < prev_results->count))
			prefetch_scan_data(&prev_results->results[i + 8]);

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (unlikely(bytes_read != value_size)) {
			read_failures++;
			/* Debug: Log first few read failures */
			if (read_failures <= 3) {
				pr_info("snakedrv: Read failed at 0x%llx (bytes_read=%zd, expected=%u)\n",
				        addr, bytes_read, value_size);
			}
			continue;  /* Skip inaccessible */
		}

		/* Debug: Log first few comparisons */
		if (debug_sample < 5) {
			pr_info("snakedrv: [%u] addr=0x%llx old=0x%llx cur=0x%llx %s\n",
			        i, addr, old_value, current_value,
			        (current_value != old_value) ? "CHANGED" : "same");
			debug_sample++;
		}

		/* Check if value changed */
		if (unlikely(current_value != old_value)) {
			if (unlikely(scanner_add_result(new_results, addr, current_value) < 0))
				break;  /* Result set full */
			changes++;
		}
	}

	pr_info("snakedrv: Changed value scan complete: %zd changes found, %u read failures\n",
	        changes, read_failures);
	return changes;
}

/**
 * scanner_unchanged_values - Rescan for unchanged values
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for unchanged values
 * @value_size: Size of values to compare
 *
 * Rescans addresses from previous scan and keeps only those where
 * the value has NOT changed.
 *
 * OPTIMIZED: Prefetching result arrays for better cache performance
 *
 * Return: Number of unchanged values found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_unchanged_values(struct memory_backend *backend,
                                 struct scan_result_set *prev_results,
                                 struct scan_result_set *new_results,
                                 uint32_t value_size)
{
	uint32_t i;
	ssize_t unchanged = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (unlikely(!backend || !prev_results || !new_results))
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for unchanged values\n",
	        prev_results->count);

	/* Prefetch first result entry */
	if (likely(prev_results->count > 0))
		prefetch_scan_data(&prev_results->results[0]);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;
		uint64_t old_value = prev_results->results[i].value;

		/* Prefetch next result entry */
		if (likely(i + 8 < prev_results->count))
			prefetch_scan_data(&prev_results->results[i + 8]);

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (unlikely(bytes_read != value_size))
			continue;  /* Skip inaccessible */

		/* Check if value unchanged */
		if (likely(current_value == old_value)) {
			if (unlikely(scanner_add_result(new_results, addr, current_value) < 0))
				break;  /* Result set full */
			unchanged++;
		}
	}

	pr_info("snakedrv: Unchanged value scan complete: %zd unchanged found\n", unchanged);
	return unchanged;
}

/* ============================================================================
 * Increased/Decreased Value Scanning
 * ============================================================================ */

/**
 * scanner_increased_values - Rescan for increased values
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for increased values
 * @value_size: Size of values to compare
 *
 * OPTIMIZED: Prefetching result arrays for better cache performance
 *
 * Return: Number of increased values found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_increased_values(struct memory_backend *backend,
                                 struct scan_result_set *prev_results,
                                 struct scan_result_set *new_results,
                                 uint32_t value_size)
{
	uint32_t i;
	ssize_t increased = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (unlikely(!backend || !prev_results || !new_results))
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for increased values\n",
	        prev_results->count);

	/* Prefetch first result entry */
	if (likely(prev_results->count > 0))
		prefetch_scan_data(&prev_results->results[0]);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;
		uint64_t old_value = prev_results->results[i].value;

		/* Prefetch next result entry */
		if (likely(i + 8 < prev_results->count))
			prefetch_scan_data(&prev_results->results[i + 8]);

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (unlikely(bytes_read != value_size))
			continue;

		/* Check if value increased */
		if (unlikely(current_value > old_value)) {
			if (unlikely(scanner_add_result(new_results, addr, current_value) < 0))
				break;
			increased++;
		}
	}

	pr_info("snakedrv: Increased value scan complete: %zd increased found\n", increased);
	return increased;
}

/**
 * scanner_decreased_values - Rescan for decreased values
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for decreased values
 * @value_size: Size of values to compare
 *
 * Return: Number of decreased values found, or negative error code
 */
ssize_t scanner_decreased_values(struct memory_backend *backend,
                                 struct scan_result_set *prev_results,
                                 struct scan_result_set *new_results,
                                 uint32_t value_size)
{
	uint32_t i;
	ssize_t decreased = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (!backend || !prev_results || !new_results)
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for decreased values\n",
	        prev_results->count);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;
		uint64_t old_value = prev_results->results[i].value;

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (bytes_read != value_size)
			continue;

		/* Check if value decreased */
		if (current_value < old_value) {
			if (scanner_add_result(new_results, addr, current_value) < 0)
				break;
			decreased++;
		}
	}

	pr_info("snakedrv: Decreased value scan complete: %zd decreased found\n", decreased);
	return decreased;
}

/**
 * scanner_exact_value_rescan - Rescan for exact value match
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for matches
 * @search_value: Value to search for
 * @value_size: Size of value in bytes
 *
 * Rescans addresses from previous scan and keeps only those where
 * the current value matches the search value exactly.
 *
 * Return: Number of matches found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_exact_value_rescan(struct memory_backend *backend,
                                   struct scan_result_set *prev_results,
                                   struct scan_result_set *new_results,
                                   uint64_t search_value,
                                   uint32_t value_size)
{
	uint32_t i;
	ssize_t matches = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (!backend || !prev_results || !new_results)
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for exact value 0x%llx\n",
	        prev_results->count, search_value);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (bytes_read != value_size)
			continue;

		/* Check if value matches exactly */
		if (current_value == search_value) {
			if (scanner_add_result(new_results, addr, current_value) < 0)
				break;
			matches++;
		}
	}

	pr_info("snakedrv: Exact value rescan complete: %zd matches found\n", matches);
	return matches;
}

/**
 * scanner_value_between - Rescan for value in range
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for matches
 * @min_value: Minimum value (inclusive)
 * @max_value: Maximum value (inclusive)
 * @value_size: Size of value in bytes
 *
 * Rescans addresses from previous scan and keeps only those where
 * the current value is between min and max (inclusive).
 *
 * Return: Number of matches found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_value_between(struct memory_backend *backend,
                              struct scan_result_set *prev_results,
                              struct scan_result_set *new_results,
                              uint64_t min_value,
                              uint64_t max_value,
                              uint32_t value_size)
{
	uint32_t i;
	ssize_t matches = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (!backend || !prev_results || !new_results)
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for value between 0x%llx and 0x%llx\n",
	        prev_results->count, min_value, max_value);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (bytes_read != value_size)
			continue;

		/* Check if value is in range */
		if (current_value >= min_value && current_value <= max_value) {
			if (scanner_add_result(new_results, addr, current_value) < 0)
				break;
			matches++;
		}
	}

	pr_info("snakedrv: Value between scan complete: %zd matches found\n", matches);
	return matches;
}

/**
 * scanner_increased_by - Rescan for values increased by exact amount
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for matches
 * @delta: Amount the value should have increased by
 * @value_size: Size of value in bytes
 *
 * Rescans addresses from previous scan and keeps only those where
 * current_value = old_value + delta (exactly).
 *
 * Return: Number of matches found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_increased_by(struct memory_backend *backend,
                            struct scan_result_set *prev_results,
                            struct scan_result_set *new_results,
                            uint64_t delta,
                            uint32_t value_size)
{
	uint32_t i;
	ssize_t matches = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (!backend || !prev_results || !new_results)
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for values increased by 0x%llx\n",
	        prev_results->count, delta);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;
		uint64_t old_value = prev_results->results[i].value;

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (bytes_read != value_size)
			continue;

		/* Check if value increased by exactly delta */
		if (current_value == old_value + delta) {
			if (scanner_add_result(new_results, addr, current_value) < 0)
				break;
			matches++;
		}
	}

	pr_info("snakedrv: Increased by scan complete: %zd matches found\n", matches);
	return matches;
}

/**
 * scanner_decreased_by - Rescan for values decreased by exact amount
 * @backend: Memory backend
 * @prev_results: Previous scan results
 * @new_results: New result set for matches
 * @delta: Amount the value should have decreased by
 * @value_size: Size of value in bytes
 *
 * Rescans addresses from previous scan and keeps only those where
 * current_value = old_value - delta (exactly).
 *
 * Return: Number of matches found, or negative error code
 */
SNAKEDRV_HOT
ssize_t scanner_decreased_by(struct memory_backend *backend,
                            struct scan_result_set *prev_results,
                            struct scan_result_set *new_results,
                            uint64_t delta,
                            uint32_t value_size)
{
	uint32_t i;
	ssize_t matches = 0;
	ssize_t bytes_read;
	uint64_t current_value;

	if (!backend || !prev_results || !new_results)
		return -EINVAL;

	pr_info("snakedrv: Rescanning %u addresses for values decreased by 0x%llx\n",
	        prev_results->count, delta);

	for (i = 0; i < prev_results->count; i++) {
		uint64_t addr = prev_results->results[i].address;
		uint64_t old_value = prev_results->results[i].value;

		/* Read current value */
		bytes_read = backend_read(backend, addr, &current_value, value_size);
		if (bytes_read != value_size)
			continue;

		/* Check if value decreased by exactly delta */
		if (current_value == old_value - delta) {
			if (scanner_add_result(new_results, addr, current_value) < 0)
				break;
			matches++;
		}
	}

	pr_info("snakedrv: Decreased by scan complete: %zd matches found\n", matches);
	return matches;
}

/* ============================================================================
 * Float/Double Scanning
 * ============================================================================ */

/**
 * scanner_float_value - Scan for float value in memory
 * @backend: Memory backend
 * @params: Scan parameters
 * @search_value: Float value to search for (passed as integer bits)
 * @results: Result set to store matches
 *
 * Scans memory for IEEE 754 single-precision float matches.
 * Compares bit patterns directly (no FPU operations in kernel).
 *
 * NOTE: search_value must be passed as union { float f; uint32_t u; }.u
 *
 * Return: Number of matches found, or negative error code
 */
ssize_t scanner_float_value(struct memory_backend *backend,
                            struct scan_params *params,
                            float search_value,
                            struct scan_result_set *results)
{
	uint64_t addr;
	uint64_t end_addr;
	uint8_t *scan_buf;
	size_t buf_size = PAGE_SIZE * 16;  /* 64KB chunks */
	ssize_t bytes_read;
	ssize_t matches = 0;
	uint32_t search_bits;

	if (!backend || !params || !results)
		return -EINVAL;

	/* Extract bit pattern from float (passed via union from userland) */
	search_bits = *(uint32_t *)&search_value;

	/* Allocate scan buffer */
	scan_buf = kvmalloc(buf_size, GFP_KERNEL);
	if (!scan_buf)
		return -ENOMEM;

	pr_info("snakedrv: Starting float scan: 0x%llx to 0x%llx (bits=0x%08x)\n",
	        params->start_address, params->end_address, search_bits);

	addr = params->start_address;
	end_addr = params->end_address;

	/* Align to 4-byte boundary for float */
	if (params->aligned)
		addr = ALIGN(addr, 4);

	/* Scan memory in chunks */
	while (addr < end_addr) {
		size_t chunk_size = min_t(size_t, buf_size, end_addr - addr);
		size_t i;

		/* Read chunk from memory */
		bytes_read = backend_read(backend, addr, scan_buf, chunk_size);
		if (bytes_read <= 0) {
			addr += PAGE_SIZE;
			continue;
		}

		/* Scan chunk for float value (exact bit match) */
		for (i = 0; i <= bytes_read - 4; i += (params->aligned ? 4 : 1)) {
			uint32_t current_bits;

			if (i + 4 > bytes_read)
				break;

			current_bits = *(uint32_t *)(scan_buf + i);

			/* Direct bit comparison (no FPU) */
			if (current_bits == search_bits) {
				if (scanner_add_result(results, addr + i, current_bits) < 0) {
					pr_warn("snakedrv: Scan result set full\n");
					goto out;
				}
				matches++;
			}
		}

		addr += bytes_read;
	}

out:
	kvfree(scan_buf);
	pr_info("snakedrv: Float scan complete: %zd matches found\n", matches);
	return matches;
}

/**
 * scanner_double_value - Scan for double value in memory
 * @backend: Memory backend
 * @params: Scan parameters
 * @search_value: Double value to search for (passed as integer bits)
 * @results: Result set to store matches
 *
 * Scans memory for IEEE 754 double-precision float matches.
 * Compares bit patterns directly (no FPU operations in kernel).
 *
 * NOTE: search_value must be passed as union { double d; uint64_t u; }.u
 *
 * Return: Number of matches found, or negative error code
 */
ssize_t scanner_double_value(struct memory_backend *backend,
                             struct scan_params *params,
                             double search_value,
                             struct scan_result_set *results)
{
	uint64_t addr;
	uint64_t end_addr;
	uint8_t *scan_buf;
	size_t buf_size = PAGE_SIZE * 16;  /* 64KB chunks */
	ssize_t bytes_read;
	ssize_t matches = 0;
	uint64_t search_bits;

	if (!backend || !params || !results)
		return -EINVAL;

	/* Extract bit pattern from double (passed via union from userland) */
	search_bits = *(uint64_t *)&search_value;

	/* Allocate scan buffer */
	scan_buf = kvmalloc(buf_size, GFP_KERNEL);
	if (!scan_buf)
		return -ENOMEM;

	pr_info("snakedrv: Starting double scan: 0x%llx to 0x%llx (bits=0x%016llx)\n",
	        params->start_address, params->end_address, search_bits);

	addr = params->start_address;
	end_addr = params->end_address;

	/* Align to 8-byte boundary for double */
	if (params->aligned)
		addr = ALIGN(addr, 8);

	/* Scan memory in chunks */
	while (addr < end_addr) {
		size_t chunk_size = min_t(size_t, buf_size, end_addr - addr);
		size_t i;

		/* Read chunk from memory */
		bytes_read = backend_read(backend, addr, scan_buf, chunk_size);
		if (bytes_read <= 0) {
			addr += PAGE_SIZE;
			continue;
		}

		/* Scan chunk for double value (exact bit match) */
		for (i = 0; i <= bytes_read - 8; i += (params->aligned ? 8 : 1)) {
			uint64_t current_bits;

			if (i + 8 > bytes_read)
				break;

			current_bits = *(uint64_t *)(scan_buf + i);

			/* Direct bit comparison (no FPU) */
			if (current_bits == search_bits) {
				if (scanner_add_result(results, addr + i, current_bits) < 0) {
					pr_warn("snakedrv: Scan result set full\n");
					goto out;
				}
				matches++;
			}
		}

		addr += bytes_read;
	}

out:
	kvfree(scan_buf);
	pr_info("snakedrv: Double scan complete: %zd matches found\n", matches);
	return matches;
}

/* ============================================================================
 * String Scanning
 * ============================================================================ */

/**
 * scanner_string_ascii - Scan for ASCII string in memory
 * @backend: Memory backend
 * @params: Scan parameters
 * @search_string: ASCII string to search for
 * @string_len: Length of string (without null terminator)
 * @case_sensitive: True for case-sensitive search
 * @results: Result set to store matches
 *
 * Scans memory for ASCII string matches.
 * Supports both case-sensitive and case-insensitive search.
 *
 * Return: Number of matches found, or negative error code
 */
ssize_t scanner_string_ascii(struct memory_backend *backend,
                             struct scan_params *params,
                             const char *search_string,
                             size_t string_len,
                             bool case_sensitive,
                             struct scan_result_set *results)
{
	uint64_t addr;
	uint64_t end_addr;
	uint8_t *scan_buf;
	size_t buf_size = PAGE_SIZE * 16;  /* 64KB chunks */
	ssize_t bytes_read;
	ssize_t matches = 0;

	if (!backend || !params || !search_string || !results)
		return -EINVAL;

	if (string_len == 0 || string_len > 1024)
		return -EINVAL;

	/* Allocate scan buffer */
	scan_buf = kvmalloc(buf_size, GFP_KERNEL);
	if (!scan_buf)
		return -ENOMEM;

	pr_info("snakedrv: Starting ASCII string scan: 0x%llx to 0x%llx (string=\"%s\", case_sensitive=%d)\n",
	        params->start_address, params->end_address, search_string, case_sensitive);

	addr = params->start_address;
	end_addr = params->end_address;

	/* Scan memory in chunks */
	while (addr < end_addr) {
		size_t chunk_size = min_t(size_t, buf_size, end_addr - addr);
		size_t i;

		/* Read chunk from memory */
		bytes_read = backend_read(backend, addr, scan_buf, chunk_size);
		if (bytes_read <= 0) {
			addr += PAGE_SIZE;
			continue;
		}

		/* Scan chunk for string */
		for (i = 0; i <= bytes_read - string_len; i++) {
			bool match = true;
			size_t j;

			/* Compare string */
			for (j = 0; j < string_len; j++) {
				char c1 = scan_buf[i + j];
				char c2 = search_string[j];

				if (case_sensitive) {
					if (c1 != c2) {
						match = false;
						break;
					}
				} else {
					/* Case-insensitive comparison */
					if (c1 >= 'A' && c1 <= 'Z')
						c1 += 'a' - 'A';
					if (c2 >= 'A' && c2 <= 'Z')
						c2 += 'a' - 'A';

					if (c1 != c2) {
						match = false;
						break;
					}
				}
			}

			if (match) {
				if (scanner_add_result(results, addr + i, 0) < 0) {
					pr_warn("snakedrv: Scan result set full\n");
					goto out;
				}
				matches++;
			}
		}

		addr += bytes_read;
	}

out:
	kvfree(scan_buf);
	pr_info("snakedrv: ASCII string scan complete: %zd matches found\n", matches);
	return matches;
}

/**
 * scanner_string_unicode - Scan for Unicode (UTF-16) string in memory
 * @backend: Memory backend
 * @params: Scan parameters
 * @search_string: Unicode string to search for (UTF-16LE)
 * @string_len: Length of string in characters (not bytes)
 * @case_sensitive: True for case-sensitive search
 * @results: Result set to store matches
 *
 * Scans memory for UTF-16 Little Endian string matches.
 * Supports both case-sensitive and case-insensitive search.
 *
 * Return: Number of matches found, or negative error code
 */
ssize_t scanner_string_unicode(struct memory_backend *backend,
                               struct scan_params *params,
                               const uint16_t *search_string,
                               size_t string_len,
                               bool case_sensitive,
                               struct scan_result_set *results)
{
	uint64_t addr;
	uint64_t end_addr;
	uint8_t *scan_buf;
	size_t buf_size = PAGE_SIZE * 16;  /* 64KB chunks */
	ssize_t bytes_read;
	ssize_t matches = 0;
	size_t byte_len;

	if (!backend || !params || !search_string || !results)
		return -EINVAL;

	if (string_len == 0 || string_len > 512)
		return -EINVAL;

	byte_len = string_len * 2;  /* UTF-16 = 2 bytes per char */

	/* Allocate scan buffer */
	scan_buf = kvmalloc(buf_size, GFP_KERNEL);
	if (!scan_buf)
		return -ENOMEM;

	pr_info("snakedrv: Starting Unicode string scan: 0x%llx to 0x%llx (len=%zu, case_sensitive=%d)\n",
	        params->start_address, params->end_address, string_len, case_sensitive);

	addr = params->start_address;
	end_addr = params->end_address;

	/* Align to 2-byte boundary for UTF-16 */
	if (params->aligned)
		addr = ALIGN(addr, 2);

	/* Scan memory in chunks */
	while (addr < end_addr) {
		size_t chunk_size = min_t(size_t, buf_size, end_addr - addr);
		size_t i;

		/* Read chunk from memory */
		bytes_read = backend_read(backend, addr, scan_buf, chunk_size);
		if (bytes_read <= 0) {
			addr += PAGE_SIZE;
			continue;
		}

		/* Scan chunk for string */
		for (i = 0; i <= bytes_read - byte_len; i += (params->aligned ? 2 : 1)) {
			bool match = true;
			size_t j;

			/* Compare string */
			for (j = 0; j < string_len; j++) {
				uint16_t c1 = *(uint16_t *)(scan_buf + i + j * 2);
				uint16_t c2 = search_string[j];

				if (case_sensitive) {
					if (c1 != c2) {
						match = false;
						break;
					}
				} else {
					/* Case-insensitive comparison */
					if (c1 >= 'A' && c1 <= 'Z')
						c1 += 'a' - 'A';
					if (c2 >= 'A' && c2 <= 'Z')
						c2 += 'a' - 'A';

					if (c1 != c2) {
						match = false;
						break;
					}
				}
			}

			if (match) {
				if (scanner_add_result(results, addr + i, 0) < 0) {
					pr_warn("snakedrv: Scan result set full\n");
					goto out;
				}
				matches++;
			}
		}

		addr += bytes_read;
	}

out:
	kvfree(scan_buf);
	pr_info("snakedrv: Unicode string scan complete: %zd matches found\n", matches);
	return matches;
}

/* ============================================================================
 * Pointer Chain Scanning
 * ============================================================================ */

/**
 * scanner_pointer_chain - Follow pointer chain to resolve final address
 * @backend: Memory backend
 * @base_address: Starting address (base pointer)
 * @offsets: Array of offsets to apply at each level
 * @offset_count: Number of offsets in chain
 * @final_address: Output - resolved final address
 *
 * Follows a chain of pointers to resolve the final address.
 * Example: [[base + offset0] + offset1] + offset2...
 *
 * This is essential for finding dynamically allocated game objects
 * that move in memory but are referenced through stable pointer chains.
 *
 * Return: 0 on success, negative error code on failure
 */
ssize_t scanner_pointer_chain(struct memory_backend *backend,
                              uint64_t base_address,
                              const uint32_t *offsets,
                              size_t offset_count,
                              uint64_t *final_address)
{
	uint64_t current_addr = base_address;
	size_t i;

	if (!backend || !offsets || !final_address)
		return -EINVAL;

	if (offset_count == 0 || offset_count > 32)
		return -EINVAL;

	pr_debug("snakedrv: Following pointer chain from 0x%llx (%zu levels)\n",
	         base_address, offset_count);

	/* Follow the pointer chain */
	for (i = 0; i < offset_count; i++) {
		uint64_t pointer_value;
		ssize_t bytes_read;

		/* Add offset to current address */
		current_addr += offsets[i];

		pr_debug("snakedrv:   Level %zu: 0x%llx + 0x%x = 0x%llx\n",
		         i, current_addr - offsets[i], offsets[i], current_addr);

		/* Read pointer at current address */
		bytes_read = backend_read(backend, current_addr, &pointer_value,
		                         sizeof(pointer_value));

		if (bytes_read != sizeof(pointer_value)) {
			pr_debug("snakedrv: Pointer chain broken at level %zu (read %zd bytes)\n",
			         i, bytes_read);
			return -EFAULT;
		}

		/* Follow the pointer */
		current_addr = pointer_value;

		/* Sanity check - pointer should be in reasonable range */
		if (current_addr == 0 || current_addr == (uint64_t)-1) {
			pr_debug("snakedrv: Invalid pointer 0x%llx at level %zu\n",
			         current_addr, i);
			return -EINVAL;
		}
	}

	*final_address = current_addr;

	pr_info("snakedrv: Pointer chain resolved: 0x%llx -> 0x%llx\n",
	        base_address, *final_address);

	return 0;
}
