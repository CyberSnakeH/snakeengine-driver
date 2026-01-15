// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Performance Optimization Helpers
 *
 * World-class performance tuning for memory scanning operations.
 * Techniques from high-frequency trading, game engines, and databases.
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_OPTIMIZE_H_
#define _SNAKEDRV_OPTIMIZE_H_

#include <linux/kernel.h>
#include <linux/prefetch.h>
#include <linux/cache.h>

/* ============================================================================
 * CPU Cache Optimization Constants
 * ============================================================================ */

/*
 * Modern CPU cache line sizes:
 * - L1 Cache: 32KB-64KB (very fast, ~4 cycles)
 * - L2 Cache: 256KB-512KB (fast, ~12 cycles)
 * - L3 Cache: 8MB-32MB (slower, ~40 cycles)
 * - Cache line: 64 bytes (x86_64/ARM64)
 */

#define SNAKEDRV_CACHE_LINE_SIZE    64
#define SNAKEDRV_L1_CACHE_SIZE      (32 * 1024)
#define SNAKEDRV_L2_CACHE_SIZE      (256 * 1024)
#define SNAKEDRV_L3_CACHE_SIZE      (8 * 1024 * 1024)

/*
 * Optimal chunk sizes for scanning:
 * - Small chunks: Fit in L1 cache for maximum speed
 * - Medium chunks: Fit in L2 cache for balanced performance
 * - Large chunks: Minimize syscall overhead for huge scans
 */
#define SNAKEDRV_SCAN_CHUNK_SMALL   (16 * 1024)   /* 16KB - fits L1 */
#define SNAKEDRV_SCAN_CHUNK_MEDIUM  (64 * 1024)   /* 64KB - fits L2 */
#define SNAKEDRV_SCAN_CHUNK_LARGE   (256 * 1024)  /* 256KB - fits L3 */

/*
 * Prefetch distance: How many cache lines ahead to prefetch
 * - Too small: Prefetch arrives too late (cache miss)
 * - Too large: Prefetch evicts useful data (cache pollution)
 * - Sweet spot: ~4-8 cache lines ahead
 */
#define SNAKEDRV_PREFETCH_DISTANCE  (8 * SNAKEDRV_CACHE_LINE_SIZE)

/* ============================================================================
 * Prefetch Macros
 * ============================================================================ */

/**
 * prefetch_scan_data - Prefetch data for read (scanning)
 * @ptr: Pointer to prefetch
 *
 * Tells CPU to load data into cache before we need it.
 * Uses temporal locality hint (data will be accessed multiple times).
 */
#define prefetch_scan_data(ptr) \
	prefetch((ptr))

/**
 * prefetch_scan_write - Prefetch data for write (result storage)
 * @ptr: Pointer to prefetch
 *
 * Prefetch with write intent (exclusive cache line ownership).
 */
#define prefetch_scan_write(ptr) \
	prefetchw((ptr))

/**
 * prefetch_scan_range - Prefetch a range of memory
 * @start: Start address
 * @size: Size in bytes
 *
 * Prefetches multiple cache lines for sequential access.
 */
static inline void prefetch_scan_range(const void *start, size_t size)
{
	const char *ptr = (const char *)start;
	const char *end = ptr + size;

	/* Prefetch every cache line in the range */
	while (ptr < end) {
		prefetch_scan_data(ptr);
		ptr += SNAKEDRV_CACHE_LINE_SIZE;
	}
}

/* ============================================================================
 * Cache-Aligned Allocation
 * ============================================================================ */

/**
 * is_cache_aligned - Check if address is cache-line aligned
 * @addr: Address to check
 *
 * Return: true if aligned to cache line boundary
 */
static inline bool is_cache_aligned(unsigned long addr)
{
	return (addr & (SNAKEDRV_CACHE_LINE_SIZE - 1)) == 0;
}

/**
 * cache_align_up - Round up to next cache line boundary
 * @addr: Address to align
 *
 * Return: Cache-aligned address
 */
static inline unsigned long cache_align_up(unsigned long addr)
{
	return ALIGN(addr, SNAKEDRV_CACHE_LINE_SIZE);
}

/**
 * cache_align_down - Round down to cache line boundary
 * @addr: Address to align
 *
 * Return: Cache-aligned address
 */
static inline unsigned long cache_align_down(unsigned long addr)
{
	return addr & ~(SNAKEDRV_CACHE_LINE_SIZE - 1);
}

/* ============================================================================
 * Branch Prediction Hints
 * ============================================================================ */

/*
 * Help the CPU's branch predictor make better decisions.
 * Modern CPUs are very good at branch prediction, but explicit hints
 * can improve performance in tight loops by ~5-10%.
 */

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* ============================================================================
 * Loop Optimization Hints
 * ============================================================================ */

/**
 * SNAKEDRV_HOT - Mark hot path function
 *
 * Tells compiler this function is called frequently.
 * Compiler will optimize for speed over size.
 */
#define SNAKEDRV_HOT __attribute__((hot))

/**
 * SNAKEDRV_COLD - Mark cold path function
 *
 * Tells compiler this function is rarely called.
 * Compiler will optimize for size over speed.
 */
#define SNAKEDRV_COLD __attribute__((cold))

/**
 * SNAKEDRV_INLINE - Force inline for hot path
 *
 * Always inline critical functions to eliminate call overhead.
 */
#define SNAKEDRV_INLINE __always_inline

/* ============================================================================
 * Memory Access Optimization
 * ============================================================================ */

/**
 * read_once_optimized - Read memory location once (no volatile reload)
 * @var: Variable to read
 *
 * Prevents compiler from reloading the value multiple times.
 * Useful in hot loops where we know the value won't change.
 */
#define read_once_optimized(var) READ_ONCE(var)

/**
 * write_once_optimized - Write memory location once
 * @var: Variable to write
 * @val: Value to write
 *
 * Ensures single write, prevents compiler optimizations that
 * might break concurrent access patterns.
 */
#define write_once_optimized(var, val) WRITE_ONCE(var, val)

/* ============================================================================
 * SIMD/Vector Hints
 * ============================================================================ */

/*
 * Note: Kernel space doesn't allow direct SIMD usage, but we can:
 * 1. Ensure proper alignment for potential future SIMD
 * 2. Structure data for vectorization-friendly patterns
 * 3. Use REP MOVSB/STOSB for block operations
 */

/**
 * SNAKEDRV_VECTOR_ALIGN - Alignment for SIMD-friendly data
 *
 * 16-byte alignment works for SSE, 32-byte for AVX, 64-byte for AVX-512.
 * We use 64-byte to be cache-line aligned as well.
 */
#define SNAKEDRV_VECTOR_ALIGN __aligned(SNAKEDRV_CACHE_LINE_SIZE)

/* ============================================================================
 * Performance Counters & Instrumentation
 * ============================================================================ */

/**
 * perf_counter_inc - Increment performance counter (zero-cost in release)
 * @counter: Atomic counter to increment
 */
#ifdef CONFIG_SNAKEDRV_PERF_COUNTERS
#define perf_counter_inc(counter) atomic64_inc(&(counter))
#define perf_counter_add(counter, val) atomic64_add(val, &(counter))
#else
#define perf_counter_inc(counter) do { } while (0)
#define perf_counter_add(counter, val) do { } while (0)
#endif

/**
 * perf_mark_hotpath - Mark hot path for profiling
 *
 * Helps with perf/ftrace analysis.
 */
#define perf_mark_hotpath() \
	do { if (unlikely(0)) barrier(); } while (0)

/* ============================================================================
 * Huge Pages Support
 * ============================================================================ */

/**
 * is_huge_page_aligned - Check if address is huge-page aligned
 * @addr: Address to check
 * @size: Huge page size (2MB or 1GB)
 *
 * Return: true if aligned
 */
static inline bool is_huge_page_aligned(unsigned long addr, unsigned long size)
{
	return (addr & (size - 1)) == 0;
}

#define HUGE_PAGE_2MB  (2 * 1024 * 1024)
#define HUGE_PAGE_1GB  (1024 * 1024 * 1024)

/* ============================================================================
 * Scan Strategy Selection
 * ============================================================================ */

/**
 * select_optimal_chunk_size - Choose best chunk size for scan
 * @total_size: Total memory region to scan
 *
 * Adaptively selects chunk size based on total scan size:
 * - Small regions: Use small chunks (L1 cache-friendly)
 * - Medium regions: Use medium chunks (L2 cache-friendly)
 * - Large regions: Use large chunks (minimize overhead)
 *
 * Return: Optimal chunk size in bytes
 */
static inline size_t select_optimal_chunk_size(uint64_t total_size)
{
	if (total_size < SNAKEDRV_L1_CACHE_SIZE)
		return SNAKEDRV_SCAN_CHUNK_SMALL;
	else if (total_size < SNAKEDRV_L2_CACHE_SIZE)
		return SNAKEDRV_SCAN_CHUNK_MEDIUM;
	else
		return SNAKEDRV_SCAN_CHUNK_LARGE;
}

/**
 * select_chunk_size_for_page - Choose chunk size based on page type
 * @page_size: Size of current page (4KB, 2MB, or 1GB)
 * @remaining: Bytes remaining to scan
 *
 * Optimizes chunk size for huge pages:
 * - 1GB pages: Use 2MB chunks (maximize throughput)
 * - 2MB pages: Use full 2MB chunks (no page boundary crossing)
 * - 4KB pages: Use standard adaptive chunks
 *
 * This reduces page table walks and exploits huge page contiguity.
 *
 * Return: Optimal chunk size for this page type
 */
static inline size_t select_chunk_size_for_page(uint32_t page_size,
                                                 uint64_t remaining)
{
	size_t chunk_size;

	if (page_size >= HUGE_PAGE_1GB) {
		/* 1GB page: Use 2MB chunks for maximum throughput */
		chunk_size = HUGE_PAGE_2MB;
	} else if (page_size >= HUGE_PAGE_2MB) {
		/* 2MB page: Use full 2MB chunks */
		chunk_size = HUGE_PAGE_2MB;
	} else {
		/* 4KB page: Use standard adaptive chunk sizing */
		chunk_size = select_optimal_chunk_size(remaining);
	}

	/* Never exceed remaining bytes */
	return min_t(size_t, chunk_size, remaining);
}

/**
 * get_huge_page_boundary - Calculate next huge page boundary
 * @addr: Current address
 * @page_size: Size of current page
 *
 * Calculates the end address of the current huge page.
 * Useful for determining how much contiguous memory we can scan
 * without triggering a new page table walk.
 *
 * Return: Address of next page boundary
 */
static inline uint64_t get_huge_page_boundary(uint64_t addr, uint32_t page_size)
{
	if (page_size >= HUGE_PAGE_1GB) {
		/* Align to next 1GB boundary */
		return (addr + HUGE_PAGE_1GB) & ~(HUGE_PAGE_1GB - 1);
	} else if (page_size >= HUGE_PAGE_2MB) {
		/* Align to next 2MB boundary */
		return (addr + HUGE_PAGE_2MB) & ~(HUGE_PAGE_2MB - 1);
	} else {
		/* 4KB page - align to next 4KB boundary */
		return (addr + PAGE_SIZE) & PAGE_MASK;
	}
}

#endif /* _SNAKEDRV_OPTIMIZE_H_ */
