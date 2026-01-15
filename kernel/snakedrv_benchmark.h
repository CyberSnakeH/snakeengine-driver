// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Benchmark Framework & Performance Metrics
 *
 * Comprehensive performance monitoring for all scanner operations.
 * Tracks latency, throughput, cache efficiency, and parallelism.
 *
 * Metrics are exported via sysfs for userspace analysis tools.
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_BENCHMARK_H_
#define _SNAKEDRV_BENCHMARK_H_

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/limits.h>

/* ============================================================================
 * Performance Counters
 * ============================================================================ */

/**
 * struct scan_perf_counters - Per-scan-type performance counters
 * @total_scans: Total number of scans performed
 * @total_bytes: Total bytes scanned
 * @total_matches: Total matches found
 * @total_time_ns: Total time spent scanning (nanoseconds)
 * @min_time_ns: Minimum scan time (fastest scan)
 * @max_time_ns: Maximum scan time (slowest scan)
 * @cache_hits: Number of buffer pool cache hits
 * @cache_misses: Number of buffer pool cache misses
 * @huge_page_scans: Number of scans that used huge pages
 * @parallel_scans: Number of parallel scans
 * @sequential_scans: Number of sequential scans
 */
struct scan_perf_counters {
	atomic64_t total_scans;
	atomic64_t total_bytes;
	atomic64_t total_matches;
	atomic64_t total_time_ns;
	atomic64_t min_time_ns;
	atomic64_t max_time_ns;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
	atomic64_t huge_page_scans;
	atomic64_t parallel_scans;
	atomic64_t sequential_scans;
};

/**
 * struct snakedrv_perf_stats - Global performance statistics
 * @exact_value: Counters for exact value scans
 * @pattern: Counters for pattern/AOB scans
 * @changed: Counters for changed value rescans
 * @unchanged: Counters for unchanged value rescans
 * @float_scan: Counters for float scans
 * @double_scan: Counters for double scans
 * @string_ascii: Counters for ASCII string scans
 * @string_unicode: Counters for Unicode string scans
 * @pointer_chain: Counters for pointer chain resolutions
 */
struct snakedrv_perf_stats {
	struct scan_perf_counters exact_value;
	struct scan_perf_counters pattern;
	struct scan_perf_counters changed;
	struct scan_perf_counters unchanged;
	struct scan_perf_counters float_scan;
	struct scan_perf_counters double_scan;
	struct scan_perf_counters string_ascii;
	struct scan_perf_counters string_unicode;
	struct scan_perf_counters pointer_chain;
};

/* Global performance statistics */
extern struct snakedrv_perf_stats global_perf_stats;

/**
 * snakedrv_perf_init - Initialize performance counters
 *
 * Resets all performance counters to zero.
 * Call once during module initialization.
 */
static inline void snakedrv_perf_init(struct snakedrv_perf_stats *stats)
{
	memset(stats, 0, sizeof(*stats));

	/* Initialize min_time_ns to max value */
	atomic64_set(&stats->exact_value.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->pattern.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->changed.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->unchanged.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->float_scan.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->double_scan.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->string_ascii.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->string_unicode.min_time_ns, LLONG_MAX);
	atomic64_set(&stats->pointer_chain.min_time_ns, LLONG_MAX);
}

/* ============================================================================
 * Performance Measurement
 * ============================================================================ */

/**
 * struct scan_timer - High-resolution timer for scan operations
 * @start: Start time (ktime)
 * @end: End time (ktime)
 * @counters: Performance counters to update
 * @bytes_scanned: Number of bytes scanned
 * @matches_found: Number of matches found
 * @is_parallel: Whether scan used parallelism
 * @is_huge_page: Whether scan used huge pages
 */
struct scan_timer {
	ktime_t start;
	ktime_t end;
	struct scan_perf_counters *counters;
	uint64_t bytes_scanned;
	uint64_t matches_found;
	bool is_parallel;
	bool is_huge_page;
};

/**
 * snakedrv_timer_start - Start performance timer
 * @timer: Timer structure
 * @counters: Performance counters to update when done
 *
 * Captures start time using high-resolution kernel time.
 */
static inline void snakedrv_timer_start(struct scan_timer *timer,
                                        struct scan_perf_counters *counters)
{
	timer->start = ktime_get();
	timer->counters = counters;
	timer->bytes_scanned = 0;
	timer->matches_found = 0;
	timer->is_parallel = false;
	timer->is_huge_page = false;
}

/**
 * snakedrv_timer_stop - Stop performance timer and update counters
 * @timer: Timer structure
 *
 * Captures end time and updates all relevant performance counters.
 * Calculates throughput, latency, and other metrics.
 */
static inline void snakedrv_timer_stop(struct scan_timer *timer)
{
	int64_t elapsed_ns, old_min, old_max;

	if (!timer->counters)
		return;

	timer->end = ktime_get();
	elapsed_ns = ktime_to_ns(ktime_sub(timer->end, timer->start));

	/* Update counters atomically */
	atomic64_inc(&timer->counters->total_scans);
	atomic64_add(timer->bytes_scanned, &timer->counters->total_bytes);
	atomic64_add(timer->matches_found, &timer->counters->total_matches);
	atomic64_add(elapsed_ns, &timer->counters->total_time_ns);

	/* Update min time (lock-free) */
	do {
		old_min = atomic64_read(&timer->counters->min_time_ns);
		if (elapsed_ns >= old_min)
			break;
	} while (atomic64_cmpxchg(&timer->counters->min_time_ns,
	                          old_min, elapsed_ns) != old_min);

	/* Update max time (lock-free) */
	do {
		old_max = atomic64_read(&timer->counters->max_time_ns);
		if (elapsed_ns <= old_max)
			break;
	} while (atomic64_cmpxchg(&timer->counters->max_time_ns,
	                          old_max, elapsed_ns) != old_max);

	/* Update optimization-specific counters */
	if (timer->is_parallel)
		atomic64_inc(&timer->counters->parallel_scans);
	else
		atomic64_inc(&timer->counters->sequential_scans);

	if (timer->is_huge_page)
		atomic64_inc(&timer->counters->huge_page_scans);
}

/* ============================================================================
 * Statistics Calculation
 * ============================================================================ */

/**
 * snakedrv_get_avg_latency_ns - Calculate average scan latency
 * @counters: Performance counters
 *
 * Return: Average latency in nanoseconds, or 0 if no scans
 */
static inline int64_t snakedrv_get_avg_latency_ns(struct scan_perf_counters *counters)
{
	int64_t total_scans = atomic64_read(&counters->total_scans);
	int64_t total_time = atomic64_read(&counters->total_time_ns);

	if (total_scans == 0)
		return 0;

	return total_time / total_scans;
}

/**
 * snakedrv_get_throughput_mbps - Calculate average throughput
 * @counters: Performance counters
 *
 * Return: Throughput in MB/s, or 0 if no scans
 */
static inline int64_t snakedrv_get_throughput_mbps(struct scan_perf_counters *counters)
{
	int64_t total_bytes = atomic64_read(&counters->total_bytes);
	int64_t total_time_ns = atomic64_read(&counters->total_time_ns);

	if (total_time_ns == 0)
		return 0;

	/* throughput = (bytes / time_ns) * 1e9 / (1024*1024) */
	return (total_bytes * 1000) / (total_time_ns / 1000000);
}

/**
 * snakedrv_get_match_rate - Calculate matches per second
 * @counters: Performance counters
 *
 * Return: Matches per second, or 0 if no scans
 */
static inline int64_t snakedrv_get_match_rate(struct scan_perf_counters *counters)
{
	int64_t total_matches = atomic64_read(&counters->total_matches);
	int64_t total_time_ns = atomic64_read(&counters->total_time_ns);

	if (total_time_ns == 0)
		return 0;

	/* matches_per_sec = (matches / time_ns) * 1e9 */
	return (total_matches * 1000000000) / total_time_ns;
}

/**
 * snakedrv_get_cache_hit_rate - Calculate cache hit rate percentage
 * @counters: Performance counters
 *
 * Return: Cache hit rate (0-100), or 0 if no cache operations
 */
static inline int64_t snakedrv_get_cache_hit_rate(struct scan_perf_counters *counters)
{
	int64_t hits = atomic64_read(&counters->cache_hits);
	int64_t misses = atomic64_read(&counters->cache_misses);
	int64_t total = hits + misses;

	if (total == 0)
		return 0;

	return (hits * 100) / total;
}

/**
 * snakedrv_get_parallel_ratio - Calculate percentage of parallel scans
 * @counters: Performance counters
 *
 * Return: Parallel scan ratio (0-100)
 */
static inline int64_t snakedrv_get_parallel_ratio(struct scan_perf_counters *counters)
{
	int64_t parallel = atomic64_read(&counters->parallel_scans);
	int64_t total = atomic64_read(&counters->total_scans);

	if (total == 0)
		return 0;

	return (parallel * 100) / total;
}

/* ============================================================================
 * Performance Report Generation
 * ============================================================================ */

/**
 * snakedrv_perf_report - Generate human-readable performance report
 * @buf: Output buffer
 * @size: Buffer size
 * @counters: Performance counters
 * @name: Name of scan type (for report)
 *
 * Return: Number of bytes written to buffer
 */
static inline ssize_t snakedrv_perf_report(char *buf, size_t size,
                                            struct scan_perf_counters *counters,
                                            const char *name)
{
	int64_t total_scans = atomic64_read(&counters->total_scans);
	int64_t total_bytes = atomic64_read(&counters->total_bytes);
	int64_t total_matches = atomic64_read(&counters->total_matches);
	int64_t min_time = atomic64_read(&counters->min_time_ns);
	int64_t max_time = atomic64_read(&counters->max_time_ns);

	if (total_scans == 0)
		return scnprintf(buf, size, "%s: No data\n", name);

	return scnprintf(buf, size,
		"%s Performance:\n"
		"  Total scans:      %lld\n"
		"  Total bytes:      %lld MB\n"
		"  Total matches:    %lld\n"
		"  Avg latency:      %lld µs\n"
		"  Min latency:      %lld µs\n"
		"  Max latency:      %lld µs\n"
		"  Throughput:       %lld MB/s\n"
		"  Match rate:       %lld /sec\n"
		"  Cache hit rate:   %lld%%\n"
		"  Parallel ratio:   %lld%%\n"
		"  Huge page scans:  %lld\n",
		name,
		total_scans,
		total_bytes / (1024 * 1024),
		total_matches,
		snakedrv_get_avg_latency_ns(counters) / 1000,
		(min_time == LLONG_MAX) ? 0 : min_time / 1000,
		max_time / 1000,
		snakedrv_get_throughput_mbps(counters),
		snakedrv_get_match_rate(counters),
		snakedrv_get_cache_hit_rate(counters),
		snakedrv_get_parallel_ratio(counters),
		atomic64_read(&counters->huge_page_scans)
	);
}

/**
 * snakedrv_perf_report_all - Generate complete performance report
 * @buf: Output buffer
 * @size: Buffer size
 * @stats: Global performance statistics
 *
 * Return: Number of bytes written to buffer
 */
static inline ssize_t snakedrv_perf_report_all(char *buf, size_t size,
                                                struct snakedrv_perf_stats *stats)
{
	ssize_t len = 0;

	len += scnprintf(buf + len, size - len,
		"=== SnakeEngine Performance Statistics ===\n\n");

	len += snakedrv_perf_report(buf + len, size - len,
	                            &stats->exact_value, "Exact Value Scan");
	len += scnprintf(buf + len, size - len, "\n");

	len += snakedrv_perf_report(buf + len, size - len,
	                            &stats->pattern, "Pattern/AOB Scan");
	len += scnprintf(buf + len, size - len, "\n");

	len += snakedrv_perf_report(buf + len, size - len,
	                            &stats->changed, "Changed Value Rescan");
	len += scnprintf(buf + len, size - len, "\n");

	len += snakedrv_perf_report(buf + len, size - len,
	                            &stats->unchanged, "Unchanged Value Rescan");
	len += scnprintf(buf + len, size - len, "\n");

	return len;
}

#endif /* _SNAKEDRV_BENCHMARK_H_ */
