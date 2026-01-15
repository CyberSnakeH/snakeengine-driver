/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SnakeEngine - Memory Scanner UAPI
 *
 * Userspace API for CheatEngine-style memory scanning
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_SCANNER_H_
#define _SNAKEDRV_SCANNER_H_

#include <linux/types.h>
#include <linux/ioctl.h>

/* ============================================================================
 * Scan Types
 * ============================================================================ */

/**
 * enum scan_type - Type of memory scan to perform
 */
enum scan_type {
	SCAN_TYPE_EXACT_VALUE      = 0,  /* Find exact value */
	SCAN_TYPE_PATTERN          = 1,  /* Array of bytes pattern */
	SCAN_TYPE_CHANGED_VALUE    = 2,  /* Value changed since last scan */
	SCAN_TYPE_UNCHANGED_VALUE  = 3,  /* Value unchanged */
	SCAN_TYPE_INCREASED_VALUE  = 4,  /* Value increased */
	SCAN_TYPE_DECREASED_VALUE  = 5,  /* Value decreased */
	SCAN_TYPE_RANGE            = 6,  /* Value in range [min, max] */
	SCAN_TYPE_FLOAT            = 7,  /* Float/Double scan */
	SCAN_TYPE_STRING_ASCII     = 8,  /* ASCII string */
	SCAN_TYPE_STRING_UNICODE   = 9,  /* Unicode string */
	SCAN_TYPE_POINTER_CHAIN    = 10, /* Multi-level pointer */
	SCAN_TYPE_INCREASED_BY     = 11, /* Value increased by exact amount */
	SCAN_TYPE_DECREASED_BY     = 12, /* Value decreased by exact amount */
};

/**
 * enum scan_value_type - Data type of value to scan
 */
enum scan_value_type {
	SCAN_VALUE_INT8    = 1,
	SCAN_VALUE_INT16   = 2,
	SCAN_VALUE_INT32   = 4,
	SCAN_VALUE_INT64   = 8,
	SCAN_VALUE_FLOAT   = 4,
	SCAN_VALUE_DOUBLE  = 8,
	SCAN_VALUE_BYTES   = 0,  /* Variable length */
};

/**
 * enum backend_type - Memory backend to use
 */
enum backend_type {
	BACKEND_AUTO    = 0,  /* Auto-detect */
	BACKEND_PROCESS = 2,  /* Native process (kernel-mode access) */
};

/* ============================================================================
 * IOCTL Structures
 * ============================================================================ */

/**
 * struct snake_scan_params - Parameters for memory scan
 * @pid: Target process ID
 * @scan_type: Type of scan (enum scan_type)
 * @value_type: Data type to scan for
 * @start_address: Start of memory range (0 = auto)
 * @end_address: End of memory range (0 = auto)
 * @search_value: Value to search for (exact/range scans)
 * @search_value_2: Second value (for range scans)
 * @pattern: Pattern buffer (for pattern scans)
 * @pattern_len: Length of pattern
 * @aligned: Only scan aligned addresses
 * @writable_only: Only scan writable memory
 * @parallel: Enable parallel multi-core scanning
 * @num_threads: Number of threads (0 = auto)
 * @use_bloom: Enable Bloom filter for rescans
 * @max_results: Maximum results to return (0 = unlimited)
 * @result_set_id: Result set ID for rescans (0 = new scan)
 */
struct snake_scan_params {
	__u32 pid;
	__u32 scan_type;
	__u32 value_type;
	__u64 start_address;
	__u64 end_address;
	__u64 search_value;
	__u64 search_value_2;
	__u64 pattern;           /* Pointer to pattern buffer */
	__u32 pattern_len;
	__u32 aligned:1;
	__u32 writable_only:1;
	__u32 parallel:1;
	__u32 use_bloom:1;
	__u32 num_threads;
	__u32 max_results;
	__u32 result_set_id;
	__u32 _reserved[4];
};

/**
 * struct snake_scan_result - Single scan result
 * @address: Memory address where value was found
 * @value: Value at this address
 * @size: Size of value in bytes
 * @region_index: Index of memory region containing this address
 */
struct snake_scan_result {
	__u64 address;
	__u64 value;
	__u32 size;
	__u32 region_index;
};

/**
 * struct snake_scan_execute - Execute a memory scan
 * @params: Scan parameters
 * @results: Buffer to receive results
 * @results_capacity: Size of results buffer (in number of results)
 * @results_count: Number of results returned
 * @result_set_id: ID of created result set (for future rescans)
 * @total_matches: Total matches found (may be > results_count)
 * @bytes_scanned: Total bytes scanned
 * @time_us: Scan time in microseconds
 * @result: Result code (SNAKEDRV_SUCCESS on success)
 */
struct snake_scan_execute {
	struct snake_scan_params params;
	__u64 results;           /* Pointer to result buffer */
	__u32 results_capacity;
	__u32 results_count;
	__u32 result_set_id;
	__u32 total_matches;
	__u64 bytes_scanned;
	__u64 time_us;
	__s32 result;
	__u32 _reserved[3];
};

/**
 * struct snake_scan_result_set_info - Information about a result set
 * @result_set_id: Result set ID
 * @count: Number of results in set
 * @scan_type: Type of scan that created this set
 * @has_bloom: Whether Bloom filter is enabled
 * @memory_usage: Bytes used by this result set
 */
struct snake_scan_result_set_info {
	__u32 result_set_id;
	__u32 count;
	__u32 scan_type;
	__u32 has_bloom;
	__u64 memory_usage;
	__u32 _reserved[4];
};

/**
 * struct snake_backend_info - Backend information
 * @backend_type: Active backend (enum backend_type)
 * @supports_huge_pages: Backend supports huge page optimization
 * @supports_parallel: Backend supports parallel scanning
 * @page_size: Backend page size
 * @name: Backend name string
 */
struct snake_backend_info {
	__u32 backend_type;
	__u32 supports_huge_pages:1;
	__u32 supports_parallel:1;
	__u32 page_size;
	char name[32];
	__u32 _reserved[4];
};

/**
 * struct snake_perf_stats - Performance statistics
 * @total_scans: Total number of scans performed
 * @total_bytes: Total bytes scanned
 * @total_matches: Total matches found
 * @total_time_ns: Total time spent scanning (nanoseconds)
 * @avg_latency_us: Average scan latency (microseconds)
 * @min_latency_us: Minimum scan latency
 * @max_latency_us: Maximum scan latency
 * @throughput_mbps: Average throughput (MB/s)
 * @matches_per_sec: Matches per second
 * @cache_hit_rate: Cache hit rate percentage (0-100)
 * @parallel_ratio: Percentage of scans that were parallel (0-100)
 * @huge_page_scans: Number of scans using huge pages
 * @allocated_bytes: Current allocated memory
 * @peak_bytes: Peak allocated memory
 */
struct snake_perf_stats {
	__u64 total_scans;
	__u64 total_bytes;
	__u64 total_matches;
	__u64 total_time_ns;
	__u64 avg_latency_us;
	__u64 min_latency_us;
	__u64 max_latency_us;
	__u64 throughput_mbps;
	__u64 matches_per_sec;
	__u32 cache_hit_rate;
	__u32 parallel_ratio;
	__u64 huge_page_scans;
	__u64 allocated_bytes;
	__u64 peak_bytes;
	__u32 _reserved[8];
};

/**
 * struct snake_scan_options - Global scan options
 * @enable_parallel: Enable parallel scanning by default
 * @enable_bloom: Enable Bloom filter by default
 * @enable_prefetch: Enable cache prefetching
 * @enable_huge_pages: Enable huge page detection
 * @default_threads: Default number of threads (0 = auto)
 * @bloom_fpr: Bloom filter false positive rate (0.0 - 1.0, scaled by 1000)
 */
struct snake_scan_options {
	__u32 enable_parallel:1;
	__u32 enable_bloom:1;
	__u32 enable_prefetch:1;
	__u32 enable_huge_pages:1;
	__u32 default_threads;
	__u32 bloom_fpr;         /* FPR × 1000 (e.g., 10 = 1%) */
	__u32 _reserved[4];
};

/* ============================================================================
 * IOCTL Definitions
 * ============================================================================ */

#ifndef SNAKEDRV_IOCTL_MAGIC
#define SNAKEDRV_IOCTL_MAGIC 'S'
#endif

/* Scanner IOCTLs (0x60-0x6F) */
#define SNAKE_IOCTL_SCAN_EXECUTE        _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x60, struct snake_scan_execute)
#define SNAKE_IOCTL_SCAN_GET_RESULTS    _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x61, struct snake_scan_execute)
#define SNAKE_IOCTL_SCAN_FREE_RESULTS   _IOW(SNAKEDRV_IOCTL_MAGIC, 0x62, __u32)
#define SNAKE_IOCTL_SCAN_GET_INFO       _IOWR(SNAKEDRV_IOCTL_MAGIC, 0x63, struct snake_scan_result_set_info)

/* Backend IOCTLs (0x70-0x7F) */
#define SNAKE_IOCTL_GET_BACKEND_INFO    _IOR(SNAKEDRV_IOCTL_MAGIC, 0x70, struct snake_backend_info)
#define SNAKE_IOCTL_SET_BACKEND         _IOW(SNAKEDRV_IOCTL_MAGIC, 0x71, __u32)

/* Performance IOCTLs (0x80-0x8F) */
#define SNAKE_IOCTL_GET_PERF_STATS      _IOR(SNAKEDRV_IOCTL_MAGIC, 0x80, struct snake_perf_stats)
#define SNAKE_IOCTL_RESET_PERF_STATS    _IO(SNAKEDRV_IOCTL_MAGIC, 0x81)
#define SNAKE_IOCTL_GET_SCAN_OPTIONS    _IOR(SNAKEDRV_IOCTL_MAGIC, 0x82, struct snake_scan_options)
#define SNAKE_IOCTL_SET_SCAN_OPTIONS    _IOW(SNAKEDRV_IOCTL_MAGIC, 0x83, struct snake_scan_options)

#endif /* _SNAKEDRV_SCANNER_H_ */
