// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Memory Scanner Definitions
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_KERNEL_SCANNER_H_
#define _SNAKEDRV_KERNEL_SCANNER_H_

#include <linux/types.h>
#include <linux/spinlock.h>

/* Forward declaration */
struct memory_backend;

/* Note: scan_type enum is defined in userland header */

/**
 * struct scan_params - Internal kernel scan parameters
 * @scan_type: Type of scan to perform
 * @start_address: Starting address
 * @end_address: Ending address
 * @search_value: Value to search for
 * @value_size: Size of value in bytes
 * @aligned: Only scan aligned addresses
 * @parallel: Use parallel scanning
 * @num_threads: Number of threads
 */
struct scan_params {
	uint32_t scan_type;
	uint64_t start_address;
	uint64_t end_address;
	uint64_t search_value;
	uint32_t value_size;
	bool aligned;
	bool parallel;
	uint32_t num_threads;
};

/**
 * struct scan_result - Internal kernel scan result
 * @address: GVA where value was found
 * @value: Value found at address
 */
struct scan_result {
	uint64_t address;
	uint64_t value;
};

/* Forward declaration for Bloom filter */
struct bloom_filter;

/**
 * struct scan_result_set - Set of scan results
 * @results: Array of results
 * @count: Number of results in array
 * @max_results: Maximum capacity of results array
 * @lock: Spinlock for thread-safe access
 * @bloom: Optional Bloom filter for fast address lookups (rescans)
 * @use_bloom: If true, use Bloom filter for membership testing
 * @id: Unique ID for this result set (0 = not cached)
 * @ref_count: Reference count for cache management
 * @list: List node for cached result sets
 *
 * For rescans (changed/unchanged values), the Bloom filter provides:
 * - 90%+ memory savings vs storing all addresses
 * - O(1) lookup time with multiple hash functions
 * - ~1% false positive rate (acceptable for rescans)
 */
struct scan_result_set {
	struct scan_result *results;
	uint32_t count;
	uint32_t max_results;
	spinlock_t lock;
	struct bloom_filter *bloom;
	bool use_bloom;
	uint32_t id;
	atomic_t ref_count;
	struct list_head list;
};

/* ============================================================================
 * Scanner API
 * ============================================================================ */

/* Memory subsystem initialization/cleanup */
int snakedrv_scanner_init(void);
void snakedrv_scanner_cleanup(void);

/* Result set management */
struct scan_result_set *scanner_create_result_set(uint32_t max_results);
void scanner_free_result_set(struct scan_result_set *set);

/* Result set cache management */
int scanner_cache_init(void);
void scanner_cache_cleanup(void);
uint32_t scanner_cache_add(struct scan_result_set *set);
struct scan_result_set *scanner_cache_get(uint32_t id);
void scanner_cache_put(struct scan_result_set *set);
void scanner_cache_remove(uint32_t id);

/* Exact value scanning */
ssize_t scanner_exact_value(struct memory_backend *backend,
                            struct scan_params *params,
                            struct scan_result_set *results);

/* Pattern/AOB scanning */
ssize_t scanner_pattern(struct memory_backend *backend,
                       struct scan_params *params,
                       const uint8_t *pattern,
                       const uint8_t *mask,
                       size_t pattern_len,
                       struct scan_result_set *results);

/* Changed/Unchanged value scanning */
ssize_t scanner_changed_values(struct memory_backend *backend,
                               struct scan_result_set *prev_results,
                               struct scan_result_set *new_results,
                               uint32_t value_size);

ssize_t scanner_unchanged_values(struct memory_backend *backend,
                                 struct scan_result_set *prev_results,
                                 struct scan_result_set *new_results,
                                 uint32_t value_size);

/* Increased/Decreased value scanning */
ssize_t scanner_increased_values(struct memory_backend *backend,
                                 struct scan_result_set *prev_results,
                                 struct scan_result_set *new_results,
                                 uint32_t value_size);

ssize_t scanner_decreased_values(struct memory_backend *backend,
                                 struct scan_result_set *prev_results,
                                 struct scan_result_set *new_results,
                                 uint32_t value_size);

/* Float/Double scanning */
ssize_t scanner_float_value(struct memory_backend *backend,
                            struct scan_params *params,
                            float search_value,
                            struct scan_result_set *results);

ssize_t scanner_double_value(struct memory_backend *backend,
                             struct scan_params *params,
                             double search_value,
                             struct scan_result_set *results);

/* String scanning */
ssize_t scanner_string_ascii(struct memory_backend *backend,
                             struct scan_params *params,
                             const char *search_string,
                             size_t string_len,
                             bool case_sensitive,
                             struct scan_result_set *results);

ssize_t scanner_string_unicode(struct memory_backend *backend,
                               struct scan_params *params,
                               const uint16_t *search_string,
                               size_t string_len,
                               bool case_sensitive,
                               struct scan_result_set *results);

/* Additional differential scans */
ssize_t scanner_exact_value_rescan(struct memory_backend *backend,
                                   struct scan_result_set *prev_results,
                                   struct scan_result_set *new_results,
                                   uint64_t search_value,
                                   uint32_t value_size);

ssize_t scanner_value_between(struct memory_backend *backend,
                              struct scan_result_set *prev_results,
                              struct scan_result_set *new_results,
                              uint64_t min_value,
                              uint64_t max_value,
                              uint32_t value_size);

ssize_t scanner_increased_by(struct memory_backend *backend,
                            struct scan_result_set *prev_results,
                            struct scan_result_set *new_results,
                            uint64_t delta,
                            uint32_t value_size);

ssize_t scanner_decreased_by(struct memory_backend *backend,
                            struct scan_result_set *prev_results,
                            struct scan_result_set *new_results,
                            uint64_t delta,
                            uint32_t value_size);

/* Pointer chain scanning */
ssize_t scanner_pointer_chain(struct memory_backend *backend,
                              uint64_t base_address,
                              const uint32_t *offsets,
                              size_t offset_count,
                              uint64_t *final_address);

#endif /* _SNAKEDRV_KERNEL_SCANNER_H_ */
