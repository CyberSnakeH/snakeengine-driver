// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Bloom Filter Implementation
 *
 * Space-efficient probabilistic data structure for fast membership testing.
 * Perfect for memory scan rescans (changed/unchanged value detection).
 *
 * Theory:
 * - Bloom filter uses k hash functions to map elements to bit array
 * - False positive rate: (1 - e^(-kn/m))^k where:
 *   - k = number of hash functions
 *   - n = number of elements
 *   - m = bit array size
 *
 * For 1M addresses with 1% false positive rate:
 * - m = 9,585,058 bits (~1.2 MB)
 * - k = 7 hash functions
 * - Space savings: 93% compared to storing addresses
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_BLOOM_H_
#define _SNAKEDRV_BLOOM_H_

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/slab.h>

/* ============================================================================
 * Bloom Filter Configuration
 * ============================================================================ */

/* Default parameters for 1% false positive rate */
#define BLOOM_HASH_COUNT        7       /* Number of hash functions (k) */
#define BLOOM_BITS_PER_ELEMENT  10      /* Bits per element (m/n) */

/**
 * struct bloom_filter - Bloom filter structure
 * @bits: Bit array for filter storage
 * @size_bits: Size of bit array in bits
 * @num_hashes: Number of hash functions to use
 * @count: Number of elements inserted (for statistics)
 */
struct bloom_filter {
	unsigned long *bits;
	uint64_t size_bits;
	uint32_t num_hashes;
	uint64_t count;
};

/* ============================================================================
 * Hash Functions
 * ============================================================================ */

/**
 * bloom_hash_murmur3 - MurmurHash3 (64-bit)
 * @key: Key to hash (address)
 * @seed: Hash seed
 *
 * Fast, high-quality hash function from Austin Appleby.
 * Used by Redis, Cassandra, and many production systems.
 *
 * Return: 64-bit hash value
 */
static inline uint64_t bloom_hash_murmur3(uint64_t key, uint32_t seed)
{
	uint64_t h = seed;

	key *= 0xff51afd7ed558ccdULL;
	key ^= key >> 33;
	key *= 0xc4ceb9fe1a85ec53ULL;
	key ^= key >> 33;
	key *= 0xff51afd7ed558ccdULL;
	key ^= key >> 33;

	h ^= key;
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;

	return h;
}

/**
 * bloom_hash_fnv1a - FNV-1a hash (64-bit)
 * @key: Key to hash
 * @seed: Hash seed
 *
 * Fast, simple hash with good distribution.
 * FNV (Fowler-Noll-Vo) hash is widely used in hash tables.
 *
 * Return: 64-bit hash value
 */
static inline uint64_t bloom_hash_fnv1a(uint64_t key, uint32_t seed)
{
	uint64_t hash = 0xcbf29ce484222325ULL ^ seed;
	const uint8_t *data = (const uint8_t *)&key;
	int i;

	for (i = 0; i < sizeof(key); i++) {
		hash ^= data[i];
		hash *= 0x100000001b3ULL;
	}

	return hash;
}

/**
 * bloom_hash_xxhash - xxHash-inspired fast hash
 * @key: Key to hash
 * @seed: Hash seed
 *
 * Extremely fast hash inspired by xxHash algorithm.
 *
 * Return: 64-bit hash value
 */
static inline uint64_t bloom_hash_xxhash(uint64_t key, uint32_t seed)
{
	const uint64_t PRIME1 = 0x9E3779B185EBCA87ULL;
	const uint64_t PRIME2 = 0xC2B2AE3D27D4EB4FULL;
	const uint64_t PRIME3 = 0x165667B19E3779F9ULL;

	uint64_t h = seed + PRIME1;

	h ^= key * PRIME2;
	h = ((h << 31) | (h >> 33)) * PRIME3;

	h ^= h >> 29;
	h *= PRIME2;
	h ^= h >> 32;

	return h;
}

/**
 * bloom_compute_hash - Compute i-th hash for key
 * @bf: Bloom filter
 * @key: Key to hash
 * @i: Hash function index (0 to num_hashes-1)
 *
 * Uses double hashing technique: h_i(x) = h1(x) + i*h2(x)
 * This generates k independent-looking hash values from just 2 hash functions.
 *
 * Return: Hash value modulo filter size
 */
static inline uint64_t bloom_compute_hash(struct bloom_filter *bf,
                                          uint64_t key, uint32_t i)
{
	uint64_t h1, h2;

	/* Primary hash: MurmurHash3 */
	h1 = bloom_hash_murmur3(key, 0);

	/* Secondary hash: FNV-1a */
	h2 = bloom_hash_fnv1a(key, i);

	/* Double hashing: h_i(x) = h1(x) + i*h2(x) */
	return (h1 + i * h2) % bf->size_bits;
}

/* ============================================================================
 * Bloom Filter Operations
 * ============================================================================ */

/**
 * bloom_create - Create a new Bloom filter
 * @expected_elements: Expected number of elements to store
 * @false_positive_rate: Desired false positive rate (e.g., 0.01 for 1%)
 *
 * Allocates and initializes a Bloom filter with optimal parameters.
 *
 * Return: Pointer to bloom_filter, or NULL on failure
 */
static inline struct bloom_filter *bloom_create(uint64_t expected_elements,
                                                double false_positive_rate)
{
	struct bloom_filter *bf;
	uint64_t size_bits;
	uint64_t size_bytes;

	bf = kzalloc(sizeof(*bf), GFP_KERNEL);
	if (!bf)
		return NULL;

	/* Calculate optimal bit array size: m = -(n * ln(p)) / (ln(2)^2) */
	/* Simplified: m ≈ n * 10 for 1% FPR, n * 15 for 0.1% FPR */
	if (false_positive_rate <= 0.001)
		size_bits = expected_elements * 15;
	else if (false_positive_rate <= 0.01)
		size_bits = expected_elements * 10;
	else
		size_bits = expected_elements * 7;

	/* Round up to multiple of BITS_PER_LONG for efficient storage */
	size_bits = ALIGN(size_bits, BITS_PER_LONG);
	size_bytes = size_bits / 8;

	/* Allocate bit array */
	bf->bits = kvzalloc(size_bytes, GFP_KERNEL);
	if (!bf->bits) {
		kfree(bf);
		return NULL;
	}

	bf->size_bits = size_bits;
	bf->num_hashes = BLOOM_HASH_COUNT;
	bf->count = 0;

	pr_info("snakedrv: Bloom filter created: %llu bits (%llu KB), %u hashes, ~%llu elements\n",
	        size_bits, size_bytes / 1024, bf->num_hashes, expected_elements);

	return bf;
}

/**
 * bloom_destroy - Destroy a Bloom filter
 * @bf: Bloom filter to destroy
 */
static inline void bloom_destroy(struct bloom_filter *bf)
{
	if (!bf)
		return;

	if (bf->bits)
		kvfree(bf->bits);

	kfree(bf);
}

/**
 * bloom_add - Add element to Bloom filter
 * @bf: Bloom filter
 * @key: Element to add (typically an address)
 */
static inline void bloom_add(struct bloom_filter *bf, uint64_t key)
{
	uint32_t i;

	if (!bf || !bf->bits)
		return;

	/* Set k bits corresponding to k hash functions */
	for (i = 0; i < bf->num_hashes; i++) {
		uint64_t bit_index = bloom_compute_hash(bf, key, i);
		set_bit(bit_index, bf->bits);
	}

	bf->count++;
}

/**
 * bloom_test - Test if element might be in filter
 * @bf: Bloom filter
 * @key: Element to test
 *
 * Return: true if element MIGHT be in set (possible false positive),
 *         false if element is DEFINITELY NOT in set (no false negatives)
 */
static inline bool bloom_test(struct bloom_filter *bf, uint64_t key)
{
	uint32_t i;

	if (!bf || !bf->bits)
		return false;

	/* Check all k bits - if ANY is unset, element is not in set */
	for (i = 0; i < bf->num_hashes; i++) {
		uint64_t bit_index = bloom_compute_hash(bf, key, i);
		if (!test_bit(bit_index, bf->bits))
			return false;  /* Definitely not in set */
	}

	return true;  /* Probably in set (might be false positive) */
}

/**
 * bloom_clear - Clear all bits in filter (reset)
 * @bf: Bloom filter
 */
static inline void bloom_clear(struct bloom_filter *bf)
{
	if (!bf || !bf->bits)
		return;

	bitmap_zero(bf->bits, bf->size_bits);
	bf->count = 0;
}

/**
 * bloom_estimated_fpr - Estimate current false positive rate
 * @bf: Bloom filter
 *
 * Calculates: (1 - e^(-kn/m))^k
 *
 * Return: Estimated false positive rate (0.0 to 1.0)
 */
static inline double bloom_estimated_fpr(struct bloom_filter *bf)
{
	/* Simplified estimation based on fill ratio */
	uint64_t bits_set = 0;
	uint64_t i;
	double fill_ratio;

	if (!bf || !bf->bits || bf->size_bits == 0)
		return 0.0;

	/* Count set bits (sample first 1% for performance) */
	for (i = 0; i < bf->size_bits / 100; i++) {
		if (test_bit(i, bf->bits))
			bits_set++;
	}

	fill_ratio = (double)bits_set / (double)(bf->size_bits / 100);

	/* FPR ≈ (fill_ratio)^k */
	return fill_ratio;  /* Simplified - actual calculation requires pow() */
}

#endif /* _SNAKEDRV_BLOOM_H_ */
