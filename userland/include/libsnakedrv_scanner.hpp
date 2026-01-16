/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SnakeEngine - Memory Scanner C++ API
 *
 * Modern C++ interface for CheatEngine-style memory scanning
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _LIBSNAKEDRV_SCANNER_HPP_
#define _LIBSNAKEDRV_SCANNER_HPP_

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <chrono>
#include <cstdint>
#include <stdexcept>

#include "snakedrv_scanner.h"

namespace snake {

/* Forward declarations */
class Driver;

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

/**
 * enum class ScanType - High-level scan strategy
 */
enum class ScanType {
    ExactValue     = SCAN_TYPE_EXACT_VALUE,
    Pattern        = SCAN_TYPE_PATTERN,
    ChangedValue   = SCAN_TYPE_CHANGED_VALUE,
    UnchangedValue = SCAN_TYPE_UNCHANGED_VALUE,
    IncreasedValue = SCAN_TYPE_INCREASED_VALUE,
    DecreasedValue = SCAN_TYPE_DECREASED_VALUE,
    Range          = SCAN_TYPE_RANGE,
    Float          = SCAN_TYPE_FLOAT,
    StringAscii    = SCAN_TYPE_STRING_ASCII,
    StringUnicode  = SCAN_TYPE_STRING_UNICODE,
    PointerChain   = SCAN_TYPE_POINTER_CHAIN,
};

/**
 * enum class ValueType - Primitive value types for scans
 */
enum class ValueType {
    Int8   = SCAN_VALUE_INT8,
    Int16  = SCAN_VALUE_INT16,
    Int32  = SCAN_VALUE_INT32,
    Int64  = SCAN_VALUE_INT64,
    Float  = SCAN_VALUE_FLOAT,
    Double = SCAN_VALUE_DOUBLE,
    Bytes  = SCAN_VALUE_BYTES,
};

/**
 * enum class BackendType - Scanner backend selection
 */
enum class BackendType {
    Auto    = BACKEND_AUTO,
    Process = BACKEND_PROCESS,
};

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * struct ScanResult - Single scan hit
 * @address: Address where the match was found
 * @value: Raw value (truncated or packed)
 * @size: Size of the matched value in bytes
 * @regionIndex: Index of the region that contains the address
 */
struct ScanResult {
    uint64_t address;
    uint64_t value;
    uint32_t size;
    uint32_t regionIndex;

    /**
     * as - Interpret the raw value as a specific type
     * @return Value cast to T
     */
    template<typename T>
    T as() const {
        static_assert(sizeof(T) <= sizeof(value), "Type too large");
        return static_cast<T>(value);
    }
};

/**
 * struct ScanStats - Statistics for the most recent scan
 * @totalMatches: Total matches found in memory
 * @returnedResults: Results returned to user (may be limited)
 * @bytesScanned: Total bytes scanned
 * @timeUs: Scan time in microseconds
 */
struct ScanStats {
    uint32_t totalMatches;    // Total matches found
    uint32_t returnedResults; // Results returned (may be < total)
    uint64_t bytesScanned;    // Bytes scanned
    uint64_t timeUs;          // Scan time in microseconds

    /**
     * throughputMBps - Compute throughput from bytes/time
     * @return MB/s throughput
     */
    double throughputMBps() const {
        if (timeUs == 0) return 0.0;
        return (bytesScanned / 1024.0 / 1024.0) / (timeUs / 1000000.0);
    }

    /**
     * matchRate - Compute matches per second
     * @return Matches per second
     */
    double matchRate() const {
        if (timeUs == 0) return 0.0;
        return totalMatches / (timeUs / 1000000.0);
    }
};

/**
 * struct BackendInfo - Active backend capabilities
 * @type: Backend type in use
 * @name: Human-readable backend name
 * @supportsHugePages: Whether huge pages are supported
 * @supportsParallel: Whether parallel scanning is supported
 * @pageSize: Backend page size
 */
struct BackendInfo {
    BackendType type;
    std::string name;
    bool supportsHugePages;
    bool supportsParallel;
    uint32_t pageSize;
};

/**
 * struct PerformanceStats - Aggregated scanner performance stats
 * @totalScans/totalBytes/totalMatches/totalTimeNs: Aggregates
 * @avgLatencyUs/minLatencyUs/maxLatencyUs: Latency statistics
 * @throughputMBps/matchesPerSec: Throughput statistics
 * @cacheHitRate/parallelRatio: Percent metrics (0-100)
 * @hugePageScans: Count of huge page scans
 * @allocatedBytes/peakBytes: Memory usage stats
 */
struct PerformanceStats {
    uint64_t totalScans;
    uint64_t totalBytes;
    uint64_t totalMatches;
    uint64_t totalTimeNs;

    uint64_t avgLatencyUs;
    uint64_t minLatencyUs;
    uint64_t maxLatencyUs;

    uint64_t throughputMBps;
    uint64_t matchesPerSec;

    uint32_t cacheHitRate;      // 0-100%
    uint32_t parallelRatio;     // 0-100%
    uint64_t hugePageScans;

    uint64_t allocatedBytes;
    uint64_t peakBytes;

    /**
     * avgThroughput - Return throughput in MB/s as double
     * @return Average throughput
     */
    double avgThroughput() const { return static_cast<double>(throughputMBps); }
    /**
     * cacheEfficiency - Return cache hit rate as ratio
     * @return Cache efficiency in [0.0, 1.0]
     */
    double cacheEfficiency() const { return cacheHitRate / 100.0; }
};

/**
 * struct ScanOptions - Global scanner defaults
 * @enableParallel: Enable parallel scanning by default
 * @enableBloom: Enable Bloom filter for rescans
 * @enablePrefetch: Enable cache prefetching
 * @enableHugePages: Enable huge page detection
 * @defaultThreads: Default thread count (0 = auto)
 * @bloomFpr: Bloom filter false positive rate
 */
struct ScanOptions {
    bool enableParallel = true;
    bool enableBloom = true;
    bool enablePrefetch = true;
    bool enableHugePages = true;
    uint32_t defaultThreads = 0;  // 0 = auto
    double bloomFpr = 0.01;        // 1% false positive rate
};

/* ============================================================================
 * Result Set Handle
 * ============================================================================ */

/**
 * class ResultSet - Handle to a server-side result set
 */
class ResultSet {
public:
    /**
     * ResultSet - Construct an invalid handle
     */
    ResultSet() = default;
    /**
     * ResultSet - Construct a handle with ID and count
     * @id: Result set ID
     * @count: Number of results stored
     */
    ResultSet(uint32_t id, uint32_t count) : id_(id), count_(count) {}

    /**
     * id - Return result set ID
     * @return Result set ID
     */
    uint32_t id() const { return id_; }
    /**
     * count - Return number of results in the set
     * @return Result count
     */
    uint32_t count() const { return count_; }
    /**
     * isValid - Check if the handle refers to a valid set
     * @return true if valid
     */
    bool isValid() const { return id_ > 0; }

private:
    friend class Scanner;
    uint32_t id_ = 0;
    uint32_t count_ = 0;
};

/* ============================================================================
 * Memory Scanner Class
 * ============================================================================ */

/**
 * class Scanner - Memory scanning interface
 *
 * Provides CheatEngine-like scanning capabilities.
 * Requires an attached Driver instance.
 *
 * Example:
 *   Scanner scanner(driver);
 *   auto results = scanner.exactValue<int32_t>(12345);
 *   for (const auto& r : results) {
 *       std::cout << "Found at: 0x" << std::hex << r.address << "\n";
 *   }
 */
class Scanner {
public:
    /**
     * Construct scanner for attached driver
     * @param driver Driver instance (must be attached to a process)
     */
    /**
     * Scanner - Construct a scanner bound to a Driver
     * @driver: Driver instance (must be attached)
     */
    explicit Scanner(Driver& driver);
    /**
     * ~Scanner - Cleanup
     */
    ~Scanner();

    /* Basic scans */

    /**
     * Scan for exact value
     * @param value Value to search for
     * @param aligned Only scan aligned addresses
     * @param writableOnly Only scan writable memory
     * @return Vector of results
     */
    template<typename T>
    std::vector<ScanResult> exactValue(T value, bool aligned = false, bool writableOnly = false);

    /**
     * Scan for value in range
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     */
    template<typename T>
    std::vector<ScanResult> rangeValue(T min, T max, bool aligned = false);

    /**
     * Scan for byte pattern
     * @param pattern Pattern to search (use -1 for wildcards)
     * @return Vector of results
     */
    std::vector<ScanResult> pattern(const std::vector<int16_t>& pattern);

    /**
     * Scan for ASCII string
     */
    std::vector<ScanResult> stringAscii(const std::string& str, bool caseSensitive = true);

    /**
     * Scan for Unicode string
     */
    std::vector<ScanResult> stringUnicode(const std::wstring& str, bool caseSensitive = true);

    /* Differential scans (rescans) */

    /**
     * Find values that changed since last scan
     * @param previousResults Result set from previous scan
     * @return New result set with changed values
     */
    std::vector<ScanResult> changedValue(const ResultSet& previousResults);

    /**
     * Find values that didn't change
     */
    std::vector<ScanResult> unchangedValue(const ResultSet& previousResults);

    /**
     * Find values that increased
     */
    std::vector<ScanResult> increasedValue(const ResultSet& previousResults);

    /**
     * Find values that decreased
     */
    std::vector<ScanResult> decreasedValue(const ResultSet& previousResults);

    /**
     * Rescan for exact value
     * @param previousResults Result set from previous scan
     * @param value Value to search for
     * @return New result set with matching values
     */
    template<typename T>
    std::vector<ScanResult> exactValueRescan(const ResultSet& previousResults, T value);

    /**
     * Rescan for value in range
     * @param previousResults Result set from previous scan
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @return New result set with values in range
     */
    template<typename T>
    std::vector<ScanResult> valueBetween(const ResultSet& previousResults, T min, T max);

    /**
     * Find values increased by exact amount
     * @param previousResults Result set from previous scan
     * @param delta Amount the value should have increased by
     * @return New result set with matching values
     */
    template<typename T>
    std::vector<ScanResult> increasedBy(const ResultSet& previousResults, T delta);

    /**
     * Find values decreased by exact amount
     * @param previousResults Result set from previous scan
     * @param delta Amount the value should have decreased by
     * @return New result set with matching values
     */
    template<typename T>
    std::vector<ScanResult> decreasedBy(const ResultSet& previousResults, T delta);

    /* Advanced scans */

    /**
     * Scan for float value with tolerance
     */
    std::vector<ScanResult> floatValue(float value, float tolerance = 0.01f);

    /**
     * Scan for double value with tolerance
     */
    std::vector<ScanResult> doubleValue(double value, double tolerance = 0.01);

    /**
     * Follow pointer chain
     * @param baseAddress Starting address
     * @param offsets Vector of offsets to follow
     * @return Final address or nullopt if invalid
     */
    std::optional<uint64_t> followPointerChain(uint64_t baseAddress,
                                               const std::vector<uint64_t>& offsets);

    /* Configuration */

    /**
     * Set memory range to scan
     * @param start Start address (0 = auto)
     * @param end End address (0 = auto)
     */
    void setRange(uint64_t start, uint64_t end);

    /**
     * Reset to full memory range
     */
    void resetRange();

    /**
     * Set maximum results to return
     * @param max Maximum results (0 = unlimited)
     */
    void setMaxResults(uint32_t max);

    /**
     * Enable/disable parallel scanning
     */
    void setParallel(bool enable, uint32_t numThreads = 0);

    /**
     * Enable/disable Bloom filter for rescans
     */
    void setBloomFilter(bool enable);

    /**
     * Get last scan statistics
     */
    /**
     * lastScanStats - Get statistics from the most recent scan
     * @return ScanStats reference
     */
    const ScanStats& lastScanStats() const { return lastStats_; }

    /* Result set management */

    /**
     * Create persistent result set from results
     * Allows efficient rescanning without re-searching entire memory
     */
    ResultSet createResultSet(const std::vector<ScanResult>& results);

    /**
     * Free a result set
     */
    void freeResultSet(const ResultSet& resultSet);

    /**
     * Get information about a result set
     */
    std::optional<snake_scan_result_set_info> getResultSetInfo(const ResultSet& resultSet);

private:
    Driver& driver_;

    // Scan parameters
    uint64_t startAddress_ = 0;
    uint64_t endAddress_ = 0;
    uint32_t maxResults_ = 0;
    bool parallel_ = true;
    bool useBloom_ = true;
    uint32_t numThreads_ = 0;

    // Last scan statistics
    ScanStats lastStats_;

    // Last result set (from most recent scan)
    ResultSet lastResultSet_;

    // Internal methods
    /**
     * executeScan - Internal scan execution helper
     * @params: Fully populated scan parameters
     * @return Vector of scan results
     */
    std::vector<ScanResult> executeScan(const snake_scan_params& params);
    /**
     * makeParams - Build base scan parameters for a given scan type
     * @type: Scan type
     * @valueType: Value type
     * @return Initialized parameter struct
     */
    snake_scan_params makeParams(ScanType type, ValueType valueType) const;
};

/* ============================================================================
 * Global Functions
 * ============================================================================ */

/**
 * getBackendInfo - Query active backend information
 * @driver: Driver instance
 * @return BackendInfo
 */
BackendInfo getBackendInfo(Driver& driver);

/**
 * setBackend - Select backend type
 * @driver: Driver instance
 * @type: Backend type
 * @return true on success
 */
bool setBackend(Driver& driver, BackendType type);

/**
 * getPerformanceStats - Query performance statistics
 * @driver: Driver instance
 * @return PerformanceStats
 */
PerformanceStats getPerformanceStats(Driver& driver);

/**
 * resetPerformanceStats - Reset performance counters
 * @driver: Driver instance
 */
void resetPerformanceStats(Driver& driver);

/**
 * getScanOptions - Query global scan defaults
 * @driver: Driver instance
 * @return ScanOptions
 */
ScanOptions getScanOptions(Driver& driver);

/**
 * setScanOptions - Update global scan defaults
 * @driver: Driver instance
 * @options: Options to apply
 */
void setScanOptions(Driver& driver, const ScanOptions& options);

/* ============================================================================
 * Template Implementations
 * ============================================================================ */

/**
 * Scanner::exactValue - Template implementation for exact value scans
 * @value: Value to search for
 * @aligned: Only scan aligned addresses
 * @writableOnly: Only scan writable memory
 * @return Vector of results
 */
template<typename T>
std::vector<ScanResult> Scanner::exactValue(T value, bool aligned, bool writableOnly) {
    snake_scan_params params = makeParams(ScanType::ExactValue,
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(value);
    params.aligned = aligned ? 1 : 0;
    params.writable_only = writableOnly ? 1 : 0;

    return executeScan(params);
}

/**
 * Scanner::rangeValue - Template implementation for range scans
 * @min: Minimum value (inclusive)
 * @max: Maximum value (inclusive)
 * @aligned: Only scan aligned addresses
 * @return Vector of results
 */
template<typename T>
std::vector<ScanResult> Scanner::rangeValue(T min, T max, bool aligned) {
    snake_scan_params params = makeParams(ScanType::Range,
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(min);
    params.search_value_2 = static_cast<uint64_t>(max);
    params.aligned = aligned ? 1 : 0;

    return executeScan(params);
}

/**
 * Scanner::exactValueRescan - Template implementation for exact rescans
 * @previousResults: Result set from previous scan
 * @value: Value to search for
 * @return Vector of results
 */
template<typename T>
std::vector<ScanResult> Scanner::exactValueRescan(const ResultSet& previousResults, T value) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(ScanType::ExactValue,
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(value);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::valueBetween - Template implementation for range rescans
 * @previousResults: Result set from previous scan
 * @min: Minimum value (inclusive)
 * @max: Maximum value (inclusive)
 * @return Vector of results
 */
template<typename T>
std::vector<ScanResult> Scanner::valueBetween(const ResultSet& previousResults, T min, T max) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(ScanType::Range,
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(min);
    params.search_value_2 = static_cast<uint64_t>(max);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::increasedBy - Template implementation for increased-by rescans
 * @previousResults: Result set from previous scan
 * @delta: Increase amount
 * @return Vector of results
 */
template<typename T>
std::vector<ScanResult> Scanner::increasedBy(const ResultSet& previousResults, T delta) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(static_cast<ScanType>(SCAN_TYPE_INCREASED_BY),
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(delta);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::decreasedBy - Template implementation for decreased-by rescans
 * @previousResults: Result set from previous scan
 * @delta: Decrease amount
 * @return Vector of results
 */
template<typename T>
std::vector<ScanResult> Scanner::decreasedBy(const ResultSet& previousResults, T delta) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(static_cast<ScanType>(SCAN_TYPE_DECREASED_BY),
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(delta);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

} // namespace snake

#endif // _LIBSNAKEDRV_SCANNER_HPP_
