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
 * Scan type enumeration
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
 * Value type for scanning
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
 * Backend type
 */
enum class BackendType {
    Auto    = BACKEND_AUTO,
    Process = BACKEND_PROCESS,
};

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Single scan result
 */
struct ScanResult {
    uint64_t address;
    uint64_t value;
    uint32_t size;
    uint32_t regionIndex;

    // Helper to read value as specific type
    template<typename T>
    T as() const {
        static_assert(sizeof(T) <= sizeof(value), "Type too large");
        return static_cast<T>(value);
    }
};

/**
 * Scan statistics
 */
struct ScanStats {
    uint32_t totalMatches;    // Total matches found
    uint32_t returnedResults; // Results returned (may be < total)
    uint64_t bytesScanned;    // Bytes scanned
    uint64_t timeUs;          // Scan time in microseconds

    // Computed values
    double throughputMBps() const {
        if (timeUs == 0) return 0.0;
        return (bytesScanned / 1024.0 / 1024.0) / (timeUs / 1000000.0);
    }

    double matchRate() const {
        if (timeUs == 0) return 0.0;
        return totalMatches / (timeUs / 1000000.0);
    }
};

/**
 * Backend information
 */
struct BackendInfo {
    BackendType type;
    std::string name;
    bool supportsHugePages;
    bool supportsParallel;
    uint32_t pageSize;
};

/**
 * Performance statistics
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

    // Helper methods
    double avgThroughput() const { return static_cast<double>(throughputMBps); }
    double cacheEfficiency() const { return cacheHitRate / 100.0; }
};

/**
 * Global scan options
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
 * Handle to a result set (for rescans)
 */
class ResultSet {
public:
    ResultSet() = default;
    ResultSet(uint32_t id, uint32_t count) : id_(id), count_(count) {}

    uint32_t id() const { return id_; }
    uint32_t count() const { return count_; }
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
 * Memory scanner interface
 *
 * Provides CheatEngine-like memory scanning capabilities.
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
    explicit Scanner(Driver& driver);
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
    std::vector<ScanResult> executeScan(const snake_scan_params& params);
    snake_scan_params makeParams(ScanType type, ValueType valueType) const;
};

/* ============================================================================
 * Global Functions
 * ============================================================================ */

/**
 * Get current backend information
 */
BackendInfo getBackendInfo(Driver& driver);

/**
 * Set active backend
 */
bool setBackend(Driver& driver, BackendType type);

/**
 * Get performance statistics
 */
PerformanceStats getPerformanceStats(Driver& driver);

/**
 * Reset performance statistics
 */
void resetPerformanceStats(Driver& driver);

/**
 * Get global scan options
 */
ScanOptions getScanOptions(Driver& driver);

/**
 * Set global scan options
 */
void setScanOptions(Driver& driver, const ScanOptions& options);

/* ============================================================================
 * Template Implementations
 * ============================================================================ */

template<typename T>
std::vector<ScanResult> Scanner::exactValue(T value, bool aligned, bool writableOnly) {
    snake_scan_params params = makeParams(ScanType::ExactValue,
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(value);
    params.aligned = aligned ? 1 : 0;
    params.writable_only = writableOnly ? 1 : 0;

    return executeScan(params);
}

template<typename T>
std::vector<ScanResult> Scanner::rangeValue(T min, T max, bool aligned) {
    snake_scan_params params = makeParams(ScanType::Range,
                                         static_cast<ValueType>(sizeof(T)));
    params.search_value = static_cast<uint64_t>(min);
    params.search_value_2 = static_cast<uint64_t>(max);
    params.aligned = aligned ? 1 : 0;

    return executeScan(params);
}

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
