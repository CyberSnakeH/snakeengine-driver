/*
 * SnakeEngine - Memory Scanner Implementation
 *
 * Copyright (c) 2024 SnakeEngine Project
 * Licensed under GPL v2
 */

#include "libsnakedrv_scanner.hpp"
#include "libsnakedrv.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>
#include <cwctype>
#include <algorithm>
#include <stdexcept>

namespace snake {

/* ============================================================================
 * Scanner Implementation
 * ============================================================================ */

/**
 * Scanner::Scanner - Construct a scanner bound to an attached driver
 */
Scanner::Scanner(Driver& driver) : driver_(driver) {
    if (!driver_.isAttached()) {
        throw NotAttachedException();
    }
}

/**
 * Scanner::~Scanner - Default destructor
 */
Scanner::~Scanner() = default;

/**
 * Scanner::makeParams - Build base scan parameters
 */
snake_scan_params Scanner::makeParams(ScanType type, ValueType valueType) const {
    snake_scan_params params{};
    params.pid = driver_.attachedPid();
    params.scan_type = static_cast<uint32_t>(type);
    params.value_type = static_cast<uint32_t>(valueType);
    params.start_address = startAddress_;
    params.end_address = endAddress_;
    params.max_results = maxResults_;
    params.parallel = parallel_ ? 1 : 0;
    params.use_bloom = useBloom_ ? 1 : 0;
    params.num_threads = numThreads_;
    return params;
}

/**
 * Scanner::executeScan - Execute a scan via IOCTL
 */
std::vector<ScanResult> Scanner::executeScan(const snake_scan_params& params) {
    if (!driver_.isOpen()) {
        throw DriverException("Driver not open");
    }

    // Allocate buffer for results
    constexpr size_t MAX_RESULTS_PER_CALL = 10000;
    std::vector<snake_scan_result> kresults(MAX_RESULTS_PER_CALL);
    std::vector<ScanResult> results;

    snake_scan_execute exec{};
    exec.params = params;
    exec.results = reinterpret_cast<uint64_t>(kresults.data());
    exec.results_capacity = MAX_RESULTS_PER_CALL;

    // Execute scan via IOCTL
    int fd = driver_.getFd();
    if (ioctl(fd, SNAKE_IOCTL_SCAN_EXECUTE, &exec) < 0) {
        throw DriverException("Scan failed", errno);
    }

    if (exec.result != 0) {
        throw DriverException("Scan failed with code: " + std::to_string(exec.result));
    }

    // Update statistics
    lastStats_.totalMatches = exec.total_matches;
    lastStats_.returnedResults = exec.results_count;
    lastStats_.bytesScanned = exec.bytes_scanned;
    lastStats_.timeUs = exec.time_us;

    // Store result set for future rescans
    lastResultSet_ = ResultSet(exec.result_set_id, exec.total_matches);

    // Convert results
    results.reserve(exec.results_count);
    for (uint32_t i = 0; i < exec.results_count; i++) {
        ScanResult r;
        r.address = kresults[i].address;
        r.value = kresults[i].value;
        r.size = kresults[i].size;
        r.regionIndex = kresults[i].region_index;
        results.push_back(r);
    }

    return results;
}

/**
 * Scanner::pattern - Scan for a byte pattern with wildcards
 */
std::vector<ScanResult> Scanner::pattern(const std::vector<int16_t>& pattern) {
    // Convert pattern with wildcards to byte array
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;

    for (int16_t p : pattern) {
        if (p < 0 || p > 255) {
            // Wildcard
            bytes.push_back(0);
            mask.push_back(0);
        } else {
            bytes.push_back(static_cast<uint8_t>(p));
            mask.push_back(0xFF);
        }
    }

    snake_scan_params params = makeParams(ScanType::Pattern, ValueType::Bytes);
    params.pattern = reinterpret_cast<uint64_t>(bytes.data());
    params.pattern_len = bytes.size();

    return executeScan(params);
}

/**
 * Scanner::stringAscii - Scan for an ASCII string
 */
std::vector<ScanResult> Scanner::stringAscii(const std::string& str, bool caseSensitive) {
    std::string searchStr = str;
    if (!caseSensitive) {
        std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);
    }

    snake_scan_params params = makeParams(ScanType::StringAscii, ValueType::Bytes);
    params.pattern = reinterpret_cast<uint64_t>(searchStr.c_str());
    params.pattern_len = searchStr.length();

    return executeScan(params);
}

/**
 * Scanner::stringUnicode - Scan for a UTF-16LE string
 */
std::vector<ScanResult> Scanner::stringUnicode(const std::wstring& str, bool caseSensitive) {
    // Convert wstring to UTF-16LE
    std::vector<uint16_t> utf16;
    for (wchar_t c : str) {
        if (!caseSensitive) {
            c = towlower(c);
        }
        utf16.push_back(static_cast<uint16_t>(c));
    }

    snake_scan_params params = makeParams(ScanType::StringUnicode, ValueType::Bytes);
    params.pattern = reinterpret_cast<uint64_t>(utf16.data());
    params.pattern_len = utf16.size() * 2;

    return executeScan(params);
}

/**
 * Scanner::changedValue - Rescan for changed values
 */
std::vector<ScanResult> Scanner::changedValue(const ResultSet& previousResults) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(ScanType::ChangedValue, ValueType::Int64);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::unchangedValue - Rescan for unchanged values
 */
std::vector<ScanResult> Scanner::unchangedValue(const ResultSet& previousResults) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(ScanType::UnchangedValue, ValueType::Int64);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::increasedValue - Rescan for increased values
 */
std::vector<ScanResult> Scanner::increasedValue(const ResultSet& previousResults) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(ScanType::IncreasedValue, ValueType::Int64);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::decreasedValue - Rescan for decreased values
 */
std::vector<ScanResult> Scanner::decreasedValue(const ResultSet& previousResults) {
    if (!previousResults.isValid()) {
        throw std::invalid_argument("Invalid result set");
    }

    snake_scan_params params = makeParams(ScanType::DecreasedValue, ValueType::Int64);
    params.result_set_id = previousResults.id();

    return executeScan(params);
}

/**
 * Scanner::floatValue - Scan for float values with tolerance
 */
std::vector<ScanResult> Scanner::floatValue(float value, float tolerance) {
    // For float scans, we encode tolerance in search_value_2
    snake_scan_params params = makeParams(ScanType::Float, ValueType::Float);

    // Copy float bits to uint64_t
    uint32_t valueBits;
    memcpy(&valueBits, &value, sizeof(float));
    params.search_value = valueBits;

    uint32_t toleranceBits;
    memcpy(&toleranceBits, &tolerance, sizeof(float));
    params.search_value_2 = toleranceBits;

    return executeScan(params);
}

/**
 * Scanner::doubleValue - Scan for double values with tolerance
 */
std::vector<ScanResult> Scanner::doubleValue(double value, double tolerance) {
    snake_scan_params params = makeParams(ScanType::Float, ValueType::Double);

    // Copy double bits to uint64_t
    memcpy(&params.search_value, &value, sizeof(double));
    memcpy(&params.search_value_2, &tolerance, sizeof(double));

    return executeScan(params);
}

/**
 * Scanner::followPointerChain - Resolve a pointer chain
 */
std::optional<uint64_t> Scanner::followPointerChain(uint64_t baseAddress,
                                                     const std::vector<uint64_t>& offsets) {
    uint64_t current = baseAddress;

    for (size_t i = 0; i < offsets.size(); i++) {
        // Read pointer at current address
        uint64_t pointer = 0;
        size_t read = driver_.readMemory(current, &pointer, sizeof(pointer));
        if (read != sizeof(pointer) || pointer == 0) {
            return std::nullopt;  // Invalid pointer
        }

        // Add offset
        current = pointer + offsets[i];
    }

    return current;
}

/**
 * Scanner::setRange - Set scan address range
 */
void Scanner::setRange(uint64_t start, uint64_t end) {
    startAddress_ = start;
    endAddress_ = end;
}

/**
 * Scanner::resetRange - Reset scan range to default
 */
void Scanner::resetRange() {
    startAddress_ = 0;
    endAddress_ = 0;
}

/**
 * Scanner::setMaxResults - Set maximum results per scan
 */
void Scanner::setMaxResults(uint32_t max) {
    maxResults_ = max;
}

/**
 * Scanner::setParallel - Enable or disable parallel scanning
 */
void Scanner::setParallel(bool enable, uint32_t numThreads) {
    parallel_ = enable;
    numThreads_ = numThreads;
}

/**
 * Scanner::setBloomFilter - Enable or disable Bloom filters
 */
void Scanner::setBloomFilter(bool enable) {
    useBloom_ = enable;
}

/**
 * Scanner::createResultSet - Return handle for the last result set
 */
ResultSet Scanner::createResultSet(const std::vector<ScanResult>& results) {
    // Result set is created automatically during scan and stored in lastResultSet_
    // Return the last result set from the most recent scan
    if (!lastResultSet_.isValid()) {
        throw std::runtime_error("No valid result set available. Perform a scan first.");
    }
    return lastResultSet_;
}

/**
 * Scanner::freeResultSet - Free a stored result set in the kernel
 */
void Scanner::freeResultSet(const ResultSet& resultSet) {
    if (!resultSet.isValid()) {
        return;
    }

    int fd = driver_.getFd();
    uint32_t id = resultSet.id();
    ioctl(fd, SNAKE_IOCTL_SCAN_FREE_RESULTS, &id);
}

/**
 * Scanner::getResultSetInfo - Query metadata for a result set
 */
std::optional<snake_scan_result_set_info> Scanner::getResultSetInfo(const ResultSet& resultSet) {
    if (!resultSet.isValid()) {
        return std::nullopt;
    }

    snake_scan_result_set_info info{};
    info.result_set_id = resultSet.id();

    int fd = driver_.getFd();
    if (ioctl(fd, SNAKE_IOCTL_SCAN_GET_INFO, &info) < 0) {
        return std::nullopt;
    }

    return info;
}

/* ============================================================================
 * Global Functions
 * ============================================================================ */

/**
 * getBackendInfo - Query backend information
 */
BackendInfo getBackendInfo(Driver& driver) {
    if (!driver.isOpen()) {
        throw DriverException("Driver not open");
    }

    snake_backend_info kinfo{};
    int fd = driver.getFd();

    if (ioctl(fd, SNAKE_IOCTL_GET_BACKEND_INFO, &kinfo) < 0) {
        throw DriverException("Failed to get backend info", errno);
    }

    BackendInfo info;
    info.type = static_cast<BackendType>(kinfo.backend_type);
    info.name = kinfo.name;
    info.supportsHugePages = kinfo.supports_huge_pages != 0;
    info.supportsParallel = kinfo.supports_parallel != 0;
    info.pageSize = kinfo.page_size;

    return info;
}

/**
 * setBackend - Select the scanning backend
 */
bool setBackend(Driver& driver, BackendType type) {
    if (!driver.isOpen()) {
        return false;
    }

    int fd = driver.getFd();
    uint32_t backend = static_cast<uint32_t>(type);

    return ioctl(fd, SNAKE_IOCTL_SET_BACKEND, &backend) == 0;
}

/**
 * getPerformanceStats - Query performance statistics
 */
PerformanceStats getPerformanceStats(Driver& driver) {
    if (!driver.isOpen()) {
        throw DriverException("Driver not open");
    }

    snake_perf_stats kstats{};
    int fd = driver.getFd();

    if (ioctl(fd, SNAKE_IOCTL_GET_PERF_STATS, &kstats) < 0) {
        throw DriverException("Failed to get performance stats", errno);
    }

    PerformanceStats stats;
    stats.totalScans = kstats.total_scans;
    stats.totalBytes = kstats.total_bytes;
    stats.totalMatches = kstats.total_matches;
    stats.totalTimeNs = kstats.total_time_ns;
    stats.avgLatencyUs = kstats.avg_latency_us;
    stats.minLatencyUs = kstats.min_latency_us;
    stats.maxLatencyUs = kstats.max_latency_us;
    stats.throughputMBps = kstats.throughput_mbps;
    stats.matchesPerSec = kstats.matches_per_sec;
    stats.cacheHitRate = kstats.cache_hit_rate;
    stats.parallelRatio = kstats.parallel_ratio;
    stats.hugePageScans = kstats.huge_page_scans;
    stats.allocatedBytes = kstats.allocated_bytes;
    stats.peakBytes = kstats.peak_bytes;

    return stats;
}

/**
 * resetPerformanceStats - Reset performance counters
 */
void resetPerformanceStats(Driver& driver) {
    if (!driver.isOpen()) {
        throw DriverException("Driver not open");
    }

    int fd = driver.getFd();
    ioctl(fd, SNAKE_IOCTL_RESET_PERF_STATS);
}

/**
 * getScanOptions - Query global scan options
 */
ScanOptions getScanOptions(Driver& driver) {
    if (!driver.isOpen()) {
        throw DriverException("Driver not open");
    }

    snake_scan_options kopts{};
    int fd = driver.getFd();

    if (ioctl(fd, SNAKE_IOCTL_GET_SCAN_OPTIONS, &kopts) < 0) {
        throw DriverException("Failed to get scan options", errno);
    }

    ScanOptions opts;
    opts.enableParallel = kopts.enable_parallel != 0;
    opts.enableBloom = kopts.enable_bloom != 0;
    opts.enablePrefetch = kopts.enable_prefetch != 0;
    opts.enableHugePages = kopts.enable_huge_pages != 0;
    opts.defaultThreads = kopts.default_threads;
    opts.bloomFpr = kopts.bloom_fpr / 1000.0;

    return opts;
}

/**
 * setScanOptions - Update global scan options
 */
void setScanOptions(Driver& driver, const ScanOptions& options) {
    if (!driver.isOpen()) {
        throw DriverException("Driver not open");
    }

    snake_scan_options kopts{};
    kopts.enable_parallel = options.enableParallel ? 1 : 0;
    kopts.enable_bloom = options.enableBloom ? 1 : 0;
    kopts.enable_prefetch = options.enablePrefetch ? 1 : 0;
    kopts.enable_huge_pages = options.enableHugePages ? 1 : 0;
    kopts.default_threads = options.defaultThreads;
    kopts.bloom_fpr = static_cast<uint32_t>(options.bloomFpr * 1000.0);

    int fd = driver.getFd();

    if (ioctl(fd, SNAKE_IOCTL_SET_SCAN_OPTIONS, &kopts) < 0) {
        throw DriverException("Failed to set scan options", errno);
    }
}

} // namespace snake
