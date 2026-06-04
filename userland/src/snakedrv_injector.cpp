/*
 * SnakeEngine Userland Library - Manual Mapping Injector (Optimized)
 * 
 * "The only way to go fast is to go well."
 * 
 * Implements full ELF loading with external symbol resolution.
 * Uses aggressive caching of remote export tables to minimize IOCTL overhead.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <map>
#include <algorithm>
#include <limits>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#include "../include/snakedrv.h"
#include "../include/snakedrv_elf.hpp"

// Logging macros
#define LOG_INFO(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__)
#define LOG_DBG(fmt, ...) // fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

namespace snakedrv {

static bool checked_add_u64(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

static bool range_fits(size_t container_size, uint64_t offset, uint64_t size) {
    uint64_t end;
    return checked_add_u64(offset, size, end) && end <= container_size;
}

static uint64_t image_base_vaddr(const ElfImage& image) {
    uint64_t base = std::numeric_limits<uint64_t>::max();
    for (const auto& seg : image.segments) {
        if (seg.virtual_address < base) base = seg.virtual_address;
    }
    return base == std::numeric_limits<uint64_t>::max() ? 0 : base;
}

static uint8_t* image_vaddr_ptr(ElfImage& image, uint64_t vaddr, size_t size) {
    uint64_t base = image_base_vaddr(image);
    uint64_t end;
    if (!checked_add_u64(vaddr, size, end)) return nullptr;

    for (const auto& seg : image.segments) {
        uint64_t seg_end;
        if (!checked_add_u64(seg.virtual_address, seg.memory_size, seg_end))
            continue;
        if (vaddr < seg.virtual_address || end > seg_end)
            continue;

        uint64_t offset = vaddr - base;
        if (!range_fits(image.raw_image.size(), offset, size))
            return nullptr;
        return image.raw_image.data() + offset;
    }
    return nullptr;
}

/*
 * Remote Process Reader Implementation
 * Handles communication with the driver and caching of remote module info.
 */
/**
 * class DriverRemoteReader - RemoteReader implementation backed by driver IOCTLs
 */
class DriverRemoteReader : public RemoteReader {
public:
    /**
     * DriverRemoteReader - Attach and prepare module cache
     * @fd: Driver file descriptor
     * @pid: Target process ID
     */
    DriverRemoteReader(int fd, pid_t pid) : driver_fd(fd), target_pid(pid) {
        // Must attach to process to perform read operations
        struct snake_debug_attach attach{};
        attach.pid = pid;
        attach.flags = 0; // No suspend needed
        attach.result = 0;
        
        if (ioctl(driver_fd, SNAKE_IOCTL_DEBUG_ATTACH, &attach) < 0) {
            // Ignore EBUSY if already attached
            if (errno != EBUSY) {
                LOG_ERR("Failed to attach to process %d: %s", pid, strerror(errno));
            }
        }
        
        refresh_module_list();
    }

    /**
     * read - Read remote memory in driver-sized chunks
     * @address: Remote address
     * @buffer: Local buffer
     * @size: Number of bytes to read
     * @return true on success
     */
    bool read(uint64_t address, void* buffer, size_t size) override {
        const size_t MAX_CHUNK = 1024 * 1024; // 1MB limit in driver
        uint8_t* ptr = (uint8_t*)buffer;
        size_t remaining = size;
        uint64_t current_addr = address;

        while (remaining > 0) {
            size_t chunk = (remaining > MAX_CHUNK) ? MAX_CHUNK : remaining;
            
            struct snake_memory_op op{};
            op.pid = target_pid;
            op.address = current_addr;
            op.size = chunk;
            op.user_buffer = (uint64_t)ptr;
            op.result = 0;
            op.flags = 0;
            
            if (ioctl(driver_fd, SNAKE_IOCTL_READ_MEMORY, &op) < 0) {
                LOG_ERR("Read IOCTL failed at %lx size %zu: %s", current_addr, chunk, strerror(errno));
                return false;
            }
            
            if (op.result != (int32_t)chunk) {
                 LOG_ERR("Partial read at %lx: expected %zu, got %d", current_addr, chunk, op.result);
                 return false;
            }
            
            ptr += chunk;
            current_addr += chunk;
            remaining -= chunk;
        }
        return true;
    }

    /**
     * get_module_base - Resolve a module base by name substring
     * @module_name: Module name substring to match
     * @return Base address or 0 if not found
     */
    uint64_t get_module_base(const std::string& module_name) override {
        // Simple heuristic: name contains the requested string
        for (const auto& mod : modules) {
            if (mod.path.find(module_name) != std::string::npos) {
                return mod.base;
            }
        }
        return 0;
    }

    /**
     * resolve_symbol_in_remote_modules - Resolve a symbol across loaded modules
     *
     * This uses a cached export table per module to avoid repeated IOCTL reads.
     *
     * @symbol_name: Symbol to resolve
     * @return Remote address or 0 if not found
     */
    uint64_t resolve_symbol_in_remote_modules(const std::string& symbol_name) {
        // Common libraries to search in order
        // Added versioned names which are common on Linux (libc.so.6, etc)
        static const std::vector<std::string> search_order = {
            "libc.so.6", "libc.so", 
            "libm.so.6", "libm.so", 
            "libdl.so.2", "libdl.so", 
            "libpthread.so.0", "libpthread.so", 
            "libstdc++.so.6", "libstdc++.so"
        };

        for (const auto& lib_name : search_order) {
            uint64_t base = get_module_base(lib_name);
            if (base == 0) continue;

            // Check cache
            if (export_cache.find(base) == export_cache.end()) {
                cache_exports(base, lib_name);
            }

            const auto& exports = export_cache[base];
            auto it = exports.find(symbol_name);
            if (it != exports.end()) {
                return base + it->second;
            }
        }

        // Fallback: Search in ALL loaded modules (Automated Discovery)
        // This handles dependencies we didn't explicitly list.
        for (const auto& mod : modules) {
             // Skip if already checked (heuristic check)
             bool checked = false;
             for(const auto& common : search_order) {
                 if (mod.path.find(common) != std::string::npos) { checked = true; break; }
             }
             if (checked) continue;

             uint64_t base = mod.base;
             if (export_cache.find(base) == export_cache.end()) {
                 // Don't cache everything to save RAM/Time, only if needed?
                 // Ideally we scan one by one.
                 // Filter out obviously useless mappings (not .so)
                 if (mod.path.find(".so") == std::string::npos) continue;
                 
                 cache_exports(base, mod.path);
             }

             const auto& exports = export_cache[base];
             auto it = exports.find(symbol_name);
             if (it != exports.end()) {
                 LOG_INFO("Found symbol '%s' in %s (Auto-detected)", symbol_name.c_str(), mod.path.c_str());
                 return base + it->second;
             }
        }

        return 0;
    }

private:
    int driver_fd;
    pid_t target_pid;

    /**
     * struct ModuleInfo - Cached remote module metadata
     * @base: Base address
     * @path: Filesystem path
     */
    struct ModuleInfo {
        uint64_t base;
        std::string path;
    };
    std::vector<ModuleInfo> modules;
    
    // Cache: Module Base -> { Symbol Name -> Offset }
    std::map<uint64_t, std::map<std::string, uint64_t>> export_cache;

    /**
     * refresh_module_list - Parse /proc/<pid>/maps and cache module bases
     */
    void refresh_module_list() {
        modules.clear();
        std::string maps_path = "/proc/" + std::to_string(target_pid) + "/maps";
        std::ifstream maps(maps_path);
        std::string line;

        while (std::getline(maps, line)) {
            uint64_t start, end, offset;
            char perms[5] = {0};
            char path_buf[1024] = {0};
            
            // Robust parsing using sscanf
            // Format: 7ff...-7ff... r-xp 00000000 00:00 0  /path/to/file
            // Note: device is major:minor, inode is long long. We skip dev/inode details.
            if (sscanf(line.c_str(), "%lx-%lx %4s %lx %*s %*s %1023s", &start, &end, perms, &offset, path_buf) == 5) {
                // We want the BASE address (offset 0)
                if (offset != 0) continue;
                
                // Optional: Filter out non-files (like [heap], [stack]) if they don't look like paths
                if (path_buf[0] != '/') continue;
                
                std::string path = path_buf;
                
                // Check duplicate
                bool found = false;
                for(const auto& m : modules) if(m.path == path) found = true;
                
                if (!found) {
                    modules.push_back({start, path});
                    LOG_INFO("Found module: %s at %lx (perms: %s)", path.c_str(), start, perms);
                }
            }
        }
        
        if (modules.empty()) {
            LOG_ERR("No modules found! Check /proc/%d/maps permissions or parsing.", target_pid);
        }
    }

    /**
     * cache_exports - Cache export symbols for a module base
     * @base: Module base address
     * @name: Module path or name for logging
     */
    void cache_exports(uint64_t base, const std::string& name) {
        // 1. Read ELF Header
        Elf64_Ehdr ehdr;
        if (!read(base, &ehdr, sizeof(ehdr))) {
            LOG_ERR("Failed to read ELF header at %lx for %s", base, name.c_str());
            return;
        }

        // DEBUG: Hex dump the magic we just read
        if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
            LOG_ERR("Invalid ELF Magic at %lx for %s. Read: %02x %02x %02x %02x", 
                    base, name.c_str(), 
                    ehdr.e_ident[0], ehdr.e_ident[1], ehdr.e_ident[2], ehdr.e_ident[3]);
            return;
        }
        
        // Log success for magic check
        LOG_INFO("DEBUG: Valid ELF Header found for %s at %lx", name.c_str(), base);

        // 2. Read Program Headers to find DYNAMIC segment
        std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
        if (!read(base + ehdr.e_phoff, phdrs.data(), sizeof(Elf64_Phdr) * ehdr.e_phnum)) {
             LOG_ERR("Failed to read PHDRs at %lx", base + ehdr.e_phoff);
             return;
        }

        uint64_t dyn_vaddr = 0;
        uint64_t dyn_size = 0;

        for (const auto& ph : phdrs) {
            if (ph.p_type == PT_DYNAMIC) {
                dyn_vaddr = ph.p_vaddr;
                dyn_size = ph.p_memsz;
                break;
            }
        }

        if (dyn_vaddr == 0) return;

        // 3. Read Dynamic Segment
        // Adjust vaddr if not pre-linked (for shared objects, vaddr is offset from base)
        // Usually dyn_vaddr is an offset for .so files.
        uint64_t dyn_addr = base + dyn_vaddr;
        std::vector<Elf64_Dyn> dyns(dyn_size / sizeof(Elf64_Dyn));
        if (!read(dyn_addr, dyns.data(), dyn_size)) return;

        uint64_t strtab = 0, symtab = 0, hash = 0;
        size_t strsz = 0;

        for (const auto& d : dyns) {
            switch (d.d_tag) {
                case DT_STRTAB: strtab = d.d_un.d_ptr; break;
                case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
                case DT_STRSZ:  strsz = d.d_un.d_val; break;
                case DT_HASH:   hash = d.d_un.d_ptr; break;
            }
        }

        if (!strtab || !symtab || !strsz) return;
        
        // Adjust pointers if they are offsets (common in PIE/PIC)
        if (strtab < base) strtab += base;
        if (symtab < base) symtab += base;
        if (hash && hash < base) hash += base;

        // Dynamic Size Calculation
        size_t sym_data_size = 0;
        size_t str_data_size = strsz;
        size_t num_syms = 0;

        if (hash) {
            uint32_t hash_header[2] = {};
            if (read(hash, hash_header, sizeof(hash_header))) {
                num_syms = hash_header[1];
                sym_data_size = num_syms * sizeof(Elf64_Sym);
            }
        }

        if (sym_data_size == 0 && strtab > symtab) {
            // Common case: symtab is immediately followed by strtab
            sym_data_size = strtab - symtab;
            num_syms = sym_data_size / sizeof(Elf64_Sym);
        }

        if (sym_data_size == 0) {
            // Fallback if layout is weird (e.g. strtab before symtab)
            // Read a reasonable amount, but try not to over-read.
            sym_data_size = 512 * 1024; // 512KB safe bet?
            num_syms = sym_data_size / sizeof(Elf64_Sym);
        }
        
        // Safety cap for fallback
        if (str_data_size > 32 * 1024 * 1024) str_data_size = 32 * 1024 * 1024; // Cap at 32MB
        if (sym_data_size > 32 * 1024 * 1024) sym_data_size = 32 * 1024 * 1024;
        num_syms = std::min(num_syms, sym_data_size / sizeof(Elf64_Sym));

        std::vector<uint8_t> sym_data(sym_data_size);
        std::vector<uint8_t> str_data(str_data_size);
        
        // Read Tables
        // We use a relaxed read for symtab in fallback case might be good, but strict for now
        
        // DEBUG LOGGING
        LOG_INFO("DEBUG: Module %s Base=%lx SymTab=%lx StrTab=%lx StrSz=%lx", 
                 name.c_str(), base, symtab, strtab, strsz);

        if (!read(symtab, sym_data.data(), sym_data_size)) {
            LOG_ERR("Failed to read symbol table at %lx size %zu", symtab, sym_data_size);
            return;
        }
        
        if (!read(strtab, str_data.data(), str_data_size)) {
            LOG_ERR("Failed to read string table at %lx size %zu", strtab, str_data_size);
            return;
        }

        // 5. Parse Symbols locally
        Elf64_Sym* syms = (Elf64_Sym*)sym_data.data();
        
        LOG_INFO("DEBUG: Parsing %zu symbols...", num_syms);

        auto& cache = export_cache[base];
        
        for (size_t i = 0; i < num_syms; i++) {
            if (syms[i].st_name >= str_data_size) continue; // Out of read bounds
            if (memchr(str_data.data() + syms[i].st_name, '\0',
                       str_data_size - syms[i].st_name) == nullptr)
                continue;
            
            // Only care about defined global/weak functions
            unsigned char type = ELF64_ST_TYPE(syms[i].st_info);
            unsigned char bind = ELF64_ST_BIND(syms[i].st_info);
            
            // Accept FUNC, OBJECT, COMMON, and GNU_IFUNC (10)
            bool is_valid_type = (type == STT_FUNC || type == STT_OBJECT || 
                                  type == STT_COMMON || type == 10 /* STT_GNU_IFUNC */);

            if ((bind == STB_GLOBAL || bind == STB_WEAK) && 
                is_valid_type &&
                syms[i].st_value != 0) {
                
                std::string name = (char*)(str_data.data() + syms[i].st_name);
                
                // Handle Symbol Versioning (e.g. stdout@@GLIBC_2.2.5 -> stdout)
                size_t version_pos = name.find('@');
                if (version_pos != std::string::npos) {
                    name = name.substr(0, version_pos);
                }

                cache[name] = syms[i].st_value;
            }
        }
        
        LOG_INFO("Cached %zu exports from %s", cache.size(), name.c_str());
    }
};

/*
 * ElfParser Implementation
 */
/**
 * ElfParser::ElfParser - Construct parser for a local ELF path
 */
ElfParser::ElfParser(const std::string& path) : file_path(path), ehdr(nullptr), phdr(nullptr) {}

/**
 * ElfParser::~ElfParser - Default destructor
 */
ElfParser::~ElfParser() {}

/**
 * ElfParser::load_file - Read file into memory and validate headers
 */
bool ElfParser::load_file() {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    
    std::streamsize size = file.tellg();
    if (size < static_cast<std::streamsize>(sizeof(Elf64_Ehdr)))
        return false;
    file.seekg(0, std::ios::beg);
    
    file_data.resize(size);
    if (!file.read((char*)file_data.data(), size)) return false;
    
    ehdr = (Elf64_Ehdr*)file_data.data();
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) return false;
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) return false;
    if (ehdr->e_machine != EM_X86_64) return false;
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) return false;
    if (!range_fits(file_data.size(), ehdr->e_phoff,
                    static_cast<uint64_t>(ehdr->e_phnum) * sizeof(Elf64_Phdr)))
        return false;
    if (ehdr->e_shnum > 0) {
        if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) return false;
        if (!range_fits(file_data.size(), ehdr->e_shoff,
                        static_cast<uint64_t>(ehdr->e_shnum) * sizeof(Elf64_Shdr)))
            return false;
    }
    
    phdr = (Elf64_Phdr*)(file_data.data() + ehdr->e_phoff);
    return true;
}

/**
 * ElfParser::parse - Parse the ELF and build the local image
 */
bool ElfParser::parse() {
    if (!load_file()) return false;
    
    uint64_t min_vaddr = UINT64_MAX;
    uint64_t max_vaddr = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint64_t seg_end;
            if (phdr[i].p_filesz > phdr[i].p_memsz)
                return false;
            if (!checked_add_u64(phdr[i].p_vaddr, phdr[i].p_memsz, seg_end))
                return false;
            if (!range_fits(file_data.size(), phdr[i].p_offset, phdr[i].p_filesz))
                return false;
            if (phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
            if (seg_end > max_vaddr) max_vaddr = seg_end;
        }
    }
    if (min_vaddr == UINT64_MAX || max_vaddr <= min_vaddr)
        return false;
    
    image.total_size = max_vaddr - min_vaddr;
    if (image.total_size > 512ULL * 1024ULL * 1024ULL)
        return false;
    image.base_address = 0; 
    image.entry_point = ehdr->e_entry;
    image.raw_image.resize(image.total_size, 0);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            ElfSegment seg;
            seg.virtual_address = phdr[i].p_vaddr;
            seg.file_offset = phdr[i].p_offset;
            seg.file_size = phdr[i].p_filesz;
            seg.memory_size = phdr[i].p_memsz;
            seg.flags = phdr[i].p_flags;
            
            if (seg.file_size > 0) {
                uint64_t image_offset = seg.virtual_address - min_vaddr;
                if (!range_fits(image.raw_image.size(), image_offset, seg.file_size))
                    return false;
                memcpy(image.raw_image.data() + image_offset,
                       file_data.data() + seg.file_offset,
                       seg.file_size);
            }
            image.segments.push_back(seg);
        }
    }
    
    collect_imports();
    return true;
}

/**
 * ElfParser::collect_imports - Collect external relocations
 */
void ElfParser::collect_imports() {
    Elf64_Dyn* dyn = nullptr;
    size_t dyn_count = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            if (phdr[i].p_filesz % sizeof(Elf64_Dyn) != 0 ||
                !range_fits(file_data.size(), phdr[i].p_offset, phdr[i].p_filesz)) {
                LOG_ERR("Invalid PT_DYNAMIC bounds");
                return;
            }
            dyn = (Elf64_Dyn*)(file_data.data() + phdr[i].p_offset);
            dyn_count = phdr[i].p_filesz / sizeof(Elf64_Dyn);
            break;
        }
    }
    if (!dyn) return;

    uint64_t rela_offset = 0;
    uint64_t rela_sz = 0;
    uint64_t rela_ent = 0;
    uint64_t jmprel_offset = 0;
    uint64_t jmprel_sz = 0;
    uint64_t symtab_offset = 0;
    uint64_t strtab_offset = 0;
    uint64_t strtab_size = 0;
    uint64_t hash_offset = 0;

    for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
            case DT_RELA: rela_offset = dyn[i].d_un.d_ptr; break;
            case DT_RELASZ: rela_sz = dyn[i].d_un.d_val; break;
            case DT_RELAENT: rela_ent = dyn[i].d_un.d_val; break;
            case DT_JMPREL: jmprel_offset = dyn[i].d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprel_sz = dyn[i].d_un.d_val; break;
            case DT_SYMTAB: symtab_offset = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB: strtab_offset = dyn[i].d_un.d_ptr; break;
            case DT_STRSZ: strtab_size = dyn[i].d_un.d_val; break;
            case DT_HASH: hash_offset = dyn[i].d_un.d_ptr; break;
        }
    }

    size_t sym_count = 0;
    if (ehdr->e_shnum > 0) {
        const Elf64_Shdr* shdr =
            (const Elf64_Shdr*)(file_data.data() + ehdr->e_shoff);
        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if ((shdr[i].sh_type == SHT_DYNSYM || shdr[i].sh_type == SHT_SYMTAB) &&
                shdr[i].sh_addr == symtab_offset &&
                shdr[i].sh_entsize == sizeof(Elf64_Sym)) {
                sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);
                if (shdr[i].sh_link < ehdr->e_shnum && strtab_size == 0)
                    strtab_size = shdr[shdr[i].sh_link].sh_size;
                break;
            }
        }
    }

    if (sym_count == 0 && hash_offset) {
        uint32_t* hash = (uint32_t*)image_vaddr_ptr(image, hash_offset,
                                                    2 * sizeof(uint32_t));
        if (hash)
            sym_count = hash[1];
    }

    if (!symtab_offset || !strtab_offset || !strtab_size || !sym_count) {
        LOG_ERR("ELF dynamic symbol metadata is incomplete");
        return;
    }
    if (sym_count > image.raw_image.size() / sizeof(Elf64_Sym)) {
        LOG_ERR("ELF dynamic symbol count is out of bounds");
        return;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)image_vaddr_ptr(
        image, symtab_offset, sym_count * sizeof(Elf64_Sym));
    char* strtab = (char*)image_vaddr_ptr(image, strtab_offset, strtab_size);
    
    if (!symtab || !strtab) {
        LOG_ERR("Dynamic symbol/string table is out of mapped image bounds");
        return;
    }

    auto symbol_name = [&](uint32_t sym_idx) -> const char* {
        if (sym_idx >= sym_count || symtab[sym_idx].st_name >= strtab_size)
            return nullptr;
        char* name = strtab + symtab[sym_idx].st_name;
        size_t remaining = strtab_size - symtab[sym_idx].st_name;
        return memchr(name, '\0', remaining) ? name : nullptr;
    };

    auto collect_rela = [&](uint64_t rela_vaddr, uint64_t rela_size,
                            uint64_t rela_entry_size) {
        if (!rela_vaddr || !rela_size) return;
        if (rela_entry_size == 0) rela_entry_size = sizeof(Elf64_Rela);
        if (rela_entry_size != sizeof(Elf64_Rela) ||
            rela_size % sizeof(Elf64_Rela) != 0) {
            LOG_ERR("Unsupported RELA entry size");
            return;
        }

        size_t count = rela_size / sizeof(Elf64_Rela);
        Elf64_Rela* rela = (Elf64_Rela*)image_vaddr_ptr(image, rela_vaddr,
                                                        rela_size);
        if (!rela) {
            LOG_ERR("Relocation table out of mapped image bounds");
            return;
        }

        for (size_t i = 0; i < count; i++) {
            uint32_t type = ELF64_R_TYPE(rela[i].r_info);
            uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);

            if (type != R_X86_64_GLOB_DAT && type != R_X86_64_JUMP_SLOT)
                continue;
            if (sym_idx == 0 || sym_idx >= sym_count)
                continue;

            uint64_t* patch_loc = (uint64_t*)image_vaddr_ptr(
                image, rela[i].r_offset, sizeof(uint64_t));
            if (!patch_loc) {
                LOG_ERR("Relocation target 0x%lx out of mapped image bounds",
                        rela[i].r_offset);
                continue;
            }

            if (symtab[sym_idx].st_shndx != SHN_UNDEF) {
                image.internal_relocs.push_back(rela[i].r_offset);
                *patch_loc = symtab[sym_idx].st_value;
            } else {
                const char* name = symbol_name(sym_idx);
                if (!name || name[0] == '\0') {
                    LOG_ERR("Invalid external symbol name at relocation %zu", i);
                    continue;
                }
                image.pending_imports.push_back({name, rela[i].r_offset, type});
            }
        }
    };

    collect_rela(rela_offset, rela_sz, rela_ent);

    /* Collect .init_array entries from DT_INIT_ARRAY / DT_INIT_ARRAYSZ */
    {
        uint64_t init_arr_addr = 0, init_arr_sz = 0;
        for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
            if (dyn[i].d_tag == DT_INIT_ARRAY)
                init_arr_addr = dyn[i].d_un.d_ptr;
            if (dyn[i].d_tag == DT_INIT_ARRAYSZ)
                init_arr_sz = dyn[i].d_un.d_val;
        }
        if (init_arr_addr && init_arr_sz &&
            init_arr_sz % sizeof(uint64_t) == 0) {
            uint64_t *arr = (uint64_t *)image_vaddr_ptr(image, init_arr_addr,
                                                        init_arr_sz);
            size_t count = init_arr_sz / sizeof(uint64_t);
            if (arr) {
                for (size_t i = 0; i < count; i++) {
                    if (arr[i] != 0)
                        image.init_array.push_back(arr[i]);
                }
                LOG_DBG("Found %zu .init_array entries", image.init_array.size());
            }
        }
    }

    collect_rela(jmprel_offset, jmprel_sz, sizeof(Elf64_Rela));
}

/**
 * ElfParser::relocate_base - Apply base relocations
 */
bool ElfParser::relocate_base(uint64_t target_base) {
    // Find DYNAMIC segment
    Elf64_Dyn* dyn = nullptr;
    size_t dyn_count = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            if (phdr[i].p_filesz % sizeof(Elf64_Dyn) != 0 ||
                !range_fits(file_data.size(), phdr[i].p_offset, phdr[i].p_filesz))
                return false;
            dyn = (Elf64_Dyn*)(file_data.data() + phdr[i].p_offset);
            dyn_count = phdr[i].p_filesz / sizeof(Elf64_Dyn);
            break;
        }
    }
    
    if (!dyn) return false;

    uint64_t rela_offset = 0;
    uint64_t rela_sz = 0;
    uint64_t rela_ent = 0;

    for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
            case DT_RELA: rela_offset = dyn[i].d_un.d_ptr; break;
            case DT_RELASZ: rela_sz = dyn[i].d_un.d_val; break;
            case DT_RELAENT: rela_ent = dyn[i].d_un.d_val; break;
        }
    }

    if (rela_offset == 0) return true; // No relocations needed
    if (rela_ent == 0) rela_ent = sizeof(Elf64_Rela);
    if (rela_ent != sizeof(Elf64_Rela) ||
        rela_sz % sizeof(Elf64_Rela) != 0)
        return false;

    Elf64_Rela* rela = (Elf64_Rela*)image_vaddr_ptr(image, rela_offset, rela_sz);
    if (!rela) {
        LOG_DBG("Could not map relocation table");
        return false;
    }

    size_t count = rela_sz / sizeof(Elf64_Rela);
    int rel_count = 0;

    for (size_t i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        uint64_t *target = (uint64_t *)image_vaddr_ptr(image, rela[i].r_offset,
                                                       sizeof(uint64_t));

        if (!target)
            continue;

        switch (type) {
        case R_X86_64_RELATIVE:
            /* Base address slide: S + A where S = target_base */
            *target = target_base + rela[i].r_addend;
            rel_count++;
            break;

        case R_X86_64_64: {
            /*
             * Absolute 64-bit: S + A where S = symbol value.
             * The GOT entry was already patched by resolve_imports
             * with the remote symbol address.  We just add the
             * addend (usually 0).
             */
            *target += rela[i].r_addend;
            rel_count++;
            break;
        }

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            /*
             * These are handled in resolve_imports() which patches
             * the GOT/PLT entry directly.  After resolve_imports,
             * the entry already contains the resolved remote address.
             * We still need to add target_base for internal symbols
             * (done via internal_relocs below).
             */
            break;

        default:
            break;
        }
    }
    
    // Also handle internal GOT entries (discovered during import collection)
    for (uint64_t offset : image.internal_relocs) {
        uint64_t* target = (uint64_t*)image_vaddr_ptr(image, offset,
                                                      sizeof(uint64_t));
        if (target) {
            // The value at *target is already the internal offset (st_value)
            // We just add the base.
            *target += target_base;
            rel_count++;
        }
    }
    
    LOG_INFO("Applied %d relocations (Base: 0x%lx)", rel_count, target_base);
    return true; 
}

/**
 * ElfParser::resolve_imports - Resolve external imports using remote reader
 */
bool ElfParser::resolve_imports(RemoteReader& reader) {
    DriverRemoteReader* driver_reader = dynamic_cast<DriverRemoteReader*>(&reader);
    if (!driver_reader) return false;

    int resolved_count = 0;
    
    LOG_INFO("Resolving %zu imports...", image.pending_imports.size());

    for (const auto& imp : image.pending_imports) {
        // Find symbol in remote process
        uint64_t remote_addr = driver_reader->resolve_symbol_in_remote_modules(imp.name);
        
        if (remote_addr == 0) {
            LOG_ERR("FATAL: unresolved symbol: %s (GOT entry will be NULL → crash)",
                    imp.name.c_str());
            return false;
        }
        
        uint64_t* patch_loc = (uint64_t*)image_vaddr_ptr(
            image, imp.offset, sizeof(uint64_t));
        if (patch_loc) {
            *patch_loc = remote_addr;
            resolved_count++;
        } else {
            LOG_ERR("Failed to patch import at offset %lx (out of bounds)", imp.offset);
            return false;
        }
    }
    
    LOG_INFO("Resolved %d/%zu symbols", resolved_count, image.pending_imports.size());
    return true;
}

/**
 * ElfParser::get_symbol_offset - Lookup a symbol offset in the local image
 */
uint64_t ElfParser::get_symbol_offset(const std::string& name) {
    if (ehdr->e_shnum == 0)
        return 0;

    const Elf64_Shdr* shdr =
        (const Elf64_Shdr*)(file_data.data() + ehdr->e_shoff);

    for (uint16_t s = 0; s < ehdr->e_shnum; s++) {
        if (shdr[s].sh_type != SHT_DYNSYM && shdr[s].sh_type != SHT_SYMTAB)
            continue;
        if (shdr[s].sh_entsize != sizeof(Elf64_Sym) ||
            shdr[s].sh_link >= ehdr->e_shnum ||
            !range_fits(file_data.size(), shdr[s].sh_offset, shdr[s].sh_size))
            continue;

        const Elf64_Shdr& str_sh = shdr[shdr[s].sh_link];
        if (str_sh.sh_type != SHT_STRTAB ||
            !range_fits(file_data.size(), str_sh.sh_offset, str_sh.sh_size))
            continue;

        const Elf64_Sym* symtab =
            (const Elf64_Sym*)(file_data.data() + shdr[s].sh_offset);
        const char* strtab =
            (const char*)(file_data.data() + str_sh.sh_offset);
        size_t sym_count = shdr[s].sh_size / sizeof(Elf64_Sym);
        size_t str_size = str_sh.sh_size;

        for (size_t i = 0; i < sym_count; i++) {
            if (symtab[i].st_name >= str_size)
                continue;
            const char* sym_name = strtab + symtab[i].st_name;
            size_t remaining = str_size - symtab[i].st_name;
            if (!memchr(sym_name, '\0', remaining))
                continue;
            if (name == sym_name)
                return symtab[i].st_value;
        }
    }
    
    return 0;
}

/**
 * class ManualMapper - Orchestrates manual mapping and remote thread start
 */
class ManualMapper {
public:
    /**
     * ManualMapper - Bind to driver FD and target PID
     * @fd: Driver file descriptor
     * @pid: Target process ID
     */
    ManualMapper(int fd, pid_t pid) : driver_fd(fd), target_pid(pid) {}
    
    /**
     * inject - Manual map an ELF shared object into the target process
     * @library_path: Path to the shared object
     * @return true on success
     */
    bool inject(const std::string& library_path) {
        ElfParser parser(library_path);
        if (!parser.parse()) {
            LOG_ERR("Failed to parse ELF");
            return false;
        }
        
        const auto& img = parser.get_image();
        
        /*
         * Step 1: Allocate RWX memory in target (normal VMA path).
         * Visible in /proc/pid/maps until stealth is applied.
         */
        struct snake_inject_alloc alloc{};
        alloc.pid        = target_pid;
        alloc.size       = img.total_size;
        alloc.protection = SNAKE_PROT_READ | SNAKE_PROT_WRITE | SNAKE_PROT_EXEC;

        if (ioctl(driver_fd, SNAKE_IOCTL_INJECT_ALLOC, &alloc) < 0 ||
            alloc.result < 0) {
            LOG_ERR("Allocation failed: %d", alloc.result);
            return false;
        }
        LOG_INFO("Allocated at 0x%lx (%zu bytes)", alloc.address, img.total_size);

        /* Step 2: Resolve imports from target's loaded modules */
        DriverRemoteReader reader(driver_fd, target_pid);
        if (!parser.resolve_imports(reader)) {
            LOG_ERR("Import resolution failed");
            return false;
        }

        /* Step 3: Apply base relocations */
        if (!parser.relocate_base(alloc.address)) {
            LOG_ERR("Failed to apply base relocations");
            return false;
        }

        /* Step 4: Write payload via WRITE_MEMORY (chunked, 1MB max) */
        const uint8_t *src_ptr = img.raw_image.data();
        size_t write_remaining = img.total_size;
        uint64_t write_addr = alloc.address;
        const size_t MAX_WRITE_CHUNK = 1024 * 1024;

        while (write_remaining > 0) {
            size_t chunk = std::min(write_remaining, MAX_WRITE_CHUNK);

            struct snake_memory_op wop{};
            wop.pid         = target_pid;
            wop.address     = write_addr;
            wop.size        = chunk;
            wop.user_buffer = reinterpret_cast<uint64_t>(src_ptr);

            if (ioctl(driver_fd, SNAKE_IOCTL_WRITE_MEMORY, &wop) < 0 ||
                wop.result != static_cast<int32_t>(chunk)) {
                LOG_ERR("Write at 0x%lx size %zu failed: %d (%s)",
                        write_addr, chunk, wop.result, strerror(errno));
                return false;
            }

            src_ptr         += chunk;
            write_addr      += chunk;
            write_remaining -= chunk;
        }

        LOG_INFO("Payload written (%zu bytes)", img.total_size);

        /*
         * Stealth (VMA hide) is intentionally not applied here.
         * Hiding before all pages have faulted in can SIGSEGV the target;
         * a future implementation must make deferred hiding page-fault-safe.
         */

        /* Step 6: Execute ManualMapEntry via thread hijack */
        struct snake_inject_thread thread{};
        thread.pid = target_pid;

        uint64_t manual_entry = parser.get_symbol_offset("ManualMapEntry");
        if (manual_entry != 0) {
            LOG_INFO("Entry: ManualMapEntry at +0x%lx", manual_entry);
            thread.start_address = alloc.address + manual_entry;
        } else {
            LOG_ERR("ManualMapEntry export not found");
            return false;
        }

        if (ioctl(driver_fd, SNAKE_IOCTL_INJECT_THREAD, &thread) < 0) {
            LOG_ERR("Thread creation failed");
            return false;
        }

        return true;
    }

private:
    int driver_fd;
    pid_t target_pid;
};

} // namespace snakedrv

extern "C" {
    /**
     * snake_inject_library - C ABI wrapper for ManualMapper::inject
     * @fd: Driver file descriptor
     * @pid: Target PID
     * @path: Path to the shared object
     * @return 0 on success, -1 on failure
     */
    int snake_inject_library(int fd, int pid, const char* path) {
        snakedrv::ManualMapper mapper(fd, pid);
        return mapper.inject(path) ? 0 : -1;
    }
}
