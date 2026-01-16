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
        struct snake_debug_attach attach = {0};
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
            
            struct snake_memory_op op = {0};
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

        uint64_t strtab = 0, symtab = 0, syment = 0;
        size_t strsz = 0;

        for (const auto& d : dyns) {
            switch (d.d_tag) {
                case DT_STRTAB: strtab = d.d_un.d_ptr; break;
                case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
                case DT_STRSZ:  strsz = d.d_un.d_val; break;
                case DT_SYMENT: syment = d.d_un.d_val; break;
            }
        }

        if (!strtab || !symtab) return;
        
        // Adjust pointers if they are offsets (common in PIE/PIC)
        if (strtab < base) strtab += base;
        if (symtab < base) symtab += base;

        // 4. Bulk Read Symbol Table and String Table
        // This is the Optimization Key: Read huge chunks instead of ping-ponging
        
        if (strtab < base) strtab += base;
        if (symtab < base) symtab += base;

        // Dynamic Size Calculation
        size_t sym_data_size = 0;
        size_t str_data_size = strsz;

        if (strtab > symtab) {
            // Common case: symtab is immediately followed by strtab
            sym_data_size = strtab - symtab;
        } else {
            // Fallback if layout is weird (e.g. strtab before symtab)
            // Read a reasonable amount, but try not to over-read.
            sym_data_size = 512 * 1024; // 512KB safe bet?
        }
        
        // Safety cap for fallback
        if (str_data_size > 32 * 1024 * 1024) str_data_size = 32 * 1024 * 1024; // Cap at 32MB
        if (sym_data_size > 32 * 1024 * 1024) sym_data_size = 32 * 1024 * 1024;

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
        size_t num_syms = sym_data_size / sizeof(Elf64_Sym);
        Elf64_Sym* syms = (Elf64_Sym*)sym_data.data();
        
        LOG_INFO("DEBUG: Parsing %zu symbols...", num_syms);

        auto& cache = export_cache[base];
        int debug_count = 0;
        
        for (size_t i = 0; i < num_syms; i++) {
            if (syms[i].st_name >= str_data_size) continue; // Out of read bounds
            
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
    file.seekg(0, std::ios::beg);
    
    file_data.resize(size);
    if (!file.read((char*)file_data.data(), size)) return false;
    
    ehdr = (Elf64_Ehdr*)file_data.data();
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (ehdr->e_machine != EM_X86_64) return false;
    
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
            if (phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
            if (phdr[i].p_vaddr + phdr[i].p_memsz > max_vaddr) 
                max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    
    image.total_size = max_vaddr - min_vaddr;
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
                memcpy(image.raw_image.data() + (seg.virtual_address - min_vaddr),
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
    // Helper to find segment pointer
    auto vaddr_to_ptr = [&](uint64_t vaddr) -> uint8_t* {
        for(const auto& seg : image.segments) {
            if(vaddr >= seg.virtual_address && vaddr < seg.virtual_address + seg.file_size) {
                return image.raw_image.data() + (vaddr - image.segments[0].virtual_address);
            }
        }
        return nullptr;
    };

    Elf64_Dyn* dyn = nullptr;
    uint64_t dyn_size = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(file_data.data() + phdr[i].p_offset);
            dyn_size = phdr[i].p_filesz / sizeof(Elf64_Dyn);
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

    for (size_t i = 0; i < dyn_size; i++) {
        switch (dyn[i].d_tag) {
            case DT_RELA: rela_offset = dyn[i].d_un.d_ptr; break;
            case DT_RELASZ: rela_sz = dyn[i].d_un.d_val; break;
            case DT_RELAENT: rela_ent = dyn[i].d_un.d_val; break;
            case DT_JMPREL: jmprel_offset = dyn[i].d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprel_sz = dyn[i].d_un.d_val; break;
            case DT_SYMTAB: symtab_offset = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB: strtab_offset = dyn[i].d_un.d_ptr; break;
        }
    }

    Elf64_Sym* symtab = (Elf64_Sym*)vaddr_to_ptr(symtab_offset);
    char* strtab = (char*)vaddr_to_ptr(strtab_offset);
    
    if (!symtab || !strtab) {
        // LOG_DBG("Could not map dynamic sections to local image");
        return;
    }

    // Process DT_RELA (Data Relocations)
    if (rela_offset != 0 && rela_sz > 0) {
        Elf64_Rela* rela = (Elf64_Rela*)vaddr_to_ptr(rela_offset);
        if (rela) {
            size_t count = rela_sz / rela_ent;
            for (size_t i = 0; i < count; i++) {
                uint32_t type = ELF64_R_TYPE(rela[i].r_info);
                uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
                
                if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT) {
                    if (sym_idx != 0) {
                        if (symtab[sym_idx].st_shndx != SHN_UNDEF) {
                            // Internal
                            image.internal_relocs.push_back(rela[i].r_offset);
                            uint64_t* patch_loc = (uint64_t*)(image.raw_image.data() + rela[i].r_offset);
                            *patch_loc = symtab[sym_idx].st_value;
                        } else {
                            // External
                            std::string name = strtab + symtab[sym_idx].st_name;
                            image.pending_imports.push_back({name, rela[i].r_offset, type});
                        }
                    }
                }
            }
        }
    }

    // Process DT_JMPREL (PLT Relocations - Functions)
    if (jmprel_offset != 0 && jmprel_sz > 0) {
        Elf64_Rela* rela = (Elf64_Rela*)vaddr_to_ptr(jmprel_offset);
        if (rela) {
            size_t count = jmprel_sz / sizeof(Elf64_Rela); 
            for (size_t i = 0; i < count; i++) {
                uint32_t type = ELF64_R_TYPE(rela[i].r_info);
                uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
                
                if (type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) {
                    if (sym_idx != 0) {
                        if (symtab[sym_idx].st_shndx != SHN_UNDEF) {
                            // Internal
                            image.internal_relocs.push_back(rela[i].r_offset);
                            uint64_t* patch_loc = (uint64_t*)(image.raw_image.data() + rela[i].r_offset);
                            *patch_loc = symtab[sym_idx].st_value;
                        } else {
                            // External
                            std::string name = strtab + symtab[sym_idx].st_name;
                            image.pending_imports.push_back({name, rela[i].r_offset, type});
                        }
                    }
                }
            }
        }
    }
}

/**
 * ElfParser::relocate_base - Apply base relocations
 */
bool ElfParser::relocate_base(uint64_t target_base) {
    // Helper to find segment pointer
    auto vaddr_to_ptr = [&](uint64_t vaddr) -> uint8_t* {
        for(const auto& seg : image.segments) {
            if(vaddr >= seg.virtual_address && vaddr < seg.virtual_address + seg.memory_size) {
                // Check if offset is within file size (data exists)
                if (vaddr < seg.virtual_address + seg.file_size) {
                    return image.raw_image.data() + (vaddr - image.segments[0].virtual_address);
                }
            }
        }
        return nullptr;
    };

    // Find DYNAMIC segment
    Elf64_Dyn* dyn = nullptr;
    uint64_t dyn_size = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(file_data.data() + phdr[i].p_offset);
            dyn_size = phdr[i].p_filesz / sizeof(Elf64_Dyn);
            break;
        }
    }
    
    if (!dyn) return false;

    uint64_t rela_offset = 0;
    uint64_t rela_sz = 0;
    uint64_t rela_ent = 0;

    for (size_t i = 0; i < dyn_size; i++) {
        switch (dyn[i].d_tag) {
            case DT_RELA: rela_offset = dyn[i].d_un.d_ptr; break;
            case DT_RELASZ: rela_sz = dyn[i].d_un.d_val; break;
            case DT_RELAENT: rela_ent = dyn[i].d_un.d_val; break;
        }
    }

    if (rela_offset == 0) return true; // No relocations needed

    Elf64_Rela* rela = (Elf64_Rela*)vaddr_to_ptr(rela_offset);
    if (!rela) {
        LOG_DBG("Could not map relocation table");
        return false;
    }

    size_t count = rela_sz / rela_ent;
    int rel_count = 0;

    for (size_t i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        
        // Handle R_X86_64_RELATIVE (Base Address Slide)
        if (type == R_X86_64_RELATIVE) {
            uint64_t* target = (uint64_t*)vaddr_to_ptr(rela[i].r_offset);
            if (target) {
                *target = target_base + rela[i].r_addend;
                rel_count++;
            }
        }
    }
    
    // Also handle internal GOT entries (discovered during import collection)
    for (uint64_t offset : image.internal_relocs) {
        uint64_t* target = (uint64_t*)vaddr_to_ptr(offset);
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
            LOG_ERR("Failed to resolve symbol: %s", imp.name.c_str());
            continue; // Fail soft?
        }
        
        // Patch the GOT/PLT entry in our LOCAL raw image
        // imp.offset is the VADDR in the image
        // We need to map this VADDR to our local buffer
        auto vaddr_to_ptr = [&](uint64_t vaddr) -> uint8_t* {
            for(const auto& seg : image.segments) {
                if(vaddr >= seg.virtual_address && vaddr < seg.virtual_address + seg.file_size) {
                    return image.raw_image.data() + (vaddr - image.segments[0].virtual_address);
                }
            }
            return nullptr;
        };

        uint64_t* patch_loc = (uint64_t*)vaddr_to_ptr(imp.offset); 
        if (patch_loc) {
            *patch_loc = remote_addr;
            resolved_count++;
        } else {
            LOG_ERR("Failed to patch import at offset %lx (out of bounds)", imp.offset);
        }
    }
    
    LOG_INFO("Resolved %d/%zu symbols", resolved_count, image.pending_imports.size());
    return true;
}

/**
 * ElfParser::get_symbol_offset - Lookup a symbol offset in the local image
 */
uint64_t ElfParser::get_symbol_offset(const std::string& name) {
    auto vaddr_to_ptr = [&](uint64_t vaddr) -> uint8_t* {
        for(const auto& seg : image.segments) {
            if(vaddr >= seg.virtual_address && vaddr < seg.virtual_address + seg.memory_size) {
                if (vaddr < seg.virtual_address + seg.file_size) {
                    return image.raw_image.data() + (vaddr - image.segments[0].virtual_address);
                }
            }
        }
        return nullptr;
    };

    // Helper to find Dynamic Section (repeated logic, should be refactored but safe here)
    Elf64_Dyn* dyn = nullptr;
    uint64_t dyn_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(file_data.data() + phdr[i].p_offset);
            dyn_size = phdr[i].p_filesz / sizeof(Elf64_Dyn);
            break;
        }
    }
    if (!dyn) return 0;

    uint64_t symtab_off = 0, strtab_off = 0;
    
    for (size_t i = 0; i < dyn_size; i++) {
        if (dyn[i].d_tag == DT_SYMTAB) symtab_off = dyn[i].d_un.d_ptr;
        if (dyn[i].d_tag == DT_STRTAB) strtab_off = dyn[i].d_un.d_ptr;
    }
    
    if (!symtab_off || !strtab_off) return 0;
    
    Elf64_Sym* symtab = (Elf64_Sym*)vaddr_to_ptr(symtab_off);
    char* strtab = (char*)vaddr_to_ptr(strtab_off);
    
    if (!symtab || !strtab) return 0;
    
    // We don't know the number of symbols easily without hash table
    // But we can iterate until we hit invalid memory or a reasonable limit
    // Heuristic: iterate 5000 symbols max
    for (int i = 0; i < 5000; i++) {
        // Basic bounds check (unsafe if we are at end of page, but ok for now)
        if (symtab[i].st_name == 0 && i > 0 && symtab[i].st_value == 0) continue; 
        
        const char* sym_name = strtab + symtab[i].st_name;
        if (name == sym_name) {
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
        
        // 1. Allocate
        struct snake_inject_alloc alloc = {0};
        alloc.pid = target_pid;
        alloc.size = img.total_size;
        alloc.protection = SNAKE_PROT_READ | SNAKE_PROT_WRITE | SNAKE_PROT_EXEC; // Stealth applied later
        alloc.address = 0;
        alloc.result = 0;
        
        if (ioctl(driver_fd, SNAKE_IOCTL_INJECT_ALLOC, &alloc) < 0 || alloc.result < 0) {
            LOG_ERR("Kernel allocation failed: %d", alloc.result);
            return false;
        }
        LOG_INFO("Allocated at 0x%lx", alloc.address);
        
        // 2. Resolve Imports (The hard part)
        DriverRemoteReader reader(driver_fd, target_pid);
        parser.resolve_imports(reader);
        
        // 3. Relocate Base (R_X86_64_RELATIVE)
        if (!parser.relocate_base(alloc.address)) {
            LOG_ERR("Failed to apply base relocations");
            return false;
        }
        
        // 4. Write (Chunked to respect driver limit of 1MB)
        uint8_t* src_ptr = (uint8_t*)img.raw_image.data();
        size_t write_remaining = img.total_size;
        uint64_t write_addr = alloc.address;
        const size_t MAX_WRITE_CHUNK = 1024 * 1024;

        while (write_remaining > 0) {
            size_t chunk = (write_remaining > MAX_WRITE_CHUNK) ? MAX_WRITE_CHUNK : write_remaining;
            
            struct snake_memory_op mem_op = {0};
            mem_op.pid = target_pid;
            mem_op.address = write_addr;
            mem_op.size = chunk;
            mem_op.user_buffer = (uint64_t)src_ptr;
            mem_op.result = 0;
            mem_op.flags = 0;
            
            if (ioctl(driver_fd, SNAKE_IOCTL_WRITE_MEMORY, &mem_op) < 0 || mem_op.result != (int32_t)chunk) {
                LOG_ERR("Failed to write payload chunk at %lx size %zu. Ret: %d, Errno: %s", 
                        write_addr, chunk, mem_op.result, strerror(errno));
                return false;
            }
            
            src_ptr += chunk;
            write_addr += chunk;
            write_remaining -= chunk;
        }
        
        LOG_INFO("Payload written successfully (%zu bytes)", img.total_size);
        
        // 4.5 Apply Stealth (Unlink VMA)
        // Now that we have written the data, we can hide the VMA.
        // The pages should remain accessible via TLB/Pagetables for execution?
        // WARNING: If the kernel reclaims these pages or we get a page fault, we crash.
        // But for a loaded library, faults shouldn't happen if everything is resident.
        // We might need to mlock() or similar before hiding.
        // For now, let's just hide.
        struct snake_inject_protect stealth_op = {0};
        stealth_op.pid = target_pid;
        stealth_op.address = alloc.address;
        stealth_op.size = 0;
        stealth_op.protection = 0;
        stealth_op.result = 0;
        
        if (ioctl(driver_fd, SNAKE_IOCTL_INJECT_STEALTH, &stealth_op) < 0) {
            LOG_ERR("Failed to apply stealth mode");
        } else {
            LOG_INFO("Stealth mode activated (VMA unlinked)");
        }
        
        // 5. Execute
        struct snake_inject_thread thread = {0};
        thread.pid = target_pid;
        thread.result = 0;
        thread.start_address = 0; // Will be set below
        thread.argument = 0; // No argument for ManualMapEntry currently
        
        // Try to find Manual Entry Point first
        uint64_t manual_entry = parser.get_symbol_offset("ManualMapEntry");
        if (manual_entry != 0) {
            LOG_INFO("Using manual entry point at offset +0x%lx", manual_entry);
            thread.start_address = alloc.address + manual_entry;
        } else {
            LOG_INFO("Using ELF entry point at offset +0x%lx", img.entry_point);
            thread.start_address = alloc.address + img.entry_point;
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
