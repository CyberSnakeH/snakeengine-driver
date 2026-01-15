#ifndef SNAKEDRV_ELF_HPP
#define SNAKEDRV_ELF_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <elf.h>

namespace snakedrv {

struct ElfSegment {
    uint64_t virtual_address;
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t memory_size;
    uint32_t flags;
    std::vector<uint8_t> data;
};

struct ElfImage {
    uint64_t entry_point;
    uint64_t base_address;
    uint64_t total_size;
    std::vector<ElfSegment> segments;
    std::vector<uint8_t> raw_image; // The mapped image in local memory
    
    // Symbols needed for resolution
    struct ImportInfo {
        std::string name;
        uint64_t offset;  // Offset in the GOT/Relocation table
        uint32_t type;    // Relocation type
    };
    std::vector<ImportInfo> pending_imports;
    
    // Internal relocations (GOT entries pointing to internal symbols)
    // These just need "Base Address" added to them.
    std::vector<uint64_t> internal_relocs;
};

// Interface for reading remote memory (abstracted for optimization)
class RemoteReader {
public:
    virtual bool read(uint64_t address, void* buffer, size_t size) = 0;
    virtual uint64_t get_module_base(const std::string& module_name) = 0;
    virtual ~RemoteReader() = default;
};

class ElfParser {
public:
    explicit ElfParser(const std::string& path);
    ~ElfParser();

    bool parse();
    const ElfImage& get_image() const { return image; }
    
    // Perform relative relocations (base address fixups)
    bool relocate_base(uint64_t target_base);
    
    // Resolve external imports using a remote process reader
    bool resolve_imports(RemoteReader& reader);
    
    // Find offset of an exported symbol in the local ELF image
    uint64_t get_symbol_offset(const std::string& name);

private:
    std::string file_path;
    ElfImage image;
    std::vector<uint8_t> file_data;
    
    // Internal ELF pointers
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    
    bool load_file();
    void process_segments();
    // Collects all relocations that need external symbols
    void collect_imports(); 
};

} // namespace snakedrv

#endif // SNAKEDRV_ELF_HPP
