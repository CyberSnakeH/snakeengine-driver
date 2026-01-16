#ifndef SNAKEDRV_ELF_HPP
#define SNAKEDRV_ELF_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <elf.h>

namespace snakedrv {

/**
 * struct ElfSegment - In-memory representation of a PT_LOAD segment
 * @virtual_address: Virtual address of the segment in the ELF image
 * @file_offset: File offset where the segment data starts
 * @file_size: Size of the segment data in the file
 * @memory_size: Size of the segment in memory after mapping
 * @flags: ELF segment flags (PF_R/PF_W/PF_X)
 * @data: Optional raw segment bytes (if loaded)
 */
struct ElfSegment {
    uint64_t virtual_address;
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t memory_size;
    uint32_t flags;
    std::vector<uint8_t> data;
};

/**
 * struct ElfImage - Parsed ELF image ready for manual mapping
 * @entry_point: Entry point address from the ELF header
 * @base_address: Base address for relocation (set during mapping)
 * @total_size: Total size of the mapped image
 * @segments: Loadable segments extracted from the ELF file
 * @raw_image: Contiguous local image after segment copy
 * @pending_imports: External relocations that need resolution
 * @internal_relocs: Relocations that only need base address adjustment
 */
struct ElfImage {
    uint64_t entry_point;
    uint64_t base_address;
    uint64_t total_size;
    std::vector<ElfSegment> segments;
    std::vector<uint8_t> raw_image; // The mapped image in local memory
    
    // Symbols needed for resolution
    /**
     * struct ImportInfo - External relocation entry
     * @name: Symbol name to resolve in the remote process
     * @offset: Offset in the relocation table/GOT
     * @type: Relocation type (ELF64)
     */
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

/**
 * class RemoteReader - Abstract interface for remote memory access
 *
 * This allows the ELF parser to resolve imports without hard-coding
 * the access mechanism (driver IOCTLs, ptrace, etc).
 */
class RemoteReader {
public:
    /**
     * read - Read memory from a remote process
     * @address: Remote virtual address
     * @buffer: Local destination buffer
     * @size: Number of bytes to read
     * @return true on success, false on failure
     */
    virtual bool read(uint64_t address, void* buffer, size_t size) = 0;
    /**
     * get_module_base - Resolve a module base address in the remote process
     * @module_name: Module name or substring to match
     * @return Base address, or 0 if not found
     */
    virtual uint64_t get_module_base(const std::string& module_name) = 0;
    /**
     * ~RemoteReader - Virtual destructor for interface cleanup
     */
    virtual ~RemoteReader() = default;
};

/**
 * class ElfParser - ELF parsing and relocation helper
 *
 * Loads an ELF file, builds a local mapped image, tracks relocations,
 * and resolves external imports using a RemoteReader implementation.
 */
class ElfParser {
public:
    /**
     * ElfParser - Create a parser for a local ELF file
     * @path: Filesystem path to the ELF file
     */
    explicit ElfParser(const std::string& path);
    /**
     * ~ElfParser - Release parser state
     */
    ~ElfParser();

    /**
     * parse - Parse the ELF file and build the local image
     * @return true on success, false on failure
     */
    bool parse();
    /**
     * get_image - Access the parsed image after parse()
     * @return Reference to the parsed ElfImage
     */
    const ElfImage& get_image() const { return image; }
    
    /**
     * relocate_base - Apply base relocations to the local image
     * @target_base: Base address where the image will be mapped remotely
     * @return true on success, false on failure
     */
    bool relocate_base(uint64_t target_base);
    
    /**
     * resolve_imports - Resolve external symbols in the remote process
     * @reader: Remote reader for symbol lookup and memory access
     * @return true on success, false on failure
     */
    bool resolve_imports(RemoteReader& reader);
    
    /**
     * get_symbol_offset - Resolve an exported symbol offset in the local image
     * @name: Symbol name to look up
     * @return Offset within the image, or 0 if not found
     */
    uint64_t get_symbol_offset(const std::string& name);

private:
    std::string file_path;
    ElfImage image;
    std::vector<uint8_t> file_data;
    
    // Internal ELF pointers
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    
    /**
     * load_file - Read the ELF file into memory and validate headers
     * @return true on success, false on failure
     */
    bool load_file();
    /**
     * process_segments - Legacy helper for segment processing
     *
     * This helper is not currently used because parse() handles segments
     * inline. Keep in sync or remove if not needed.
     */
    void process_segments();
    /**
     * collect_imports - Collect relocations that require external symbols
     */
    void collect_imports(); 
};

} // namespace snakedrv

#endif // SNAKEDRV_ELF_HPP
