#include "snakedrv_elf.hpp"

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: test_manualmap_elf <payload.so>\n";
        return 2;
    }

    snakedrv::ElfParser parser(argv[1]);
    if (!parser.parse()) {
        std::cerr << "failed to parse ELF payload\n";
        return 1;
    }

    uint64_t entry = parser.get_symbol_offset("ManualMapEntry");
    if (entry == 0) {
        std::cerr << "ManualMapEntry was not found\n";
        return 1;
    }

    std::cout << "ManualMapEntry=0x" << std::hex << entry << "\n";
    return 0;
}
