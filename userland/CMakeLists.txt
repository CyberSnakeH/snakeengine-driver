cmake_minimum_required(VERSION 3.10)
project(libsnakedrv VERSION 2.0.2 LANGUAGES CXX)

# Options
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(SNAKEDRV_BUILD_TESTS "Build test executables" OFF)

# Compiler definitions
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/libsnakedrv.cpp
    src/libsnakedrv_scanner.cpp
    src/snakedrv_injector.cpp
)

# Headers
set(HEADERS
    include/libsnakedrv.hpp
    include/libsnakedrv_scanner.hpp
    include/snakedrv.h
    include/snakedrv_scanner.h
)

# Library target
add_library(snakedrv ${SOURCES} ${HEADERS})

# Alias for easy inclusion
add_library(Snake::Driver ALIAS snakedrv)

# Installation definitions
include(GNUInstallDirs)

# Install targets
install(TARGETS snakedrv
    EXPORT snakedrvTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install headers
install(FILES ${HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/snakeengine
)

# Packaging (CPack)
set(CPACK_PACKAGE_NAME "libsnakedrv")
set(CPACK_PACKAGE_VENDOR "SnakeEngine Project")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SnakeEngine Driver Userland Library")
include(CPack)

if(SNAKEDRV_BUILD_TESTS)
    enable_testing()

    add_library(manual_map_payload SHARED
        selftests/manual_map_payload.cpp
    )
    set_target_properties(manual_map_payload PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        PREFIX ""
    )

    add_executable(test_manualmap_elf
        selftests/test_manualmap_elf.cpp
        src/snakedrv_injector.cpp
    )
    target_include_directories(test_manualmap_elf PRIVATE include)

    add_test(NAME manualmap_elf
        COMMAND test_manualmap_elf "$<TARGET_FILE:manual_map_payload>"
    )

    add_executable(test_ioctl_abi
        selftests/test_ioctl_abi.cpp
    )
    target_include_directories(test_ioctl_abi PRIVATE include)
    add_test(NAME ioctl_abi
        COMMAND test_ioctl_abi
    )
endif()
