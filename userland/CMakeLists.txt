cmake_minimum_required(VERSION 3.10)
project(libsnakedrv VERSION 1.0.0 LANGUAGES CXX)

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
