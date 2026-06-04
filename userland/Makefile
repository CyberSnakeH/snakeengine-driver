# Makefile for libsnakedrv — SnakeEngine kernel-driver userland library.
#
# Build:
#   make            (or `make -j`)
#
# Install (DESTDIR-aware, no sudo by default):
#   make install                              # → /usr/local
#   make install PREFIX=/usr                  # → /usr
#   make install DESTDIR=/tmp/stage           # staging build (for packaging)
#
# Variables (all overridable on the command line):
#   PREFIX     install prefix          [/usr/local]
#   LIBDIR     library directory       [$(PREFIX)/lib]
#   INCLUDEDIR header directory        [$(PREFIX)/include]
#   PCDIR      pkg-config directory    [$(LIBDIR)/pkgconfig]
#   CMAKEDIR   CMake config directory  [$(LIBDIR)/cmake/SnakeDrv]
#   DESTDIR    staging root            [empty]
#

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O3 -fPIC
CXXFLAGS += -D_FILE_OFFSET_BITS=64
INCLUDES := -Iinclude
LDFLAGS  := -shared -Wl,-soname,libsnakedrv.so

PREFIX     ?= /usr/local
LIBDIR     ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PCDIR      ?= $(LIBDIR)/pkgconfig
CMAKEDIR   ?= $(LIBDIR)/cmake/SnakeDrv

# Repo-relative paths.
PACKAGING_DIR := ../packaging
HEADER_FILE   := include/snakedrv.h
BUILD_DIR     ?= build

# Version is the single source of truth: parse it directly from the header.
SNAKEDRV_VERSION_MAJOR := $(shell awk '/^[[:space:]]*#define[[:space:]]+SNAKEDRV_VERSION_MAJOR/{print $$3}' $(HEADER_FILE))
SNAKEDRV_VERSION_MINOR := $(shell awk '/^[[:space:]]*#define[[:space:]]+SNAKEDRV_VERSION_MINOR/{print $$3}' $(HEADER_FILE))
SNAKEDRV_VERSION_PATCH := $(shell awk '/^[[:space:]]*#define[[:space:]]+SNAKEDRV_VERSION_PATCH/{print $$3}' $(HEADER_FILE))
SNAKEDRV_ABI_VERSION   := $(shell awk '/^[[:space:]]*#define[[:space:]]+SNAKEDRV_ABI_VERSION/{print $$3}' $(HEADER_FILE))
SNAKEDRV_VERSION       := $(SNAKEDRV_VERSION_MAJOR).$(SNAKEDRV_VERSION_MINOR).$(SNAKEDRV_VERSION_PATCH)

SRCS := src/libsnakedrv.cpp src/libsnakedrv_scanner.cpp src/snakedrv_injector.cpp
OBJS := $(patsubst src/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))
TARGET := libsnakedrv.so
MANUALMAP_PAYLOAD := $(BUILD_DIR)/manual_map_payload.so
MANUALMAP_ELF_TEST := $(BUILD_DIR)/test_manualmap_elf
IOCTL_ABI_TEST := $(BUILD_DIR)/test_ioctl_abi

# Headers shipped to consumers (everything under include/).
PUBLIC_HEADERS := $(wildcard include/*.h) $(wildcard include/*.hpp)

# DESTDIR-prefixed install paths.
D_LIBDIR     := $(DESTDIR)$(LIBDIR)
D_INCLUDEDIR := $(DESTDIR)$(INCLUDEDIR)/snakedrv
D_PCDIR      := $(DESTDIR)$(PCDIR)
D_CMAKEDIR   := $(DESTDIR)$(CMAKEDIR)

INSTALL ?= install

.PHONY: all clean install test test-manualmap test-ioctl-abi \
        install-lib install-headers install-pkgconfig install-cmake \
        print-version

all: $(TARGET)

print-version:
	@echo "snakedrv $(SNAKEDRV_VERSION) (ABI $(SNAKEDRV_ABI_VERSION))"

# ─── Build the shared library ──────────────────────────────────────────

$(TARGET): $(OBJS)
	@echo "  LD    $@"
	@$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: src/%.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "  CXX   $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -MMD -MP -c $< -o $@

$(MANUALMAP_PAYLOAD): selftests/manual_map_payload.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "  CXX   $@"
	@$(CXX) $(CXXFLAGS) -shared -fPIC $< -o $@

$(MANUALMAP_ELF_TEST): selftests/test_manualmap_elf.cpp src/snakedrv_injector.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "  CXX   $@"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@

$(IOCTL_ABI_TEST): selftests/test_ioctl_abi.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "  CXX   $@"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@

test: test-manualmap test-ioctl-abi

test-manualmap: $(MANUALMAP_PAYLOAD) $(MANUALMAP_ELF_TEST)
	@$(MANUALMAP_ELF_TEST) $(MANUALMAP_PAYLOAD)

test-ioctl-abi: $(IOCTL_ABI_TEST)
	@$(IOCTL_ABI_TEST)

-include $(OBJS:.o=.d)

# ─── sed substitution shared by all rendered packaging files ───────────
#
# Packaging files (.pc, CMake config) embed the install paths, so they
# MUST be re-rendered with the current PREFIX/LIBDIR/INCLUDEDIR at
# install time — caching the rendered file would lock in stale paths.

SED_SUBS = \
    -e 's|@PREFIX@|$(PREFIX)|g' \
    -e 's|@LIBDIR@|$(LIBDIR)|g' \
    -e 's|@INCLUDEDIR@|$(INCLUDEDIR)/snakedrv|g' \
    -e 's|@SNAKEDRV_VERSION@|$(SNAKEDRV_VERSION)|g' \
    -e 's|@SNAKEDRV_VERSION_MAJOR@|$(SNAKEDRV_VERSION_MAJOR)|g' \
    -e 's|@SNAKEDRV_VERSION_MINOR@|$(SNAKEDRV_VERSION_MINOR)|g' \
    -e 's|@SNAKEDRV_VERSION_PATCH@|$(SNAKEDRV_VERSION_PATCH)|g' \
    -e 's|@SNAKEDRV_ABI_VERSION@|$(SNAKEDRV_ABI_VERSION)|g'

# ─── Install ───────────────────────────────────────────────────────────

install: install-lib install-headers install-pkgconfig install-cmake

install-lib: $(TARGET)
	@echo "  INSTALL  $(D_LIBDIR)/$(TARGET)"
	@$(INSTALL) -d $(D_LIBDIR)
	@$(INSTALL) -m 0755 $(TARGET) $(D_LIBDIR)/

install-headers:
	@echo "  INSTALL  $(D_INCLUDEDIR)/"
	@$(INSTALL) -d $(D_INCLUDEDIR)
	@$(INSTALL) -m 0644 $(PUBLIC_HEADERS) $(D_INCLUDEDIR)/

install-pkgconfig:
	@echo "  INSTALL  $(D_PCDIR)/snakedrv.pc"
	@$(INSTALL) -d $(D_PCDIR)
	@sed $(SED_SUBS) $(PACKAGING_DIR)/pkgconfig/snakedrv.pc.in \
	    > $(D_PCDIR)/snakedrv.pc
	@chmod 0644 $(D_PCDIR)/snakedrv.pc

install-cmake:
	@echo "  INSTALL  $(D_CMAKEDIR)/"
	@$(INSTALL) -d $(D_CMAKEDIR)
	@sed $(SED_SUBS) $(PACKAGING_DIR)/cmake/SnakeDrvConfig.cmake.in \
	    > $(D_CMAKEDIR)/SnakeDrvConfig.cmake
	@sed $(SED_SUBS) $(PACKAGING_DIR)/cmake/SnakeDrvConfigVersion.cmake.in \
	    > $(D_CMAKEDIR)/SnakeDrvConfigVersion.cmake
	@chmod 0644 $(D_CMAKEDIR)/SnakeDrvConfig.cmake \
	            $(D_CMAKEDIR)/SnakeDrvConfigVersion.cmake

# ─── Clean ─────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
