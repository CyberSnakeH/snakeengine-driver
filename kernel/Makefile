# ============================================================================
# SnakeEngine Kernel Driver - Makefile
# 
# Supports building as both in-tree and out-of-tree module
# Compatible with DKMS for automatic rebuilding on kernel updates
# ============================================================================

# Module name
MODULE_NAME := snakedrv

# Object files
$(MODULE_NAME)-y := snakedrv_main.o

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Compiler flags
ccflags-y := -Wall -Wextra -Werror
ccflags-y += -Wno-unused-parameter
ccflags-y += -Wno-missing-field-initializers
ccflags-y += -I$(PWD)/../userland/include

# Debug build
ifdef DEBUG
ccflags-y += -DDEBUG -g -O0
else
ccflags-y += -O2
endif

# Module
obj-m := $(MODULE_NAME).o

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean install uninstall load unload reload help

all: modules

modules:
	@echo "Building SnakeEngine Kernel Driver..."
	@echo "Kernel: $(shell uname -r)"
	@echo "KDIR: $(KDIR)"
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.symvers *.order .*.cmd

install: modules
	@echo "Installing module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a
	@echo "Module installed successfully"

uninstall:
	@echo "Uninstalling module..."
	rm -f /lib/modules/$(shell uname -r)/extra/$(MODULE_NAME).ko
	depmod -a
	@echo "Module uninstalled"

# Load module
load:
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
		echo "Module already loaded"; \
	else \
		echo "Loading module..."; \
		insmod ./$(MODULE_NAME).ko && echo "Module loaded successfully"; \
	fi

# Unload module
unload:
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
		echo "Unloading module..."; \
		rmmod $(MODULE_NAME) && echo "Module unloaded successfully"; \
	else \
		echo "Module not loaded"; \
	fi

# Reload module
reload: unload load

# Create device node (normally handled by udev)
create-dev:
	@MAJOR=$$(grep $(MODULE_NAME) /proc/devices | awk '{print $$1}'); \
	if [ -n "$$MAJOR" ]; then \
		rm -f /dev/$(MODULE_NAME); \
		mknod /dev/$(MODULE_NAME) c $$MAJOR 0; \
		chmod 660 /dev/$(MODULE_NAME); \
		echo "Created /dev/$(MODULE_NAME) with major $$MAJOR"; \
	else \
		echo "Module not loaded or device number not found"; \
	fi

# Show module info
info:
	@echo "=== SnakeEngine Kernel Driver ==="
	@echo "Module: $(MODULE_NAME)"
	@echo "Kernel: $(shell uname -r)"
	@echo ""
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
		echo "Status: LOADED"; \
		modinfo ./$(MODULE_NAME).ko 2>/dev/null || modinfo $(MODULE_NAME); \
	else \
		echo "Status: NOT LOADED"; \
	fi
	@echo ""
	@if [ -e /dev/$(MODULE_NAME) ]; then \
		echo "Device: /dev/$(MODULE_NAME) EXISTS"; \
		ls -la /dev/$(MODULE_NAME); \
	else \
		echo "Device: /dev/$(MODULE_NAME) NOT FOUND"; \
	fi

# Show kernel logs
dmesg:
	dmesg | grep -i snakedrv | tail -50

# Check for build dependencies
check-deps:
	@echo "Checking build dependencies..."
	@which gcc >/dev/null 2>&1 || (echo "ERROR: gcc not found" && exit 1)
	@which make >/dev/null 2>&1 || (echo "ERROR: make not found" && exit 1)
	@[ -d "$(KDIR)" ] || (echo "ERROR: Kernel headers not found at $(KDIR)" && exit 1)
	@[ -f "$(KDIR)/Makefile" ] || (echo "ERROR: Kernel Makefile not found" && exit 1)
	@echo "All dependencies satisfied!"
	@echo "  gcc: $$(gcc --version | head -1)"
	@echo "  make: $$(make --version | head -1)"
	@echo "  kernel headers: $(KDIR)"

# Help
help:
	@echo "SnakeEngine Kernel Driver - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build Targets:"
	@echo "  all          - Build the kernel module (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install module to kernel modules directory"
	@echo "  uninstall    - Remove installed module"
	@echo ""
	@echo "Runtime Targets:"
	@echo "  load         - Load the kernel module"
	@echo "  unload       - Unload the kernel module"
	@echo "  reload       - Unload and reload the module"
	@echo "  create-dev   - Manually create device node"
	@echo ""
	@echo "Information:"
	@echo "  info         - Show module information and status"
	@echo "  dmesg        - Show kernel log messages from module"
	@echo "  check-deps   - Verify build dependencies"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1      - Build with debug symbols and verbose logging"
	@echo "  KDIR=<path>  - Specify kernel build directory"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build module"
	@echo "  make DEBUG=1            # Debug build"
	@echo "  sudo make load          # Load module"
	@echo "  sudo make install       # Install to system"
