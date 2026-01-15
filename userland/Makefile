# Makefile for libsnakedrv - Userland library for SnakeEngine kernel driver

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O3 -march=native -fPIC
INCLUDES := -Iinclude
LDFLAGS := -shared

SRCS := src/libsnakedrv.cpp src/libsnakedrv_scanner.cpp src/snakedrv_injector.cpp
OBJS := build/libsnakedrv.o build/libsnakedrv_scanner.o build/snakedrv_injector.o
TARGET := libsnakedrv.so

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(LDFLAGS) $^ -o $@

build/%.o: src/%.cpp
	@mkdir -p build
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf build $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/lib/
	sudo ldconfig
