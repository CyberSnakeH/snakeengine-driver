# Makefile for libsnakedrv - Userland library for SnakeEngine kernel driver

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O3 -march=native -fPIC
INCLUDES := -Iinclude
LDFLAGS := -shared

SRC := src/libsnakedrv.cpp
TARGET := libsnakedrv.so
OBJ := build/libsnakedrv.o

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "Linking $(TARGET)..."
	$(CXX) $(LDFLAGS) $^ -o $@

$(OBJ): $(SRC)
	@mkdir -p build
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf build $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/lib/
	sudo ldconfig
