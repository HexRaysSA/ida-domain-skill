# Makefile for Vtable Discovery Demo Binary
#
# Builds a C++ binary with virtual classes, inheritance, and vtables for IDA analysis.
# Uses C++ because Zig does not support C++ style virtual classes.
#
# Note: This exercise requires C++ features (vtables, virtual methods, RTTI)
# that are not available in Zig.

CXX ?= g++
BUILD_DIR = ../
TARGET = input
SRC = vtable_demo.cpp

# Compiler flags:
# -std=c++11: Use C++11 for override keyword
# -O1: Light optimization to keep function structure clear
# -fno-inline: Prevent inlining to preserve function boundaries
# -frtti: Enable RTTI (Run-Time Type Information) for type_info analysis
# -g: Debug symbols (can be stripped for harder exercises)
CXXFLAGS = -std=c++11 -O1 -fno-inline -frtti -g

# Default target
all: $(BUILD_DIR)/$(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build the main binary with RTTI preserved
$(BUILD_DIR)/$(TARGET): $(SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Build stripped version (no symbols, harder analysis)
stripped: $(SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $(BUILD_DIR)/$(TARGET)_stripped $<
	strip $(BUILD_DIR)/$(TARGET)_stripped

# Build without RTTI (no type_info, vtable-only analysis)
no-rtti: $(SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -fno-rtti -o $(BUILD_DIR)/$(TARGET)_nortti $<

# Build with higher optimization (more inlining, harder to analyze)
optimized: $(SRC) | $(BUILD_DIR)
	$(CXX) -std=c++11 -O2 -frtti -g -o $(BUILD_DIR)/$(TARGET)_opt $<

# Build all variants for different analysis difficulty levels
all-variants: all stripped no-rtti optimized

# Run the binary
run: $(BUILD_DIR)/$(TARGET)
	$(BUILD_DIR)/$(TARGET)

# Show vtable-related symbols
symbols: $(BUILD_DIR)/$(TARGET)
	@echo "=== Vtable symbols (ZTV = vtable, ZTI = typeinfo, ZTS = typeinfo name) ==="
	nm $(BUILD_DIR)/$(TARGET) | grep -E "(ZTV|ZTI|ZTS)" | c++filt
	@echo ""
	@echo "=== Virtual method symbols ==="
	nm $(BUILD_DIR)/$(TARGET) | grep -E "(draw|area|name|scale|serialize)" | c++filt | head -30

# Disassemble to see vtable patterns
disasm: $(BUILD_DIR)/$(TARGET)
	objdump -d -C $(BUILD_DIR)/$(TARGET) | grep -A 10 "vtable\|type_info"

# Show .rodata section (where vtables live)
rodata: $(BUILD_DIR)/$(TARGET)
	objdump -s -j .rodata $(BUILD_DIR)/$(TARGET) | head -100

# Show class hierarchy via RTTI
rtti-info: $(BUILD_DIR)/$(TARGET)
	@echo "=== RTTI type_info symbols ==="
	nm $(BUILD_DIR)/$(TARGET) | grep "_ZTI" | c++filt
	@echo ""
	@echo "=== Vtable symbols ==="
	nm $(BUILD_DIR)/$(TARGET) | grep "_ZTV" | c++filt

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all stripped no-rtti optimized all-variants run symbols disasm rodata rtti-info clean
