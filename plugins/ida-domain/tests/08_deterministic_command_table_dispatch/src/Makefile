# Makefile for Exercise 08: Command Table Dispatch
# Builds a binary with switch/jump-table based dispatch patterns

ZIG ?= zig
OUTPUT_DIR := ..
SRC_DIR := src
BINARY := $(OUTPUT_DIR)/input

# Default target - build ReleaseSafe (preserves jump tables, has debug info)
all: $(BINARY)

$(BINARY): $(SRC_DIR)/main.zig
	$(ZIG) build-exe $< -O ReleaseSafe -fno-PIE --name input -femit-bin=$(BINARY)

# Debug build - full debug symbols, no optimization
debug: $(SRC_DIR)/main.zig
	$(ZIG) build-exe $< -O Debug -fno-PIE --name input_debug -femit-bin=$(OUTPUT_DIR)/input_debug

# ReleaseSmall - more aggressive optimization, may inline handlers
release-small: $(SRC_DIR)/main.zig
	$(ZIG) build-exe $< -O ReleaseSmall -fno-PIE --name input_small -femit-bin=$(OUTPUT_DIR)/input_small

# ReleaseFast - maximum optimization
release-fast: $(SRC_DIR)/main.zig
	$(ZIG) build-exe $< -O ReleaseFast -fno-PIE --name input_fast -femit-bin=$(OUTPUT_DIR)/input_fast

# Build all variants
all-variants: $(BINARY) debug release-small release-fast

# Run the binary
run: $(BINARY)
	./$(BINARY)

# Clean build artifacts
clean:
	rm -f $(OUTPUT_DIR)/input $(OUTPUT_DIR)/input_debug $(OUTPUT_DIR)/input_small $(OUTPUT_DIR)/input_fast
	rm -f $(OUTPUT_DIR)/*.o

# Show disassembly of dispatch function (requires objdump)
disasm: $(BINARY)
	objdump -d $(BINARY) | grep -A 100 "dispatchCommand"

.PHONY: all debug release-small release-fast all-variants run clean disasm
