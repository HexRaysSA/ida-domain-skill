# Makefile for Thunk Forest Binary
#
# Builds a binary with heavy thunking/indirection patterns for IDA analysis.
# Uses Zig for precise control over tail calls and function pointer tables.
#
# NOTE: The default target uses Debug mode to preserve all thunk chains.
# Optimized builds (Release*) may inline thunks, reducing their visibility.

ZIG ?= zig
BUILD_DIR = ../build
TARGET = thunk_forest
SRC = thunk_forest.zig

# Default target - Debug mode preserves all thunk chains for IDA analysis
all: $(BUILD_DIR)/$(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build with Debug to preserve ALL thunk functions (best for IDA exercise)
# This ensures all levels of indirection remain as separate functions
$(BUILD_DIR)/$(TARGET): $(SRC) | $(BUILD_DIR)
	$(ZIG) build-exe $(SRC) \
		-O Debug \
		-femit-bin=$(BUILD_DIR)/$(TARGET) \
		--name $(TARGET)

# Build with ReleaseSafe (some thunks may be inlined)
release-safe: $(SRC) | $(BUILD_DIR)
	$(ZIG) build-exe $(SRC) \
		-O ReleaseSafe \
		-femit-bin=$(BUILD_DIR)/$(TARGET)_release \
		--name $(TARGET)_release

# Build with ReleaseSmall (aggressive inlining, fewer visible thunks)
release-small: $(SRC) | $(BUILD_DIR)
	$(ZIG) build-exe $(SRC) \
		-O ReleaseSmall \
		-femit-bin=$(BUILD_DIR)/$(TARGET)_small \
		--name $(TARGET)_small

# Build with ReleaseFast (highest optimization, most inlining)
release-fast: $(SRC) | $(BUILD_DIR)
	$(ZIG) build-exe $(SRC) \
		-O ReleaseFast \
		-femit-bin=$(BUILD_DIR)/$(TARGET)_fast \
		--name $(TARGET)_fast

# Build all variants for comparison
all-variants: all release-safe release-small release-fast

# Run the binary
run: $(BUILD_DIR)/$(TARGET)
	$(BUILD_DIR)/$(TARGET)

# Disassemble to see thunk patterns (requires objdump)
disasm: $(BUILD_DIR)/$(TARGET)
	objdump -d $(BUILD_DIR)/$(TARGET) | grep -A 10 "_thunk_level\|_indirect_thunk\|_ultimate_\|_mixed_\|_partial_"

# Show all exported symbols related to thunks
symbols: $(BUILD_DIR)/$(TARGET)
	nm $(BUILD_DIR)/$(TARGET) | grep -E "(thunk|ultimate|indirect|partial|dispatch|got_)" | sort

# Count thunk-related symbols (useful for verifying build)
count-symbols: $(BUILD_DIR)/$(TARGET)
	@echo "Thunk-related symbols:"
	@nm $(BUILD_DIR)/$(TARGET) | grep -cE "(thunk|ultimate|indirect|partial|dispatch|got_)" || echo "0"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf zig-cache
	rm -rf .zig-cache

.PHONY: all release-safe release-small release-fast all-variants run disasm symbols count-symbols clean
