# Makefile for Exercise 19: Symbolic Constant Propagation
# Compiles Zig source with optimizations disabled to preserve patterns

# Output binary name
TARGET = symbolic_constants

# Zig source file
SRC = symbolic_constants.zig

# Build directory
BUILD_DIR = ../build

# Zig compiler flags
# -O ReleaseFast would optimize away our patterns, so we use Debug or ReleaseSafe
# Debug mode preserves all patterns and makes analysis easier
ZIG_FLAGS = -O Debug

# For even more explicit pattern preservation, we can use ReleaseSmall
# which does less aggressive optimization than ReleaseFast
ZIG_FLAGS_SMALL = -O ReleaseSmall

.PHONY: all clean debug release-safe release-small

all: debug

# Debug build - best for symbolic analysis (all patterns preserved)
debug: $(BUILD_DIR)
	zig build-exe $(SRC) -O Debug -femit-bin=$(BUILD_DIR)/$(TARGET)_debug
	@echo "Built debug binary: $(BUILD_DIR)/$(TARGET)_debug"
	@echo "Debug mode preserves all computation patterns for analysis"

# ReleaseSafe build - some optimization but bounds checks preserved
release-safe: $(BUILD_DIR)
	zig build-exe $(SRC) -O ReleaseSafe -femit-bin=$(BUILD_DIR)/$(TARGET)_safe
	@echo "Built release-safe binary: $(BUILD_DIR)/$(TARGET)_safe"

# ReleaseSmall build - size optimized, less aggressive than ReleaseFast
release-small: $(BUILD_DIR)
	zig build-exe $(SRC) -O ReleaseSmall -femit-bin=$(BUILD_DIR)/$(TARGET)_small
	@echo "Built release-small binary: $(BUILD_DIR)/$(TARGET)_small"

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET)_debug $(TARGET)_safe $(TARGET)_small
	rm -rf zig-cache
	rm -rf .zig-cache

# Help target
help:
	@echo "Symbolic Constant Propagation Test Binary"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build debug version (default)"
	@echo "  debug        - Build with -O Debug (all patterns preserved)"
	@echo "  release-safe - Build with -O ReleaseSafe"
	@echo "  release-small- Build with -O ReleaseSmall"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "The debug build is recommended for symbolic constant propagation"
	@echo "analysis as it preserves all computation patterns without"
	@echo "optimizing them away."
	@echo ""
	@echo "Patterns included:"
	@echo "  1. Jump table with computable base and index"
	@echo "  2. XOR decryption with constant key"
	@echo "  3. Arithmetic string deobfuscation (ADD)"
	@echo "  4. Computed function pointer from table"
	@echo "  5. Multi-step constant computation"
	@echo "  6. LEA-based address computation"
	@echo "  7. Rolling XOR decryption"
	@echo "  8. Computed data pointer with offset"
	@echo "  9. Switch-like dispatch with computed case values"
	@echo " 10. Nested table lookup"
