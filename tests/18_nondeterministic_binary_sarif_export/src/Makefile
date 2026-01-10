# Makefile for Exercise 18: Binary-to-SARIF Security Analysis
# Builds a vulnerable test binary with security anti-patterns

ZIG = zig
SRC_DIR = src
OUT_DIR = ..
TARGET = input

# Source file
SRC = $(SRC_DIR)/vulnerable_app.zig

# Build flags - include debug info for better analysis
# Release mode still keeps symbols for IDA analysis
BUILD_FLAGS = -OReleaseSafe

.PHONY: all clean debug release

all: release

# Release build (default) - optimized but with symbols
release: $(SRC)
	$(ZIG) build-exe $(SRC) -femit-bin=$(OUT_DIR)/$(TARGET) $(BUILD_FLAGS) -lc

# Debug build - full debug info, no optimization
debug: $(SRC)
	$(ZIG) build-exe $(SRC) -femit-bin=$(OUT_DIR)/$(TARGET)_debug -ODebug -lc

# Build both versions
both: release debug

# Clean build artifacts
clean:
	rm -f $(OUT_DIR)/$(TARGET) $(OUT_DIR)/$(TARGET)_debug
	rm -f $(OUT_DIR)/*.o

# Show info about the binary
info: release
	@echo "Binary information:"
	@file $(OUT_DIR)/$(TARGET)
	@echo ""
	@echo "Size:"
	@ls -lh $(OUT_DIR)/$(TARGET)
	@echo ""
	@echo "Symbols (first 20):"
	@nm $(OUT_DIR)/$(TARGET) 2>/dev/null | head -20 || true

# Help target
help:
	@echo "Available targets:"
	@echo "  all     - Build release version (default)"
	@echo "  release - Build optimized binary with symbols"
	@echo "  debug   - Build debug binary with full debug info"
	@echo "  both    - Build both release and debug versions"
	@echo "  clean   - Remove built binaries"
	@echo "  info    - Show binary information"
	@echo "  help    - Show this help message"
