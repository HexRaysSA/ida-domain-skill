# Makefile for Exercise 17: Hook Surface Identification
# Builds a binary suitable for dynamic instrumentation analysis
# Features: exported functions, network/crypto/file wrappers, clear init sequence

TARGET = input
ZIG = zig

# Build directory
BUILD_DIR = ../

# Output binary
OUTPUT = $(BUILD_DIR)/$(TARGET)

# Detect strip command (macOS needs llvm-strip for ELF binaries)
LLVM_STRIP := $(shell which llvm-strip 2>/dev/null || echo /opt/homebrew/opt/llvm@20/bin/llvm-strip)
ifeq ($(shell test -x $(LLVM_STRIP) && echo yes),yes)
    STRIP = $(LLVM_STRIP) --strip-all
else
    STRIP = strip --strip-all
endif

.PHONY: all clean rebuild debug macos symbols

all: $(OUTPUT)

# Build optimized binary with symbols preserved for hook identification
# ReleaseSafe keeps function boundaries clean while optimizing
# Use -rdynamic equivalent to export symbols for dynamic instrumentation
$(OUTPUT): main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-linux-gnu \
		-O ReleaseSafe \
		-fno-stack-check \
		-fno-omit-frame-pointer \
		--name $(TARGET)
	$(STRIP) $(TARGET)
	mv $(TARGET) $(OUTPUT)
	@echo "Built stripped x64 binary: $(OUTPUT)"
	@echo "Size: $$(ls -lh $(OUTPUT) | awk '{print $$5}')"

# Build with symbols preserved (for verification and Frida testing)
symbols: main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-linux-gnu \
		-O ReleaseSafe \
		-fno-stack-check \
		-fno-omit-frame-pointer \
		--name $(TARGET)_symbols
	mv $(TARGET)_symbols $(BUILD_DIR)/
	@echo "Built x64 binary with symbols: $(BUILD_DIR)/$(TARGET)_symbols"
	@echo "Use 'readelf -s' or 'nm' to see exported symbols"

# Build for macOS
macos: main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-macos \
		-O ReleaseSafe \
		-fno-stack-check \
		-fno-omit-frame-pointer \
		--name $(TARGET)
	strip $(TARGET)
	mv $(TARGET) $(OUTPUT)
	@echo "Built stripped x64 macOS binary: $(OUTPUT)"

# Build with full debug info
debug: main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-linux-gnu \
		-O Debug \
		--name $(TARGET)_debug
	mv $(TARGET)_debug $(BUILD_DIR)/
	@echo "Built debug x64 binary: $(BUILD_DIR)/$(TARGET)_debug"

clean:
	rm -f $(OUTPUT) $(BUILD_DIR)/$(TARGET)_debug $(BUILD_DIR)/$(TARGET)_symbols
	rm -f *.o

rebuild: clean all

# Show exported symbols (for verification)
show-exports:
	@if [ -f $(OUTPUT) ]; then \
		echo "Exported symbols in $(OUTPUT):"; \
		readelf -s $(OUTPUT) 2>/dev/null | grep -E "FUNC.*GLOBAL" || nm -D $(OUTPUT) 2>/dev/null | grep -E " T "; \
	else \
		echo "Binary not found. Run 'make' first."; \
	fi
