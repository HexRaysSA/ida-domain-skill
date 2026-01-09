# Makefile for Callgraph Hotspot Binary
# Compiles Zig source to create a binary suitable for IDA analysis

ZIG ?= zig
OUTPUT_DIR ?= ..
BINARY_NAME ?= input

# Default target - uses Debug for maximum function visibility in IDA
all: $(OUTPUT_DIR)/$(BINARY_NAME)

# Build the binary (Debug mode preserves function boundaries for analysis)
$(OUTPUT_DIR)/$(BINARY_NAME): main.zig
	$(ZIG) build-exe main.zig -O Debug --name $(BINARY_NAME)
	mv $(BINARY_NAME) $(OUTPUT_DIR)/

# ReleaseSafe build (some inlining, still readable)
release-safe: main.zig
	$(ZIG) build-exe main.zig -O ReleaseSafe -fno-strip --name $(BINARY_NAME)_release_safe
	mv $(BINARY_NAME)_release_safe $(OUTPUT_DIR)/

# ReleaseFast build (heavily optimized)
release-fast: main.zig
	$(ZIG) build-exe main.zig -O ReleaseFast --name $(BINARY_NAME)_release_fast
	mv $(BINARY_NAME)_release_fast $(OUTPUT_DIR)/

# Build all variants
all-variants: all release-safe release-fast

# Clean build artifacts
clean:
	rm -f $(OUTPUT_DIR)/$(BINARY_NAME)
	rm -f $(OUTPUT_DIR)/$(BINARY_NAME)_release_safe
	rm -f $(OUTPUT_DIR)/$(BINARY_NAME)_release_fast
	rm -f *.o

# Show function count (after building)
count-functions:
	@echo "Counting functions in binary..."
	@if [ -f $(OUTPUT_DIR)/$(BINARY_NAME) ]; then \
		echo "Total text symbols: $$(nm $(OUTPUT_DIR)/$(BINARY_NAME) 2>/dev/null | grep -E ' [Tt] ' | wc -l | tr -d ' ')"; \
		echo "Custom main.* functions: $$(nm $(OUTPUT_DIR)/$(BINARY_NAME) 2>/dev/null | grep -E ' [Tt] ' | grep '_main\.' | wc -l | tr -d ' ')"; \
	else \
		echo "Binary not built yet. Run 'make' first."; \
	fi

# Test the binary
test: $(OUTPUT_DIR)/$(BINARY_NAME)
	$(OUTPUT_DIR)/$(BINARY_NAME)

.PHONY: all debug release all-variants clean count-functions test
