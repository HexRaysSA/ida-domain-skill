# Makefile for Exercise 12: Decompiler Renaming
# Builds a stripped binary with libc API calls for variable renaming exercises

BINARY = input
SRC_DIR = src
SRC = $(SRC_DIR)/main.zig

# Default target
all: $(BINARY)

# Build and strip the binary
# Link with libc to get recognizable API calls (memcpy, malloc, etc.)
$(BINARY): $(SRC)
	zig build-exe $(SRC) -O ReleaseFast --name $(BINARY) -fno-stack-check -fstrip -lc
	@echo "Built and stripped binary: $(BINARY)"

# Build for Linux x86_64 (cross-compile from macOS)
linux: $(SRC)
	zig build-exe $(SRC) -O ReleaseFast --name $(BINARY) -fno-stack-check -fstrip -lc -target x86_64-linux-gnu
	@echo "Built Linux x86_64 binary: $(BINARY)"

# Build with debug info (for reference/verification)
debug: $(SRC)
	zig build-exe $(SRC) -O Debug --name $(BINARY)_debug -lc
	@echo "Built debug binary: $(BINARY)_debug"

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)_debug
	rm -f $(BINARY).o $(BINARY)_debug.o
	rm -rf zig-cache .zig-cache

# Show binary info
info: $(BINARY)
	@echo "=== Binary Info ==="
	file $(BINARY)
	@echo ""
	@echo "=== Size ==="
	ls -lh $(BINARY)
	@echo ""
	@echo "=== Symbol check (should be minimal/none) ==="
	nm $(BINARY) 2>/dev/null | head -20 || echo "No symbols (stripped)"
	@echo ""
	@echo "=== Imported functions (libc calls) ==="
	nm -u $(BINARY) 2>/dev/null | head -30 || objdump -T $(BINARY) 2>/dev/null | grep -E 'malloc|free|memcpy|memset|strlen|strcmp|open|read|write|socket|connect|send|recv' | head -20 || echo "Use objdump -d to see calls"

# Run the binary
run: $(BINARY)
	./$(BINARY)

# Verify libc calls are present
verify: $(BINARY)
	@echo "=== Verifying libc API calls in binary ==="
	@objdump -d $(BINARY) 2>/dev/null | grep -E 'call.*<(malloc|free|memcpy|memset|memmove|realloc|strlen|strcpy|strncpy|strcmp|strncmp|strcat|strchr|strstr|open|read|write|close|lseek|socket|connect|send|recv|bind|listen|accept)' | head -40 || echo "Use IDA to see imported functions"

.PHONY: all linux debug clean info run verify
