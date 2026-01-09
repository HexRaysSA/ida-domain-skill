# Makefile for prototype reconstruction exercise binary
# Creates a stripped binary demonstrating varied function signatures

BINARY = input
SRC_DIR = src
SRC = $(SRC_DIR)/main.zig

# Default target
all: $(BINARY)

# Build and strip the binary
# Using ReleaseSmall to preserve function boundaries, then strip all symbols
$(BINARY): $(SRC)
	zig build-exe $(SRC) -O ReleaseSmall --name $(BINARY) -fno-stack-check
	strip -x $(BINARY)
	@echo "Built and stripped binary: $(BINARY)"

# Build with debug info (for reference/verification)
debug: $(SRC)
	zig build-exe $(SRC) -O Debug --name $(BINARY)_debug
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

# Run the binary (exits with computed result as exit code)
run: $(BINARY)
	-./$(BINARY); echo "Binary executed with exit code: $$?"

.PHONY: all debug clean info run
