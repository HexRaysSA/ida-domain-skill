# Makefile for Cross-Module Import Usage Map test binary
# Compiles Zig source to produce a binary with diverse imports

TARGET = input
SRC_DIR = src
SRC = $(SRC_DIR)/main.zig

.PHONY: all clean release debug

all: $(TARGET)

$(TARGET): $(SRC)
	zig build-exe $(SRC) -femit-bin=$(TARGET) -ODebug \
		-lSystem \
		-lc

# Debug build with full symbols
debug: $(SRC)
	zig build-exe $(SRC) -femit-bin=$(TARGET) -ODebug \
		-lSystem \
		-lc

# Release build (smaller, optimized)
release: $(SRC)
	zig build-exe $(SRC) -femit-bin=$(TARGET) -OReleaseSafe \
		-lSystem \
		-lc

# Strip symbols for release
release-stripped: release
	strip $(TARGET)

# Show import information (macOS)
imports: $(TARGET)
	@echo "=== Dynamic Libraries ==="
	otool -L $(TARGET)
	@echo ""
	@echo "=== Import Symbols ==="
	nm -u $(TARGET) | head -50
	@echo ""
	@echo "=== Total undefined symbols ==="
	nm -u $(TARGET) | wc -l

clean:
	rm -f $(TARGET) $(TARGET).o

# Run the binary
run: $(TARGET)
	./$(TARGET)

# Create IDA database (requires IDA)
idb: $(TARGET)
	@echo "To create IDA database, open $(TARGET) in IDA Pro"
	@echo "Then save as input.i64"

help:
	@echo "Targets:"
	@echo "  all       - Build debug binary (default)"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build optimized binary"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and run the binary"
	@echo "  imports   - Show import information"
	@echo "  help      - Show this help"
