# Makefile for String Provenance Sample Binary
# Compiles Zig source to create a binary with diverse interesting strings

ZIG := zig
SRC := main.zig
OUT_DIR := ../
BINARY := $(OUT_DIR)input

# Default target
.PHONY: all
all: $(BINARY)

# Build the binary (release-small to keep strings visible without too much optimization)
$(BINARY): $(SRC)
	$(ZIG) build-exe $(SRC) -O ReleaseSmall -fno-strip --name input
	mv input $(BINARY)

# Debug build (preserves more symbols)
.PHONY: debug
debug: $(SRC)
	$(ZIG) build-exe $(SRC) -O Debug --name input_debug
	mv input_debug $(OUT_DIR)

# Release build with all optimizations
.PHONY: release
release: $(SRC)
	$(ZIG) build-exe $(SRC) -O ReleaseFast --name input_release
	mv input_release $(OUT_DIR)

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY) $(OUT_DIR)input_debug $(OUT_DIR)input_release
	rm -f *.o

# Show strings in the binary (for verification)
.PHONY: strings
strings: $(BINARY)
	strings $(BINARY) | grep -E "(http|https|ftp|wss|HKEY|HKLM|HKCU|\.exe|\.dll|/etc/|/tmp/|C:\\\\|api/|AES|RSA|SHA|MD5|cmd\.exe|powershell)"

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all      - Build the binary (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build with full optimizations"
	@echo "  clean    - Remove build artifacts"
	@echo "  strings  - Show interesting strings in the binary"
	@echo "  help     - Show this help message"
