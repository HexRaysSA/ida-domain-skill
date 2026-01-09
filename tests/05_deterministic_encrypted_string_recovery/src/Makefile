# Makefile for encrypted string recovery exercise binary
# Compiles Zig source to a stripped binary suitable for IDA analysis

BINARY = input
OUTPUT = ../input
ZIG = zig

# Detect host architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
    NATIVE_TARGET = aarch64-macos
    CROSS_TARGET = x86_64-linux
else
    NATIVE_TARGET = x86_64-macos
    CROSS_TARGET = aarch64-linux
endif

# Build targets
.PHONY: all clean release debug x86_64 aarch64 linux-x86_64 both-arch

all: release

# Release build: optimized and stripped (native architecture)
release: $(OUTPUT)

$(OUTPUT): main.zig
	$(ZIG) build-exe main.zig -O ReleaseFast -femit-bin=$(OUTPUT) -fstrip
	@echo "Built stripped release binary: $(OUTPUT) (native)"

# Cross-compile for x86_64 Linux (good for IDA analysis)
linux-x86_64: main.zig
	$(ZIG) build-exe main.zig -O ReleaseFast --name $(BINARY)_linux_x64 -fstrip -target x86_64-linux
	@echo "Built stripped x86_64 Linux binary: $(BINARY)_linux_x64"

# Cross-compile for x86_64 macOS
macos-x86_64: main.zig
	$(ZIG) build-exe main.zig -O ReleaseFast --name $(BINARY)_macos_x64 -fstrip -target x86_64-macos
	@echo "Built stripped x86_64 macOS binary: $(BINARY)_macos_x64"

# Debug build with symbols (for verification)
debug: main.zig
	$(ZIG) build-exe main.zig -O Debug --name $(BINARY)_debug
	@echo "Built debug binary with symbols: $(BINARY)_debug"

# Build both release and debug
both: release debug

# Build for multiple architectures
multi-arch: release linux-x86_64

# Clean build artifacts
clean:
	rm -f $(BINARY) ../input_debug ../input_linux_x64 ../input_macos_x64
	rm -f *.o *.pdb
	rm -rf zig-cache .zig-cache
	@echo "Cleaned build artifacts"

# Test the binary
test: release
	./$(BINARY)

# Show info about the binary
info: release
	@echo "Binary info:"
	@file $(BINARY)
	@echo ""
	@echo "Size:"
	@ls -lh $(BINARY)
	@echo ""
	@echo "Strings (should show minimal plaintext):"
	@strings $(BINARY) | grep -E "(secret|password|admin|config)" || echo "No obvious plaintext strings found (good!)"
