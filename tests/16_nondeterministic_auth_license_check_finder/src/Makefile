# Makefile for Exercise 16: Auth/License Check Finder
# Builds a binary with authentication and license verification patterns for IDA analysis

ZIG := zig
SRC_DIR := src
OUT_DIR := ..
TARGET := input

# Build for x86_64 Linux by default (better for IDA analysis)
ZIG_TARGET ?= x86_64-linux-gnu

# Detect strip command (macOS needs llvm-strip for ELF binaries)
LLVM_STRIP := $(shell which llvm-strip 2>/dev/null || echo /opt/homebrew/opt/llvm@20/bin/llvm-strip)
ifeq ($(shell test -x $(LLVM_STRIP) && echo yes),yes)
    STRIP = $(LLVM_STRIP) --strip-all
else
    STRIP = strip --strip-all
endif

.PHONY: all clean rebuild

all: $(OUT_DIR)/$(TARGET)

# Build optimized binary - ReleaseSafe keeps more code patterns visible
# Strip symbols to simulate real-world protected binary
$(OUT_DIR)/$(TARGET): $(SRC_DIR)/auth_license.zig
	$(ZIG) build-exe $< \
		-target $(ZIG_TARGET) \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET) \
		-femit-bin=$@
	$(STRIP) $@
	@echo "Built stripped x64 binary: $@"
	@echo "Size: $$(ls -lh $@ | awk '{print $$5}')"

# Build variants for different targets
.PHONY: linux-x64 macos-x64 macos-arm64 windows-x64

linux-x64:
	$(ZIG) build-exe $(SRC_DIR)/auth_license.zig \
		-target x86_64-linux-gnu \
		-O ReleaseFast \
		-fno-stack-check \
		--name $(TARGET)_linux_x64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_linux_x64
	$(STRIP) $(OUT_DIR)/$(TARGET)_linux_x64

macos-x64:
	$(ZIG) build-exe $(SRC_DIR)/auth_license.zig \
		-target x86_64-macos \
		-O ReleaseFast \
		-fno-stack-check \
		--name $(TARGET)_macos_x64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_macos_x64
	strip $(OUT_DIR)/$(TARGET)_macos_x64

macos-arm64:
	$(ZIG) build-exe $(SRC_DIR)/auth_license.zig \
		-target aarch64-macos \
		-O ReleaseFast \
		-fno-stack-check \
		--name $(TARGET)_macos_arm64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_macos_arm64
	strip $(OUT_DIR)/$(TARGET)_macos_arm64

windows-x64:
	$(ZIG) build-exe $(SRC_DIR)/auth_license.zig \
		-target x86_64-windows \
		-O ReleaseFast \
		-fno-stack-check \
		--name $(TARGET)_windows_x64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_windows_x64.exe

# Debug build (with symbols for verification)
debug: $(SRC_DIR)/auth_license.zig
	$(ZIG) build-exe $< \
		-target $(ZIG_TARGET) \
		-O Debug \
		--name $(TARGET)_debug \
		-femit-bin=$(OUT_DIR)/$(TARGET)_debug
	@echo "Built debug binary with symbols: $(OUT_DIR)/$(TARGET)_debug"

# ReleaseSafe build (with more safety checks visible)
safe: $(SRC_DIR)/auth_license.zig
	$(ZIG) build-exe $< \
		-target $(ZIG_TARGET) \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)_safe \
		-femit-bin=$(OUT_DIR)/$(TARGET)_safe
	@echo "Built ReleaseSafe binary: $(OUT_DIR)/$(TARGET)_safe"

clean:
	rm -f $(OUT_DIR)/$(TARGET) $(OUT_DIR)/$(TARGET)_* $(OUT_DIR)/*.o

rebuild: clean all
