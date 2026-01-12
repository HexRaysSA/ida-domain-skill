# Makefile for Exercise 06: Configuration Structure Carving
# Builds a binary with embedded configuration blob for IDA analysis

ZIG := zig
SRC_DIR := .
OUT_DIR := ..
TARGET := input

# Build for x86_64 macOS by default
# Change target as needed for other platforms
ZIG_TARGET ?= native

.PHONY: all clean

all: $(OUT_DIR)/$(TARGET)

$(OUT_DIR)/$(TARGET): $(SRC_DIR)/config_blob.zig
	$(ZIG) build-exe $< \
		-target $(ZIG_TARGET) \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET) \
		-femit-bin=$@

# Build variants for different targets
.PHONY: linux-x64 macos-x64 macos-arm64 windows-x64

linux-x64:
	$(ZIG) build-exe $(SRC_DIR)/config_blob.zig \
		-target x86_64-linux \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)_linux_x64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_linux_x64

macos-x64:
	$(ZIG) build-exe $(SRC_DIR)/config_blob.zig \
		-target x86_64-macos \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)_macos_x64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_macos_x64

macos-arm64:
	$(ZIG) build-exe $(SRC_DIR)/config_blob.zig \
		-target aarch64-macos \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)_macos_arm64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_macos_arm64

windows-x64:
	$(ZIG) build-exe $(SRC_DIR)/config_blob.zig \
		-target x86_64-windows \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)_windows_x64 \
		-femit-bin=$(OUT_DIR)/$(TARGET)_windows_x64.exe

clean:
	rm -f $(OUT_DIR)/$(TARGET) $(OUT_DIR)/$(TARGET)_* $(OUT_DIR)/*.o
