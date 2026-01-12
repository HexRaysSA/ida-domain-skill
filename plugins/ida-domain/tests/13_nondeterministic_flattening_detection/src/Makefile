# Makefile for Exercise 13: Flattening Detection
# Builds a stripped x64 binary with manually flattened control flow

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

.PHONY: all clean rebuild

all: $(OUTPUT)

# Build optimized binary
# Using ReleaseSafe to preserve the flattening structure while allowing optimization
$(OUTPUT): main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-linux-gnu \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)
	$(STRIP) $(TARGET)
	mv $(TARGET) $(OUTPUT)
	@echo "Built stripped x64 binary with flattened functions: $(OUTPUT)"
	@echo "Size: $$(ls -lh $(OUTPUT) | awk '{print $$5}')"

# Alternative: build for macOS
macos: main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-macos \
		-O ReleaseSafe \
		-fno-stack-check \
		--name $(TARGET)
	strip $(TARGET)
	mv $(TARGET) $(OUTPUT)
	@echo "Built stripped x64 macOS binary: $(OUTPUT)"

# Build without stripping (for debugging/verification)
debug: main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-linux-gnu \
		-O Debug \
		--name $(TARGET)_debug
	mv $(TARGET)_debug $(BUILD_DIR)/

# Build with minimal optimization to preserve flattening structure better
# ReleaseSmall tends to preserve switch patterns
minimal: main.zig
	$(ZIG) build-exe main.zig \
		-target x86_64-linux-gnu \
		-O ReleaseSmall \
		-fno-stack-check \
		--name $(TARGET)
	$(STRIP) $(TARGET)
	mv $(TARGET) $(OUTPUT)
	@echo "Built minimal optimized binary: $(OUTPUT)"

clean:
	rm -f $(OUTPUT) $(BUILD_DIR)/$(TARGET)_debug
	rm -f *.o

rebuild: clean all
