#!/bin/bash
# download_test_binary.sh
# Downloads and prepares suitable large binaries for Exercise 20
# Target: 10,000-50,000+ functions for scalability testing

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXERCISE_DIR="$(dirname "$SCRIPT_DIR")"
DEST_DIR="$EXERCISE_DIR"

echo "=============================================="
echo "Exercise 20: Large Binary Downloader"
echo "=============================================="
echo ""
echo "This exercise requires a binary with 10k-50k+ functions."
echo "Manual generation is impractical, so we'll use real binaries."
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo "Detected: macOS"
elif [[ "$OSTYPE" == "linux"* ]]; then
    OS="linux"
    echo "Detected: Linux"
else
    OS="unknown"
    echo "Detected: Unknown OS ($OSTYPE)"
fi

echo ""
echo "=== Option 1: Use System FFmpeg (Recommended) ==="

FFMPEG_PATH=""
if command -v ffmpeg &> /dev/null; then
    FFMPEG_PATH="$(which ffmpeg)"
    echo "Found ffmpeg at: $FFMPEG_PATH"

    # Get function count estimate
    if command -v nm &> /dev/null; then
        FUNC_COUNT=$(nm "$FFMPEG_PATH" 2>/dev/null | grep -c " T " || echo "unknown")
        echo "Estimated function count: $FUNC_COUNT"
    fi

    echo ""
    read -p "Copy ffmpeg as test binary? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        cp "$FFMPEG_PATH" "$DEST_DIR/input"
        echo "Copied to: $DEST_DIR/input"
        echo ""
        echo "Next step: Create IDA database with:"
        echo "  ida64 -B \"$DEST_DIR/input\""
        exit 0
    fi
else
    echo "FFmpeg not found. Install with:"
    if [[ "$OS" == "macos" ]]; then
        echo "  brew install ffmpeg"
    else
        echo "  apt install ffmpeg  # or equivalent"
    fi
fi

echo ""
echo "=== Option 2: Use System SQLite ==="

SQLITE_PATH=""
if command -v sqlite3 &> /dev/null; then
    SQLITE_PATH="$(which sqlite3)"
    echo "Found sqlite3 at: $SQLITE_PATH"

    if command -v nm &> /dev/null; then
        FUNC_COUNT=$(nm "$SQLITE_PATH" 2>/dev/null | grep -c " T " || echo "unknown")
        echo "Estimated function count: $FUNC_COUNT (may be smaller, ~2k-5k)"
    fi

    echo ""
    read -p "Copy sqlite3 as test binary? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        cp "$SQLITE_PATH" "$DEST_DIR/input"
        echo "Copied to: $DEST_DIR/input"
        echo ""
        echo "Next step: Create IDA database with:"
        echo "  ida64 -B \"$DEST_DIR/input\""
        exit 0
    fi
else
    echo "SQLite not found."
fi

echo ""
echo "=== Option 3: Build SQLite with All Features ==="
echo "This builds SQLite from source with extra features enabled."
echo ""
read -p "Build SQLite from source? [y/N]: " choice
if [[ "$choice" =~ ^[Yy]$ ]]; then
    BUILD_DIR="/tmp/sqlite_build_$$"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    echo "Downloading SQLite amalgamation..."
    curl -L "https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip" -o sqlite.zip
    unzip -q sqlite.zip
    cd sqlite-amalgamation-*

    echo "Compiling with all features enabled..."
    if [[ "$OS" == "macos" ]]; then
        clang -O2 \
            -DSQLITE_ENABLE_FTS5 \
            -DSQLITE_ENABLE_JSON1 \
            -DSQLITE_ENABLE_RTREE \
            -DSQLITE_ENABLE_GEOPOLY \
            -DSQLITE_ENABLE_MATH_FUNCTIONS \
            -DSQLITE_ENABLE_STAT4 \
            -DSQLITE_ENABLE_SESSION \
            -DSQLITE_ENABLE_PREUPDATE_HOOK \
            -o sqlite3_full shell.c sqlite3.c -lpthread
    else
        gcc -O2 \
            -DSQLITE_ENABLE_FTS5 \
            -DSQLITE_ENABLE_JSON1 \
            -DSQLITE_ENABLE_RTREE \
            -DSQLITE_ENABLE_GEOPOLY \
            -DSQLITE_ENABLE_MATH_FUNCTIONS \
            -DSQLITE_ENABLE_STAT4 \
            -DSQLITE_ENABLE_SESSION \
            -DSQLITE_ENABLE_PREUPDATE_HOOK \
            -o sqlite3_full shell.c sqlite3.c -lpthread -ldl -lm
    fi

    cp sqlite3_full "$DEST_DIR/input"
    echo "Built and copied to: $DEST_DIR/input"

    # Cleanup
    cd /
    rm -rf "$BUILD_DIR"

    echo ""
    echo "Next step: Create IDA database with:"
    echo "  ida64 -B \"$DEST_DIR/input\""
    exit 0
fi

echo ""
echo "=== Option 4: Manual Selection ==="
echo ""
echo "Other recommended large binaries:"
echo "  - Blender: /Applications/Blender.app/Contents/MacOS/Blender"
echo "  - GIMP: Various locations depending on install"
echo "  - Game binaries: Unity/Unreal games"
echo "  - Browser components: Chrome/Firefox libraries"
echo ""
echo "To use a custom binary:"
echo "  cp /path/to/large_binary \"$DEST_DIR/input\""
echo "  ida64 -B \"$DEST_DIR/input\""
echo ""
echo "Verify function count in IDA:"
echo "  import idautils; print(len(list(idautils.Functions())))"
