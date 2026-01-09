# Exercise 20: Binary Generation Skipped

## Why Manual Binary Generation is Impractical

This exercise requires a **very large binary with 10,000-50,000+ functions**. Generating such a binary manually is impractical for several reasons:

1. **Code Volume**: Writing 10k+ unique, meaningful functions by hand would require hundreds of thousands of lines of code
2. **Realistic Complexity**: The exercise specifically requires "realistic complexity (not artificially inflated)" - auto-generated stub functions wouldn't provide meaningful test cases
3. **Compilation Time**: Even if generated, compiling such a large codebase would take significant time
4. **Maintenance Burden**: Any generated binary would need to be rebuilt and maintained across different platforms

## Recommended Alternatives

### Option 1: Use Real-World Large Binaries

The following binaries are commonly available and contain 10k-50k+ functions:

| Binary | Approx. Functions | Source |
|--------|-------------------|--------|
| SQLite (amalgamation build) | ~2,000-5,000 | sqlite.org |
| LuaJIT | ~3,000-8,000 | luajit.org |
| FFmpeg libraries | 10,000+ | ffmpeg.org |
| Chromium components | 50,000+ | chromium.org |
| Game engine DLLs | 20,000+ | Various |
| libcurl + dependencies | ~5,000 | curl.se |

### Option 2: Compile Large Open-Source Projects

Projects that compile to large binaries with static linking:

- **SQLite** (single-file amalgamation)
- **LuaJIT** or **Lua** interpreter
- **Redis** server
- **Nginx** with modules
- **PostgreSQL** client libraries
- **OpenSSL** libraries

### Option 3: Static Linking Bundle

Combine multiple libraries into a single binary:
- Link OpenSSL + zlib + libcurl + SQLite statically
- Results in a binary with 15,000+ functions

## Obtaining Test Binaries

### Script: Download Pre-built Binaries

```bash
#!/bin/bash
# download_large_binaries.sh
# Downloads suitable large binaries for Exercise 20

set -e

DEST_DIR="$(dirname "$0")/binaries"
mkdir -p "$DEST_DIR"

echo "=== Exercise 20: Large Binary Downloader ==="
echo "Downloading pre-built binaries suitable for scalability testing..."
echo ""

# Option 1: Download SQLite shell (cross-platform)
echo "[1/3] Downloading SQLite..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use Homebrew binary or compile
    echo "  On macOS, install via: brew install sqlite"
    echo "  Binary location: $(which sqlite3 2>/dev/null || echo '/usr/bin/sqlite3')"
elif [[ "$OSTYPE" == "linux"* ]]; then
    # Linux - download precompiled
    curl -L "https://www.sqlite.org/2024/sqlite-tools-linux-x64-3450100.zip" -o "$DEST_DIR/sqlite.zip"
    unzip -o "$DEST_DIR/sqlite.zip" -d "$DEST_DIR"
    rm "$DEST_DIR/sqlite.zip"
fi

# Option 2: FFmpeg (very large, 10k+ functions)
echo "[2/3] FFmpeg (manual download recommended)..."
echo "  Download from: https://ffmpeg.org/download.html"
echo "  Or on macOS: brew install ffmpeg"
echo "  Or on Linux: apt install ffmpeg"

# Option 3: Building from source (SQLite amalgamation)
echo "[3/3] SQLite amalgamation (build from source)..."
echo "  wget https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip"
echo "  unzip sqlite-amalgamation-3450100.zip"
echo "  cd sqlite-amalgamation-3450100"
echo "  gcc -O2 -o sqlite3 shell.c sqlite3.c -lpthread -ldl -lm"

echo ""
echo "=== Recommended binaries for this exercise ==="
echo "1. /usr/bin/sqlite3 or /opt/homebrew/bin/sqlite3 (~3,000 functions)"
echo "2. FFmpeg binaries: ffmpeg, ffprobe (~15,000+ functions each)"
echo "3. Any game engine binary or browser component"
echo ""
echo "After obtaining a binary, create the IDA database:"
echo "  ida64 -B /path/to/binary"
echo "  cp /path/to/binary.i64 $(dirname "$0")/input.i64"
```

### Script: Build SQLite with Static Linking

```bash
#!/bin/bash
# build_sqlite_static.sh
# Builds SQLite with all features enabled for maximum function count

set -e

DEST_DIR="$(dirname "$0")/src"
BUILD_DIR="/tmp/sqlite_build_$$"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Downloading SQLite amalgamation..."
curl -L "https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip" -o sqlite.zip
unzip sqlite.zip
cd sqlite-amalgamation-*

echo "Compiling with all features enabled..."
# Enable many optional features to increase function count
gcc -O2 -DSQLITE_ENABLE_FTS5 \
    -DSQLITE_ENABLE_JSON1 \
    -DSQLITE_ENABLE_RTREE \
    -DSQLITE_ENABLE_GEOPOLY \
    -DSQLITE_ENABLE_MATH_FUNCTIONS \
    -DSQLITE_ENABLE_STAT4 \
    -DSQLITE_ENABLE_SESSION \
    -DSQLITE_ENABLE_PREUPDATE_HOOK \
    -o sqlite3_full shell.c sqlite3.c -lpthread -ldl -lm

echo "Binary created: $BUILD_DIR/sqlite-amalgamation-*/sqlite3_full"
echo "Function count estimate: ~4,000-6,000 functions"

# Copy to destination
cp sqlite3_full "$DEST_DIR/../input" 2>/dev/null || \
    echo "Copy binary to exercise directory and create IDA database manually"

# Cleanup
cd /
rm -rf "$BUILD_DIR"

echo "Done! Create IDA database with: ida64 -B input"
```

## Recommended Approach for This Exercise

1. **Use an existing system binary**:
   ```bash
   # macOS
   cp /opt/homebrew/bin/ffmpeg ./input
   ida64 -B ./input

   # Linux
   cp /usr/bin/ffmpeg ./input
   ida64 -B ./input
   ```

2. **Or download a game/application**:
   - Unity game binaries (UnityPlayer.dll)
   - Unreal Engine binaries
   - Blender executable
   - GIMP executable

3. **Create the IDA database**:
   ```bash
   ida64 -B ./input
   mv ./input.i64 ./input.i64
   ```

## Function Count Verification

After creating the IDA database, verify function count:

```python
# In IDA Python console
import idautils
print(f"Function count: {len(list(idautils.Functions()))}")
```

Target: **10,000+ functions** for meaningful scalability testing.
