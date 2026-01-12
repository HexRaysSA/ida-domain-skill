// Prototype reconstruction exercise binary
// Demonstrates varied function signatures, mixed types, and usage patterns
// that reveal type information when analyzing a stripped binary

const std = @import("std");

// ============================================================================
// SECTION 1: Functions with varied argument counts (0-6+)
// Using noinline to prevent optimization from merging functions
// ============================================================================

// No arguments - returns status code
noinline fn getStatus() i32 {
    return 42;
}

// One argument - int
noinline fn incrementValue(x: i32) i32 {
    return x + 1;
}

// Two arguments - pointer and size (buffer pattern)
noinline fn clearBuffer(ptr: [*]u8, size: usize) void {
    var i: usize = 0;
    while (i < size) : (i += 1) {
        ptr[i] = 0;
    }
}

// Three arguments - memcpy-like pattern
noinline fn copyData(dst: [*]u8, src: [*]const u8, len: usize) [*]u8 {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        dst[i] = src[i];
    }
    return dst;
}

// Four arguments - mixed types
noinline fn processRange(buffer: [*]u8, start: usize, end: usize, fill_value: u8) i32 {
    if (start >= end) return -1;
    var i: usize = start;
    while (i < end) : (i += 1) {
        buffer[i] = fill_value;
    }
    return @intCast(end - start);
}

// Five arguments - complex operation
noinline fn compareAndSwap(ptr: *i32, old_val: i32, new_val: i32, success_code: i32, fail_code: i32) i32 {
    if (ptr.* == old_val) {
        ptr.* = new_val;
        return success_code;
    }
    return fail_code;
}

// Six arguments - reaching register limit on x64 SysV / ARM64
noinline fn computeChecksum(data: [*]const u8, len: usize, seed: u32, poly: u32, init_val: u32, final_xor: u32) u32 {
    var result: u32 = init_val;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        result = (result +% @as(u32, data[i])) *% poly +% seed;
    }
    return result ^ final_xor;
}

// Seven arguments - some on stack (ARM64: x0-x7 are args, then stack)
noinline fn complexTransform(
    input: [*]const u8,
    output: [*]u8,
    len: usize,
    key: u32,
    iv: u32,
    flags: u32,
    mode: u32,
) i32 {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const byte_val: u32 = @as(u32, input[i]);
        const transformed = (byte_val ^ key) +% iv +% flags +% mode;
        output[i] = @truncate(transformed);
    }
    return @intCast(len);
}

// Eight arguments - definitely uses stack
noinline fn encryptBlock(
    input: [*]const u8,
    output: [*]u8,
    len: usize,
    key1: u32,
    key2: u32,
    iv1: u32,
    iv2: u32,
    rounds: u32,
) i32 {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        var val: u32 = @as(u32, input[i]);
        var r: u32 = 0;
        while (r < rounds) : (r += 1) {
            val = (val ^ key1) +% key2;
            val = (val ^ iv1) +% iv2;
        }
        output[i] = @truncate(val);
    }
    return @intCast(len);
}

// ============================================================================
// SECTION 2: Struct by value (passed in registers or stack depending on size)
// ============================================================================

const Point = extern struct {
    x: i32,
    y: i32,
};

const Rectangle = extern struct {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
};

const LargeStruct = extern struct {
    a: i64,
    b: i64,
    c: i64,
    d: i64,
};

// Small struct fits in registers
noinline fn addPoints(a: Point, b: Point) Point {
    return Point{
        .x = a.x + b.x,
        .y = a.y + b.y,
    };
}

// Larger struct behavior
noinline fn scaleRect(rect: Rectangle, factor: i32) Rectangle {
    return Rectangle{
        .x = rect.x * factor,
        .y = rect.y * factor,
        .width = rect.width * factor,
        .height = rect.height * factor,
    };
}

noinline fn rectArea(rect: Rectangle) i32 {
    return rect.width * rect.height;
}

// Very large struct - passed by reference on most ABIs
noinline fn sumLargeStruct(s: LargeStruct) i64 {
    return s.a + s.b + s.c + s.d;
}

// ============================================================================
// SECTION 3: Functions with pointer parameters (type inference from usage)
// ============================================================================

// strlen-like pattern - reveals string pointer type
noinline fn stringLength(str: [*:0]const u8) usize {
    var len: usize = 0;
    while (str[len] != 0) {
        len += 1;
    }
    return len;
}

// strcmp-like pattern
noinline fn stringCompare(s1: [*:0]const u8, s2: [*:0]const u8) i32 {
    var i: usize = 0;
    while (s1[i] != 0 and s2[i] != 0) {
        if (s1[i] < s2[i]) return -1;
        if (s1[i] > s2[i]) return 1;
        i += 1;
    }
    if (s1[i] == 0 and s2[i] == 0) return 0;
    if (s1[i] == 0) return -1;
    return 1;
}

// Pointer to int (dereferenced for comparison)
noinline fn isPositive(value_ptr: *const i32) i32 {
    return if (value_ptr.* > 0) 1 else 0;
}

// Double pointer (array of pointers)
noinline fn findInArray(arr: [*]const [*:0]const u8, count: usize, target: [*:0]const u8) i32 {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (stringCompare(arr[i], target) == 0) {
            return @intCast(i);
        }
    }
    return -1;
}

// ============================================================================
// SECTION 4: Return value variations
// ============================================================================

// Void return with side effects (prevents DCE)
var volatile_sink: u64 = 0;

noinline fn logMessage(msg: [*:0]const u8) void {
    // Side effect to prevent optimization
    volatile_sink +%= @intFromPtr(msg);
}

// Boolean return (used in conditionals)
noinline fn isValidRange(start: usize, end: usize, max: usize) i32 {
    return if (start < end and end <= max) 1 else 0;
}

// Pointer return (result used in subsequent operations)
noinline fn findChar(str: [*:0]const u8, c: u8) ?[*]const u8 {
    var i: usize = 0;
    while (str[i] != 0) {
        if (str[i] == c) {
            return str + i;
        }
        i += 1;
    }
    return null;
}

// ============================================================================
// SECTION 5: Helper for multiple call sites (same function, different contexts)
// ============================================================================

// Called from multiple sites with different argument patterns
noinline fn computeHash(data: [*]const u8, len: usize) u32 {
    var hash: u32 = 5381;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        hash = ((hash << 5) +% hash) +% @as(u32, data[i]);
    }
    return hash;
}

// Another multiply-called function
var static_buffer: [1024]u8 = undefined;

noinline fn allocateAndInit(size: usize, init_value: u8) ?[*]u8 {
    if (size > static_buffer.len) return null;

    var i: usize = 0;
    while (i < size) : (i += 1) {
        static_buffer[i] = init_value;
    }
    return &static_buffer;
}

// ============================================================================
// SECTION 6: More complex patterns for analysis
// ============================================================================

// memset-like pattern
noinline fn fillMemory(ptr: [*]u8, value: u8, count: usize) [*]u8 {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        ptr[i] = value;
    }
    return ptr;
}

// memcmp-like pattern
noinline fn compareMemory(p1: [*]const u8, p2: [*]const u8, len: usize) i32 {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (p1[i] < p2[i]) return -1;
        if (p1[i] > p2[i]) return 1;
    }
    return 0;
}

// Callback-like pattern (function pointer)
const CallbackFn = *const fn (i32, i32) i32;

noinline fn applyCallback(a: i32, b: i32, callback: CallbackFn) i32 {
    return callback(a, b);
}

noinline fn addInts(a: i32, b: i32) i32 {
    return a + b;
}

noinline fn mulInts(a: i32, b: i32) i32 {
    return a * b;
}

// ============================================================================
// MAIN: Exercise all functions to ensure they're not optimized away
// Uses volatile operations to prevent constant folding
// ============================================================================

var global_result: i64 = 0;

pub export fn main() i32 {
    // Use getStatus
    const status = getStatus();
    global_result +%= status;

    // Use incrementValue with runtime value to prevent constant folding
    const val = incrementValue(@as(i32, @truncate(global_result)));
    global_result +%= val;

    // Use clearBuffer
    var buf1: [64]u8 = undefined;
    for (&buf1) |*b| b.* = 0xFF;
    clearBuffer(&buf1, 32);
    global_result +%= buf1[0];

    // Use copyData
    var buf2: [64]u8 = undefined;
    const src_data: [*]const u8 = "Hello, World!";
    _ = copyData(&buf2, src_data, 13);
    global_result +%= buf2[0];

    // Use processRange
    var buf3: [128]u8 = undefined;
    const processed = processRange(&buf3, 10, 50, 'A');
    global_result +%= processed;

    // Use compareAndSwap
    var atomic_val: i32 = 100;
    const cas_result = compareAndSwap(&atomic_val, 100, 200, 1, 0);
    global_result +%= cas_result;

    // Use computeChecksum (6 args)
    const checksum_data: [*]const u8 = "test data for checksum";
    const checksum = computeChecksum(checksum_data, 22, 0x1234, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF);
    global_result +%= checksum;

    // Use complexTransform (7 args)
    var transform_output: [64]u8 = undefined;
    const transform_input: [*]const u8 = "input data";
    const transform_result = complexTransform(transform_input, &transform_output, 10, 0xDEAD, 0xBEEF, 0x01, 0x02);
    global_result +%= transform_result;

    // Use encryptBlock (8 args)
    var encrypt_output: [64]u8 = undefined;
    const encrypt_input: [*]const u8 = "secret";
    const encrypt_result = encryptBlock(encrypt_input, &encrypt_output, 6, 0x1111, 0x2222, 0x3333, 0x4444, 4);
    global_result +%= encrypt_result;

    // Use struct functions
    const p1 = Point{ .x = 10, .y = 20 };
    const p2 = Point{ .x = 5, .y = 15 };
    const p3 = addPoints(p1, p2);
    global_result +%= p3.x + p3.y;

    const rect = Rectangle{ .x = 0, .y = 0, .width = 100, .height = 50 };
    const scaled = scaleRect(rect, 2);
    const area = rectArea(rect);
    global_result +%= scaled.x + scaled.y + scaled.width + scaled.height + area;

    // Use large struct
    const large = LargeStruct{ .a = 1, .b = 2, .c = 3, .d = 4 };
    const large_sum = sumLargeStruct(large);
    global_result +%= large_sum;

    // Use string functions
    const test_str: [*:0]const u8 = "Hello";
    const len = stringLength(test_str);
    global_result +%= @as(i64, @intCast(len));

    const cmp = stringCompare("abc", "abd");
    global_result +%= cmp;

    // Use isPositive
    var pos_val: i32 = 42;
    var neg_val: i32 = -10;
    global_result +%= isPositive(&pos_val);
    global_result +%= isPositive(&neg_val);

    // Use findInArray
    const strings: [3][*:0]const u8 = .{ "apple", "banana", "cherry" };
    const found_idx = findInArray(&strings, 3, "banana");
    global_result +%= found_idx;

    // Use logMessage (void return)
    logMessage("This is a log message");

    // Use isValidRange
    const valid = isValidRange(10, 50, 100);
    global_result +%= valid;

    // Use findChar
    if (findChar("hello world", 'w')) |ptr| {
        global_result +%= @as(i64, @intCast(@intFromPtr(ptr)));
    }

    // Multiple calls to computeHash (different contexts)
    const hash1 = computeHash("first string", 12);
    const hash2 = computeHash("second", 6);
    const hash3 = computeHash(&buf1, 64);
    global_result +%= hash1;
    global_result +%= hash2;
    global_result +%= hash3;

    // Multiple calls to allocateAndInit
    if (allocateAndInit(100, 0)) |ptr| {
        global_result +%= @as(i64, @intCast(@intFromPtr(ptr)));
    }
    if (allocateAndInit(50, 0xFF)) |ptr| {
        global_result +%= @as(i64, @intCast(@intFromPtr(ptr)));
    }

    // Use fillMemory
    var buf4: [32]u8 = undefined;
    _ = fillMemory(&buf4, 0xAA, 32);
    global_result +%= buf4[0];

    // Use compareMemory
    const cmp_result = compareMemory(&buf1, &buf2, 16);
    global_result +%= cmp_result;

    // Use applyCallback with different callbacks
    const add_result = applyCallback(10, 20, &addInts);
    const mul_result = applyCallback(10, 20, &mulInts);
    global_result +%= add_result;
    global_result +%= mul_result;

    // Return something based on global_result
    return @truncate(global_result);
}
