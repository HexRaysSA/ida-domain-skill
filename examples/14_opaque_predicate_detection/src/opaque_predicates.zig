// Opaque Predicate Detection Exercise
// This file contains various opaque predicates for reverse engineering practice.
//
// IMPORTANT: Zig's optimizer is very aggressive. To preserve opaque predicates:
// - Compile with: zig build-exe -O ReleaseSafe (not ReleaseFast)
// - Or use: zig build-exe -O Debug for guaranteed preservation
// - The volatile operations help prevent some optimizations
//
// For truly robust opaque predicates, consider:
// - Tigress obfuscator (http://tigress.cs.arizona.edu/)
// - Manual assembly insertion
// - LLVM obfuscator passes

const std = @import("std");
const posix = std.posix;

// Global volatile variable to prevent compile-time evaluation
var global_runtime_value: i32 = 0;

// Helper to get a runtime value that compiler cannot predict
fn getVolatileValue() i32 {
    const ptr: *volatile i32 = @ptrCast(&global_runtime_value);
    return ptr.*;
}

fn setVolatileValue(v: i32) void {
    const ptr: *volatile i32 = @ptrCast(&global_runtime_value);
    ptr.* = v;
}

// Prevent dead code elimination
fn blackhole(x: anytype) void {
    const ptr: *volatile @TypeOf(x) = @constCast(@ptrCast(&x));
    _ = ptr.*;
}

// Simple print helper for Zig 0.15
fn printNumber(prefix: []const u8, num: i64) void {
    _ = posix.write(1, prefix) catch {};
    var buf: [32]u8 = undefined;
    var n: u64 = if (num < 0) @intCast(-num) else @intCast(num);
    var i: usize = buf.len;

    if (n == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (n > 0) {
            i -= 1;
            buf[i] = @intCast('0' + (n % 10));
            n /= 10;
        }
    }
    if (num < 0) {
        i -= 1;
        buf[i] = '-';
    }
    _ = posix.write(1, buf[i..]) catch {};
    _ = posix.write(1, "\n") catch {};
}

// ============================================================================
// OPAQUE PREDICATE 1: x * x >= 0 (always true for any integer due to unsigned result)
// Actually for signed integers this can overflow, but x^2 is always non-negative
// in mathematical terms. Using unsigned to guarantee the property.
// ============================================================================
fn opaquePredicate1(input: u32) u32 {
    const x = input;
    const x_squared = x *% x; // Wrapping multiplication

    // OPAQUE: x*x is always >= 0 for unsigned (trivially true)
    // This branch is ALWAYS taken
    if (x_squared >= 0) {
        return input + 1;
    } else {
        // Dead code - never reached
        return 0xDEADBEEF;
    }
}

// ============================================================================
// OPAQUE PREDICATE 2: x ^ x == 0 (always true, XOR of any value with itself is 0)
// ============================================================================
fn opaquePredicate2(input: i32) i32 {
    const x = input + getVolatileValue();

    // OPAQUE: x XOR x is always 0
    // This branch is ALWAYS taken
    if ((x ^ x) == 0) {
        return input * 2;
    } else {
        // Dead code - never reached
        return 0x0BADF00D;
    }
}

// ============================================================================
// OPAQUE PREDICATE 3: (x | 1) != 0 (always true, OR with 1 always sets bit 0)
// ============================================================================
fn opaquePredicate3(input: u32) u32 {
    const x = input;

    // OPAQUE: (x | 1) is never zero because bit 0 is always set
    // This branch is ALWAYS taken
    if ((x | 1) != 0) {
        return input + 42;
    } else {
        // Dead code - never reached
        return 0xCAFEBABE;
    }
}

// ============================================================================
// OPAQUE PREDICATE 4: x - x == 0 (always true)
// ============================================================================
fn opaquePredicate4(input: i32) i32 {
    const x = input +% getVolatileValue();

    // OPAQUE: x - x is always 0
    // This branch is ALWAYS taken
    if ((x -% x) == 0) {
        return input + 100;
    } else {
        // Dead code - never reached
        return @bitCast(@as(u32, 0xFEEDFACE));
    }
}

// ============================================================================
// OPAQUE PREDICATE 5: (x & 0) == 0 (always true, AND with 0 is always 0)
// ============================================================================
fn opaquePredicate5(input: u32) u32 {
    const x = input;

    // OPAQUE: x AND 0 is always 0
    // This branch is ALWAYS taken
    if ((x & 0) == 0) {
        return input ^ 0xFF;
    } else {
        // Dead code - never reached
        return 0xBADCAFE;
    }
}

// ============================================================================
// OPAQUE PREDICATE 6: x * 0 == 0 (always true)
// ============================================================================
fn opaquePredicate6(input: i32) i32 {
    const x = input +% getVolatileValue();

    // OPAQUE: x * 0 is always 0
    // This branch is ALWAYS taken
    if ((x *% 0) == 0) {
        return input -% 50;
    } else {
        // Dead code - never reached
        return @bitCast(@as(u32, 0xDEADC0DE));
    }
}

// ============================================================================
// OPAQUE PREDICATE 7: (x | x) == x (always true, OR with self is identity)
// ============================================================================
fn opaquePredicate7(input: u32) u32 {
    const x = input;

    // OPAQUE: x OR x equals x (idempotent property)
    // This branch is ALWAYS taken
    if ((x | x) == x) {
        return input << 1;
    } else {
        // Dead code - never reached
        return 0xC0FFEE;
    }
}

// ============================================================================
// OPAQUE PREDICATE 8: x == x (trivially always true)
// ============================================================================
fn opaquePredicate8(input: i32) i32 {
    const x = input +% getVolatileValue();

    // OPAQUE: x equals x (reflexive property)
    // This branch is ALWAYS taken
    if (x == x) {
        return input +% 77;
    } else {
        // Dead code - never reached
        return @bitCast(@as(u32, 0xFACEFEED));
    }
}

// ============================================================================
// OPAQUE PREDICATE 9: 2 * x == x + x (always true, distributive property)
// ============================================================================
fn opaquePredicate9(input: i32) i32 {
    const x = input +% getVolatileValue();

    // OPAQUE: 2*x equals x+x (always true mathematically)
    // This branch is ALWAYS taken
    if ((2 *% x) == (x +% x)) {
        return input ^ 0xAA;
    } else {
        // Dead code - never reached
        return @bitCast(@as(u32, 0xABADBABE));
    }
}

// ============================================================================
// OPAQUE PREDICATE 10: (x & x) == x (always true, AND with self is identity)
// ============================================================================
fn opaquePredicate10(input: u32) u32 {
    const x = input;

    // OPAQUE: x AND x equals x (idempotent property)
    // This branch is ALWAYS taken
    if ((x & x) == x) {
        return input >> 1;
    } else {
        // Dead code - never reached
        return 0xBAADF00D;
    }
}

// ============================================================================
// OPAQUE PREDICATE 11: x * (x + 1) is always even (always true)
// For any integer x, either x or x+1 is even, so product is divisible by 2
// ============================================================================
fn opaquePredicate11(input: i32) i32 {
    const x = input +% getVolatileValue();
    const product = x *% (x +% 1);

    // OPAQUE: x*(x+1) is always even, so (product & 1) == 0
    // This branch is ALWAYS taken
    if ((product & 1) == 0) {
        return input +% 33;
    } else {
        // Dead code - never reached
        return 0xDEFACED;
    }
}

// ============================================================================
// OPAQUE PREDICATE 12: ~(x ^ ~x) == 0 (always true)
// x XOR ~x gives all 1s, NOT of that is all 0s
// ============================================================================
fn opaquePredicate12(input: u32) u32 {
    const x = input;

    // OPAQUE: ~(x ^ ~x) is always 0
    // This branch is ALWAYS taken
    if (~(x ^ ~x) == 0) {
        return input +% 999;
    } else {
        // Dead code - never reached
        return 0xB16B00B5;
    }
}

// ============================================================================
// OPAQUE PREDICATE 13: Always-FALSE predicate (x != x)
// ============================================================================
fn opaquePredicate13(input: i32) i32 {
    const x = input +% getVolatileValue();

    // OPAQUE: x != x is always false (x always equals itself)
    // This branch is NEVER taken
    if (x != x) {
        // Dead code - never reached
        return 0xDEAD;
    } else {
        return input +% 1;
    }
}

// ============================================================================
// OPAQUE PREDICATE 14: Always-FALSE predicate ((x ^ x) != 0)
// ============================================================================
fn opaquePredicate14(input: u32) u32 {
    const x = input;

    // OPAQUE: x XOR x is always 0, so this is always false
    // This branch is NEVER taken
    if ((x ^ x) != 0) {
        // Dead code - never reached
        return 0xBEEF;
    } else {
        return input +% 2;
    }
}

// ============================================================================
// OPAQUE PREDICATE 15: Complex identity (x + y) - y == x (always true)
// ============================================================================
fn opaquePredicate15(input: i32) i32 {
    const x = input +% getVolatileValue();
    const y: i32 = 12345;

    // OPAQUE: (x + y) - y simplifies to x, so this is always true
    // This branch is ALWAYS taken
    if (((x +% y) -% y) == x) {
        return input ^ 0x55;
    } else {
        // Dead code - never reached
        return @bitCast(@as(u32, 0xFEEDBEEF));
    }
}

// Main function that chains all opaque predicates
pub fn main() !void {
    // Get initial value from command line or use default
    var args = std.process.args();
    _ = args.skip(); // Skip program name

    var input_value: i32 = 42;
    if (args.next()) |arg| {
        input_value = std.fmt.parseInt(i32, arg, 10) catch 42;
    }

    // Set the global volatile value
    setVolatileValue(input_value);

    var result: i64 = 0;

    // Call all opaque predicate functions
    result += opaquePredicate1(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate2(input_value);
    result += opaquePredicate3(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate4(input_value);
    result += opaquePredicate5(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate6(input_value);
    result += opaquePredicate7(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate8(input_value);
    result += opaquePredicate9(input_value);
    result += opaquePredicate10(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate11(input_value);
    result += opaquePredicate12(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate13(input_value);
    result += opaquePredicate14(@intCast(@as(u32, @bitCast(input_value))));
    result += opaquePredicate15(input_value);

    printNumber("Input: ", input_value);
    printNumber("Result: ", result);

    // Ensure result is used
    blackhole(result);
}
