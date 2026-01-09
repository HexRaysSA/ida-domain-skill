const std = @import("std");

// ============================================================================
// CONTROL-FLOW FLATTENING EXAMPLE
// This file contains manually flattened functions that exhibit the classic
// dispatcher loop pattern used by obfuscators like Tigress and OLLVM.
//
// Pattern characteristics:
// - Single entry dispatcher block with while loop
// - State variable controlling flow (typically an integer)
// - All original basic blocks as switch cases
// - State transitions replace normal control flow
// ============================================================================

// Global state to prevent compiler optimization
var global_accumulator: i64 = 0;
var global_buffer: [256]u8 = undefined;

// ============================================================================
// FLATTENED FUNCTION 1: Simple if-else chain (3 original blocks -> 5 states)
//
// Original logic:
//   if (x > 10) { result = x * 2; }
//   else { result = x + 5; }
//   return result + 1;
//
// Flattened into dispatcher with states:
//   0: entry - check condition
//   1: true branch
//   2: false branch
//   3: merge point
//   255: exit
// ============================================================================
fn flattened_simple_branch(x: i32) i32 {
    var state: u8 = 0;
    var result: i32 = 0;

    // Dispatcher loop - classic flattening pattern
    while (state != 255) {
        switch (state) {
            0 => {
                // Entry block: evaluate condition
                if (x > 10) {
                    state = 1; // True branch
                } else {
                    state = 2; // False branch
                }
            },
            1 => {
                // True branch: x > 10
                result = x * 2;
                state = 3; // Go to merge
            },
            2 => {
                // False branch: x <= 10
                result = x + 5;
                state = 3; // Go to merge
            },
            3 => {
                // Merge point: add 1 and exit
                result = result + 1;
                state = 255; // Exit
            },
            else => {
                state = 255; // Safety exit
            },
        }
    }

    return result;
}

// ============================================================================
// FLATTENED FUNCTION 2: Nested conditionals (more complex CFG)
//
// Original logic:
//   if (a > 0) {
//       if (b > 0) { result = a + b; }
//       else { result = a - b; }
//   } else {
//       if (b > 0) { result = b - a; }
//       else { result = -(a + b); }
//   }
//   return result * 2;
//
// States:
//   0: entry - check a
//   1: a > 0, check b
//   2: a <= 0, check b
//   3: a > 0 && b > 0
//   4: a > 0 && b <= 0
//   5: a <= 0 && b > 0
//   6: a <= 0 && b <= 0
//   7: final computation
//   255: exit
// ============================================================================
fn flattened_nested_conditionals(a: i32, b: i32) i32 {
    var state: u8 = 0;
    var result: i32 = 0;

    // Dispatcher loop
    while (state != 255) {
        switch (state) {
            0 => {
                // Entry: check first condition
                if (a > 0) {
                    state = 1;
                } else {
                    state = 2;
                }
            },
            1 => {
                // a > 0: check second condition
                if (b > 0) {
                    state = 3;
                } else {
                    state = 4;
                }
            },
            2 => {
                // a <= 0: check second condition
                if (b > 0) {
                    state = 5;
                } else {
                    state = 6;
                }
            },
            3 => {
                // a > 0 && b > 0
                result = a + b;
                state = 7;
            },
            4 => {
                // a > 0 && b <= 0
                result = a - b;
                state = 7;
            },
            5 => {
                // a <= 0 && b > 0
                result = b - a;
                state = 7;
            },
            6 => {
                // a <= 0 && b <= 0
                result = -(a + b);
                state = 7;
            },
            7 => {
                // Final computation
                result = result * 2;
                state = 255;
            },
            else => {
                state = 255;
            },
        }
    }

    return result;
}

// ============================================================================
// FLATTENED FUNCTION 3: Loop with early exit (while loop flattening)
//
// Original logic:
//   sum = 0;
//   i = 0;
//   while (i < n) {
//       if (data[i] == 0) break;
//       sum += data[i];
//       i++;
//   }
//   return sum;
//
// States:
//   0: initialization
//   1: loop condition check
//   2: early exit check (data[i] == 0)
//   3: loop body (accumulate)
//   4: loop increment
//   5: loop exit / return
//   255: exit
// ============================================================================
fn flattened_loop_with_break(data: []const u8, n: usize) u32 {
    var state: u8 = 0;
    var sum: u32 = 0;
    var i: usize = 0;
    const limit = @min(n, data.len);

    // Dispatcher loop
    while (state != 255) {
        switch (state) {
            0 => {
                // Initialization
                sum = 0;
                i = 0;
                state = 1; // Go to loop condition
            },
            1 => {
                // Loop condition: i < limit
                if (i < limit) {
                    state = 2; // Check early exit
                } else {
                    state = 5; // Exit loop
                }
            },
            2 => {
                // Early exit check: data[i] == 0
                if (data[i] == 0) {
                    state = 5; // Break out
                } else {
                    state = 3; // Continue to body
                }
            },
            3 => {
                // Loop body: accumulate
                sum += data[i];
                state = 4; // Go to increment
            },
            4 => {
                // Loop increment
                i += 1;
                state = 1; // Back to condition
            },
            5 => {
                // Loop exit
                state = 255;
            },
            else => {
                state = 255;
            },
        }
    }

    return sum;
}

// ============================================================================
// FLATTENED FUNCTION 4: State machine (already naturally suited for flattening)
// This simulates a simple protocol parser with multiple states.
//
// States:
//   0: IDLE - waiting for start byte
//   1: HEADER - reading header
//   2: LENGTH - reading length byte
//   3: DATA - reading data bytes
//   4: CHECKSUM - verifying checksum
//   5: COMPLETE - packet complete
//   6: ERROR - invalid packet
//   255: exit
// ============================================================================
const START_BYTE: u8 = 0xAA;
const END_BYTE: u8 = 0x55;

fn flattened_protocol_parser(packet: []const u8) i32 {
    var state: u8 = 0;
    var idx: usize = 0;
    var expected_len: u8 = 0;
    var data_count: u8 = 0;
    var checksum: u8 = 0;
    var result: i32 = 0;

    // Dispatcher loop
    while (state != 255) {
        switch (state) {
            0 => {
                // IDLE: look for start byte
                if (idx >= packet.len) {
                    result = -1; // No start found
                    state = 6;
                } else if (packet[idx] == START_BYTE) {
                    checksum = packet[idx];
                    idx += 1;
                    state = 1; // Go to HEADER
                } else {
                    idx += 1;
                    state = 0; // Stay in IDLE
                }
            },
            1 => {
                // HEADER: validate header byte
                if (idx >= packet.len) {
                    result = -2;
                    state = 6;
                } else if (packet[idx] >= 0x01 and packet[idx] <= 0x0F) {
                    checksum ^= packet[idx];
                    idx += 1;
                    state = 2; // Go to LENGTH
                } else {
                    result = -3;
                    state = 6;
                }
            },
            2 => {
                // LENGTH: read length byte
                if (idx >= packet.len) {
                    result = -4;
                    state = 6;
                } else {
                    expected_len = packet[idx];
                    checksum ^= packet[idx];
                    data_count = 0;
                    idx += 1;
                    if (expected_len == 0) {
                        state = 4; // Skip to checksum
                    } else {
                        state = 3; // Go to DATA
                    }
                }
            },
            3 => {
                // DATA: read data bytes
                if (idx >= packet.len) {
                    result = -5;
                    state = 6;
                } else {
                    checksum ^= packet[idx];
                    data_count += 1;
                    idx += 1;
                    if (data_count >= expected_len) {
                        state = 4; // Go to CHECKSUM
                    } else {
                        state = 3; // Stay in DATA
                    }
                }
            },
            4 => {
                // CHECKSUM: verify
                if (idx >= packet.len) {
                    result = -6;
                    state = 6;
                } else {
                    if (packet[idx] == checksum) {
                        result = @as(i32, data_count); // Success: return data length
                        state = 5;
                    } else {
                        result = -7; // Checksum mismatch
                        state = 6;
                    }
                }
            },
            5 => {
                // COMPLETE
                state = 255;
            },
            6 => {
                // ERROR
                state = 255;
            },
            else => {
                state = 255;
            },
        }
    }

    return result;
}

// ============================================================================
// FLATTENED FUNCTION 5: Computation with multiple phases
// Simulates a hash-like computation with initialization, rounds, and finalization.
//
// Original structure:
//   init phase
//   for each round (4 rounds):
//       mix operations
//   finalization
//   return hash
//
// States:
//   0: initialization
//   1: round check
//   2: round mix step 1
//   3: round mix step 2
//   4: round mix step 3
//   5: round increment
//   6: finalization
//   255: exit
// ============================================================================
fn flattened_hash_computation(input: u32) u32 {
    var state: u8 = 0;
    var hash: u32 = 0;
    var round: u32 = 0;
    const rounds: u32 = 4;
    const magic1: u32 = 0x5A827999;
    const magic2: u32 = 0x6ED9EBA1;
    const magic3: u32 = 0x8F1BBCDC;

    // Dispatcher loop
    while (state != 255) {
        switch (state) {
            0 => {
                // Initialization
                hash = input ^ 0xDEADBEEF;
                round = 0;
                state = 1;
            },
            1 => {
                // Round check
                if (round < rounds) {
                    state = 2;
                } else {
                    state = 6;
                }
            },
            2 => {
                // Mix step 1: rotate and XOR
                hash = std.math.rotl(u32, hash, 5) ^ magic1;
                state = 3;
            },
            3 => {
                // Mix step 2: add round constant
                hash = hash +% (round *% magic2);
                state = 4;
            },
            4 => {
                // Mix step 3: another transform
                hash = (hash ^ (hash >> 11)) +% magic3;
                state = 5;
            },
            5 => {
                // Round increment
                round += 1;
                state = 1;
            },
            6 => {
                // Finalization
                hash = hash ^ (hash >> 16);
                hash = hash *% 0x85EBCA6B;
                hash = hash ^ (hash >> 13);
                state = 255;
            },
            else => {
                state = 255;
            },
        }
    }

    return hash;
}

// ============================================================================
// FLATTENED FUNCTION 6: String processing with multiple operations
// Demonstrates more complex control flow with nested loops.
//
// Original:
//   count = 0
//   for each char c in str:
//       if is_uppercase(c):
//           count++
//       elif is_digit(c):
//           count += 2
//   return count
//
// States:
//   0: init
//   1: loop condition
//   2: check uppercase
//   3: check digit
//   4: increment for uppercase
//   5: increment for digit
//   6: next iteration
//   7: return
//   255: exit
// ============================================================================
fn flattened_char_counter(str: []const u8) u32 {
    var state: u8 = 0;
    var count: u32 = 0;
    var i: usize = 0;
    var current_char: u8 = 0;

    // Dispatcher loop
    while (state != 255) {
        switch (state) {
            0 => {
                // Init
                count = 0;
                i = 0;
                state = 1;
            },
            1 => {
                // Loop condition
                if (i < str.len) {
                    current_char = str[i];
                    state = 2;
                } else {
                    state = 7;
                }
            },
            2 => {
                // Check uppercase (A-Z: 65-90)
                if (current_char >= 'A' and current_char <= 'Z') {
                    state = 4;
                } else {
                    state = 3;
                }
            },
            3 => {
                // Check digit (0-9: 48-57)
                if (current_char >= '0' and current_char <= '9') {
                    state = 5;
                } else {
                    state = 6;
                }
            },
            4 => {
                // Increment for uppercase
                count += 1;
                state = 6;
            },
            5 => {
                // Increment for digit
                count += 2;
                state = 6;
            },
            6 => {
                // Next iteration
                i += 1;
                state = 1;
            },
            7 => {
                // Return
                state = 255;
            },
            else => {
                state = 255;
            },
        }
    }

    return count;
}

// ============================================================================
// UTILITY FUNCTIONS (non-flattened for comparison)
// ============================================================================

fn simple_checksum(data: []const u8) u8 {
    var sum: u8 = 0;
    for (data) |byte| {
        sum ^= byte;
    }
    return sum;
}

fn reverse_bytes(buf: []u8) void {
    var left: usize = 0;
    var right: usize = buf.len;
    while (left < right) {
        right -= 1;
        const tmp = buf[left];
        buf[left] = buf[right];
        buf[right] = tmp;
        left += 1;
    }
}

// ============================================================================
// MAIN FUNCTION - Exercise all flattened functions
// ============================================================================

pub fn main() void {
    std.debug.print("=== Control-Flow Flattening Test Program ===\n\n", .{});

    // Test flattened_simple_branch
    std.debug.print("1. Simple Branch (flattened):\n", .{});
    std.debug.print("   f(5)  = {}\n", .{flattened_simple_branch(5)});
    std.debug.print("   f(15) = {}\n", .{flattened_simple_branch(15)});
    std.debug.print("   f(10) = {}\n\n", .{flattened_simple_branch(10)});

    // Test flattened_nested_conditionals
    std.debug.print("2. Nested Conditionals (flattened):\n", .{});
    std.debug.print("   f(5, 3)   = {}\n", .{flattened_nested_conditionals(5, 3)});
    std.debug.print("   f(5, -3)  = {}\n", .{flattened_nested_conditionals(5, -3)});
    std.debug.print("   f(-5, 3)  = {}\n", .{flattened_nested_conditionals(-5, 3)});
    std.debug.print("   f(-5, -3) = {}\n\n", .{flattened_nested_conditionals(-5, -3)});

    // Test flattened_loop_with_break
    std.debug.print("3. Loop with Break (flattened):\n", .{});
    const data1 = [_]u8{ 1, 2, 3, 4, 5 };
    const data2 = [_]u8{ 1, 2, 0, 4, 5 };
    std.debug.print("   sum([1,2,3,4,5]) = {}\n", .{flattened_loop_with_break(&data1, 5)});
    std.debug.print("   sum([1,2,0,4,5]) = {} (early break)\n\n", .{flattened_loop_with_break(&data2, 5)});

    // Test flattened_protocol_parser
    std.debug.print("4. Protocol Parser (flattened):\n", .{});
    // Valid packet: START(0xAA) + HEADER(0x01) + LEN(3) + DATA(0x10,0x20,0x30) + CHECKSUM
    const valid_packet = [_]u8{ 0xAA, 0x01, 0x03, 0x10, 0x20, 0x30, 0xAA ^ 0x01 ^ 0x03 ^ 0x10 ^ 0x20 ^ 0x30 };
    const invalid_packet = [_]u8{ 0xAA, 0x01, 0x02, 0x10, 0x20, 0xFF }; // Bad checksum
    std.debug.print("   parse(valid)   = {}\n", .{flattened_protocol_parser(&valid_packet)});
    std.debug.print("   parse(invalid) = {}\n\n", .{flattened_protocol_parser(&invalid_packet)});

    // Test flattened_hash_computation
    std.debug.print("5. Hash Computation (flattened):\n", .{});
    std.debug.print("   hash(0x12345678) = 0x{X:0>8}\n", .{flattened_hash_computation(0x12345678)});
    std.debug.print("   hash(0xDEADBEEF) = 0x{X:0>8}\n", .{flattened_hash_computation(0xDEADBEEF)});
    std.debug.print("   hash(0x00000000) = 0x{X:0>8}\n\n", .{flattened_hash_computation(0x00000000)});

    // Test flattened_char_counter
    std.debug.print("6. Char Counter (flattened):\n", .{});
    std.debug.print("   count(\"Hello123\") = {}\n", .{flattened_char_counter("Hello123")});
    std.debug.print("   count(\"ABC\")      = {}\n", .{flattened_char_counter("ABC")});
    std.debug.print("   count(\"abc\")      = {}\n", .{flattened_char_counter("abc")});
    std.debug.print("   count(\"12345\")    = {}\n\n", .{flattened_char_counter("12345")});

    std.debug.print("=== All tests completed ===\n", .{});
}

// ============================================================================
// TESTS
// ============================================================================

test "simple_branch" {
    try std.testing.expectEqual(@as(i32, 11), flattened_simple_branch(5));
    try std.testing.expectEqual(@as(i32, 31), flattened_simple_branch(15));
    try std.testing.expectEqual(@as(i32, 16), flattened_simple_branch(10));
}

test "nested_conditionals" {
    // a > 0, b > 0: (a + b) * 2 = (5 + 3) * 2 = 16
    try std.testing.expectEqual(@as(i32, 16), flattened_nested_conditionals(5, 3));
    // a > 0, b <= 0: (a - b) * 2 = (5 - (-3)) * 2 = 16
    try std.testing.expectEqual(@as(i32, 16), flattened_nested_conditionals(5, -3));
    // a <= 0, b > 0: (b - a) * 2 = (3 - (-5)) * 2 = 16
    try std.testing.expectEqual(@as(i32, 16), flattened_nested_conditionals(-5, 3));
    // a <= 0, b <= 0: -(a + b) * 2 = -(-5 + -3) * 2 = -(-8) * 2 = 16
    try std.testing.expectEqual(@as(i32, 16), flattened_nested_conditionals(-5, -3));
}

test "loop_with_break" {
    const data1 = [_]u8{ 1, 2, 3, 4, 5 };
    const data2 = [_]u8{ 1, 2, 0, 4, 5 };
    try std.testing.expectEqual(@as(u32, 15), flattened_loop_with_break(&data1, 5));
    try std.testing.expectEqual(@as(u32, 3), flattened_loop_with_break(&data2, 5));
}

test "hash_computation" {
    // Just verify it produces consistent results
    const h1 = flattened_hash_computation(0x12345678);
    const h2 = flattened_hash_computation(0x12345678);
    try std.testing.expectEqual(h1, h2);
}

test "char_counter" {
    try std.testing.expectEqual(@as(u32, 7), flattened_char_counter("Hello123")); // H + 1*2 + 2*2 + 3*2 = 1 + 6 = 7
    try std.testing.expectEqual(@as(u32, 3), flattened_char_counter("ABC"));
    try std.testing.expectEqual(@as(u32, 0), flattened_char_counter("abc"));
    try std.testing.expectEqual(@as(u32, 10), flattened_char_counter("12345"));
}
