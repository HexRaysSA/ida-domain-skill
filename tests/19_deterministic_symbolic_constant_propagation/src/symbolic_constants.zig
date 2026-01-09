// ============================================================================
// Symbolic Constant Propagation Test Binary
// ============================================================================
// This binary contains patterns that can be resolved through lightweight
// symbolic constant propagation:
// - Computed jump targets
// - Table lookups with known base and index
// - Simple decrypt loops with constant keys
// - String deobfuscation via arithmetic
// ============================================================================

// ----------------------------------------------------------------------------
// 1. Jump table with computable base and index
// ----------------------------------------------------------------------------
const jump_offsets = [_]i32{ 0x10, 0x20, 0x30, 0x40, 0x50 };

fn computedJumpDispatch(selector: u32) u32 {
    // The base address of jump_offsets is known (.rodata)
    // When selector is constant (0-4), the target is resolvable
    const base_value: u32 = 100;

    // Use inline assembly to create a computed jump pattern
    // that a symbolic evaluator can resolve
    var result: u32 = undefined;

    // Manual bounds check with computable condition
    if (selector < 5) {
        const offset = jump_offsets[selector];
        // Computed value: base + offset, both can be known
        result = base_value + @as(u32, @intCast(offset));
    } else {
        result = 0;
    }

    return result;
}

// ----------------------------------------------------------------------------
// 2. XOR decryption with constant key - strings
// ----------------------------------------------------------------------------
const xor_key: u8 = 0x42;
const encrypted_hello = [_]u8{
    'H' ^ xor_key, // 0x0A
    'e' ^ xor_key, // 0x27
    'l' ^ xor_key, // 0x2E
    'l' ^ xor_key, // 0x2E
    'o' ^ xor_key, // 0x2D
    0 ^ xor_key, // 0x42
};

fn decryptString(encrypted: []const u8, output: []u8, key: u8) void {
    // Key is passed as constant 0x42
    // Each byte XOR'd with known key produces known result
    for (encrypted, 0..) |byte, i| {
        if (i < output.len) {
            output[i] = byte ^ key;
        }
    }
}

// Wrapper that uses the constant key
var hello_buffer: [16]u8 = undefined;

fn getDecryptedHello() [*]const u8 {
    // Here key=0x42 is propagated, making decryption resolvable
    decryptString(&encrypted_hello, &hello_buffer, xor_key);
    return &hello_buffer;
}

// ----------------------------------------------------------------------------
// 3. Arithmetic string deobfuscation
// ----------------------------------------------------------------------------
const add_key: u8 = 7;
const obfuscated_world = [_]u8{
    'W' - add_key, // 80
    'o' - add_key, // 104
    'r' - add_key, // 107
    'l' - add_key, // 101
    'd' - add_key, // 93
    0,
};

fn deobfuscateAddition(obfuscated: []const u8, output: []u8, key: u8) void {
    // Add constant to each byte - fully resolvable
    for (obfuscated, 0..) |byte, i| {
        if (i < output.len) {
            output[i] = byte +% key;
        }
    }
}

var world_buffer: [16]u8 = undefined;

fn getDeobfuscatedWorld() [*]const u8 {
    deobfuscateAddition(&obfuscated_world, &world_buffer, add_key);
    return &world_buffer;
}

// ----------------------------------------------------------------------------
// 4. Computed function pointer from table
// ----------------------------------------------------------------------------
fn handler0() u32 {
    return 1000;
}
fn handler1() u32 {
    return 2000;
}
fn handler2() u32 {
    return 3000;
}
fn handler3() u32 {
    return 4000;
}

const HandlerFn = *const fn () u32;
const handler_table = [_]HandlerFn{
    handler0,
    handler1,
    handler2,
    handler3,
};

fn computedCallDispatch(index: u32) u32 {
    // When index is known constant, call target is resolvable
    // Base of handler_table is known (.data/.rodata)
    if (index < 4) {
        const handler = handler_table[index];
        return handler();
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 5. Multi-step constant computation
// ----------------------------------------------------------------------------
fn multiStepComputation(input: u32) u32 {
    // Each step produces a known value when input is known
    const step1 = input ^ 0xDEADBEEF; // XOR with known constant
    const step2 = step1 +% 0x12345678; // ADD known constant
    const step3 = step2 & 0xFFFF0000; // AND mask - result bounded
    const step4 = step3 >> 16; // SHR - extract high word

    // Final computed value used as table index
    const table_index = step4 & 0x3; // Only 4 possible values
    return handler_table[table_index]();
}

// ----------------------------------------------------------------------------
// 6. LEA-based address computation
// ----------------------------------------------------------------------------
const data_table = [_]u32{ 0x11111111, 0x22222222, 0x33333333, 0x44444444 };

fn leaComputation(base_offset: u32, scale: u32) u32 {
    // Simulates LEA [base + index*scale] pattern
    // When base_offset and scale are known, address is resolvable
    const computed_index = (base_offset *% scale) >> 4;
    const bounded_index = computed_index & 0x3;

    return data_table[bounded_index];
}

// ----------------------------------------------------------------------------
// 7. Rolling XOR decryption (loop with constant key schedule)
// ----------------------------------------------------------------------------
const rolling_key = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
const rolling_encrypted = [_]u8{
    'T' ^ 0x11, // E
    'e' ^ 0x22, // G
    's' ^ 0x33, // @
    't' ^ 0x44, // 0
};

fn rollingXorDecrypt(encrypted: []const u8, output: []u8) void {
    // Key schedule is constant, so each position is resolvable
    for (encrypted, 0..) |byte, i| {
        if (i < output.len) {
            const key_byte = rolling_key[i % rolling_key.len];
            output[i] = byte ^ key_byte;
        }
    }
}

var rolling_buffer: [16]u8 = undefined;

fn getRollingDecrypted() [*]const u8 {
    rollingXorDecrypt(&rolling_encrypted, &rolling_buffer);
    return &rolling_buffer;
}

// ----------------------------------------------------------------------------
// 8. Computed data pointer with offset
// ----------------------------------------------------------------------------
const magic_values = [_]u64{
    0xCAFEBABE00000000,
    0xDEADC0DE00000000,
    0xBAADF00D00000000,
    0xFEEDFACE00000000,
};

fn getComputedPointer(selector: u32, offset: u32) u64 {
    // Base pointer computed from table, then offset applied
    // Both are resolvable when arguments are constant
    if (selector < 4) {
        const base_value = magic_values[selector];
        const computed_value = base_value | @as(u64, offset);
        return computed_value;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 9. Switch-like dispatch with computed case values
// ----------------------------------------------------------------------------
fn switchDispatch(command: u32) u32 {
    // Each case value involves computation
    const base_cmd: u32 = 0x100;

    // Computed case values - analyzer can determine which branch
    const case_read = base_cmd + 1; // 0x101
    const case_write = base_cmd + 2; // 0x102
    const case_exec = base_cmd + 3; // 0x103
    const case_close = base_cmd + 4; // 0x104

    if (command == case_read) {
        return 10;
    } else if (command == case_write) {
        return 20;
    } else if (command == case_exec) {
        return 30;
    } else if (command == case_close) {
        return 40;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 10. Nested table lookup
// ----------------------------------------------------------------------------
const outer_indices = [_]u32{ 2, 0, 3, 1 };
const inner_values = [_]u32{ 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD };

fn nestedTableLookup(selector: u32) u32 {
    // Two-level indirection, but both tables are in .rodata
    // First lookup gives index, second gives value
    if (selector < 4) {
        const intermediate = outer_indices[selector];
        if (intermediate < 4) {
            return inner_values[intermediate];
        }
    }
    return 0;
}

// ----------------------------------------------------------------------------
// Main function to exercise all patterns
// ----------------------------------------------------------------------------
// Volatile to prevent optimization
var volatile_result: u64 = 0;

fn doNotOptimize(value: anytype) void {
    @as(*volatile @TypeOf(value), @ptrCast(@constCast(&value))).* = value;
}

pub fn main() void {
    // Test computed jump dispatch
    const jump_result = computedJumpDispatch(2);
    doNotOptimize(jump_result);

    // Test XOR decryption
    const hello_ptr = getDecryptedHello();
    doNotOptimize(hello_ptr);

    // Test addition deobfuscation
    const world_ptr = getDeobfuscatedWorld();
    doNotOptimize(world_ptr);

    // Test computed call dispatch
    const call_result = computedCallDispatch(1);
    doNotOptimize(call_result);

    // Test multi-step computation
    const multi_result = multiStepComputation(0x12345678);
    doNotOptimize(multi_result);

    // Test LEA computation
    const lea_result = leaComputation(0x10, 4);
    doNotOptimize(lea_result);

    // Test rolling XOR
    const rolling_ptr = getRollingDecrypted();
    doNotOptimize(rolling_ptr);

    // Test computed pointer
    const ptr_result = getComputedPointer(1, 0xABCD);
    doNotOptimize(ptr_result);

    // Test switch dispatch
    const switch_result = switchDispatch(0x102);
    doNotOptimize(switch_result);

    // Test nested lookup
    const nested_result = nestedTableLookup(0);
    doNotOptimize(nested_result);

    // Store final result to prevent dead code elimination
    volatile_result = @as(u64, jump_result) +
        @as(u64, call_result) +
        @as(u64, multi_result) +
        @as(u64, lea_result) +
        ptr_result +
        @as(u64, switch_result) +
        @as(u64, nested_result);
}

// Export functions for analysis
pub export fn test_jump_dispatch(sel: u32) u32 {
    return computedJumpDispatch(sel);
}

pub export fn test_call_dispatch(idx: u32) u32 {
    return computedCallDispatch(idx);
}

pub export fn test_multi_step(inp: u32) u32 {
    return multiStepComputation(inp);
}

pub export fn test_lea_compute(base: u32, scale: u32) u32 {
    return leaComputation(base, scale);
}

pub export fn test_switch(cmd: u32) u32 {
    return switchDispatch(cmd);
}

pub export fn test_nested(sel: u32) u32 {
    return nestedTableLookup(sel);
}

pub export fn test_computed_ptr(sel: u32, off: u32) u64 {
    return getComputedPointer(sel, off);
}

pub export fn test_xor_decrypt() [*]const u8 {
    return getDecryptedHello();
}

pub export fn test_add_deobfuscate() [*]const u8 {
    return getDeobfuscatedWorld();
}

pub export fn test_rolling_xor() [*]const u8 {
    return getRollingDecrypted();
}
