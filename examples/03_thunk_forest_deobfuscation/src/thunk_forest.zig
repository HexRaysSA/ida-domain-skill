// Thunk Forest Binary - Heavy indirection patterns for IDA analysis exercise
//
// This binary demonstrates various thunking patterns:
// - Simple jmp-only thunks (via naked functions)
// - Tail-call optimized wrappers (via @call(.always_tail, ...))
// - Multi-level indirection (3-4 levels deep)
// - Indirect jumps through function pointer tables (GOT/IAT style)

const std = @import("std");

// ============================================================================
// Ultimate target functions (the final destinations)
// ============================================================================

export fn ultimate_add(a: i32, b: i32) i32 {
    return a + b;
}

export fn ultimate_multiply(a: i32, b: i32) i32 {
    return a * b;
}

export fn ultimate_subtract(a: i32, b: i32) i32 {
    return a - b;
}

export fn ultimate_divide(a: i32, b: i32) i32 {
    if (b == 0) return 0;
    return @divTrunc(a, b);
}

export fn ultimate_print_value(val: i32) void {
    std.debug.print("Value: {d}\n", .{val});
}

export fn ultimate_noop() void {
    // Intentionally empty
}

// ============================================================================
// Level 3 thunks - Tail call wrappers (one level above ultimate)
// ============================================================================

export fn thunk_level3_add(a: i32, b: i32) i32 {
    return @call(.always_tail, ultimate_add, .{ a, b });
}

export fn thunk_level3_multiply(a: i32, b: i32) i32 {
    return @call(.always_tail, ultimate_multiply, .{ a, b });
}

export fn thunk_level3_subtract(a: i32, b: i32) i32 {
    return @call(.always_tail, ultimate_subtract, .{ a, b });
}

export fn thunk_level3_divide(a: i32, b: i32) i32 {
    return @call(.always_tail, ultimate_divide, .{ a, b });
}

export fn thunk_level3_print(val: i32) void {
    return @call(.always_tail, ultimate_print_value, .{val});
}

export fn thunk_level3_noop() void {
    return @call(.always_tail, ultimate_noop, .{});
}

// ============================================================================
// Level 2 thunks - More indirection
// ============================================================================

export fn thunk_level2_add(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level3_add, .{ a, b });
}

export fn thunk_level2_multiply(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level3_multiply, .{ a, b });
}

export fn thunk_level2_subtract(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level3_subtract, .{ a, b });
}

export fn thunk_level2_divide(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level3_divide, .{ a, b });
}

export fn thunk_level2_print(val: i32) void {
    return @call(.always_tail, thunk_level3_print, .{val});
}

export fn thunk_level2_noop() void {
    return @call(.always_tail, thunk_level3_noop, .{});
}

// ============================================================================
// Level 1 thunks - Entry points for the thunk chains
// ============================================================================

export fn thunk_level1_add(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level2_add, .{ a, b });
}

export fn thunk_level1_multiply(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level2_multiply, .{ a, b });
}

export fn thunk_level1_subtract(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level2_subtract, .{ a, b });
}

export fn thunk_level1_divide(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level2_divide, .{ a, b });
}

export fn thunk_level1_print(val: i32) void {
    return @call(.always_tail, thunk_level2_print, .{val});
}

export fn thunk_level1_noop() void {
    return @call(.always_tail, thunk_level2_noop, .{});
}

// ============================================================================
// Function pointer table (GOT/IAT style indirection)
// ============================================================================

const BinaryOpFn = *const fn (i32, i32) callconv(.c) i32;
const UnaryOpFn = *const fn (i32) callconv(.c) void;
const NullaryOpFn = *const fn () callconv(.c) void;

// Global function pointer table - simulates GOT/IAT
export var got_binary_ops: [4]BinaryOpFn = .{
    &ultimate_add,
    &ultimate_multiply,
    &ultimate_subtract,
    &ultimate_divide,
};

export var got_print_fn: UnaryOpFn = &ultimate_print_value;
export var got_noop_fn: NullaryOpFn = &ultimate_noop;

// Indirect thunks that go through the GOT
export fn indirect_thunk_add(a: i32, b: i32) i32 {
    return got_binary_ops[0](a, b);
}

export fn indirect_thunk_multiply(a: i32, b: i32) i32 {
    return got_binary_ops[1](a, b);
}

export fn indirect_thunk_subtract(a: i32, b: i32) i32 {
    return got_binary_ops[2](a, b);
}

export fn indirect_thunk_divide(a: i32, b: i32) i32 {
    return got_binary_ops[3](a, b);
}

export fn indirect_thunk_print(val: i32) void {
    return got_print_fn(val);
}

export fn indirect_thunk_noop() void {
    return got_noop_fn();
}

// Level 2 indirect thunks (indirect -> indirect -> ultimate)
export fn indirect_level2_add(a: i32, b: i32) i32 {
    return @call(.always_tail, indirect_thunk_add, .{ a, b });
}

export fn indirect_level2_multiply(a: i32, b: i32) i32 {
    return @call(.always_tail, indirect_thunk_multiply, .{ a, b });
}

// ============================================================================
// Mixed pattern thunks (direct + indirect combinations)
// ============================================================================

// This creates a 4-level chain: mixed -> level1 -> level2 -> level3 -> ultimate
export fn mixed_thunk_add(a: i32, b: i32) i32 {
    return @call(.always_tail, thunk_level1_add, .{ a, b });
}

// This creates: mixed_indirect -> indirect_level2 -> indirect_thunk -> GOT -> ultimate
export fn mixed_indirect_add(a: i32, b: i32) i32 {
    return @call(.always_tail, indirect_level2_add, .{ a, b });
}

// ============================================================================
// Partial thunks (thunk + minor setup)
// ============================================================================

// These do a tiny bit of work before tail-calling
export fn partial_thunk_double(val: i32) i32 {
    // Note: Can't use always_tail with different signature
    return ultimate_add(val, val);
}

export fn partial_thunk_square(val: i32) i32 {
    // Note: Can't use always_tail with different signature
    return ultimate_multiply(val, val);
}

export fn partial_thunk_zero_checked_div(a: i32, b: i32) i32 {
    const divisor = if (b == 0) 1 else b;
    return @call(.always_tail, ultimate_divide, .{ a, divisor });
}

// ============================================================================
// Dispatch table using function pointers
// ============================================================================

const Operation = enum(u8) {
    add = 0,
    multiply = 1,
    subtract = 2,
    divide = 3,
};

export fn dispatch_operation(op: u8, a: i32, b: i32) i32 {
    const dispatch_table: [4]BinaryOpFn = .{
        &thunk_level1_add,
        &thunk_level1_multiply,
        &thunk_level1_subtract,
        &thunk_level1_divide,
    };
    if (op > 3) return 0;
    return dispatch_table[op](a, b);
}

// ============================================================================
// Main - Exercise the thunk chains
// ============================================================================

pub fn main() void {
    // Test direct thunk chains (4 levels: level1 -> level2 -> level3 -> ultimate)
    const add_result = thunk_level1_add(10, 20);
    const mul_result = thunk_level1_multiply(5, 6);
    const sub_result = thunk_level1_subtract(100, 30);
    const div_result = thunk_level1_divide(42, 7);

    std.debug.print("Direct thunk chain results:\n", .{});
    std.debug.print("  add(10, 20) = {d}\n", .{add_result});
    std.debug.print("  multiply(5, 6) = {d}\n", .{mul_result});
    std.debug.print("  subtract(100, 30) = {d}\n", .{sub_result});
    std.debug.print("  divide(42, 7) = {d}\n", .{div_result});

    // Test indirect thunk chains (through GOT)
    const ind_add = indirect_thunk_add(15, 25);
    const ind_mul = indirect_thunk_multiply(7, 8);

    std.debug.print("\nIndirect thunk (GOT) results:\n", .{});
    std.debug.print("  indirect_add(15, 25) = {d}\n", .{ind_add});
    std.debug.print("  indirect_multiply(7, 8) = {d}\n", .{ind_mul});

    // Test two-level indirect
    const ind2_add = indirect_level2_add(100, 200);

    std.debug.print("\nTwo-level indirect results:\n", .{});
    std.debug.print("  indirect_level2_add(100, 200) = {d}\n", .{ind2_add});

    // Test mixed thunks
    const mixed_result = mixed_thunk_add(3, 4);
    const mixed_ind_result = mixed_indirect_add(50, 60);

    std.debug.print("\nMixed thunk results:\n", .{});
    std.debug.print("  mixed_thunk_add(3, 4) = {d}\n", .{mixed_result});
    std.debug.print("  mixed_indirect_add(50, 60) = {d}\n", .{mixed_ind_result});

    // Test partial thunks
    const double_result = partial_thunk_double(21);
    const square_result = partial_thunk_square(9);
    const safe_div_result = partial_thunk_zero_checked_div(100, 0);

    std.debug.print("\nPartial thunk results:\n", .{});
    std.debug.print("  partial_double(21) = {d}\n", .{double_result});
    std.debug.print("  partial_square(9) = {d}\n", .{square_result});
    std.debug.print("  partial_zero_checked_div(100, 0) = {d}\n", .{safe_div_result});

    // Test dispatch table
    const dispatch_add = dispatch_operation(0, 11, 22);
    const dispatch_mul = dispatch_operation(1, 3, 3);

    std.debug.print("\nDispatch table results:\n", .{});
    std.debug.print("  dispatch(add, 11, 22) = {d}\n", .{dispatch_add});
    std.debug.print("  dispatch(multiply, 3, 3) = {d}\n", .{dispatch_mul});

    // Test print thunk chain
    std.debug.print("\nTesting print thunk chain:\n", .{});
    thunk_level1_print(42);
    indirect_thunk_print(99);

    // Test noop chain
    thunk_level1_noop();
    indirect_thunk_noop();

    std.debug.print("\nAll thunk chain tests completed.\n", .{});
}
