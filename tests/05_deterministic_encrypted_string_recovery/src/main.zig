const std = @import("std");

// ============================================================================
// Encrypted String Recovery Exercise
// This binary contains various string obfuscation techniques:
// 1. XOR-encoded strings (single-byte key)
// 2. XOR-encoded strings (rolling/multi-byte key)
// 3. Stack-constructed strings (char-by-char)
// 4. ADD/SUB encoded strings
// ============================================================================

// Single-byte XOR encrypted strings (key = 0x42)
// Format: [length][encrypted_data]
const xor_single_key: u8 = 0x42;

// XOR encrypted with key 0x42:
// "secret_password" -> encrypted
const enc_str_01 = [_]u8{ 0x31, 0x27, 0x25, 0x30, 0x27, 0x36, 0x1f, 0x32, 0x23, 0x31, 0x31, 0x35, 0x2d, 0x30, 0x26 };
// "administrator" -> encrypted
const enc_str_02 = [_]u8{ 0x23, 0x26, 0x2f, 0x2b, 0x2c, 0x2b, 0x31, 0x36, 0x30, 0x23, 0x36, 0x2d, 0x30 };
// "config.ini" -> encrypted
const enc_str_03 = [_]u8{ 0x21, 0x2d, 0x2c, 0x24, 0x2b, 0x25, 0x0c, 0x2b, 0x2c, 0x2b };
// "database_conn" -> encrypted
const enc_str_04 = [_]u8{ 0x26, 0x23, 0x36, 0x23, 0x20, 0x23, 0x31, 0x27, 0x1f, 0x21, 0x2d, 0x2c, 0x2c };
// "api_key_12345" -> encrypted
const enc_str_05 = [_]u8{ 0x23, 0x32, 0x2b, 0x1f, 0x29, 0x27, 0x3b, 0x1f, 0x73, 0x70, 0x71, 0x76, 0x77 };

// Rolling XOR key for multi-byte encryption
const rolling_key = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

// Rolling XOR encrypted strings:
// "system32" -> encrypted with rolling key
const enc_str_06 = [_]u8{ 0xAD, 0xCC, 0xCF, 0x81, 0xA8, 0xCF, 0xD1, 0x95 };
// "kernel32.dll" -> encrypted
const enc_str_07 = [_]u8{ 0xB5, 0xC8, 0xD0, 0x87, 0xB1, 0xC1, 0xD1, 0x97, 0x88, 0xC1, 0xD4, 0x83 };
// "ntdll.dll" -> encrypted
const enc_str_08 = [_]u8{ 0xB2, 0xD9, 0xC8, 0x83, 0xB2, 0x85, 0xC8, 0x83, 0xB2 };
// "cmd.exe" -> encrypted
const enc_str_09 = [_]u8{ 0xBD, 0xC0, 0xC8, 0x81, 0xB9, 0xD1, 0xC7 };
// "powershell" -> encrypted
const enc_str_10 = [_]u8{ 0xAE, 0xC2, 0xD1, 0x84, 0xB4, 0xDE, 0xC7, 0x83, 0xB2, 0xC1 };

// ADD-encoded strings (each byte + 0x13)
const add_key: u8 = 0x13;

// ADD encrypted:
// "registry" -> each byte + 0x13
const enc_str_11 = [_]u8{ 0x85, 0x78, 0x80, 0x82, 0x86, 0x87, 0x85, 0x8c };
// "firewall" -> encrypted
const enc_str_12 = [_]u8{ 0x79, 0x7c, 0x85, 0x78, 0x8a, 0x74, 0x7f, 0x7f };
// "antivirus" -> encrypted
const enc_str_13 = [_]u8{ 0x74, 0x81, 0x87, 0x7c, 0x89, 0x7c, 0x85, 0x88, 0x86 };
// "sandbox" -> encrypted
const enc_str_14 = [_]u8{ 0x86, 0x74, 0x81, 0x77, 0x75, 0x82, 0x8d };
// "debugger" -> encrypted
const enc_str_15 = [_]u8{ 0x77, 0x78, 0x75, 0x88, 0x80, 0x80, 0x78, 0x85 };

// SUB-encoded strings (each byte - 0x07)
const sub_key: u8 = 0x07;

// SUB encrypted:
// "network" -> each byte - 0x07
const enc_str_16 = [_]u8{ 0x67, 0x5E, 0x6D, 0x70, 0x68, 0x6B, 0x60 };
// "payload" -> encrypted
const enc_str_17 = [_]u8{ 0x69, 0x5A, 0x72, 0x63, 0x68, 0x5A, 0x5D };
// "exploit" -> encrypted
const enc_str_18 = [_]u8{ 0x5E, 0x71, 0x69, 0x63, 0x68, 0x62, 0x6D };
// "shellcode" -> encrypted
const enc_str_19 = [_]u8{ 0x6C, 0x61, 0x5E, 0x63, 0x63, 0x5C, 0x68, 0x5D, 0x5E };
// "rootkit" -> encrypted
const enc_str_20 = [_]u8{ 0x6B, 0x68, 0x68, 0x6D, 0x62, 0x62, 0x6D };

// More XOR single-byte strings for variety
// "C:\\Windows\\System32" -> XOR 0x42
const enc_str_21 = [_]u8{ 0x01, 0x1c, 0x1c, 0x15, 0x2b, 0x2c, 0x26, 0x2d, 0x35, 0x31, 0x1c, 0x11, 0x3b, 0x31, 0x36, 0x27, 0x2f, 0x71, 0x70 };
// "HKEY_LOCAL_MACHINE" -> XOR 0x42
const enc_str_22 = [_]u8{ 0x0A, 0x09, 0x07, 0x1B, 0x1F, 0x0E, 0x0F, 0x01, 0x03, 0x0E, 0x1F, 0x0F, 0x03, 0x01, 0x0A, 0x0B, 0x0C, 0x07 };
// "temp_file.dat" -> XOR 0x42
const enc_str_23 = [_]u8{ 0x36, 0x27, 0x2f, 0x32, 0x1f, 0x24, 0x2b, 0x2e, 0x27, 0x0c, 0x26, 0x23, 0x36 };
// "socket_conn" -> XOR 0x42
const enc_str_24 = [_]u8{ 0x31, 0x2d, 0x21, 0x29, 0x27, 0x36, 0x1f, 0x21, 0x2d, 0x2c, 0x2c };
// "encrypt_data" -> XOR 0x42
const enc_str_25 = [_]u8{ 0x27, 0x2c, 0x21, 0x30, 0x3b, 0x32, 0x36, 0x1f, 0x26, 0x23, 0x36, 0x23 };

// Rolling XOR additional strings
// "CreateProcess" -> rolling key
const enc_str_26 = [_]u8{ 0x9D, 0xD5, 0xC7, 0x8E, 0xB0, 0xC8, 0xCE, 0x84, 0xB2, 0xC8, 0xD1, 0x86, 0xB1 };
// "VirtualAlloc" -> rolling key
const enc_str_27 = [_]u8{ 0x88, 0xC4, 0xD0, 0x81, 0xBA, 0xC8, 0xD4, 0x8E, 0xB2, 0xC1, 0xDC, 0x8C };
// "WriteFile" -> rolling key
const enc_str_28 = [_]u8{ 0x89, 0xD5, 0xCF, 0x81, 0xB9, 0xC9, 0xCE, 0x83, 0xB9 };
// "ReadFile" -> rolling key
const enc_str_29 = [_]u8{ 0x8C, 0xC8, 0xC5, 0x8D, 0x9A, 0xC4, 0xD4, 0x84 };
// "GetProcAddr" -> rolling key
const enc_str_30 = [_]u8{ 0x99, 0xC8, 0xD2, 0x9F, 0xBA, 0xC2, 0xC9, 0x8E, 0xAC, 0xC1, 0xD0 };

// Volatile to prevent optimization
var volatile_sink: u8 = 0;

// ============================================================================
// Decryption Functions - Each has identifiable patterns
// ============================================================================

/// Single-byte XOR decryption
/// Pattern: tight loop with XOR operation using constant key
fn decrypt_xor_single(encrypted: []const u8, key: u8, output: []u8) void {
    for (encrypted, 0..) |byte, i| {
        output[i] = byte ^ key;
    }
}

/// Rolling/multi-byte XOR decryption
/// Pattern: tight loop with XOR and modulo for key index
fn decrypt_xor_rolling(encrypted: []const u8, key: []const u8, output: []u8) void {
    for (encrypted, 0..) |byte, i| {
        output[i] = byte ^ key[i % key.len];
    }
}

/// ADD decryption (subtract to decrypt)
/// Pattern: tight loop with SUB operation
fn decrypt_add(encrypted: []const u8, key: u8, output: []u8) void {
    for (encrypted, 0..) |byte, i| {
        output[i] = byte -% key;
    }
}

/// SUB decryption (add to decrypt)
/// Pattern: tight loop with ADD operation
fn decrypt_sub(encrypted: []const u8, key: u8, output: []u8) void {
    for (encrypted, 0..) |byte, i| {
        output[i] = byte +% key;
    }
}

/// Stack-constructed string builder
/// Pattern: individual character assignments to stack buffer
fn build_stack_string_1() [16]u8 {
    var buf: [16]u8 = undefined;
    buf[0] = 'h';
    buf[1] = 'i';
    buf[2] = 'd';
    buf[3] = 'd';
    buf[4] = 'e';
    buf[5] = 'n';
    buf[6] = '_';
    buf[7] = 's';
    buf[8] = 't';
    buf[9] = 'r';
    buf[10] = 'i';
    buf[11] = 'n';
    buf[12] = 'g';
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 0;
    return buf;
}

fn build_stack_string_2() [16]u8 {
    var buf: [16]u8 = undefined;
    buf[0] = 'm';
    buf[1] = 'a';
    buf[2] = 'l';
    buf[3] = 'w';
    buf[4] = 'a';
    buf[5] = 'r';
    buf[6] = 'e';
    buf[7] = '_';
    buf[8] = 'c';
    buf[9] = '2';
    buf[10] = 0;
    buf[11] = 0;
    buf[12] = 0;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 0;
    return buf;
}

fn build_stack_string_3() [24]u8 {
    var buf: [24]u8 = undefined;
    buf[0] = 'b';
    buf[1] = 'a';
    buf[2] = 'c';
    buf[3] = 'k';
    buf[4] = 'd';
    buf[5] = 'o';
    buf[6] = 'o';
    buf[7] = 'r';
    buf[8] = '_';
    buf[9] = 'c';
    buf[10] = 'o';
    buf[11] = 'n';
    buf[12] = 'n';
    buf[13] = 'e';
    buf[14] = 'c';
    buf[15] = 't';
    buf[16] = 'i';
    buf[17] = 'o';
    buf[18] = 'n';
    buf[19] = 0;
    buf[20] = 0;
    buf[21] = 0;
    buf[22] = 0;
    buf[23] = 0;
    return buf;
}

fn build_stack_string_4() [16]u8 {
    var buf: [16]u8 = undefined;
    buf[0] = 's';
    buf[1] = 't';
    buf[2] = 'e';
    buf[3] = 'a';
    buf[4] = 'l';
    buf[5] = '_';
    buf[6] = 'c';
    buf[7] = 'r';
    buf[8] = 'e';
    buf[9] = 'd';
    buf[10] = 's';
    buf[11] = 0;
    buf[12] = 0;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 0;
    return buf;
}

fn build_stack_string_5() [16]u8 {
    var buf: [16]u8 = undefined;
    buf[0] = 'k';
    buf[1] = 'e';
    buf[2] = 'y';
    buf[3] = 'l';
    buf[4] = 'o';
    buf[5] = 'g';
    buf[6] = 'g';
    buf[7] = 'e';
    buf[8] = 'r';
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;
    buf[12] = 0;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 0;
    return buf;
}

/// Use a decrypted string (prevents optimization)
fn use_string(s: []const u8) void {
    for (s) |c| {
        volatile_sink ^= c;
    }
}

/// Process single-byte XOR strings
fn process_xor_single_strings() void {
    var buf: [64]u8 = undefined;

    decrypt_xor_single(&enc_str_01, xor_single_key, buf[0..enc_str_01.len]);
    use_string(buf[0..enc_str_01.len]);

    decrypt_xor_single(&enc_str_02, xor_single_key, buf[0..enc_str_02.len]);
    use_string(buf[0..enc_str_02.len]);

    decrypt_xor_single(&enc_str_03, xor_single_key, buf[0..enc_str_03.len]);
    use_string(buf[0..enc_str_03.len]);

    decrypt_xor_single(&enc_str_04, xor_single_key, buf[0..enc_str_04.len]);
    use_string(buf[0..enc_str_04.len]);

    decrypt_xor_single(&enc_str_05, xor_single_key, buf[0..enc_str_05.len]);
    use_string(buf[0..enc_str_05.len]);

    decrypt_xor_single(&enc_str_21, xor_single_key, buf[0..enc_str_21.len]);
    use_string(buf[0..enc_str_21.len]);

    decrypt_xor_single(&enc_str_22, xor_single_key, buf[0..enc_str_22.len]);
    use_string(buf[0..enc_str_22.len]);

    decrypt_xor_single(&enc_str_23, xor_single_key, buf[0..enc_str_23.len]);
    use_string(buf[0..enc_str_23.len]);

    decrypt_xor_single(&enc_str_24, xor_single_key, buf[0..enc_str_24.len]);
    use_string(buf[0..enc_str_24.len]);

    decrypt_xor_single(&enc_str_25, xor_single_key, buf[0..enc_str_25.len]);
    use_string(buf[0..enc_str_25.len]);
}

/// Process rolling XOR strings
fn process_xor_rolling_strings() void {
    var buf: [64]u8 = undefined;

    decrypt_xor_rolling(&enc_str_06, &rolling_key, buf[0..enc_str_06.len]);
    use_string(buf[0..enc_str_06.len]);

    decrypt_xor_rolling(&enc_str_07, &rolling_key, buf[0..enc_str_07.len]);
    use_string(buf[0..enc_str_07.len]);

    decrypt_xor_rolling(&enc_str_08, &rolling_key, buf[0..enc_str_08.len]);
    use_string(buf[0..enc_str_08.len]);

    decrypt_xor_rolling(&enc_str_09, &rolling_key, buf[0..enc_str_09.len]);
    use_string(buf[0..enc_str_09.len]);

    decrypt_xor_rolling(&enc_str_10, &rolling_key, buf[0..enc_str_10.len]);
    use_string(buf[0..enc_str_10.len]);

    decrypt_xor_rolling(&enc_str_26, &rolling_key, buf[0..enc_str_26.len]);
    use_string(buf[0..enc_str_26.len]);

    decrypt_xor_rolling(&enc_str_27, &rolling_key, buf[0..enc_str_27.len]);
    use_string(buf[0..enc_str_27.len]);

    decrypt_xor_rolling(&enc_str_28, &rolling_key, buf[0..enc_str_28.len]);
    use_string(buf[0..enc_str_28.len]);

    decrypt_xor_rolling(&enc_str_29, &rolling_key, buf[0..enc_str_29.len]);
    use_string(buf[0..enc_str_29.len]);

    decrypt_xor_rolling(&enc_str_30, &rolling_key, buf[0..enc_str_30.len]);
    use_string(buf[0..enc_str_30.len]);
}

/// Process ADD-encoded strings
fn process_add_strings() void {
    var buf: [64]u8 = undefined;

    decrypt_add(&enc_str_11, add_key, buf[0..enc_str_11.len]);
    use_string(buf[0..enc_str_11.len]);

    decrypt_add(&enc_str_12, add_key, buf[0..enc_str_12.len]);
    use_string(buf[0..enc_str_12.len]);

    decrypt_add(&enc_str_13, add_key, buf[0..enc_str_13.len]);
    use_string(buf[0..enc_str_13.len]);

    decrypt_add(&enc_str_14, add_key, buf[0..enc_str_14.len]);
    use_string(buf[0..enc_str_14.len]);

    decrypt_add(&enc_str_15, add_key, buf[0..enc_str_15.len]);
    use_string(buf[0..enc_str_15.len]);
}

/// Process SUB-encoded strings
fn process_sub_strings() void {
    var buf: [64]u8 = undefined;

    decrypt_sub(&enc_str_16, sub_key, buf[0..enc_str_16.len]);
    use_string(buf[0..enc_str_16.len]);

    decrypt_sub(&enc_str_17, sub_key, buf[0..enc_str_17.len]);
    use_string(buf[0..enc_str_17.len]);

    decrypt_sub(&enc_str_18, sub_key, buf[0..enc_str_18.len]);
    use_string(buf[0..enc_str_18.len]);

    decrypt_sub(&enc_str_19, sub_key, buf[0..enc_str_19.len]);
    use_string(buf[0..enc_str_19.len]);

    decrypt_sub(&enc_str_20, sub_key, buf[0..enc_str_20.len]);
    use_string(buf[0..enc_str_20.len]);
}

/// Process stack-constructed strings
fn process_stack_strings() void {
    const s1 = build_stack_string_1();
    use_string(&s1);

    const s2 = build_stack_string_2();
    use_string(&s2);

    const s3 = build_stack_string_3();
    use_string(&s3);

    const s4 = build_stack_string_4();
    use_string(&s4);

    const s5 = build_stack_string_5();
    use_string(&s5);
}

pub fn main() void {
    // Process all encrypted string categories
    process_xor_single_strings();
    process_xor_rolling_strings();
    process_add_strings();
    process_sub_strings();
    process_stack_strings();

    // Final output to prevent dead code elimination
    // Use posix.write directly for Zig 0.15 compatibility
    var msg: [64]u8 = undefined;
    const result_str = std.fmt.bufPrint(&msg, "Processing complete. Result: {d}\n", .{volatile_sink}) catch "Error\n";
    _ = std.posix.write(std.posix.STDOUT_FILENO, result_str) catch {};
}
