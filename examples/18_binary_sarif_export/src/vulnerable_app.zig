// Vulnerable application for SARIF security analysis testing
// This file intentionally contains security anti-patterns for detection testing

const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("stdio.h");
    @cInclude("unistd.h");
    @cInclude("time.h");
    @cInclude("sys/ptrace.h");
});

// =============================================================================
// CRITICAL: Hardcoded Secrets (should be detected)
// =============================================================================

// Hardcoded API key - CRITICAL severity
const API_KEY: []const u8 = "sk-live-4f3c2d1e0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d";

// Hardcoded password - CRITICAL severity
const DB_PASSWORD: []const u8 = "SuperSecretP@ssw0rd!2024";

// Hardcoded encryption key (AES-256) - CRITICAL severity
const ENCRYPTION_KEY: [32]u8 = .{
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

// AWS credentials - CRITICAL severity
const AWS_ACCESS_KEY: []const u8 = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY: []const u8 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// JWT secret - CRITICAL severity
const JWT_SECRET: []const u8 = "my-super-secret-jwt-signing-key-do-not-share";

// =============================================================================
// HIGH: Buffer Overflow Patterns (dangerous C API usage)
// =============================================================================

// Using strcpy - HIGH severity (no bounds checking)
fn copyStringUnsafe(dest: [*c]u8, src: [*c]const u8) void {
    _ = c.strcpy(dest, src);
}

// Using sprintf - HIGH severity (format string + no bounds)
fn formatStringUnsafe(buffer: [*c]u8, format: [*c]const u8, value: c_int) void {
    _ = c.sprintf(buffer, format, value);
}

// Using gets equivalent pattern - HIGH severity
fn readLineUnsafe(buffer: [*c]u8, _: usize) void {
    // Simulating gets-like behavior (reading without bounds)
    var i: usize = 0;
    while (true) {
        const ch = c.getchar();
        if (ch == '\n' or ch == c.EOF) break;
        buffer[i] = @intCast(ch);
        i += 1;
        // No bounds check - buffer overflow possible
    }
    buffer[i] = 0;
}

// Using strcat without bounds - HIGH severity
fn concatStringUnsafe(dest: [*c]u8, src: [*c]const u8) void {
    _ = c.strcat(dest, src);
}

// =============================================================================
// MEDIUM: Anti-Debug Checks
// =============================================================================

// ptrace-based anti-debug - MEDIUM severity
fn checkDebuggerPtrace() bool {
    const result = c.ptrace(c.PT_DENY_ATTACH, 0, null, 0);
    return result == -1;
}

// Timing-based anti-debug check - MEDIUM severity
fn checkDebuggerTiming() bool {
    const start = c.clock();

    // Decoy computation
    var sum: u64 = 0;
    for (0..1000) |i| {
        sum +%= i * i;
    }

    const end = c.clock();
    const elapsed = end - start;

    // If debugger stepping, this takes much longer
    return elapsed > 10000;
}

// Environment-based anti-debug - MEDIUM severity
fn checkDebuggerEnvironment() bool {
    const debug_env = c.getenv("DEBUG");
    const ida_env = c.getenv("IDA_PATH");
    const gdb_env = c.getenv("GDB_INIT");

    return debug_env != null or ida_env != null or gdb_env != null;
}

// Parent process check - MEDIUM severity
fn checkDebuggerParent() bool {
    const ppid = c.getppid();
    // Suspicious if parent PID is 1 (init) or very low
    return ppid <= 1;
}

// =============================================================================
// LOW: Insecure Random Number Generation
// =============================================================================

// Using rand() without proper seeding - LOW severity
fn getWeakRandomNumber() c_int {
    // Predictable: seeded with time (can be guessed)
    c.srand(@intCast(c.time(null)));
    return c.rand();
}

// Using time as seed makes it predictable - LOW severity
fn generatePredictableToken() [16]u8 {
    c.srand(@intCast(c.time(null)));
    var token: [16]u8 = undefined;
    for (&token) |*byte| {
        byte.* = @truncate(@as(u32, @intCast(c.rand())));
    }
    return token;
}

// =============================================================================
// MEDIUM: Self-Modifying Code Indicators
// =============================================================================

// Code that writes to executable memory regions
fn selfModifyingPattern() void {
    // mprotect/VirtualProtect pattern indicator
    // In real malware, this would modify code at runtime
    var code_region: [64]u8 = undefined;
    @memset(&code_region, 0x90); // NOP sled pattern

    // XOR decryption pattern (common in packers)
    const xor_key: u8 = 0x42;
    for (&code_region) |*byte| {
        byte.* ^= xor_key;
    }
}

// =============================================================================
// CRITICAL: Command Injection Patterns
// =============================================================================

// System call with user input - CRITICAL severity
fn executeCommand(user_input: [*c]const u8) c_int {
    var cmd_buffer: [512]u8 = undefined;
    _ = c.sprintf(&cmd_buffer, "echo %s", user_input);
    return c.system(&cmd_buffer);
}

// Popen with concatenated user input - CRITICAL severity
fn readCommandOutput(filename: [*c]const u8) void {
    var cmd: [256]u8 = undefined;
    _ = c.sprintf(&cmd, "cat %s", filename);
    const fp = c.popen(&cmd, "r");
    if (fp != null) {
        _ = c.pclose(fp);
    }
}

// =============================================================================
// HIGH: High-Entropy Regions (potential packed/encrypted data)
// =============================================================================

// This looks like encrypted or packed data - HIGH severity for analysis
const SUSPICIOUS_BLOB: [64]u8 = .{
    0xa3, 0xf7, 0x2c, 0x91, 0x8e, 0x4d, 0xb5, 0x62,
    0x1f, 0x73, 0xc8, 0x9a, 0x0d, 0xe6, 0x54, 0xbb,
    0x7c, 0x29, 0x85, 0xf1, 0x46, 0xda, 0x03, 0x6e,
    0xac, 0x57, 0xe2, 0x1b, 0x90, 0x3f, 0xc4, 0x68,
    0xd9, 0x24, 0x7a, 0xef, 0x51, 0xb6, 0x0c, 0x83,
    0x4f, 0xe8, 0x35, 0x9d, 0x62, 0xca, 0x17, 0xa1,
    0x78, 0x2e, 0xb4, 0x5f, 0xc9, 0x01, 0x86, 0xd3,
    0x4a, 0xf5, 0x20, 0x9c, 0x67, 0xbe, 0x13, 0x58,
};

// Another high-entropy constant (looks like hash or key)
const OBFUSCATED_DATA: [32]u8 = .{
    0xe4, 0x9b, 0x2f, 0x86, 0xc1, 0x5d, 0x73, 0xa8,
    0x14, 0xdf, 0x69, 0x3c, 0xb0, 0x47, 0xf2, 0x85,
    0x9e, 0x21, 0xca, 0x56, 0x0b, 0x78, 0xe3, 0x3d,
    0xa7, 0x64, 0x1c, 0xf9, 0x42, 0xbd, 0x05, 0x6f,
};

// =============================================================================
// LOW: Deprecated/Insecure API Usage
// =============================================================================

// Using tmpnam (deprecated, race condition) - LOW severity
fn createTempFile() [*c]u8 {
    return c.tmpnam(null);
}

// Using getenv for sensitive data - LOW severity
fn getPasswordFromEnv() [*c]u8 {
    return c.getenv("USER_PASSWORD");
}

// =============================================================================
// Main function demonstrating all vulnerabilities
// =============================================================================

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Security Test Application\n", .{});
    try stdout.print("=========================\n\n", .{});

    // Anti-debug checks
    if (checkDebuggerPtrace()) {
        try stdout.print("[!] Debugger detected (ptrace)\n", .{});
        try stdout.flush();
        return;
    }

    if (checkDebuggerTiming()) {
        try stdout.print("[!] Debugger detected (timing)\n", .{});
        try stdout.flush();
        return;
    }

    if (checkDebuggerEnvironment()) {
        try stdout.print("[!] Debug environment detected\n", .{});
    }

    if (checkDebuggerParent()) {
        try stdout.print("[!] Suspicious parent process\n", .{});
    }

    // Demonstrate dangerous operations (for testing detection)
    var buffer: [64]u8 = undefined;
    const unsafe_buffer: [*c]u8 = &buffer;

    // Dangerous string operations
    copyStringUnsafe(unsafe_buffer, "test");
    concatStringUnsafe(unsafe_buffer, " data");

    var format_buffer: [128]u8 = undefined;
    formatStringUnsafe(&format_buffer, "Value: %d", 42);

    // Weak random
    const weak_random = getWeakRandomNumber();
    try stdout.print("Random value: {d}\n", .{weak_random});

    const token = generatePredictableToken();
    try stdout.print("Token: ", .{});
    for (token) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Self-modifying code pattern
    selfModifyingPattern();

    // Show hardcoded secrets being used (bad practice)
    try stdout.print("\nUsing API Key: {s}...\n", .{API_KEY[0..10]});
    try stdout.print("DB Password length: {d}\n", .{DB_PASSWORD.len});
    try stdout.print("Encryption key first byte: 0x{x:0>2}\n", .{ENCRYPTION_KEY[0]});

    // High-entropy data access
    var entropy_sum: u32 = 0;
    for (SUSPICIOUS_BLOB) |byte| {
        entropy_sum +%= byte;
    }
    try stdout.print("Blob checksum: {d}\n", .{entropy_sum});

    for (OBFUSCATED_DATA) |byte| {
        entropy_sum +%= byte;
    }
    try stdout.print("Obfuscated data checksum: {d}\n", .{entropy_sum});

    // Temp file (deprecated API)
    const tmp = createTempFile();
    if (tmp != null) {
        try stdout.print("Temp file: {s}\n", .{std.mem.span(tmp)});
    }

    // Get password from environment (insecure)
    const env_pass = getPasswordFromEnv();
    if (env_pass != null) {
        try stdout.print("Got password from env\n", .{});
    }

    try stdout.print("\n[*] Application completed\n", .{});
    try stdout.flush();
}
