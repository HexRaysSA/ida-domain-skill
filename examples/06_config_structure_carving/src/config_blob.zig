const std = @import("std");

// High-entropy "encrypted" key material (256 bytes)
// This simulates encrypted data with pseudo-random bytes
const encrypted_key_material: [256]u8 = .{
    0x7a, 0x3f, 0x9c, 0x2e, 0x81, 0xd5, 0x47, 0xb9, 0xf3, 0x6a, 0x1c, 0x8e, 0x52, 0xcd, 0x0b, 0xa4,
    0xe8, 0x35, 0x9f, 0x63, 0xd1, 0x4c, 0x76, 0xba, 0x28, 0xe5, 0x91, 0x0d, 0x5a, 0xc7, 0x3b, 0x84,
    0xfc, 0x29, 0x67, 0xb3, 0x1e, 0xa8, 0x5d, 0xc2, 0x46, 0xf7, 0x83, 0x0a, 0x59, 0xd6, 0x24, 0xbe,
    0x71, 0xe4, 0x38, 0x9d, 0x02, 0xc5, 0x6f, 0xab, 0x17, 0xda, 0x4e, 0x93, 0x2b, 0xf0, 0x64, 0xcc,
    0x85, 0x49, 0xb7, 0x1d, 0xe9, 0x56, 0xa0, 0x3d, 0xc8, 0x72, 0xfe, 0x21, 0x8b, 0xd4, 0x4a, 0x97,
    0x03, 0xce, 0x68, 0xbc, 0x15, 0xea, 0x5f, 0xa3, 0x36, 0xd9, 0x43, 0x9e, 0x2a, 0xf5, 0x6c, 0xb1,
    0x1f, 0xe2, 0x54, 0xa9, 0x07, 0xca, 0x75, 0xbf, 0x32, 0xdd, 0x48, 0x92, 0x2f, 0xf9, 0x61, 0xae,
    0x13, 0xd8, 0x5c, 0xa5, 0x39, 0xec, 0x4d, 0xb5, 0x0e, 0xe1, 0x57, 0x96, 0x26, 0xfb, 0x69, 0xac,
    0x18, 0xde, 0x51, 0xa2, 0x3e, 0xc9, 0x73, 0xbd, 0x34, 0xdb, 0x45, 0x94, 0x2c, 0xf4, 0x6b, 0xaf,
    0x11, 0xe6, 0x58, 0xa7, 0x04, 0xcb, 0x77, 0xb8, 0x31, 0xdc, 0x47, 0x90, 0x2d, 0xfa, 0x62, 0xad,
    0x16, 0xd7, 0x50, 0xa1, 0x3c, 0xe7, 0x74, 0xbb, 0x33, 0xdf, 0x44, 0x95, 0x29, 0xf1, 0x6e, 0xb0,
    0x12, 0xe3, 0x55, 0xa6, 0x05, 0xc4, 0x78, 0xb6, 0x30, 0xd0, 0x46, 0x8f, 0x2e, 0xf6, 0x60, 0xaa,
    0x19, 0xd2, 0x53, 0x9b, 0x3a, 0xef, 0x70, 0xbc, 0x37, 0xde, 0x42, 0x8c, 0x2a, 0xf2, 0x66, 0xab,
    0x10, 0xe0, 0x56, 0x99, 0x06, 0xc3, 0x79, 0xb4, 0x32, 0xd1, 0x41, 0x8d, 0x2b, 0xf3, 0x65, 0xa8,
    0x14, 0xd3, 0x52, 0x9a, 0x08, 0xc6, 0x7c, 0xba, 0x35, 0xdb, 0x4b, 0x8e, 0x27, 0xf8, 0x6d, 0xac,
    0x1a, 0xe1, 0x59, 0x98, 0x0c, 0xc1, 0x7f, 0xb2, 0x38, 0xd5, 0x49, 0x89, 0x23, 0xfd, 0x61, 0xaf,
};

// Nested structure for server endpoint
const ServerEndpoint = extern struct {
    ip_addr: [4]u8 align(1),        // IPv4 address bytes
    port: u16 align(1),              // Port number
    timeout_ms: u32 align(1),        // Connection timeout
    retry_count: u8 align(1),        // Max retries
    flags: u8 align(1),              // Connection flags
    _padding: [2]u8 align(1),        // Alignment padding
};

// Nested structure for credentials
const CredentialBlock = extern struct {
    username: [32]u8 align(1),       // Null-terminated username
    password_hash: [32]u8 align(1),  // SHA-256 hash of password
    api_key: [64]u8 align(1),        // API key string
    token_expiry: u64 align(1),      // Unix timestamp
};

// Main configuration structure (~512 bytes with nested structs + arrays)
const ConfigBlob = extern struct {
    // Magic number for identification
    magic: [4]u8 align(1),           // "CFG\x00"

    // Version info
    version_major: u16 align(1),
    version_minor: u16 align(1),
    config_size: u32 align(1),       // Total config size

    // Feature flags
    feature_flags: u32 align(1),

    // C2 server configuration (nested structure)
    primary_server: ServerEndpoint align(1),
    backup_server: ServerEndpoint align(1),

    // URLs as C strings
    callback_url: [128]u8 align(1),   // Null-terminated URL
    update_url: [128]u8 align(1),     // Null-terminated URL

    // Paths
    install_path: [64]u8 align(1),    // Null-terminated path
    log_path: [64]u8 align(1),        // Null-terminated path

    // Credentials (nested structure)
    credentials: CredentialBlock align(1),

    // Timing configuration
    beacon_interval_sec: u32 align(1),
    jitter_percent: u16 align(1),
    sleep_on_error_sec: u16 align(1),

    // IP whitelist (fixed-size array)
    ip_whitelist: [8][4]u8 align(1),  // 8 IPv4 addresses

    // Encrypted key material (high-entropy region)
    encryption_key: [64]u8 align(1),

    // Checksum at the end
    config_checksum: u32 align(1),
    _end_padding: [4]u8 align(1),
};

// Global configuration instance with realistic values
export const g_config: ConfigBlob align(16) = .{
    .magic = .{ 'C', 'F', 'G', 0 },
    .version_major = 2,
    .version_minor = 5,
    .config_size = @sizeOf(ConfigBlob),
    .feature_flags = 0x8003_0501, // Various feature bits

    .primary_server = .{
        .ip_addr = .{ 192, 168, 1, 100 },
        .port = 8443,
        .timeout_ms = 30000,
        .retry_count = 3,
        .flags = 0x05,
        ._padding = .{ 0, 0 },
    },

    .backup_server = .{
        .ip_addr = .{ 10, 0, 0, 50 },
        .port = 443,
        .timeout_ms = 60000,
        .retry_count = 5,
        .flags = 0x07,
        ._padding = .{ 0, 0 },
    },

    .callback_url = initString("https://api.example-c2.net/beacon/v2/callback", 128),
    .update_url = initString("https://updates.example-c2.net/agent/update", 128),

    .install_path = initString("/var/lib/.hidden/agent", 64),
    .log_path = initString("/tmp/.cache/agent.log", 64),

    .credentials = .{
        .username = initString("agent_service_user", 32),
        .password_hash = .{
            0x5e, 0x88, 0x48, 0x98, 0xda, 0x28, 0x04, 0x71,
            0x51, 0xd0, 0xe5, 0x6f, 0x8d, 0xc6, 0x29, 0x27,
            0x73, 0x60, 0x3d, 0x0d, 0x6a, 0xab, 0xbd, 0xd6,
            0x2a, 0x11, 0xef, 0x72, 0x1d, 0x15, 0x42, 0xd8,
        },
        .api_key = initString("sk-live-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0", 64),
        .token_expiry = 1735689600, // Some future timestamp
    },

    .beacon_interval_sec = 300, // 5 minutes
    .jitter_percent = 20,
    .sleep_on_error_sec = 3600, // 1 hour

    .ip_whitelist = .{
        .{ 10, 0, 0, 1 },
        .{ 10, 0, 0, 2 },
        .{ 192, 168, 1, 1 },
        .{ 192, 168, 1, 254 },
        .{ 172, 16, 0, 1 },
        .{ 0, 0, 0, 0 }, // Empty entries
        .{ 0, 0, 0, 0 },
        .{ 0, 0, 0, 0 },
    },

    // High-entropy encryption key (first 64 bytes from encrypted_key_material)
    .encryption_key = encrypted_key_material[0..64].*,

    .config_checksum = 0xDEADBEEF,
    ._end_padding = .{ 0xAA, 0xBB, 0xCC, 0xDD },
};

// Helper to create null-terminated strings in fixed arrays
fn initString(comptime str: []const u8, comptime size: usize) [size]u8 {
    var result: [size]u8 = [_]u8{0} ** size;
    for (str, 0..) |c, i| {
        result[i] = c;
    }
    return result;
}

// Configuration initialization function that references the config blob
var g_initialized: bool = false;
var g_active_server: ?*const ServerEndpoint = null;

export fn config_init() callconv(.c) i32 {
    if (g_initialized) {
        return -1; // Already initialized
    }

    // Validate magic
    if (g_config.magic[0] != 'C' or
        g_config.magic[1] != 'F' or
        g_config.magic[2] != 'G')
    {
        return -2; // Invalid magic
    }

    // Validate version
    if (g_config.version_major < 1 or g_config.version_major > 10) {
        return -3; // Invalid version
    }

    // Select server based on flags
    if ((g_config.feature_flags & 0x01) != 0) {
        g_active_server = &g_config.primary_server;
    } else {
        g_active_server = &g_config.backup_server;
    }

    g_initialized = true;
    return 0;
}

export fn config_get_server() callconv(.c) ?*const ServerEndpoint {
    return g_active_server;
}

export fn config_get_beacon_interval() callconv(.c) u32 {
    if (!g_initialized) {
        return 0;
    }
    return g_config.beacon_interval_sec;
}

export fn config_get_callback_url() callconv(.c) [*:0]const u8 {
    return @ptrCast(&g_config.callback_url);
}

export fn config_decrypt_key(out_buf: [*]u8, buf_len: usize) callconv(.c) i32 {
    if (!g_initialized) {
        return -1;
    }

    const key_len = g_config.encryption_key.len;
    if (buf_len < key_len) {
        return -2;
    }

    // Simple XOR "decryption" with the high-entropy material
    for (g_config.encryption_key, 0..) |byte, i| {
        out_buf[i] = byte ^ encrypted_key_material[(i + 64) % 256];
    }

    return @intCast(key_len);
}

// Verify config size at compile time
comptime {
    const size = @sizeOf(ConfigBlob);
    if (size < 256 or size > 2048) {
        @compileError("ConfigBlob size must be between 256 and 2048 bytes");
    }
}

// Main function for standalone binary
pub fn main() void {
    const result = config_init();

    if (result == 0) {
        std.debug.print("Configuration initialized successfully\n", .{});
        std.debug.print("Config size: {} bytes\n", .{@sizeOf(ConfigBlob)});
        std.debug.print("Beacon interval: {} seconds\n", .{config_get_beacon_interval()});

        if (g_active_server) |server| {
            std.debug.print("Active server: {}.{}.{}.{}:{}\n", .{
                server.ip_addr[0],
                server.ip_addr[1],
                server.ip_addr[2],
                server.ip_addr[3],
                server.port,
            });
        }
    } else {
        std.debug.print("Configuration initialization failed: {}\n", .{result});
    }
}
