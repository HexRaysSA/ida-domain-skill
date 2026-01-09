const std = @import("std");

// ============================================================================
// Hook Surface Identification Exercise
// This binary is designed for dynamic instrumentation (Frida/DynamoRIO):
// - Clear initialization sequence
// - Network-like communication functions (send/recv wrappers)
// - Crypto-like operations (encrypt/decrypt)
// - File I/O operations (read/write wrappers)
// - Exported functions and internal wrappers
// - Stable internal APIs (not inline-heavy)
// ============================================================================

// ============================================================================
// GLOBAL STATE - Initialization tracking
// ============================================================================

var g_initialized: bool = false;
var g_config_loaded: bool = false;
var g_session_id: u64 = 0;
var g_crypto_key: [32]u8 = undefined;
var g_connection_state: ConnectionState = .disconnected;

const ConnectionState = enum(u8) {
    disconnected = 0,
    connecting = 1,
    connected = 2,
    authenticated = 3,
    error_state = 255,
};

// ============================================================================
// CONFIGURATION STRUCTURE
// ============================================================================

const Config = struct {
    server_host: [64]u8,
    server_port: u16,
    encryption_enabled: bool,
    log_level: u8,
    max_retries: u8,
    timeout_ms: u32,
    session_key: [16]u8,
};

var g_config: Config = undefined;

// ============================================================================
// INITIALIZATION FUNCTIONS - Clear init boundary
// ============================================================================

/// Primary initialization entry point - EXPORTED
/// Good hook point: Called once at startup, captures initial state
pub export fn app_init() bool {
    if (g_initialized) return true;

    // Initialize crypto subsystem first
    if (!crypto_init()) {
        return false;
    }

    // Load configuration
    if (!config_load_defaults()) {
        return false;
    }

    // Initialize network subsystem
    if (!net_init()) {
        return false;
    }

    // Generate session ID
    g_session_id = generate_session_id();

    g_initialized = true;
    return true;
}

/// Secondary init for late-binding modules - EXPORTED
pub export fn module_init(module_id: u32) bool {
    if (!g_initialized) {
        if (!app_init()) return false;
    }

    // Module-specific initialization
    return init_module_internal(module_id);
}

/// Cleanup/shutdown - EXPORTED
pub export fn app_shutdown() void {
    if (!g_initialized) return;

    // Close any open connections
    net_disconnect();

    // Clear sensitive data
    @memset(&g_crypto_key, 0);
    @memset(&g_config.session_key, 0);

    g_initialized = false;
}

// Internal init helpers (good internal hook candidates)
fn crypto_init() bool {
    // Initialize crypto key from pseudo-random source
    var seed: u64 = 0x5DEECE66D;
    for (&g_crypto_key) |*byte| {
        seed = seed *% 0x5DEECE66D +% 0xB;
        byte.* = @truncate(seed >> 16);
    }
    return true;
}

fn config_load_defaults() bool {
    // Set default configuration
    @memset(&g_config.server_host, 0);
    const host = "127.0.0.1";
    @memcpy(g_config.server_host[0..host.len], host);

    g_config.server_port = 8443;
    g_config.encryption_enabled = true;
    g_config.log_level = 2;
    g_config.max_retries = 3;
    g_config.timeout_ms = 30000;

    // Generate session key
    var seed: u64 = 0xCAFEBABE;
    for (&g_config.session_key) |*byte| {
        seed = seed *% 0x5DEECE66D +% 0xB;
        byte.* = @truncate(seed >> 24);
    }

    g_config_loaded = true;
    return true;
}

fn net_init() bool {
    g_connection_state = .disconnected;
    return true;
}

fn init_module_internal(module_id: u32) bool {
    // Validate module ID range
    if (module_id > 1000) return false;

    // Module init logic placeholder - use module_id in dummy computation
    g_session_id ^= module_id;
    return true;
}

fn generate_session_id() u64 {
    // Simple PRNG-based session ID
    var id: u64 = 0xDEADBEEF;
    id = id *% 0x5851F42D4C957F2D +% 0x14057B7EF767814F;
    return id;
}

// ============================================================================
// NETWORK COMMUNICATION FUNCTIONS - Network boundary hooks
// ============================================================================

/// Connect to server - EXPORTED
/// Good hook point: Captures connection attempts, server address
pub export fn net_connect(host: [*]const u8, host_len: usize, port: u16) i32 {
    if (!g_initialized) return -1;
    if (g_connection_state == .connected) return 0;

    // Validate parameters
    if (host_len == 0 or host_len > 255) return -2;

    // Internal connection logic
    const result = net_connect_internal(host, host_len, port);
    if (result == 0) {
        g_connection_state = .connected;
    }
    return result;
}

/// Disconnect from server - EXPORTED
pub export fn net_disconnect() void {
    if (g_connection_state == .disconnected) return;

    net_send_disconnect_packet();
    g_connection_state = .disconnected;
}

/// Send data wrapper - EXPORTED
/// Good hook point: All outgoing data passes through here
pub export fn net_send(data: [*]const u8, len: usize) i32 {
    if (g_connection_state != .connected and g_connection_state != .authenticated) {
        return -1;
    }

    // Encrypt if enabled
    if (g_config.encryption_enabled) {
        return net_send_encrypted(data, len);
    } else {
        return net_send_raw(data, len);
    }
}

/// Receive data wrapper - EXPORTED
/// Good hook point: All incoming data passes through here
pub export fn net_recv(buffer: [*]u8, buffer_len: usize, received_len: *usize) i32 {
    if (g_connection_state != .connected and g_connection_state != .authenticated) {
        received_len.* = 0;
        return -1;
    }

    // Decrypt if enabled
    if (g_config.encryption_enabled) {
        return net_recv_encrypted(buffer, buffer_len, received_len);
    } else {
        return net_recv_raw(buffer, buffer_len, received_len);
    }
}

/// Send structured message - EXPORTED
/// Good hook point: Higher-level protocol messages
pub export fn net_send_message(msg_type: u16, payload: [*]const u8, payload_len: usize) i32 {
    var header: [8]u8 = undefined;

    // Build message header
    header[0] = 0xDE; // Magic
    header[1] = 0xAD;
    header[2] = @truncate(msg_type >> 8);
    header[3] = @truncate(msg_type);
    header[4] = @truncate(payload_len >> 24);
    header[5] = @truncate(payload_len >> 16);
    header[6] = @truncate(payload_len >> 8);
    header[7] = @truncate(payload_len);

    // Send header
    var result = net_send(&header, 8);
    if (result < 0) return result;

    // Send payload
    if (payload_len > 0) {
        result = net_send(payload, payload_len);
    }

    return result;
}

// Internal network functions (wrapper candidates)
fn net_connect_internal(host: [*]const u8, host_len: usize, port: u16) i32 {
    _ = host;
    _ = host_len;
    _ = port;
    // Simulated connection logic
    return 0;
}

fn net_send_disconnect_packet() void {
    const disconnect_msg = [_]u8{ 0xFF, 0xFF, 0x00, 0x00 };
    _ = net_send_raw(&disconnect_msg, 4);
}

fn net_send_raw(data: [*]const u8, len: usize) i32 {
    // Simulate raw send - in real code would call system send()
    // Compute checksum to prevent optimization
    var checksum: u8 = 0;
    for (0..len) |i| {
        checksum ^= data[i];
    }
    // Use checksum to prevent dead code elimination
    if (checksum == 0xFF and len == 0) return -99;
    return @intCast(len);
}

fn net_send_encrypted(data: [*]const u8, len: usize) i32 {
    // Copy to temp buffer, encrypt, then send
    var temp_buf: [4096]u8 = undefined;
    if (len > temp_buf.len) return -3;

    @memcpy(temp_buf[0..len], data[0..len]);

    // Encrypt the buffer
    crypto_encrypt(temp_buf[0..len]);

    return net_send_raw(&temp_buf, len);
}

fn net_recv_raw(buffer: [*]u8, buffer_len: usize, received_len: *usize) i32 {
    // Simulate receive - fill with dummy data
    const dummy_len = @min(buffer_len, 64);
    for (0..dummy_len) |i| {
        buffer[i] = @truncate(i ^ 0xAA);
    }
    received_len.* = dummy_len;
    return 0;
}

fn net_recv_encrypted(buffer: [*]u8, buffer_len: usize, received_len: *usize) i32 {
    // Receive raw data
    const result = net_recv_raw(buffer, buffer_len, received_len);
    if (result < 0) return result;

    // Decrypt in place
    if (received_len.* > 0) {
        crypto_decrypt(buffer[0..received_len.*]);
    }

    return result;
}

// ============================================================================
// CRYPTO OPERATIONS - Crypto boundary hooks
// ============================================================================

/// Encrypt data in place - EXPORTED
/// Good hook point: Capture plaintext before encryption
pub export fn crypto_encrypt_buffer(data: [*]u8, len: usize) void {
    if (len == 0) return;
    crypto_encrypt(data[0..len]);
}

/// Decrypt data in place - EXPORTED
/// Good hook point: Capture plaintext after decryption
pub export fn crypto_decrypt_buffer(data: [*]u8, len: usize) void {
    if (len == 0) return;
    crypto_decrypt(data[0..len]);
}

/// Hash data - EXPORTED
/// Good hook point: See what data is being hashed
pub export fn crypto_hash(data: [*]const u8, len: usize, hash_out: *[32]u8) void {
    compute_hash(data[0..len], hash_out);
}

/// Derive key from password - EXPORTED
pub export fn crypto_derive_key(password: [*]const u8, password_len: usize, salt: [*]const u8, salt_len: usize, key_out: *[32]u8) void {
    derive_key_internal(password[0..password_len], salt[0..salt_len], key_out);
}

/// Set encryption key - EXPORTED
/// Good hook point: Capture the encryption key
pub export fn crypto_set_key(key: [*]const u8, key_len: usize) bool {
    if (key_len != 32) return false;
    @memcpy(&g_crypto_key, key[0..32]);
    return true;
}

// Internal crypto functions
fn crypto_encrypt(data: []u8) void {
    // XOR encryption with key schedule
    for (data, 0..) |*byte, i| {
        const key_byte = g_crypto_key[i % g_crypto_key.len];
        byte.* ^= key_byte;
        byte.* = rotl8(byte.*, 3);
    }
}

fn crypto_decrypt(data: []u8) void {
    // Reverse of encrypt
    for (data, 0..) |*byte, i| {
        byte.* = rotr8(byte.*, 3);
        const key_byte = g_crypto_key[i % g_crypto_key.len];
        byte.* ^= key_byte;
    }
}

fn compute_hash(data: []const u8, hash_out: *[32]u8) void {
    // Simple hash function (FNV-1a variant extended)
    var state: [4]u64 = .{
        0xcbf29ce484222325,
        0x100000001b3,
        0x6c62272e07bb0142,
        0x62b821756295c58d,
    };

    for (data) |byte| {
        state[0] ^= byte;
        state[0] *%= 0x100000001b3;
        state[1] ^= state[0];
        state[2] ^= byte;
        state[2] *%= 0x100000001b3;
        state[3] ^= state[2];
    }

    // Mix final state into output
    for (0..4) |i| {
        const s = state[i];
        hash_out[i * 8 + 0] = @truncate(s >> 56);
        hash_out[i * 8 + 1] = @truncate(s >> 48);
        hash_out[i * 8 + 2] = @truncate(s >> 40);
        hash_out[i * 8 + 3] = @truncate(s >> 32);
        hash_out[i * 8 + 4] = @truncate(s >> 24);
        hash_out[i * 8 + 5] = @truncate(s >> 16);
        hash_out[i * 8 + 6] = @truncate(s >> 8);
        hash_out[i * 8 + 7] = @truncate(s);
    }
}

fn derive_key_internal(password: []const u8, salt: []const u8, key_out: *[32]u8) void {
    // Simple PBKDF-like derivation
    var temp_hash: [32]u8 = undefined;

    // First round with password
    compute_hash(password, &temp_hash);

    // XOR with salt
    for (temp_hash[0..@min(salt.len, 32)], 0..) |*byte, i| {
        byte.* ^= salt[i];
    }

    // Multiple rounds
    for (0..1000) |_| {
        compute_hash(&temp_hash, &temp_hash);
    }

    @memcpy(key_out, &temp_hash);
}

fn rotl8(value: u8, count: u3) u8 {
    const inv_count: u3 = @truncate(8 -% @as(u4, count));
    return (value << count) | (value >> inv_count);
}

fn rotr8(value: u8, count: u3) u8 {
    const inv_count: u3 = @truncate(8 -% @as(u4, count));
    return (value >> count) | (value << inv_count);
}

// ============================================================================
// FILE I/O OPERATIONS - File boundary hooks
// ============================================================================

/// Read file contents - EXPORTED
/// Good hook point: Monitor file reads, capture file paths
pub export fn file_read(path: [*]const u8, path_len: usize, buffer: [*]u8, buffer_len: usize, bytes_read: *usize) i32 {
    return file_read_internal(path[0..path_len], buffer[0..buffer_len], bytes_read);
}

/// Write file contents - EXPORTED
/// Good hook point: Monitor file writes, capture data being written
pub export fn file_write(path: [*]const u8, path_len: usize, data: [*]const u8, data_len: usize, bytes_written: *usize) i32 {
    return file_write_internal(path[0..path_len], data[0..data_len], bytes_written);
}

/// Append to file - EXPORTED
pub export fn file_append(path: [*]const u8, path_len: usize, data: [*]const u8, data_len: usize, bytes_written: *usize) i32 {
    return file_append_internal(path[0..path_len], data[0..data_len], bytes_written);
}

/// Check if file exists - EXPORTED
pub export fn file_exists(path: [*]const u8, path_len: usize) bool {
    return file_exists_internal(path[0..path_len]);
}

/// Delete file - EXPORTED
pub export fn file_delete(path: [*]const u8, path_len: usize) bool {
    return file_delete_internal(path[0..path_len]);
}

/// Read encrypted file - EXPORTED
/// Good hook point: Capture decrypted file contents
pub export fn file_read_encrypted(path: [*]const u8, path_len: usize, buffer: [*]u8, buffer_len: usize, bytes_read: *usize) i32 {
    const result = file_read_internal(path[0..path_len], buffer[0..buffer_len], bytes_read);
    if (result == 0 and bytes_read.* > 0) {
        crypto_decrypt(buffer[0..bytes_read.*]);
    }
    return result;
}

/// Write encrypted file - EXPORTED
/// Good hook point: Capture plaintext before encryption
pub export fn file_write_encrypted(path: [*]const u8, path_len: usize, data: [*]const u8, data_len: usize, bytes_written: *usize) i32 {
    var temp_buf: [4096]u8 = undefined;
    if (data_len > temp_buf.len) return -3;

    @memcpy(temp_buf[0..data_len], data[0..data_len]);
    crypto_encrypt(temp_buf[0..data_len]);

    return file_write_internal(path[0..path_len], temp_buf[0..data_len], bytes_written);
}

// Internal file functions (wrapper candidates)
fn file_read_internal(path: []const u8, buffer: []u8, bytes_read: *usize) i32 {
    // Simulate file read
    _ = path;

    // Fill with dummy data
    const read_len = @min(buffer.len, 256);
    for (0..read_len) |i| {
        buffer[i] = @truncate((i * 7 + 13) % 256);
    }
    bytes_read.* = read_len;
    return 0;
}

fn file_write_internal(path: []const u8, data: []const u8, bytes_written: *usize) i32 {
    // Simulate file write - use path to prevent optimization
    if (path.len == 0) return -1;

    bytes_written.* = data.len;
    return 0;
}

fn file_append_internal(path: []const u8, data: []const u8, bytes_written: *usize) i32 {
    // Simulate file append - use path to prevent optimization
    if (path.len == 0) return -1;

    bytes_written.* = data.len;
    return 0;
}

fn file_exists_internal(path: []const u8) bool {
    // Simulate file existence check
    if (path.len == 0) return false;

    // Pretend certain patterns exist
    for (path) |c| {
        if (c == '.') return true;
    }
    return false;
}

fn file_delete_internal(path: []const u8) bool {
    // Simulate file deletion
    if (path.len == 0) return false;
    return true;
}

// ============================================================================
// CENTRAL DISPATCHER - High-value internal hook point
// ============================================================================

/// Command dispatcher - EXPORTED
/// Good hook point: Central dispatch for all commands
pub export fn dispatch_command(cmd_id: u32, arg1: u64, arg2: u64, result: *u64) i32 {
    return command_dispatch_internal(cmd_id, arg1, arg2, result);
}

/// Message handler - EXPORTED
/// Good hook point: Handles all incoming messages
pub export fn handle_message(msg_type: u16, payload: [*]const u8, payload_len: usize) i32 {
    return message_handler_internal(msg_type, payload[0..payload_len]);
}

// Internal dispatcher (high-value hook candidate)
fn command_dispatch_internal(cmd_id: u32, arg1: u64, arg2: u64, result: *u64) i32 {
    result.* = 0;

    return switch (cmd_id) {
        0x0001 => cmd_ping(arg1, result),
        0x0002 => cmd_get_status(result),
        0x0003 => cmd_set_config(arg1, arg2),
        0x0004 => cmd_encrypt_data(arg1, arg2, result),
        0x0005 => cmd_decrypt_data(arg1, arg2, result),
        0x0010 => cmd_connect(arg1, @truncate(arg2)),
        0x0011 => cmd_disconnect(),
        0x0012 => cmd_send_data(arg1, arg2, result),
        0x0020 => cmd_read_file(arg1, arg2, result),
        0x0021 => cmd_write_file(arg1, arg2, result),
        else => -1, // Unknown command
    };
}

fn message_handler_internal(msg_type: u16, payload: []const u8) i32 {
    return switch (msg_type) {
        0x0001 => handle_ping_message(payload),
        0x0002 => handle_pong_message(payload),
        0x0010 => handle_auth_request(payload),
        0x0011 => handle_auth_response(payload),
        0x0020 => handle_data_message(payload),
        0x0030 => handle_error_message(payload),
        else => -1,
    };
}

// Command implementations
fn cmd_ping(timestamp: u64, result: *u64) i32 {
    result.* = timestamp ^ 0xDEADC0DE;
    return 0;
}

fn cmd_get_status(result: *u64) i32 {
    result.* = @as(u64, @intFromEnum(g_connection_state)) |
        (@as(u64, @intFromBool(g_initialized)) << 8) |
        (@as(u64, @intFromBool(g_config_loaded)) << 16);
    return 0;
}

fn cmd_set_config(config_id: u64, value: u64) i32 {
    switch (config_id) {
        0 => g_config.log_level = @truncate(value),
        1 => g_config.max_retries = @truncate(value),
        2 => g_config.timeout_ms = @truncate(value),
        3 => g_config.encryption_enabled = value != 0,
        else => return -1,
    }
    return 0;
}

fn cmd_encrypt_data(data_ptr: u64, data_len: u64, result: *u64) i32 {
    _ = data_ptr;
    _ = data_len;
    result.* = 0;
    return 0;
}

fn cmd_decrypt_data(data_ptr: u64, data_len: u64, result: *u64) i32 {
    _ = data_ptr;
    _ = data_len;
    result.* = 0;
    return 0;
}

fn cmd_connect(host_ptr: u64, port: u16) i32 {
    _ = host_ptr;
    _ = port;
    g_connection_state = .connected;
    return 0;
}

fn cmd_disconnect() i32 {
    g_connection_state = .disconnected;
    return 0;
}

fn cmd_send_data(data_ptr: u64, data_len: u64, result: *u64) i32 {
    _ = data_ptr;
    result.* = data_len;
    return 0;
}

fn cmd_read_file(path_ptr: u64, buffer_ptr: u64, result: *u64) i32 {
    _ = path_ptr;
    _ = buffer_ptr;
    result.* = 0;
    return 0;
}

fn cmd_write_file(path_ptr: u64, data_len: u64, result: *u64) i32 {
    _ = path_ptr;
    result.* = data_len;
    return 0;
}

// Message handlers
fn handle_ping_message(payload: []const u8) i32 {
    _ = payload;
    return 0;
}

fn handle_pong_message(payload: []const u8) i32 {
    _ = payload;
    return 0;
}

fn handle_auth_request(payload: []const u8) i32 {
    if (payload.len < 4) return -1;
    return 0;
}

fn handle_auth_response(payload: []const u8) i32 {
    if (payload.len < 4) return -1;
    if (payload[0] == 0x00) {
        g_connection_state = .authenticated;
    }
    return 0;
}

fn handle_data_message(payload: []const u8) i32 {
    _ = payload;
    return 0;
}

fn handle_error_message(payload: []const u8) i32 {
    _ = payload;
    return -1;
}

// ============================================================================
// ADDITIONAL EXPORTED UTILITIES
// ============================================================================

/// Get session ID - EXPORTED
pub export fn get_session_id() u64 {
    return g_session_id;
}

/// Get connection state - EXPORTED
pub export fn get_connection_state() u8 {
    return @intFromEnum(g_connection_state);
}

/// Check if initialized - EXPORTED
pub export fn is_initialized() bool {
    return g_initialized;
}

/// Get version info - EXPORTED
pub export fn get_version() u32 {
    return 0x00010203; // v1.2.3
}

/// Process callback registration (for hooking callbacks) - EXPORTED
pub export fn register_callback(callback_type: u32, callback_ptr: u64) bool {
    // Store callback for later invocation
    _ = callback_type;
    _ = callback_ptr;
    return true;
}

/// Invoke registered callback - EXPORTED
pub export fn invoke_callback(callback_type: u32, arg: u64) i32 {
    _ = callback_type;
    _ = arg;
    return 0;
}

// ============================================================================
// MAIN FUNCTION - Exercises all code paths
// ============================================================================

pub fn main() void {
    // Initialize application
    if (!app_init()) {
        const msg = "Initialization failed\n";
        _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch {};
        return;
    }

    // Initialize a module
    _ = module_init(42);

    // Test crypto operations
    var test_data = [_]u8{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' };
    crypto_encrypt_buffer(&test_data, test_data.len);
    crypto_decrypt_buffer(&test_data, test_data.len);

    var hash_result: [32]u8 = undefined;
    crypto_hash(&test_data, test_data.len, &hash_result);

    var derived_key: [32]u8 = undefined;
    crypto_derive_key("password", 8, "salt1234", 8, &derived_key);

    // Test network operations
    const host = "localhost";
    _ = net_connect(host, host.len, 8080);

    var send_buf = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    _ = net_send(&send_buf, 4);

    _ = net_send_message(0x0001, &send_buf, 4);

    var recv_buf: [256]u8 = undefined;
    var received: usize = 0;
    _ = net_recv(&recv_buf, recv_buf.len, &received);

    // Test file operations
    const filepath = "/tmp/test.dat";
    var file_buf: [512]u8 = undefined;
    var bytes_transferred: usize = 0;

    _ = file_read(filepath, filepath.len, &file_buf, file_buf.len, &bytes_transferred);
    _ = file_write(filepath, filepath.len, &test_data, test_data.len, &bytes_transferred);
    _ = file_exists(filepath, filepath.len);
    _ = file_read_encrypted(filepath, filepath.len, &file_buf, file_buf.len, &bytes_transferred);
    _ = file_write_encrypted(filepath, filepath.len, &test_data, test_data.len, &bytes_transferred);

    // Test command dispatch
    var cmd_result: u64 = 0;
    _ = dispatch_command(0x0001, 12345, 0, &cmd_result);
    _ = dispatch_command(0x0002, 0, 0, &cmd_result);
    _ = dispatch_command(0x0003, 0, 2, &cmd_result);

    // Test message handling
    var msg_payload = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    _ = handle_message(0x0001, &msg_payload, 4);
    _ = handle_message(0x0011, &msg_payload, 4);

    // Query state
    _ = get_session_id();
    _ = get_connection_state();
    _ = is_initialized();
    _ = get_version();

    // Callback registration
    _ = register_callback(1, 0x12345678);
    _ = invoke_callback(1, 100);

    // Cleanup
    net_disconnect();
    app_shutdown();

    const success_msg = "Hook surface binary executed successfully.\n";
    _ = std.posix.write(std.posix.STDOUT_FILENO, success_msg) catch {};
}
