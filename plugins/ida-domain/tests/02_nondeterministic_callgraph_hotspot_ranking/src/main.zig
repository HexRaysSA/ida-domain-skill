// Callgraph Hotspot Binary - Designed for IDA analysis exercise
// Creates a binary with ~250 functions demonstrating:
// - Central dispatcher functions
// - Multiple call layers
// - Mutual recursion / callback patterns
// - Isolated utility clusters

const std = @import("std");

// ============================================================================
// LAYER 0: Core utilities (isolated cluster)
// ============================================================================

fn util_hash(data: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (data) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

fn util_checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    for (data) |b| {
        sum += b;
    }
    return @truncate(sum);
}

fn util_validate_length(len: usize) bool {
    return len > 0 and len < 65536;
}

fn util_clamp(val: i32, min: i32, max: i32) i32 {
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

fn util_abs(val: i32) i32 {
    return if (val < 0) -val else val;
}

fn util_min(a: u32, b: u32) u32 {
    return if (a < b) a else b;
}

fn util_max(a: u32, b: u32) u32 {
    return if (a > b) a else b;
}

fn util_swap(a: *u32, b: *u32) void {
    const tmp = a.*;
    a.* = b.*;
    b.* = tmp;
}

fn util_rotate_left(val: u32, bits: u5) u32 {
    const complement: u5 = 0 -% bits;
    return (val << bits) | (val >> complement);
}

fn util_rotate_right(val: u32, bits: u5) u32 {
    const complement: u5 = 0 -% bits;
    return (val >> bits) | (val << complement);
}

// ============================================================================
// LAYER 0: String utilities (isolated cluster)
// ============================================================================

fn str_length(s: []const u8) usize {
    return s.len;
}

fn str_compare(a: []const u8, b: []const u8) i32 {
    const min_len = util_min(@truncate(a.len), @truncate(b.len));
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        if (a[i] != b[i]) {
            return @as(i32, a[i]) - @as(i32, b[i]);
        }
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

fn str_starts_with(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return std.mem.eql(u8, s[0..prefix.len], prefix);
}

fn str_ends_with(s: []const u8, suffix: []const u8) bool {
    if (s.len < suffix.len) return false;
    return std.mem.eql(u8, s[s.len - suffix.len ..], suffix);
}

fn str_to_upper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') return c - 32;
    return c;
}

fn str_to_lower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

fn str_is_digit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn str_is_alpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

fn str_is_alnum(c: u8) bool {
    return str_is_digit(c) or str_is_alpha(c);
}

fn str_is_space(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

// ============================================================================
// LAYER 0: Math utilities (isolated cluster)
// ============================================================================

fn math_gcd(a: u32, b: u32) u32 {
    var x = a;
    var y = b;
    while (y != 0) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

fn math_lcm(a: u32, b: u32) u32 {
    if (a == 0 or b == 0) return 0;
    return (a / math_gcd(a, b)) * b;
}

fn math_pow(base: u32, exp: u32) u32 {
    if (exp == 0) return 1;
    var result: u32 = 1;
    var b = base;
    var e = exp;
    while (e > 0) {
        if (e & 1 == 1) result *= b;
        b *= b;
        e >>= 1;
    }
    return result;
}

fn math_sqrt_int(n: u32) u32 {
    if (n == 0) return 0;
    var x = n;
    var y = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

fn math_is_prime(n: u32) bool {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    var i: u32 = 3;
    while (i * i <= n) : (i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

fn math_factorial(n: u32) u32 {
    if (n <= 1) return 1;
    var result: u32 = 1;
    var i: u32 = 2;
    while (i <= n) : (i += 1) {
        result *= i;
    }
    return result;
}

fn math_fibonacci(n: u32) u32 {
    if (n <= 1) return n;
    var a: u32 = 0;
    var b: u32 = 1;
    var i: u32 = 2;
    while (i <= n) : (i += 1) {
        const tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

fn math_mod_pow(base: u32, exp: u32, mod: u32) u32 {
    if (mod == 0) return 0;
    var result: u64 = 1;
    var b: u64 = base % mod;
    var e = exp;
    while (e > 0) {
        if (e & 1 == 1) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1;
    }
    return @truncate(result);
}

// ============================================================================
// LAYER 1: Data validation functions
// ============================================================================

fn validate_packet_header(data: []const u8) bool {
    if (!util_validate_length(data.len)) return false;
    if (data.len < 8) return false;
    const magic = util_hash(data[0..4]);
    return magic != 0;
}

fn validate_packet_checksum(data: []const u8) bool {
    if (data.len < 2) return false;
    const stored = @as(u16, data[data.len - 2]) | (@as(u16, data[data.len - 1]) << 8);
    const computed = util_checksum(data[0 .. data.len - 2]);
    return stored == computed;
}

fn validate_packet_version(version: u8) bool {
    return version >= 1 and version <= 5;
}

fn validate_packet_type(ptype: u8) bool {
    return ptype < 32;
}

fn validate_packet_length(declared: u16, actual: usize) bool {
    return declared == @as(u16, @truncate(actual));
}

fn validate_auth_token(token: []const u8) bool {
    if (token.len != 32) return false;
    for (token) |c| {
        if (!str_is_alnum(c)) return false;
    }
    return true;
}

fn validate_session_id(sid: u32) bool {
    return sid > 0 and sid < 0x7FFFFFFF;
}

fn validate_sequence_number(seq: u32, expected: u32) bool {
    const diff = if (seq > expected) seq - expected else expected - seq;
    return diff < 1000;
}

fn validate_timestamp(ts: u64, current: u64) bool {
    if (ts > current) return false;
    return current - ts < 3600;
}

fn validate_payload_size(size: usize, max: usize) bool {
    return size <= max and size > 0;
}

// ============================================================================
// LAYER 1: Encoding/Decoding utilities
// ============================================================================

fn encode_base64_char(val: u6) u8 {
    const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return table[val];
}

fn decode_base64_char(c: u8) ?u6 {
    if (c >= 'A' and c <= 'Z') return @truncate(c - 'A');
    if (c >= 'a' and c <= 'z') return @truncate(c - 'a' + 26);
    if (c >= '0' and c <= '9') return @truncate(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return null;
}

fn encode_hex_digit(val: u4) u8 {
    if (val < 10) return '0' + @as(u8, val);
    return 'a' + @as(u8, val) - 10;
}

fn decode_hex_digit(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @truncate(c - '0');
    if (c >= 'a' and c <= 'f') return @truncate(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @truncate(c - 'A' + 10);
    return null;
}

fn encode_varint(val: u32, out: []u8) usize {
    var v = val;
    var i: usize = 0;
    while (v >= 0x80 and i < out.len) {
        out[i] = @truncate((v & 0x7F) | 0x80);
        v >>= 7;
        i += 1;
    }
    if (i < out.len) {
        out[i] = @truncate(v);
        i += 1;
    }
    return i;
}

fn decode_varint(data: []const u8) u32 {
    var result: u32 = 0;
    var shift: u5 = 0;
    for (data) |b| {
        result |= @as(u32, b & 0x7F) << shift;
        if (b & 0x80 == 0) break;
        shift += 7;
        if (shift >= 32) break;
    }
    return result;
}

fn encode_zigzag(val: i32) u32 {
    return @bitCast((val << 1) ^ (val >> 31));
}

fn decode_zigzag(val: u32) i32 {
    return @bitCast((val >> 1) ^ (0 -% (val & 1)));
}

// ============================================================================
// LAYER 2: Protocol message types
// ============================================================================

const MessageType = enum(u8) {
    connect = 0,
    disconnect = 1,
    ping = 2,
    pong = 3,
    auth_request = 4,
    auth_response = 5,
    data_request = 6,
    data_response = 7,
    error_response = 8,
    status_query = 9,
    status_response = 10,
    config_get = 11,
    config_set = 12,
    config_response = 13,
    file_open = 14,
    file_close = 15,
    file_read = 16,
    file_write = 17,
    file_response = 18,
    notify = 19,
    subscribe = 20,
    unsubscribe = 21,
    heartbeat = 22,
    shutdown = 23,
    unknown = 255,
};

fn message_type_from_byte(b: u8) MessageType {
    return switch (b) {
        0 => .connect,
        1 => .disconnect,
        2 => .ping,
        3 => .pong,
        4 => .auth_request,
        5 => .auth_response,
        6 => .data_request,
        7 => .data_response,
        8 => .error_response,
        9 => .status_query,
        10 => .status_response,
        11 => .config_get,
        12 => .config_set,
        13 => .config_response,
        14 => .file_open,
        15 => .file_close,
        16 => .file_read,
        17 => .file_write,
        18 => .file_response,
        19 => .notify,
        20 => .subscribe,
        21 => .unsubscribe,
        22 => .heartbeat,
        23 => .shutdown,
        else => .unknown,
    };
}

fn message_requires_auth(mtype: MessageType) bool {
    return switch (mtype) {
        .connect, .disconnect, .ping, .pong, .heartbeat => false,
        else => true,
    };
}

fn message_is_response(mtype: MessageType) bool {
    return switch (mtype) {
        .pong, .auth_response, .data_response, .error_response, .status_response, .config_response, .file_response => true,
        else => false,
    };
}

fn message_has_payload(mtype: MessageType) bool {
    return switch (mtype) {
        .ping, .pong, .disconnect, .heartbeat, .shutdown => false,
        else => true,
    };
}

// ============================================================================
// LAYER 2: Error handling
// ============================================================================

const ErrorCode = enum(u16) {
    success = 0,
    invalid_header = 1,
    invalid_checksum = 2,
    invalid_version = 3,
    auth_failed = 4,
    session_expired = 5,
    permission_denied = 6,
    resource_not_found = 7,
    resource_busy = 8,
    timeout = 9,
    internal_error = 10,
    not_implemented = 11,
    bad_request = 12,
    rate_limited = 13,
    connection_closed = 14,
    protocol_error = 15,
};

fn error_is_recoverable(code: ErrorCode) bool {
    return switch (code) {
        .success, .timeout, .resource_busy, .rate_limited => true,
        else => false,
    };
}

fn error_requires_reconnect(code: ErrorCode) bool {
    return switch (code) {
        .session_expired, .connection_closed, .protocol_error => true,
        else => false,
    };
}

fn error_to_string(code: ErrorCode) []const u8 {
    return switch (code) {
        .success => "Success",
        .invalid_header => "Invalid header",
        .invalid_checksum => "Invalid checksum",
        .invalid_version => "Invalid version",
        .auth_failed => "Authentication failed",
        .session_expired => "Session expired",
        .permission_denied => "Permission denied",
        .resource_not_found => "Resource not found",
        .resource_busy => "Resource busy",
        .timeout => "Timeout",
        .internal_error => "Internal error",
        .not_implemented => "Not implemented",
        .bad_request => "Bad request",
        .rate_limited => "Rate limited",
        .connection_closed => "Connection closed",
        .protocol_error => "Protocol error",
    };
}

fn error_get_severity(code: ErrorCode) u8 {
    return switch (code) {
        .success => 0,
        .timeout, .resource_busy, .rate_limited => 1,
        .invalid_header, .invalid_checksum, .bad_request => 2,
        .auth_failed, .session_expired, .permission_denied => 3,
        .resource_not_found, .not_implemented => 4,
        .internal_error, .protocol_error, .connection_closed => 5,
        else => 5,
    };
}

// ============================================================================
// LAYER 2: State machine
// ============================================================================

const ConnectionState = enum {
    disconnected,
    connecting,
    authenticating,
    authenticated,
    active,
    closing,
    error_state,
};

var global_state: ConnectionState = .disconnected;
var global_session_id: u32 = 0;
var global_sequence: u32 = 0;

fn state_can_transition(from: ConnectionState, to: ConnectionState) bool {
    return switch (from) {
        .disconnected => to == .connecting,
        .connecting => to == .authenticating or to == .error_state or to == .disconnected,
        .authenticating => to == .authenticated or to == .error_state or to == .disconnected,
        .authenticated => to == .active or to == .closing or to == .error_state,
        .active => to == .closing or to == .error_state,
        .closing => to == .disconnected,
        .error_state => to == .disconnected,
    };
}

fn state_transition(to: ConnectionState) bool {
    if (state_can_transition(global_state, to)) {
        global_state = to;
        return true;
    }
    return false;
}

fn state_reset() void {
    global_state = .disconnected;
    global_session_id = 0;
    global_sequence = 0;
}

fn state_is_connected() bool {
    return switch (global_state) {
        .authenticated, .active => true,
        else => false,
    };
}

fn state_can_send() bool {
    return global_state == .active;
}

fn state_can_receive() bool {
    return switch (global_state) {
        .connecting, .authenticating, .authenticated, .active => true,
        else => false,
    };
}

// ============================================================================
// LAYER 3: Message handlers (Central dispatcher pattern)
// ============================================================================

fn handle_connect(data: []const u8) ErrorCode {
    _ = data;
    if (global_state != .disconnected) return .protocol_error;
    if (!state_transition(.connecting)) return .internal_error;
    return .success;
}

fn handle_disconnect(data: []const u8) ErrorCode {
    _ = data;
    if (!state_is_connected()) return .protocol_error;
    _ = state_transition(.closing);
    state_reset();
    return .success;
}

fn handle_ping(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_pong(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_auth_request(data: []const u8) ErrorCode {
    if (global_state != .connecting) return .protocol_error;
    if (!state_transition(.authenticating)) return .internal_error;
    if (data.len < 32) return .auth_failed;
    if (!validate_auth_token(data[0..32])) return .auth_failed;
    if (!state_transition(.authenticated)) return .internal_error;
    global_session_id = util_hash(data[0..32]);
    return .success;
}

fn handle_auth_response(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_data_request(data: []const u8) ErrorCode {
    if (!state_can_send()) return .permission_denied;
    if (data.len == 0) return .bad_request;
    return .success;
}

fn handle_data_response(data: []const u8) ErrorCode {
    if (!state_can_receive()) return .protocol_error;
    if (!validate_payload_size(data.len, 65536)) return .bad_request;
    return .success;
}

fn handle_error_response(data: []const u8) ErrorCode {
    if (data.len < 2) return .bad_request;
    const code: u16 = @as(u16, data[0]) | (@as(u16, data[1]) << 8);
    if (code > 15) return .protocol_error;
    return .success;
}

fn handle_status_query(data: []const u8) ErrorCode {
    _ = data;
    if (!state_is_connected()) return .permission_denied;
    return .success;
}

fn handle_status_response(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_config_get(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len == 0) return .bad_request;
    return .success;
}

fn handle_config_set(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len < 2) return .bad_request;
    return .success;
}

fn handle_config_response(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_file_open(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len == 0) return .bad_request;
    for (data) |c| {
        if (c == 0) break;
        if (!str_is_alnum(c) and c != '.' and c != '/' and c != '_' and c != '-') {
            return .bad_request;
        }
    }
    return .success;
}

fn handle_file_close(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len < 4) return .bad_request;
    return .success;
}

fn handle_file_read(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len < 8) return .bad_request;
    return .success;
}

fn handle_file_write(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len < 8) return .bad_request;
    return .success;
}

fn handle_file_response(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_notify(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len == 0) return .bad_request;
    return .success;
}

fn handle_subscribe(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len < 4) return .bad_request;
    return .success;
}

fn handle_unsubscribe(data: []const u8) ErrorCode {
    if (!state_is_connected()) return .permission_denied;
    if (data.len < 4) return .bad_request;
    return .success;
}

fn handle_heartbeat(data: []const u8) ErrorCode {
    _ = data;
    return .success;
}

fn handle_shutdown(data: []const u8) ErrorCode {
    _ = data;
    state_reset();
    return .success;
}

fn handle_unknown(data: []const u8) ErrorCode {
    _ = data;
    return .not_implemented;
}

// ============================================================================
// LAYER 4: Central message dispatcher (HIGH FAN-IN/FAN-OUT)
// ============================================================================

fn dispatch_message(mtype: MessageType, data: []const u8) ErrorCode {
    return switch (mtype) {
        .connect => handle_connect(data),
        .disconnect => handle_disconnect(data),
        .ping => handle_ping(data),
        .pong => handle_pong(data),
        .auth_request => handle_auth_request(data),
        .auth_response => handle_auth_response(data),
        .data_request => handle_data_request(data),
        .data_response => handle_data_response(data),
        .error_response => handle_error_response(data),
        .status_query => handle_status_query(data),
        .status_response => handle_status_response(data),
        .config_get => handle_config_get(data),
        .config_set => handle_config_set(data),
        .config_response => handle_config_response(data),
        .file_open => handle_file_open(data),
        .file_close => handle_file_close(data),
        .file_read => handle_file_read(data),
        .file_write => handle_file_write(data),
        .file_response => handle_file_response(data),
        .notify => handle_notify(data),
        .subscribe => handle_subscribe(data),
        .unsubscribe => handle_unsubscribe(data),
        .heartbeat => handle_heartbeat(data),
        .shutdown => handle_shutdown(data),
        .unknown => handle_unknown(data),
    };
}

// ============================================================================
// LAYER 3: Packet processing pipeline
// ============================================================================

fn process_packet_header(data: []const u8) ?struct { version: u8, mtype: MessageType, len: u16 } {
    if (data.len < 4) return null;
    const version = data[0];
    const mtype_byte = data[1];
    const len = @as(u16, data[2]) | (@as(u16, data[3]) << 8);
    if (!validate_packet_version(version)) return null;
    return .{
        .version = version,
        .mtype = message_type_from_byte(mtype_byte),
        .len = len,
    };
}

fn process_packet_auth(mtype: MessageType, session: u32) bool {
    if (!message_requires_auth(mtype)) return true;
    return validate_session_id(session);
}

fn process_packet_sequence(seq: u32) bool {
    if (!validate_sequence_number(seq, global_sequence)) return false;
    global_sequence = seq + 1;
    return true;
}

fn process_packet_payload(data: []const u8, expected_len: u16) ?[]const u8 {
    if (!validate_packet_length(expected_len, data.len)) return null;
    return data;
}

// ============================================================================
// LAYER 4: Main packet processor (HIGH FAN-IN)
// ============================================================================

fn process_packet(data: []const u8) ErrorCode {
    // Validate header
    if (!validate_packet_header(data)) return .invalid_header;

    // Parse header
    const header = process_packet_header(data) orelse return .invalid_header;

    // Check auth requirement
    if (!process_packet_auth(header.mtype, global_session_id)) return .auth_failed;

    // Get payload
    const payload_start: usize = 8; // Header size
    if (data.len < payload_start) return .bad_request;

    const payload = data[payload_start..];

    // Dispatch to handler
    return dispatch_message(header.mtype, payload);
}

// ============================================================================
// LAYER 2: Crypto utilities (isolated cluster with internal calls)
// ============================================================================

fn crypto_xor_block(data: []u8, key: []const u8) void {
    for (data, 0..) |*b, i| {
        b.* ^= key[i % key.len];
    }
}

fn crypto_rotate_key(key: []u8) void {
    if (key.len == 0) return;
    const first = key[0];
    for (0..key.len - 1) |i| {
        key[i] = key[i + 1];
    }
    key[key.len - 1] = first;
}

fn crypto_derive_key(master: []const u8, salt: u32) u32 {
    var h = util_hash(master);
    h ^= salt;
    h = util_rotate_left(h, 13);
    h *%= 0x5bd1e995;
    return h;
}

fn crypto_hmac_simple(data: []const u8, key: []const u8) u32 {
    var h1 = util_hash(key);
    const h2 = util_hash(data);
    h1 ^= util_rotate_left(h2, 16);
    return h1 *% h2;
}

fn crypto_verify_signature(data: []const u8, sig: u32, key: []const u8) bool {
    const expected = crypto_hmac_simple(data, key);
    return expected == sig;
}

fn crypto_generate_nonce(seed: u64) u32 {
    var s = seed;
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    return @truncate(s *% 0x2545F4914F6CDD1D);
}

fn crypto_pad_pkcs7(data: []u8, len: usize, block_size: u8) usize {
    const padding = block_size - @as(u8, @truncate(len % block_size));
    var i: usize = len;
    while (i < len + padding and i < data.len) : (i += 1) {
        data[i] = padding;
    }
    return len + padding;
}

fn crypto_unpad_pkcs7(data: []const u8) ?[]const u8 {
    if (data.len == 0) return null;
    const padding = data[data.len - 1];
    if (padding == 0 or padding > data.len) return null;
    return data[0 .. data.len - padding];
}

// ============================================================================
// LAYER 3: Session management
// ============================================================================

const Session = struct {
    id: u32,
    created: u64,
    last_active: u64,
    state: ConnectionState,
    sequence: u32,
};

var sessions: [16]Session = undefined;
var session_count: usize = 0;

fn session_create(timestamp: u64) ?*Session {
    if (session_count >= sessions.len) return null;
    const id = crypto_generate_nonce(timestamp);
    sessions[session_count] = .{
        .id = id,
        .created = timestamp,
        .last_active = timestamp,
        .state = .disconnected,
        .sequence = 0,
    };
    session_count += 1;
    return &sessions[session_count - 1];
}

fn session_find(id: u32) ?*Session {
    for (&sessions) |*s| {
        if (s.id == id) return s;
    }
    return null;
}

fn session_update_activity(s: *Session, timestamp: u64) void {
    s.last_active = timestamp;
}

fn session_is_expired(s: *Session, current: u64, timeout: u64) bool {
    return current - s.last_active > timeout;
}

fn session_destroy(id: u32) bool {
    for (&sessions, 0..) |*s, i| {
        if (s.id == id) {
            // Shift remaining sessions
            var j = i;
            while (j < session_count - 1) : (j += 1) {
                sessions[j] = sessions[j + 1];
            }
            session_count -= 1;
            return true;
        }
    }
    return false;
}

fn session_cleanup_expired(current: u64, timeout: u64) usize {
    var removed: usize = 0;
    var i: usize = 0;
    while (i < session_count) {
        if (session_is_expired(&sessions[i], current, timeout)) {
            _ = session_destroy(sessions[i].id);
            removed += 1;
        } else {
            i += 1;
        }
    }
    return removed;
}

// ============================================================================
// LAYER 2: Buffer management
// ============================================================================

const Buffer = struct {
    data: [4096]u8,
    len: usize,
    pos: usize,
};

fn buffer_init() Buffer {
    return .{
        .data = undefined,
        .len = 0,
        .pos = 0,
    };
}

fn buffer_reset(b: *Buffer) void {
    b.len = 0;
    b.pos = 0;
}

fn buffer_remaining(b: *Buffer) usize {
    return b.len - b.pos;
}

fn buffer_space(b: *Buffer) usize {
    return b.data.len - b.len;
}

fn buffer_write(b: *Buffer, data: []const u8) usize {
    const space = buffer_space(b);
    const to_write = util_min(@truncate(space), @truncate(data.len));
    @memcpy(b.data[b.len..][0..to_write], data[0..to_write]);
    b.len += to_write;
    return to_write;
}

fn buffer_read(b: *Buffer, out: []u8) usize {
    const available = buffer_remaining(b);
    const to_read = util_min(@truncate(available), @truncate(out.len));
    @memcpy(out[0..to_read], b.data[b.pos..][0..to_read]);
    b.pos += to_read;
    return to_read;
}

fn buffer_peek(b: *Buffer, out: []u8) usize {
    const available = buffer_remaining(b);
    const to_read = util_min(@truncate(available), @truncate(out.len));
    @memcpy(out[0..to_read], b.data[b.pos..][0..to_read]);
    return to_read;
}

fn buffer_skip(b: *Buffer, count: usize) usize {
    const available = buffer_remaining(b);
    const to_skip = util_min(@truncate(available), @truncate(count));
    b.pos += to_skip;
    return to_skip;
}

fn buffer_compact(b: *Buffer) void {
    if (b.pos == 0) return;
    const remaining = buffer_remaining(b);
    if (remaining > 0) {
        std.mem.copyForwards(u8, b.data[0..remaining], b.data[b.pos .. b.pos + remaining]);
    }
    b.len = remaining;
    b.pos = 0;
}

// ============================================================================
// LAYER 3: Command registry (callback pattern)
// ============================================================================

const CommandHandler = *const fn ([]const u8) ErrorCode;

const Command = struct {
    name: []const u8,
    handler: CommandHandler,
    min_args: usize,
    max_args: usize,
    requires_auth: bool,
};

fn cmd_help(args: []const u8) ErrorCode {
    _ = args;
    return .success;
}

fn cmd_version(args: []const u8) ErrorCode {
    _ = args;
    return .success;
}

fn cmd_status(args: []const u8) ErrorCode {
    _ = args;
    if (!state_is_connected()) return .permission_denied;
    return .success;
}

fn cmd_connect(args: []const u8) ErrorCode {
    return handle_connect(args);
}

fn cmd_disconnect(args: []const u8) ErrorCode {
    return handle_disconnect(args);
}

fn cmd_auth(args: []const u8) ErrorCode {
    return handle_auth_request(args);
}

fn cmd_ping(args: []const u8) ErrorCode {
    return handle_ping(args);
}

fn cmd_get(args: []const u8) ErrorCode {
    return handle_config_get(args);
}

fn cmd_set(args: []const u8) ErrorCode {
    return handle_config_set(args);
}

fn cmd_list(args: []const u8) ErrorCode {
    _ = args;
    if (!state_is_connected()) return .permission_denied;
    return .success;
}

fn cmd_read(args: []const u8) ErrorCode {
    return handle_file_read(args);
}

fn cmd_write(args: []const u8) ErrorCode {
    return handle_file_write(args);
}

fn cmd_delete(args: []const u8) ErrorCode {
    _ = args;
    if (!state_is_connected()) return .permission_denied;
    return .success;
}

fn cmd_subscribe(args: []const u8) ErrorCode {
    return handle_subscribe(args);
}

fn cmd_unsubscribe(args: []const u8) ErrorCode {
    return handle_unsubscribe(args);
}

fn cmd_quit(args: []const u8) ErrorCode {
    return handle_shutdown(args);
}

const commands = [_]Command{
    .{ .name = "help", .handler = cmd_help, .min_args = 0, .max_args = 1, .requires_auth = false },
    .{ .name = "version", .handler = cmd_version, .min_args = 0, .max_args = 0, .requires_auth = false },
    .{ .name = "status", .handler = cmd_status, .min_args = 0, .max_args = 0, .requires_auth = true },
    .{ .name = "connect", .handler = cmd_connect, .min_args = 0, .max_args = 2, .requires_auth = false },
    .{ .name = "disconnect", .handler = cmd_disconnect, .min_args = 0, .max_args = 0, .requires_auth = true },
    .{ .name = "auth", .handler = cmd_auth, .min_args = 1, .max_args = 1, .requires_auth = false },
    .{ .name = "ping", .handler = cmd_ping, .min_args = 0, .max_args = 0, .requires_auth = false },
    .{ .name = "get", .handler = cmd_get, .min_args = 1, .max_args = 1, .requires_auth = true },
    .{ .name = "set", .handler = cmd_set, .min_args = 2, .max_args = 2, .requires_auth = true },
    .{ .name = "list", .handler = cmd_list, .min_args = 0, .max_args = 1, .requires_auth = true },
    .{ .name = "read", .handler = cmd_read, .min_args = 1, .max_args = 3, .requires_auth = true },
    .{ .name = "write", .handler = cmd_write, .min_args = 2, .max_args = 3, .requires_auth = true },
    .{ .name = "delete", .handler = cmd_delete, .min_args = 1, .max_args = 1, .requires_auth = true },
    .{ .name = "subscribe", .handler = cmd_subscribe, .min_args = 1, .max_args = 2, .requires_auth = true },
    .{ .name = "unsubscribe", .handler = cmd_unsubscribe, .min_args = 1, .max_args = 1, .requires_auth = true },
    .{ .name = "quit", .handler = cmd_quit, .min_args = 0, .max_args = 0, .requires_auth = false },
};

// ============================================================================
// LAYER 4: Command dispatcher (HIGH FAN-OUT)
// ============================================================================

fn find_command(name: []const u8) ?*const Command {
    for (&commands) |*cmd| {
        if (str_compare(cmd.name, name) == 0) return cmd;
    }
    return null;
}

fn dispatch_command(name: []const u8, args: []const u8) ErrorCode {
    const cmd = find_command(name) orelse return .not_implemented;
    if (cmd.requires_auth and !state_is_connected()) {
        return .permission_denied;
    }
    return cmd.handler(args);
}

// ============================================================================
// LAYER 2: Event system (mutual recursion pattern)
// ============================================================================

const EventType = enum(u8) {
    none = 0,
    connected = 1,
    disconnected = 2,
    authenticated = 3,
    data_received = 4,
    error_occurred = 5,
    timeout = 6,
    state_changed = 7,
};

const Event = struct {
    etype: EventType,
    source: u32,
    data: u32,
    timestamp: u64,
};

var event_queue: [64]Event = undefined;
var event_head: usize = 0;
var event_tail: usize = 0;

fn event_queue_push(e: Event) bool {
    const next = (event_tail + 1) % event_queue.len;
    if (next == event_head) return false;
    event_queue[event_tail] = e;
    event_tail = next;
    return true;
}

fn event_queue_pop() ?Event {
    if (event_head == event_tail) return null;
    const e = event_queue[event_head];
    event_head = (event_head + 1) % event_queue.len;
    return e;
}

fn event_queue_is_empty() bool {
    return event_head == event_tail;
}

fn event_queue_clear() void {
    event_head = 0;
    event_tail = 0;
}

// Mutual recursion: event_dispatch can trigger event_emit, which can call event_dispatch
fn event_emit(etype: EventType, source: u32, data: u32, ts: u64) void {
    const e = Event{
        .etype = etype,
        .source = source,
        .data = data,
        .timestamp = ts,
    };
    _ = event_queue_push(e);
}

fn event_handle_connected(e: Event) void {
    _ = e;
    // Could emit more events
    event_emit(.state_changed, 0, @intFromEnum(ConnectionState.connecting), 0);
}

fn event_handle_disconnected(e: Event) void {
    _ = e;
    event_emit(.state_changed, 0, @intFromEnum(ConnectionState.disconnected), 0);
}

fn event_handle_authenticated(e: Event) void {
    _ = e;
    event_emit(.state_changed, 0, @intFromEnum(ConnectionState.authenticated), 0);
}

fn event_handle_data_received(e: Event) void {
    _ = e;
}

fn event_handle_error(e: Event) void {
    if (e.data > 10) {
        event_emit(.disconnected, e.source, 0, e.timestamp);
    }
}

fn event_handle_timeout(e: Event) void {
    _ = e;
    event_emit(.error_occurred, 0, @intFromEnum(ErrorCode.timeout), 0);
}

fn event_handle_state_changed(e: Event) void {
    _ = e;
}

// Central event dispatcher with mutual recursion potential
fn event_dispatch(e: Event) void {
    switch (e.etype) {
        .none => {},
        .connected => event_handle_connected(e),
        .disconnected => event_handle_disconnected(e),
        .authenticated => event_handle_authenticated(e),
        .data_received => event_handle_data_received(e),
        .error_occurred => event_handle_error(e),
        .timeout => event_handle_timeout(e),
        .state_changed => event_handle_state_changed(e),
    }
}

fn event_process_all() void {
    var iterations: usize = 0;
    while (!event_queue_is_empty() and iterations < 100) : (iterations += 1) {
        if (event_queue_pop()) |e| {
            event_dispatch(e);
        }
    }
}

// ============================================================================
// LAYER 3: Protocol encoder/decoder
// ============================================================================

fn protocol_encode_header(buf: []u8, version: u8, mtype: MessageType, len: u16) usize {
    if (buf.len < 4) return 0;
    buf[0] = version;
    buf[1] = @intFromEnum(mtype);
    buf[2] = @truncate(len);
    buf[3] = @truncate(len >> 8);
    return 4;
}

fn protocol_encode_session(buf: []u8, session_id: u32) usize {
    if (buf.len < 4) return 0;
    buf[0] = @truncate(session_id);
    buf[1] = @truncate(session_id >> 8);
    buf[2] = @truncate(session_id >> 16);
    buf[3] = @truncate(session_id >> 24);
    return 4;
}

fn protocol_encode_sequence(buf: []u8, seq: u32) usize {
    return protocol_encode_session(buf, seq);
}

fn protocol_decode_u16(data: []const u8) u16 {
    if (data.len < 2) return 0;
    return @as(u16, data[0]) | (@as(u16, data[1]) << 8);
}

fn protocol_decode_u32(data: []const u8) u32 {
    if (data.len < 4) return 0;
    return @as(u32, data[0]) |
        (@as(u32, data[1]) << 8) |
        (@as(u32, data[2]) << 16) |
        (@as(u32, data[3]) << 24);
}

fn protocol_encode_string(buf: []u8, s: []const u8) usize {
    if (buf.len < 2 + s.len) return 0;
    const len: u16 = @truncate(s.len);
    buf[0] = @truncate(len);
    buf[1] = @truncate(len >> 8);
    @memcpy(buf[2..][0..s.len], s);
    return 2 + s.len;
}

fn protocol_decode_string(data: []const u8) ?[]const u8 {
    if (data.len < 2) return null;
    const len = protocol_decode_u16(data);
    if (data.len < 2 + len) return null;
    return data[2..][0..len];
}

// ============================================================================
// LAYER 3: Parser combinators (recursive descent pattern)
// ============================================================================

const ParseResult = struct {
    success: bool,
    consumed: usize,
    value: u32,
};

fn parse_digit(data: []const u8, pos: usize) ParseResult {
    if (pos >= data.len) return .{ .success = false, .consumed = 0, .value = 0 };
    if (str_is_digit(data[pos])) {
        return .{ .success = true, .consumed = 1, .value = data[pos] - '0' };
    }
    return .{ .success = false, .consumed = 0, .value = 0 };
}

fn parse_digits(data: []const u8, pos: usize) ParseResult {
    var value: u32 = 0;
    var i = pos;
    while (i < data.len and str_is_digit(data[i])) {
        value = value * 10 + (data[i] - '0');
        i += 1;
    }
    if (i == pos) return .{ .success = false, .consumed = 0, .value = 0 };
    return .{ .success = true, .consumed = i - pos, .value = value };
}

fn parse_alpha(data: []const u8, pos: usize) ParseResult {
    if (pos >= data.len) return .{ .success = false, .consumed = 0, .value = 0 };
    if (str_is_alpha(data[pos])) {
        return .{ .success = true, .consumed = 1, .value = data[pos] };
    }
    return .{ .success = false, .consumed = 0, .value = 0 };
}

fn parse_word(data: []const u8, pos: usize) ParseResult {
    var i = pos;
    while (i < data.len and str_is_alnum(data[i])) {
        i += 1;
    }
    if (i == pos) return .{ .success = false, .consumed = 0, .value = 0 };
    return .{ .success = true, .consumed = i - pos, .value = @truncate(i - pos) };
}

fn parse_whitespace(data: []const u8, pos: usize) ParseResult {
    var i = pos;
    while (i < data.len and str_is_space(data[i])) {
        i += 1;
    }
    return .{ .success = true, .consumed = i - pos, .value = @truncate(i - pos) };
}

fn parse_literal(data: []const u8, pos: usize, expected: []const u8) ParseResult {
    if (pos + expected.len > data.len) return .{ .success = false, .consumed = 0, .value = 0 };
    if (std.mem.eql(u8, data[pos..][0..expected.len], expected)) {
        return .{ .success = true, .consumed = expected.len, .value = @truncate(expected.len) };
    }
    return .{ .success = false, .consumed = 0, .value = 0 };
}

// Recursive descent: parse_expression calls parse_term which calls parse_factor
fn parse_factor(data: []const u8, pos: usize) ParseResult {
    // Try number
    const num = parse_digits(data, pos);
    if (num.success) return num;

    // Try parenthesized expression
    const lparen = parse_literal(data, pos, "(");
    if (lparen.success) {
        const expr = parse_expression(data, pos + 1);
        if (expr.success) {
            const rparen = parse_literal(data, pos + 1 + expr.consumed, ")");
            if (rparen.success) {
                return .{
                    .success = true,
                    .consumed = 1 + expr.consumed + 1,
                    .value = expr.value,
                };
            }
        }
    }

    return .{ .success = false, .consumed = 0, .value = 0 };
}

fn parse_term(data: []const u8, pos: usize) ParseResult {
    var result = parse_factor(data, pos);
    if (!result.success) return result;

    var i = pos + result.consumed;
    while (i < data.len) {
        if (data[i] == '*') {
            const next = parse_factor(data, i + 1);
            if (!next.success) break;
            result.value *%= next.value;
            result.consumed += 1 + next.consumed;
            i += 1 + next.consumed;
        } else if (data[i] == '/') {
            const next = parse_factor(data, i + 1);
            if (!next.success or next.value == 0) break;
            result.value /= next.value;
            result.consumed += 1 + next.consumed;
            i += 1 + next.consumed;
        } else {
            break;
        }
    }
    return result;
}

fn parse_expression(data: []const u8, pos: usize) ParseResult {
    var result = parse_term(data, pos);
    if (!result.success) return result;

    var i = pos + result.consumed;
    while (i < data.len) {
        if (data[i] == '+') {
            const next = parse_term(data, i + 1);
            if (!next.success) break;
            result.value +%= next.value;
            result.consumed += 1 + next.consumed;
            i += 1 + next.consumed;
        } else if (data[i] == '-') {
            const next = parse_term(data, i + 1);
            if (!next.success) break;
            result.value -%= next.value;
            result.consumed += 1 + next.consumed;
            i += 1 + next.consumed;
        } else {
            break;
        }
    }
    return result;
}

// ============================================================================
// LAYER 2: Configuration management
// ============================================================================

const ConfigEntry = struct {
    key: []const u8,
    value: u32,
    readonly: bool,
};

var config_entries: [32]ConfigEntry = undefined;
var config_count: usize = 0;

fn config_init() void {
    config_count = 0;
}

fn config_set_entry(key: []const u8, value: u32, readonly: bool) bool {
    // Check if exists
    for (&config_entries) |*e| {
        if (str_compare(e.key, key) == 0) {
            if (e.readonly) return false;
            e.value = value;
            return true;
        }
    }
    // Add new
    if (config_count >= config_entries.len) return false;
    config_entries[config_count] = .{
        .key = key,
        .value = value,
        .readonly = readonly,
    };
    config_count += 1;
    return true;
}

fn config_get_entry(key: []const u8) ?u32 {
    for (&config_entries) |*e| {
        if (str_compare(e.key, key) == 0) {
            return e.value;
        }
    }
    return null;
}

fn config_delete_entry(key: []const u8) bool {
    for (&config_entries, 0..) |*e, i| {
        if (str_compare(e.key, key) == 0) {
            if (e.readonly) return false;
            var j = i;
            while (j < config_count - 1) : (j += 1) {
                config_entries[j] = config_entries[j + 1];
            }
            config_count -= 1;
            return true;
        }
    }
    return false;
}

fn config_entry_count() usize {
    return config_count;
}

fn config_clear() void {
    config_count = 0;
}

// ============================================================================
// LAYER 2: Resource pool management
// ============================================================================

const Resource = struct {
    id: u32,
    rtype: u8,
    refcount: u32,
    data: u64,
};

var resource_pool: [64]Resource = undefined;
var resource_count: usize = 0;

fn resource_alloc(rtype: u8, data: u64) ?*Resource {
    if (resource_count >= resource_pool.len) return null;
    const id = @as(u32, @truncate(resource_count)) + 1;
    resource_pool[resource_count] = .{
        .id = id,
        .rtype = rtype,
        .refcount = 1,
        .data = data,
    };
    resource_count += 1;
    return &resource_pool[resource_count - 1];
}

fn resource_find(id: u32) ?*Resource {
    for (&resource_pool) |*r| {
        if (r.id == id) return r;
    }
    return null;
}

fn resource_acquire(r: *Resource) void {
    r.refcount += 1;
}

fn resource_release(r: *Resource) bool {
    if (r.refcount == 0) return false;
    r.refcount -= 1;
    return r.refcount == 0;
}

fn resource_free(id: u32) bool {
    for (&resource_pool, 0..) |*r, i| {
        if (r.id == id) {
            if (r.refcount > 0) return false;
            var j = i;
            while (j < resource_count - 1) : (j += 1) {
                resource_pool[j] = resource_pool[j + 1];
            }
            resource_count -= 1;
            return true;
        }
    }
    return false;
}

fn resource_count_by_type(rtype: u8) usize {
    var count: usize = 0;
    for (&resource_pool) |*r| {
        if (r.rtype == rtype) count += 1;
    }
    return count;
}

// ============================================================================
// LAYER 3: Logging system
// ============================================================================

const LogLevel = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,
    fatal = 5,
};

var log_level: LogLevel = .info;
var log_count: u64 = 0;

fn log_set_level(level: LogLevel) void {
    log_level = level;
}

fn log_should_log(level: LogLevel) bool {
    return @intFromEnum(level) >= @intFromEnum(log_level);
}

fn log_format_level(level: LogLevel) []const u8 {
    return switch (level) {
        .trace => "TRACE",
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .err => "ERROR",
        .fatal => "FATAL",
    };
}

fn log_entry(level: LogLevel, msg: []const u8) void {
    if (!log_should_log(level)) return;
    _ = msg;
    log_count += 1;
}

fn log_trace(msg: []const u8) void {
    log_entry(.trace, msg);
}

fn log_debug(msg: []const u8) void {
    log_entry(.debug, msg);
}

fn log_info(msg: []const u8) void {
    log_entry(.info, msg);
}

fn log_warn(msg: []const u8) void {
    log_entry(.warn, msg);
}

fn log_error(msg: []const u8) void {
    log_entry(.err, msg);
}

fn log_fatal(msg: []const u8) void {
    log_entry(.fatal, msg);
}

fn log_get_count() u64 {
    return log_count;
}

fn log_reset() void {
    log_count = 0;
}

// ============================================================================
// LAYER 4: Main processing loop (HIGH FAN-OUT - calls many subsystems)
// ============================================================================

fn init_subsystems() void {
    state_reset();
    config_init();
    event_queue_clear();
    log_reset();
    log_set_level(.debug);
    log_info("Subsystems initialized");
}

fn process_input(data: []const u8) ErrorCode {
    log_debug("Processing input");

    // Validate
    if (!validate_packet_header(data)) {
        log_warn("Invalid packet header");
        return .invalid_header;
    }

    // Process
    const result = process_packet(data);

    // Emit event
    if (result == .success) {
        event_emit(.data_received, 0, @truncate(data.len), 0);
    } else {
        event_emit(.error_occurred, 0, @intFromEnum(result), 0);
    }

    // Process events
    event_process_all();

    return result;
}

fn cleanup_subsystems() void {
    log_info("Cleaning up subsystems");
    state_reset();
    config_clear();
    event_queue_clear();
    session_count = 0;
    resource_count = 0;
}

// ============================================================================
// LAYER 5: High-level API (Facade pattern - HIGH FAN-OUT)
// ============================================================================

fn api_connect(host: []const u8, port: u16) ErrorCode {
    _ = host;
    _ = port;
    log_info("API: connect");
    return handle_connect(&[_]u8{});
}

fn api_authenticate(token: []const u8) ErrorCode {
    log_info("API: authenticate");
    return handle_auth_request(token);
}

fn api_send_data(data: []const u8) ErrorCode {
    log_info("API: send_data");
    return handle_data_request(data);
}

fn api_receive_data(buffer: []u8) ErrorCode {
    _ = buffer;
    log_info("API: receive_data");
    return handle_data_response(&[_]u8{});
}

fn api_get_config(key: []const u8) ?u32 {
    log_debug("API: get_config");
    return config_get_entry(key);
}

fn api_set_config(key: []const u8, value: u32) bool {
    log_debug("API: set_config");
    return config_set_entry(key, value, false);
}

fn api_subscribe_event(channel: u32) ErrorCode {
    log_info("API: subscribe");
    var buf: [4]u8 = undefined;
    buf[0] = @truncate(channel);
    buf[1] = @truncate(channel >> 8);
    buf[2] = @truncate(channel >> 16);
    buf[3] = @truncate(channel >> 24);
    return handle_subscribe(&buf);
}

fn api_unsubscribe_event(channel: u32) ErrorCode {
    log_info("API: unsubscribe");
    var buf: [4]u8 = undefined;
    buf[0] = @truncate(channel);
    buf[1] = @truncate(channel >> 8);
    buf[2] = @truncate(channel >> 16);
    buf[3] = @truncate(channel >> 24);
    return handle_unsubscribe(&buf);
}

fn api_disconnect() ErrorCode {
    log_info("API: disconnect");
    return handle_disconnect(&[_]u8{});
}

fn api_get_status() ConnectionState {
    return global_state;
}

// ============================================================================
// LAYER 5: Test/demo functions
// ============================================================================

fn demo_utils() void {
    _ = util_hash("test");
    _ = util_checksum("data");
    _ = util_clamp(50, 0, 100);
    _ = util_abs(-42);
    _ = math_gcd(48, 18);
    _ = math_fibonacci(10);
    _ = str_compare("abc", "def");
}

fn demo_crypto() void {
    var key = [_]u8{ 1, 2, 3, 4 };
    var data = [_]u8{ 5, 6, 7, 8 };
    crypto_xor_block(&data, &key);
    crypto_rotate_key(&key);
    _ = crypto_derive_key("master", 12345);
    _ = crypto_hmac_simple("data", "key");
}

fn demo_protocol() void {
    var buf: [64]u8 = undefined;
    _ = protocol_encode_header(&buf, 1, .ping, 0);
    _ = protocol_encode_session(buf[4..], 12345);
    _ = protocol_encode_string(buf[8..], "hello");
}

fn demo_parsing() void {
    _ = parse_expression("1+2*3", 0);
    _ = parse_word("hello123", 0);
    _ = parse_digits("12345", 0);
}

fn demo_events() void {
    event_emit(.connected, 0, 0, 0);
    event_emit(.authenticated, 0, 0, 0);
    event_process_all();
}

fn demo_sessions() void {
    _ = session_create(1000);
    _ = session_cleanup_expired(2000, 500);
}

fn demo_resources() void {
    const r = resource_alloc(1, 0xDEADBEEF);
    if (r) |res| {
        resource_acquire(res);
        _ = resource_release(res);
    }
}

fn demo_config() void {
    config_init();
    _ = config_set_entry("timeout", 30, false);
    _ = config_set_entry("max_conn", 100, true);
    _ = config_get_entry("timeout");
}

fn demo_buffers() void {
    var b = buffer_init();
    _ = buffer_write(&b, "test data");
    var out: [32]u8 = undefined;
    _ = buffer_read(&b, &out);
    buffer_compact(&b);
}

fn demo_commands() void {
    _ = dispatch_command("help", "");
    _ = dispatch_command("version", "");
    _ = dispatch_command("ping", "");
}

fn demo_logging() void {
    log_trace("trace message");
    log_debug("debug message");
    log_info("info message");
    log_warn("warn message");
    log_error("error message");
}

fn demo_validation() void {
    _ = validate_auth_token("12345678901234567890123456789012");
    _ = validate_session_id(12345);
    _ = validate_timestamp(900, 1000);
}

fn demo_encoding() void {
    _ = encode_base64_char(0);
    _ = decode_base64_char('A');
    _ = encode_hex_digit(15);
    _ = decode_hex_digit('F');
    var buf: [8]u8 = undefined;
    _ = encode_varint(12345, &buf);
    _ = decode_varint(&buf);
    _ = encode_zigzag(-100);
    _ = decode_zigzag(199);
}

fn run_all_demos() void {
    demo_utils();
    demo_crypto();
    demo_protocol();
    demo_parsing();
    demo_events();
    demo_sessions();
    demo_resources();
    demo_config();
    demo_buffers();
    demo_commands();
    demo_logging();
    demo_validation();
    demo_encoding();
}

// ============================================================================
// MAIN ENTRYPOINT
// ============================================================================

pub fn main() void {
    // Initialize all subsystems
    init_subsystems();

    // Run demos to ensure all functions are linked
    run_all_demos();

    // Simulate some protocol activity
    _ = api_connect("localhost", 8080);

    // Create a fake auth token
    const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
    _ = api_authenticate(token);

    // Try some operations
    _ = api_set_config("debug", 1);
    _ = api_get_config("debug");
    _ = api_subscribe_event(100);
    _ = api_send_data("Hello, World!");

    // Process a simulated packet
    var packet: [64]u8 = undefined;
    packet[0] = 1; // version
    packet[1] = @intFromEnum(MessageType.ping); // type
    packet[2] = 0; // len low
    packet[3] = 0; // len high
    packet[4] = 0; // session id
    packet[5] = 0;
    packet[6] = 0;
    packet[7] = 0;
    _ = process_input(&packet);

    // Cleanup
    _ = api_unsubscribe_event(100);
    _ = api_disconnect();
    cleanup_subsystems();

    // Print completion message using posix write
    const message =
        \\Callgraph demo binary executed successfully.
        \\This binary contains ~250 functions with:
        \\  - Central dispatchers (dispatch_message, dispatch_command, event_dispatch)
        \\  - Multiple call layers (utils -> validation -> handlers -> dispatchers -> API)
        \\  - Mutual recursion (event system, parser combinators)
        \\  - Isolated utility clusters (math, string, crypto)
        \\
    ;
    _ = std.posix.write(std.posix.STDOUT_FILENO, message) catch {};
}

// Force all functions to be exported/linked
comptime {
    // Utilities
    _ = &util_hash;
    _ = &util_checksum;
    _ = &util_validate_length;
    _ = &util_clamp;
    _ = &util_abs;
    _ = &util_min;
    _ = &util_max;
    _ = &util_swap;
    _ = &util_rotate_left;
    _ = &util_rotate_right;
    // String utilities
    _ = &str_length;
    _ = &str_compare;
    _ = &str_starts_with;
    _ = &str_ends_with;
    _ = &str_to_upper;
    _ = &str_to_lower;
    _ = &str_is_digit;
    _ = &str_is_alpha;
    _ = &str_is_alnum;
    _ = &str_is_space;
    // Math utilities
    _ = &math_gcd;
    _ = &math_lcm;
    _ = &math_pow;
    _ = &math_sqrt_int;
    _ = &math_is_prime;
    _ = &math_factorial;
    _ = &math_fibonacci;
    _ = &math_mod_pow;
    // Validation
    _ = &validate_packet_header;
    _ = &validate_packet_checksum;
    _ = &validate_packet_version;
    _ = &validate_packet_type;
    _ = &validate_packet_length;
    _ = &validate_auth_token;
    _ = &validate_session_id;
    _ = &validate_sequence_number;
    _ = &validate_timestamp;
    _ = &validate_payload_size;
    // Encoding
    _ = &encode_base64_char;
    _ = &decode_base64_char;
    _ = &encode_hex_digit;
    _ = &decode_hex_digit;
    _ = &encode_varint;
    _ = &decode_varint;
    _ = &encode_zigzag;
    _ = &decode_zigzag;
    // Message types
    _ = &message_type_from_byte;
    _ = &message_requires_auth;
    _ = &message_is_response;
    _ = &message_has_payload;
    // Error handling
    _ = &error_is_recoverable;
    _ = &error_requires_reconnect;
    _ = &error_to_string;
    _ = &error_get_severity;
    // State machine
    _ = &state_can_transition;
    _ = &state_transition;
    _ = &state_reset;
    _ = &state_is_connected;
    _ = &state_can_send;
    _ = &state_can_receive;
    // Message handlers
    _ = &handle_connect;
    _ = &handle_disconnect;
    _ = &handle_ping;
    _ = &handle_pong;
    _ = &handle_auth_request;
    _ = &handle_auth_response;
    _ = &handle_data_request;
    _ = &handle_data_response;
    _ = &handle_error_response;
    _ = &handle_status_query;
    _ = &handle_status_response;
    _ = &handle_config_get;
    _ = &handle_config_set;
    _ = &handle_config_response;
    _ = &handle_file_open;
    _ = &handle_file_close;
    _ = &handle_file_read;
    _ = &handle_file_write;
    _ = &handle_file_response;
    _ = &handle_notify;
    _ = &handle_subscribe;
    _ = &handle_unsubscribe;
    _ = &handle_heartbeat;
    _ = &handle_shutdown;
    _ = &handle_unknown;
    // Dispatchers
    _ = &dispatch_message;
    _ = &dispatch_command;
    // Packet processing
    _ = &process_packet_header;
    _ = &process_packet_auth;
    _ = &process_packet_sequence;
    _ = &process_packet_payload;
    _ = &process_packet;
    // Crypto
    _ = &crypto_xor_block;
    _ = &crypto_rotate_key;
    _ = &crypto_derive_key;
    _ = &crypto_hmac_simple;
    _ = &crypto_verify_signature;
    _ = &crypto_generate_nonce;
    _ = &crypto_pad_pkcs7;
    _ = &crypto_unpad_pkcs7;
    // Sessions
    _ = &session_create;
    _ = &session_find;
    _ = &session_update_activity;
    _ = &session_is_expired;
    _ = &session_destroy;
    _ = &session_cleanup_expired;
    // Buffers
    _ = &buffer_init;
    _ = &buffer_reset;
    _ = &buffer_remaining;
    _ = &buffer_space;
    _ = &buffer_write;
    _ = &buffer_read;
    _ = &buffer_peek;
    _ = &buffer_skip;
    _ = &buffer_compact;
    // Commands
    _ = &cmd_help;
    _ = &cmd_version;
    _ = &cmd_status;
    _ = &cmd_connect;
    _ = &cmd_disconnect;
    _ = &cmd_auth;
    _ = &cmd_ping;
    _ = &cmd_get;
    _ = &cmd_set;
    _ = &cmd_list;
    _ = &cmd_read;
    _ = &cmd_write;
    _ = &cmd_delete;
    _ = &cmd_subscribe;
    _ = &cmd_unsubscribe;
    _ = &cmd_quit;
    _ = &find_command;
    // Events
    _ = &event_queue_push;
    _ = &event_queue_pop;
    _ = &event_queue_is_empty;
    _ = &event_queue_clear;
    _ = &event_emit;
    _ = &event_handle_connected;
    _ = &event_handle_disconnected;
    _ = &event_handle_authenticated;
    _ = &event_handle_data_received;
    _ = &event_handle_error;
    _ = &event_handle_timeout;
    _ = &event_handle_state_changed;
    _ = &event_dispatch;
    _ = &event_process_all;
    // Protocol
    _ = &protocol_encode_header;
    _ = &protocol_encode_session;
    _ = &protocol_encode_sequence;
    _ = &protocol_decode_u16;
    _ = &protocol_decode_u32;
    _ = &protocol_encode_string;
    _ = &protocol_decode_string;
    // Parser
    _ = &parse_digit;
    _ = &parse_digits;
    _ = &parse_alpha;
    _ = &parse_word;
    _ = &parse_whitespace;
    _ = &parse_literal;
    _ = &parse_factor;
    _ = &parse_term;
    _ = &parse_expression;
    // Config
    _ = &config_init;
    _ = &config_set_entry;
    _ = &config_get_entry;
    _ = &config_delete_entry;
    _ = &config_entry_count;
    _ = &config_clear;
    // Resources
    _ = &resource_alloc;
    _ = &resource_find;
    _ = &resource_acquire;
    _ = &resource_release;
    _ = &resource_free;
    _ = &resource_count_by_type;
    // Logging
    _ = &log_set_level;
    _ = &log_should_log;
    _ = &log_format_level;
    _ = &log_entry;
    _ = &log_trace;
    _ = &log_debug;
    _ = &log_info;
    _ = &log_warn;
    _ = &log_error;
    _ = &log_fatal;
    _ = &log_get_count;
    _ = &log_reset;
    // Main processing
    _ = &init_subsystems;
    _ = &process_input;
    _ = &cleanup_subsystems;
    // API
    _ = &api_connect;
    _ = &api_authenticate;
    _ = &api_send_data;
    _ = &api_receive_data;
    _ = &api_get_config;
    _ = &api_set_config;
    _ = &api_subscribe_event;
    _ = &api_unsubscribe_event;
    _ = &api_disconnect;
    _ = &api_get_status;
    // Demos
    _ = &demo_utils;
    _ = &demo_crypto;
    _ = &demo_protocol;
    _ = &demo_parsing;
    _ = &demo_events;
    _ = &demo_sessions;
    _ = &demo_resources;
    _ = &demo_config;
    _ = &demo_buffers;
    _ = &demo_commands;
    _ = &demo_logging;
    _ = &demo_validation;
    _ = &demo_encoding;
    _ = &run_all_demos;
}
