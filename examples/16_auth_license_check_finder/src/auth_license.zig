const std = @import("std");

// ============================================================================
// AUTH/LICENSE VERIFICATION BINARY
// This binary simulates various license checking and authentication patterns
// commonly found in commercial software for reverse engineering practice.
// ============================================================================

// ============================================================================
// LICENSE KEY VALIDATION
// Various key format checking and validation functions
// ============================================================================

// License key format: XXXX-XXXX-XXXX-XXXX (alphanumeric)
const EXPECTED_KEY_HASH: u32 = 0xDEADBEEF;
const LICENSE_MAGIC: u32 = 0x4C494345; // "LICE"
const TRIAL_DAYS: u32 = 30;

// Strings that will appear in binary (searchable patterns)
const LICENSE_EXPIRED_MSG = "License has expired. Please renew your subscription.";
const LICENSE_INVALID_MSG = "Invalid license key. Please check and try again.";
const LICENSE_VALID_MSG = "License validated successfully!";
const TRIAL_EXPIRED_MSG = "Trial period has ended. Please purchase a license.";
const TRIAL_REMAINING_MSG = "Trial mode: %d days remaining";
const FEATURE_LOCKED_MSG = "This feature requires a Pro license.";
const FEATURE_UNLOCKED_MSG = "Pro feature unlocked.";
const AUTH_FAILED_MSG = "Authentication failed. Access denied.";
const AUTH_SUCCESS_MSG = "Authentication successful. Welcome!";
const HWID_MISMATCH_MSG = "Hardware ID mismatch. License not valid for this machine.";
const SERIAL_INVALID_MSG = "Invalid serial number format.";
const CHECKSUM_FAILED_MSG = "License checksum verification failed.";

// License validation function 1: Check key format (XXXX-XXXX-XXXX-XXXX)
fn validate_key_format(key: []const u8) bool {
    if (key.len != 19) return false;

    var i: usize = 0;
    while (i < key.len) : (i += 1) {
        if (i == 4 or i == 9 or i == 14) {
            if (key[i] != '-') return false;
        } else {
            const c = key[i];
            if (!((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'))) {
                return false;
            }
        }
    }
    return true;
}

// License validation function 2: Compute key hash
fn compute_key_hash(key: []const u8) u32 {
    var hash: u32 = 0x811c9dc5; // FNV offset basis
    for (key) |byte| {
        if (byte != '-') {
            hash ^= byte;
            hash *%= 0x01000193; // FNV prime
        }
    }
    return hash;
}

// License validation function 3: Verify key checksum (last 4 digits)
fn verify_key_checksum(key: []const u8) bool {
    if (key.len < 4) return false;

    // Compute checksum of first part
    var sum: u16 = 0;
    for (key[0 .. key.len - 4]) |c| {
        if (c != '-') {
            sum +%= c;
            sum ^= (sum << 5);
        }
    }

    // Compare with embedded checksum (last 4 chars as hex)
    const check_str = key[key.len - 4 ..];
    const expected = parse_hex_u16(check_str) orelse return false;

    return sum == expected;
}

fn parse_hex_u16(str: []const u8) ?u16 {
    if (str.len != 4) return null;
    var result: u16 = 0;
    for (str) |c| {
        const digit: u16 = if (c >= '0' and c <= '9')
            c - '0'
        else if (c >= 'A' and c <= 'F')
            c - 'A' + 10
        else if (c >= 'a' and c <= 'f')
            c - 'a' + 10
        else
            return null;
        result = result * 16 + digit;
    }
    return result;
}

// License validation function 4: Full license key validation
fn validate_license_key(key: []const u8) bool {
    // Step 1: Format check
    if (!validate_key_format(key)) {
        log_error(SERIAL_INVALID_MSG);
        return false;
    }

    // Step 2: Checksum verification
    if (!verify_key_checksum(key)) {
        log_error(CHECKSUM_FAILED_MSG);
        return false;
    }

    // Step 3: Hash verification against expected
    const hash = compute_key_hash(key);
    if (hash != EXPECTED_KEY_HASH) {
        log_error(LICENSE_INVALID_MSG);
        return false;
    }

    log_info(LICENSE_VALID_MSG);
    return true;
}

// ============================================================================
// SERIAL NUMBER CHECKING
// Different serial validation patterns
// ============================================================================

const SERIAL_PREFIX = "HX-";
const SERIAL_SUFFIX = "-PRO";
const VALID_SERIAL_LEN = 16;

// Serial check function 1: Validate serial prefix
fn check_serial_prefix(serial: []const u8) bool {
    if (serial.len < SERIAL_PREFIX.len) return false;
    return std.mem.eql(u8, serial[0..SERIAL_PREFIX.len], SERIAL_PREFIX);
}

// Serial check function 2: Validate serial suffix
fn check_serial_suffix(serial: []const u8) bool {
    if (serial.len < SERIAL_SUFFIX.len) return false;
    const suffix_start = serial.len - SERIAL_SUFFIX.len;
    return std.mem.eql(u8, serial[suffix_start..], SERIAL_SUFFIX);
}

// Serial check function 3: Luhn algorithm for serial validation
fn luhn_check(digits: []const u8) bool {
    var sum: u32 = 0;
    var double_next = false;

    var i = digits.len;
    while (i > 0) {
        i -= 1;
        if (digits[i] < '0' or digits[i] > '9') continue;

        var digit: u32 = digits[i] - '0';
        if (double_next) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        double_next = !double_next;
    }

    return sum % 10 == 0;
}

// Serial check function 4: Full serial validation
fn validate_serial_number(serial: []const u8) bool {
    if (serial.len != VALID_SERIAL_LEN) {
        log_error(SERIAL_INVALID_MSG);
        return false;
    }

    if (!check_serial_prefix(serial)) {
        log_error(SERIAL_INVALID_MSG);
        return false;
    }

    if (!check_serial_suffix(serial)) {
        log_error(SERIAL_INVALID_MSG);
        return false;
    }

    // Extract numeric portion for Luhn check
    const numeric_part = serial[SERIAL_PREFIX.len .. serial.len - SERIAL_SUFFIX.len];
    if (!luhn_check(numeric_part)) {
        log_error(CHECKSUM_FAILED_MSG);
        return false;
    }

    log_info(LICENSE_VALID_MSG);
    return true;
}

// ============================================================================
// TIME-BASED TRIAL LOGIC
// Trial expiration and day counting
// ============================================================================

var g_install_timestamp: u64 = 0;
var g_trial_mode: bool = true;

// Trial function 1: Get current timestamp (simulated)
fn get_current_timestamp() u64 {
    // In real code this would call time() or similar
    // Using a global to simulate
    return @as(u64, 1704067200) + g_simulated_days * 86400; // Base: 2024-01-01
}

var g_simulated_days: u64 = 0;

// Trial function 2: Calculate days since installation
fn days_since_install() u32 {
    if (g_install_timestamp == 0) return 0;
    const now = get_current_timestamp();
    if (now < g_install_timestamp) return 0;
    const diff = now - g_install_timestamp;
    return @truncate(diff / 86400);
}

// Trial function 3: Check if trial has expired
fn is_trial_expired() bool {
    const days = days_since_install();
    if (days >= TRIAL_DAYS) {
        log_error(TRIAL_EXPIRED_MSG);
        return true;
    }
    return false;
}

// Trial function 4: Get remaining trial days
fn get_trial_days_remaining() u32 {
    const days = days_since_install();
    if (days >= TRIAL_DAYS) return 0;
    return TRIAL_DAYS - days;
}

// Trial function 5: Full trial validation
fn validate_trial_status() bool {
    if (!g_trial_mode) {
        return true; // Licensed mode, no trial check needed
    }

    if (is_trial_expired()) {
        return false;
    }

    const remaining = get_trial_days_remaining();
    _ = remaining; // Would be used for display
    log_info(TRIAL_REMAINING_MSG);
    return true;
}

// Trial function 6: Check for time manipulation (anti-tamper)
var g_last_check_time: u64 = 0;

fn detect_time_rollback() bool {
    const now = get_current_timestamp();
    if (g_last_check_time > 0 and now < g_last_check_time) {
        // Time went backwards - possible tampering
        log_error("System clock tampering detected!");
        return true;
    }
    g_last_check_time = now;
    return false;
}

// ============================================================================
// FEATURE UNLOCK CHECKS
// Pro vs Basic feature gating
// ============================================================================

const Feature = enum(u8) {
    BASIC_FEATURE = 0,
    EXPORT_CSV = 1,
    EXPORT_PDF = 2,
    CLOUD_SYNC = 3,
    ADVANCED_ANALYTICS = 4,
    API_ACCESS = 5,
    PRIORITY_SUPPORT = 6,
    CUSTOM_THEMES = 7,
};

// Feature flags stored as bitmask
var g_unlocked_features: u8 = 0x01; // Basic feature always unlocked

// Feature unlock function 1: Check if specific feature is unlocked
fn is_feature_unlocked(feature: Feature) bool {
    const shift: u3 = @truncate(@intFromEnum(feature));
    const mask: u8 = @as(u8, 1) << shift;
    return (g_unlocked_features & mask) != 0;
}

// Feature unlock function 2: Unlock feature with key
fn unlock_feature(feature: Feature, unlock_code: u32) bool {
    // Each feature has its own unlock code
    const expected_codes = [_]u32{
        0x00000000, // BASIC - always unlocked
        0x12345678, // EXPORT_CSV
        0x87654321, // EXPORT_PDF
        0xDEADC0DE, // CLOUD_SYNC
        0xCAFEBABE, // ADVANCED_ANALYTICS
        0xFEEDFACE, // API_ACCESS
        0xC0FFEE00, // PRIORITY_SUPPORT
        0xBAADF00D, // CUSTOM_THEMES
    };

    const feature_idx = @intFromEnum(feature);
    if (feature_idx >= expected_codes.len) return false;

    if (unlock_code != expected_codes[feature_idx]) {
        log_error(FEATURE_LOCKED_MSG);
        return false;
    }

    const shift: u3 = @truncate(feature_idx);
    const mask: u8 = @as(u8, 1) << shift;
    g_unlocked_features |= mask;
    log_info(FEATURE_UNLOCKED_MSG);
    return true;
}

// Feature unlock function 3: Unlock all features (full license)
fn unlock_all_features() void {
    g_unlocked_features = 0xFF;
    g_trial_mode = false;
}

// Feature unlock function 4: Check license tier
const LicenseTier = enum {
    TRIAL,
    BASIC,
    PROFESSIONAL,
    ENTERPRISE,
};

fn get_license_tier() LicenseTier {
    const feature_count = @popCount(g_unlocked_features);
    if (g_trial_mode) return .TRIAL;
    if (feature_count >= 7) return .ENTERPRISE;
    if (feature_count >= 4) return .PROFESSIONAL;
    return .BASIC;
}

// ============================================================================
// STRING COMPARISONS / EXPECTED VALUES
// Hardcoded expected values for comparison
// ============================================================================

const ADMIN_PASSWORD_HASH: u32 = 0xA5A5A5A5;
const MASTER_KEY = "HEXRAYS-MASTER-2024";
const ACTIVATION_CODE_PREFIX = "ACT-";

// Comparison function 1: Verify admin password
fn verify_admin_password(password: []const u8) bool {
    const hash = compute_key_hash(password);
    if (hash != ADMIN_PASSWORD_HASH) {
        log_error(AUTH_FAILED_MSG);
        return false;
    }
    log_info(AUTH_SUCCESS_MSG);
    return true;
}

// Comparison function 2: Check master key
fn check_master_key(input: []const u8) bool {
    if (input.len != MASTER_KEY.len) return false;
    return std.mem.eql(u8, input, MASTER_KEY);
}

// Comparison function 3: Constant-time comparison (anti-timing attack)
fn secure_compare(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |ca, cb| {
        diff |= ca ^ cb;
    }
    return diff == 0;
}

// Comparison function 4: Validate activation code format
fn validate_activation_code(code: []const u8) bool {
    if (code.len < ACTIVATION_CODE_PREFIX.len + 8) return false;

    // Check prefix
    if (!std.mem.eql(u8, code[0..ACTIVATION_CODE_PREFIX.len], ACTIVATION_CODE_PREFIX)) {
        return false;
    }

    // Rest should be hex digits
    for (code[ACTIVATION_CODE_PREFIX.len..]) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F') or (c >= 'a' and c <= 'f'))) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// HARDWARE ID VALIDATION
// Machine fingerprinting for license binding
// ============================================================================

var g_stored_hwid: u32 = 0;

// HWID function 1: Generate hardware ID (simulated)
fn generate_hwid() u32 {
    // In real code, this would combine:
    // - MAC address
    // - Disk serial number
    // - CPU ID
    // - etc.
    // Simulating with a constant for this example
    return 0x12ABCDEF;
}

// HWID function 2: Store HWID in license file
fn store_hwid(hwid: u32) void {
    g_stored_hwid = hwid;
}

// HWID function 3: Verify HWID matches stored value
fn verify_hwid() bool {
    const current_hwid = generate_hwid();
    if (g_stored_hwid != 0 and g_stored_hwid != current_hwid) {
        log_error(HWID_MISMATCH_MSG);
        return false;
    }
    return true;
}

// ============================================================================
// LICENSE FILE OPERATIONS
// Reading and writing license data
// ============================================================================

const LICENSE_FILE_MAGIC: u32 = 0x4C494346; // "LICF"
const LICENSE_FILE_VERSION: u16 = 1;

const LicenseFileHeader = struct {
    magic: u32,
    version: u16,
    flags: u16,
    hwid: u32,
    expiry_timestamp: u64,
    checksum: u32,
};

// License file function 1: Validate license file header
fn validate_license_file_header(header: *const LicenseFileHeader) bool {
    if (header.magic != LICENSE_FILE_MAGIC) {
        log_error(LICENSE_INVALID_MSG);
        return false;
    }

    if (header.version != LICENSE_FILE_VERSION) {
        log_error("License file version mismatch");
        return false;
    }

    return true;
}

// License file function 2: Check license expiry
fn check_license_expiry(expiry: u64) bool {
    const now = get_current_timestamp();
    if (now > expiry) {
        log_error(LICENSE_EXPIRED_MSG);
        return false;
    }
    return true;
}

// License file function 3: Compute license file checksum
fn compute_license_checksum(data: []const u8) u32 {
    var checksum: u32 = 0;
    var i: usize = 0;
    while (i + 4 <= data.len) : (i += 4) {
        const word = std.mem.readInt(u32, data[i..][0..4], .little);
        checksum ^= word;
        checksum = (checksum << 7) | (checksum >> 25);
    }
    // Handle remaining bytes
    var remaining: u32 = 0;
    for (data[i..]) |b| {
        remaining = (remaining << 8) | b;
    }
    checksum ^= remaining;
    return checksum;
}

// ============================================================================
// ONLINE VALIDATION (SIMULATED)
// Network-based license verification
// ============================================================================

const LICENSE_SERVER_URL = "https://license.hexrays.example.com/validate";
const API_KEY = "sk_live_XXXXXXXXXXXX";

// Online validation function 1: Build validation request
fn build_validation_request(key: []const u8, hwid: u32, buf: []u8) usize {
    _ = key;
    _ = hwid;
    // Would format JSON request
    const request = "{\"key\":\"\",\"hwid\":\"\",\"version\":\"1.0\"}";
    if (buf.len < request.len) return 0;
    @memcpy(buf[0..request.len], request);
    return request.len;
}

// Online validation function 2: Parse validation response
fn parse_validation_response(response: []const u8) bool {
    // Look for success indicator in response
    const success_marker = "\"valid\":true";
    const fail_marker = "\"valid\":false";

    if (std.mem.indexOf(u8, response, success_marker) != null) {
        log_info(LICENSE_VALID_MSG);
        return true;
    }

    if (std.mem.indexOf(u8, response, fail_marker) != null) {
        log_error(LICENSE_INVALID_MSG);
        return false;
    }

    // No clear response - fail safe
    log_error("License server response invalid");
    return false;
}

// Online validation function 3: Full online validation (simulated)
fn perform_online_validation(key: []const u8) bool {
    var request_buf: [512]u8 = undefined;
    const hwid = generate_hwid();

    const req_len = build_validation_request(key, hwid, &request_buf);
    if (req_len == 0) return false;

    // Simulated response (in real code, would make HTTP request)
    const simulated_response = "{\"valid\":true,\"expires\":\"2025-12-31\"}";

    return parse_validation_response(simulated_response);
}

// ============================================================================
// CRYPTO-BASED LICENSE VALIDATION
// RSA/signature verification patterns
// ============================================================================

// Simplified RSA-like signature verification (not real RSA, just pattern)
const RSA_MODULUS: u64 = 0x1234567890ABCDEF;
const RSA_PUBLIC_EXP: u32 = 65537;

// Crypto validation function 1: Simple modular exponentiation
fn mod_exp(base: u64, exp: u32, mod: u64) u64 {
    if (mod == 0) return 0;
    var result: u64 = 1;
    var b = base % mod;
    var e = exp;

    while (e > 0) {
        if (e & 1 != 0) {
            result = @rem(result *% b, mod);
        }
        e >>= 1;
        b = @rem(b *% b, mod);
    }
    return result;
}

// Crypto validation function 2: Verify signature
fn verify_signature(message_hash: u64, signature: u64) bool {
    const decrypted = mod_exp(signature, RSA_PUBLIC_EXP, RSA_MODULUS);
    return decrypted == message_hash;
}

// Crypto validation function 3: Hash message for signing
fn hash_message(message: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325; // FNV-1a 64-bit offset
    for (message) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3; // FNV-1a 64-bit prime
    }
    return hash;
}

// Crypto validation function 4: Full signature validation
fn validate_signed_license(license_data: []const u8, signature: u64) bool {
    const msg_hash = hash_message(license_data);
    if (!verify_signature(msg_hash, signature)) {
        log_error("License signature verification failed");
        return false;
    }
    log_info("License signature verified");
    return true;
}

// ============================================================================
// COMPREHENSIVE LICENSE CHECK (MAIN ENTRY POINT)
// ============================================================================

fn perform_full_license_check(key: []const u8) bool {
    // Step 1: HWID verification
    if (!verify_hwid()) {
        return false;
    }

    // Step 2: Time rollback detection
    if (detect_time_rollback()) {
        return false;
    }

    // Step 3: License key validation
    if (!validate_license_key(key)) {
        return false;
    }

    // Step 4: Trial status check (if in trial mode)
    if (!validate_trial_status()) {
        return false;
    }

    // All checks passed
    return true;
}

// ============================================================================
// LOGGING UTILITIES
// ============================================================================

var g_log_buffer: [4096]u8 = undefined;
var g_log_pos: usize = 0;
var g_verbose: bool = false; // Controls actual output

fn log_error(msg: []const u8) void {
    const prefix = "[ERROR] ";
    log_append(prefix);
    log_append(msg);
    log_append("\n");
    // Actually write to stderr to prevent optimization
    if (g_verbose) {
        _ = std.posix.write(std.posix.STDERR_FILENO, prefix) catch {};
        _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch {};
        _ = std.posix.write(std.posix.STDERR_FILENO, "\n") catch {};
    }
}

fn log_info(msg: []const u8) void {
    const prefix = "[INFO] ";
    log_append(prefix);
    log_append(msg);
    log_append("\n");
    // Actually write to stdout to prevent optimization
    if (g_verbose) {
        _ = std.posix.write(std.posix.STDOUT_FILENO, prefix) catch {};
        _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch {};
        _ = std.posix.write(std.posix.STDOUT_FILENO, "\n") catch {};
    }
}

fn log_append(data: []const u8) void {
    const space = g_log_buffer.len - g_log_pos;
    const to_copy = if (data.len < space) data.len else space;
    @memcpy(g_log_buffer[g_log_pos .. g_log_pos + to_copy], data[0..to_copy]);
    g_log_pos += to_copy;
}

// ============================================================================
// EXPORTED API FUNCTIONS
// These exports force the compiler to preserve functions and strings
// ============================================================================

export fn check_license(key_ptr: [*]const u8, key_len: usize) bool {
    if (key_len == 0 or key_len > 256) return false;
    const key = key_ptr[0..key_len];
    return validate_license_key(key);
}

export fn check_serial(serial_ptr: [*]const u8, serial_len: usize) bool {
    if (serial_len == 0 or serial_len > 64) return false;
    const serial = serial_ptr[0..serial_len];
    return validate_serial_number(serial);
}

export fn check_trial() bool {
    return validate_trial_status();
}

export fn check_feature(feature_id: u8) bool {
    if (feature_id > 7) return false;
    const features = [_]Feature{ .BASIC_FEATURE, .EXPORT_CSV, .EXPORT_PDF, .CLOUD_SYNC, .ADVANCED_ANALYTICS, .API_ACCESS, .PRIORITY_SUPPORT, .CUSTOM_THEMES };
    return is_feature_unlocked(features[feature_id]);
}

export fn do_unlock_feature(feature_id: u8, code: u32) bool {
    if (feature_id > 7) return false;
    const features = [_]Feature{ .BASIC_FEATURE, .EXPORT_CSV, .EXPORT_PDF, .CLOUD_SYNC, .ADVANCED_ANALYTICS, .API_ACCESS, .PRIORITY_SUPPORT, .CUSTOM_THEMES };
    return unlock_feature(features[feature_id], code);
}

export fn authenticate(pass_ptr: [*]const u8, pass_len: usize) bool {
    if (pass_len == 0 or pass_len > 128) return false;
    const password = pass_ptr[0..pass_len];
    return verify_admin_password(password);
}

export fn validate_hwid() bool {
    return verify_hwid();
}

export fn full_license_check(key_ptr: [*]const u8, key_len: usize) bool {
    if (key_len == 0 or key_len > 256) return false;
    const key = key_ptr[0..key_len];
    return perform_full_license_check(key);
}

export fn online_validate(key_ptr: [*]const u8, key_len: usize) bool {
    if (key_len == 0 or key_len > 256) return false;
    const key = key_ptr[0..key_len];
    return perform_online_validation(key);
}

export fn verify_license_signature(data_ptr: [*]const u8, data_len: usize, sig: u64) bool {
    if (data_len == 0 or data_len > 4096) return false;
    const data = data_ptr[0..data_len];
    return validate_signed_license(data, sig);
}

export fn get_trial_days() u32 {
    return get_trial_days_remaining();
}

export fn is_license_expired(expiry: u64) bool {
    return !check_license_expiry(expiry);
}

export fn get_current_tier() u8 {
    const tier = get_license_tier();
    return switch (tier) {
        .TRIAL => 0,
        .BASIC => 1,
        .PROFESSIONAL => 2,
        .ENTERPRISE => 3,
    };
}

// ============================================================================
// MAIN FUNCTION - Exercises all license checking code paths
// ============================================================================

pub fn main() void {
    // Initialize
    g_install_timestamp = get_current_timestamp();
    store_hwid(generate_hwid());

    // Test 1: License key format validation
    const test_key1 = "ABCD-1234-WXYZ-5678";
    const valid_format = validate_key_format(test_key1);
    _ = valid_format;

    // Test 2: Serial number validation
    const test_serial = "HX-123456789-PRO";
    const valid_serial = validate_serial_number(test_serial);
    _ = valid_serial;

    // Test 3: Trial status
    const trial_ok = validate_trial_status();
    _ = trial_ok;

    // Test 4: Feature checks
    const csv_unlocked = is_feature_unlocked(.EXPORT_CSV);
    _ = csv_unlocked;

    _ = unlock_feature(.EXPORT_PDF, 0x87654321);
    const tier = get_license_tier();
    _ = tier;

    // Test 5: Admin authentication
    const auth_ok = verify_admin_password("secret123");
    _ = auth_ok;

    // Test 6: Master key check
    const master_ok = check_master_key(MASTER_KEY);
    _ = master_ok;

    // Test 7: Activation code
    const act_valid = validate_activation_code("ACT-DEADBEEF");
    _ = act_valid;

    // Test 8: HWID verification
    const hwid_ok = verify_hwid();
    _ = hwid_ok;

    // Test 9: Online validation (simulated)
    const online_ok = perform_online_validation(test_key1);
    _ = online_ok;

    // Test 10: Signature verification
    const test_data = "License: Pro Edition";
    const fake_sig: u64 = 0x123456789ABCDEF0;
    const sig_ok = validate_signed_license(test_data, fake_sig);
    _ = sig_ok;

    // Test 11: Full license check
    const full_check = perform_full_license_check(test_key1);
    _ = full_check;

    // Test 12: License expiry
    const expiry_ok = check_license_expiry(get_current_timestamp() + 86400 * 365);
    _ = expiry_ok;

    // Test 13: Secure comparison
    const sec_cmp = secure_compare("password", "password");
    _ = sec_cmp;

    // Test 14: Checksum computation
    const test_lic_data = [_]u8{ 0x4C, 0x49, 0x43, 0x46, 0x01, 0x00, 0x00, 0x00 };
    const chksum = compute_license_checksum(&test_lic_data);
    _ = chksum;

    // Output result message
    const msg = "Auth/License check binary executed successfully.\n";
    _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch {};
}
