const std = @import("std");

// Command context passed to all handlers
const CommandContext = struct {
    connection_id: u32,
    flags: u16,
    data: []const u8,
    response_buffer: []u8,
    response_len: *usize,
};

// Opcode definitions - sparse range with gaps
const Opcode = enum(u16) {
    // Basic commands (0x00-0x0F)
    CMD_PING = 0x00,
    CMD_PONG = 0x01,
    CMD_VERSION = 0x02,
    CMD_STATUS = 0x05,
    CMD_ECHO = 0x07,

    // Authentication commands (0x10-0x1F)
    CMD_AUTH_LOGIN = 0x10,
    CMD_AUTH_LOGOUT = 0x12,
    CMD_AUTH_TOKEN = 0x15,

    // Data commands (0x30-0x4F) - large gap from 0x15
    CMD_DATA_READ = 0x30,
    CMD_DATA_WRITE = 0x32,
    CMD_DATA_DELETE = 0x35,
    CMD_DATA_LIST = 0x38,

    // Admin commands (0x80-0x8F) - high range
    CMD_ADMIN_SHUTDOWN = 0x80,
    CMD_ADMIN_CONFIG = 0x82,
    CMD_ADMIN_DEBUG = 0x8F,

    _,
};

// Sub-command opcodes for nested dispatch (data commands)
const DataSubCommand = enum(u8) {
    SUB_GET_SIZE = 0x01,
    SUB_GET_OFFSET = 0x02,
    SUB_SET_FLAGS = 0x05,
    SUB_VALIDATE = 0x08,
    SUB_COMPRESS = 0x10,
    SUB_ENCRYPT = 0x12,
    _,
};

// Error codes
const CommandError = error{
    InvalidOpcode,
    InvalidSubCommand,
    AuthRequired,
    PermissionDenied,
    InvalidData,
    BufferTooSmall,
    InternalError,
};

// Global state for demonstration
var g_authenticated: bool = false;
var g_admin_mode: bool = false;
var g_debug_enabled: bool = false;
var g_shutdown_requested: bool = false;

// ============================================================================
// Basic command handlers (0x00-0x0F)
// ============================================================================

fn handlePing(ctx: *CommandContext) CommandError!void {
    _ = std.fmt.bufPrint(ctx.response_buffer, "PONG from connection {d}", .{ctx.connection_id}) catch return error.BufferTooSmall;
    ctx.response_len.* = 24;
}

fn handlePong(ctx: *CommandContext) CommandError!void {
    _ = ctx;
    // Silent acknowledgment - no response needed
}

fn handleVersion(ctx: *CommandContext) CommandError!void {
    const version_string = "CommandDispatcher v2.4.1 (Protocol 3.0)";
    @memcpy(ctx.response_buffer[0..version_string.len], version_string);
    ctx.response_len.* = version_string.len;
}

fn handleStatus(ctx: *CommandContext) CommandError!void {
    const status = if (g_authenticated) "AUTHENTICATED" else "GUEST";
    const mode = if (g_admin_mode) "ADMIN" else "USER";
    _ = std.fmt.bufPrint(ctx.response_buffer, "Status: {s}, Mode: {s}, Debug: {s}", .{
        status,
        mode,
        if (g_debug_enabled) "ON" else "OFF",
    }) catch return error.BufferTooSmall;
    ctx.response_len.* = 48;
}

fn handleEcho(ctx: *CommandContext) CommandError!void {
    if (ctx.data.len > ctx.response_buffer.len) {
        return error.BufferTooSmall;
    }
    @memcpy(ctx.response_buffer[0..ctx.data.len], ctx.data);
    ctx.response_len.* = ctx.data.len;
}

// ============================================================================
// Authentication command handlers (0x10-0x1F)
// ============================================================================

fn handleAuthLogin(ctx: *CommandContext) CommandError!void {
    // Simple auth check - in real code this would verify credentials
    if (ctx.data.len >= 8) {
        g_authenticated = true;
        const msg = "LOGIN_SUCCESS: Session established";
        @memcpy(ctx.response_buffer[0..msg.len], msg);
        ctx.response_len.* = msg.len;
    } else {
        const msg = "LOGIN_FAILED: Invalid credentials";
        @memcpy(ctx.response_buffer[0..msg.len], msg);
        ctx.response_len.* = msg.len;
    }
}

fn handleAuthLogout(ctx: *CommandContext) CommandError!void {
    g_authenticated = false;
    g_admin_mode = false;
    const msg = "LOGOUT_SUCCESS: Session terminated";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

fn handleAuthToken(ctx: *CommandContext) CommandError!void {
    if (!g_authenticated) {
        return error.AuthRequired;
    }
    // Generate fake token
    const token = "TOKEN:ABCD1234EFGH5678";
    @memcpy(ctx.response_buffer[0..token.len], token);
    ctx.response_len.* = token.len;
}

// ============================================================================
// Data command handlers with nested sub-command dispatch (0x30-0x4F)
// ============================================================================

fn handleDataSubCommand(ctx: *CommandContext, sub_opcode: u8) CommandError!void {
    const sub_cmd: DataSubCommand = @enumFromInt(sub_opcode);

    // Nested switch for sub-commands
    switch (sub_cmd) {
        .SUB_GET_SIZE => {
            const msg = "DATA_SIZE: 1048576 bytes";
            @memcpy(ctx.response_buffer[0..msg.len], msg);
            ctx.response_len.* = msg.len;
        },
        .SUB_GET_OFFSET => {
            const msg = "DATA_OFFSET: 0x00400000";
            @memcpy(ctx.response_buffer[0..msg.len], msg);
            ctx.response_len.* = msg.len;
        },
        .SUB_SET_FLAGS => {
            const msg = "FLAGS_SET: RW";
            @memcpy(ctx.response_buffer[0..msg.len], msg);
            ctx.response_len.* = msg.len;
        },
        .SUB_VALIDATE => {
            const msg = "VALIDATION: CRC32=0xDEADBEEF";
            @memcpy(ctx.response_buffer[0..msg.len], msg);
            ctx.response_len.* = msg.len;
        },
        .SUB_COMPRESS => {
            const msg = "COMPRESS: LZ4 ratio=0.65";
            @memcpy(ctx.response_buffer[0..msg.len], msg);
            ctx.response_len.* = msg.len;
        },
        .SUB_ENCRYPT => {
            const msg = "ENCRYPT: AES-256-GCM applied";
            @memcpy(ctx.response_buffer[0..msg.len], msg);
            ctx.response_len.* = msg.len;
        },
        _ => {
            return error.InvalidSubCommand;
        },
    }
}

fn handleDataRead(ctx: *CommandContext) CommandError!void {
    if (!g_authenticated) {
        return error.AuthRequired;
    }
    // Check for sub-command in data
    if (ctx.data.len > 0) {
        return handleDataSubCommand(ctx, ctx.data[0]);
    }
    const msg = "DATA_READ: Block 0, 4096 bytes";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

fn handleDataWrite(ctx: *CommandContext) CommandError!void {
    if (!g_authenticated) {
        return error.AuthRequired;
    }
    if (ctx.data.len < 4) {
        return error.InvalidData;
    }
    const msg = "DATA_WRITE: OK, bytes written";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

fn handleDataDelete(ctx: *CommandContext) CommandError!void {
    if (!g_authenticated) {
        return error.AuthRequired;
    }
    if (!g_admin_mode) {
        return error.PermissionDenied;
    }
    const msg = "DATA_DELETE: Record removed";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

fn handleDataList(ctx: *CommandContext) CommandError!void {
    if (!g_authenticated) {
        return error.AuthRequired;
    }
    const msg = "DATA_LIST: [rec_001, rec_002, rec_003]";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

// ============================================================================
// Admin command handlers (0x80-0x8F)
// ============================================================================

fn handleAdminShutdown(ctx: *CommandContext) CommandError!void {
    if (!g_admin_mode) {
        return error.PermissionDenied;
    }
    g_shutdown_requested = true;
    const msg = "SHUTDOWN: Initiating graceful shutdown";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

fn handleAdminConfig(ctx: *CommandContext) CommandError!void {
    if (!g_admin_mode) {
        return error.PermissionDenied;
    }
    const msg = "CONFIG: max_conn=1000, timeout=30s";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

fn handleAdminDebug(ctx: *CommandContext) CommandError!void {
    if (!g_admin_mode) {
        return error.PermissionDenied;
    }
    g_debug_enabled = !g_debug_enabled;
    const msg = if (g_debug_enabled) "DEBUG: Mode enabled" else "DEBUG: Mode disabled";
    @memcpy(ctx.response_buffer[0..msg.len], msg);
    ctx.response_len.* = msg.len;
}

// ============================================================================
// Main dispatcher with bounds checking and jump table
// ============================================================================

fn dispatchCommand(opcode_raw: u16, ctx: *CommandContext) CommandError!void {
    // Bounds checking before dispatch
    if (opcode_raw > 0x8F) {
        return error.InvalidOpcode;
    }

    const opcode: Opcode = @enumFromInt(opcode_raw);

    // Main switch/jump table dispatch
    switch (opcode) {
        // Basic commands
        .CMD_PING => return handlePing(ctx),
        .CMD_PONG => return handlePong(ctx),
        .CMD_VERSION => return handleVersion(ctx),
        .CMD_STATUS => return handleStatus(ctx),
        .CMD_ECHO => return handleEcho(ctx),

        // Auth commands
        .CMD_AUTH_LOGIN => return handleAuthLogin(ctx),
        .CMD_AUTH_LOGOUT => return handleAuthLogout(ctx),
        .CMD_AUTH_TOKEN => return handleAuthToken(ctx),

        // Data commands
        .CMD_DATA_READ => return handleDataRead(ctx),
        .CMD_DATA_WRITE => return handleDataWrite(ctx),
        .CMD_DATA_DELETE => return handleDataDelete(ctx),
        .CMD_DATA_LIST => return handleDataList(ctx),

        // Admin commands
        .CMD_ADMIN_SHUTDOWN => return handleAdminShutdown(ctx),
        .CMD_ADMIN_CONFIG => return handleAdminConfig(ctx),
        .CMD_ADMIN_DEBUG => return handleAdminDebug(ctx),

        _ => return error.InvalidOpcode,
    }
}

// ============================================================================
// Packet processing entry point
// ============================================================================

const PacketHeader = packed struct {
    magic: u16,      // 0x4D43 = "CM"
    version: u8,
    flags: u8,
    opcode: u16,
    length: u16,
};

fn processPacket(packet: []const u8, response_buffer: []u8, response_len: *usize) CommandError!void {
    if (packet.len < @sizeOf(PacketHeader)) {
        return error.InvalidData;
    }

    const header: *const PacketHeader = @ptrCast(@alignCast(packet.ptr));

    // Validate magic
    if (header.magic != 0x4D43) {
        return error.InvalidData;
    }

    // Extract payload
    const payload_start = @sizeOf(PacketHeader);
    const payload = if (packet.len > payload_start) packet[payload_start..] else &[_]u8{};

    var ctx = CommandContext{
        .connection_id = 12345,
        .flags = @as(u16, header.flags),
        .data = payload,
        .response_buffer = response_buffer,
        .response_len = response_len,
    };

    return dispatchCommand(header.opcode, &ctx);
}

// ============================================================================
// Main entry point for demonstration
// ============================================================================

pub fn main() void {
    var response_buffer: [256]u8 = undefined;
    var response_len: usize = 0;

    // Test various commands
    const test_opcodes = [_]u16{
        0x00, // PING
        0x02, // VERSION
        0x05, // STATUS
        0x10, // AUTH_LOGIN
        0x30, // DATA_READ
        0x80, // ADMIN_SHUTDOWN (will fail - not admin)
        0xFF, // Invalid
    };

    for (test_opcodes) |opcode| {
        response_len = 0;
        @memset(&response_buffer, 0);

        // Create test packet
        var packet: [16]u8 = undefined;
        const header: *PacketHeader = @ptrCast(@alignCast(&packet));
        header.magic = 0x4D43;
        header.version = 3;
        header.flags = 0;
        header.opcode = opcode;
        header.length = 8;
        @memset(packet[8..], 'A'); // Dummy payload

        std.debug.print("Opcode 0x{X:0>2}: ", .{opcode});

        if (processPacket(&packet, &response_buffer, &response_len)) {
            std.debug.print("{s}\n", .{response_buffer[0..response_len]});
        } else |err| {
            std.debug.print("Error: {s}\n", .{@errorName(err)});
        }
    }

    std.debug.print("\nCommand dispatch demonstration complete.\n", .{});
}
