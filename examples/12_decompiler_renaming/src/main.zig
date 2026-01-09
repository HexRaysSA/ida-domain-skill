// Exercise 12: Decompiler Renaming Binary
// A binary that uses well-known libc APIs for decompiler variable renaming exercises
// Uses libc directly to ensure recognizable API calls in the decompiled output

const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("stdio.h");
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
});

// ============================================================================
// MEMORY OPERATIONS - malloc, free, memcpy, memset, memmove, realloc
// ============================================================================

// Function 1: Basic allocation and initialization
noinline fn allocateBuffer(size: usize) callconv(.c) ?[*]u8 {
    const ptr: ?[*]u8 = @ptrCast(c.malloc(size));
    if (ptr) |p| {
        _ = c.memset(p, 0, size);
    }
    return ptr;
}

// Function 2: Allocate and copy data
noinline fn allocateAndCopy(data: [*]const u8, len: usize) callconv(.c) ?[*]u8 {
    const ptr: ?[*]u8 = @ptrCast(c.malloc(len));
    if (ptr) |p| {
        _ = c.memcpy(p, data, len);
    }
    return ptr;
}

// Function 3: Resize buffer with realloc
noinline fn resizeBuffer(ptr: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?[*]u8 {
    _ = old_size;
    const new_ptr: ?[*]u8 = @ptrCast(c.realloc(ptr, new_size));
    return new_ptr;
}

// Function 4: Free buffer wrapper
noinline fn freeBuffer(ptr: ?*anyopaque) callconv(.c) void {
    c.free(ptr);
}

// Function 5: Safe memory copy with bounds check
noinline fn safeCopy(dest: [*]u8, dest_size: usize, src: [*]const u8, src_len: usize) callconv(.c) bool {
    if (src_len > dest_size) {
        return false;
    }
    _ = c.memcpy(dest, src, src_len);
    return true;
}

// Function 6: Memory move for overlapping buffers
noinline fn moveBuffer(dest: [*]u8, src: [*]const u8, len: usize) callconv(.c) void {
    _ = c.memmove(dest, src, len);
}

// Function 7: Zero sensitive memory
noinline fn zeroMemory(ptr: [*]u8, size: usize) callconv(.c) void {
    _ = c.memset(ptr, 0, size);
}

// Function 8: Fill buffer with pattern
noinline fn fillBuffer(ptr: [*]u8, size: usize, pattern: u8) callconv(.c) void {
    _ = c.memset(ptr, pattern, size);
}

// Function 9: Compare memory regions
noinline fn compareMemory(ptr1: [*]const u8, ptr2: [*]const u8, len: usize) callconv(.c) c_int {
    return c.memcmp(ptr1, ptr2, len);
}

// Function 10: Duplicate memory region
noinline fn duplicateMemory(src: [*]const u8, len: usize) callconv(.c) ?[*]u8 {
    const ptr: ?[*]u8 = @ptrCast(c.malloc(len));
    if (ptr) |p| {
        _ = c.memcpy(p, src, len);
    }
    return ptr;
}

// ============================================================================
// STRING OPERATIONS - strlen, strcpy, strcmp, strcat, strncpy, strdup
// ============================================================================

// Function 11: Get string length
noinline fn getStringLength(str: [*:0]const u8) callconv(.c) usize {
    return c.strlen(str);
}

// Function 12: Copy string
noinline fn copyString(dest: [*:0]u8, src: [*:0]const u8) callconv(.c) [*:0]u8 {
    return @ptrCast(c.strcpy(dest, src));
}

// Function 13: Safe string copy with length limit
noinline fn safeCopyString(dest: [*:0]u8, src: [*:0]const u8, max_len: usize) callconv(.c) [*:0]u8 {
    return @ptrCast(c.strncpy(dest, src, max_len));
}

// Function 14: Compare strings
noinline fn compareStrings(str1: [*:0]const u8, str2: [*:0]const u8) callconv(.c) c_int {
    return c.strcmp(str1, str2);
}

// Function 15: Compare strings with limit
noinline fn compareStringsN(str1: [*:0]const u8, str2: [*:0]const u8, max_len: usize) callconv(.c) c_int {
    return c.strncmp(str1, str2, max_len);
}

// Function 16: Concatenate strings
noinline fn concatenateStrings(dest: [*:0]u8, src: [*:0]const u8) callconv(.c) [*:0]u8 {
    return @ptrCast(c.strcat(dest, src));
}

// Function 17: Duplicate string
noinline fn duplicateString(str: [*:0]const u8) callconv(.c) ?[*:0]u8 {
    const len = c.strlen(str) + 1;
    const ptr: ?[*]u8 = @ptrCast(c.malloc(len));
    if (ptr) |p| {
        _ = c.memcpy(p, str, len);
        return @ptrCast(p);
    }
    return null;
}

// Function 18: Find character in string
noinline fn findChar(str: [*:0]const u8, ch: c_int) callconv(.c) ?[*:0]u8 {
    const result = c.strchr(str, ch);
    if (result == null) return null;
    return @ptrCast(result);
}

// Function 19: Find substring
noinline fn findSubstring(haystack: [*:0]const u8, needle: [*:0]const u8) callconv(.c) ?[*:0]u8 {
    const result = c.strstr(haystack, needle);
    if (result == null) return null;
    return @ptrCast(result);
}

// Function 20: String to integer
noinline fn stringToInt(str: [*:0]const u8) callconv(.c) c_int {
    return c.atoi(str);
}

// ============================================================================
// FILE I/O - open, read, write, close, lseek
// ============================================================================

// Function 21: Open file for reading
noinline fn openFileRead(path: [*:0]const u8) callconv(.c) c_int {
    return c.open(path, c.O_RDONLY);
}

// Function 22: Open file for writing (create if needed)
noinline fn openFileWrite(path: [*:0]const u8) callconv(.c) c_int {
    return c.open(path, c.O_WRONLY | c.O_CREAT | c.O_TRUNC, @as(c.mode_t, 0o644));
}

// Function 23: Open file for append
noinline fn openFileAppend(path: [*:0]const u8) callconv(.c) c_int {
    return c.open(path, c.O_WRONLY | c.O_CREAT | c.O_APPEND, @as(c.mode_t, 0o644));
}

// Function 24: Read from file descriptor
noinline fn readFromFile(fd: c_int, buffer: [*]u8, count: usize) callconv(.c) isize {
    return c.read(fd, buffer, count);
}

// Function 25: Write to file descriptor
noinline fn writeToFile(fd: c_int, buffer: [*]const u8, count: usize) callconv(.c) isize {
    return c.write(fd, buffer, count);
}

// Function 26: Close file descriptor
noinline fn closeFile(fd: c_int) callconv(.c) c_int {
    return c.close(fd);
}

// Function 27: Seek in file
noinline fn seekFile(fd: c_int, offset: c.off_t, whence: c_int) callconv(.c) c.off_t {
    return c.lseek(fd, offset, whence);
}

// Function 28: Read entire file into buffer
noinline fn readFileContents(path: [*:0]const u8, buffer: [*]u8, max_size: usize) callconv(.c) isize {
    const fd = c.open(path, c.O_RDONLY);
    if (fd < 0) return -1;

    const bytes_read = c.read(fd, buffer, max_size);
    _ = c.close(fd);
    return bytes_read;
}

// Function 29: Write buffer to file
noinline fn writeFileContents(path: [*:0]const u8, buffer: [*]const u8, size: usize) callconv(.c) isize {
    const fd = c.open(path, c.O_WRONLY | c.O_CREAT | c.O_TRUNC, @as(c.mode_t, 0o644));
    if (fd < 0) return -1;

    const bytes_written = c.write(fd, buffer, size);
    _ = c.close(fd);
    return bytes_written;
}

// Function 30: Copy file contents
noinline fn copyFile(src_path: [*:0]const u8, dest_path: [*:0]const u8) callconv(.c) bool {
    const src_fd = c.open(src_path, c.O_RDONLY);
    if (src_fd < 0) return false;

    const dest_fd = c.open(dest_path, c.O_WRONLY | c.O_CREAT | c.O_TRUNC, @as(c.mode_t, 0o644));
    if (dest_fd < 0) {
        _ = c.close(src_fd);
        return false;
    }

    var buffer: [4096]u8 = undefined;
    var total_copied: isize = 0;

    while (true) {
        const bytes_read = c.read(src_fd, &buffer, buffer.len);
        if (bytes_read <= 0) break;

        const bytes_written = c.write(dest_fd, &buffer, @intCast(bytes_read));
        if (bytes_written != bytes_read) {
            _ = c.close(src_fd);
            _ = c.close(dest_fd);
            return false;
        }
        total_copied += bytes_written;
    }

    _ = c.close(src_fd);
    _ = c.close(dest_fd);
    return total_copied >= 0;
}

// ============================================================================
// NETWORK OPERATIONS - socket, connect, send, recv, bind, listen, accept
// ============================================================================

// Function 31: Create TCP socket
noinline fn createTcpSocket() callconv(.c) c_int {
    return c.socket(c.AF_INET, c.SOCK_STREAM, 0);
}

// Function 32: Create UDP socket
noinline fn createUdpSocket() callconv(.c) c_int {
    return c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
}

// Function 33: Connect to server
noinline fn connectToServer(sock: c_int, ip_addr: [*:0]const u8, port: u16) callconv(.c) c_int {
    var addr: c.sockaddr_in = undefined;
    _ = c.memset(&addr, 0, @sizeOf(c.sockaddr_in));
    addr.sin_family = c.AF_INET;
    addr.sin_port = c.htons(port);
    _ = c.inet_pton(c.AF_INET, ip_addr, &addr.sin_addr);

    return c.connect(sock, @ptrCast(&addr), @sizeOf(c.sockaddr_in));
}

// Function 34: Send data over socket
noinline fn sendData(sock: c_int, buffer: [*]const u8, len: usize) callconv(.c) isize {
    return c.send(sock, buffer, len, 0);
}

// Function 35: Receive data from socket
noinline fn receiveData(sock: c_int, buffer: [*]u8, max_len: usize) callconv(.c) isize {
    return c.recv(sock, buffer, max_len, 0);
}

// Function 36: Bind socket to address
noinline fn bindSocket(sock: c_int, port: u16) callconv(.c) c_int {
    var addr: c.sockaddr_in = undefined;
    _ = c.memset(&addr, 0, @sizeOf(c.sockaddr_in));
    addr.sin_family = c.AF_INET;
    addr.sin_port = c.htons(port);
    addr.sin_addr.s_addr = c.INADDR_ANY;

    return c.bind(sock, @ptrCast(&addr), @sizeOf(c.sockaddr_in));
}

// Function 37: Listen on socket
noinline fn listenSocket(sock: c_int, backlog: c_int) callconv(.c) c_int {
    return c.listen(sock, backlog);
}

// Function 38: Accept connection
noinline fn acceptConnection(sock: c_int) callconv(.c) c_int {
    var client_addr: c.sockaddr_in = undefined;
    var addr_len: c.socklen_t = @sizeOf(c.sockaddr_in);
    return c.accept(sock, @ptrCast(&client_addr), &addr_len);
}

// Function 39: Close socket
noinline fn closeSocket(sock: c_int) callconv(.c) c_int {
    return c.close(sock);
}

// Function 40: Send all data (handles partial sends)
noinline fn sendAll(sock: c_int, buffer: [*]const u8, len: usize) callconv(.c) bool {
    var total_sent: usize = 0;
    while (total_sent < len) {
        const sent = c.send(sock, buffer + total_sent, len - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += @intCast(sent);
    }
    return true;
}

// ============================================================================
// HIGHER-LEVEL OPERATIONS (combining multiple APIs)
// ============================================================================

// Function 41: Allocate and read from file
noinline fn allocateAndReadFile(path: [*:0]const u8, out_size: *usize) callconv(.c) ?[*]u8 {
    const fd = c.open(path, c.O_RDONLY);
    if (fd < 0) return null;

    // Seek to end to get file size
    const size = c.lseek(fd, 0, c.SEEK_END);
    if (size < 0) {
        _ = c.close(fd);
        return null;
    }
    _ = c.lseek(fd, 0, c.SEEK_SET);

    // Allocate buffer
    const buffer: ?[*]u8 = @ptrCast(c.malloc(@intCast(size)));
    if (buffer == null) {
        _ = c.close(fd);
        return null;
    }

    // Read file
    const bytes_read = c.read(fd, buffer, @intCast(size));
    _ = c.close(fd);

    if (bytes_read != size) {
        c.free(buffer);
        return null;
    }

    out_size.* = @intCast(size);
    return buffer;
}

// Function 42: String buffer management
const StringBuffer = extern struct {
    data: [*]u8,
    len: usize,
    capacity: usize,
};

noinline fn createStringBuffer(initial_capacity: usize) callconv(.c) ?*StringBuffer {
    const sb: ?*StringBuffer = @ptrCast(@alignCast(c.malloc(@sizeOf(StringBuffer))));
    if (sb == null) return null;

    const data: ?[*]u8 = @ptrCast(c.malloc(initial_capacity));
    if (data == null) {
        c.free(sb);
        return null;
    }

    sb.?.data = data.?;
    sb.?.len = 0;
    sb.?.capacity = initial_capacity;
    _ = c.memset(data, 0, initial_capacity);
    return sb;
}

// Function 43: Append to string buffer
noinline fn appendToBuffer(sb: *StringBuffer, str: [*:0]const u8) callconv(.c) bool {
    const str_len = c.strlen(str);
    const new_len = sb.len + str_len;

    if (new_len >= sb.capacity) {
        const new_capacity = new_len * 2;
        const new_data: ?[*]u8 = @ptrCast(c.realloc(sb.data, new_capacity));
        if (new_data == null) return false;
        sb.data = new_data.?;
        sb.capacity = new_capacity;
    }

    _ = c.memcpy(sb.data + sb.len, str, str_len);
    sb.len = new_len;
    sb.data[sb.len] = 0;
    return true;
}

// Function 44: Free string buffer
noinline fn freeStringBuffer(sb: *StringBuffer) callconv(.c) void {
    c.free(sb.data);
    c.free(sb);
}

// Function 45: HTTP-like request builder
noinline fn buildHttpRequest(method: [*:0]const u8, path: [*:0]const u8, host: [*:0]const u8, buffer: [*]u8, max_size: usize) callconv(.c) usize {
    var pos: usize = 0;

    // Method
    const method_len = c.strlen(method);
    if (pos + method_len + 1 > max_size) return 0;
    _ = c.memcpy(buffer + pos, method, method_len);
    pos += method_len;
    buffer[pos] = ' ';
    pos += 1;

    // Path
    const path_len = c.strlen(path);
    if (pos + path_len + 1 > max_size) return 0;
    _ = c.memcpy(buffer + pos, path, path_len);
    pos += path_len;

    // HTTP version
    const version = " HTTP/1.1\r\nHost: ";
    const version_len = c.strlen(version);
    if (pos + version_len > max_size) return 0;
    _ = c.memcpy(buffer + pos, version, version_len);
    pos += version_len;

    // Host
    const host_len = c.strlen(host);
    if (pos + host_len + 4 > max_size) return 0;
    _ = c.memcpy(buffer + pos, host, host_len);
    pos += host_len;
    _ = c.memcpy(buffer + pos, "\r\n\r\n", 4);
    pos += 4;

    return pos;
}

// Function 46: Parse key-value pair
noinline fn parseKeyValue(input: [*:0]const u8, key: [*]u8, key_max: usize, value: [*]u8, value_max: usize) callconv(.c) bool {
    const eq_pos = c.strchr(input, '=');
    if (eq_pos == null) return false;

    const input_addr = @intFromPtr(input);
    const eq_addr = @intFromPtr(eq_pos);
    const key_len = eq_addr - input_addr;

    if (key_len >= key_max) return false;
    _ = c.memcpy(key, input, key_len);
    key[key_len] = 0;

    const value_start: [*:0]const u8 = @ptrCast(eq_pos.? + 1);
    const value_len = c.strlen(value_start);
    if (value_len >= value_max) return false;
    _ = c.memcpy(value, value_start, value_len);
    value[value_len] = 0;

    return true;
}

// Function 47: Simple encryption (XOR with key)
noinline fn xorEncrypt(data: [*]u8, data_len: usize, key: [*]const u8, key_len: usize) callconv(.c) void {
    var i: usize = 0;
    while (i < data_len) : (i += 1) {
        data[i] ^= key[i % key_len];
    }
}

// Function 48: Calculate checksum
noinline fn calculateChecksum(data: [*]const u8, len: usize) callconv(.c) u32 {
    var checksum: u32 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        checksum = checksum +% @as(u32, data[i]);
        checksum = (checksum << 1) | (checksum >> 31);
    }
    return checksum;
}

// Function 49: Hex encode buffer
noinline fn hexEncode(input: [*]const u8, input_len: usize, output: [*]u8, output_max: usize) callconv(.c) usize {
    const hex_chars = "0123456789abcdef";
    if (input_len * 2 > output_max) return 0;

    var i: usize = 0;
    while (i < input_len) : (i += 1) {
        output[i * 2] = hex_chars[(input[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_chars[input[i] & 0x0F];
    }
    return input_len * 2;
}

// Function 50: Base64 encode (simplified)
noinline fn base64Encode(input: [*]const u8, input_len: usize, output: [*]u8, output_max: usize) callconv(.c) usize {
    const base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const output_len = ((input_len + 2) / 3) * 4;
    if (output_len > output_max) return 0;

    var i: usize = 0;
    var j: usize = 0;

    while (i < input_len) {
        const b0: u32 = input[i];
        const b1: u32 = if (i + 1 < input_len) input[i + 1] else 0;
        const b2: u32 = if (i + 2 < input_len) input[i + 2] else 0;

        const triple = (b0 << 16) | (b1 << 8) | b2;

        output[j] = base64_chars[@as(usize, @intCast((triple >> 18) & 0x3F))];
        output[j + 1] = base64_chars[@as(usize, @intCast((triple >> 12) & 0x3F))];
        output[j + 2] = if (i + 1 < input_len) base64_chars[@as(usize, @intCast((triple >> 6) & 0x3F))] else '=';
        output[j + 3] = if (i + 2 < input_len) base64_chars[@as(usize, @intCast(triple & 0x3F))] else '=';

        i += 3;
        j += 4;
    }

    return output_len;
}

// ============================================================================
// CONTEXT STRUCTURE OPERATIONS
// ============================================================================

const CryptoContext = extern struct {
    key: [32]u8,
    iv: [16]u8,
    state: [256]u8,
    initialized: bool,
};

// Function 51: Initialize crypto context
noinline fn initCryptoContext(ctx: *CryptoContext, key: [*]const u8, key_len: usize, iv: [*]const u8) callconv(.c) void {
    _ = c.memset(ctx, 0, @sizeOf(CryptoContext));

    const copy_len = if (key_len > 32) 32 else key_len;
    _ = c.memcpy(&ctx.key, key, copy_len);
    _ = c.memcpy(&ctx.iv, iv, 16);

    // Initialize state (RC4-like)
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        ctx.state[i] = @truncate(i);
    }

    var j: u8 = 0;
    i = 0;
    while (i < 256) : (i += 1) {
        j = j +% ctx.state[i] +% ctx.key[i % copy_len];
        const tmp = ctx.state[i];
        ctx.state[i] = ctx.state[j];
        ctx.state[j] = tmp;
    }

    ctx.initialized = true;
}

// Function 52: Encrypt with context
noinline fn encryptWithContext(ctx: *CryptoContext, plaintext: [*]u8, len: usize, ciphertext: [*]u8) callconv(.c) void {
    if (!ctx.initialized) return;

    _ = c.memcpy(ciphertext, plaintext, len);

    var i: u8 = 0;
    var j: u8 = 0;
    var k: usize = 0;

    while (k < len) : (k += 1) {
        i +%= 1;
        j +%= ctx.state[i];
        const tmp = ctx.state[i];
        ctx.state[i] = ctx.state[j];
        ctx.state[j] = tmp;
        ciphertext[k] ^= ctx.state[ctx.state[i] +% ctx.state[j]];
    }
}

// Function 53: Decrypt with context (same as encrypt for stream cipher)
noinline fn decryptWithContext(ctx: *CryptoContext, ciphertext: [*]u8, len: usize, plaintext: [*]u8) callconv(.c) void {
    encryptWithContext(ctx, ciphertext, len, plaintext);
}

// Function 54: Destroy crypto context
noinline fn destroyCryptoContext(ctx: *CryptoContext) callconv(.c) void {
    _ = c.memset(ctx, 0, @sizeOf(CryptoContext));
}

// ============================================================================
// CONNECTION HANDLER
// ============================================================================

const ConnectionContext = extern struct {
    sock: c_int,
    recv_buffer: [4096]u8,
    send_buffer: [4096]u8,
    recv_len: usize,
    connected: bool,
};

// Function 55: Initialize connection
noinline fn initConnection(ctx: *ConnectionContext) callconv(.c) void {
    _ = c.memset(ctx, 0, @sizeOf(ConnectionContext));
    ctx.sock = -1;
    ctx.connected = false;
}

// Function 56: Connect
noinline fn establishConnection(ctx: *ConnectionContext, host: [*:0]const u8, port: u16) callconv(.c) bool {
    ctx.sock = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (ctx.sock < 0) return false;

    var addr: c.sockaddr_in = undefined;
    _ = c.memset(&addr, 0, @sizeOf(c.sockaddr_in));
    addr.sin_family = c.AF_INET;
    addr.sin_port = c.htons(port);
    _ = c.inet_pton(c.AF_INET, host, &addr.sin_addr);

    if (c.connect(ctx.sock, @ptrCast(&addr), @sizeOf(c.sockaddr_in)) < 0) {
        _ = c.close(ctx.sock);
        ctx.sock = -1;
        return false;
    }

    ctx.connected = true;
    return true;
}

// Function 57: Send message
noinline fn sendMessage(ctx: *ConnectionContext, msg: [*]const u8, len: usize) callconv(.c) bool {
    if (!ctx.connected) return false;

    var total_sent: usize = 0;
    while (total_sent < len) {
        const sent = c.send(ctx.sock, msg + total_sent, len - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += @intCast(sent);
    }
    return true;
}

// Function 58: Receive message
noinline fn receiveMessage(ctx: *ConnectionContext) callconv(.c) isize {
    if (!ctx.connected) return -1;

    const received = c.recv(ctx.sock, &ctx.recv_buffer, ctx.recv_buffer.len - 1, 0);
    if (received > 0) {
        ctx.recv_len = @intCast(received);
        ctx.recv_buffer[@intCast(received)] = 0;
    }
    return received;
}

// Function 59: Close connection
noinline fn closeConnection(ctx: *ConnectionContext) callconv(.c) void {
    if (ctx.sock >= 0) {
        _ = c.close(ctx.sock);
        ctx.sock = -1;
    }
    ctx.connected = false;
    _ = c.memset(&ctx.recv_buffer, 0, ctx.recv_buffer.len);
    _ = c.memset(&ctx.send_buffer, 0, ctx.send_buffer.len);
}

// Function 60: Process received data
noinline fn processReceivedData(ctx: *ConnectionContext, handler: *const fn ([*]u8, usize) callconv(.c) void) callconv(.c) void {
    if (ctx.recv_len > 0) {
        handler(&ctx.recv_buffer, ctx.recv_len);
    }
}

// ============================================================================
// MAIN - Exercise all functions
// ============================================================================

// Volatile global to prevent DCE
var g_result: i64 = 0;

fn use(val: anytype) void {
    const T = @TypeOf(val);
    switch (@typeInfo(T)) {
        .int, .comptime_int => {
            const info = @typeInfo(T).int;
            if (info.signedness == .signed) {
                g_result +%= @as(i64, @intCast(val));
            } else {
                // For unsigned, cast to i64 safely
                g_result +%= @as(i64, @intCast(val));
            }
        },
        .bool => g_result +%= if (val) 1 else 0,
        .pointer => g_result +%= @as(i64, @bitCast(@as(u64, @intFromPtr(val)))),
        .optional => if (val) |v| use(v),
        else => {},
    }
}

noinline fn dummyHandler(data: [*]u8, len: usize) callconv(.c) void {
    _ = data;
    g_result +%= @as(i64, @intCast(len));
}

pub export fn main() c_int {
    // Memory operations
    const buf1 = allocateBuffer(256);
    use(buf1);

    const test_data = "Hello, World!";
    const buf2 = allocateAndCopy(test_data, 13);
    use(buf2);

    const buf3 = resizeBuffer(buf1, 256, 512);
    use(buf3);

    var temp_buf: [128]u8 = undefined;
    use(safeCopy(&temp_buf, temp_buf.len, test_data, 13));

    moveBuffer(&temp_buf, &temp_buf, 64);
    zeroMemory(&temp_buf, 64);
    fillBuffer(&temp_buf, 64, 0xAA);
    use(compareMemory(&temp_buf, test_data, 13));

    const dup = duplicateMemory(test_data, 13);
    use(dup);

    // String operations
    use(getStringLength("Test String"));

    var str_buf: [256:0]u8 = undefined;
    _ = copyString(&str_buf, "Hello");
    _ = safeCopyString(&str_buf, "Hello World", 100);
    use(compareStrings("abc", "abd"));
    use(compareStringsN("abcdef", "abcxyz", 3));
    _ = concatenateStrings(&str_buf, " Extra");

    const str_dup = duplicateString("Duplicate Me");
    use(str_dup);

    use(findChar("hello", 'e'));
    use(findSubstring("hello world", "wor"));
    use(stringToInt("12345"));

    // File operations (won't actually work but exercises the code paths)
    const fd1 = openFileRead("/dev/null");
    use(fd1);
    if (fd1 >= 0) {
        var file_buf: [256]u8 = undefined;
        use(readFromFile(fd1, &file_buf, 256));
        use(closeFile(fd1));
    }

    const fd2 = openFileWrite("/tmp/test_output.txt");
    use(fd2);
    if (fd2 >= 0) {
        use(writeToFile(fd2, test_data, 13));
        use(seekFile(fd2, 0, c.SEEK_SET));
        use(closeFile(fd2));
    }

    var content_buf: [1024]u8 = undefined;
    use(readFileContents("/dev/null", &content_buf, 1024));
    use(writeFileContents("/tmp/test2.txt", test_data, 13));
    use(copyFile("/dev/null", "/tmp/test3.txt"));

    // Network operations (won't connect but exercises code)
    const sock1 = createTcpSocket();
    use(sock1);
    const sock2 = createUdpSocket();
    use(sock2);

    if (sock1 >= 0) {
        // These will fail but that's OK for testing
        use(connectToServer(sock1, "127.0.0.1", 8080));
        use(sendData(sock1, test_data, 13));

        var recv_buf: [256]u8 = undefined;
        use(receiveData(sock1, &recv_buf, 256));
        use(closeSocket(sock1));
    }

    if (sock2 >= 0) {
        use(bindSocket(sock2, 9090));
        use(listenSocket(sock2, 5));
        use(closeSocket(sock2));
    }

    // Higher-level operations
    var file_size: usize = 0;
    const file_content = allocateAndReadFile("/dev/null", &file_size);
    use(file_content);

    const sb = createStringBuffer(64);
    if (sb) |string_buf| {
        use(appendToBuffer(string_buf, "First "));
        use(appendToBuffer(string_buf, "Second"));
        freeStringBuffer(string_buf);
    }

    var http_buf: [1024]u8 = undefined;
    use(buildHttpRequest("GET", "/index.html", "example.com", &http_buf, 1024));

    var key_buf: [64]u8 = undefined;
    var val_buf: [64]u8 = undefined;
    use(parseKeyValue("name=value", &key_buf, 64, &val_buf, 64));

    var encrypt_buf: [32]u8 = undefined;
    @memcpy(encrypt_buf[0..13], test_data[0..13]);
    xorEncrypt(&encrypt_buf, 13, "key", 3);
    use(calculateChecksum(&encrypt_buf, 13));

    var hex_out: [64]u8 = undefined;
    use(hexEncode(test_data, 13, &hex_out, 64));

    var b64_out: [64]u8 = undefined;
    use(base64Encode(test_data, 13, &b64_out, 64));

    // Crypto context
    var crypto_ctx: CryptoContext = undefined;
    const crypto_key = "0123456789abcdef0123456789abcdef";
    const crypto_iv = "0123456789abcdef";
    initCryptoContext(&crypto_ctx, crypto_key, 32, crypto_iv);

    var plaintext: [64]u8 = undefined;
    var ciphertext: [64]u8 = undefined;
    @memcpy(plaintext[0..16], "Secret message!!");
    encryptWithContext(&crypto_ctx, &plaintext, 16, &ciphertext);
    decryptWithContext(&crypto_ctx, &ciphertext, 16, &plaintext);
    destroyCryptoContext(&crypto_ctx);

    // Connection context
    var conn_ctx: ConnectionContext = undefined;
    initConnection(&conn_ctx);
    // Don't actually try to connect
    // use(establishConnection(&conn_ctx, "127.0.0.1", 8080));
    processReceivedData(&conn_ctx, &dummyHandler);
    closeConnection(&conn_ctx);

    // Free allocated memory
    freeBuffer(buf2);
    freeBuffer(buf3);
    freeBuffer(dup);
    if (str_dup) |sd| freeBuffer(sd);
    if (file_content) |fc| freeBuffer(fc);

    // Print result
    const msg = "Binary test completed.\n";
    _ = c.write(1, msg, c.strlen(msg));

    return @truncate(g_result);
}
