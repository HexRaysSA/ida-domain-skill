// Cross-Module Import Usage Map - Test Binary
// Creates a binary with diverse imports for IDA import analysis
//
// Categories of imports demonstrated:
// 1. Standard library (libc) via Zig std
// 2. Network APIs (POSIX sockets)
// 3. File I/O functions
// 4. Dynamic import resolution (dlopen/dlsym)
// 5. Crypto via CommonCrypto (macOS)

const std = @import("std");
const posix = std.posix;
const c = @cImport({
    @cInclude("dlfcn.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("errno.h");
    @cInclude("time.h");
    @cInclude("pthread.h");
    @cInclude("signal.h");
    @cInclude("netdb.h");
    @cInclude("sys/time.h");
    @cInclude("sys/syslimits.h");
    // macOS CommonCrypto for crypto functions
    @cInclude("CommonCrypto/CommonDigest.h");
    @cInclude("CommonCrypto/CommonCryptor.h");
    @cInclude("CommonCrypto/CommonRandom.h");
});

// Global state for demonstration
var g_initialized: bool = false;
var g_log_file: ?*c.FILE = null;
var g_crypto_ready: bool = false;

// ============================================================================
// Section 1: Standard Library Imports (libc)
// ============================================================================

fn initializeLogging() bool {
    g_log_file = c.fopen("/tmp/import_test.log", "w");
    if (g_log_file == null) {
        _ = c.perror("Failed to open log file");
        return false;
    }
    _ = c.fprintf(g_log_file, "=== Import Test Log ===\n");
    _ = c.fflush(g_log_file);
    return true;
}

fn logMessage(msg: [*c]const u8) void {
    if (g_log_file) |file| {
        var time_buf: [64]u8 = undefined;
        const now = c.time(null);
        const tm = c.localtime(&now);
        _ = c.strftime(&time_buf, time_buf.len, "%Y-%m-%d %H:%M:%S", tm);
        _ = c.fprintf(file, "[%s] %s\n", &time_buf, msg);
        _ = c.fflush(file);
    }
}

fn closeLogging() void {
    if (g_log_file) |file| {
        _ = c.fprintf(file, "=== Log Closed ===\n");
        _ = c.fclose(file);
        g_log_file = null;
    }
}

fn allocateAndProcess() !void {
    // malloc/free usage
    const size: usize = 1024;
    const buffer: ?*anyopaque = c.malloc(size);
    if (buffer == null) {
        return error.AllocationFailed;
    }
    defer c.free(buffer);

    // memset/memcpy usage
    _ = c.memset(buffer, 0, size);

    const test_data = "Test data for memory operations";
    _ = c.memcpy(buffer, test_data, test_data.len);

    // strlen usage
    const len = c.strlen(@ptrCast(buffer));
    _ = c.printf("Copied %zu bytes\n", len);
}

fn environmentOperations() void {
    // getenv usage
    const home = c.getenv("HOME");
    if (home != null) {
        _ = c.printf("HOME: %s\n", home);
    }

    // getcwd usage
    var cwd_buf: [1024]u8 = undefined;
    const cwd = c.getcwd(&cwd_buf, cwd_buf.len);
    if (cwd != null) {
        _ = c.printf("CWD: %s\n", cwd);
    }
}

fn stringOperations() void {
    var buf1: [256]u8 = undefined;
    var buf2: [256]u8 = undefined;

    // strcpy, strcat, strcmp
    _ = c.strcpy(&buf1, "Hello, ");
    _ = c.strcat(&buf1, "World!");

    _ = c.strcpy(&buf2, "Hello, World!");

    const cmp_result = c.strcmp(&buf1, &buf2);
    _ = c.printf("String comparison result: %d\n", cmp_result);

    // strstr usage
    const found = c.strstr(&buf1, "World");
    if (found != null) {
        const found_addr: isize = @intCast(@intFromPtr(found));
        const buf_addr: isize = @intCast(@intFromPtr(&buf1));
        _ = c.printf("Found substring at offset: %td\n", found_addr - buf_addr);
    }

    // sprintf usage
    _ = c.sprintf(&buf1, "Formatted: %d, %s, %f", @as(c_int, 42), "test", @as(f64, 3.14));
}

// ============================================================================
// Section 2: File I/O Functions
// ============================================================================

fn fileOperationsHighLevel() !void {
    const test_file = "/tmp/import_test_data.txt";

    // fopen, fwrite, fclose
    const fp = c.fopen(test_file, "w");
    if (fp == null) {
        return error.FileOpenFailed;
    }

    const data = "Test data for file operations\n";
    _ = c.fwrite(data, 1, data.len, fp);
    _ = c.fflush(fp);
    _ = c.fclose(fp);

    // fopen, fread for reading back
    const fp_read = c.fopen(test_file, "r");
    if (fp_read == null) {
        return error.FileOpenFailed;
    }
    defer _ = c.fclose(fp_read);

    var read_buf: [256]u8 = undefined;
    const bytes_read = c.fread(&read_buf, 1, read_buf.len, fp_read);
    _ = c.printf("Read %zu bytes from file\n", bytes_read);

    // ftell, fseek
    _ = c.fseek(fp_read, 0, c.SEEK_END);
    const file_size = c.ftell(fp_read);
    _ = c.printf("File size: %ld bytes\n", file_size);

    // remove file
    _ = c.remove(test_file);
}

fn fileOperationsLowLevel() !void {
    const test_file = "/tmp/import_test_low.dat";

    // open (low-level)
    const fd = c.open(test_file, c.O_CREAT | c.O_WRONLY | c.O_TRUNC, @as(c.mode_t, 0o644));
    if (fd < 0) {
        return error.FileOpenFailed;
    }

    // write
    const data = "Low-level file data";
    _ = c.write(fd, data, data.len);

    // fsync
    _ = c.fsync(fd);

    // close
    _ = c.close(fd);

    // stat
    var stat_buf: c.struct_stat = undefined;
    if (c.stat(test_file, &stat_buf) == 0) {
        _ = c.printf("File mode: %o, size: %lld\n", stat_buf.st_mode, stat_buf.st_size);
    }

    // access
    if (c.access(test_file, c.R_OK | c.W_OK) == 0) {
        _ = c.printf("File is readable and writable\n");
    }

    // unlink
    _ = c.unlink(test_file);
}

fn directoryOperations() void {
    const test_dir = "/tmp/import_test_dir";

    // mkdir
    _ = c.mkdir(test_dir, 0o755);

    // chdir (save and restore)
    var old_cwd: [1024]u8 = undefined;
    _ = c.getcwd(&old_cwd, old_cwd.len);

    if (c.chdir(test_dir) == 0) {
        _ = c.printf("Changed to test directory\n");
        _ = c.chdir(&old_cwd);
    }

    // rmdir
    _ = c.rmdir(test_dir);
}

// ============================================================================
// Section 3: Network APIs (POSIX Sockets)
// ============================================================================

fn networkOperationsSocket() !void {
    // socket creation
    const sock = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (sock < 0) {
        logMessage("Failed to create socket");
        return error.SocketFailed;
    }
    defer _ = c.close(sock);

    // setsockopt
    var opt: c_int = 1;
    _ = c.setsockopt(sock, c.SOL_SOCKET, c.SO_REUSEADDR, &opt, @sizeOf(c_int));

    // Set non-blocking
    const flags = c.fcntl(sock, c.F_GETFL, @as(c_int, 0));
    _ = c.fcntl(sock, c.F_SETFL, flags | c.O_NONBLOCK);

    // getsockname (after potential bind)
    var addr: c.struct_sockaddr_in = undefined;
    var addr_len: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
    _ = c.getsockname(sock, @ptrCast(&addr), &addr_len);

    logMessage("Socket operations completed");
}

fn networkOperationsAddress() void {
    // inet_pton / inet_ntop
    var addr: c.struct_in_addr = undefined;
    _ = c.inet_pton(c.AF_INET, "127.0.0.1", &addr);

    var addr_str: [c.INET_ADDRSTRLEN]u8 = undefined;
    _ = c.inet_ntop(c.AF_INET, &addr, &addr_str, c.INET_ADDRSTRLEN);
    _ = c.printf("Address: %s\n", &addr_str);

    // htons, htonl, ntohs, ntohl
    const port: u16 = 8080;
    const net_port = c.htons(port);
    const host_port = c.ntohs(net_port);
    _ = c.printf("Port conversion: %u -> %u -> %u\n", port, net_port, host_port);

    const ip: u32 = 0x7F000001;
    const net_ip = c.htonl(ip);
    _ = c.printf("IP conversion: 0x%08X -> 0x%08X\n", ip, net_ip);
}

fn networkOperationsDNS() void {
    // getaddrinfo - modern DNS resolution
    var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = c.AF_INET;
    hints.ai_socktype = c.SOCK_STREAM;

    var result: ?*c.struct_addrinfo = null;
    const status = c.getaddrinfo("localhost", "80", &hints, &result);
    if (status == 0 and result != null) {
        _ = c.printf("DNS resolution successful\n");
        c.freeaddrinfo(result);
    }
}

// ============================================================================
// Section 4: Crypto Functions (CommonCrypto on macOS)
// ============================================================================

fn cryptoHashMD5(data: []const u8) void {
    var digest: [c.CC_MD5_DIGEST_LENGTH]u8 = undefined;

    // CC_MD5 - single-shot hash
    _ = c.CC_MD5(data.ptr, @intCast(data.len), &digest);

    _ = c.printf("MD5: ");
    for (digest) |byte| {
        _ = c.printf("%02x", byte);
    }
    _ = c.printf("\n");
}

fn cryptoHashSHA1(data: []const u8) void {
    var digest: [c.CC_SHA1_DIGEST_LENGTH]u8 = undefined;

    // CC_SHA1 - single-shot hash
    _ = c.CC_SHA1(data.ptr, @intCast(data.len), &digest);

    _ = c.printf("SHA1: ");
    for (digest) |byte| {
        _ = c.printf("%02x", byte);
    }
    _ = c.printf("\n");
}

fn cryptoHashSHA256(data: []const u8) void {
    var digest: [c.CC_SHA256_DIGEST_LENGTH]u8 = undefined;

    // CC_SHA256 - single-shot hash
    _ = c.CC_SHA256(data.ptr, @intCast(data.len), &digest);

    _ = c.printf("SHA256: ");
    for (digest) |byte| {
        _ = c.printf("%02x", byte);
    }
    _ = c.printf("\n");
}

fn cryptoHashContextBased() void {
    // Context-based hashing (multiple updates)
    var ctx: c.CC_SHA256_CTX = undefined;
    _ = c.CC_SHA256_Init(&ctx);

    const part1 = "Hello, ";
    const part2 = "World!";
    _ = c.CC_SHA256_Update(&ctx, part1, part1.len);
    _ = c.CC_SHA256_Update(&ctx, part2, part2.len);

    var digest: [c.CC_SHA256_DIGEST_LENGTH]u8 = undefined;
    _ = c.CC_SHA256_Final(&digest, &ctx);

    _ = c.printf("SHA256 (context): ");
    for (digest) |byte| {
        _ = c.printf("%02x", byte);
    }
    _ = c.printf("\n");
}

fn cryptoRandom() void {
    var random_bytes: [32]u8 = undefined;

    // CCRandomGenerateBytes - secure random
    const status = c.CCRandomGenerateBytes(&random_bytes, random_bytes.len);
    if (status == c.kCCSuccess) {
        _ = c.printf("Random bytes: ");
        for (random_bytes[0..8]) |byte| {
            _ = c.printf("%02x", byte);
        }
        _ = c.printf("...\n");
    }
}

fn cryptoSymmetric() void {
    // AES encryption/decryption
    const key: [16]u8 = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const iv: [16]u8 = .{0} ** 16;
    const plaintext = "Encrypt this!!!!"; // 16 bytes for AES block
    var ciphertext: [32]u8 = undefined;
    var decrypted: [32]u8 = undefined;
    var out_len: usize = 0;

    // CCCrypt for encryption
    var status = c.CCCrypt(
        c.kCCEncrypt,
        c.kCCAlgorithmAES128,
        c.kCCOptionPKCS7Padding,
        &key,
        key.len,
        &iv,
        plaintext,
        plaintext.len,
        &ciphertext,
        ciphertext.len,
        &out_len,
    );

    if (status == c.kCCSuccess) {
        _ = c.printf("Encrypted %zu bytes\n", out_len);

        // CCCrypt for decryption
        var dec_len: usize = 0;
        status = c.CCCrypt(
            c.kCCDecrypt,
            c.kCCAlgorithmAES128,
            c.kCCOptionPKCS7Padding,
            &key,
            key.len,
            &iv,
            &ciphertext,
            out_len,
            &decrypted,
            decrypted.len,
            &dec_len,
        );

        if (status == c.kCCSuccess) {
            _ = c.printf("Decrypted: %.*s\n", @as(c_int, @intCast(dec_len)), &decrypted);
        }
    }
}

// ============================================================================
// Section 5: Dynamic Import Resolution (dlopen/dlsym)
// ============================================================================

const DynamicFuncInfo = struct {
    name: [*c]const u8,
    handle: ?*anyopaque,
};

var g_dynamic_funcs: [8]DynamicFuncInfo = undefined;
var g_dynamic_count: usize = 0;

fn resolveDynamicFunction(lib_handle: ?*anyopaque, func_name: [*c]const u8) ?*anyopaque {
    if (lib_handle == null) return null;

    // Clear any existing error
    _ = c.dlerror();

    // dlsym - the key function for dynamic import resolution
    const func_ptr = c.dlsym(lib_handle, func_name);

    const err = c.dlerror();
    if (err != null) {
        _ = c.printf("dlsym error for %s: %s\n", func_name, err);
        return null;
    }

    // Track resolved function
    if (g_dynamic_count < g_dynamic_funcs.len) {
        g_dynamic_funcs[g_dynamic_count] = .{
            .name = func_name,
            .handle = func_ptr,
        };
        g_dynamic_count += 1;
    }

    _ = c.printf("Resolved: %s -> %p\n", func_name, func_ptr);
    return func_ptr;
}

fn dynamicImportResolution() void {
    // dlopen - load a dynamic library
    const lib_handle = c.dlopen("libSystem.B.dylib", c.RTLD_NOW | c.RTLD_LOCAL);
    if (lib_handle == null) {
        const err = c.dlerror();
        _ = c.printf("dlopen failed: %s\n", err);
        return;
    }
    defer _ = c.dlclose(lib_handle);

    _ = c.printf("Library loaded at: %p\n", lib_handle);

    // Resolve multiple functions dynamically
    // This pattern is what IDA should detect for "pseudo-imports"
    const functions_to_resolve = [_][*c]const u8{
        "malloc",
        "free",
        "printf",
        "strlen",
        "memcpy",
        "open",
        "close",
        "read",
    };

    for (functions_to_resolve) |func_name| {
        _ = resolveDynamicFunction(lib_handle, func_name);
    }

    // Pattern: resolve function and call it
    const dyn_malloc_ptr = c.dlsym(lib_handle, "malloc");
    const dyn_free_ptr = c.dlsym(lib_handle, "free");

    if (dyn_malloc_ptr != null and dyn_free_ptr != null) {
        // Cast to function pointers and call
        const MallocFnType = *const fn (usize) callconv(.c) ?*anyopaque;
        const FreeFnType = *const fn (?*anyopaque) callconv(.c) void;

        const dyn_malloc: MallocFnType = @ptrCast(@alignCast(dyn_malloc_ptr));
        const dyn_free: FreeFnType = @ptrCast(@alignCast(dyn_free_ptr));

        const mem_ptr = dyn_malloc(256);
        if (mem_ptr != null) {
            _ = c.printf("Dynamic malloc returned: %p\n", mem_ptr);
            dyn_free(mem_ptr);
            _ = c.printf("Dynamic free called\n");
        }
    }
}

fn loadOptionalLibraries() void {
    // Try to load additional libraries (may not exist)
    const optional_libs = [_][*c]const u8{
        "/usr/lib/libz.dylib",
        "/usr/lib/libcurl.dylib",
        "/usr/lib/libsqlite3.dylib",
    };

    for (optional_libs) |lib_path| {
        const handle = c.dlopen(lib_path, c.RTLD_NOW | c.RTLD_LOCAL);
        if (handle != null) {
            _ = c.printf("Loaded optional library: %s\n", lib_path);

            // Resolve some functions from loaded library
            _ = c.dlsym(handle, "deflate"); // libz
            _ = c.dlsym(handle, "curl_easy_init"); // libcurl
            _ = c.dlsym(handle, "sqlite3_open"); // libsqlite3

            _ = c.dlclose(handle);
        }
    }
}

// ============================================================================
// Section 6: Threading and Synchronization
// ============================================================================

var g_mutex: c.pthread_mutex_t = undefined;
var g_thread_data: i32 = 0;

fn threadFunction(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = arg;

    // pthread_mutex_lock/unlock
    _ = c.pthread_mutex_lock(&g_mutex);
    g_thread_data += 1;
    _ = c.printf("Thread incremented data to: %d\n", g_thread_data);
    _ = c.pthread_mutex_unlock(&g_mutex);

    // pthread_self
    const self = c.pthread_self();
    _ = c.printf("Thread ID: %p\n", @as(?*anyopaque, @ptrCast(self)));

    return null;
}

fn threadingOperations() void {
    // pthread_mutex_init
    _ = c.pthread_mutex_init(&g_mutex, null);
    defer _ = c.pthread_mutex_destroy(&g_mutex);

    var threads: [4]c.pthread_t = undefined;

    // pthread_create
    for (&threads) |*thread| {
        _ = c.pthread_create(thread, null, &threadFunction, null);
    }

    // pthread_join
    for (threads) |thread| {
        _ = c.pthread_join(thread, null);
    }

    _ = c.printf("All threads completed, final data: %d\n", g_thread_data);
}

// ============================================================================
// Section 7: Signal Handling
// ============================================================================

var g_signal_received: bool = false;

fn signalHandler(sig: c_int) callconv(.c) void {
    g_signal_received = true;
    _ = c.printf("Received signal: %d\n", sig);
}

fn signalOperations() void {
    // Use sigaction for signal handling (more portable than signal())
    var sa: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
    sa.__sigaction_u.__sa_handler = &signalHandler;

    // sigaction - register handler for SIGUSR1
    if (c.sigaction(c.SIGUSR1, &sa, null) == 0) {
        _ = c.printf("Signal handler registered via sigaction\n");

        // raise - send signal to self
        _ = c.raise(c.SIGUSR1);
    }

    // Also register for SIGUSR2
    _ = c.sigaction(c.SIGUSR2, &sa, null);
}

// ============================================================================
// Section 8: Process and System Information
// ============================================================================

fn processOperations() void {
    // getpid, getppid
    const pid = c.getpid();
    const ppid = c.getppid();
    _ = c.printf("PID: %d, PPID: %d\n", pid, ppid);

    // getuid, geteuid, getgid, getegid
    const uid = c.getuid();
    const euid = c.geteuid();
    const gid = c.getgid();
    const egid = c.getegid();
    _ = c.printf("UID: %d, EUID: %d, GID: %d, EGID: %d\n", uid, euid, gid, egid);
}

fn timeOperations() void {
    // time
    const now = c.time(null);
    _ = c.printf("Current time: %ld\n", now);

    // gettimeofday
    var tv: c.struct_timeval = undefined;
    _ = c.gettimeofday(&tv, null);
    _ = c.printf("Time: %ld.%06d\n", tv.tv_sec, @as(c_int, @intCast(tv.tv_usec)));

    // localtime, strftime
    const tm = c.localtime(&now);
    var time_str: [64]u8 = undefined;
    _ = c.strftime(&time_str, time_str.len, "%Y-%m-%d %H:%M:%S", tm);
    _ = c.printf("Formatted time: %s\n", &time_str);

    // sleep (short)
    _ = c.usleep(1000); // 1ms
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub fn main() !void {
    _ = c.printf("=== Cross-Module Import Test Binary ===\n\n");

    // Initialize logging
    if (!initializeLogging()) {
        _ = c.printf("Warning: Logging initialization failed\n");
    }
    defer closeLogging();

    logMessage("Starting import test");

    // Section 1: Standard Library
    _ = c.printf("--- Standard Library Operations ---\n");
    try allocateAndProcess();
    environmentOperations();
    stringOperations();

    // Section 2: File I/O
    _ = c.printf("\n--- File I/O Operations ---\n");
    try fileOperationsHighLevel();
    try fileOperationsLowLevel();
    directoryOperations();

    // Section 3: Network APIs
    _ = c.printf("\n--- Network Operations ---\n");
    try networkOperationsSocket();
    networkOperationsAddress();
    networkOperationsDNS();

    // Section 4: Crypto Functions
    _ = c.printf("\n--- Crypto Operations ---\n");
    const test_data = "Hello, World!";
    cryptoHashMD5(test_data);
    cryptoHashSHA1(test_data);
    cryptoHashSHA256(test_data);
    cryptoHashContextBased();
    cryptoRandom();
    cryptoSymmetric();

    // Section 5: Dynamic Import Resolution
    _ = c.printf("\n--- Dynamic Import Resolution ---\n");
    dynamicImportResolution();
    loadOptionalLibraries();

    // Section 6: Threading
    _ = c.printf("\n--- Threading Operations ---\n");
    threadingOperations();

    // Section 7: Signals
    _ = c.printf("\n--- Signal Operations ---\n");
    signalOperations();

    // Section 8: Process/System Info
    _ = c.printf("\n--- Process Operations ---\n");
    processOperations();
    timeOperations();

    logMessage("Import test completed");
    _ = c.printf("\n=== Test Complete ===\n");

    // Summary of dynamic imports resolved
    _ = c.printf("\nDynamic imports resolved: %zu\n", g_dynamic_count);
    for (g_dynamic_funcs[0..g_dynamic_count]) |func_info| {
        _ = c.printf("  - %s: %p\n", func_info.name, func_info.handle);
    }
}
