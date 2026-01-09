// String Provenance Sample Binary
// Contains diverse "interesting" strings for reverse engineering analysis
//
// Features:
// - Network communication code
// - Persistence mechanisms
// - Anti-debug/anti-VM checks
// - Configuration handling

const std = @import("std");

// Global volatile pointer to prevent optimization
var sink: usize = 0;

// Helper to prevent string optimization
fn use_string(s: []const u8) void {
    sink +%= s.len;
    sink +%= @intFromPtr(s.ptr);
}

// ============================================================================
// NETWORK STRINGS - URLs, IPs, Ports, API Endpoints
// ============================================================================

pub export fn network_beacon_url1() [*:0]const u8 {
    return "http://evil.example.com/beacon";
}

pub export fn network_beacon_url2() [*:0]const u8 {
    return "https://cdn.malware-c2.net/update.php";
}

pub export fn network_beacon_url3() [*:0]const u8 {
    return "http://192.168.1.100:8080/cmd";
}

pub export fn network_beacon_url4() [*:0]const u8 {
    return "https://api.legitimate-service.com/v2/data";
}

pub export fn network_beacon_url5() [*:0]const u8 {
    return "http://10.0.0.1:443/exfil";
}

pub export fn network_beacon_url6() [*:0]const u8 {
    return "wss://realtime.tracker.io/socket";
}

pub export fn network_beacon_url7() [*:0]const u8 {
    return "ftp://files.dropzone.ru/incoming";
}

pub export fn get_ip_addr1() [*:0]const u8 {
    return "192.168.1.1";
}

pub export fn get_ip_addr2() [*:0]const u8 {
    return "10.0.0.254";
}

pub export fn get_ip_addr3() [*:0]const u8 {
    return "172.16.0.1";
}

pub export fn get_ip_addr4() [*:0]const u8 {
    return "8.8.8.8";
}

pub export fn get_ip_addr5() [*:0]const u8 {
    return "1.1.1.1";
}

pub export fn get_ip_addr6() [*:0]const u8 {
    return "203.0.113.50";
}

pub export fn get_ip_addr7() [*:0]const u8 {
    return "198.51.100.23";
}

pub export fn get_api_endpoint1() [*:0]const u8 {
    return "/api/v1/auth/login";
}

pub export fn get_api_endpoint2() [*:0]const u8 {
    return "/api/v2/users/profile";
}

pub export fn get_api_endpoint3() [*:0]const u8 {
    return "/rest/config/update";
}

pub export fn get_api_endpoint4() [*:0]const u8 {
    return "/webhook/callback";
}

pub export fn get_api_endpoint5() [*:0]const u8 {
    return "/graphql";
}

pub export fn get_api_endpoint6() [*:0]const u8 {
    return "/admin/panel";
}

pub export fn get_api_endpoint7() [*:0]const u8 {
    return "/metrics/prometheus";
}

fn init_network_module() void {
    use_string("http://evil.example.com/beacon");
    use_string("https://cdn.malware-c2.net/update.php");
    use_string("http://192.168.1.100:8080/cmd");
    use_string("https://api.legitimate-service.com/v2/data");
    use_string("http://10.0.0.1:443/exfil");
    use_string("wss://realtime.tracker.io/socket");
    use_string("ftp://files.dropzone.ru/incoming");
    use_string("192.168.1.1");
    use_string("10.0.0.254");
    use_string("172.16.0.1");
    use_string("8.8.8.8");
    use_string("1.1.1.1");
    use_string("203.0.113.50");
    use_string("198.51.100.23");
    use_string("/api/v1/auth/login");
    use_string("/api/v2/users/profile");
    use_string("/rest/config/update");
    use_string("/webhook/callback");
    use_string("/graphql");
    use_string("/admin/panel");
    use_string("/metrics/prometheus");
}

// ============================================================================
// PERSISTENCE STRINGS - Registry, Startup Paths, Scheduled Tasks
// ============================================================================

pub export fn get_registry_key1() [*:0]const u8 {
    return "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
}

pub export fn get_registry_key2() [*:0]const u8 {
    return "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
}

pub export fn get_registry_key3() [*:0]const u8 {
    return "HKLM\\SYSTEM\\CurrentControlSet\\Services";
}

pub export fn get_registry_key4() [*:0]const u8 {
    return "HKCU\\Software\\Classes\\CLSID";
}

pub export fn get_registry_key5() [*:0]const u8 {
    return "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
}

pub export fn get_registry_key6() [*:0]const u8 {
    return "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
}

pub export fn get_startup_path1() [*:0]const u8 {
    return "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
}

pub export fn get_startup_path2() [*:0]const u8 {
    return "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
}

pub export fn get_startup_path3() [*:0]const u8 {
    return "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
}

pub export fn get_startup_path4() [*:0]const u8 {
    return "/etc/init.d/";
}

pub export fn get_startup_path5() [*:0]const u8 {
    return "/Library/LaunchDaemons/";
}

pub export fn get_startup_path6() [*:0]const u8 {
    return "~/.config/autostart/";
}

pub export fn get_scheduled_task1() [*:0]const u8 {
    return "\\Microsoft\\Windows\\UpdateTask";
}

pub export fn get_scheduled_task2() [*:0]const u8 {
    return "SystemHealthMonitor";
}

pub export fn get_scheduled_task3() [*:0]const u8 {
    return "AdobeFlashPlayerUpdater";
}

pub export fn get_scheduled_task4() [*:0]const u8 {
    return "GoogleUpdateTaskMachine";
}

fn install_persistence() void {
    use_string("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    use_string("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    use_string("HKLM\\SYSTEM\\CurrentControlSet\\Services");
    use_string("HKCU\\Software\\Classes\\CLSID");
    use_string("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    use_string("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");
    use_string("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp");
    use_string("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    use_string("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    use_string("/etc/init.d/");
    use_string("/Library/LaunchDaemons/");
    use_string("~/.config/autostart/");
    use_string("\\Microsoft\\Windows\\UpdateTask");
    use_string("SystemHealthMonitor");
    use_string("AdobeFlashPlayerUpdater");
    use_string("GoogleUpdateTaskMachine");
    use_string("malware.exe");
}

// ============================================================================
// ANTI-DEBUG STRINGS - Debugger Detection, VM Detection
// ============================================================================

pub export fn get_debug_api1() [*:0]const u8 {
    return "IsDebuggerPresent";
}

pub export fn get_debug_api2() [*:0]const u8 {
    return "CheckRemoteDebuggerPresent";
}

pub export fn get_debug_api3() [*:0]const u8 {
    return "NtQueryInformationProcess";
}

pub export fn get_debug_api4() [*:0]const u8 {
    return "OutputDebugStringA";
}

pub export fn get_debug_api5() [*:0]const u8 {
    return "FindWindowA";
}

pub export fn get_debug_api6() [*:0]const u8 {
    return "GetTickCount";
}

pub export fn get_debug_api7() [*:0]const u8 {
    return "QueryPerformanceCounter";
}

pub export fn get_vm_indicator1() [*:0]const u8 {
    return "VMwareService.exe";
}

pub export fn get_vm_indicator2() [*:0]const u8 {
    return "VBoxService.exe";
}

pub export fn get_vm_indicator3() [*:0]const u8 {
    return "vmtoolsd.exe";
}

pub export fn get_vm_indicator4() [*:0]const u8 {
    return "vmsrvc.exe";
}

pub export fn get_vm_indicator5() [*:0]const u8 {
    return "VBOX HARDDISK";
}

pub export fn get_vm_indicator6() [*:0]const u8 {
    return "Virtual HD";
}

pub export fn get_vm_indicator7() [*:0]const u8 {
    return "QEMU HARDDISK";
}

pub export fn get_vm_indicator8() [*:0]const u8 {
    return "VMWARE";
}

pub export fn get_debugger_window1() [*:0]const u8 {
    return "OllyDbg";
}

pub export fn get_debugger_window2() [*:0]const u8 {
    return "x64dbg";
}

pub export fn get_debugger_window3() [*:0]const u8 {
    return "x32dbg";
}

pub export fn get_debugger_window4() [*:0]const u8 {
    return "IDA";
}

pub export fn get_debugger_window5() [*:0]const u8 {
    return "Immunity Debugger";
}

pub export fn get_debugger_window6() [*:0]const u8 {
    return "Ghidra";
}

pub export fn get_debugger_window7() [*:0]const u8 {
    return "WinDbg";
}

pub export fn get_debugger_window8() [*:0]const u8 {
    return "Process Monitor";
}

fn perform_antidebug_checks() bool {
    use_string("IsDebuggerPresent");
    use_string("CheckRemoteDebuggerPresent");
    use_string("NtQueryInformationProcess");
    use_string("OutputDebugStringA");
    use_string("FindWindowA");
    use_string("GetTickCount");
    use_string("QueryPerformanceCounter");
    use_string("VMwareService.exe");
    use_string("VBoxService.exe");
    use_string("vmtoolsd.exe");
    use_string("vmsrvc.exe");
    use_string("VBOX HARDDISK");
    use_string("Virtual HD");
    use_string("QEMU HARDDISK");
    use_string("VMWARE");
    use_string("OllyDbg");
    use_string("x64dbg");
    use_string("x32dbg");
    use_string("IDA");
    use_string("Immunity Debugger");
    use_string("Ghidra");
    use_string("WinDbg");
    use_string("Process Monitor");
    return false;
}

// ============================================================================
// FILE OPERATION STRINGS - Paths, Extensions, File Names
// ============================================================================

pub export fn get_target_path1() [*:0]const u8 {
    return "C:\\Windows\\System32\\config\\SAM";
}

pub export fn get_target_path2() [*:0]const u8 {
    return "C:\\Windows\\System32\\config\\SYSTEM";
}

pub export fn get_target_path3() [*:0]const u8 {
    return "/etc/passwd";
}

pub export fn get_target_path4() [*:0]const u8 {
    return "/etc/shadow";
}

pub export fn get_target_path5() [*:0]const u8 {
    return "~/.ssh/id_rsa";
}

pub export fn get_target_path6() [*:0]const u8 {
    return "C:\\Users\\%USERNAME%\\Documents";
}

pub export fn get_target_path7() [*:0]const u8 {
    return "%TEMP%\\payload.dll";
}

pub export fn get_target_path8() [*:0]const u8 {
    return "/tmp/.hidden_payload";
}

pub export fn get_extension1() [*:0]const u8 {
    return ".doc";
}

pub export fn get_extension2() [*:0]const u8 {
    return ".docx";
}

pub export fn get_extension3() [*:0]const u8 {
    return ".xls";
}

pub export fn get_extension4() [*:0]const u8 {
    return ".xlsx";
}

pub export fn get_extension5() [*:0]const u8 {
    return ".pdf";
}

pub export fn get_extension6() [*:0]const u8 {
    return ".pst";
}

pub export fn get_extension7() [*:0]const u8 {
    return ".wallet";
}

pub export fn get_extension8() [*:0]const u8 {
    return ".dat";
}

pub export fn get_extension9() [*:0]const u8 {
    return ".db";
}

pub export fn get_extension10() [*:0]const u8 {
    return ".sqlite";
}

pub export fn get_dropped_file1() [*:0]const u8 {
    return "svchost.exe";
}

pub export fn get_dropped_file2() [*:0]const u8 {
    return "csrss.exe";
}

pub export fn get_dropped_file3() [*:0]const u8 {
    return "lsass.exe";
}

pub export fn get_dropped_file4() [*:0]const u8 {
    return "winlogon.exe";
}

pub export fn get_dropped_file5() [*:0]const u8 {
    return "explorer.exe";
}

pub export fn get_dropped_file6() [*:0]const u8 {
    return "rundll32.exe";
}

pub export fn get_dropped_file7() [*:0]const u8 {
    return "system.dll";
}

pub export fn get_dropped_file8() [*:0]const u8 {
    return "kernel32.dll";
}

fn file_operations_module() void {
    use_string("C:\\Windows\\System32\\config\\SAM");
    use_string("C:\\Windows\\System32\\config\\SYSTEM");
    use_string("/etc/passwd");
    use_string("/etc/shadow");
    use_string("~/.ssh/id_rsa");
    use_string("C:\\Users\\%USERNAME%\\Documents");
    use_string("%TEMP%\\payload.dll");
    use_string("/tmp/.hidden_payload");
    use_string(".doc");
    use_string(".docx");
    use_string(".xls");
    use_string(".xlsx");
    use_string(".pdf");
    use_string(".pst");
    use_string(".wallet");
    use_string(".dat");
    use_string(".db");
    use_string(".sqlite");
    use_string("svchost.exe");
    use_string("csrss.exe");
    use_string("lsass.exe");
    use_string("winlogon.exe");
    use_string("explorer.exe");
    use_string("rundll32.exe");
    use_string("system.dll");
    use_string("kernel32.dll");
}

// ============================================================================
// CRYPTO STRINGS - Algorithms, Key Names, Crypto-related
// ============================================================================

pub export fn get_crypto_algo1() [*:0]const u8 {
    return "AES-256-CBC";
}

pub export fn get_crypto_algo2() [*:0]const u8 {
    return "AES-128-GCM";
}

pub export fn get_crypto_algo3() [*:0]const u8 {
    return "RSA-2048";
}

pub export fn get_crypto_algo4() [*:0]const u8 {
    return "RSA-4096";
}

pub export fn get_crypto_algo5() [*:0]const u8 {
    return "ChaCha20-Poly1305";
}

pub export fn get_crypto_algo6() [*:0]const u8 {
    return "SHA256";
}

pub export fn get_crypto_algo7() [*:0]const u8 {
    return "SHA512";
}

pub export fn get_crypto_algo8() [*:0]const u8 {
    return "MD5";
}

pub export fn get_crypto_algo9() [*:0]const u8 {
    return "HMAC-SHA256";
}

pub export fn get_crypto_algo10() [*:0]const u8 {
    return "PBKDF2";
}

pub export fn get_crypto_key1() [*:0]const u8 {
    return "master_key";
}

pub export fn get_crypto_key2() [*:0]const u8 {
    return "session_key";
}

pub export fn get_crypto_key3() [*:0]const u8 {
    return "encryption_key";
}

pub export fn get_crypto_key4() [*:0]const u8 {
    return "private_key";
}

pub export fn get_crypto_key5() [*:0]const u8 {
    return "public_key";
}

pub export fn get_crypto_key6() [*:0]const u8 {
    return "api_secret";
}

pub export fn get_crypto_key7() [*:0]const u8 {
    return "jwt_secret";
}

pub export fn get_crypto_key8() [*:0]const u8 {
    return "aes_iv";
}

pub export fn get_crypto_str1() [*:0]const u8 {
    return "-----BEGIN RSA PRIVATE KEY-----";
}

pub export fn get_crypto_str2() [*:0]const u8 {
    return "-----BEGIN CERTIFICATE-----";
}

pub export fn get_crypto_str3() [*:0]const u8 {
    return "ENCRYPTED";
}

pub export fn get_crypto_str4() [*:0]const u8 {
    return "DECRYPT_KEY";
}

pub export fn get_crypto_str5() [*:0]const u8 {
    return "base64";
}

pub export fn get_crypto_str6() [*:0]const u8 {
    return "CryptoAPI";
}

pub export fn get_crypto_str7() [*:0]const u8 {
    return "BCrypt";
}

pub export fn get_crypto_str8() [*:0]const u8 {
    return "OpenSSL";
}

fn crypto_module_init() void {
    use_string("AES-256-CBC");
    use_string("AES-128-GCM");
    use_string("RSA-2048");
    use_string("RSA-4096");
    use_string("ChaCha20-Poly1305");
    use_string("SHA256");
    use_string("SHA512");
    use_string("MD5");
    use_string("HMAC-SHA256");
    use_string("PBKDF2");
    use_string("master_key");
    use_string("session_key");
    use_string("encryption_key");
    use_string("private_key");
    use_string("public_key");
    use_string("api_secret");
    use_string("jwt_secret");
    use_string("aes_iv");
    use_string("-----BEGIN RSA PRIVATE KEY-----");
    use_string("-----BEGIN CERTIFICATE-----");
    use_string("ENCRYPTED");
    use_string("DECRYPT_KEY");
    use_string("base64");
    use_string("CryptoAPI");
    use_string("BCrypt");
    use_string("OpenSSL");
}

// ============================================================================
// COMMAND STRINGS - Shell Commands, PowerShell, CMD patterns
// ============================================================================

pub export fn get_shell_cmd1() [*:0]const u8 {
    return "cmd.exe /c";
}

pub export fn get_shell_cmd2() [*:0]const u8 {
    return "powershell.exe -ExecutionPolicy Bypass";
}

pub export fn get_shell_cmd3() [*:0]const u8 {
    return "powershell -enc";
}

pub export fn get_shell_cmd4() [*:0]const u8 {
    return "/bin/sh -c";
}

pub export fn get_shell_cmd5() [*:0]const u8 {
    return "/bin/bash";
}

pub export fn get_shell_cmd6() [*:0]const u8 {
    return "wmic process call create";
}

pub export fn get_shell_cmd7() [*:0]const u8 {
    return "net user";
}

pub export fn get_shell_cmd8() [*:0]const u8 {
    return "netstat -an";
}

pub export fn get_shell_cmd9() [*:0]const u8 {
    return "tasklist /v";
}

pub export fn get_shell_cmd10() [*:0]const u8 {
    return "whoami /all";
}

pub export fn get_powershell1() [*:0]const u8 {
    return "Invoke-Expression";
}

pub export fn get_powershell2() [*:0]const u8 {
    return "Invoke-WebRequest";
}

pub export fn get_powershell3() [*:0]const u8 {
    return "DownloadString";
}

pub export fn get_powershell4() [*:0]const u8 {
    return "IEX";
}

pub export fn get_powershell5() [*:0]const u8 {
    return "New-Object Net.WebClient";
}

pub export fn get_powershell6() [*:0]const u8 {
    return "-WindowStyle Hidden";
}

pub export fn get_powershell7() [*:0]const u8 {
    return "Set-MpPreference -DisableRealtimeMonitoring";
}

fn command_execution_module() void {
    use_string("cmd.exe /c");
    use_string("powershell.exe -ExecutionPolicy Bypass");
    use_string("powershell -enc");
    use_string("/bin/sh -c");
    use_string("/bin/bash");
    use_string("wmic process call create");
    use_string("net user");
    use_string("netstat -an");
    use_string("tasklist /v");
    use_string("whoami /all");
    use_string("Invoke-Expression");
    use_string("Invoke-WebRequest");
    use_string("DownloadString");
    use_string("IEX");
    use_string("New-Object Net.WebClient");
    use_string("-WindowStyle Hidden");
    use_string("Set-MpPreference -DisableRealtimeMonitoring");
}

// ============================================================================
// CONFIGURATION HANDLING
// ============================================================================

pub export fn get_config_key1() [*:0]const u8 {
    return "beacon_interval";
}

pub export fn get_config_key2() [*:0]const u8 {
    return "c2_server";
}

pub export fn get_config_key3() [*:0]const u8 {
    return "encryption_enabled";
}

pub export fn get_config_key4() [*:0]const u8 {
    return "persistence_method";
}

pub export fn get_config_key5() [*:0]const u8 {
    return "exfil_path";
}

pub export fn get_config_key6() [*:0]const u8 {
    return "kill_date";
}

pub export fn get_config_key7() [*:0]const u8 {
    return "target_processes";
}

pub export fn get_config_key8() [*:0]const u8 {
    return "debug_mode";
}

pub export fn get_config_path1() [*:0]const u8 {
    return "%APPDATA%\\config.dat";
}

pub export fn get_config_path2() [*:0]const u8 {
    return "/tmp/.config";
}

pub export fn get_config_path3() [*:0]const u8 {
    return "C:\\ProgramData\\settings.ini";
}

pub export fn get_config_path4() [*:0]const u8 {
    return "~/.local/share/app/config.json";
}

fn config_handler() void {
    use_string("beacon_interval");
    use_string("c2_server");
    use_string("encryption_enabled");
    use_string("persistence_method");
    use_string("exfil_path");
    use_string("kill_date");
    use_string("target_processes");
    use_string("debug_mode");
    use_string("%APPDATA%\\config.dat");
    use_string("/tmp/.config");
    use_string("C:\\ProgramData\\settings.ini");
    use_string("~/.local/share/app/config.json");
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

pub fn main() u8 {
    // Anti-debug checks first
    if (perform_antidebug_checks()) {
        return 1;
    }

    // Load configuration
    config_handler();

    // Initialize crypto
    crypto_module_init();

    // Set up network
    init_network_module();

    // Install persistence
    install_persistence();

    // File operations
    file_operations_module();

    // Command execution
    command_execution_module();

    return @as(u8, @intCast(sink & 0xFF));
}
