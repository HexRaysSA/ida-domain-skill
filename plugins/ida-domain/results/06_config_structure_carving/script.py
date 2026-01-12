# Exercise 06: Configuration Structure Carving
# Find embedded configuration blob and parse its structure
# Updated with correct offsets based on binary analysis

import math
from collections import OrderedDict

def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence"""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy

def format_ipv4(data):
    """Format 4 bytes as IPv4 address"""
    return f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"

print("=" * 70)
print("Configuration Structure Carving Analysis")
print("=" * 70)

# Step 1: Find the config blob
print("\n[1] Searching for configuration blob...")

config_addr = None

# Search for "CFG\x00" magic using find_binary_sequence
magic_pattern = b"CFG\x00"
found_addrs = db.bytes.find_binary_sequence(magic_pattern)

if found_addrs:
    print(f"    Found 'CFG' magic at {len(found_addrs)} location(s):")
    for addr in found_addrs:
        print(f"    - 0x{addr:08X}")
    config_addr = found_addrs[0]
else:
    print("    ERROR: Could not locate configuration blob")
    exit(1)

print(f"\n    Config blob identified at: 0x{config_addr:08X}")

# Step 2: Read configuration data
print("\n[2] Reading configuration data...")

config_data = db.bytes.get_bytes_at(config_addr, 700)

if not config_data:
    print("    ERROR: Could not read config data")
    exit(1)

# Parse header
magic = config_data[0:4]
print(f"    Magic: {magic}")

# Correct offsets based on actual binary analysis:
# The structure appears to be packed with the following layout:
# 0x00: magic[4]
# 0x04: version_major (u16)
# 0x06: version_minor (u16)
# 0x08: config_size (u32)
# 0x0C: feature_flags (u32)
# 0x10: primary_server.ip_addr[4]
# 0x14: primary_server.port (u16)
# 0x16: primary_server.timeout_ms (u32)
# 0x1A: primary_server.retry_count (u8)
# 0x1B: primary_server.flags (u8)
# 0x1C: primary_server._padding[2]
# 0x1E: backup_server.ip_addr[4]
# 0x22: backup_server.port (u16)
# 0x24: backup_server.timeout_ms (u32)
# 0x28: backup_server.retry_count (u8)
# 0x29: backup_server.flags (u8)
# 0x2A: backup_server._padding[2]
# 0x2C: callback_url[128] - confirmed by string at offset 0x2C
# 0xAC: update_url[128]
# 0x12C: install_path[64]
# 0x16C: log_path[64]
# 0x1AC: credentials.username[32]
# 0x1CC: credentials.password_hash[32]
# 0x1EC: credentials.api_key[64]
# 0x22C: credentials.token_expiry (u64)
# 0x234: beacon_interval_sec (u32)
# 0x238: jitter_percent (u16)
# 0x23A: sleep_on_error_sec (u16)
# 0x23C: ip_whitelist[8][4] = 32 bytes
# 0x25C: encryption_key[64]
# 0x29C: config_checksum (u32)
# 0x2A0: _end_padding[4]

# Define offsets based on hex dump analysis
OFFSET_VERSION_MAJOR = 0x04
OFFSET_VERSION_MINOR = 0x06
OFFSET_CONFIG_SIZE = 0x08
OFFSET_FEATURE_FLAGS = 0x0C
OFFSET_PRIMARY_SERVER = 0x10
OFFSET_BACKUP_SERVER = 0x1E
OFFSET_CALLBACK_URL = 0x2C  # Confirmed: "https://api.example-c2.net..." at offset 44
OFFSET_UPDATE_URL = 0xAC    # Confirmed: "https://updates.example-c2.net..." at offset 172
OFFSET_INSTALL_PATH = 0x12C  # Confirmed: "/var/lib/.hidden/agent" at offset 300
OFFSET_LOG_PATH = 0x16C      # Confirmed: "/tmp/.cache/agent.log" at offset 364
OFFSET_CREDENTIALS = 0x1AC  # Confirmed: "agent_service_user" at offset 428
OFFSET_PASSWORD_HASH = 0x1CC  # 0x1AC + 32
OFFSET_API_KEY = 0x1EC      # Confirmed: "sk-live-..." at offset 492
OFFSET_TOKEN_EXPIRY = 0x22C  # 0x1EC + 64
OFFSET_BEACON_INTERVAL = 0x234  # 0x22C + 8
OFFSET_JITTER_PERCENT = 0x238
OFFSET_SLEEP_ON_ERROR = 0x23A
OFFSET_IP_WHITELIST = 0x23C
OFFSET_ENCRYPTION_KEY = 0x25C
OFFSET_CONFIG_CHECKSUM = 0x29C
OFFSET_END_PADDING = 0x2A0

def read_u16(data, offset):
    return int.from_bytes(data[offset:offset+2], 'little')

def read_u32(data, offset):
    return int.from_bytes(data[offset:offset+4], 'little')

def read_u64(data, offset):
    return int.from_bytes(data[offset:offset+8], 'little')

def read_string(data, offset, max_len):
    end = offset
    while end < offset + max_len and end < len(data) and data[end] != 0:
        end += 1
    return data[offset:end].decode('ascii', errors='replace')

# Step 3: Parse all fields
print("\n[3] Parsing configuration fields...")

config_fields = OrderedDict()

# Header fields
version_major = read_u16(config_data, OFFSET_VERSION_MAJOR)
version_minor = read_u16(config_data, OFFSET_VERSION_MINOR)
config_size = read_u32(config_data, OFFSET_CONFIG_SIZE)
feature_flags = read_u32(config_data, OFFSET_FEATURE_FLAGS)

config_fields['magic'] = ('char[4]', 0, magic.decode('ascii', errors='replace').rstrip('\x00'))
config_fields['version_major'] = ('uint16_t', OFFSET_VERSION_MAJOR, version_major)
config_fields['version_minor'] = ('uint16_t', OFFSET_VERSION_MINOR, version_minor)
config_fields['config_size'] = ('uint32_t', OFFSET_CONFIG_SIZE, config_size)
config_fields['feature_flags'] = ('uint32_t', OFFSET_FEATURE_FLAGS, f"0x{feature_flags:08X}")

print(f"    Version: {version_major}.{version_minor}")
print(f"    Config size: {config_size} bytes")
print(f"    Feature flags: 0x{feature_flags:08X}")

# Primary server endpoint
primary_ip = config_data[OFFSET_PRIMARY_SERVER:OFFSET_PRIMARY_SERVER+4]
primary_port = read_u16(config_data, OFFSET_PRIMARY_SERVER+4)
primary_timeout = read_u32(config_data, OFFSET_PRIMARY_SERVER+6)
primary_retry = config_data[OFFSET_PRIMARY_SERVER+10]
primary_flags = config_data[OFFSET_PRIMARY_SERVER+11]

config_fields['primary_server.ip_addr'] = ('uint8_t[4]', OFFSET_PRIMARY_SERVER, format_ipv4(primary_ip))
config_fields['primary_server.port'] = ('uint16_t', OFFSET_PRIMARY_SERVER+4, primary_port)
config_fields['primary_server.timeout_ms'] = ('uint32_t', OFFSET_PRIMARY_SERVER+6, primary_timeout)
config_fields['primary_server.retry_count'] = ('uint8_t', OFFSET_PRIMARY_SERVER+10, primary_retry)
config_fields['primary_server.flags'] = ('uint8_t', OFFSET_PRIMARY_SERVER+11, f"0x{primary_flags:02X}")

print(f"\n    Primary Server:")
print(f"      IP: {format_ipv4(primary_ip)}")
print(f"      Port: {primary_port}")
print(f"      Timeout: {primary_timeout}ms")
print(f"      Retry count: {primary_retry}")
print(f"      Flags: 0x{primary_flags:02X}")

# Backup server endpoint
backup_ip = config_data[OFFSET_BACKUP_SERVER:OFFSET_BACKUP_SERVER+4]
backup_port = read_u16(config_data, OFFSET_BACKUP_SERVER+4)
backup_timeout = read_u32(config_data, OFFSET_BACKUP_SERVER+6)
backup_retry = config_data[OFFSET_BACKUP_SERVER+10]
backup_flags = config_data[OFFSET_BACKUP_SERVER+11]

config_fields['backup_server.ip_addr'] = ('uint8_t[4]', OFFSET_BACKUP_SERVER, format_ipv4(backup_ip))
config_fields['backup_server.port'] = ('uint16_t', OFFSET_BACKUP_SERVER+4, backup_port)
config_fields['backup_server.timeout_ms'] = ('uint32_t', OFFSET_BACKUP_SERVER+6, backup_timeout)
config_fields['backup_server.retry_count'] = ('uint8_t', OFFSET_BACKUP_SERVER+10, backup_retry)
config_fields['backup_server.flags'] = ('uint8_t', OFFSET_BACKUP_SERVER+11, f"0x{backup_flags:02X}")

print(f"\n    Backup Server:")
print(f"      IP: {format_ipv4(backup_ip)}")
print(f"      Port: {backup_port}")
print(f"      Timeout: {backup_timeout}ms")
print(f"      Retry count: {backup_retry}")
print(f"      Flags: 0x{backup_flags:02X}")

# URLs
callback_url = read_string(config_data, OFFSET_CALLBACK_URL, 128)
update_url = read_string(config_data, OFFSET_UPDATE_URL, 128)

config_fields['callback_url'] = ('char[128]', OFFSET_CALLBACK_URL, callback_url)
config_fields['update_url'] = ('char[128]', OFFSET_UPDATE_URL, update_url)

print(f"\n    URLs:")
print(f"      Callback: {callback_url}")
print(f"      Update: {update_url}")

# Paths
install_path = read_string(config_data, OFFSET_INSTALL_PATH, 64)
log_path = read_string(config_data, OFFSET_LOG_PATH, 64)

config_fields['install_path'] = ('char[64]', OFFSET_INSTALL_PATH, install_path)
config_fields['log_path'] = ('char[64]', OFFSET_LOG_PATH, log_path)

print(f"\n    Paths:")
print(f"      Install: {install_path}")
print(f"      Log: {log_path}")

# Credentials
username = read_string(config_data, OFFSET_CREDENTIALS, 32)
password_hash = config_data[OFFSET_PASSWORD_HASH:OFFSET_PASSWORD_HASH+32]
api_key = read_string(config_data, OFFSET_API_KEY, 64)
token_expiry = read_u64(config_data, OFFSET_TOKEN_EXPIRY)

config_fields['credentials.username'] = ('char[32]', OFFSET_CREDENTIALS, username)
config_fields['credentials.password_hash'] = ('uint8_t[32]', OFFSET_PASSWORD_HASH, password_hash.hex()[:32] + "...")
config_fields['credentials.api_key'] = ('char[64]', OFFSET_API_KEY, api_key)
config_fields['credentials.token_expiry'] = ('uint64_t', OFFSET_TOKEN_EXPIRY, token_expiry)

print(f"\n    Credentials:")
print(f"      Username: {username}")
print(f"      Password hash: {password_hash.hex()[:32]}...")
print(f"      API key: {api_key}")
print(f"      Token expiry: {token_expiry} (Unix timestamp)")

# Timing configuration
beacon_interval = read_u32(config_data, OFFSET_BEACON_INTERVAL)
jitter_percent = read_u16(config_data, OFFSET_JITTER_PERCENT)
sleep_on_error = read_u16(config_data, OFFSET_SLEEP_ON_ERROR)

config_fields['beacon_interval_sec'] = ('uint32_t', OFFSET_BEACON_INTERVAL, beacon_interval)
config_fields['jitter_percent'] = ('uint16_t', OFFSET_JITTER_PERCENT, jitter_percent)
config_fields['sleep_on_error_sec'] = ('uint16_t', OFFSET_SLEEP_ON_ERROR, sleep_on_error)

print(f"\n    Timing:")
print(f"      Beacon interval: {beacon_interval} seconds ({beacon_interval/60:.1f} minutes)")
print(f"      Jitter: {jitter_percent}%")
print(f"      Sleep on error: {sleep_on_error} seconds")

# IP whitelist
print(f"\n    IP Whitelist:")
ip_whitelist = []
for i in range(8):
    offset = OFFSET_IP_WHITELIST + i * 4
    ip_bytes = config_data[offset:offset+4]
    ip_str = format_ipv4(ip_bytes)
    ip_whitelist.append(ip_str)
    if ip_bytes != b'\x00\x00\x00\x00':
        print(f"      [{i}]: {ip_str}")

config_fields['ip_whitelist'] = ('uint8_t[8][4]', OFFSET_IP_WHITELIST, ip_whitelist)

# Encryption key (high-entropy region)
encryption_key = config_data[OFFSET_ENCRYPTION_KEY:OFFSET_ENCRYPTION_KEY+64]
key_entropy = calculate_entropy(encryption_key)

config_fields['encryption_key'] = ('uint8_t[64]', OFFSET_ENCRYPTION_KEY, f"[{key_entropy:.2f} bits entropy]")

print(f"\n    Encryption Key:")
print(f"      First 16 bytes: {encryption_key[:16].hex()}")
print(f"      Entropy: {key_entropy:.2f} bits (high entropy indicates encrypted/random data)")

# Checksum
config_checksum = read_u32(config_data, OFFSET_CONFIG_CHECKSUM)
end_padding = config_data[OFFSET_END_PADDING:OFFSET_END_PADDING+4]

config_fields['config_checksum'] = ('uint32_t', OFFSET_CONFIG_CHECKSUM, f"0x{config_checksum:08X}")
config_fields['_end_padding'] = ('uint8_t[4]', OFFSET_END_PADDING, end_padding.hex())

print(f"\n    Checksum: 0x{config_checksum:08X}")
print(f"    End padding: 0x{end_padding.hex()}")

# Step 4: Generate IDA struct definition
print("\n[4] Generating IDA struct definition...")

struct_def = f"""
// Auto-generated configuration structure from binary analysis
// Base address: 0x{config_addr:08X}

typedef struct {{
    uint8_t ip_addr[4];        // IPv4 address
    uint16_t port;             // Port number
    uint32_t timeout_ms;       // Connection timeout (ms)
    uint8_t retry_count;       // Max retries
    uint8_t flags;             // Connection flags
    uint8_t _padding[2];       // Alignment padding
}} ServerEndpoint;             // size: 14 bytes

typedef struct {{
    char username[32];         // Null-terminated username
    uint8_t password_hash[32]; // SHA-256 hash
    char api_key[64];          // API key string
    uint64_t token_expiry;     // Unix timestamp
}} CredentialBlock;            // size: 136 bytes

typedef struct {{
    char magic[4];             // "CFG\\0" - offset 0x{0:03X}
    uint16_t version_major;    // offset 0x{OFFSET_VERSION_MAJOR:03X}
    uint16_t version_minor;    // offset 0x{OFFSET_VERSION_MINOR:03X}
    uint32_t config_size;      // Total size - offset 0x{OFFSET_CONFIG_SIZE:03X}
    uint32_t feature_flags;    // Feature bits - offset 0x{OFFSET_FEATURE_FLAGS:03X}
    ServerEndpoint primary_server;  // offset 0x{OFFSET_PRIMARY_SERVER:03X}
    ServerEndpoint backup_server;   // offset 0x{OFFSET_BACKUP_SERVER:03X}
    char callback_url[128];    // C2 callback URL - offset 0x{OFFSET_CALLBACK_URL:03X}
    char update_url[128];      // Update URL - offset 0x{OFFSET_UPDATE_URL:03X}
    char install_path[64];     // Installation path - offset 0x{OFFSET_INSTALL_PATH:03X}
    char log_path[64];         // Log file path - offset 0x{OFFSET_LOG_PATH:03X}
    CredentialBlock credentials;    // offset 0x{OFFSET_CREDENTIALS:03X}
    uint32_t beacon_interval_sec;   // Beacon timing - offset 0x{OFFSET_BEACON_INTERVAL:03X}
    uint16_t jitter_percent;   // Timing jitter - offset 0x{OFFSET_JITTER_PERCENT:03X}
    uint16_t sleep_on_error_sec;    // Error sleep - offset 0x{OFFSET_SLEEP_ON_ERROR:03X}
    uint8_t ip_whitelist[8][4];     // 8 IPv4 addresses - offset 0x{OFFSET_IP_WHITELIST:03X}
    uint8_t encryption_key[64];     // High-entropy key - offset 0x{OFFSET_ENCRYPTION_KEY:03X}
    uint32_t config_checksum;  // CRC/checksum - offset 0x{OFFSET_CONFIG_CHECKSUM:03X}
    uint8_t _end_padding[4];   // End marker - offset 0x{OFFSET_END_PADDING:03X}
}} ConfigBlob;                 // Total size: {config_size} bytes
"""

print(struct_def)

# Step 5: Summary report
print("\n" + "=" * 70)
print("Configuration Structure Carving Summary")
print("=" * 70)

print(f"""
CONFIG BLOB LOCATION: 0x{config_addr:08X}
CONFIG SIZE: {config_size} bytes

DECODED VALUES:
---------------
Version: {version_major}.{version_minor}
Feature Flags: 0x{feature_flags:08X}

Primary C2 Server:
  Address: {format_ipv4(primary_ip)}:{primary_port}
  Timeout: {primary_timeout}ms
  Retries: {primary_retry}

Backup C2 Server:
  Address: {format_ipv4(backup_ip)}:{backup_port}
  Timeout: {backup_timeout}ms
  Retries: {backup_retry}

URLs:
  Callback: {callback_url}
  Update: {update_url}

Paths:
  Install: {install_path}
  Log: {log_path}

Credentials:
  Username: {username}
  API Key: {api_key}
  Token Expiry: {token_expiry}

Timing:
  Beacon: {beacon_interval}s ({beacon_interval/60:.1f} min)
  Jitter: {jitter_percent}%
  Sleep on Error: {sleep_on_error}s

IP Whitelist: {', '.join([ip for ip in ip_whitelist if ip != '0.0.0.0'])}

Encryption Key Entropy: {key_entropy:.2f} bits
Config Checksum: 0x{config_checksum:08X}
""")

# Step 6: Output field table
print("\nFIELD TABLE:")
print("-" * 70)
print(f"{'Field Name':<30} {'Type':<15} {'Offset':<8} {'Value'}")
print("-" * 70)
for field_name, (field_type, offset, value) in config_fields.items():
    val_str = str(value)
    if len(val_str) > 40:
        val_str = val_str[:37] + "..."
    print(f"{field_name:<30} {field_type:<15} 0x{offset:04X}   {val_str}")

print("=" * 70)
print("Analysis complete.")
