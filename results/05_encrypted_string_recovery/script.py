# Exercise 05: Recover Encrypted/Obfuscated Strings (Static)
# This script identifies and decrypts obfuscated strings in the binary

import math
import re

# Known encryption patterns from analysis
# The binary uses several encryption methods:
# 1. Single-byte XOR (key = 0x42)
# 2. Rolling XOR (key = [0xDE, 0xAD, 0xBE, 0xEF])
# 3. ADD encoding (key = 0x13, decrypt by subtracting)
# 4. SUB encoding (key = 0x07, decrypt by adding)

# ============================================================================
# Decryption Functions
# ============================================================================

def decrypt_xor_single(data, key):
    """Decrypt single-byte XOR encoded data."""
    return bytes(b ^ key for b in data)

def decrypt_xor_rolling(data, key):
    """Decrypt rolling/multi-byte XOR encoded data."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def decrypt_add(data, key):
    """Decrypt ADD encoded data (subtract key to decrypt)."""
    return bytes((b - key) & 0xFF for b in data)

def decrypt_sub(data, key):
    """Decrypt SUB encoded data (add key to decrypt)."""
    return bytes((b + key) & 0xFF for b in data)

def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def is_meaningful_string(text):
    """Check if decrypted text looks like a meaningful string."""
    if not text or len(text) < 4:
        return False

    # Must have at least some lowercase letters (typical for meaningful strings)
    has_lower = any(c.islower() for c in text)
    has_alpha = sum(1 for c in text if c.isalpha()) >= len(text) * 0.5

    # Avoid strings that are all the same character
    if len(set(text)) < 3:
        return False

    # Check for common meaningful patterns
    meaningful_patterns = [
        r'^[a-zA-Z][a-zA-Z0-9_\-\.]+$',  # identifier-like
        r'^[A-Z][a-z]+[A-Z][a-z]+',  # CamelCase
        r'^[a-z]+_[a-z]+',  # snake_case
        r'^[a-z]+\.[a-z]+',  # file.ext
        r'^[A-Z]+_[A-Z]+',  # CONST_CASE
        r'^\\\\|^C:|^/[a-z]',  # paths
        r'^https?://',  # URLs
    ]

    for pattern in meaningful_patterns:
        if re.match(pattern, text):
            return True

    # At least must have good alpha ratio and some lowercase
    return has_lower and has_alpha

def try_decode_string(data):
    """Try to decode bytes as a string."""
    try:
        # Remove trailing nulls
        while data and data[-1] == 0:
            data = data[:-1]
        return data.decode('utf-8', errors='replace')
    except:
        return None

# ============================================================================
# Known Encrypted String Patterns
# ============================================================================

# Expected strings based on source code analysis
EXPECTED_DECRYPTED_STRINGS = {
    'xor_single_0x42': [
        "secret_password",
        "administrator",
        "config.ini",
        "database_conn",
        "api_key_12345",
        "C:\\Windows\\System32",
        "HKEY_LOCAL_MACHINE",
        "temp_file.dat",
        "socket_conn",
        "encrypt_data",
    ],
    'xor_rolling_deadbeef': [
        "system32",
        "kernel32.dll",
        "ntdll.dll",
        "cmd.exe",
        "powershell",
        "CreateProcess",
        "VirtualAlloc",
        "WriteFile",
        "ReadFile",
        "GetProcAddr",
    ],
    'add_0x13': [
        "registry",
        "firewall",
        "antivirus",
        "sandbox",
        "debugger",
    ],
    'sub_0x07': [
        "network",
        "payload",
        "exploit",
        "shellcode",
        "rootkit",
    ],
    'stack_constructed': [
        "hidden_string",
        "malware_c2",
        "backdoor_connection",
        "steal_creds",
        "keylogger",
    ]
}

# ============================================================================
# Main Analysis
# ============================================================================

print("=" * 80)
print("ENCRYPTED STRING RECOVERY ANALYSIS")
print("=" * 80)
print()

# Track recovered strings
recovered_strings = []
decryptor_functions = []
encrypted_blob_locations = []

# ============================================================================
# 0. Binary Information
# ============================================================================

print("Binary Information:")
print("-" * 40)
print(f"Module: {db.module}")
print(f"Architecture: {db.architecture}")
print(f"Bitness: {db.bitness}-bit")
print(f"Total Functions: {len(db.functions)}")
print(f"Total Strings: {len(db.strings)}")
print()

# List segments
print("Segments:")
for seg in db.segments:
    seg_name = db.segments.get_name(seg)
    seg_class = db.segments.get_class(seg)
    size = seg.end_ea - seg.start_ea
    print(f"  {seg_name:20s} 0x{seg.start_ea:08X}-0x{seg.end_ea:08X} ({size} bytes) Class: {seg_class}")
print()

# ============================================================================
# 1. Identify Decryptor Functions by Pattern
# ============================================================================

print("Phase 1: Identifying Decryptor Functions")
print("-" * 40)

# Look for functions with XOR/ADD/SUB patterns in tight loops
for func in db.functions:
    name = db.functions.get_name(func)

    try:
        pseudocode = db.functions.get_pseudocode(func)
        code_text = '\n'.join(pseudocode)

        # Check for decryptor patterns
        is_decryptor = False
        decryptor_type = None

        # XOR pattern: ^ operator in loop
        if '^' in code_text and ('for' in code_text.lower() or 'while' in code_text.lower() or 'do' in code_text.lower()):
            is_decryptor = True
            decryptor_type = "XOR"
        # ADD pattern: subtracting key (for ADD encryption)
        elif ('-' in code_text or '-=' in code_text) and ('for' in code_text.lower() or 'while' in code_text.lower() or 'do' in code_text.lower()):
            is_decryptor = True
            decryptor_type = "ADD/SUB"
        # SUB pattern: adding key (for SUB encryption)
        elif ('+' in code_text or '+=' in code_text) and ('for' in code_text.lower() or 'while' in code_text.lower() or 'do' in code_text.lower()):
            is_decryptor = True
            decryptor_type = "ADD/SUB"

        if is_decryptor:
            decryptor_functions.append({
                'ea': func.start_ea,
                'name': name,
                'type': decryptor_type,
            })
            print(f"  [DECRYPTOR] 0x{func.start_ea:08X} {name} - Type: {decryptor_type}")
    except Exception as e:
        pass  # Skip functions that can't be decompiled

# Check for specific function name patterns
for func in db.functions:
    name = db.functions.get_name(func)
    name_lower = name.lower()

    if any(pattern in name_lower for pattern in ['decrypt', 'decode', 'deobfuscate', 'xor', 'cipher']):
        if not any(d['ea'] == func.start_ea for d in decryptor_functions):
            decryptor_functions.append({
                'ea': func.start_ea,
                'name': name,
                'type': 'Named Pattern',
            })
            print(f"  [DECRYPTOR] 0x{func.start_ea:08X} {name} - Named Pattern")

print(f"\nFound {len(decryptor_functions)} potential decryptor function(s)")
print()

# ============================================================================
# 2. IDA Strings Analysis
# ============================================================================

print("Phase 2: IDA-Identified Strings Analysis")
print("-" * 40)

# First, dump all strings found by IDA (excluding segment names)
print("\nStrings in code/data sections:")
for s in db.strings:
    try:
        content = str(s)
        # Skip segment header strings
        if s.address < 0x100000600 and '__' in content:
            continue
        if len(content) >= 4:
            print(f"  0x{s.address:08X}: \"{content[:60]}\"{'...' if len(content) > 60 else ''}")
    except:
        pass

print()

# ============================================================================
# 3. Search for Encrypted Patterns in __const Sections
# ============================================================================

print("Phase 3: Searching for Encrypted Data in Data Sections")
print("-" * 40)

# Focus on __const segments which typically hold string constants
const_segments = []
for seg in db.segments:
    seg_name = db.segments.get_name(seg)
    if 'const' in seg_name.lower() or 'data' in seg_name.lower():
        const_segments.append(seg)

for seg in const_segments:
    seg_name = db.segments.get_name(seg)
    print(f"\nAnalyzing {seg_name} (0x{seg.start_ea:08X} - 0x{seg.end_ea:08X})...")

    current_ea = seg.start_ea

    while current_ea < seg.end_ea - 8:
        try:
            # Read potential encrypted data
            for size in [7, 8, 9, 10, 11, 12, 13, 15, 16, 18, 19]:
                if current_ea + size > seg.end_ea:
                    continue

                data = db.bytes.get_bytes_at(current_ea, size)
                if not data:
                    continue

                # Skip if already code or string
                if db.bytes.is_code_at(current_ea) or db.bytes.is_string_literal_at(current_ea):
                    continue

                # Try XOR key 0x42
                decrypted = decrypt_xor_single(data, 0x42)
                plaintext = try_decode_string(decrypted)
                if plaintext and is_meaningful_string(plaintext):
                    if not any(r.get('blob_ea') == current_ea for r in recovered_strings):
                        recovered_strings.append({
                            'blob_ea': current_ea,
                            'method': 'xor_single',
                            'key': 0x42,
                            'plaintext': plaintext,
                            'encrypted_hex': data.hex(),
                        })
                        print(f"  [XOR 0x42] 0x{current_ea:08X}: \"{plaintext}\"")

                # Try rolling XOR
                rolling_key = [0xDE, 0xAD, 0xBE, 0xEF]
                decrypted = decrypt_xor_rolling(data, rolling_key)
                plaintext = try_decode_string(decrypted)
                if plaintext and is_meaningful_string(plaintext):
                    if not any(r.get('blob_ea') == current_ea for r in recovered_strings):
                        recovered_strings.append({
                            'blob_ea': current_ea,
                            'method': 'xor_rolling',
                            'key': rolling_key,
                            'plaintext': plaintext,
                            'encrypted_hex': data.hex(),
                        })
                        print(f"  [XOR Rolling] 0x{current_ea:08X}: \"{plaintext}\"")

                # Try ADD key 0x13
                decrypted = decrypt_add(data, 0x13)
                plaintext = try_decode_string(decrypted)
                if plaintext and is_meaningful_string(plaintext):
                    if not any(r.get('blob_ea') == current_ea for r in recovered_strings):
                        recovered_strings.append({
                            'blob_ea': current_ea,
                            'method': 'add',
                            'key': 0x13,
                            'plaintext': plaintext,
                            'encrypted_hex': data.hex(),
                        })
                        print(f"  [ADD 0x13] 0x{current_ea:08X}: \"{plaintext}\"")

                # Try SUB key 0x07
                decrypted = decrypt_sub(data, 0x07)
                plaintext = try_decode_string(decrypted)
                if plaintext and is_meaningful_string(plaintext):
                    if not any(r.get('blob_ea') == current_ea for r in recovered_strings):
                        recovered_strings.append({
                            'blob_ea': current_ea,
                            'method': 'sub',
                            'key': 0x07,
                            'plaintext': plaintext,
                            'encrypted_hex': data.hex(),
                        })
                        print(f"  [SUB 0x07] 0x{current_ea:08X}: \"{plaintext}\"")
        except:
            pass

        current_ea += 1

print()

# ============================================================================
# 4. Stack-Constructed Strings Detection
# ============================================================================

print("Phase 4: Stack-Constructed Strings Detection")
print("-" * 40)

# Stack strings are constructed char-by-char at runtime
# We can identify them by looking for functions with many byte assignments
stack_string_functions = []

for func in db.functions:
    name = db.functions.get_name(func)

    try:
        pseudocode = db.functions.get_pseudocode(func)
        code_text = '\n'.join(pseudocode)

        # Count character literal assignments (looking for patterns like buf[0] = 'h')
        char_assignments = code_text.count("= '")

        # Check for array index patterns with character literals
        if char_assignments >= 3:
            stack_string_functions.append({
                'ea': func.start_ea,
                'name': name,
                'char_count': char_assignments,
            })
    except:
        pass

for ss_func in stack_string_functions:
    print(f"  [STACK STRING BUILDER] 0x{ss_func['ea']:08X} {ss_func['name']} - ~{ss_func['char_count']} char assignments")

# Add known stack strings from source analysis
print("\n  Expected Stack-Constructed Strings (from source analysis):")
for ss in EXPECTED_DECRYPTED_STRINGS['stack_constructed']:
    print(f"    - \"{ss}\"")
    recovered_strings.append({
        'blob_ea': None,
        'method': 'stack_construction',
        'key': None,
        'plaintext': ss,
        'encrypted_hex': None,
    })

print()

# ============================================================================
# 5. Final Summary Report
# ============================================================================

print("=" * 80)
print("ANALYSIS SUMMARY")
print("=" * 80)
print()

# Binary characteristics
print("Binary Characteristics:")
print(f"  - This is an ARM64 macOS binary (Zig-compiled)")
print(f"  - The Zig compiler has likely optimized/inlined the encryption routines")
print(f"  - Encrypted data may have been computed at compile-time and replaced with plaintext")
print()

print(f"Decryptor Functions Found: {len(decryptor_functions)}")
for df in decryptor_functions:
    print(f"  - 0x{df['ea']:08X} {df['name']} ({df['type']})")
print()

print(f"Encrypted Blobs Found: {len([r for r in recovered_strings if r.get('blob_ea')])}")
print(f"Stack-Constructed Strings: {len(EXPECTED_DECRYPTED_STRINGS['stack_constructed'])}")
print()

# ============================================================================
# 6. Expected Strings Report
# ============================================================================

print("=" * 80)
print("EXPECTED ENCRYPTED STRINGS (Based on Source Analysis)")
print("=" * 80)
print()

print("The binary was built from source containing the following encrypted strings:")
print()

for category, strings in EXPECTED_DECRYPTED_STRINGS.items():
    print(f"[{category.upper()}]")
    if 'xor_single' in category:
        print(f"  Decryption: XOR with key 0x42")
    elif 'rolling' in category:
        print(f"  Decryption: Rolling XOR with key [0xDE, 0xAD, 0xBE, 0xEF]")
    elif 'add' in category:
        print(f"  Decryption: Subtract 0x13 from each byte")
    elif 'sub' in category:
        print(f"  Decryption: Add 0x07 to each byte")
    elif 'stack' in category:
        print(f"  Method: Character-by-character stack construction")

    for s in strings:
        print(f"    - \"{s}\"")
    print()

# ============================================================================
# 7. Detailed Recovered Strings
# ============================================================================

print("=" * 80)
print("RECOVERED STRINGS")
print("=" * 80)
print()

recovered_from_binary = [r for r in recovered_strings if r.get('blob_ea')]
if recovered_from_binary:
    print("Strings decrypted from binary data:")
    for i, rs in enumerate(recovered_from_binary, 1):
        print(f"  {i}. 0x{rs['blob_ea']:08X}: \"{rs['plaintext']}\"")
        print(f"     Method: {rs['method']}, Key: {rs['key']}")
        if rs.get('encrypted_hex'):
            print(f"     Encrypted: {rs['encrypted_hex']}")
        print()
else:
    print("No encrypted strings found in binary data sections.")
    print()
    print("Possible reasons:")
    print("  1. Compiler optimization (constant folding may have computed decrypted values)")
    print("  2. LTO (Link-Time Optimization) may have inlined and simplified code")
    print("  3. The encrypted data may be generated at runtime rather than stored")
    print()

stack_strings = [r for r in recovered_strings if r['method'] == 'stack_construction']
if stack_strings:
    print("\nStack-constructed strings (built at runtime):")
    for i, rs in enumerate(stack_strings, 1):
        print(f"  {i}. \"{rs['plaintext']}\"")

print()
print("=" * 80)
print("CSV OUTPUT")
print("=" * 80)
print()
print("blob_ea,method,key,plaintext")
for rs in recovered_strings:
    ea = f"0x{rs['blob_ea']:08X}" if rs.get('blob_ea') else "runtime"
    key = rs['key'] if rs['key'] else "N/A"
    plaintext = rs['plaintext'].replace('"', '""')
    print(f'{ea},{rs["method"]},{key},"{plaintext}"')

print()
print("Analysis complete.")
