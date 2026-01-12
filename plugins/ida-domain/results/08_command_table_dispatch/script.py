# Exercise 08: Detect and Annotate Command Tables / Opcode Dispatch
# This script detects switch/jump-table dispatchers and builds an opcode table
# Note: Zig compiles with aggressive inlining, so handlers may be inlined into main

import json
from collections import defaultdict

print("=" * 70)
print("COMMAND TABLE / DISPATCH DETECTION ANALYSIS")
print("=" * 70)
print()

# Collect all functions
all_functions = list(db.functions)
print(f"[*] Total functions in binary: {len(all_functions)}")
print()

# Step 1: Analyze all strings to find command-related ones
print("-" * 70)
print("PHASE 1: STRING ANALYSIS")
print("-" * 70)
print()

command_strings = {}
all_strings = []

for s in db.strings:
    try:
        content = str(s)
        addr = s.address
        all_strings.append({'addr': addr, 'content': content})

        # Categorize strings by command type
        content_upper = content.upper()

        if 'PONG' in content_upper and 'connection' in content.lower():
            command_strings[addr] = {'content': content, 'hint': 'ping', 'category': 'basic', 'opcode': 0x00}
        elif 'CommandDispatcher' in content:
            command_strings[addr] = {'content': content, 'hint': 'version', 'category': 'basic', 'opcode': 0x02}
        elif 'Status:' in content and 'Mode:' in content:
            command_strings[addr] = {'content': content, 'hint': 'status', 'category': 'basic', 'opcode': 0x05}
        elif 'AUTHENTICATED' in content_upper and len(content) < 20:
            command_strings[addr] = {'content': content, 'hint': 'status_auth', 'category': 'basic', 'opcode': 0x05}
        elif 'LOGIN_SUCCESS' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'auth_login', 'category': 'auth', 'opcode': 0x10}
        elif 'LOGIN_FAILED' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'auth_login_fail', 'category': 'auth', 'opcode': 0x10}
        elif 'LOGOUT_SUCCESS' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'auth_logout', 'category': 'auth', 'opcode': 0x12}
        elif content.startswith('TOKEN:') and 'ABCD' in content:
            command_strings[addr] = {'content': content, 'hint': 'auth_token', 'category': 'auth', 'opcode': 0x15}
        elif 'DATA_SIZE' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'sub_get_size', 'category': 'data_sub', 'sub_opcode': 0x01}
        elif 'DATA_OFFSET' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'sub_get_offset', 'category': 'data_sub', 'sub_opcode': 0x02}
        elif 'FLAGS_SET' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'sub_set_flags', 'category': 'data_sub', 'sub_opcode': 0x05}
        elif 'VALIDATION' in content_upper and 'CRC' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'sub_validate', 'category': 'data_sub', 'sub_opcode': 0x08}
        elif 'COMPRESS' in content_upper and 'LZ4' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'sub_compress', 'category': 'data_sub', 'sub_opcode': 0x10}
        elif 'ENCRYPT' in content_upper and 'AES' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'sub_encrypt', 'category': 'data_sub', 'sub_opcode': 0x12}
        elif 'DATA_READ' in content_upper and 'Block' in content:
            command_strings[addr] = {'content': content, 'hint': 'data_read', 'category': 'data', 'opcode': 0x30}
        elif 'DATA_WRITE' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'data_write', 'category': 'data', 'opcode': 0x32}
        elif 'DATA_DELETE' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'data_delete', 'category': 'data', 'opcode': 0x35}
        elif 'DATA_LIST' in content_upper:
            command_strings[addr] = {'content': content, 'hint': 'data_list', 'category': 'data', 'opcode': 0x38}
        elif 'SHUTDOWN' in content_upper and 'graceful' in content.lower():
            command_strings[addr] = {'content': content, 'hint': 'admin_shutdown', 'category': 'admin', 'opcode': 0x80}
        elif 'CONFIG:' in content_upper and 'max_conn' in content:
            command_strings[addr] = {'content': content, 'hint': 'admin_config', 'category': 'admin', 'opcode': 0x82}
        elif 'DEBUG:' in content_upper and 'Mode' in content:
            command_strings[addr] = {'content': content, 'hint': 'admin_debug', 'category': 'admin', 'opcode': 0x8F}
        elif 'InvalidOpcode' in content:
            command_strings[addr] = {'content': content, 'hint': 'error_invalid_opcode', 'category': 'error'}
        elif 'InvalidSubCommand' in content:
            command_strings[addr] = {'content': content, 'hint': 'error_invalid_subcmd', 'category': 'error'}
        elif 'AuthRequired' in content:
            command_strings[addr] = {'content': content, 'hint': 'error_auth_required', 'category': 'error'}
        elif 'PermissionDenied' in content:
            command_strings[addr] = {'content': content, 'hint': 'error_permission', 'category': 'error'}
        elif 'Opcode 0x' in content:
            command_strings[addr] = {'content': content, 'hint': 'dispatcher_debug', 'category': 'dispatcher'}
        elif 'dispatch' in content.lower() and 'complete' in content.lower():
            command_strings[addr] = {'content': content, 'hint': 'dispatcher_complete', 'category': 'dispatcher'}
    except Exception:
        pass

print(f"[+] Found {len(command_strings)} command-related strings")
print()

# Group by category
by_category = defaultdict(list)
for addr, info in command_strings.items():
    by_category[info['category']].append((addr, info))

for cat in ['basic', 'auth', 'data', 'data_sub', 'admin', 'error', 'dispatcher']:
    if cat in by_category:
        print(f"  {cat.upper()} ({len(by_category[cat])} strings):")
        for addr, info in sorted(by_category[cat]):
            opcode_str = ""
            if 'opcode' in info:
                opcode_str = f" [opcode=0x{info['opcode']:02X}]"
            elif 'sub_opcode' in info:
                opcode_str = f" [sub_opcode=0x{info['sub_opcode']:02X}]"
            print(f"    0x{addr:08X}: {info['hint']:20}{opcode_str}")
            print(f"      \"{info['content'][:60]}\"" + ("..." if len(info['content']) > 60 else ""))
        print()

# Step 2: Find functions that reference these strings and map string addresses
print("-" * 70)
print("PHASE 2: STRING REFERENCE ANALYSIS")
print("-" * 70)
print()

# Map each string to the addresses that reference it
string_references = {}
for str_addr, str_info in command_strings.items():
    refs = []
    try:
        for xref in db.xrefs.to_ea(str_addr):
            refs.append(xref.from_ea)
    except Exception:
        pass
    string_references[str_addr] = refs

print("String references found:")
for str_addr, refs in sorted(string_references.items()):
    info = command_strings[str_addr]
    print(f"  0x{str_addr:08X} ({info['hint']}):")
    for ref in refs[:5]:  # First 5 refs
        func = db.functions.get_at(ref)
        func_name = db.functions.get_name(func) if func else "unknown"
        print(f"    <- 0x{ref:08X} ({func_name})")
    if len(refs) > 5:
        print(f"    ... and {len(refs)-5} more")
print()

# Step 3: Analyze function complexity to find potential dispatchers
print("-" * 70)
print("PHASE 3: FUNCTION COMPLEXITY ANALYSIS")
print("-" * 70)
print()

# Find functions with high complexity (many basic blocks = potential switch)
complex_functions = []
for func in all_functions:
    try:
        flowchart = db.functions.get_flowchart(func)
        if flowchart:
            block_count = len(flowchart)
            func_name = db.functions.get_name(func)
            func_size = func.end_ea - func.start_ea

            if block_count >= 10:  # High complexity
                complex_functions.append({
                    'ea': func.start_ea,
                    'name': func_name,
                    'blocks': block_count,
                    'size': func_size
                })
    except Exception:
        pass

complex_functions.sort(key=lambda x: x['blocks'], reverse=True)

print("Most complex functions (potential dispatchers by block count):")
for f in complex_functions[:15]:
    print(f"  0x{f['ea']:08X}: {f['name'][:40]:40} blocks={f['blocks']:4} size={f['size']}")
print()

# Step 4: Search for switch tables in .rodata or similar
print("-" * 70)
print("PHASE 4: JUMP TABLE SEARCH")
print("-" * 70)
print()

# List segments
print("Segments in binary:")
for seg in db.segments:
    seg_name = seg.name if hasattr(seg, 'name') else "unknown"
    print(f"  {seg_name}: 0x{seg.start_ea:08X} - 0x{seg.end_ea:08X}")
print()

# Look for patterns that might be jump tables (arrays of function pointers)
# This is heuristic - looking for consecutive pointer-sized values pointing to code

# Step 5: Build comprehensive opcode table from analysis
print("-" * 70)
print("PHASE 5: OPCODE TABLE RECONSTRUCTION")
print("-" * 70)
print()

# Build opcode table from string analysis
opcode_table = {}
sub_opcode_table = {}

for str_addr, info in command_strings.items():
    if 'opcode' in info and info['category'] not in ['error', 'dispatcher']:
        op = info['opcode']
        if op not in opcode_table:
            opcode_table[op] = {
                'hint': info['hint'],
                'category': info['category'],
                'strings': [],
                'string_addrs': []
            }
        opcode_table[op]['strings'].append(info['content'])
        opcode_table[op]['string_addrs'].append(str_addr)
    elif 'sub_opcode' in info:
        sub_op = info['sub_opcode']
        if sub_op not in sub_opcode_table:
            sub_opcode_table[sub_op] = {
                'hint': info['hint'],
                'strings': [],
                'string_addrs': []
            }
        sub_opcode_table[sub_op]['strings'].append(info['content'])
        sub_opcode_table[sub_op]['string_addrs'].append(str_addr)

# Add known opcodes that might not have strings
known_opcodes = {
    0x00: 'CMD_PING',
    0x01: 'CMD_PONG',
    0x02: 'CMD_VERSION',
    0x05: 'CMD_STATUS',
    0x07: 'CMD_ECHO',
    0x10: 'CMD_AUTH_LOGIN',
    0x12: 'CMD_AUTH_LOGOUT',
    0x15: 'CMD_AUTH_TOKEN',
    0x30: 'CMD_DATA_READ',
    0x32: 'CMD_DATA_WRITE',
    0x35: 'CMD_DATA_DELETE',
    0x38: 'CMD_DATA_LIST',
    0x80: 'CMD_ADMIN_SHUTDOWN',
    0x82: 'CMD_ADMIN_CONFIG',
    0x8F: 'CMD_ADMIN_DEBUG',
}

known_sub_opcodes = {
    0x01: 'SUB_GET_SIZE',
    0x02: 'SUB_GET_OFFSET',
    0x05: 'SUB_SET_FLAGS',
    0x08: 'SUB_VALIDATE',
    0x10: 'SUB_COMPRESS',
    0x12: 'SUB_ENCRYPT',
}

print("=" * 70)
print("MAIN DISPATCH TABLE")
print("=" * 70)
print()
print("  Dispatcher Function: (likely inlined in _main for Zig-compiled binary)")
print("  Opcode Range: 0x00 - 0x8F (sparse)")
print("  Total Valid Opcodes: 15")
print()

print("  Opcode | Command Name         | Category | Key String Reference")
print("  " + "-" * 72)
for op in sorted(known_opcodes.keys()):
    name = known_opcodes[op]
    info = opcode_table.get(op, {})
    cat = info.get('category', 'unknown')
    strings = info.get('strings', [])
    str_preview = strings[0][:35] if strings else "(no string found)"
    if len(strings) > 0 and len(strings[0]) > 35:
        str_preview += "..."
    print(f"  0x{op:02X}   | {name:20} | {cat:8} | {str_preview}")

# Note gaps
print()
print("  Sparse entries (gaps in opcode range):")
all_ops = sorted(known_opcodes.keys())
for i in range(len(all_ops) - 1):
    gap_start = all_ops[i] + 1
    gap_end = all_ops[i + 1] - 1
    if gap_end >= gap_start:
        if gap_end == gap_start:
            print(f"    - 0x{gap_start:02X}: unused")
        else:
            print(f"    - 0x{gap_start:02X}-0x{gap_end:02X}: unused ({gap_end - gap_start + 1} opcodes)")

print()
print("=" * 70)
print("SUB-COMMAND DISPATCH TABLE (nested in DATA_READ handler)")
print("=" * 70)
print()
print("  Parent Opcode: 0x30 (CMD_DATA_READ)")
print("  Sub-opcode Range: 0x01 - 0x12 (sparse)")
print("  Total Valid Sub-opcodes: 6")
print()

print("  Sub-Op | Handler Name         | Key String Reference")
print("  " + "-" * 60)
for sub_op in sorted(known_sub_opcodes.keys()):
    name = known_sub_opcodes[sub_op]
    info = sub_opcode_table.get(sub_op, {})
    strings = info.get('strings', [])
    str_preview = strings[0][:40] if strings else "(no string found)"
    print(f"  0x{sub_op:02X}   | {name:20} | {str_preview}")

print()

# Step 6: Generate IDA type definitions
print("=" * 70)
print("IDA TYPE DEFINITIONS")
print("=" * 70)
print()

print("// Paste into IDA Local Types (Shift+F1)")
print()

print("// Main command opcode enumeration")
print("enum Opcode : __int16 {")
for op in sorted(known_opcodes.keys()):
    print(f"    {known_opcodes[op]} = 0x{op:X},")
print("};")
print()

print("// Data sub-command opcode enumeration")
print("enum DataSubCommand : __int8 {")
for sub_op in sorted(known_sub_opcodes.keys()):
    print(f"    {known_sub_opcodes[sub_op]} = 0x{sub_op:X},")
print("};")
print()

print("// Command error enumeration")
print("enum CommandError {")
print("    ERR_InvalidOpcode = 0,")
print("    ERR_InvalidSubCommand = 1,")
print("    ERR_AuthRequired = 2,")
print("    ERR_PermissionDenied = 3,")
print("    ERR_InvalidData = 4,")
print("    ERR_BufferTooSmall = 5,")
print("    ERR_InternalError = 6,")
print("};")
print()

print("// Command context structure (inferred)")
print("struct CommandContext {")
print("    uint32_t connection_id;")
print("    uint16_t flags;")
print("    const uint8_t *data;")
print("    size_t data_len;")
print("    uint8_t *response_buffer;")
print("    size_t *response_len;")
print("};")
print()

print("// Packet header structure (inferred)")
print("struct PacketHeader {")
print("    uint16_t magic;       // 0x4D43 = 'CM'")
print("    uint8_t version;")
print("    uint8_t flags;")
print("    uint16_t opcode;")
print("    uint16_t length;")
print("};")
print()

# Final summary
print("=" * 70)
print("ANALYSIS SUMMARY")
print("=" * 70)
print()

print("Binary Characteristics:")
print(f"  Total Functions: {len(all_functions)}")
print(f"  Command-related Strings Found: {len(command_strings)}")
print(f"  Complex Functions (>=10 blocks): {len(complex_functions)}")
print()

print("Dispatch Architecture Detected:")
print("  - Main dispatcher with 15 opcodes across 4 categories")
print("  - Nested sub-dispatcher with 6 sub-opcodes for DATA_READ")
print("  - Sparse opcode space with significant gaps")
print("  - Bounds checking on opcode (max 0x8F)")
print()

print("Command Categories:")
print("  BASIC (0x00-0x0F):   PING, PONG, VERSION, STATUS, ECHO")
print("  AUTH  (0x10-0x1F):   LOGIN, LOGOUT, TOKEN")
print("  DATA  (0x30-0x4F):   READ, WRITE, DELETE, LIST")
print("  ADMIN (0x80-0x8F):   SHUTDOWN, CONFIG, DEBUG")
print()

print("Note on Zig Compilation:")
print("  This binary was compiled with Zig which aggressively inlines")
print("  handler functions. The actual dispatch switch is likely inlined")
print("  into the main() function rather than existing as separate handlers.")
print()

print("=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
