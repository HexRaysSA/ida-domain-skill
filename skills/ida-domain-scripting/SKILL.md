---
name: ida-domain-scripting
description: Write and execute Python scripts using the IDA Domain API for reverse engineering. Analyze binaries, extract functions, strings, cross-references, decompile code, work with IDA Pro databases (.i64/.idb). Use when user wants to analyze binaries, reverse engineer executables, or automate IDA Pro tasks.
---

# IDA Domain Scripting

Write and execute Python scripts using the IDA Domain API for
reverse engineering analysis of binaries and IDA databases.

## Setup (Required First)

Run setup before first use:
```bash
cd $SKILL_DIR && uv run python setup.py
```

Requirements:
- uv package manager
- IDA Pro 9.1+
- IDADIR environment variable pointing to IDA installation

## Critical Workflow

1. Always write scripts to `/tmp/ida-domain-*.py`
2. Execute via: `cd $SKILL_DIR && uv run python run.py /tmp/script.py -f <binary>`
3. For modifications: **ASK USER** before generating scripts with `--save`

## Input Modes

| Mode | Command |
|------|---------|
| File | `uv run python run.py /tmp/script.py -f binary.exe` |
| Inline | `uv run python run.py -c "code" -f binary.exe` |
| Stdin | `cat script.py \| uv run python run.py -f binary.exe` |

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `-f, --file` | Target binary or .i64 file (required) |
| `-c, --code` | Inline code string |
| `-s, --save` | Enable `save_on_close=True` (default: False) |
| `--no-wrap` | Skip auto-wrapping (for complete scripts) |
| `--timeout` | Execution timeout in seconds (default: 1800, 0 for no timeout) |

## Script Conventions

- Scripts are auto-wrapped with `Database.open()` boilerplate
- Use `db` variable to access all entities:
  - `db.functions` - Function analysis (iterate, search, decompile)
  - `db.strings` - String detection and enumeration
  - `db.xrefs` - Cross-references (to/from addresses)
  - `db.bytes` - Raw byte access and pattern search
  - `db.segments` - Memory segments
  - `db.types` - Type information
  - `db.names` - Symbol names
  - `db.comments` - Code comments
  - `db.instructions` - Instruction decoding
  - `db.heads` - Instruction/data heads
  - `db.entries` - Entry points
- Database metadata: `db.module`, `db.path`, `db.architecture`, `db.bitness`, `db.format`, `db.md5`, `db.sha256`
- Use `--no-wrap` for complete standalone scripts

## Modification Warning

Scripts that rename, comment, patch, or modify the database require
explicit user confirmation. Always ask:

> "This script will modify the database. Should I include `--save` to persist changes?"

## Common Patterns

### List all functions
```python
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{name}: {hex(func.start_ea)} - {hex(func.end_ea)}")
```

### Find functions by name pattern
```python
matches = find_functions_by_pattern(db, r".*crypt.*")
for func, name in matches:
    print(f"{name} at {format_address(func.start_ea)}")
```

### Get database summary
```python
summary = get_db_summary(db)
print(f"Binary: {summary['module']}")
print(f"Architecture: {summary['architecture']} {summary['bitness']}-bit")
print(f"Functions: {summary['function_count']}")
print(f"Strings: {summary['string_count']}")
```

### Find interesting strings
```python
interesting = find_interesting_strings(db)
for string_item, keyword in interesting:
    print(f"[{keyword}] {format_address(string_item.address)}: {string_item}")
```

### Search strings with regex
```python
# Find URLs
urls = search_strings(db, r"https?://[\w./]+")
for s in urls:
    print(f"{format_address(s.address)}: {s}")

# Find IP addresses
ips = search_strings(db, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
```

### Get function callers
```python
func = db.functions.get_function_by_name("malloc")
if func:
    callers = get_function_callers(db, func)
    print(f"malloc called by {len(callers)} functions:")
    for caller in callers:
        print(f"  - {db.functions.get_name(caller)}")
```

### Get function callees
```python
func = db.functions.get_function_by_name("main")
if func:
    callees = get_function_callees(db, func)
    for callee in callees:
        print(f"main calls: {db.functions.get_name(callee)}")
```

### Decompile a function
```python
func = db.functions.get_function_by_name("main")
if func:
    pseudocode = decompile_function(db, func)
    if pseudocode:
        print(pseudocode)
```

### Analyze function complexity
```python
for func in db.functions:
    name = db.functions.get_name(func)
    metrics = get_function_complexity(db, func)
    if metrics['cyclomatic_complexity'] > 10:
        print(f"{name}: complexity={metrics['cyclomatic_complexity']}, "
              f"blocks={metrics['basic_block_count']}")
```

### Find byte patterns
```python
# Search for NOP sled
nops = find_pattern(db, b"\x90\x90\x90\x90\x90")

# Search using hex string
pattern_addrs = find_pattern(db, "48 89 E5")  # mov rbp, rsp
for addr in pattern_addrs:
    print(f"Found at {format_address(addr)}")
```

### Detect crypto constants
```python
crypto = find_crypto_constants(db)
for name, addresses in crypto.items():
    print(f"{name} found at {[format_address(a) for a in addresses]}")
```

### Find undiscovered functions
```python
prologues = find_function_prologues(db)
known_funcs = {func.start_ea for func in db.functions}
undiscovered = [p for p in prologues if p not in known_funcs]
print(f"Found {len(undiscovered)} potential undiscovered functions")
```

### Get cross-references to a string
```python
for string_item in db.strings:
    xrefs = get_string_xrefs(db, string_item.address)
    if len(xrefs) > 5:
        print(f"'{string_item}' referenced {len(xrefs)} times")
```

### Generate summary report
```python
report = generate_summary_report(db)
print(report)
# Or save to file:
from pathlib import Path
Path("/tmp/report.md").write_text(report)
```

### Export data to JSON
```python
count = export_functions_json(db, "/tmp/functions.json")
print(f"Exported {count} functions")

count = export_strings_json(db, "/tmp/strings.json")
print(f"Exported {count} strings")
```

### Print formatted table
```python
headers = ["Name", "Address", "Size"]
rows = []
for func in list(db.functions)[:10]:
    name = db.functions.get_name(func)
    rows.append([name, format_address(func.start_ea), func.end_ea - func.start_ea])
print_table(headers, rows)
```

## Helper Functions Reference

All helpers are automatically available in wrapped scripts via `from helpers import *`.

### Database Helpers
- `quick_open(path, save=False, auto_analysis=True)` - Simplified database opening
- `get_db_summary(db)` - Returns dict with file info and statistics

### Function Analysis
- `find_functions_by_pattern(db, pattern, case_sensitive=False)` - Regex match on function names
- `get_function_callers(db, func)` - Get functions that call this function
- `get_function_callees(db, func)` - Get functions called by this function
- `decompile_function(db, func)` - Get pseudocode as string (requires Hex-Rays)
- `get_function_complexity(db, func)` - Returns dict with block count, edges, cyclomatic complexity

### String Analysis
- `find_interesting_strings(db, keywords=None)` - Find passwords, URLs, paths, etc.
- `get_string_xrefs(db, string_addr)` - Get cross-references to a string
- `search_strings(db, pattern, case_sensitive=False)` - Regex search in strings

### Byte Patterns
- `find_pattern(db, pattern, start_ea=None, end_ea=None)` - Find byte pattern (hex string or bytes)
- `find_crypto_constants(db)` - Detect AES, SHA256, MD5, RSA, RC4, DES, Blowfish constants
- `find_function_prologues(db, architecture=None)` - Find function entry patterns

### Output Formatting
- `format_function(db, func)` - Pretty string like "main @ 0x00401000 - 0x00401100 (256 bytes)"
- `format_xref(xref)` - Format like "0x00401000 -> 0x00402000 (CALL_NEAR)"
- `format_address(ea)` - Format address like "0x00401000"
- `print_table(headers, rows)` - Print aligned ASCII table

### Report Generation
- `generate_summary_report(db)` - Generate Markdown analysis report
- `export_functions_json(db, path)` - Export functions to JSON file
- `export_strings_json(db, path)` - Export strings to JSON file

## API Reference

For complete IDA Domain API documentation, see [API_REFERENCE.md](API_REFERENCE.md).

Key classes and their methods:
- `Database` - Main entry point for all operations
- `Functions` - Function enumeration, creation, analysis
- `Strings` - String detection and access
- `Xrefs` - Cross-reference queries
- `Bytes` - Raw byte access and binary search
- `Segments` - Memory segment information
- `Types` - Type library access
- `Names` - Symbol name management
- `Comments` - Comment access and modification

## Tips

- Always run setup first if you get import errors
- Use `--no-wrap` when your script already has `Database.open()`
- Default is read-only; use `--save` only when modifications should persist
- Check `IDADIR` environment variable if IDA SDK fails to load
- Use `--timeout 0` for long-running analysis scripts
- Scripts are auto-cleaned from `/tmp` after 1 hour
