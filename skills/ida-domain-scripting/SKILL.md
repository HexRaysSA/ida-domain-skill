---
name: ida-domain-scripting
description: Write and execute Python scripts using the IDA Domain API for reverse engineering. Analyze binaries, extract functions, strings, cross-references, decompile code, work with IDA Pro databases (.i64/.idb). Use when user wants to analyze binaries, reverse engineer executables, or automate IDA Pro tasks.
---

**IMPORTANT - Path Resolution:**
This skill can be installed in different locations. Before executing any commands, determine the skill directory based on where you loaded this SKILL.md file, and use that path in all commands below. Replace `$SKILL_DIR` with the actual discovered path.

Common installation paths:
- Project-specific: `<project>/.claude/skills/ida-domain-scripting`
- Manual global: `~/.claude/skills/ida-domain-scripting`

# IDA Domain Scripting

General-purpose binary analysis skill. I'll write custom IDAPython code for any reverse engineering task you request and execute it via the universal executor.

**CRITICAL WORKFLOW - Follow these steps in order:**

1. **Check API_REFERENCE.md exists** - Always check that $SKILL_DIR/API_REFERENCE.md exists. Inform the user to run 
   the bootstrap if not. 

2. **Write scripts to /tmp** - NEVER write scripts to skill directory; always use `/tmp/ida-domain-*.py`

3. **Execute from skill directory** - Always run: `cd $SKILL_DIR && uv run python run.py /tmp/script.py -f <binary>`

4. **Ask before saving** - Scripts that modify the database require explicit user confirmation before using `--save`

## How It Works

1. You describe what you want to analyze/extract
2. I write custom IDA Domain API code in `/tmp/ida-domain-*.py` (won't clutter your project)
3. I execute it via: `cd $SKILL_DIR && uv run python run.py /tmp/script.py -f <binary>`
4. Results displayed in real-time
5. Script files auto-cleaned from /tmp by your OS

## Setup (First Time)

```bash
cd $SKILL_DIR && uv run python setup.py
```

This clones ida-domain from GitHub and installs dependencies. Only needed once.

**Using a specific version:**
```bash
uv run python setup.py --ref v0.1.0   # Specific release
uv run python setup.py --ref main     # Bleeding edge
```

Requirements:
- uv package manager
- git
- IDA Pro 9.1+
- IDADIR environment variable pointing to IDA installation

## Execution Pattern

**Step 1: Write analysis script to /tmp**

```python
# /tmp/ida-domain-analysis.py
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{name}: 0x{func.start_ea:08X}")
```

**Step 2: Execute from skill directory**

```bash
cd $SKILL_DIR && uv run python run.py /tmp/ida-domain-analysis.py -f /path/to/binary
```

**Step 3: Review results**

Scripts are auto-wrapped with `Database.open()` boilerplate. The `db` variable is available for accessing all entities.

## Common Patterns

### List All Functions

```python
# /tmp/ida-domain-list-functions.py
for func in db.functions:
    name = db.functions.get_name(func)
    size = func.end_ea - func.start_ea
    print(f"{name}: 0x{func.start_ea:08X} - 0x{func.end_ea:08X} ({size} bytes)")
```

### Find Function by Name

```python
# /tmp/ida-domain-find-function.py
func = db.functions.get_function_by_name("main")
if func:
    print(f"Found main at 0x{func.start_ea:08X}")

    # Get callers
    callers = db.functions.get_callers(func)
    print(f"Called by {len(callers)} functions:")
    for caller in callers:
        print(f"  - {db.functions.get_name(caller)}")
else:
    print("main not found")
```

### Search Strings

```python
# /tmp/ida-domain-search-strings.py
import re

# Find all strings
for s in db.strings:
    print(f"0x{s.address:08X}: {s}")

# Find URLs
url_pattern = re.compile(r"https?://[\w./]+", re.IGNORECASE)
for s in db.strings:
    try:
        content = str(s)
        if url_pattern.search(content):
            print(f"URL found: {content}")
    except:
        pass
```

### Analyze Cross-References

```python
# /tmp/ida-domain-xrefs.py
# Get xrefs TO an address
target = 0x00401000
print(f"References TO 0x{target:08X}:")
for xref in db.xrefs.to_ea(target):
    print(f"  From 0x{xref.from_ea:08X} (type: {xref.type.name})")

# Get xrefs FROM an address
print(f"References FROM 0x{target:08X}:")
for xref in db.xrefs.from_ea(target):
    print(f"  To 0x{xref.to_ea:08X} (type: {xref.type.name})")
```

### Decompile Function

```python
# /tmp/ida-domain-decompile.py
func = db.functions.get_function_by_name("main")
if func:
    try:
        lines = db.functions.get_pseudocode(func)
        print("\n".join(lines))
    except RuntimeError as e:
        print(f"Decompilation failed: {e}")
```

### Analyze Function Complexity

```python
# /tmp/ida-domain-complexity.py
complex_funcs = []
for func in db.functions:
    flowchart = db.functions.get_flowchart(func)
    if flowchart:
        block_count = len(flowchart)
        edge_count = sum(b.count_successors() for b in flowchart)
        cyclomatic = edge_count - block_count + 2

        if cyclomatic > 10:
            name = db.functions.get_name(func)
            complex_funcs.append((name, func.start_ea, cyclomatic))

complex_funcs.sort(key=lambda x: x[2], reverse=True)
print("Most complex functions:")
for name, addr, cc in complex_funcs[:10]:
    print(f"  {name}: complexity={cc} at 0x{addr:08X}")
```

### Search Byte Patterns

```python
# /tmp/ida-domain-patterns.py
# Search for NOP sled
pattern = b"\x90\x90\x90\x90"
results = db.bytes.find_binary_sequence(pattern)
for addr in results:
    print(f"Found NOP sled at 0x{addr:08X}")

# Search for x64 function prologue
prologue = b"\x55\x48\x89\xE5"  # push rbp; mov rbp, rsp
for addr in db.bytes.find_binary_sequence(prologue):
    print(f"Prologue at 0x{addr:08X}")
```

### Export to JSON

```python
# /tmp/ida-domain-export.py
import json
from pathlib import Path

functions = []
for func in db.functions:
    name = db.functions.get_name(func)
    functions.append({
        "name": name,
        "start": f"0x{func.start_ea:08X}",
        "end": f"0x{func.end_ea:08X}",
        "size": func.end_ea - func.start_ea,
    })

output = {"module": db.module, "functions": functions}
Path("/tmp/functions.json").write_text(json.dumps(output, indent=2))
print(f"Exported {len(functions)} functions to /tmp/functions.json")
```

## Inline Execution (Simple Tasks)

For quick one-off tasks, you can execute code inline without creating files:

```bash
# Quick function count
cd $SKILL_DIR && uv run python run.py -c "print(f'Functions: {len(db.functions)}')" -f binary

# Get binary info
cd $SKILL_DIR && uv run python run.py -c "print(f'{db.module}: {db.architecture} {db.bitness}-bit')" -f binary
```

**When to use inline vs files:**
- **Inline**: Quick one-off tasks (count functions, get binary info, check if symbol exists)
- **Files**: Complex analysis, multi-step tasks, anything user might want to re-run

## Advanced Usage

For comprehensive IDA Domain API documentation, see [API_REFERENCE.md](API_REFERENCE.md):

- Database properties and metadata
- Function enumeration and analysis
- String detection and searching
- Cross-reference queries
- Byte pattern matching
- Control flow analysis
- Decompilation (Hex-Rays)
- Type information
- Comments and names

## Tips

- **Use /tmp for scripts** - Write to `/tmp/ida-domain-*.py`, never to skill directory or user's project
- **Default is read-only** - Use `--save` only when modifications should persist (and ask user first!)
- **Timeout** - Default 30 minutes; use `--timeout 0` for long-running analysis
- **No-wrap mode** - Use `--no-wrap` when your script already has `Database.open()`
- **Error handling** - Always use try-except for decompilation and string operations
- **Check for None** - Functions like `get_function_by_name()` return None if not found

## Troubleshooting

**When encountering errors:**
Check the ida-domain source code first by searching for the method signature in `$SKILL_DIR/ida-domain/ida_domain/`. The API may differ from what's documented or expected.

**Virtual environment not found:**
```bash
cd $SKILL_DIR && uv run python setup.py
```

**IDA SDK fails to load / IDADIR error:**
```bash
export IDADIR=/path/to/ida
```

**Script timeout:**
```bash
cd $SKILL_DIR && uv run python run.py --timeout 3600 ...  # 1 hour
cd $SKILL_DIR && uv run python run.py --timeout 0 ...     # No timeout
```

**AttributeError: 'Xrefs' has no attribute 'get_xrefs_to':**
Use `db.xrefs.to_ea(addr)` not `db.xrefs.get_xrefs_to(addr)`

**AttributeError on func_t object:**
Call methods on `db.functions`, not on the func object:
```python
# Wrong: func.get_callers()
# Right: db.functions.get_callers(func)
```

**UnicodeDecodeError when reading strings:**
```python
for s in db.strings:
    try:
        content = str(s)
    except:
        continue  # Skip problematic strings
```

## Example Usage

```
User: "How many functions are in this binary?"

Claude: I'll count the functions. Let me analyze the binary...
[Writes: /tmp/ida-domain-count.py]
[Runs: cd $SKILL_DIR && uv run python run.py /tmp/ida-domain-count.py -f binary]
[Output: Functions: 250]

The binary contains 250 functions.
```

```
User: "Find all functions that call malloc"

Claude: I'll find all callers of malloc...
[Writes: /tmp/ida-domain-malloc-callers.py]
[Runs: cd $SKILL_DIR && uv run python run.py /tmp/ida-domain-malloc-callers.py -f binary]
[Output: malloc called by 15 functions: sub_401000, sub_402000, ...]

Found 15 functions that call malloc:
- sub_401000 at 0x00401000
- sub_402000 at 0x00402000
...
```

```
User: "Decompile the main function and save it"

Claude: I'll decompile main and save the output...
[Writes: /tmp/ida-domain-decompile-main.py]
[Runs: cd $SKILL_DIR && uv run python run.py /tmp/ida-domain-decompile-main.py -f binary]
[Output: Saved to /tmp/main.c]

Done! The decompiled code is saved to /tmp/main.c
```

## Notes

- Each analysis script is custom-written for your specific request
- Not limited to pre-built scripts - any IDA analysis task possible
- Scripts written to `/tmp` for automatic cleanup (no clutter)
- Code executes reliably with proper module resolution via `run.py`
- Database opened read-only by default to prevent accidental modifications
