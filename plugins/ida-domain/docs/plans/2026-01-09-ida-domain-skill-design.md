# IDA Domain Skill Design

> Design document for creating a Claude Code skill for writing and executing Python scripts using the IDA Domain API.

**Date:** 2026-01-09
**Status:** Draft
**Inspired by:** [playwright-skill](https://github.com/lackeyjb/playwright-skill)

## Overview

This skill enables Claude to write and execute Python scripts that use the IDA Domain API for reverse engineering analysis. Scripts are generated in `/tmp` and executed against user-provided binaries or IDA databases (.i64/.idb files).

The skill follows the same architecture patterns as the Playwright skill:
- Setup script to validate environment
- Universal runner script supporting multiple input modes
- Helper utilities for common patterns
- Progressive disclosure with separate API reference

## Project Structure

```
ida-domain-skill/
├── .claude-plugin/
│   └── plugin.json              # Plugin metadata for marketplace
├── skills/
│   └── ida-domain-scripting/
│       ├── SKILL.md             # Main instructions Claude reads
│       ├── API_REFERENCE.md     # Full IDA Domain docs (llms-full.txt)
│       ├── pyproject.toml       # Dependencies (ida-domain)
│       ├── run.py               # Universal script executor
│       ├── setup.py             # Setup/validation script
│       └── lib/
│           └── helpers.py       # Reusable utility functions
├── LICENSE                      # MIT (matching ida-domain)
├── README.md                    # Installation & usage
└── .gitignore
```

## Setup Flow

The setup script (`setup.py`) performs these steps in order:

```
┌─────────────────────────────────────────────────────────────┐
│  1. CHECK UV                                                │
│     - Run `uv --version`                                    │
│     - If missing: print install instructions, exit 1        │
│       "Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  2. UV SYNC                                                 │
│     - Run `uv sync` in skill directory                      │
│     - Creates .venv/, installs ida-domain                   │
│     - If fails: print error, exit 1                         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  3. CHECK IDADIR                                            │
│     - Verify IDADIR environment variable is set             │
│     - Verify path exists and contains IDA                   │
│     - If missing: print setup instructions, exit 1          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  4. VALIDATION TEST                                         │
│     - Run minimal script: import ida_domain, print version  │
│     - Confirms IDA Domain can load IDA SDK                  │
│     - If fails: print diagnostic info, exit 1               │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  ✓ SUCCESS                                                  │
│     - Print "Setup complete! Ready to use."                 │
│     - exit 0                                                │
└─────────────────────────────────────────────────────────────┘
```

Invoked via: `uv run python setup.py`

## Runner Script (`run.py`)

The runner handles three input modes and wraps user code with necessary boilerplate.

### Input Modes

```bash
# 1. File
uv run python run.py /tmp/analyze.py -f /path/to/binary.exe

# 2. Inline code
uv run python run.py -c "for f in db.functions: print(f.name)" -f binary.exe

# 3. Stdin
cat /tmp/analyze.py | uv run python run.py -f binary.exe
```

### Runner Responsibilities

1. **Parse arguments** - Detect input mode, extract target file (`-f`), options
2. **Check setup** - Verify venv exists, prompt to run setup if needed
3. **Wrap user code** - Inject imports and `Database.open()` boilerplate:
   ```python
   # Auto-injected wrapper
   from ida_domain import Database
   from ida_domain.database import IdaCommandOptions
   from lib.helpers import *

   with Database.open(TARGET_FILE, IdaCommandOptions(auto_analysis=True), save_on_close=SAVE_FLAG) as db:
       # --- User code inserted here ---
   ```
4. **Execute** - Run wrapped code, capture output/errors
5. **Cleanup** - Remove temp files older than 1 hour

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `-f, --file` | Target binary or .i64 (required) |
| `-c, --code` | Inline code string |
| `-s, --save` | Enable `save_on_close=True` (default: False) |
| `--no-wrap` | Skip auto-wrapping (for complete scripts) |

## Helper Utilities (`lib/helpers.py`)

Six categories of reusable functions:

### 1. Database Helpers

```python
def quick_open(path, save=False, auto_analysis=True)  # Simplified Database.open()
def get_db_summary(db)                                 # Returns dict with stats
```

### 2. Function Analysis

```python
def find_functions_by_pattern(db, pattern)            # Regex match on names
def get_function_callers(db, func)                    # Who calls this function
def get_function_callees(db, func)                    # What does this function call
def decompile_function(db, func)                      # Get pseudocode as string
def get_function_complexity(db, func)                 # Basic block count, cyclomatic
```

### 3. String Analysis

```python
def find_interesting_strings(db, keywords=None)       # Passwords, URLs, paths, etc.
def get_string_xrefs(db, string_addr)                 # Who references this string
def search_strings(db, pattern)                       # Regex search in strings
```

### 4. Byte Patterns

```python
def find_pattern(db, pattern)                         # Hex pattern search
def find_crypto_constants(db)                         # Known crypto magic bytes
def find_function_prologues(db)                       # Architecture-aware
```

### 5. Output Formatting

```python
def format_function(func)                             # Pretty string representation
def format_xref(xref)                                 # "0x1234 -> 0x5678 (CALL)"
def format_address(ea)                                # "0x00401000"
def print_table(headers, rows)                        # Aligned columns
```

### 6. Report Generation

```python
def generate_summary_report(db)                       # Markdown overview
def export_functions_json(db, path)                   # JSON export
def export_strings_json(db, path)                     # JSON export
```

## SKILL.md Structure

```yaml
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

## Script Conventions

- Scripts are auto-wrapped with `Database.open()` boilerplate
- Use `db` variable to access all entities:
  - `db.functions` - Function analysis
  - `db.strings` - String detection
  - `db.xrefs` - Cross-references
  - `db.bytes` - Raw byte access
  - `db.segments` - Memory segments
  - `db.types` - Type information
  - `db.names` - Symbol names
  - `db.comments` - Code comments
- Use `--no-wrap` for complete standalone scripts

## Modification Warning

Scripts that rename, comment, patch, or modify the database require
explicit user confirmation. Always ask:

> "This script will modify the database. Should I include `--save` to persist changes?"

## Common Patterns

### List all functions
```python
for func in db.functions:
    print(f"{func.name}: {hex(func.start_ea)}")
```

### Find functions by name pattern
```python
for func in find_functions_by_pattern(db, r".*crypt.*"):
    print(func.name)
```

### Analyze strings
```python
for s in find_interesting_strings(db):
    print(f"{hex(s.address)}: {s}")
```

### Get function callers
```python
func = db.functions.get_by_name("main")
for caller in get_function_callers(db, func):
    print(f"Called from: {caller.name}")
```

### Decompile a function
```python
func = db.functions.get_by_name("main")
pseudocode = decompile_function(db, func)
print(pseudocode)
```

## Helper Functions

See `lib/helpers.py` for available utilities:
- Database helpers: `quick_open()`, `get_db_summary()`
- Function analysis: `find_functions_by_pattern()`, `get_function_callers()`, etc.
- String analysis: `find_interesting_strings()`, `search_strings()`
- Byte patterns: `find_pattern()`, `find_crypto_constants()`
- Output formatting: `format_function()`, `print_table()`
- Report generation: `generate_summary_report()`, `export_functions_json()`

## API Reference

For complete IDA Domain API documentation, see [API_REFERENCE.md](API_REFERENCE.md).

## Tips

- Always run setup first if you get import errors
- Use `--no-wrap` when your script already has `Database.open()`
- Default is read-only; use `--save` only when modifications should persist
- Check `IDADIR` environment variable if IDA SDK fails to load
```

## Plugin Metadata (`plugin.json`)

```json
{
  "name": "ida-domain-scripting",
  "displayName": "IDA Domain Scripting",
  "description": "Write and execute Python scripts using the IDA Domain API for reverse engineering",
  "version": "1.0.0",
  "author": "Hex-Rays SA",
  "homepage": "https://github.com/HexRaysSA/ida-domain-skill",
  "license": "MIT",
  "skills": ["skills/ida-domain-scripting"],
  "setup": {
    "command": "cd skills/ida-domain-scripting && uv run python setup.py",
    "description": "Installs dependencies and validates IDA configuration"
  },
  "keywords": [
    "ida-pro",
    "reverse-engineering",
    "binary-analysis",
    "ida-domain",
    "hex-rays"
  ]
}
```

## API Reference

The `API_REFERENCE.md` file contains the complete IDA Domain documentation from `https://ida-domain.docs.hex-rays.com/llms-full.txt`.

This provides comprehensive coverage of:
- Database management
- Function analysis
- Instruction decoding
- Byte manipulation
- String detection
- Type system
- Cross-references
- Hooks/events
- All examples from official docs

## Design Decisions

### Why uv?

- Fast, modern Python package manager
- Reliable virtual environment management
- Single tool for both venv creation and package installation
- Growing adoption in Python ecosystem

### Why scripts in /tmp?

- Follows Playwright skill pattern
- Avoids cluttering project directories
- Auto-cleanup of old scripts
- Clear separation of generated vs. source code

### Why auto-wrapping?

- Reduces boilerplate for simple scripts
- Consistent `db` variable access
- Automatic cleanup via context manager
- Can be disabled with `--no-wrap` for complex scripts

### Why ask before saving?

- IDA databases are valuable analysis artifacts
- Accidental modifications can be hard to undo
- Explicit confirmation prevents surprises
- Read-only default is safest

## Implementation Plan

1. Create project structure
2. Implement `setup.py` with all validation steps
3. Implement `run.py` with three input modes
4. Create `lib/helpers.py` with utility functions
5. Write `SKILL.md` with instructions
6. Copy IDA Domain docs to `API_REFERENCE.md`
7. Create `plugin.json` metadata
8. Write `pyproject.toml` with dependencies
9. Add `README.md` and `LICENSE`
10. Test end-to-end with sample binary

## References

- [Playwright Skill](https://github.com/lackeyjb/playwright-skill) - Inspiration and patterns
- [IDA Domain API](https://github.com/HexRaysSA/ida-domain) - Target API
- [IDA Domain Docs](https://ida-domain.docs.hex-rays.com/) - Official documentation
- [Claude Code Skills](https://code.claude.com/docs/en/skills.md) - Skill specification
