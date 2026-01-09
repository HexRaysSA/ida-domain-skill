# IDA Domain Skill

A Claude Code skill for writing and executing Python scripts using the IDA Domain API. Analyze binaries, extract functions, strings, cross-references, decompile code, and automate reverse engineering tasks with IDA Pro.

## Requirements

- [uv](https://docs.astral.sh/uv/) package manager
- IDA Pro 9.1 or later
- `IDADIR` environment variable pointing to your IDA installation

## Installation

Clone this repository or add it as a Claude Code plugin:

```bash
git clone https://github.com/HexRaysSA/ida-domain-skill.git
```

## Setup

Before first use, run the setup script to install dependencies and validate your environment:

```bash
cd skills/ida-domain-scripting && uv run python setup.py
```

The setup script will:
1. Verify uv is installed
2. Install Python dependencies (ida-domain)
3. Check that IDADIR is set correctly
4. Validate IDA Domain can load

### Setting IDADIR

Set the `IDADIR` environment variable to your IDA installation directory:

```bash
# macOS
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"

# Linux
export IDADIR="/opt/idapro-9.1"

# Windows
set IDADIR=C:\Program Files\IDA Professional 9.1
```

## Usage

Write scripts to `/tmp/` and execute them with the runner:

```bash
# Analyze a binary
cd skills/ida-domain-scripting
uv run python run.py /tmp/script.py -f /path/to/binary

# Inline code execution
uv run python run.py -c "print(get_db_summary(db))" -f /path/to/binary

# Open an existing IDA database
uv run python run.py /tmp/script.py -f /path/to/file.i64
```

### Example Script

```python
# List all functions with their addresses
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{name}: {hex(func.start_ea)}")

# Find interesting strings
interesting = find_interesting_strings(db)
for string_item, keyword in interesting:
    print(f"[{keyword}] {string_item}")
```

See [SKILL.md](skills/ida-domain-scripting/SKILL.md) for complete documentation and API reference.

## License

MIT License - Copyright (c) 2026 Hex-Rays SA

## Author

[Hex-Rays SA](https://hex-rays.com)

## Links

- [IDA Domain Repository](https://github.com/HexRaysSA/ida-domain)
- [IDA Domain Documentation](https://ida-domain.docs.hex-rays.com/)
- [IDA Pro](https://hex-rays.com/ida-pro/)
