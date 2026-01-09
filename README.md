# IDA Domain Skill for Claude Code

**Reverse engineering automation as a Claude Skill**

A [Claude Skill](https://docs.claude.com/en/docs/claude-code/skills) that enables Claude to write and execute any IDA Domain script on-the-fly - from simple function listings to complex binary analysis workflows. Packaged as a [Claude Code Plugin](https://docs.claude.com/en/docs/claude-code/plugins) for easy installation and distribution.

Claude autonomously decides when to use this skill based on your reverse engineering needs, loading only the minimal information required for your specific task.

Made using Claude Code.

## Features

- **Any Analysis Task** - Claude writes custom scripts for your specific request, not limited to pre-built queries
- **Environment Validation** - Setup script verifies IDA installation, IDADIR, and dependencies
- **Version Selection** - Choose specific ida-domain releases or use bleeding edge with `--ref`
- **Progressive Disclosure** - Concise SKILL.md with full API reference loaded only when needed
- **Comprehensive Helpers** - Optional utility functions for common analysis patterns
- **Flexible Execution** - Run script files or inline code, use existing databases or analyze new binaries

## Requirements

- [uv](https://docs.astral.sh/uv/) package manager
- IDA Pro 9.1 or later
- `IDADIR` environment variable pointing to your IDA installation

## Installation

This repository is structured as a [Claude Code Plugin](https://docs.claude.com/en/docs/claude-code/plugins) containing a skill. You can install it as either a **plugin** (recommended) or extract it as a **standalone skill**.

### Understanding the Structure

This repository uses the plugin format with a nested structure:

```
ida-domain-skill/              # Plugin root
├── .claude-plugin/            # Plugin metadata
└── skills/
    └── ida-domain-scripting/  # The actual skill
        └── SKILL.md
```

Claude Code expects skills to be directly in folders under `.claude/skills/`, so manual installation requires extracting the nested skill folder.

---

### Option 1: Plugin Installation (Recommended)

Install via Claude Code's plugin system for automatic updates and team distribution:

```bash
# Add this repository as a marketplace
/plugin marketplace add HexRaysSA/ida-domain-skill

# Install the plugin
/plugin install ida-domain-skill@ida-domain-skill

# Navigate to the skill directory and run setup
cd ~/.claude/plugins/marketplaces/ida-domain-skill/skills/ida-domain-scripting
uv run python setup.py
```

Verify installation by running `/help` to confirm the skill is available.

---

### Option 2: Standalone Skill Installation

To install as a standalone skill (without the plugin system), extract only the skill folder:

**Global Installation (Available Everywhere):**

```bash
# Clone to a temporary location
git clone https://github.com/HexRaysSA/ida-domain-skill.git /tmp/ida-domain-skill-temp

# Copy only the skill folder to your global skills directory
mkdir -p ~/.claude/skills
cp -r /tmp/ida-domain-skill-temp/skills/ida-domain-scripting ~/.claude/skills/

# Navigate to the skill and run setup
cd ~/.claude/skills/ida-domain-scripting
uv run python setup.py

# Clean up temporary files
rm -rf /tmp/ida-domain-skill-temp
```

**Project-Specific Installation:**

```bash
# Clone to a temporary location
git clone https://github.com/HexRaysSA/ida-domain-skill.git /tmp/ida-domain-skill-temp

# Copy only the skill folder to your project
mkdir -p .claude/skills
cp -r /tmp/ida-domain-skill-temp/skills/ida-domain-scripting .claude/skills/

# Navigate to the skill and run setup
cd .claude/skills/ida-domain-scripting
uv run python setup.py

# Clean up temporary files
rm -rf /tmp/ida-domain-skill-temp
```

**Why this structure?** The plugin format requires the `skills/` directory for organizing multiple skills within a plugin. When installing as a standalone skill, you only need the inner `skills/ida-domain-scripting/` folder contents.

---

### Option 3: Download Release

1. Download and extract the latest release from [GitHub Releases](https://github.com/HexRaysSA/ida-domain-skill/releases)
2. Copy only the `skills/ida-domain-scripting/` folder to:
   - Global: `~/.claude/skills/ida-domain-scripting`
   - Project: `/path/to/your/project/.claude/skills/ida-domain-scripting`
3. Navigate to the skill directory and run setup:
   ```bash
   cd ~/.claude/skills/ida-domain-scripting  # or your project path
   uv run python setup.py
   ```

---
### Verify Installation

Run `/help` to confirm the skill is loaded, then ask Claude to perform a simple analysis task like "List all functions in /path/to/binary".

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

## Quick Start

After installation, simply ask Claude to analyze any binary. Claude will write custom IDA Domain scripts, execute them, and return results with formatted output.

## First run 

The first time the skill is used it will generate and API_REFERENCE.md file. You can also generate this file by 
using the /ida-domain-bootstrap slash command 

## Usage Examples

### Function Analysis

```
"List all functions in the binary"
"Find functions that call malloc"
"Show the disassembly for function main"
```

### String Analysis

```
"Find all strings in the binary"
"Search for strings containing 'password' or 'secret'"
"Find interesting strings (URLs, paths, credentials)"
```

### Decompilation

```
"Decompile the function at address 0x401000"
"Show pseudocode for all functions calling encrypt"
"Analyze the main function logic"
```

### Cross-References

```
"Find all references to this function"
"What calls the connect function?"
"Show data xrefs to this address"
```

## How It Works

1. Describe what you want to analyze or extract from a binary
2. Claude writes a custom IDA Domain script for the task
3. The runner (`run.py`) executes the script with IDA Pro in batch mode
4. IDA Domain provides a clean Python API to access IDA's analysis
5. Results are returned with formatted output

## Configuration

Default settings:

- **Output:** Results printed to stdout
- **Scripts:** Written to `/tmp/` directory
- **Database:** Can use existing `.i64`/`.idb` or create temporary analysis
- **Timeout:** No default timeout (analysis runs to completion)

**Using a specific ida-domain version:**
```bash
# Use a specific release tag
uv run python setup.py --ref v0.1.0

# Use main branch (bleeding edge)
uv run python setup.py --ref main
```

## Project Structure

```
ida-domain-skill/
├── .claude-plugin/
│   ├── plugin.json          # Plugin metadata for distribution
│   └── marketplace.json     # Marketplace configuration
├── skills/
│   └── ida-domain-scripting/    # The actual skill (Claude discovers this)
│       ├── SKILL.md             # What Claude reads
│       ├── run.py               # Script executor (batch mode)
│       ├── setup.py             # Environment setup & validation
│       ├── pyproject.toml       # Python dependencies
│       └── lib/
│           └── helpers.py       # Optional utility functions
│       └── API_REFERENCE.md     # Full IDA Domain API reference
├── README.md                # This file - user documentation
└── LICENSE                  # MIT License
```

## Advanced Usage

Claude will automatically load `API_REFERENCE.md` created during the bootstrap when needed for comprehensive 
documentation on functions, strings, cross-references, segments, types, decompilation, and more.


## Dependencies

- [uv](https://docs.astral.sh/uv/) package manager
- IDA Pro 9.1 or later (with valid license)
- ida-domain (installed via setup script)

## Troubleshooting

**IDADIR not set?**
Set the environment variable to your IDA installation directory. See [Setting IDADIR](#setting-idadir).

**Setup fails to find IDA?**
Verify the path contains `idat64` (Linux/macOS) or `idat64.exe` (Windows).

**Import errors for ida_domain?**
Run the setup script again: `uv run python setup.py`

**Analysis takes too long?**
Large binaries may take time on first analysis. Use existing `.i64` databases when possible.

**Permission denied errors?**
Ensure IDA Pro is properly licensed and can run in batch mode.

## What is a Skill?

[Agent Skills](https://agentskills.io) are folders of instructions, scripts, and resources that agents can discover and use to do things more accurately and efficiently. When you ask Claude to analyze a binary or reverse engineer code, Claude discovers this skill, loads the necessary instructions, executes custom IDA Domain scripts, and returns formatted analysis results.

This IDA Domain skill implements the [open Agent Skills specification](https://agentskills.io), making it compatible across agent platforms.

## Contributing

Contributions are welcome. Fork the repository, create a feature branch, make your changes, and submit a pull request.

## Learn More

- [Agent Skills Specification](https://agentskills.io) - Open specification for agent skills
- [Claude Code Skills Documentation](https://docs.claude.com/en/docs/claude-code/skills)
- [Claude Code Plugins Documentation](https://docs.claude.com/en/docs/claude-code/plugins)
- [Plugin Marketplaces](https://docs.claude.com/en/docs/claude-code/plugin-marketplaces)
- [IDA Domain Repository](https://github.com/HexRaysSA/ida-domain)
- [IDA Domain Documentation](https://ida-domain.docs.hex-rays.com/)
- [IDA Pro](https://hex-rays.com/ida-pro/)
- [API_REFERENCE.md](skills/ida-domain-scripting/API_REFERENCE.md) - Full IDA Domain API documentation
- [GitHub Issues](https://github.com/HexRaysSA/ida-domain-skill/issues)

## License

MIT License - see [LICENSE](LICENSE) file for details.
