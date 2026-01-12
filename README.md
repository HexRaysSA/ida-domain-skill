# IDA Claude Plugins

A monorepo containing Claude Code plugins and skills for IDA Pro reverse engineering workflows. These plugins enable Claude to autonomously create IDA Pro plugins and execute binary analysis scripts.

## Plugins

### ida-plugin

Claude skill for developing IDAPython plugins for IDA Pro 9.x with HCLI-compatible packaging.

**Features:**
- 6 production-ready templates (minimal, dockable, chooser, multi_view, hint, debugger_view)
- Comprehensive API reference for Qt widgets, actions, hooks, and settings
- Automatic plugin packaging and validation via HCLI
- PySide6 (Qt6) UI framework support

See [plugins/ida-plugin/README.md](plugins/ida-plugin/README.md) for detailed documentation.

### ida-domain

Claude skill for writing and executing Python scripts using the IDA Domain API for binary analysis.

**Features:**
- High-level abstraction over IDA's native APIs
- 20+ test cases with real binaries
- Complete API reference documentation
- Script execution wrapper with headless IDA support

See [plugins/ida-domain/](plugins/ida-domain/) for detailed documentation.

## Installation

### Via Claude Code Plugin Marketplace (Recommended)

```bash
/plugin marketplace add HexRaysSA/ida-claude-plugins
/plugin install ida-plugin@ida-plugin
/plugin install ida-domain@ida-domain
```

### Manual Installation

Clone to your Claude skills directory:

```bash
# Global installation
git clone https://github.com/HexRaysSA/ida-claude-plugins.git ~/.claude/skills/ida-claude-plugins

# Project-specific installation
git clone https://github.com/HexRaysSA/ida-claude-plugins.git .claude/skills/ida-claude-plugins
```

## Requirements

- IDA Pro 9.x
- `hcli` command-line tool (for plugin packaging)
- `uv` package manager
- Python 3.x

## License

MIT License - Copyright 2026 Hex-Rays SA
