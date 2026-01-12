# IDA Plugin Skill for Claude Code

**Create IDAPython plugins for IDA Pro 9.x with Claude**

A [Claude Skill](https://docs.claude.com/en/docs/claude-code/skills) that enables Claude to autonomously create, package, and install IDAPython plugins with proper HCLI-compatible packaging.

Claude handles plugin infrastructure (Qt widgets, menus, actions, hooks, settings) so you can focus on what your plugin should do.

## Features

- **Template-Based Generation** - Four proven templates covering common plugin patterns
- **HCLI Packaging** - Generates `ida-plugin.json` manifests compatible with IDA's plugin manager
- **Comprehensive Qt6 Support** - Dockable widgets, dialogs, choosers, custom views
- **Best Practices** - Proper lifecycle management, error handling, logging

## Requirements

- [uv](https://docs.astral.sh/uv/) package manager
- IDA Pro 9.x (for `hcli` command-line tool)
- `hcli` in your PATH

## Installation

### Option 1: Plugin Installation (Recommended)

```bash
# Add this repository as a marketplace
/plugin marketplace add HexRaysSA/ida-plugin-skill

# Install the plugin
/plugin install ida-plugin-skill@ida-plugin-skill

# Run setup to verify hcli is available
cd ~/.claude/plugins/marketplaces/ida-plugin-skill/skills/ida-plugin
uv run python setup.py
```

### Option 2: Standalone Skill Installation

**Global Installation:**

```bash
git clone https://github.com/HexRaysSA/ida-plugin-skill.git /tmp/ida-plugin-skill-temp
mkdir -p ~/.claude/skills
cp -r /tmp/ida-plugin-skill-temp/skills/ida-plugin ~/.claude/skills/
cd ~/.claude/skills/ida-plugin
uv run python setup.py
rm -rf /tmp/ida-plugin-skill-temp
```

**Project-Specific Installation:**

```bash
git clone https://github.com/HexRaysSA/ida-plugin-skill.git /tmp/ida-plugin-skill-temp
mkdir -p .claude/skills
cp -r /tmp/ida-plugin-skill-temp/skills/ida-plugin .claude/skills/
cd .claude/skills/ida-plugin
uv run python setup.py
rm -rf /tmp/ida-plugin-skill-temp
```

## Quick Start

After installation, describe the plugin you want to create:

```
"Create an IDA plugin that adds a menu item to list all functions with 'crypto' in their name"
```

Claude will:
1. Select the appropriate template
2. Generate the plugin code
3. Create the `ida-plugin.json` manifest
4. Package and validate with `hcli plugin lint`
5. Optionally install the plugin

## Usage Examples

### Simple Action Plugin

```
"Create a plugin with a hotkey Ctrl+Shift+R that renames the current function to 'analyzed_' prefix"
```

### Dockable Widget

```
"Create a plugin with a dockable panel that shows a list of all imported functions"
```

### Chooser (List/Table)

```
"Create a plugin that displays all strings containing URLs in a searchable table"
```

### Multi-View Plugin

```
"Create a plugin with a master-detail view: a list of functions on the left, decompiled code on the right"
```

## Templates

| Template | Use Case |
|----------|----------|
| `minimal.py` | Single menu action with hotkey |
| `dockable.py` | Persistent dockable widget |
| `chooser.py` | List/table with selection |
| `multi_view.py` | MVC architecture with multiple coordinated views |

## Project Structure

```
ida-plugin-skill/
├── .claude-plugin/
│   └── plugin.json           # Claude Code plugin metadata
├── skills/
│   └── ida-plugin/
│       ├── SKILL.md          # Main skill instructions
│       ├── REFERENCE.md      # Detailed API reference
│       ├── setup.py          # Environment validation
│       ├── package.py        # Packaging script
│       ├── ida-plugin.template.json
│       └── templates/
│           ├── minimal.py
│           ├── dockable.py
│           ├── chooser.py
│           └── multi_view.py
├── docs/
│   └── plans/                # Design documents
├── README.md
└── LICENSE
```

## Scope

**In Scope:**
- Plugin infrastructure (lifecycle, registration)
- Qt6 widgets (forms, dialogs, choosers)
- Actions, menus, hotkeys
- UI_Hooks for event handling
- Settings descriptors
- HCLI packaging and validation

**Out of Scope:**
- IDA scripting/analysis logic (use [ida-domain-skill](https://github.com/HexRaysSA/ida-domain-skill) for that)
- IDA 7.x/8.x compatibility
- C++ SDK plugins

## Related

- [ida-domain-skill](https://github.com/HexRaysSA/ida-domain-skill) - For IDA scripting and analysis tasks
- [HCLI Documentation](https://hcli.docs.hex-rays.com/) - Plugin packaging reference
- [IDAPython Documentation](https://hex-rays.com/products/ida/support/idapython_docs/)

## Contributing

Contributions are welcome. Fork the repository, create a feature branch, make your changes, and submit a pull request.

## License

MIT License - see [LICENSE](LICENSE) file for details.
