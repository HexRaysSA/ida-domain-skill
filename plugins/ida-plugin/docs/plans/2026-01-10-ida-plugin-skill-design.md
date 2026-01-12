# IDA Plugin Skill Design

**Date:** 2026-01-10
**Status:** Approved

## Overview

A Claude Code skill that enables Claude to autonomously create and install IDAPython plugins for IDA Pro 9.x with proper HCLI packaging.

## Scope

### In Scope
- IDAPython plugins for IDA 9.x only
- HCLI-compatible packaging (`ida-plugin.json` manifest)
- Plugin settings descriptors
- Single-file or package structure (complexity-appropriate)
- Python dependencies with IDA-specific guidance
- Comprehensive Qt6/PySide6: dialogs, dockable widgets, viewers, choosers, graphs, toolbars, status bar
- UI_Hooks for event handling
- Actions, menus, key bindings
- MVC structure when appropriate
- Structured logging and error handling
- Testing via `hcli plugin lint` and testability patterns

### Out of Scope
- IDA scripting/analysis logic (IDB_Hooks, database manipulation, etc.)
- IDA 7.x/8.x compatibility
- C++ SDK plugins

## Skill Structure

```
ida-plugin-skill/                    # Repository root
├── .claude-plugin/
│   └── plugin.json                  # Plugin metadata for distribution
├── skills/
│   └── ida-plugin/                  # The actual skill
│       ├── SKILL.md                 # Main instructions Claude reads
│       ├── setup.py                 # Environment validation (checks hcli)
│       ├── package.py               # Package/lint/install generated plugin
│       ├── templates/
│       │   ├── minimal.py           # Single-action plugin
│       │   ├── dockable.py          # Dockable widget plugin
│       │   ├── chooser.py           # Chooser-based plugin
│       │   └── multi_view.py        # MVC multi-view plugin
│       ├── REFERENCE.md             # Qt, hooks, actions, settings docs
│       └── ida-plugin.template.json # Manifest template
├── README.md
└── LICENSE
```

## SKILL.md Structure

The main skill file (~200 lines). Concise, focused on decision-making and workflow.

```markdown
---
name: ida-plugin
description: Create IDAPython plugins for IDA Pro 9.x with proper HCLI packaging.
  Use when user wants to build IDA plugins with UI (widgets, menus, actions,
  dialogs), event hooks, or settings. Handles Qt6, actions, keybindings,
  dockable forms, choosers, and HCLI-compatible manifest generation.
---

# IDA Plugin Development

Create and package IDAPython plugins for IDA Pro 9.x.

## Setup (Required First)

cd $SKILL_DIR && uv run python setup.py

## Workflow

1. Understand what the user wants (UI type, interactions, settings)
2. Select appropriate template from `templates/`
3. Adapt template to requirements
4. Generate `ida-plugin.json` manifest
5. Package and validate: `cd $SKILL_DIR && uv run python package.py <plugin-dir>`

## Template Selection

| User needs... | Template |
|--------------|----------|
| Single menu action, hotkey | `minimal.py` |
| Dockable panel/window | `dockable.py` |
| List/table with selection | `chooser.py` |
| Multiple views, complex state | `multi_view.py` |

## Quick Reference

[Key patterns for actions, menus, settings]

## Full Reference

For Qt widgets, UI_Hooks, detailed patterns: see REFERENCE.md
```

## Templates

Each template is a complete, runnable plugin. Claude adapts names, logic, and UI elements but the structure is proven correct.

### minimal.py (~80 lines)
- Plugin class with `init()`, `run()`, `term()`
- One action with menu entry and hotkey
- Basic logging setup
- Manifest-compatible metadata in docstring

### dockable.py (~150 lines)
- `PluginForm` subclass for dockable window
- Qt6 widget creation (`OnCreate`)
- Proper lifecycle (`OnClose`, cleanup)
- Action to toggle visibility
- Settings for window state persistence

### chooser.py (~180 lines)
- `Choose` subclass with columns
- Data model population
- Selection callbacks (`OnSelectLine`, `OnDeleteLine`)
- Refresh mechanism
- Context menu integration

### multi_view.py (~250 lines)
- Separated Model/View/Controller
- Multiple coordinated widgets
- Shared state management
- UI_Hooks for event response
- Settings for user preferences
- Proper cleanup on term()

### Common to All Templates
- Complete imports
- Logging setup (IDA output window + Python logging)
- Error handling that won't crash IDA
- Comments marking where to customize

## REFERENCE.md Content

Detailed reference (~500 lines) Claude loads when needed. Organized by topic:

### 1. Actions & Menus (~100 lines)
- `action_desc_t` structure
- `register_action()` / `unregister_action()`
- `attach_action_to_menu()` with menu paths
- Hotkey format (e.g., `"Ctrl+Shift+X"`)
- Dynamic enable/disable (`update()` callback)

### 2. Qt6 Widgets (~200 lines)
- Getting IDA's Qt instance
- Common widgets: `QWidget`, `QDialog`, `QTableWidget`, `QTreeWidget`
- Layouts: `QVBoxLayout`, `QHBoxLayout`, `QFormLayout`
- Dockable forms via `PluginForm`
- Custom graph views
- Toolbar and status bar integration
- Modal vs. non-modal dialogs

### 3. UI_Hooks (~80 lines)
- Hook installation/removal
- Available callbacks: `ready_to_run`, `widget_visible`, `populating_widget_popup`
- Avoiding recursion issues
- Cleanup patterns

### 4. Settings Descriptors (~60 lines)
- `plugin.settings` manifest format
- Supported types: string, boolean, number, enum
- Accessing settings at runtime
- Default values

### 5. Logging & Error Handling (~50 lines)
- `ida_kernwin.msg()` for output window
- Python logging integration
- Exception handling that doesn't crash IDA
- Debug vs. release patterns

### 6. Dependencies (~40 lines)
- `pythonDependencies` in manifest
- IDA's Python environment pitfalls
- Version pinning recommendations

## Manifest Template

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "{{plugin_name}}",
    "version": "{{version}}",
    "description": "{{description}}",
    "entryPoint": "{{entry_point}}",
    "authors": [
      { "name": "{{author_name}}", "email": "{{author_email}}" }
    ],
    "license": "{{license}}",
    "urls": {
      "repository": "{{repo_url}}"
    },
    "idaVersions": ["9.0.0"],
    "platforms": ["win64", "linux64", "mac64", "macarm64"],
    "pythonDependencies": [],
    "settings": []
  }
}
```

## Scripts

### setup.py (~50 lines)
- Check `hcli` in PATH via `shutil.which()`
- Run `hcli --version` to confirm availability
- Print success/failure message
- Exit with appropriate code

### package.py (~100 lines)
- Accept plugin directory as argument
- Validate `ida-plugin.json` exists
- Create ZIP with correct structure
- Run `hcli plugin lint <zip>`
- Report lint results
- Optional `--install` flag to run `hcli plugin install`
- Cleanup temp files on failure

## Validation Checklist

### Pre-packaging
- Plugin loads without errors (no import failures)
- Action IDs are unique (prefixed with plugin name)
- All registered actions are unregistered in `term()`
- All hooks are unhooked in `term()`
- Qt widgets properly parented or cleaned up
- No hardcoded paths

### Manifest
- `ida-plugin.json` present and valid JSON
- Required fields: name, version, entryPoint, authors, repository
- `entryPoint` matches actual plugin file
- Version follows semver

### Post-lint
- `hcli plugin lint` returns 0
- No warnings about missing fields
- Platform specification correct

## Plugin Structure Patterns

### Single-file plugin (for minimal, simple dockable)
```
my_plugin/
├── ida-plugin.json
└── my_plugin.py
```

### Package plugin (for chooser, multi-view, or when logic grows)
```
my_plugin/
├── ida-plugin.json
├── my_plugin.py          # Entry point, registers plugin
├── ui/
│   ├── __init__.py
│   ├── main_form.py      # Primary widget
│   └── dialogs.py        # Modal dialogs
├── core/
│   ├── __init__.py
│   └── model.py          # Data/state management
└── resources/
    └── icons/            # Optional icons
```

Claude decides based on complexity. Rule of thumb: if more than 2 UI components or shared state, use package structure.

## Installation Flow

```
1. User describes plugin
         ↓
2. Claude selects template, reads it
         ↓
3. Claude adapts code to requirements
         ↓
4. Claude generates ida-plugin.json from template
         ↓
5. Claude writes files to /tmp/plugin_name/
         ↓
6. Claude runs: cd $SKILL_DIR && uv run python package.py /tmp/plugin_name/
         ↓
7. package.py creates ZIP, runs hcli lint
         ↓
8. If lint passes:
   - Ask user: "Install now?"
   - If yes: hcli plugin install <zip>
         ↓
9. Report success, provide ZIP location
```

## Key Decisions

1. **Template-based approach** - Consistent, validated structure; less room for errors
2. **Single-file vs package** - Complexity-appropriate; Claude decides
3. **Progressive disclosure** - SKILL.md concise, REFERENCE.md on demand
4. **Validation via hcli** - Leverages official tooling
5. **No IDADIR required** - hcli works standalone for packaging/linting
