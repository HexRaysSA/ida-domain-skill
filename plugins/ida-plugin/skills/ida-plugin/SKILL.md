---
name: ida-plugin
description: Create IDAPython plugins for IDA Pro 9.x with HCLI-compatible packaging. Use when user wants to build IDA plugins with UI (dockable widgets, dialogs, menus, choosers), actions, keybindings, event hooks, or settings. Generates complete plugin code and manifest for installation via hcli.
---

# IDA Plugin Development

Create and package IDAPython plugins for IDA Pro 9.x.

## Setup (Required First)

```bash
cd $SKILL_DIR && uv run python setup.py
```

Validates that `hcli` is available for packaging and linting.

## Workflow

1. Understand what the user wants (UI type, interactions, settings)
2. Select appropriate template from `templates/`
3. Read and adapt template to requirements
4. Generate `ida-plugin.json` manifest
5. Write files to `/tmp/<plugin_name>/`
6. Package and validate: `cd $SKILL_DIR && uv run python package.py /tmp/<plugin_name>/`
7. Ask user if they want to install, then add `--install` flag

## Template Selection

| User needs... | Template | Use when... |
|---------------|----------|-------------|
| Single menu action, hotkey | `minimal.py` | Simple automation, no persistent UI |
| Dockable panel/window | `dockable.py` | Persistent widget, custom Qt UI |
| List/table with selection | `chooser.py` | Data browser, item selection |
| Multiple views, complex state | `multi_view.py` | MVC architecture, coordinated views |
| Custom hover hints | `hint.py` | Passive plugin providing tooltips in disassembly |
| Debugger-related views | `debugger_view.py` | Views that update during debugging sessions |

## Quick Reference

### Plugin Entry Points

```python
class MyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP  # See flag combinations below
    comment = "Plugin description"
    help = "Help text"
    wanted_name = "My Plugin"
    wanted_hotkey = ""  # Optional global hotkey

    def init(self):
        # Called once at load. Return PLUGIN_KEEP, PLUGIN_OK, or PLUGIN_SKIP
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Called when user invokes plugin (menu or wanted_hotkey)
        pass

    def term(self):
        # Called at unload. Clean up actions, hooks, widgets.
        pass

def PLUGIN_ENTRY():
    return MyPlugin()
```

### Plugin Flags

| Flag | Description |
|------|-------------|
| `PLUGIN_KEEP` | Stay resident in memory |
| `PLUGIN_HIDE` | Hide from Edit/Plugins menu (use with custom actions) |
| `PLUGIN_PROC` | Reload when IDB opens/closes |
| `PLUGIN_MOD` | Plugin may modify the database |
| `PLUGIN_SKIP` | Return from `init()` to skip loading |

**Common Flag Combinations:**

```python
# Standard plugin with menu presence
flags = ida_idaapi.PLUGIN_KEEP

# Passive plugin (hooks only, no menu entry)
flags = ida_idaapi.PLUGIN_KEEP | ida_idaapi.PLUGIN_HIDE

# Plugin that reloads per-database
flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE
```

### Actions

```python
# Define action handler
class MyActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        # Action logic here
        return 1

    def update(self, ctx):
        # Return availability: AST_ENABLE_ALWAYS, AST_ENABLE, AST_DISABLE
        return ida_kernwin.AST_ENABLE_ALWAYS

# Register action (in init)
action_desc = ida_kernwin.action_desc_t(
    "myplugin:my_action",       # Unique ID (prefix with plugin name)
    "My Action",                 # Display name
    MyActionHandler(),           # Handler instance
    "Ctrl+Shift+M",             # Hotkey (or None)
    "Action tooltip",           # Tooltip
    -1                          # Icon ID (-1 for none)
)
ida_kernwin.register_action(action_desc)

# Attach to menu (after registering)
ida_kernwin.attach_action_to_menu(
    "Edit/Plugins/",            # Menu path
    "myplugin:my_action",       # Action ID
    ida_kernwin.SETMENU_APP     # Append
)

# Unregister (in term)
ida_kernwin.unregister_action("myplugin:my_action")
```

### Common Menu Paths

- `"File/"` - File menu
- `"Edit/"` - Edit menu
- `"Edit/Plugins/"` - Plugins submenu
- `"View/"` - View menu
- `"Search/"` - Search menu
- `"Debugger/"` - Debugger menu

### IDA 9.x Qt Imports

```python
# IDA 9.x uses PySide6
from PySide6 import QtGui, QtCore, QtWidgets
from PySide6.QtGui import QAction
```

### Logging

```python
import ida_kernwin

# Output to IDA's Output window
ida_kernwin.msg("Info message\n")
ida_kernwin.warning("Warning message\n")

# For debugging (also goes to Output window)
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
```

### Error Handling

```python
def safe_operation():
    try:
        # Your code here
        pass
    except Exception as e:
        ida_kernwin.warning(f"Operation failed: {e}\n")
        import traceback
        traceback.print_exc()  # Goes to Output window
```

## Manifest Required Fields

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "my-plugin",
    "version": "1.0.0",
    "description": "What the plugin does",
    "entryPoint": "my_plugin.py",
    "authors": [{"name": "Author", "email": "email@example.com"}],
    "license": "MIT",
    "urls": {"repository": "https://github.com/user/repo"},
    "idaVersions": ["9.0.0"],
    "platforms": ["win64", "linux64", "mac64", "macarm64"]
  }
}
```

## Full Reference

For detailed Qt widgets, UI_Hooks, settings descriptors, and more patterns, see [REFERENCE.md](REFERENCE.md).

## Validation

Before packaging, verify:
- [ ] Action IDs are prefixed with plugin name
- [ ] All registered actions are unregistered in `term()`
- [ ] All hooks are unhooked in `term()`
- [ ] Custom icons are freed with `free_custom_icon()` in `term()`
- [ ] No hardcoded paths (use `ida_idaapi.get_user_idadir()` for user data)
- [ ] Qt imports use PySide6 (IDA 9.x requirement)
- [ ] Long operations show wait box and check `user_cancelled()`
- [ ] `ida-plugin.json` has all required fields
- [ ] `entryPoint` matches actual file name

## Packaging

```bash
# Package and lint
cd $SKILL_DIR && uv run python package.py /tmp/my_plugin/

# Package, lint, and install
cd $SKILL_DIR && uv run python package.py /tmp/my_plugin/ --install
```
