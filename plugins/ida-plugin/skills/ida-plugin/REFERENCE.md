# IDA Plugin Development Reference

Detailed reference for IDAPython plugin development in IDA Pro 9.x.

## Table of Contents

1. [Actions & Menus](#actions--menus)
2. [Qt Widgets](#qt-widgets)
3. [Hooks](#hooks)
   - [UI_Hooks](#ui_hooks)
   - [IDB_Hooks](#idb_hooks)
   - [IDP_Hooks](#idp_hooks)
   - [DBG_Hooks](#dbg_hooks)
4. [Settings & Persistence](#settings--persistence)
5. [Thread Safety](#thread-safety)
6. [Custom Viewer Features](#custom-viewer-features)
7. [Logging & Error Handling](#logging--error-handling)
8. [Dependencies](#dependencies)

---

## Actions & Menus

### Action Descriptor

```python
import ida_kernwin

action_desc = ida_kernwin.action_desc_t(
    "plugin_name:action_id",  # Unique ID (MUST prefix with plugin name)
    "Action Label",            # Display name in menu
    handler_instance,          # action_handler_t subclass instance
    "Ctrl+Shift+X",           # Hotkey (or None)
    "Tooltip text",           # Shown on hover
    icon_id                   # Icon number (-1 for none)
)
```

### Action Handler

```python
class MyHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        """
        Called when action is triggered.

        Args:
            ctx: action_activation_ctx_t with context info:
                - ctx.widget: Current widget
                - ctx.widget_type: Widget type (BWN_*)
                - ctx.cur_ea: Current address (if applicable)
                - ctx.cur_value: Current value
                - ctx.action: Action name

        Returns:
            1 for success, 0 for failure
        """
        return 1

    def update(self, ctx):
        """
        Return action availability.

        Args:
            ctx: action_update_ctx_t

        Returns:
            AST_ENABLE_ALWAYS - Always enabled
            AST_ENABLE - Enabled (will call activate)
            AST_DISABLE - Disabled (grayed out)
            AST_DISABLE_ALWAYS - Always disabled
        """
        return ida_kernwin.AST_ENABLE_ALWAYS
```

### Registering Actions

```python
# Register
if not ida_kernwin.register_action(action_desc):
    print("Failed to register action")

# Attach to menu
ida_kernwin.attach_action_to_menu(
    "Edit/Plugins/",           # Menu path
    "plugin_name:action_id",   # Action ID
    ida_kernwin.SETMENU_APP    # Flags
)

# Attach to toolbar
ida_kernwin.attach_action_to_toolbar(
    "AnalysisToolBar",         # Toolbar name
    "plugin_name:action_id"    # Action ID
)

# Attach to context menu (in popup handler)
ida_kernwin.attach_action_to_popup(
    widget,                    # Widget
    popup,                     # Popup handle
    "plugin_name:action_id",   # Action ID
    None,                      # Popup path (None for root)
    ida_kernwin.SETMENU_APP
)
```

### Common Menu Paths

| Path | Description |
|------|-------------|
| `"File/"` | File menu |
| `"Edit/"` | Edit menu |
| `"Edit/Plugins/"` | Plugins submenu |
| `"Jump/"` | Jump/navigation menu |
| `"Search/"` | Search menu |
| `"View/"` | View menu |
| `"Debugger/"` | Debugger menu |
| `"Options/"` | Options menu |

### Hotkey Format

```python
# Single key
"A", "F1", "Escape"

# With modifiers
"Ctrl+A", "Shift+F1", "Alt+X"
"Ctrl+Shift+A", "Ctrl+Alt+X"

# None for no hotkey
None
```

### Unregistering (in term())

```python
ida_kernwin.detach_action_from_menu("Edit/Plugins/", "plugin_name:action_id")
ida_kernwin.unregister_action("plugin_name:action_id")
```

---

## Qt Widgets

IDA Pro 9.x uses PySide6 for Qt integration.

### Qt Imports

```python
from PySide6 import QtGui, QtCore, QtWidgets
from PySide6.QtGui import QAction

Qt = QtCore.Qt
Signal = QtCore.Signal
```

### Getting IDA's Qt Application

```python
from PySide6.QtWidgets import QApplication

# Get the application instance
app = QApplication.instance()
```

### PluginForm (Dockable Widget)

```python
import ida_kernwin
from PySide6.QtWidgets import QVBoxLayout, QLabel

class MyForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        # Convert to Qt widget
        self.parent = self.FormToPyQtWidget(form)

        # Create layout
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Hello"))
        self.parent.setLayout(layout)

    def OnClose(self, form):
        # Clean up
        pass

# Show the form
form = MyForm()
form.Show(
    "Window Title",
    options=ida_kernwin.PluginForm.WOPN_PERSIST  # Keep on restart
)

# Options:
# WOPN_PERSIST - Persist across sessions
# WOPN_RESTORE - Restore position
# WOPN_DP_TAB - Open as tab (default)
# WOPN_DP_FLOATING - Open floating
```

### Finding and Managing Widgets

```python
# Find widget by title
widget = ida_kernwin.find_widget("Window Title")

# Activate (bring to front)
ida_kernwin.activate_widget(widget, True)

# Close widget
ida_kernwin.close_widget(widget, 0)  # 0 = don't save
```

### Common Qt Widgets

```python
from PySide6.QtWidgets import (
    QWidget,
    QDialog,
    QLabel,
    QPushButton,
    QLineEdit,
    QTextEdit,
    QComboBox,
    QCheckBox,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QListWidget,
    QListWidgetItem,
    QTabWidget,
    QSplitter,
    QGroupBox,
    QScrollArea,
)

from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGridLayout,
)

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QColor
```

### Modal Dialogs

```python
from PySide6.QtWidgets import QDialog, QVBoxLayout, QPushButton, QDialogButtonBox

class MyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("My Dialog")

        layout = QVBoxLayout(self)

        # Add widgets...

        # Standard buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

# Show modal dialog
dialog = MyDialog()
if dialog.exec_() == QDialog.Accepted:
    # User clicked OK
    pass
```

### Message Boxes

```python
from PySide6.QtWidgets import QMessageBox

# Information
QMessageBox.information(None, "Title", "Message")

# Warning
QMessageBox.warning(None, "Title", "Warning message")

# Question
result = QMessageBox.question(
    None,
    "Title",
    "Are you sure?",
    QMessageBox.Yes | QMessageBox.No
)
if result == QMessageBox.Yes:
    pass
```

### Tables

```python
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

table = QTableWidget()
table.setColumnCount(3)
table.setHorizontalHeaderLabels(["Address", "Name", "Size"])

# Add row
row = table.rowCount()
table.insertRow(row)
table.setItem(row, 0, QTableWidgetItem("0x401000"))
table.setItem(row, 1, QTableWidgetItem("main"))
table.setItem(row, 2, QTableWidgetItem("256"))

# Selection
table.setSelectionBehavior(QTableWidget.SelectRows)
table.setSelectionMode(QTableWidget.SingleSelection)

# Connect to selection
table.itemSelectionChanged.connect(on_selection_changed)
```

---

## Hooks

### UI_Hooks

React to IDA UI events.

### Basic Usage

```python
class MyUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        super().__init__()

    def ready_to_run(self):
        """IDA is fully initialized and ready."""
        print("IDA is ready")

    def widget_visible(self, widget):
        """A widget became visible."""
        pass

    def widget_invisible(self, widget):
        """A widget became invisible."""
        pass

    def widget_closing(self, widget):
        """A widget is about to close."""
        pass

    def current_widget_changed(self, widget, prev_widget):
        """Active widget changed."""
        pass

    def populating_widget_popup(self, widget, popup):
        """Context menu is being populated."""
        # Add custom action to popup
        ida_kernwin.attach_action_to_popup(
            widget, popup,
            "myplugin:context_action",
            None,
            ida_kernwin.SETMENU_APP
        )

# Install hooks
hooks = MyUIHooks()
hooks.hook()

# Remove hooks (in term())
hooks.unhook()
```

### Available Callbacks

| Callback | Description |
|----------|-------------|
| `ready_to_run()` | IDA fully initialized |
| `widget_visible(widget)` | Widget shown |
| `widget_invisible(widget)` | Widget hidden |
| `widget_closing(widget)` | Widget closing |
| `current_widget_changed(widget, prev)` | Focus changed |
| `populating_widget_popup(widget, popup)` | Context menu building |
| `finish_populating_widget_popup(widget, popup)` | After context menu built |
| `updating_actions(ctx)` | Before action state update |
| `updated_actions()` | After action state update |
| `get_custom_viewer_hint(view, place)` | Custom hover tooltip |
| `create_desktop_widget(title, cfg)` | Restore widget on desktop load |

### Desktop Persistence Hook

```python
class DesktopHooks(ida_kernwin.UI_Hooks):
    def create_desktop_widget(self, title, cfg):
        """Called when IDA restores a saved desktop layout."""
        if title == "My Plugin View":
            widget = MyPluginForm()
            widget.Show(title, options=ida_kernwin.PluginForm.WOPN_CREATE_ONLY)
            return widget.GetWidget()
        return None

hooks = DesktopHooks()
hooks.hook()
```

### IDB_Hooks

React to database events.

```python
import ida_idp

class MyIDBHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        super().__init__()

    def renamed(self, ea, new_name, local_name, old_name):
        """Called when an address is renamed."""
        print(f"Renamed {ea:#x}: {old_name} -> {new_name}")
        return 0

    def byte_patched(self, ea, old_value):
        """Called when a byte is patched."""
        return 0

    def allsegs_moved(self, info):
        """Called when binary is rebased."""
        return 0

    def bookmark_changed(self, index, pos, desc, operation):
        """Called when bookmark is added/removed/changed."""
        return 0

# Install/uninstall
hooks = MyIDBHooks()
hooks.hook()
# ... later ...
hooks.unhook()
```

**Available IDB_Hooks Callbacks:**

| Callback | Description |
|----------|-------------|
| `renamed(ea, new_name, local_name, old_name)` | Address renamed |
| `byte_patched(ea, old_value)` | Byte value changed |
| `allsegs_moved(info)` | Binary rebased |
| `bookmark_changed(index, pos, desc, op)` | Bookmark modified |
| `func_added(func)` | Function created |
| `deleting_func(func)` | Function being deleted |
| `sgr_changed(start, end, regnum, value, old, tag)` | Segment register changed |

### IDP_Hooks

React to processor events (instruction-level customization).

```python
import ida_idp
import ctypes

class MyIDPHooks(ida_idp.IDP_Hooks):
    def __init__(self):
        super().__init__()

    def ev_get_bg_color(self, color, ea):
        """
        Set background color for an address.

        Args:
            color: Pointer to color value (use ctypes)
            ea: Address being displayed

        Returns:
            1 if handled, 0 for default color
        """
        if self.should_highlight(ea):
            bgcolor = ctypes.cast(int(color), ctypes.POINTER(ctypes.c_int))
            bgcolor[0] = 0xFFD0D0  # Light red
            return 1
        return 0

    def ev_out_mnem(self, ctx):
        """Customize mnemonic output."""
        return 0

# Install/uninstall
hooks = MyIDPHooks()
hooks.hook()
```

### DBG_Hooks

React to debugger events.

```python
import ida_dbg

class MyDBGHooks(ida_dbg.DBG_Hooks):
    def __init__(self):
        super().__init__()

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        """Process started."""
        print(f"Process started: {name} PID={pid}")
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        """Process exited."""
        return 0

    def dbg_suspend_process(self):
        """Process suspended (breakpoint hit, step complete, etc.)."""
        ida_dbg.refresh_debugger_memory()
        self.on_suspend()
        return 0

    def dbg_bpt(self, tid, ea):
        """Breakpoint hit."""
        return 0

    def dbg_step_into(self):
        """Step into completed."""
        return 0

# Install/uninstall
hooks = MyDBGHooks()
hooks.hook()
```

**Available DBG_Hooks Callbacks:**

| Callback | Description |
|----------|-------------|
| `dbg_process_start(pid, tid, ea, name, base, size)` | Process started |
| `dbg_process_exit(pid, tid, ea, code)` | Process exited |
| `dbg_process_attach(pid, tid, ea, name, base, size)` | Attached to process |
| `dbg_suspend_process()` | Process suspended |
| `dbg_bpt(tid, ea)` | Breakpoint hit |
| `dbg_step_into()` | Step into completed |
| `dbg_step_over()` | Step over completed |
| `dbg_run_to(pid, tid, ea)` | Run to address completed |

---

## Settings & Persistence

### ida_settings (User Preferences)

For settings that persist across IDA sessions:

```python
import ida_settings

# Create settings object for your plugin
settings = ida_settings.IDASettings("myplugin")

# Read settings (with defaults)
api_key = settings.user.get("api_key", "")
auto_analyze = settings.user.get("auto_analyze", True)
max_results = settings.user.get("max_results", 100)

# Write settings
settings.user["api_key"] = "abc123"
settings.user["auto_analyze"] = False

# Delete setting
del settings.user["api_key"]
```

### Netnode (IDB-Specific Data)

For data that should persist within a specific IDB file:

```python
import ida_netnode
import json

# Unique netnode name (convention: "$ company.plugin.data")
NETNODE_NAME = "$ com.example.myplugin.cache"

def save_to_idb(data):
    """Save data to current IDB."""
    node = ida_netnode.netnode(NETNODE_NAME, 0, True)  # Create if needed
    json_str = json.dumps(data)
    node.setblob(json_str.encode('utf-8'), 0, 'I')

def load_from_idb():
    """Load data from current IDB."""
    node = ida_netnode.netnode(NETNODE_NAME, 0, False)
    if not node:
        return None
    blob = node.getblob(0, 'I')
    if not blob:
        return None
    return json.loads(blob.decode('utf-8'))

def clear_idb_data():
    """Remove data from current IDB."""
    node = ida_netnode.netnode(NETNODE_NAME, 0, False)
    if node:
        node.delblob(0, 'I')
```

### Settings Descriptors (Manifest)

Define user-configurable settings in `ida-plugin.json`.

### Manifest Format

```json
{
  "plugin": {
    "settings": [
      {
        "name": "api_key",
        "type": "string",
        "label": "API Key",
        "description": "Your API key for the service",
        "default": ""
      },
      {
        "name": "auto_analyze",
        "type": "boolean",
        "label": "Auto-analyze on open",
        "description": "Automatically run analysis when a database is opened",
        "default": true
      },
      {
        "name": "max_results",
        "type": "number",
        "label": "Maximum results",
        "description": "Maximum number of results to display",
        "default": 100,
        "minimum": 1,
        "maximum": 10000
      },
      {
        "name": "output_format",
        "type": "enum",
        "label": "Output format",
        "description": "Format for exported results",
        "default": "json",
        "options": ["json", "csv", "xml"]
      }
    ]
  }
}
```

### Supported Types

| Type | Description | Extra Properties |
|------|-------------|------------------|
| `string` | Text input | - |
| `boolean` | Checkbox | - |
| `number` | Numeric input | `minimum`, `maximum` |
| `enum` | Dropdown selection | `options` (array) |

### Accessing Settings at Runtime

```python
import ida_settings

# Get setting value
value = ida_settings.get("myplugin", "api_key", default="")

# Set setting value
ida_settings.set("myplugin", "auto_analyze", True)

# Note: Plugin name must match manifest name
```

---

## Thread Safety

IDA's UI runs on a single main thread. Background operations must synchronize with the main thread.

### execute_sync

```python
import ida_kernwin
import functools

def execute_on_main_thread(func):
    """Decorator to run function on IDA's main thread."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = [None]
        def thunk():
            result[0] = func(*args, **kwargs)
            return 1
        ida_kernwin.execute_sync(thunk, ida_kernwin.MFF_FAST)
        return result[0]
    return wrapper

# Usage
@execute_on_main_thread
def update_ui():
    ida_kernwin.msg("Updated from background thread\n")
```

### MFF Flags

| Flag | Description |
|------|-------------|
| `MFF_FAST` | UI operations (no database access) |
| `MFF_READ` | Safe database read operations |
| `MFF_WRITE` | Database write operations |
| `MFF_NOWAIT` | Don't wait for completion (IDA 7.1+) |

### Wait Box for Long Operations

```python
import ida_kernwin

def long_operation():
    ida_kernwin.show_wait_box("Processing...")
    try:
        for i in range(100):
            # Check if user cancelled
            if ida_kernwin.user_cancelled():
                ida_kernwin.msg("Operation cancelled\n")
                return False

            # Update progress message
            ida_kernwin.replace_wait_box(f"Processing... {i}%")

            # Do work here
            do_work(i)
    finally:
        ida_kernwin.hide_wait_box()
    return True
```

### Background Thread Pattern

```python
import threading
import queue

class BackgroundWorker:
    def __init__(self):
        self.queue = queue.Queue()
        self.thread = None
        self.running = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self.queue.put(None)  # Signal to exit
        if self.thread:
            self.thread.join(timeout=2.0)

    def _worker_loop(self):
        while self.running:
            task = self.queue.get()
            if task is None:
                break
            try:
                result = task()
                # Update UI on main thread
                ida_kernwin.execute_sync(
                    lambda: self.on_complete(result),
                    ida_kernwin.MFF_FAST
                )
            except Exception as e:
                ida_kernwin.execute_sync(
                    lambda: ida_kernwin.warning(f"Error: {e}"),
                    ida_kernwin.MFF_FAST
                )
```

---

## Custom Viewer Features

### Custom Hover Hints

```python
class HintHook(ida_kernwin.UI_Hooks):
    def get_custom_viewer_hint(self, view, place):
        """
        Provide custom tooltip when hovering over disassembly.

        Args:
            view: The viewer widget
            place: place_t object (can be None)

        Returns:
            tuple(hint_text, important_lines) or None
            - hint_text: String to display
            - important_lines: Number of lines to show without scrolling
        """
        if not place:
            return None

        # Check we're in disassembly view
        widget = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return None

        ea = place.toea()
        hint = f"Address: {ea:#x}\nSize: {ida_bytes.get_item_size(ea)}"
        return hint, 3  # 3 important lines

hooks = HintHook()
hooks.hook()
```

### Custom Line Prefix

```python
import ida_lines

class MyPrefix(ida_lines.user_defined_prefix_t):
    def __init__(self):
        # Width of prefix in characters
        super().__init__(3)

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        """
        Return custom prefix for disassembly line.

        Args:
            ea: Address
            insn: Instruction (insn_t)
            lnnum: Line number within item
            indent: Current indent level
            line: Line text

        Returns:
            Prefix string (must match width)
        """
        if self.should_mark(ea):
            return ">>>"
        return "   "  # Same width as prefix

# Install (keep reference to prevent garbage collection)
prefix = MyPrefix()

# Uninstall
prefix = None  # Setting to None removes the prefix
```

### Navigation Band Colorizer

```python
import ida_kernwin

class NavbandColorizer:
    def __init__(self):
        self.original_colorizer = None
        self.highlighted_addresses = set()

    def colorizer(self, ea, nbytes):
        """Return color for address in navigation band."""
        if ea in self.highlighted_addresses:
            return 0xFF0000  # Red
        # Fall back to original colorizer
        if self.original_colorizer:
            return ida_kernwin.call_nav_colorizer(self.original_colorizer, ea, nbytes)
        return None

    def install(self):
        self.original_colorizer = ida_kernwin.set_nav_colorizer(self.colorizer)

    def uninstall(self):
        if self.original_colorizer:
            ida_kernwin.set_nav_colorizer(self.original_colorizer)
            self.original_colorizer = None
```

### Refresh Disassembly

```python
import ida_kernwin

# Request refresh of disassembly view
ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)

# Force immediate refresh
ida_kernwin.refresh_idaview_anyway()
```

---

## Logging & Error Handling

### IDA Output Window

```python
import ida_kernwin

# Regular message
ida_kernwin.msg("This is a message\n")

# Warning (may show dialog)
ida_kernwin.warning("This is a warning")

# Info (status bar)
ida_kernwin.info("Status message")
```

### Python Logging Integration

```python
import logging
import ida_kernwin

class IDAHandler(logging.Handler):
    """Send Python logging to IDA output window."""

    def emit(self, record):
        msg = self.format(record)
        ida_kernwin.msg(f"{msg}\n")

# Setup
logger = logging.getLogger("myplugin")
logger.setLevel(logging.DEBUG)
logger.addHandler(IDAHandler())

# Usage
logger.info("Plugin initialized")
logger.debug("Debug info: %s", value)
logger.error("Something failed: %s", error)
```

### Safe Exception Handling

```python
import traceback
import ida_kernwin

def safe_execute(func):
    """Decorator for safe execution."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            ida_kernwin.warning(f"Error: {e}")
            traceback.print_exc()  # To output window
            return None
    return wrapper

# Usage
@safe_execute
def risky_operation():
    # Code that might fail
    pass
```

### Debug vs Release

```python
import os

DEBUG = os.environ.get("IDA_PLUGIN_DEBUG", "0") == "1"

def debug_log(msg):
    if DEBUG:
        ida_kernwin.msg(f"[DEBUG] {msg}\n")
```

---

## Dependencies

### Declaring in Manifest

```json
{
  "plugin": {
    "pythonDependencies": [
      "requests>=2.28.0",
      "pyyaml>=6.0"
    ]
  }
}
```

### IDA Python Environment Notes

1. **IDA uses its bundled Python** - Not your system Python
2. **Some packages may conflict** - Test thoroughly
3. **Binary packages need compatible builds** - May need IDA-specific builds
4. **Prefer pure Python packages** - Fewer compatibility issues

### Recommended Practices

```python
# Check for optional dependency
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    ida_kernwin.warning("requests not installed, some features disabled")

# Use with fallback
if HAS_REQUESTS:
    response = requests.get(url)
else:
    # Fallback implementation
    pass
```

### Installing Dependencies

Dependencies declared in `pythonDependencies` are installed automatically by `hcli plugin install`. For development:

```bash
# Install to IDA's Python
$IDADIR/python3 -m pip install requests

# Or use the plugin's virtual environment if configured
```
