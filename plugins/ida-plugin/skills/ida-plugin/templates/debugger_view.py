"""
Debugger View Plugin Template

A plugin that provides a custom view during debugging sessions.
Uses DBG_Hooks to update when the debugger state changes.

Customization points marked with: # CUSTOMIZE
"""

from typing import Optional

import ida_idaapi
import ida_kernwin
import ida_dbg
import idc

# IDA 9.x uses PySide6
from PySide6 import QtWidgets


# CUSTOMIZE: Plugin metadata
PLUGIN_NAME = "My Debugger View"
PLUGIN_COMMENT = "Custom debugger view"
PLUGIN_HELP = "Opens a custom view that updates during debugging"
WIDGET_TITLE = "My Debug View"

# CUSTOMIZE: Action configuration
ACTION_ID = "mydebugview:open"
ACTION_NAME = "Open Debug View"
ACTION_HOTKEY = "Alt+Shift+D"


class DebuggerHooks(ida_dbg.DBG_Hooks):
    """Hooks to react to debugger events."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _notify(self):
        """Refresh debugger memory and call the callback."""
        ida_dbg.refresh_debugger_memory()
        self.callback()

    def dbg_suspend_process(self):
        """Called when process is suspended (breakpoint, step, etc.)."""
        self._notify()
        return 0

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        """Called when attached to a process."""
        self._notify()
        return 0

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        """Called when process starts."""
        self._notify()
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        """Called when process exits."""
        self._notify()
        return 0

    def dbg_bpt(self, tid, ea):
        """Called when breakpoint is hit."""
        return 0

    def dbg_step_into(self):
        """Called after step into."""
        return 0

    def dbg_step_over(self):
        """Called after step over."""
        return 0


class DebugViewForm(ida_kernwin.PluginForm):
    """Custom debugger view form."""

    def __init__(self):
        super().__init__()
        self.hooks: Optional[DebuggerHooks] = None
        self.text_widget: Optional[QtWidgets.QTextEdit] = None

    def OnCreate(self, form):
        """Called when the form is created."""
        self.parent = self.FormToPyQtWidget(form)
        self._create_ui()
        self._install_hooks()
        self.refresh_view()

    def _create_ui(self):
        """Create the UI layout."""
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # CUSTOMIZE: Add your UI widgets here

        # Toolbar
        toolbar = QtWidgets.QHBoxLayout()
        refresh_btn = QtWidgets.QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_view)
        toolbar.addWidget(refresh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Main content area
        self.text_widget = QtWidgets.QTextEdit()
        self.text_widget.setReadOnly(True)
        self.text_widget.setFontFamily("Courier")
        layout.addWidget(self.text_widget)

        self.parent.setLayout(layout)

    def _install_hooks(self):
        """Install debugger hooks."""
        self.hooks = DebuggerHooks(self.refresh_view)
        self.hooks.hook()

    def OnClose(self, form):
        """Called when form is closed."""
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None

    def refresh_view(self):
        """Refresh the view content."""
        if not self.text_widget:
            return

        # Check if we're in a debugging session
        if not ida_dbg.is_debugger_on():
            self.text_widget.setPlainText("Debugger not active")
            return

        # Check if process is suspended
        if not self._is_process_suspended():
            self.text_widget.setPlainText("Process running...")
            return

        # CUSTOMIZE: Generate your view content here
        content = self._generate_content()
        self.text_widget.setPlainText(content)

    def _is_process_suspended(self) -> bool:
        """Check if the debugged process is suspended."""
        try:
            # Try to read a register - will fail if not suspended
            idc.get_reg_value("EIP") or idc.get_reg_value("RIP")
            return True
        except:
            return False

    def _generate_content(self) -> str:
        """
        Generate the view content.

        CUSTOMIZE: Implement your view logic here.
        """
        lines = []

        # Example: Show current registers
        lines.append("=== Current State ===")
        lines.append("")

        # Try to get instruction pointer
        try:
            if ida_idaapi.inf_is_64bit():
                ip = idc.get_reg_value("RIP")
                sp = idc.get_reg_value("RSP")
                lines.append(f"RIP: {ip:#018x}")
                lines.append(f"RSP: {sp:#018x}")
            else:
                ip = idc.get_reg_value("EIP")
                sp = idc.get_reg_value("ESP")
                lines.append(f"EIP: {ip:#010x}")
                lines.append(f"ESP: {sp:#010x}")
        except Exception as e:
            lines.append(f"Error reading registers: {e}")

        # CUSTOMIZE: Add more content
        # - Stack contents
        # - Memory regions
        # - Custom analysis

        return '\n'.join(lines)


class OpenViewHandler(ida_kernwin.action_handler_t):
    """Handler to open the debug view."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.open_view()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class DebugViewPlugin(ida_idaapi.plugin_t):
    """Main plugin class."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.form: Optional[DebugViewForm] = None

    def init(self) -> int:
        """Initialize the plugin."""
        # Register action
        action_desc = ida_kernwin.action_desc_t(
            ACTION_ID,
            ACTION_NAME,
            OpenViewHandler(self),
            ACTION_HOTKEY,
            PLUGIN_COMMENT,
            -1
        )

        if not ida_kernwin.register_action(action_desc):
            ida_kernwin.msg(f"{PLUGIN_NAME}: Failed to register action\n")
            return ida_idaapi.PLUGIN_SKIP

        # Attach to Debugger menu
        ida_kernwin.attach_action_to_menu(
            "Debugger/Debugger windows/",
            ACTION_ID,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.msg(f"{PLUGIN_NAME}: Loaded\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        """Called when plugin is invoked."""
        self.open_view()

    def open_view(self):
        """Open or focus the debug view."""
        # Check if already open
        widget = ida_kernwin.find_widget(WIDGET_TITLE)
        if widget:
            ida_kernwin.activate_widget(widget, True)
            return

        # Create new form
        self.form = DebugViewForm()
        self.form.Show(
            WIDGET_TITLE,
            options=(
                ida_kernwin.PluginForm.WOPN_TAB |
                ida_kernwin.PluginForm.WOPN_RESTORE
            )
        )

        # Position near other debugger windows
        self._set_dock_position()

    def _set_dock_position(self):
        """Set docking position for the view."""
        # Try to dock near existing debugger windows
        for target in ["Stack view", "Locals", "Watches", "General registers"]:
            if ida_kernwin.find_widget(target):
                ida_kernwin.set_dock_pos(WIDGET_TITLE, target, ida_kernwin.DP_RIGHT)
                return

    def term(self) -> None:
        """Clean up when plugin is unloaded."""
        ida_kernwin.detach_action_from_menu(
            "Debugger/Debugger windows/",
            ACTION_ID
        )
        ida_kernwin.unregister_action(ACTION_ID)
        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return DebugViewPlugin()
