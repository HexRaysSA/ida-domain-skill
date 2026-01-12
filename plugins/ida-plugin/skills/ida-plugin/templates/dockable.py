"""
Dockable Widget IDA Plugin Template

A plugin with a dockable widget that persists in IDA's workspace.
Use this template for plugins that need a persistent UI panel.

Customization points marked with: # CUSTOMIZE
"""

import ida_idaapi
import ida_kernwin
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QWidget,
)


# CUSTOMIZE: Plugin metadata
PLUGIN_NAME = "My Dockable Plugin"
PLUGIN_COMMENT = "A plugin with a dockable widget"
PLUGIN_HELP = "This plugin demonstrates dockable widget usage"

# CUSTOMIZE: Action configuration
ACTION_ID = "myplugin:toggle_widget"
ACTION_NAME = "Show My Widget"
ACTION_HOTKEY = "Ctrl+Shift+W"
ACTION_TOOLTIP = "Toggle the plugin widget"

# Widget form title (used for window management)
WIDGET_TITLE = "My Plugin Widget"


class MyPluginForm(ida_kernwin.PluginForm):
    """Dockable widget form."""

    def OnCreate(self, form):
        """Called when the widget is created."""
        # Get the Qt widget
        self.parent = self.FormToPyQtWidget(form)
        self._create_ui()

    def _create_ui(self):
        """Create the widget UI."""
        layout = QVBoxLayout()

        # CUSTOMIZE: Add your UI elements here

        # Header
        header = QLabel(f"<h3>{PLUGIN_NAME}</h3>")
        layout.addWidget(header)

        # Content area
        self.text_area = QTextEdit()
        self.text_area.setPlaceholderText("Output will appear here...")
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        # Button row
        button_layout = QHBoxLayout()

        self.run_button = QPushButton("Run Analysis")
        self.run_button.clicked.connect(self._on_run_clicked)
        button_layout.addWidget(self.run_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self._on_clear_clicked)
        button_layout.addWidget(self.clear_button)

        layout.addLayout(button_layout)

        self.parent.setLayout(layout)

    def _on_run_clicked(self):
        """Handle Run button click."""
        # CUSTOMIZE: Your analysis logic here
        self.text_area.append("Running analysis...")
        self.text_area.append("Analysis complete!")

    def _on_clear_clicked(self):
        """Handle Clear button click."""
        self.text_area.clear()

    def OnClose(self, form):
        """Called when the widget is closed."""
        # CUSTOMIZE: Clean up any resources
        pass


class ToggleWidgetHandler(ida_kernwin.action_handler_t):
    """Handler to toggle the dockable widget."""

    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        """Toggle widget visibility."""
        self.plugin.toggle_widget()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class MyPlugin(ida_idaapi.plugin_t):
    """Main plugin class."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        """Initialize the plugin."""
        self.form = None

        # Register toggle action
        action_desc = ida_kernwin.action_desc_t(
            ACTION_ID,
            ACTION_NAME,
            ToggleWidgetHandler(self),
            ACTION_HOTKEY,
            ACTION_TOOLTIP,
            -1
        )

        if not ida_kernwin.register_action(action_desc):
            ida_kernwin.msg(f"{PLUGIN_NAME}: Failed to register action\n")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.attach_action_to_menu(
            "View/",
            ACTION_ID,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.msg(f"{PLUGIN_NAME}: Loaded (use {ACTION_HOTKEY} to toggle)\n")
        return ida_idaapi.PLUGIN_KEEP

    def toggle_widget(self):
        """Show or hide the dockable widget."""
        # Check if widget already exists
        widget = ida_kernwin.find_widget(WIDGET_TITLE)

        if widget:
            # Widget exists, close it
            ida_kernwin.close_widget(widget, 0)
            self.form = None
        else:
            # Create and show widget
            self.form = MyPluginForm()
            self.form.Show(
                WIDGET_TITLE,
                options=ida_kernwin.PluginForm.WOPN_PERSIST
            )

    def run(self, arg):
        """Called when plugin is invoked directly."""
        self.toggle_widget()

    def term(self):
        """Clean up when plugin is unloaded."""
        # Close widget if open
        widget = ida_kernwin.find_widget(WIDGET_TITLE)
        if widget:
            ida_kernwin.close_widget(widget, 0)

        # Unregister action
        ida_kernwin.detach_action_from_menu("View/", ACTION_ID)
        ida_kernwin.unregister_action(ACTION_ID)

        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return MyPlugin()
