"""
Multi-View MVC IDA Plugin Template

A complex plugin with multiple coordinated views and MVC architecture.
Use this template for plugins with rich UI and shared state.

Customization points marked with: # CUSTOMIZE
"""

import ida_idaapi
import ida_kernwin
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QListWidget,
    QTextEdit,
    QSplitter,
    QWidget,
)


# CUSTOMIZE: Plugin metadata
PLUGIN_NAME = "My Multi-View Plugin"
PLUGIN_COMMENT = "A plugin with MVC architecture"
PLUGIN_HELP = "This plugin demonstrates multi-view coordination"

# CUSTOMIZE: Action configuration
ACTION_ID = "myplugin:show_main"
ACTION_NAME = "Show Multi-View"
ACTION_HOTKEY = "Ctrl+Shift+V"
ACTION_TOOLTIP = "Display the multi-view window"

WIDGET_TITLE = "Multi-View Plugin"


# =============================================================================
# Model
# =============================================================================


class PluginModel(QObject):
    """
    Data model for the plugin.

    Holds shared state and emits signals when data changes.
    """

    # CUSTOMIZE: Define signals for state changes
    items_changed = Signal()
    selection_changed = Signal(object)  # Emits selected item

    def __init__(self):
        super().__init__()
        # CUSTOMIZE: Initialize your data structures
        self._items = []
        self._selected_item = None

    @property
    def items(self):
        return self._items

    @items.setter
    def items(self, value):
        self._items = value
        self.items_changed.emit()

    @property
    def selected_item(self):
        return self._selected_item

    @selected_item.setter
    def selected_item(self, value):
        self._selected_item = value
        self.selection_changed.emit(value)

    def load_data(self):
        """Load or refresh data."""
        # CUSTOMIZE: Populate with your data
        self.items = [
            {"id": 1, "name": "Item One", "description": "First item description"},
            {"id": 2, "name": "Item Two", "description": "Second item description"},
            {"id": 3, "name": "Item Three", "description": "Third item description"},
        ]

    def get_item_by_id(self, item_id):
        """Find item by ID."""
        for item in self._items:
            if item.get("id") == item_id:
                return item
        return None


# =============================================================================
# Views
# =============================================================================


class ItemListView(QWidget):
    """List view showing all items."""

    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
        self._setup_ui()
        self._connect_signals()
        self._refresh()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.label = QLabel("<b>Items</b>")
        layout.addWidget(self.label)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        button_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        button_layout.addWidget(self.refresh_btn)
        layout.addLayout(button_layout)

    def _connect_signals(self):
        self.model.items_changed.connect(self._refresh)
        self.list_widget.currentRowChanged.connect(self._on_selection_changed)
        self.refresh_btn.clicked.connect(self._on_refresh_clicked)

    def _refresh(self):
        self.list_widget.clear()
        for item in self.model.items:
            self.list_widget.addItem(item.get("name", "Unknown"))

    def _on_selection_changed(self, row):
        if 0 <= row < len(self.model.items):
            self.model.selected_item = self.model.items[row]

    def _on_refresh_clicked(self):
        self.model.load_data()


class DetailView(QWidget):
    """Detail view showing selected item."""

    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.label = QLabel("<b>Details</b>")
        layout.addWidget(self.label)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlaceholderText("Select an item to view details")
        layout.addWidget(self.text_edit)

    def _connect_signals(self):
        self.model.selection_changed.connect(self._on_selection_changed)

    def _on_selection_changed(self, item):
        if item:
            # CUSTOMIZE: Format item details
            text = f"ID: {item.get('id')}\n"
            text += f"Name: {item.get('name')}\n"
            text += f"Description: {item.get('description')}\n"
            self.text_edit.setText(text)
        else:
            self.text_edit.clear()


# =============================================================================
# Main Form (Controller)
# =============================================================================


class MainPluginForm(ida_kernwin.PluginForm):
    """Main plugin form that coordinates views."""

    def __init__(self, model):
        super().__init__()
        self.model = model

    def OnCreate(self, form):
        """Create the form UI."""
        self.parent = self.FormToPyQtWidget(form)
        self._setup_ui()
        # Load initial data
        self.model.load_data()

    def _setup_ui(self):
        layout = QVBoxLayout(self.parent)

        # Header
        header = QLabel(f"<h3>{PLUGIN_NAME}</h3>")
        layout.addWidget(header)

        # Splitter with list and detail views
        splitter = QSplitter(Qt.Horizontal)

        self.list_view = ItemListView(self.model)
        splitter.addWidget(self.list_view)

        self.detail_view = DetailView(self.model)
        splitter.addWidget(self.detail_view)

        # Set initial sizes (30% / 70%)
        splitter.setSizes([300, 700])

        layout.addWidget(splitter)

    def OnClose(self, form):
        """Clean up on close."""
        pass


# =============================================================================
# UI Hooks (Optional)
# =============================================================================


class PluginUIHooks(ida_kernwin.UI_Hooks):
    """UI hooks for responding to IDA events."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        """Called when IDA is fully initialized."""
        # CUSTOMIZE: Initialization that requires IDA to be ready
        pass

    def widget_visible(self, widget):
        """Called when a widget becomes visible."""
        pass


# =============================================================================
# Plugin
# =============================================================================


class ShowMainHandler(ida_kernwin.action_handler_t):
    """Handler to show the main window."""

    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.show_main()
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
        # Create shared model
        self.model = PluginModel()
        self.form = None

        # Install UI hooks
        self.ui_hooks = PluginUIHooks(self)
        self.ui_hooks.hook()

        # Register action
        action_desc = ida_kernwin.action_desc_t(
            ACTION_ID,
            ACTION_NAME,
            ShowMainHandler(self),
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

        ida_kernwin.msg(f"{PLUGIN_NAME}: Loaded\n")
        return ida_idaapi.PLUGIN_KEEP

    def show_main(self):
        """Show or focus the main window."""
        widget = ida_kernwin.find_widget(WIDGET_TITLE)

        if widget:
            ida_kernwin.activate_widget(widget, True)
        else:
            self.form = MainPluginForm(self.model)
            self.form.Show(
                WIDGET_TITLE,
                options=ida_kernwin.PluginForm.WOPN_PERSIST
            )

    def run(self, arg):
        """Called when plugin is invoked directly."""
        self.show_main()

    def term(self):
        """Clean up when plugin is unloaded."""
        # Close form
        widget = ida_kernwin.find_widget(WIDGET_TITLE)
        if widget:
            ida_kernwin.close_widget(widget, 0)

        # Unhook UI hooks
        self.ui_hooks.unhook()

        # Unregister action
        ida_kernwin.detach_action_from_menu("View/", ACTION_ID)
        ida_kernwin.unregister_action(ACTION_ID)

        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return MyPlugin()
