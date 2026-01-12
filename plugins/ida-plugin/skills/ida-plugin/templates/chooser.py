"""
Chooser-Based IDA Plugin Template

A plugin with a list/table interface for data browsing and selection.
Use this template for plugins that display lists of items.

Customization points marked with: # CUSTOMIZE
"""

import ida_idaapi
import ida_kernwin


# CUSTOMIZE: Plugin metadata
PLUGIN_NAME = "My Chooser Plugin"
PLUGIN_COMMENT = "A plugin with a chooser interface"
PLUGIN_HELP = "This plugin demonstrates chooser usage"

# CUSTOMIZE: Action configuration
ACTION_ID = "myplugin:show_chooser"
ACTION_NAME = "Show My Chooser"
ACTION_HOTKEY = "Ctrl+Shift+L"
ACTION_TOOLTIP = "Display the chooser window"

# Chooser window title
CHOOSER_TITLE = "My Data Browser"


class MyChooser(ida_kernwin.Choose):
    """
    Chooser (list/table) widget.

    Displays data in a tabular format with selection support.
    """

    def __init__(self, title, items=None):
        # CUSTOMIZE: Define columns - list of [name, width] pairs
        columns = [
            ["Address", 16],
            ["Name", 30],
            ["Value", 20],
        ]

        ida_kernwin.Choose.__init__(
            self,
            title,
            columns,
            flags=ida_kernwin.Choose.CH_RESTORE  # Remember position
            | ida_kernwin.Choose.CH_CAN_REFRESH  # Allow refresh
        )

        # CUSTOMIZE: Initialize your data
        self.items = items if items is not None else []
        self.icon = -1

    def OnInit(self):
        """Called when chooser is initialized."""
        # CUSTOMIZE: Load initial data if not provided
        if not self.items:
            self._load_data()
        return True

    def OnGetSize(self):
        """Return the number of items."""
        return len(self.items)

    def OnGetLine(self, n):
        """Return the nth item as a list of column values."""
        if 0 <= n < len(self.items):
            item = self.items[n]
            # CUSTOMIZE: Return column values for this item
            return [
                f"0x{item.get('address', 0):08X}",
                item.get('name', ''),
                str(item.get('value', '')),
            ]
        return ["", "", ""]

    def OnSelectLine(self, n):
        """Called when user double-clicks or presses Enter on a line."""
        if 0 <= n < len(self.items):
            item = self.items[n]
            # CUSTOMIZE: Handle selection (e.g., jump to address)
            address = item.get('address')
            if address:
                ida_kernwin.jumpto(address)
                ida_kernwin.msg(f"Jumped to 0x{address:08X}\n")
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnRefresh(self, n):
        """Called when user requests refresh."""
        self._load_data()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        """Called when chooser is closed."""
        # CUSTOMIZE: Clean up resources
        pass

    def OnGetIcon(self, n):
        """Return icon for the nth item (-1 for none)."""
        return self.icon

    def OnGetLineAttr(self, n):
        """Return display attributes for the nth item."""
        # CUSTOMIZE: Return [color, flags] or None
        # Example: highlight certain items
        # if self.items[n].get('important'):
        #     return [0x0000FF, ida_kernwin.CHITEM_BOLD]
        return None

    def _load_data(self):
        """Load or reload data."""
        # CUSTOMIZE: Populate self.items with your data
        # Each item is a dict with keys matching your columns
        self.items = [
            {"address": 0x00401000, "name": "main", "value": "entry point"},
            {"address": 0x00401100, "name": "init", "value": "initialization"},
            {"address": 0x00401200, "name": "process", "value": "main logic"},
        ]


class ShowChooserHandler(ida_kernwin.action_handler_t):
    """Handler to show the chooser."""

    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        """Show the chooser."""
        self.plugin.show_chooser()
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
        self.chooser = None

        # Register action
        action_desc = ida_kernwin.action_desc_t(
            ACTION_ID,
            ACTION_NAME,
            ShowChooserHandler(self),
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

    def show_chooser(self):
        """Display the chooser window."""
        self.chooser = MyChooser(CHOOSER_TITLE)
        self.chooser.Show()

    def run(self, arg):
        """Called when plugin is invoked directly."""
        self.show_chooser()

    def term(self):
        """Clean up when plugin is unloaded."""
        # Close chooser if open
        if self.chooser:
            self.chooser.Close()
            self.chooser = None

        # Unregister action
        ida_kernwin.detach_action_from_menu("View/", ACTION_ID)
        ida_kernwin.unregister_action(ACTION_ID)

        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return MyPlugin()
