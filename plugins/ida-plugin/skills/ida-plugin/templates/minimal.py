"""
Minimal IDA Plugin Template

A simple plugin with a single menu action and optional hotkey.
Use this template for plugins that perform a single task without persistent UI.

Customization points marked with: # CUSTOMIZE
"""

import ida_idaapi
import ida_kernwin


# CUSTOMIZE: Plugin metadata
PLUGIN_NAME = "My Plugin"
PLUGIN_COMMENT = "A minimal IDA plugin"
PLUGIN_HELP = "This plugin demonstrates basic plugin structure"
PLUGIN_HOTKEY = ""  # Global hotkey to invoke run(), or empty string

# CUSTOMIZE: Action configuration
ACTION_ID = "myplugin:main_action"  # Must be unique, prefix with plugin name
ACTION_NAME = "My Plugin Action"
ACTION_HOTKEY = "Ctrl+Shift+M"  # Or None for no hotkey
ACTION_TOOLTIP = "Execute my plugin action"


class MainActionHandler(ida_kernwin.action_handler_t):
    """Handler for the main plugin action."""

    def activate(self, ctx):
        """Called when the action is triggered."""
        # CUSTOMIZE: Your action logic here
        ida_kernwin.msg(f"{PLUGIN_NAME}: Action executed!\n")
        return 1

    def update(self, ctx):
        """Return action availability state."""
        # CUSTOMIZE: Return AST_DISABLE or AST_ENABLE based on context
        # ctx.widget_type, ctx.cur_ea, etc. can be used for context checks
        return ida_kernwin.AST_ENABLE_ALWAYS


class MyPlugin(ida_idaapi.plugin_t):
    """Main plugin class."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        """Initialize the plugin. Called once when IDA loads the plugin."""
        # Register action
        action_desc = ida_kernwin.action_desc_t(
            ACTION_ID,
            ACTION_NAME,
            MainActionHandler(),
            ACTION_HOTKEY,
            ACTION_TOOLTIP,
            -1  # No icon
        )

        if not ida_kernwin.register_action(action_desc):
            ida_kernwin.msg(f"{PLUGIN_NAME}: Failed to register action\n")
            return ida_idaapi.PLUGIN_SKIP

        # Attach to menu
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/",
            ACTION_ID,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.msg(f"{PLUGIN_NAME}: Loaded\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Called when plugin is invoked via menu or hotkey."""
        # CUSTOMIZE: Direct invocation logic (or delegate to action)
        ida_kernwin.msg(f"{PLUGIN_NAME}: run() called with arg={arg}\n")

    def term(self):
        """Clean up when plugin is unloaded."""
        # Detach from menu and unregister action
        ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_ID)
        ida_kernwin.unregister_action(ACTION_ID)
        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return MyPlugin()
