"""
Hint Provider Plugin Template

A passive plugin that provides custom hover hints in the disassembly view.
Uses PLUGIN_HIDE to stay loaded without appearing in the Edit/Plugins menu.

Customization points marked with: # CUSTOMIZE
"""

import logging
from typing import Optional, Tuple

import ida_idaapi
import ida_kernwin
import ida_bytes

# Setup logging
logger = logging.getLogger(__name__)


# CUSTOMIZE: Plugin metadata
PLUGIN_NAME = "My Hint Plugin"
PLUGIN_COMMENT = "Provides custom hover hints in disassembly"
PLUGIN_HELP = "Hover over addresses in disassembly to see custom hints"


class HintHook(ida_kernwin.UI_Hooks):
    """Hook to provide custom hover tooltips."""

    def get_custom_viewer_hint(
        self, view, place: Optional[ida_kernwin.place_t]
    ) -> Optional[Tuple[str, int]]:
        """
        Called when user hovers over disassembly.

        Args:
            view: The viewer widget
            place: place_t object with location info (can be None)

        Returns:
            tuple(hint_text, important_lines) or None
            - hint_text: String to display in tooltip
            - important_lines: Number of lines to show without scrolling
        """
        if not place:
            return None

        try:
            # Guard: Only provide hints in disassembly view
            widget = ida_kernwin.get_current_widget()
            widget_type = ida_kernwin.get_widget_type(widget)
            if widget_type != ida_kernwin.BWN_DISASM:
                return None

            ea = place.toea()

            # CUSTOMIZE: Add your hint logic here
            hint_lines = self._generate_hint(ea)
            if not hint_lines:
                return None

            # Return hint text and number of important lines
            return hint_lines, min(5, hint_lines.count('\n') + 1)

        except Exception as e:
            logger.warning("Hint generation failed: %s", e, exc_info=True)
            return None

    def _generate_hint(self, ea: int) -> Optional[str]:
        """
        Generate hint text for the given address.

        CUSTOMIZE: Implement your hint logic here.

        Args:
            ea: Address being hovered

        Returns:
            Hint text string or None
        """
        # Example: Show address info
        lines = []
        lines.append(f"Address: {ea:#x}")

        # Get item size
        size = ida_bytes.get_item_size(ea)
        if size > 0:
            lines.append(f"Size: {size} bytes")

        # CUSTOMIZE: Add more information
        # - Function calls from this address
        # - Cross-references
        # - Data type information
        # - Custom analysis results

        return '\n'.join(lines) if lines else None


class HintPlugin(ida_idaapi.plugin_t):
    """
    Main plugin class.

    Uses PLUGIN_HIDE to stay resident without menu entry.
    All functionality is through the hint hook.
    """

    # PLUGIN_KEEP: Stay resident in memory
    # PLUGIN_HIDE: Don't show in Edit/Plugins menu
    flags = ida_idaapi.PLUGIN_KEEP | ida_idaapi.PLUGIN_HIDE
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""  # No hotkey needed for passive plugin

    def __init__(self):
        super().__init__()
        self.hooks: Optional[HintHook] = None

    def init(self) -> int:
        """Initialize the plugin and install hooks."""
        self.hooks = HintHook()
        if self.hooks.hook():
            ida_kernwin.msg(f"{PLUGIN_NAME}: Loaded\n")
            return ida_idaapi.PLUGIN_KEEP
        else:
            ida_kernwin.msg(f"{PLUGIN_NAME}: Failed to install hooks\n")
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg: int) -> None:
        """
        Called when plugin is invoked.

        For passive plugins, this is typically not used.
        """
        pass

    def term(self) -> None:
        """Clean up when plugin is unloaded."""
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return HintPlugin()
