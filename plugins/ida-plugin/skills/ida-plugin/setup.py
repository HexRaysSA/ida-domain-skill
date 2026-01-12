#!/usr/bin/env python3
"""
IDA Plugin Skill - Setup Script

Validates that the hcli tool is available for plugin packaging and linting.
"""

import shutil
import subprocess
import sys


def check_hcli() -> bool:
    """Check if hcli is available in PATH."""
    hcli_path = shutil.which("hcli")
    if not hcli_path:
        return False

    # Verify it runs
    try:
        result = subprocess.run(
            ["hcli", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def main() -> int:
    print("IDA Plugin Skill - Setup")
    print("=" * 40)
    print()

    print("Checking for hcli...")

    if check_hcli():
        hcli_path = shutil.which("hcli")
        print(f"  Found: {hcli_path}")

        # Get version
        result = subprocess.run(
            ["hcli", "--version"],
            capture_output=True,
            text=True
        )
        version = result.stdout.strip() or result.stderr.strip()
        if version:
            print(f"  Version: {version}")

        print()
        print("Setup complete. Ready to create IDA plugins.")
        return 0
    else:
        print("  ERROR: hcli not found in PATH")
        print()
        print("hcli is required for plugin packaging and validation.")
        print("It is included with IDA Pro 9.x installation.")
        print()
        print("To fix:")
        print("  1. Ensure IDA Pro 9.x is installed")
        print("  2. Add the IDA installation directory to your PATH")
        print("     - macOS: /Applications/IDA Professional 9.x.app/Contents/MacOS")
        print("     - Linux: /opt/idapro-9.x")
        print("     - Windows: C:\\Program Files\\IDA Professional 9.x")
        return 1


if __name__ == "__main__":
    sys.exit(main())
