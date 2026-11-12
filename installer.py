#!/usr/bin/env python3
"""Sentinel - Graphical Setup Wizard Launcher.
Run directly or double-click to launch the native Linux setup wizard.
"""

import os
import sys

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

if __name__ == "__main__":
    try:
        from ui.installer_window import run_installer_gui
        sys.exit(run_installer_gui() or 0)
    except (ImportError, ValueError) as err:
        print(f"[-] Error: Could not launch graphical setup wizard ({err}).", file=sys.stderr)
        print("[-] Required GUI libraries (GTK4 / Libadwaita / PyGObject) are not installed.", file=sys.stderr)
        print("[-] Please run './install' to automatically install all dependencies.", file=sys.stderr)
        sys.exit(1)
