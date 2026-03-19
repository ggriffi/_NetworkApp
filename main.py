#!/usr/bin/env python3
"""
NetProbe - Network Analysis Utility
Entry point
"""
import sys
import os

# ── Path setup: works when run as script, frozen exe, or from any cwd ──
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

# Also add cwd in case user runs: python netprobe/main.py
_cwd = os.getcwd()
if _cwd not in sys.path:
    sys.path.insert(0, _cwd)

# Verify we can see the ui package before importing
_ui_path = os.path.join(_here, 'ui')
_core_path = os.path.join(_here, 'core')
if not os.path.isdir(_ui_path):
    print(f"ERROR: Cannot find 'ui' folder. Expected it at:\n  {_ui_path}")
    print(f"\nMake sure you run this script from the netprobe/ directory:")
    print(f"  cd netprobe")
    print(f"  python main.py")
    sys.exit(1)
if not os.path.isdir(_core_path):
    print(f"ERROR: Cannot find 'core' folder. Expected it at:\n  {_core_path}")
    sys.exit(1)

from ui.app import NetProbeApp

if __name__ == "__main__":
    app = NetProbeApp()
    app.run()
