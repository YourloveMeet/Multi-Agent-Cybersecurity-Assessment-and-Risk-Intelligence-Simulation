"""Entry point for running CyberSentinel via `python -m cybersentinel`."""

import sys

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from cybersentinel.cli.app import main

if __name__ == "__main__":
    sys.exit(main())
