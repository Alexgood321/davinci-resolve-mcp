#!/usr/bin/env python3
"""
Strict-only DaVinci Resolve MCP installer.

Never installs the normal server entrypoint.
Always points MCP clients to strict_server.py.
"""

from pathlib import Path
import json
import os
import platform
import sys


ROOT = Path(__file__).resolve().parent
PYTHON = Path(sys.executable)
STRICT_SERVER = ROOT / "src" / "strict_server.py"


def build_entry():
    return {
        "command": str(PYTHON),
        "args": [str(STRICT_SERVER)],
        "env": {
            "DAVINCI_MCP_SECURITY_PROFILE": "safe",
            "DAVINCI_RESOLVE_MCP_UPDATE_CHECK": "0",
            "DAVINCI_RESOLVE_MCP_UPDATE_MODE": "never",
        },
    }


def main():
    if not STRICT_SERVER.exists():
        raise SystemExit("strict_server.py not found")

    entry = build_entry()

    print(json.dumps({
        "installer": "strict",
        "platform": platform.system(),
        "entrypoint": str(STRICT_SERVER),
        "config": entry,
        "network": "blocked_by_runtime",
        "profile": "safe",
    }, indent=2))


if __name__ == "__main__":
    main()
