#!/usr/bin/env python3
"""Fail-closed entrypoint for the hardened DaVinci Resolve MCP fork.

This is the only supported MCP server entrypoint in strict mode. It bootstraps
the repository package path, installs the network and AI-denial policies, and
only then imports or executes the upstream server module.
"""
from __future__ import annotations

import json
import os
import runpy
import socket
import subprocess
import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.security_policy import install_strict_security_policy
from src.utils.strict_ai_policy import install_strict_ai_policy


# Order matters: close the network first, then install import-time AI guards.
install_strict_security_policy()
install_strict_ai_policy()


def _probe() -> None:
    """Verify both policies without loading MCP or Resolve modules."""
    checks: dict[str, bool] = {}

    checks["updates_disabled"] = (
        os.environ.get("DAVINCI_RESOLVE_MCP_UPDATE_CHECK") == "0"
        and os.environ.get("DAVINCI_RESOLVE_MCP_UPDATE_MODE") == "never"
    )
    checks["strict_ai_environment"] = (
        os.environ.get("DAVINCI_MCP_STRICT_AI_DISABLED") == "1"
        and os.environ.get("HF_HUB_OFFLINE") == "1"
        and os.environ.get("TRANSFORMERS_OFFLINE") == "1"
    )

    try:
        socket.getaddrinfo("example.com", 443)
    except PermissionError:
        checks["external_dns_blocked"] = True
    else:
        checks["external_dns_blocked"] = False

    try:
        socket.create_connection(("1.1.1.1", 443), timeout=0.01)
    except PermissionError:
        checks["external_tcp_blocked"] = True
    else:
        checks["external_tcp_blocked"] = False

    try:
        subprocess.run(
            ["curl", "https://example.com"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except PermissionError:
        checks["network_subprocess_blocked"] = True
    else:
        checks["network_subprocess_blocked"] = False

    try:
        checks["localhost_allowed"] = bool(socket.getaddrinfo("localhost", 8000))
    except Exception:
        checks["localhost_allowed"] = False

    try:
        from src.utils import embeddings

        embeddings.embed_texts(["untrusted media text"])
    except PermissionError as exc:
        checks["embeddings_blocked"] = "STRICT_AI_DISABLED" in str(exc)
    except Exception:
        checks["embeddings_blocked"] = False
    else:
        checks["embeddings_blocked"] = False

    try:
        from src.utils import media_analysis

        media_analysis.execute_plan_async({})
    except PermissionError as exc:
        checks["media_analysis_blocked"] = "STRICT_AI_DISABLED" in str(exc)
    except Exception:
        checks["media_analysis_blocked"] = False
    else:
        checks["media_analysis_blocked"] = False

    payload = {
        "success": all(checks.values()),
        "entrypoint": "src/strict_server.py",
        "checks": checks,
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    raise SystemExit(0 if payload["success"] else 1)


if os.environ.get("DAVINCI_MCP_STRICT_PROBE") == "1":
    _probe()

server_path = CURRENT_FILE.with_name("server.py")
runpy.run_path(str(server_path), run_name="__main__")
