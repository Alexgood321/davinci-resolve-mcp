#!/usr/bin/env python3
"""Offline creative entrypoint for the hardened DaVinci Resolve MCP fork.

The creative profile keeps the same fail-closed network and prompt-injection
boundary as strict mode, but does not install the strict AI-denial policy.
This enables local media analysis, frame extraction, host_chat_paths handoff,
local transcription backends, edit_engine planning, and timeline execution.

External network access, URL-bearing subprocesses, shell=True, update checks,
and automatic model downloads remain blocked.
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

from src.utils.security_policy import (
    _validate_command,
    install_strict_security_policy,
)


# A parent process may have launched the strict profile previously. The creative
# MCP is a separate process and must not inherit the strict-AI capability flag.
os.environ.pop("DAVINCI_MCP_STRICT_AI_DISABLED", None)
os.environ["DAVINCI_MCP_SECURITY_PROFILE"] = "creative"

# Keep model ecosystems offline. Local, already-installed models remain usable;
# downloads must be performed explicitly outside the MCP security boundary.
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"

# Install the same network/subprocess/prompt hardening used by strict mode.
install_strict_security_policy()


def _probe() -> None:
    """Verify creative capabilities without loading Resolve itself."""
    checks: dict[str, bool] = {}

    checks["updates_disabled"] = (
        os.environ.get("DAVINCI_RESOLVE_MCP_UPDATE_CHECK") == "0"
        and os.environ.get("DAVINCI_RESOLVE_MCP_UPDATE_MODE") == "never"
    )
    checks["creative_profile_environment"] = (
        os.environ.get("DAVINCI_MCP_SECURITY_PROFILE") == "creative"
        and os.environ.get("DAVINCI_MCP_STRICT_AI_DISABLED") != "1"
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
        _validate_command(["ffmpeg", "-i", "/tmp/input.mov", "/tmp/output.mov"])
    except Exception:
        checks["local_media_subprocess_allowed"] = False
    else:
        checks["local_media_subprocess_allowed"] = True

    try:
        from src.utils import media_analysis

        execute = media_analysis.execute_plan_async
        checks["media_analysis_enabled"] = (
            callable(execute)
            and not bool(getattr(execute, "__davinci_strict_ai_blocked__", False))
        )
        checks["host_chat_paths_enabled"] = (
            getattr(media_analysis, "HOST_CHAT_PATHS_PROVIDER", None)
            == "host_chat_paths"
        )
    except Exception:
        checks["media_analysis_enabled"] = False
        checks["host_chat_paths_enabled"] = False

    payload = {
        "success": all(checks.values()),
        "entrypoint": "src/creative_server.py",
        "profile": "creative",
        "network": "blocked_by_runtime",
        "checks": checks,
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    raise SystemExit(0 if payload["success"] else 1)


if os.environ.get("DAVINCI_MCP_CREATIVE_PROBE") == "1":
    _probe()

server_path = CURRENT_FILE.with_name("server.py")
runpy.run_path(str(server_path), run_name="__main__")
