"""Regression tests for the offline creative MCP profile."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import install_strict

ROOT = Path(__file__).resolve().parents[1]


def test_creative_probe_keeps_network_closed_and_media_analysis_enabled():
    env = os.environ.copy()
    env["DAVINCI_MCP_CREATIVE_PROBE"] = "1"
    # Simulate a parent process that previously launched the strict profile.
    env["DAVINCI_MCP_STRICT_AI_DISABLED"] = "1"

    result = subprocess.run(
        [sys.executable, str(ROOT / "src" / "creative_server.py")],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["success"] is True
    assert payload["profile"] == "creative"
    assert payload["network"] == "blocked_by_runtime"
    assert all(payload["checks"].values())
    assert payload["checks"]["media_analysis_enabled"] is True
    assert payload["checks"]["host_chat_paths_enabled"] is True
    assert payload["checks"]["external_tcp_blocked"] is True


def test_installer_renders_exactly_one_enabled_profile():
    python_path = ROOT / ".venv" / "bin" / "python"

    for active in ("safe", "creative"):
        rendered = install_strict._render("", python_path, active)
        parsed = tomllib.loads(rendered)
        servers = parsed["mcp_servers"]

        assert servers["davinci_resolve_strict"]["enabled"] is (active == "safe")
        assert servers["davinci_resolve_creative"]["enabled"] is (active == "creative")
        assert servers["davinci_resolve_creative"]["args"] == [
            str(ROOT / "src" / "creative_server.py")
        ]
        assert (
            servers["davinci_resolve_creative"]["env"]["DAVINCI_MCP_SECURITY_PROFILE"]
            == "creative"
        )


def test_installer_replaces_old_managed_strict_block_when_switching_to_creative():
    python_path = ROOT / ".venv" / "bin" / "python"
    old = install_strict._managed_block("safe", python_path, enabled=True)

    rendered = install_strict._render(old, python_path, "creative")

    assert rendered.count("# BEGIN DAVINCI_RESOLVE_MCP_STRICT") == 1
    assert rendered.count("# BEGIN DAVINCI_RESOLVE_MCP_CREATIVE") == 1
    parsed = tomllib.loads(rendered)
    assert parsed["mcp_servers"]["davinci_resolve_strict"]["enabled"] is False
    assert parsed["mcp_servers"]["davinci_resolve_creative"]["enabled"] is True
