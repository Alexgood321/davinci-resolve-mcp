#!/usr/bin/env python3
"""Hardened DaVinci Resolve MCP profile installer for Codex.

The installer manages two mutually exclusive MCP profiles in
``~/.codex/config.toml``:

- ``safe``: strict offline control with AI/media analysis disabled.
- ``creative``: the same offline network and prompt-injection boundary, with
  local media analysis, host_chat_paths, local transcription, edit_engine, and
  timeline editing enabled.

Both tables are retained in the config, but exactly one is enabled at a time.
Existing configuration is backed up and validated with Python's TOML parser
before being committed atomically.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path.home() / ".codex" / "config.toml"

PROFILES: dict[str, dict[str, Any]] = {
    "safe": {
        "server_name": "davinci_resolve_strict",
        "entrypoint": (ROOT / "src" / "strict_server.py").resolve(),
        "begin_marker": "# BEGIN DAVINCI_RESOLVE_MCP_STRICT",
        "end_marker": "# END DAVINCI_RESOLVE_MCP_STRICT",
        "env": {
            "DAVINCI_MCP_SECURITY_PROFILE": "safe",
            "DAVINCI_RESOLVE_MCP_UPDATE_CHECK": "0",
            "DAVINCI_RESOLVE_MCP_UPDATE_MODE": "never",
            "DAVINCI_RESOLVE_MCP_AUTO_UPDATE": "0",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
            "TORCH_HOME": str((ROOT / ".strict-cache-disabled").resolve()),
        },
    },
    "creative": {
        "server_name": "davinci_resolve_creative",
        "entrypoint": (ROOT / "src" / "creative_server.py").resolve(),
        "begin_marker": "# BEGIN DAVINCI_RESOLVE_MCP_CREATIVE",
        "end_marker": "# END DAVINCI_RESOLVE_MCP_CREATIVE",
        "env": {
            "DAVINCI_MCP_SECURITY_PROFILE": "creative",
            "DAVINCI_RESOLVE_MCP_UPDATE_CHECK": "0",
            "DAVINCI_RESOLVE_MCP_UPDATE_MODE": "never",
            "DAVINCI_RESOLVE_MCP_AUTO_UPDATE": "0",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
        },
    },
}


def _managed_pattern(profile: dict[str, Any]) -> re.Pattern[str]:
    return re.compile(
        rf"(?ms)^\s*{re.escape(profile['begin_marker'])}\n.*?"
        rf"^\s*{re.escape(profile['end_marker'])}\s*\n?"
    )


def _table_pattern(server_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?m)^\s*\[mcp_servers\.(?:{re.escape(server_name)}|"
        rf"\"{re.escape(server_name)}\")\]\s*$"
    )


def _toml_string(value: str) -> str:
    """Return a TOML-compatible quoted string."""
    return json.dumps(value, ensure_ascii=False)


def _venv_python() -> Path:
    if os.name == "nt":
        candidate = ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = ROOT / ".venv" / "bin" / "python"

    # Do not resolve the executable symlink. On macOS a venv Python commonly
    # points at the framework interpreter; resolving it would make Codex bypass
    # the venv and lose the project's installed dependencies.
    if not candidate.is_file():
        raise SystemExit(f"Hardened venv Python not found: {candidate}")
    return candidate


def _managed_block(profile_name: str, python_path: Path, *, enabled: bool) -> str:
    profile = PROFILES[profile_name]
    server_name = profile["server_name"]
    entrypoint = profile["entrypoint"]
    lines = [
        profile["begin_marker"],
        f"[mcp_servers.{server_name}]",
        f"command = {_toml_string(str(python_path))}",
        f"args = [{_toml_string(str(entrypoint))}]",
        f"enabled = {'true' if enabled else 'false'}",
        "",
        f"[mcp_servers.{server_name}.env]",
    ]
    for key, value in profile["env"].items():
        lines.append(f"{key} = {_toml_string(str(value))}")
    lines.extend([profile["end_marker"], ""])
    return "\n".join(lines)


def _read_existing(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _render(existing: str, python_path: Path, active_profile: str) -> str:
    without_managed = existing
    for profile in PROFILES.values():
        without_managed = _managed_pattern(profile).sub("", without_managed)

    for profile in PROFILES.values():
        server_name = profile["server_name"]
        if _table_pattern(server_name).search(without_managed):
            raise SystemExit(
                f"Refusing to create duplicate [mcp_servers.{server_name}] table. "
                "Remove or rename the unmanaged table first."
            )

    blocks = [
        _managed_block(name, python_path, enabled=(name == active_profile))
        for name in ("safe", "creative")
    ]
    managed = "\n".join(blocks)
    prefix = without_managed.rstrip()
    rendered = f"{prefix}\n\n{managed}" if prefix else managed
    try:
        parsed = tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"Refusing to write invalid TOML: {exc}") from exc

    enabled_profiles = [
        name
        for name, profile in PROFILES.items()
        if parsed.get("mcp_servers", {})
        .get(profile["server_name"], {})
        .get("enabled") is True
    ]
    if enabled_profiles != [active_profile]:
        raise SystemExit(
            "Refusing to write ambiguous profile state: expected exactly "
            f"{active_profile!r} enabled, got {enabled_profiles!r}"
        )
    return rendered


def _atomic_write(path: Path, content: str) -> Path | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    old_mode: int | None = None
    if path.exists():
        old_mode = stat.S_IMODE(path.stat().st_mode)
        stamp = time.strftime("%Y%m%dT%H%M%S")
        backup = path.with_name(f"{path.name}.backup-{stamp}")
        shutil.copy2(path, backup)

    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, old_mode if old_mode is not None else 0o600)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)
    return backup


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install or switch hardened DaVinci Resolve MCP profiles for Codex"
    )
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default="safe",
        help="Profile to enable; the other managed profile remains installed but disabled.",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    for name, profile in PROFILES.items():
        entrypoint = profile["entrypoint"]
        if not entrypoint.is_file():
            raise SystemExit(f"{name} entrypoint not found: {entrypoint}")

    python_path = _venv_python()
    config_path = args.config.expanduser().resolve()
    existing = _read_existing(config_path)
    rendered = _render(existing, python_path, args.profile)

    backup = None
    if not args.dry_run:
        backup = _atomic_write(config_path, rendered)
        # Re-read and validate the exact bytes that reached disk.
        tomllib.loads(config_path.read_text(encoding="utf-8"))

    active = PROFILES[args.profile]
    result = {
        "success": True,
        "dry_run": bool(args.dry_run),
        "config_path": str(config_path),
        "backup_path": str(backup) if backup else None,
        "profile": args.profile,
        "active_server_name": active["server_name"],
        "command": str(python_path),
        "entrypoint": str(active["entrypoint"]),
        "network": "blocked_by_runtime",
        "managed_servers": {
            name: {
                "server_name": profile["server_name"],
                "entrypoint": str(profile["entrypoint"]),
                "enabled": name == args.profile,
            }
            for name, profile in PROFILES.items()
        },
        "normal_server_configured": False,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
