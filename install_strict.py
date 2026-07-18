#!/usr/bin/env python3
"""Strict-only installer for Codex.

This installer writes one managed MCP block to ``~/.codex/config.toml``.
It never configures the upstream ``src/server.py`` entrypoint and refuses to
create duplicate TOML tables. Existing configuration is backed up and the
result is parsed with Python's TOML parser before being committed atomically.
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

ROOT = Path(__file__).resolve().parent
STRICT_SERVER = (ROOT / "src" / "strict_server.py").resolve()
DEFAULT_CONFIG = Path.home() / ".codex" / "config.toml"
SERVER_NAME = "davinci_resolve_strict"
BEGIN_MARKER = "# BEGIN DAVINCI_RESOLVE_MCP_STRICT"
END_MARKER = "# END DAVINCI_RESOLVE_MCP_STRICT"
MANAGED_PATTERN = re.compile(
    rf"(?ms)^\s*{re.escape(BEGIN_MARKER)}\n.*?^\s*{re.escape(END_MARKER)}\s*\n?"
)
TABLE_PATTERN = re.compile(
    rf"(?m)^\s*\[mcp_servers\.(?:{re.escape(SERVER_NAME)}|\"{re.escape(SERVER_NAME)}\")\]\s*$"
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
        raise SystemExit(f"Strict venv Python not found: {candidate}")
    return candidate


def _managed_block(python_path: Path) -> str:
    env = {
        "DAVINCI_MCP_SECURITY_PROFILE": "safe",
        "DAVINCI_RESOLVE_MCP_UPDATE_CHECK": "0",
        "DAVINCI_RESOLVE_MCP_UPDATE_MODE": "never",
        "DAVINCI_RESOLVE_MCP_AUTO_UPDATE": "0",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "TORCH_HOME": str((ROOT / ".strict-cache-disabled").resolve()),
    }
    lines = [
        BEGIN_MARKER,
        f"[mcp_servers.{SERVER_NAME}]",
        f"command = {_toml_string(str(python_path))}",
        f"args = [{_toml_string(str(STRICT_SERVER))}]",
        "enabled = true",
        "",
        f"[mcp_servers.{SERVER_NAME}.env]",
    ]
    for key, value in env.items():
        lines.append(f"{key} = {_toml_string(value)}")
    lines.extend([END_MARKER, ""])
    return "\n".join(lines)


def _read_existing(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _render(existing: str, block: str) -> str:
    without_managed = MANAGED_PATTERN.sub("", existing)
    if TABLE_PATTERN.search(without_managed):
        raise SystemExit(
            f"Refusing to create duplicate [mcp_servers.{SERVER_NAME}] table. "
            "Remove or rename the unmanaged table first."
        )
    prefix = without_managed.rstrip()
    rendered = f"{prefix}\n\n{block}" if prefix else block
    try:
        tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"Refusing to write invalid TOML: {exc}") from exc
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
    parser = argparse.ArgumentParser(description="Install strict DaVinci Resolve MCP for Codex")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not STRICT_SERVER.is_file():
        raise SystemExit(f"strict_server.py not found: {STRICT_SERVER}")
    python_path = _venv_python()
    config_path = args.config.expanduser().resolve()
    existing = _read_existing(config_path)
    rendered = _render(existing, _managed_block(python_path))

    backup = None
    if not args.dry_run:
        backup = _atomic_write(config_path, rendered)
        # Re-read and validate the exact bytes that reached disk.
        tomllib.loads(config_path.read_text(encoding="utf-8"))

    result = {
        "success": True,
        "dry_run": bool(args.dry_run),
        "config_path": str(config_path),
        "backup_path": str(backup) if backup else None,
        "server_name": SERVER_NAME,
        "command": str(python_path),
        "entrypoint": str(STRICT_SERVER),
        "profile": "safe",
        "network": "blocked_by_runtime",
        "normal_server_configured": False,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
