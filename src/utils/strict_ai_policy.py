"""Fail-closed AI/media-analysis policy for the hardened fork.

Strict mode deliberately disables every path that can expose untrusted media,
transcripts, filenames, metadata, or derived summaries to a model.  This is a
capability boundary, not a prompt-only mitigation.
"""
from __future__ import annotations

import functools
import importlib.abc
import importlib.machinery
import os
import sys
from types import ModuleType
from typing import Any, Callable

STRICT_AI_DISABLED = True
ENV_STRICT_AI_DISABLED = "DAVINCI_MCP_STRICT_AI_DISABLED"

_DISABLED_MESSAGE = (
    "AI media analysis is disabled by DAVINCI_MCP_STRICT_AI_DISABLED. "
    "Vision, transcription, embeddings, model loading/downloads, and host-chat "
    "media handoff are unavailable in the strict security profile."
)

# Modules that can turn untrusted pixels/audio/text into model input or vectors.
_TARGET_SUFFIXES = (
    "utils.media_analysis",
    "utils.media_analysis_jobs",
    "utils.deep_vision",
    "utils.embeddings",
    "utils.transcription",
    "utils.transcribe",
    "utils.whisper",
)

# High-level media-analysis entrypoints are blocked even when their names do not
# explicitly mention vision or transcription, because they can invoke those
# capabilities internally.
_MEDIA_ANALYSIS_ENTRYPOINTS = {
    "build_plan",
    "execute_plan",
    "execute_plan_async",
    "commit_visual_analysis",
    "detect_capabilities",
    "install_guidance",
    "plan_requires_capabilities",
}

_DANGEROUS_NAME_PARTS = (
    "vision",
    "visual_analysis",
    "host_chat",
    "transcrib",
    "whisper",
    "embedding",
    "embed_",
    "embedtext",
    "embedimage",
    "model_download",
    "download_model",
    "load_model",
)

_INSTALLED = False


def strict_ai_refusal(capability: str) -> PermissionError:
    return PermissionError(
        f"DAVINCI_MCP_STRICT_AI_DISABLED: {capability}: {_DISABLED_MESSAGE}"
    )


def _blocked_callable(name: str) -> Callable[..., Any]:
    @functools.wraps(lambda *args, **kwargs: None)
    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise strict_ai_refusal(name)

    blocked.__name__ = name
    blocked.__qualname__ = name
    blocked.__doc__ = _DISABLED_MESSAGE
    setattr(blocked, "__davinci_strict_ai_blocked__", True)
    return blocked


def _should_block(module_name: str, name: str, value: Any) -> bool:
    if not callable(value):
        return False
    lower = name.lower()
    if module_name.endswith("utils.media_analysis") and name in _MEDIA_ANALYSIS_ENTRYPOINTS:
        return True
    if module_name.endswith(("utils.deep_vision", "utils.transcription", "utils.transcribe", "utils.whisper")):
        return not name.startswith("_")
    if module_name.endswith("utils.embeddings"):
        return (
            lower.startswith("detect_embedding")
            or "embed" in lower
            or "model" in lower
            or "clap" in lower
            or "clip" in lower
        )
    return any(part in lower for part in _DANGEROUS_NAME_PARTS)


def harden_ai_module(module: ModuleType) -> None:
    """Mutate a freshly imported target module into a fail-closed form."""
    module_name = module.__name__

    # Defaults become inert even for callers that only inspect constants.
    if hasattr(module, "DEFAULT_TRANSCRIPTION_ENABLED"):
        setattr(module, "DEFAULT_TRANSCRIPTION_ENABLED", False)
    if hasattr(module, "HOST_CHAT_VISION_PROVIDERS"):
        setattr(module, "HOST_CHAT_VISION_PROVIDERS", frozenset())
    if hasattr(module, "OLLAMA_URL"):
        setattr(module, "OLLAMA_URL", "http://127.0.0.1:9")

    for name, value in list(vars(module).items()):
        if _should_block(module_name, name, value):
            setattr(module, name, _blocked_callable(name))

    setattr(module, "STRICT_AI_DISABLED", True)
    setattr(module, "STRICT_AI_DISABLED_REASON", _DISABLED_MESSAGE)


class _StrictAILoader(importlib.abc.Loader):
    def __init__(self, wrapped: importlib.abc.Loader):
        self.wrapped = wrapped

    def create_module(self, spec):
        creator = getattr(self.wrapped, "create_module", None)
        return creator(spec) if creator else None

    def exec_module(self, module):
        self.wrapped.exec_module(module)
        harden_ai_module(module)


class _StrictAIFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.endswith(_TARGET_SUFFIXES):
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec and spec.loader and not isinstance(spec.loader, _StrictAILoader):
            spec.loader = _StrictAILoader(spec.loader)
        return spec


def install_strict_ai_policy() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True

    os.environ[ENV_STRICT_AI_DISABLED] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    os.environ["DAVINCI_RESOLVE_MCP_OLLAMA_URL"] = "http://127.0.0.1:9"

    if not any(isinstance(finder, _StrictAIFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _StrictAIFinder())

    # Harden targets that happened to be imported before installation.
    for module_name, module in list(sys.modules.items()):
        if module is not None and module_name.endswith(_TARGET_SUFFIXES):
            harden_ai_module(module)
