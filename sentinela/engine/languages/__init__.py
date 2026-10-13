"""Registro de linguagens suportadas."""

from __future__ import annotations

from functools import cache
from pathlib import PurePosixPath

from sentinela.engine.languages.base import LanguageAdapter
from sentinela.engine.languages.java import JavaAdapter
from sentinela.engine.languages.javascript import JavaScriptAdapter
from sentinela.engine.languages.python import PythonAdapter

_ADAPTERS: tuple[type[LanguageAdapter], ...] = (PythonAdapter, JavaScriptAdapter, JavaAdapter)
_ALIASES = {"py": "python", "js": "javascript", "node": "javascript", "jsx": "javascript"}

SUPPORTED_LANGUAGES = tuple(adapter.name for adapter in _ADAPTERS)


@cache
def get_adapter(language: str) -> LanguageAdapter:
    key = _ALIASES.get(language.lower(), language.lower())
    for adapter_cls in _ADAPTERS:
        if adapter_cls.name == key:
            return adapter_cls()
    raise KeyError(f"Linguagem não suportada: {language}")


def detect_language(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower()
    for adapter_cls in _ADAPTERS:
        if suffix in adapter_cls.extensions:
            return adapter_cls.name
    return None


__all__ = ["SUPPORTED_LANGUAGES", "LanguageAdapter", "detect_language", "get_adapter"]
