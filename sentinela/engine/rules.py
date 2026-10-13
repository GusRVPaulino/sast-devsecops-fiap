"""Motor de regras declarativas (YAML) sobre a AST de qualquer linguagem."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from tree_sitter import Node

from sentinela.engine.languages.base import FileContext, LanguageAdapter
from sentinela.engine.models import Engine, Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    language: str
    severity: Severity
    cwe: str
    owasp: str
    match: dict[str, Any]
    message: str
    remediation: str
    example: str
    references: tuple[str, ...] = field(default_factory=tuple)

    @property
    def call_patterns(self) -> tuple[str, ...]:
        return tuple(self.match.get("call", ()))


def matches_any(name: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in patterns)


def _rules_dir() -> Path:
    return Path(str(resources.files("sentinela") / "rules"))


@cache
def load_rules(language: str, rules_dir: str | None = None) -> tuple[Rule, ...]:
    directory = Path(rules_dir) if rules_dir else _rules_dir()
    path = directory / f"{language}.yml"
    if not path.exists():
        return ()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = []
    for raw in data.get("rules", []):
        rules.append(
            Rule(
                id=raw["id"],
                title=raw["title"],
                language=language,
                severity=Severity.parse(raw["severity"]),
                cwe=raw["cwe"],
                owasp=raw.get("owasp", ""),
                match=raw["match"],
                message=" ".join(str(raw.get("message", "")).split()),
                remediation=" ".join(str(raw.get("remediation", "")).split()),
                example=str(raw.get("example", "")).rstrip(),
                references=tuple(raw.get("references", ())) or _default_refs(raw["cwe"]),
            ),
        )
    return tuple(rules)


def _default_refs(cwe: str) -> tuple[str, ...]:
    number = cwe.split("-", 1)[-1]
    return (f"https://cwe.mitre.org/data/definitions/{number}.html",)


class RuleMatcher:
    """Aplica as regras de uma linguagem a um arquivo já parseado."""

    def __init__(self, adapter: LanguageAdapter, rules: tuple[Rule, ...]) -> None:
        self.adapter = adapter
        self.call_rules = [rule for rule in rules if "call" in rule.match]
        self.assign_rules = [rule for rule in rules if "member_assign" in rule.match]

    def run(self, root: Node, ctx: FileContext, *, path: str, source_lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        if self.call_rules:
            for node in self.adapter.calls(root):
                name = self.adapter.call_name(node, ctx)
                if not name:
                    continue
                for rule in self.call_rules:
                    if matches_any(name, rule.call_patterns) and self._call_conditions(rule, node):
                        findings.append(self._finding(rule, node, path, source_lines))
        if self.assign_rules:
            for node in self.adapter.walk(root):
                assignment = self.adapter.member_assignment(node)
                if assignment is None:
                    continue
                prop, value = assignment
                for rule in self.assign_rules:
                    if prop not in rule.match["member_assign"]:
                        continue
                    if rule.match.get("value_not_constant") and self.adapter.is_constant(value):
                        continue
                    findings.append(self._finding(rule, node, path, source_lines))
        return findings

    # ------------------------------------------------------------ condições
    def _call_conditions(self, rule: Rule, node: Node) -> bool:
        adapter = self.adapter
        match = rule.match
        args = adapter.call_args(node)

        if "arg_not_constant" in match:
            index = int(match["arg_not_constant"])
            if index >= len(args) or adapter.is_constant(args[index]):
                return False

        if "arg_dynamic_string" in match:
            index = int(match["arg_dynamic_string"])
            if index >= len(args) or not adapter.is_dynamic_string(args[index]):
                return False

        if "arg_in" in match:
            spec = match["arg_in"]
            index = int(spec.get("index", 0))
            value = adapter.string_value(args[index]) if index < len(args) else None
            if value is None or value not in spec["values"]:
                return False

        if "arg_matches" in match:
            spec = match["arg_matches"]
            index = int(spec.get("index", 0))
            value = adapter.string_value(args[index]) if index < len(args) else None
            if value is None or not re.search(spec["regex"], value):
                return False

        kwargs = adapter.call_kwargs(node) if ("kwarg_equals" in match or "kwarg_not_in" in match) else {}

        for name, expected in (match.get("kwarg_equals") or {}).items():
            value = kwargs.get(name)
            if value is None or adapter.text(value).strip().lower() != str(expected).lower():
                return False

        for name, safe_values in (match.get("kwarg_not_in") or {}).items():
            value = kwargs.get(name)
            if value is not None and adapter.text(value).strip() in safe_values:
                return False

        return True

    def _finding(self, rule: Rule, node: Node, path: str, source_lines: list[str]) -> Finding:
        line = self.adapter.line(node)
        end_line = self.adapter.end_line(node)
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            language=rule.language,
            file_path=path,
            line=line,
            end_line=end_line,
            column=node.start_point[1] + 1,
            severity=rule.severity,
            cwe=rule.cwe,
            owasp=rule.owasp,
            message=rule.message,
            snippet=_snippet(source_lines, line, end_line),
            engines={Engine.RULE},
            remediation=rule.remediation,
            safe_example=rule.example,
            references=list(rule.references),
        )


def _snippet(lines: list[str], start: int, end: int, max_lines: int = 4) -> str:
    end = min(end, start + max_lines - 1)
    return "\n".join(lines[start - 1 : end]).strip()


__all__ = ["Rule", "RuleMatcher", "load_rules", "matches_any"]
