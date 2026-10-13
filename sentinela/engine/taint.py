"""Taint analysis: rastreia dado externo (fonte) até uma função perigosa (sink).

Funciona igual para Python, JavaScript e Java porque opera sobre o
``LanguageAdapter``. Para cada função:

1. parâmetros anotados como entrada do usuário (``@RequestParam``) e acessos
   a fontes (``request.args``, ``req.query``, ``getParameter``) geram um
   *trace* contaminado;
2. atribuições propagam o trace para a variável de destino — ou limpam a
   variável quando o valor é seguro;
3. chamadas a sanitizadores (``int``, ``shlex.quote``, ``encodeForHTML``...)
   devolvem valor limpo;
4. quando um argumento contaminado chega a um sink, gera um achado com o
   caminho completo (fonte → propagações → sink).

Também há um nível de análise **entre funções do mesmo arquivo**: se
``buscar(id)`` repassa ``id`` a um ``execute``, chamar ``buscar(req.query.id)``
é detectado; e uma função que retorna dado de fonte é tratada como fonte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from tree_sitter import Node

from sentinela.engine.languages.base import FileContext, LanguageAdapter
from sentinela.engine.models import Engine, Finding, Severity, TaintStep
from sentinela.engine.rules import matches_any

_RETURN_TYPES = {"return_statement"}
_MAX_STEPS = 12


@dataclass(frozen=True)
class SinkSpec:
    id: str
    title: str
    severity: Severity
    cwe: str
    owasp: str
    calls: tuple[str, ...]
    args: Any  # list[int] | "any"
    require_kwarg: dict[str, str]
    member_assign: tuple[str, ...]
    remediation: str
    example: str


@dataclass(frozen=True)
class TaintSpec:
    language: str
    source_members: tuple[str, ...]
    source_calls: tuple[str, ...]
    param_annotations: tuple[str, ...]
    sanitizers: tuple[str, ...]
    sinks: tuple[SinkSpec, ...]


@cache
def load_taint_spec(language: str, rules_dir: str | None = None) -> TaintSpec | None:
    directory = Path(rules_dir) if rules_dir else Path(str(resources.files("sentinela") / "rules"))
    data = yaml.safe_load((directory / "taint.yml").read_text(encoding="utf-8")) or {}
    raw = data.get(language)
    if not raw:
        return None
    sources = raw.get("sources", {})
    sinks = tuple(
        SinkSpec(
            id=sink["id"],
            title=sink["title"],
            severity=Severity.parse(sink["severity"]),
            cwe=sink["cwe"],
            owasp=sink.get("owasp", ""),
            calls=tuple(sink.get("calls", ())),
            args=sink.get("args", [0]),
            require_kwarg=dict(sink.get("require_kwarg") or {}),
            member_assign=tuple(sink.get("member_assign", ())),
            remediation=" ".join(str(sink.get("remediation", "")).split()),
            example=str(sink.get("example", "")).rstrip(),
        )
        for sink in raw.get("sinks", [])
    )
    return TaintSpec(
        language=language,
        source_members=tuple(sources.get("members", ())),
        source_calls=tuple(sources.get("calls", ())),
        param_annotations=tuple(sources.get("param_annotations", ())),
        sanitizers=tuple(raw.get("sanitizers", ())),
        sinks=sinks,
    )


@dataclass(frozen=True)
class Trace:
    """Origem de um valor contaminado e o caminho que ele percorreu."""

    source: str
    steps: tuple[TaintStep, ...]

    def extend(self, step: TaintStep) -> Trace:
        last = self.steps[-1] if self.steps else None
        if last is not None and last.line == step.line and (last.kind == step.kind or step.kind == "propagation"):
            return self
        steps = (*self.steps, step)
        if len(steps) > _MAX_STEPS:
            steps = (steps[0], *steps[-(_MAX_STEPS - 1) :])
        return Trace(self.source, steps)


@dataclass
class FunctionSummary:
    """O que uma função faz com seus argumentos (usado entre funções)."""

    name: str
    param_offset: int
    returns_source: Trace | None = None
    param_sinks: dict[int, list[tuple[SinkSpec, Node, str]]] = field(default_factory=dict)


class TaintAnalyzer:
    def __init__(
        self,
        adapter: LanguageAdapter,
        spec: TaintSpec,
        ctx: FileContext,
        *,
        path: str,
        source_lines: list[str],
    ) -> None:
        self.adapter = adapter
        self.spec = spec
        self.ctx = ctx
        self.path = path
        self.lines = source_lines
        self.summaries: dict[str, FunctionSummary] = {}
        self._findings: dict[tuple[int, str], Finding] = {}

    # ------------------------------------------------------------- entrada
    def run(self, root: Node) -> list[Finding]:
        functions = list(self.adapter.functions(root))
        # Passo 1: resumo de cada função (o que ela retorna e onde usa cada parâmetro).
        for function in functions:
            self._summarize(function)
        # Passo 2: análise real de cada escopo, usando os resumos.
        self._analyze_scope(root, is_module=True)
        for function in functions:
            self._analyze_scope(function, is_module=False)
        return sorted(self._findings.values(), key=lambda f: (f.line, f.rule_id))

    # -------------------------------------------------------------- resumo
    def _summarize(self, function: Node) -> None:
        adapter = self.adapter
        name = adapter.function_name(function)
        if not name or name.startswith("<"):
            return
        params = adapter.function_params(function)
        offset = 1 if params and params[0].name in {"self", "cls"} else 0
        summary = FunctionSummary(name=name, param_offset=offset)
        self.summaries[name] = summary

        body = adapter.function_body(function) or function
        # O que a função retorna sem nenhum parâmetro contaminado?
        env: dict[str, Trace] = {}
        returned = self._walk_scope(body, env, emit=False)
        summary.returns_source = returned

        # Para cada parâmetro: ele alcança algum sink?
        for index, param in enumerate(params[offset:]):
            probe = Trace(
                source=f"parâmetro `{param.name}` de {name}()",
                steps=(TaintStep(adapter.line(function), "source", f"{name}({param.name})"),),
            )
            env = {param.name: probe}
            hits: list[tuple[SinkSpec, Node, str]] = []
            self._walk_scope(body, env, emit=False, sink_hits=hits)
            if hits:
                summary.param_sinks[index] = hits

    # ------------------------------------------------------------- escopos
    def _analyze_scope(self, scope: Node, *, is_module: bool) -> None:
        adapter = self.adapter
        env: dict[str, Trace] = {}
        if not is_module:
            for param in adapter.function_params(scope):
                if set(param.annotations) & set(self.spec.param_annotations):
                    annotation = next(a for a in param.annotations if a in self.spec.param_annotations)
                    env[param.name] = Trace(
                        source=f"parâmetro @{annotation} `{param.name}`",
                        steps=(
                            TaintStep(
                                adapter.line(scope),
                                "source",
                                f"@{annotation} {param.type_name or ''} {param.name}".strip(),
                            ),
                        ),
                    )
            body = adapter.function_body(scope) or scope
        else:
            body = scope
        self._walk_scope(body, env, emit=True)

    def _walk_scope(
        self,
        body: Node,
        env: dict[str, Trace],
        *,
        emit: bool,
        sink_hits: list[tuple[SinkSpec, Node, str]] | None = None,
    ) -> Trace | None:
        adapter = self.adapter
        returned: Trace | None = None
        for node in adapter.walk(body, into_functions=False):
            if node.type in adapter.function_types and node is not body:
                continue
            if node.type in adapter.assignment_types:
                self._assign(node, env)
                member = adapter.member_assignment(node)
                if member is not None:
                    self._check_member_sink(node, member, env, emit, sink_hits)
            elif node.type in adapter.loop_types:
                names, iterable = adapter.loop_binding(node)
                trace = self._taint(iterable, env) if iterable is not None else None
                for name in names:
                    if trace is not None:
                        env[name] = trace.extend(self._step(node, "propagation"))
            elif node.type in adapter.call_types:
                self._check_call_sink(node, env, emit, sink_hits)
            elif node.type in _RETURN_TYPES:
                for child in node.named_children:
                    trace = self._taint(child, env)
                    if trace is not None:
                        returned = trace
        return returned

    # -------------------------------------------------------- propagação
    def _assign(self, node: Node, env: dict[str, Trace]) -> None:
        augmented = node.type.startswith("augmented")
        for name, value in self.adapter.assignment_targets(node):
            if not name:
                continue
            trace = self._taint(value, env) if value is not None else None
            if trace is not None:
                env[name] = trace.extend(self._step(node, "propagation"))
            elif not augmented:
                env.pop(name, None)

    def _taint(self, node: Node | None, env: dict[str, Trace]) -> Trace | None:
        if node is None:
            return None
        adapter = self.adapter
        if node.type in adapter.function_types:
            return None

        reference = adapter.reference_name(node)
        if reference is not None:
            if matches_any(reference, self.spec.source_members):
                return Trace(
                    source=f"`{reference}`",
                    steps=(self._step(node, "source"),),
                )
            if reference in env:
                return env[reference]
            base = reference.split(".", 1)[0]
            if base in env:
                return env[base]
            if node.type in {"identifier", "shorthand_property_identifier"}:
                return None

        if node.type in adapter.call_types:
            name = adapter.call_name(node, self.ctx) or ""
            if matches_any(name, self.spec.source_calls):
                return Trace(source=f"`{name}()`", steps=(self._step(node, "source"),))
            if matches_any(name, self.spec.sanitizers):
                return None
            summary = self.summaries.get(name.rsplit(".", 1)[-1])
            if summary is not None and summary.returns_source is not None:
                return summary.returns_source.extend(self._step(node, "propagation"))
            receiver = adapter.call_receiver(node)
            if receiver is not None:
                trace = self._taint(receiver, env)
                if trace is not None:
                    return trace
            for arg in [*adapter.call_args(node), *adapter.call_kwargs(node).values()]:
                trace = self._taint(arg, env)
                if trace is not None:
                    return trace
            return None

        for child in node.named_children:
            trace = self._taint(child, env)
            if trace is not None:
                return trace
        return None

    # --------------------------------------------------------------- sinks
    def _check_call_sink(
        self,
        node: Node,
        env: dict[str, Trace],
        emit: bool,
        sink_hits: list[tuple[SinkSpec, Node, str]] | None,
    ) -> None:
        adapter = self.adapter
        name = adapter.call_name(node, self.ctx)
        if not name:
            return
        args = adapter.call_args(node)

        for sink in self.spec.sinks:
            if not sink.calls or not matches_any(name, sink.calls):
                continue
            if sink.require_kwarg and not self._kwargs_match(node, sink.require_kwarg):
                continue
            indexes = range(len(args)) if sink.args == "any" else [i for i in sink.args if i < len(args)]
            for index in indexes:
                trace = self._taint(args[index], env)
                if trace is None:
                    continue
                self._record(sink, node, trace, name, emit, sink_hits)
                break

        # Chamada a função local que repassa o parâmetro a um sink.
        summary = self.summaries.get(name.rsplit(".", 1)[-1])
        if summary is None or not summary.param_sinks or not emit:
            return
        for index, hits in summary.param_sinks.items():
            if index >= len(args):
                continue
            trace = self._taint(args[index], env)
            if trace is None:
                continue
            trace = trace.extend(self._step(node, "propagation"))
            for sink, sink_node, sink_name in hits:
                self._record(sink, sink_node, trace, sink_name, emit, None)

    def _check_member_sink(
        self,
        node: Node,
        member: tuple[str, Node],
        env: dict[str, Trace],
        emit: bool,
        sink_hits: list[tuple[SinkSpec, Node, str]] | None,
    ) -> None:
        prop, value = member
        for sink in self.spec.sinks:
            if prop not in sink.member_assign:
                continue
            trace = self._taint(value, env)
            if trace is not None:
                self._record(sink, node, trace, prop, emit, sink_hits)

    def _kwargs_match(self, node: Node, required: dict[str, str]) -> bool:
        kwargs = self.adapter.call_kwargs(node)
        return all(
            name in kwargs and self.adapter.text(kwargs[name]).strip().lower() == str(value).lower()
            for name, value in required.items()
        )

    def _record(
        self,
        sink: SinkSpec,
        node: Node,
        trace: Trace,
        sink_name: str,
        emit: bool,
        sink_hits: list[tuple[SinkSpec, Node, str]] | None,
    ) -> None:
        if sink_hits is not None:
            sink_hits.append((sink, node, sink_name))
        if not emit:
            return
        line = self.adapter.line(node)
        key = (line, sink.id)
        if key in self._findings:
            return
        steps = list(trace.extend(self._step(node, "sink")).steps)
        self._findings[key] = Finding(
            rule_id=sink.id,
            title=sink.title,
            language=self.adapter.name,
            file_path=self.path,
            line=line,
            end_line=self.adapter.end_line(node),
            column=node.start_point[1] + 1,
            severity=sink.severity,
            cwe=sink.cwe,
            owasp=sink.owasp,
            message=(
                f"Dado vindo de {trace.source} chega a `{sink_name}` sem sanitização. Um atacante controla esse valor."
            ),
            snippet=self._line_text(line),
            engines={Engine.TAINT},
            taint_path=steps,
            remediation=sink.remediation,
            safe_example=sink.example,
            references=[f"https://cwe.mitre.org/data/definitions/{sink.cwe.split('-')[-1]}.html"],
        )

    # ------------------------------------------------------------- helpers
    def _step(self, node: Node, kind: str) -> TaintStep:
        line = self.adapter.line(node)
        return TaintStep(line=line, kind=kind, code=self._line_text(line))

    def _line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()[:200]
        return ""


__all__ = ["TaintAnalyzer", "TaintSpec", "Trace", "load_taint_spec"]
