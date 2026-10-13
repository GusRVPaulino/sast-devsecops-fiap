"""Contrato comum entre o Tree-sitter de cada linguagem e o resto do motor.

Cada linguagem tem uma AST diferente (``call`` em Python, ``call_expression``
em JS, ``method_invocation`` em Java). Os adaptadores escondem essa diferença
atrás de perguntas que as regras e a taint analysis fazem: "qual o nome
qualificado desta chamada?", "este argumento é constante?", "que variável
esta atribuição define?". Assim uma única implementação de regras e de taint
serve às três linguagens.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Language, Node, Parser, Tree


@dataclass(frozen=True)
class Param:
    name: str
    annotations: tuple[str, ...] = ()
    type_name: str | None = None


@dataclass
class FileContext:
    """Informação de arquivo inteiro usada para resolver nomes de chamada."""

    aliases: dict[str, str] = field(default_factory=dict)  # nome local -> qualificado
    var_types: dict[str, str] = field(default_factory=dict)  # variável -> tipo (Java)


@dataclass(frozen=True)
class NamedLiteral:
    """Um literal string ligado a um nome (variável, campo, kwarg, chave)."""

    name: str
    value: str
    node: Node


class LanguageAdapter(ABC):
    name: str = ""
    extensions: tuple[str, ...] = ()
    call_types: frozenset[str] = frozenset()
    function_types: frozenset[str] = frozenset()
    assignment_types: frozenset[str] = frozenset()
    loop_types: frozenset[str] = frozenset()
    string_types: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self._language = Language(self._grammar())
        self._parser = Parser(self._language)

    @abstractmethod
    def _grammar(self) -> Any: ...

    def parse(self, source: str) -> Tree:
        return self._parser.parse(source.encode("utf-8"))

    # ------------------------------------------------------------------ texto
    @staticmethod
    def text(node: Node | None) -> str:
        if node is None:
            return ""
        return node.text.decode("utf-8", errors="replace")

    @staticmethod
    def line(node: Node) -> int:
        return node.start_point[0] + 1

    @staticmethod
    def end_line(node: Node) -> int:
        return node.end_point[0] + 1

    # --------------------------------------------------------------- travessia
    def walk(self, node: Node, *, into_functions: bool = True) -> Iterator[Node]:
        """Pré-ordem. Com ``into_functions=False`` não desce em funções aninhadas."""

        stack = [node]
        while stack:
            current = stack.pop()
            yield current
            children = list(current.children)
            if not into_functions and current is not node:
                if current.type in self.function_types:
                    continue
            stack.extend(reversed(children))

    def functions(self, root: Node) -> Iterator[Node]:
        for node in self.walk(root):
            if node.type in self.function_types:
                yield node

    def calls(self, node: Node, *, into_functions: bool = True) -> Iterator[Node]:
        for child in self.walk(node, into_functions=into_functions):
            if child.type in self.call_types:
                yield child

    # ------------------------------------------------------- abstrações chave
    @abstractmethod
    def build_context(self, root: Node) -> FileContext: ...

    @abstractmethod
    def call_name(self, node: Node, ctx: FileContext) -> str | None:
        """Nome qualificado e normalizado, ex. ``subprocess.run``."""

    @abstractmethod
    def call_args(self, node: Node) -> list[Node]: ...

    def call_kwargs(self, node: Node) -> dict[str, Node]:
        return {}

    def call_receiver(self, node: Node) -> Node | None:
        return None

    @abstractmethod
    def assignment_targets(self, node: Node) -> list[tuple[str, Node | None]]:
        """Para nós de atribuição: lista de (nome alvo, nó do valor)."""

    @abstractmethod
    def loop_binding(self, node: Node) -> tuple[list[str], Node | None]:
        """Para laços ``for x in y``: (variáveis, iterável)."""

    @abstractmethod
    def function_name(self, node: Node) -> str: ...

    @abstractmethod
    def function_params(self, node: Node) -> list[Param]: ...

    def function_body(self, node: Node) -> Node | None:
        return node.child_by_field_name("body")

    @abstractmethod
    def reference_name(self, node: Node) -> str | None:
        """Nome pontuado de um identificador/acesso a membro, ou None."""

    @abstractmethod
    def string_value(self, node: Node) -> str | None:
        """Valor de um literal string sem interpolação; None caso contrário."""

    @abstractmethod
    def is_constant(self, node: Node) -> bool:
        """Literal (ou combinação de literais) que não pode carregar entrada externa."""

    @abstractmethod
    def is_dynamic_string(self, node: Node) -> bool:
        """String montada com partes variáveis (concatenação, f-string, template...)."""

    @abstractmethod
    def named_literals(self, root: Node) -> Iterator[NamedLiteral]: ...

    def member_assignment(self, node: Node) -> tuple[str, Node] | None:
        """``obj.prop = valor`` -> (prop, valor). Só relevante em JS (DOM)."""

        return None

    # -------------------------------------------------------------- utilidades
    def string_literals(self, root: Node) -> Iterator[tuple[str, Node]]:
        for node in self.walk(root):
            if node.type in self.string_types:
                value = self.string_value(node)
                if value is not None:
                    yield value, node

    @staticmethod
    def normalize_call_name(raw: str) -> str:
        """``Runtime.getRuntime().exec`` -> ``Runtime.getRuntime.exec``."""

        out = []
        depth = 0
        for char in raw:
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and not char.isspace():
                out.append(char)
        return "".join(out).replace("?.", ".")
