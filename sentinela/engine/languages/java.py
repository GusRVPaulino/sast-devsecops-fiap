"""Adaptador Tree-sitter para Java.

Java não tem "funções soltas": as chamadas perigosas são métodos de objetos
(``stmt.executeQuery(sql)``). Para que uma regra diga ``Statement.executeQuery``
em vez de adivinhar pelo nome da variável, o adaptador registra o tipo
declarado de cada variável, parâmetro e campo do arquivo.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import tree_sitter_java
from tree_sitter import Node

from sentinela.engine.languages.base import (
    FileContext,
    LanguageAdapter,
    NamedLiteral,
    Param,
)

_CONSTANT_TYPES = {
    "decimal_integer_literal",
    "hex_integer_literal",
    "decimal_floating_point_literal",
    "true",
    "false",
    "null_literal",
    "character_literal",
}


class JavaAdapter(LanguageAdapter):
    name = "java"
    extensions = (".java",)
    call_types = frozenset({"method_invocation", "object_creation_expression"})
    function_types = frozenset({"method_declaration", "constructor_declaration", "lambda_expression"})
    assignment_types = frozenset({"variable_declarator", "assignment_expression"})
    loop_types = frozenset({"enhanced_for_statement"})
    string_types = frozenset({"string_literal"})

    def _grammar(self) -> Any:
        return tree_sitter_java.language()

    # ------------------------------------------------------------ contexto
    def build_context(self, root: Node) -> FileContext:
        ctx = FileContext()
        for node in self.walk(root):
            if node.type in {"local_variable_declaration", "field_declaration"}:
                type_name = self._simple_type(node.child_by_field_name("type"))
                for declarator in node.children_by_field_name("declarator"):
                    name = self.text(declarator.child_by_field_name("name"))
                    if name and type_name:
                        ctx.var_types[name] = type_name
            elif node.type == "formal_parameter":
                type_name = self._simple_type(node.child_by_field_name("type"))
                name = self.text(node.child_by_field_name("name"))
                if name and type_name:
                    ctx.var_types[name] = type_name
            elif node.type == "import_declaration":
                path = self.text(next((c for c in node.named_children), None))
                if path and not path.endswith("*"):
                    ctx.aliases[path.rsplit(".", 1)[-1]] = path
        return ctx

    def _simple_type(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "generic_type":
            node = node.named_children[0] if node.named_children else node
        text = self.text(node)
        return text.rsplit(".", 1)[-1] if text else None

    # ------------------------------------------------------------ chamadas
    def call_name(self, node: Node, ctx: FileContext) -> str | None:
        if node.type == "object_creation_expression":
            return f"new {self._simple_type(node.child_by_field_name('type'))}"
        name = self.text(node.child_by_field_name("name"))
        receiver = node.child_by_field_name("object")
        if receiver is None:
            return name
        if receiver.type == "identifier":
            receiver_text = self.text(receiver)
            receiver_type = ctx.var_types.get(receiver_text)
            return f"{receiver_type or receiver_text}.{name}"
        return f"{self.normalize_call_name(self.text(receiver))}.{name}"

    def call_args(self, node: Node) -> list[Node]:
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return []
        return [
            child
            for child in arguments.named_children
            if child.type not in {"comment", "line_comment", "block_comment"}
        ]

    def call_receiver(self, node: Node) -> Node | None:
        return node.child_by_field_name("object")

    # ---------------------------------------------------------- atribuições
    def assignment_targets(self, node: Node) -> list[tuple[str, Node | None]]:
        if node.type == "variable_declarator":
            return [(self.text(node.child_by_field_name("name")), node.child_by_field_name("value"))]
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        name = self.reference_name(left) if left is not None else None
        return [(name, right)] if name else []

    def loop_binding(self, node: Node) -> tuple[list[str], Node | None]:
        name = self.text(node.child_by_field_name("name"))
        return ([name] if name else []), node.child_by_field_name("value")

    # ------------------------------------------------------------- funções
    def function_name(self, node: Node) -> str:
        return self.text(node.child_by_field_name("name")) or "<lambda>"

    def function_params(self, node: Node) -> list[Param]:
        params = node.child_by_field_name("parameters")
        if params is None:
            return []
        result = []
        for child in params.named_children:
            if child.type not in {"formal_parameter", "spread_parameter"}:
                continue
            annotations = []
            for modifier in child.named_children:
                if modifier.type != "modifiers":
                    continue
                for annotation in modifier.named_children:
                    if annotation.type in {"marker_annotation", "annotation"}:
                        annotations.append(self.text(annotation.child_by_field_name("name")))
            result.append(
                Param(
                    self.text(child.child_by_field_name("name")),
                    annotations=tuple(annotations),
                    type_name=self._simple_type(child.child_by_field_name("type")),
                ),
            )
        return result

    # -------------------------------------------------------------- valores
    def reference_name(self, node: Node) -> str | None:
        if node.type == "identifier":
            return self.text(node)
        if node.type == "field_access":
            return self.normalize_call_name(self.text(node))
        if node.type == "array_access":
            return self.reference_name(node.child_by_field_name("array"))
        return None

    def string_value(self, node: Node | None) -> str | None:
        if node is None or node.type != "string_literal":
            return None
        return "".join(
            self.text(child)
            for child in node.named_children
            if child.type in {"string_fragment", "escape_sequence", "multiline_string_fragment"}
        )

    def is_constant(self, node: Node) -> bool:
        if node.type in _CONSTANT_TYPES:
            return True
        if node.type == "string_literal":
            return True
        if node.type == "binary_expression":
            return all(self.is_constant(child) for child in node.named_children)
        if node.type == "parenthesized_expression":
            return all(self.is_constant(child) for child in node.named_children)
        return False

    def is_dynamic_string(self, node: Node) -> bool:
        if node.type == "binary_expression":
            operator = self.text(node.child_by_field_name("operator"))
            has_string = any(
                child.type == "string_literal" or self.is_dynamic_string(child) for child in node.named_children
            )
            return operator == "+" and has_string and not self.is_constant(node)
        if node.type == "method_invocation":
            # String.format("...%s", x) / "...".formatted(x)
            name = self.text(node.child_by_field_name("name"))
            receiver = self.text(node.child_by_field_name("object"))
            return (name == "format" and receiver == "String") or name == "formatted"
        return False

    def named_literals(self, root: Node) -> Iterator[NamedLiteral]:
        for node in self.walk(root):
            if node.type == "variable_declarator":
                literal = self.string_value(node.child_by_field_name("value"))
                if literal is not None:
                    yield NamedLiteral(self.text(node.child_by_field_name("name")), literal, node)
            elif node.type == "assignment_expression":
                literal = self.string_value(node.child_by_field_name("right"))
                left = node.child_by_field_name("left")
                if literal is not None and left is not None:
                    yield NamedLiteral(self.text(left).rsplit(".", 1)[-1], literal, node)
            elif node.type == "method_invocation":
                # props.setProperty("db.password", "...") / headers.put("token", "...")
                args = self.call_args(node)
                if len(args) == 2:
                    key = self.string_value(args[0])
                    literal = self.string_value(args[1])
                    if key and literal is not None:
                        yield NamedLiteral(key, literal, node)
