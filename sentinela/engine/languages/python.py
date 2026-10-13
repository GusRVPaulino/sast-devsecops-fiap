"""Adaptador Tree-sitter para Python."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import tree_sitter_python
from tree_sitter import Node

from sentinela.engine.languages.base import (
    FileContext,
    LanguageAdapter,
    NamedLiteral,
    Param,
)

_CONSTANT_TYPES = {"integer", "float", "true", "false", "none"}


class PythonAdapter(LanguageAdapter):
    name = "python"
    extensions = (".py", ".pyw")
    call_types = frozenset({"call"})
    function_types = frozenset({"function_definition", "lambda"})
    assignment_types = frozenset({"assignment", "augmented_assignment"})
    loop_types = frozenset({"for_statement", "for_in_clause"})
    string_types = frozenset({"string", "concatenated_string"})

    def _grammar(self) -> Any:
        return tree_sitter_python.language()

    # ------------------------------------------------------------ contexto
    def build_context(self, root: Node) -> FileContext:
        ctx = FileContext()
        for node in self.walk(root):
            if node.type == "import_statement":
                for child in node.named_children:
                    if child.type == "dotted_name":
                        full = self.text(child)
                        ctx.aliases[full.split(".")[0]] = full.split(".")[0]
                    elif child.type == "aliased_import":
                        full = self.text(child.child_by_field_name("name"))
                        alias = self.text(child.child_by_field_name("alias"))
                        ctx.aliases[alias] = full
            elif node.type == "import_from_statement":
                module = self.text(node.child_by_field_name("module_name"))
                for child in node.children_by_field_name("name"):
                    if child.type == "dotted_name":
                        name = self.text(child)
                        ctx.aliases[name] = f"{module}.{name}"
                    elif child.type == "aliased_import":
                        name = self.text(child.child_by_field_name("name"))
                        alias = self.text(child.child_by_field_name("alias"))
                        ctx.aliases[alias] = f"{module}.{name}"
        return ctx

    # ------------------------------------------------------------ chamadas
    def call_name(self, node: Node, ctx: FileContext) -> str | None:
        function = node.child_by_field_name("function")
        if function is None:
            return None
        raw = self.normalize_call_name(self.text(function))
        if not raw:
            return None
        head, dot, rest = raw.partition(".")
        resolved = ctx.aliases.get(head)
        if resolved:
            return f"{resolved}{dot}{rest}" if rest else resolved
        return raw

    def call_args(self, node: Node) -> list[Node]:
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return []
        return [child for child in arguments.named_children if child.type not in {"keyword_argument", "comment"}]

    def call_kwargs(self, node: Node) -> dict[str, Node]:
        arguments = node.child_by_field_name("arguments")
        result: dict[str, Node] = {}
        if arguments is None:
            return result
        for child in arguments.named_children:
            if child.type == "keyword_argument":
                name = self.text(child.child_by_field_name("name"))
                value = child.child_by_field_name("value")
                if value is not None:
                    result[name] = value
        return result

    def call_receiver(self, node: Node) -> Node | None:
        function = node.child_by_field_name("function")
        if function is not None and function.type == "attribute":
            return function.child_by_field_name("object")
        return None

    # ---------------------------------------------------------- atribuições
    def assignment_targets(self, node: Node) -> list[tuple[str, Node | None]]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return [(name, right) for name in self._target_names(left)]

    def _target_names(self, node: Node | None) -> list[str]:
        if node is None:
            return []
        if node.type in {"identifier", "attribute"}:
            return [self.text(node)]
        if node.type == "subscript":
            key = node.child_by_field_name("subscript")
            value = self.string_value(key) if key is not None else None
            return [value] if value else [self.text(node.child_by_field_name("value"))]
        if node.type in {"pattern_list", "tuple_pattern", "list_pattern", "tuple", "list"}:
            names: list[str] = []
            for child in node.named_children:
                names.extend(self._target_names(child))
            return names
        return []

    def loop_binding(self, node: Node) -> tuple[list[str], Node | None]:
        return (
            self._target_names(node.child_by_field_name("left")),
            node.child_by_field_name("right"),
        )

    # ------------------------------------------------------------- funções
    def function_name(self, node: Node) -> str:
        return self.text(node.child_by_field_name("name")) or "<lambda>"

    def function_params(self, node: Node) -> list[Param]:
        params = node.child_by_field_name("parameters")
        if params is None:
            return []
        result = []
        for child in params.named_children:
            if child.type == "identifier":
                result.append(Param(self.text(child)))
            elif child.type in {
                "typed_parameter",
                "default_parameter",
                "typed_default_parameter",
            }:
                name_node = child.child_by_field_name("name") or next(
                    (c for c in child.named_children if c.type == "identifier"),
                    None,
                )
                type_node = child.child_by_field_name("type")
                result.append(
                    Param(self.text(name_node), type_name=self.text(type_node) or None),
                )
        return result

    # -------------------------------------------------------------- valores
    def reference_name(self, node: Node) -> str | None:
        if node.type == "identifier":
            return self.text(node)
        if node.type == "attribute":
            return self.normalize_call_name(self.text(node))
        if node.type == "subscript":
            return self.reference_name(node.child_by_field_name("value"))
        return None

    def string_value(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "string":
            if any(child.type == "interpolation" for child in node.children):
                return None
            return "".join(self.text(child) for child in node.children if child.type == "string_content")
        if node.type == "concatenated_string":
            parts = [self.string_value(child) for child in node.named_children]
            return None if any(part is None for part in parts) else "".join(parts)
        return None

    def is_constant(self, node: Node) -> bool:
        if node.type in _CONSTANT_TYPES:
            return True
        if node.type in self.string_types:
            return self.string_value(node) is not None
        if node.type == "binary_operator":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            return bool(left and right and self.is_constant(left) and self.is_constant(right))
        if node.type == "parenthesized_expression":
            return all(self.is_constant(c) for c in node.named_children)
        return False

    def is_dynamic_string(self, node: Node) -> bool:
        if node.type == "string":
            return any(child.type == "interpolation" for child in node.children)
        if node.type == "binary_operator":
            operator = self.text(node.child_by_field_name("operator"))
            left = node.child_by_field_name("left")
            has_string = any(
                child.type in self.string_types or self.is_dynamic_string(child) for child in node.named_children
            )
            if operator in {"+", "%"} and has_string:
                return not self.is_constant(node)
            return bool(left and self.is_dynamic_string(left))
        if node.type == "call":
            # "...".format(x)
            function = node.child_by_field_name("function")
            if function is not None and function.type == "attribute":
                obj = function.child_by_field_name("object")
                attr = self.text(function.child_by_field_name("attribute"))
                return attr == "format" and obj is not None and obj.type in self.string_types
        return False

    def named_literals(self, root: Node) -> Iterator[NamedLiteral]:
        for node in self.walk(root):
            if node.type == "assignment":
                value = node.child_by_field_name("right")
                literal = self.string_value(value)
                if literal is not None:
                    for name in self._target_names(node.child_by_field_name("left")):
                        yield NamedLiteral(name.split(".")[-1], literal, node)
            elif node.type == "keyword_argument":
                literal = self.string_value(node.child_by_field_name("value"))
                if literal is not None:
                    yield NamedLiteral(
                        self.text(node.child_by_field_name("name")),
                        literal,
                        node,
                    )
            elif node.type == "pair":
                key = self.string_value(node.child_by_field_name("key"))
                literal = self.string_value(node.child_by_field_name("value"))
                if key and literal is not None:
                    yield NamedLiteral(key, literal, node)
            elif node.type in {"default_parameter", "typed_default_parameter"}:
                literal = self.string_value(node.child_by_field_name("value"))
                name = node.child_by_field_name("name")
                if literal is not None and name is not None:
                    yield NamedLiteral(self.text(name), literal, node)
