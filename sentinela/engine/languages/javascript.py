"""Adaptador Tree-sitter para JavaScript (Node.js e navegador)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import tree_sitter_javascript
from tree_sitter import Node

from sentinela.engine.languages.base import (
    FileContext,
    LanguageAdapter,
    NamedLiteral,
    Param,
)

_CONSTANT_TYPES = {"number", "true", "false", "null", "undefined", "regex"}


class JavaScriptAdapter(LanguageAdapter):
    name = "javascript"
    extensions = (".js", ".jsx", ".mjs", ".cjs")
    call_types = frozenset({"call_expression", "new_expression"})
    function_types = frozenset(
        {
            "function_declaration",
            "function_expression",
            "function",
            "arrow_function",
            "method_definition",
            "generator_function_declaration",
        },
    )
    assignment_types = frozenset(
        {"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
    )
    loop_types = frozenset({"for_in_statement"})
    string_types = frozenset({"string", "template_string"})

    def _grammar(self) -> Any:
        return tree_sitter_javascript.language()

    # ------------------------------------------------------------ contexto
    def build_context(self, root: Node) -> FileContext:
        ctx = FileContext()
        for node in self.walk(root):
            if node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                module = self._required_module(value)
                if module is None:
                    continue
                target = node.child_by_field_name("name")
                if target is None:
                    continue
                if target.type == "identifier":
                    ctx.aliases[self.text(target)] = module
                elif target.type == "object_pattern":
                    for prop in target.named_children:
                        if prop.type == "shorthand_property_identifier_pattern":
                            name = self.text(prop)
                            ctx.aliases[name] = f"{module}.{name}"
                        elif prop.type == "pair_pattern":
                            key = self.text(prop.child_by_field_name("key"))
                            local = self.text(prop.child_by_field_name("value"))
                            ctx.aliases[local] = f"{module}.{key}"
            elif node.type == "import_statement":
                source = self.string_value(node.child_by_field_name("source"))
                if not source:
                    continue
                for clause in node.named_children:
                    if clause.type != "import_clause":
                        continue
                    for item in clause.named_children:
                        if item.type == "identifier":
                            ctx.aliases[self.text(item)] = source
                        elif item.type == "namespace_import":
                            for name in item.named_children:
                                ctx.aliases[self.text(name)] = source
                        elif item.type == "named_imports":
                            for spec in item.named_children:
                                if spec.type != "import_specifier":
                                    continue
                                name = self.text(spec.child_by_field_name("name"))
                                alias = self.text(spec.child_by_field_name("alias")) or name
                                ctx.aliases[alias] = f"{source}.{name}"
        return ctx

    def _required_module(self, node: Node | None) -> str | None:
        if node is None or node.type != "call_expression":
            return None
        function = node.child_by_field_name("function")
        if function is None or self.text(function) != "require":
            return None
        args = self.call_args(node)
        return self.string_value(args[0]) if args else None

    # ------------------------------------------------------------ chamadas
    def call_name(self, node: Node, ctx: FileContext) -> str | None:
        if node.type == "new_expression":
            constructor = node.child_by_field_name("constructor")
            return f"new {self.normalize_call_name(self.text(constructor))}" if constructor else None
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
        if arguments.type == "template_string":  # tag`...`
            return [arguments]
        return [child for child in arguments.named_children if child.type != "comment"]

    def call_kwargs(self, node: Node) -> dict[str, Node]:
        """Opções passadas como objeto literal no último argumento ({shell: true})."""

        args = self.call_args(node)
        result: dict[str, Node] = {}
        if args and args[-1].type == "object":
            for pair in args[-1].named_children:
                if pair.type == "pair":
                    key = self.text(pair.child_by_field_name("key")).strip("'\"")
                    value = pair.child_by_field_name("value")
                    if value is not None:
                        result[key] = value
        return result

    def call_receiver(self, node: Node) -> Node | None:
        function = node.child_by_field_name("function")
        if function is not None and function.type == "member_expression":
            return function.child_by_field_name("object")
        return None

    # ---------------------------------------------------------- atribuições
    def assignment_targets(self, node: Node) -> list[tuple[str, Node | None]]:
        if node.type == "variable_declarator":
            target = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
        else:
            target = node.child_by_field_name("left")
            value = node.child_by_field_name("right")
        return [(name, value) for name in self._target_names(target)]

    def _target_names(self, node: Node | None) -> list[str]:
        if node is None:
            return []
        if node.type in {"identifier", "member_expression"}:
            return [self.normalize_call_name(self.text(node))]
        if node.type == "subscript_expression":
            return [self.normalize_call_name(self.text(node.child_by_field_name("object")))]
        if node.type in {"object_pattern", "array_pattern"}:
            names: list[str] = []
            for child in node.named_children:
                if child.type in {"shorthand_property_identifier_pattern", "identifier"}:
                    names.append(self.text(child))
                elif child.type == "pair_pattern":
                    names.extend(self._target_names(child.child_by_field_name("value")))
            return names
        return []

    def loop_binding(self, node: Node) -> tuple[list[str], Node | None]:
        left = node.child_by_field_name("left")
        if left is not None and left.type in {"lexical_declaration", "variable_declaration"}:
            names = []
            for declarator in left.named_children:
                names.extend(self._target_names(declarator.child_by_field_name("name")))
        else:
            names = self._target_names(left)
        return names, node.child_by_field_name("right")

    def member_assignment(self, node: Node) -> tuple[str, Node] | None:
        if node.type != "assignment_expression" and node.type != "augmented_assignment_expression":
            return None
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "member_expression":
            return None
        return self.text(left.child_by_field_name("property")), right

    # ------------------------------------------------------------- funções
    def function_name(self, node: Node) -> str:
        name = node.child_by_field_name("name")
        if name is not None:
            return self.text(name)
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            return self.text(parent.child_by_field_name("name"))
        return "<anonymous>"

    def function_params(self, node: Node) -> list[Param]:
        params = node.child_by_field_name("parameters")
        if params is None:
            single = node.child_by_field_name("parameter")
            return [Param(self.text(single))] if single is not None else []
        result = []
        for child in params.named_children:
            if child.type == "identifier":
                result.append(Param(self.text(child)))
            elif child.type == "assignment_pattern":
                result.append(Param(self.text(child.child_by_field_name("left"))))
            elif child.type in {"object_pattern", "array_pattern"}:
                for name in self._target_names(child):
                    result.append(Param(name))
        return result

    # -------------------------------------------------------------- valores
    def reference_name(self, node: Node) -> str | None:
        if node.type in {"identifier", "shorthand_property_identifier"}:
            return self.text(node)
        if node.type == "member_expression":
            return self.normalize_call_name(self.text(node))
        if node.type == "subscript_expression":
            return self.reference_name(node.child_by_field_name("object"))
        return None

    def string_value(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "string":
            return "".join(
                self.text(child)
                for child in node.named_children
                if child.type in {"string_fragment", "escape_sequence"}
            )
        if node.type == "template_string":
            if any(child.type == "template_substitution" for child in node.named_children):
                return None
            return "".join(self.text(child) for child in node.named_children if child.type == "string_fragment")
        return None

    def is_constant(self, node: Node) -> bool:
        if node.type in _CONSTANT_TYPES:
            return True
        if node.type in self.string_types:
            return self.string_value(node) is not None
        if node.type == "binary_expression":
            return all(self.is_constant(child) for child in node.named_children)
        if node.type == "parenthesized_expression":
            return all(self.is_constant(child) for child in node.named_children)
        return False

    def is_dynamic_string(self, node: Node) -> bool:
        if node.type == "template_string":
            return self.string_value(node) is None
        if node.type == "binary_expression":
            operator = self.text(node.child_by_field_name("operator"))
            has_string = any(
                child.type in self.string_types or self.is_dynamic_string(child) for child in node.named_children
            )
            return operator == "+" and has_string and not self.is_constant(node)
        return False

    def named_literals(self, root: Node) -> Iterator[NamedLiteral]:
        for node in self.walk(root):
            if node.type in {"variable_declarator", "assignment_expression"}:
                for name, value in self.assignment_targets(node):
                    literal = self.string_value(value)
                    if literal is not None:
                        yield NamedLiteral(name.split(".")[-1], literal, node)
            elif node.type == "pair":
                key_node = node.child_by_field_name("key")
                key = self.string_value(key_node) if key_node is not None else None
                key = key or self.text(key_node)
                literal = self.string_value(node.child_by_field_name("value"))
                if key and literal is not None:
                    yield NamedLiteral(key, literal, node)
