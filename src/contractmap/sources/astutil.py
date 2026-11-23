"""Helpers for navigating Solidity AST nodes."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

Node = dict[str, Any]


def walk(node: Any) -> Iterator[Node]:
    """Depth-first traversal over every dict that carries a ``nodeType``."""

    if isinstance(node, dict):
        if "nodeType" in node:
            yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)


def children(node: Node, key: str) -> list[Node]:
    value = node.get(key)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def node_type(node: Any) -> str:
    return node.get("nodeType", "") if isinstance(node, dict) else ""


def source_location(node: Node, file_path: str | None = None) -> str | None:
    src = node.get("src")
    if not isinstance(src, str):
        return None
    parts = src.split(":")
    if len(parts) < 2:
        return None
    start, length = parts[0], parts[1]
    prefix = f"{file_path}:" if file_path else ""
    return f"{prefix}{start}:{length}"


def type_name_of(node: Node) -> str:
    """Best-effort readable type for a declaration node."""

    type_name = node.get("typeDescriptions", {}).get("typeString")
    if isinstance(type_name, str) and type_name:
        return type_name.replace("contract ", "").replace("struct ", "").split(" memory")[0]
    raw = node.get("typeName", {})
    if isinstance(raw, dict):
        kind = raw.get("nodeType")
        if kind == "ElementaryTypeName":
            return str(raw.get("name", "unknown"))
        if kind == "UserDefinedTypeName":
            identifier_path = raw.get("pathNode")
            name = (
                raw.get("name")
                or raw.get("namePath")
                or (identifier_path or {}).get("name")
                or "unknown"
            )
            return str(name)
        if kind == "ArrayTypeName":
            return f"{type_name_of(raw)}[]"
        if kind == "Mapping":
            key = type_name_of(raw.get("keyType", {}))
            value = type_name_of(raw.get("valueType", {}))
            return f"mapping({key} => {value})"
    return "unknown"


def identifier_name(node: Any) -> str | None:
    if not isinstance(node, dict):
        return None
    if node.get("nodeType") == "Identifier":
        return node.get("name")
    if node.get("nodeType") == "ElementaryTypeNameExpression":
        return node.get("typeName", {}).get("name")
    return None


def member_name(node: Any) -> str | None:
    if isinstance(node, dict) and node.get("nodeType") == "MemberAccess":
        return node.get("memberName")
    return None


def references_msg_sender(node: Any) -> bool:
    """True when the subtree reads ``msg.sender`` or ``msg.sig``."""

    for item in walk(node):
        if item.get("nodeType") == "Identifier" and item.get("name") == "msg":
            return True
    return False


def called_function(node: Any) -> tuple[str | None, str | None]:
    """(receiver, member) for a call expression, e.g. (``msg``, ``sender``)."""

    if not isinstance(node, dict) or node.get("nodeType") != "FunctionCall":
        return None, None
    expression = node.get("expression", {})
    if isinstance(expression, dict) and expression.get("nodeType") == "FunctionCallOptions":
        # `to.call{value: v}(data)`: the options wrap the real callee.
        expression = expression.get("expression", {})
    if isinstance(expression, dict) and expression.get("nodeType") == "MemberAccess":
        receiver = identifier_name(expression.get("expression"))
        return receiver, expression.get("memberName")
    return None, identifier_name(expression)


def literal_string(node: Any) -> str | None:
    if isinstance(node, dict) and node.get("nodeType") == "Literal":
        return node.get("value")
    return None
