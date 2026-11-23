"""Authorization evidence: guards in modifier bodies, role constants, signatures.

A guard is only recorded when the AST shows an actual check: a call to a known
authorization helper, or a comparison against an owner/admin/role value inside a
require or a revert branch. Merely reading ``msg.sender`` is not evidence of a
restriction, so functions that only use it for bookkeeping stay unrestricted.
"""

from __future__ import annotations

from typing import Any

from contractmap.sources import astutil as ast
from contractmap.sources.facts import (
    AUTHORIZATION_MODIFIER_HINTS,
    PRIVILEGED_NAME_HINTS,
    ModifierFact,
)

ROLE_GUARDS = {"hasRole", "_checkRole", "checkRole", "onlyRole"}
OWNER_GUARDS = {"_checkOwner", "checkOwner", "onlyOwner"}

COMPARISON_OPERATORS = {"==", "!="}
PRIVILEGE_VARIABLES = (
    "owner",
    "admin",
    "governor",
    "governance",
    "timelock",
    "operator",
    "guardian",
    "controller",
    "keeper",
    "manager",
    "multisig",
    "pauser",
    "minter",
)
# A call that is handed the caller and is named like a check reverts on failure:
# `_checkCaller(msg.sender)`, `_onlyAllowed(msg.sender)`.
CHECK_CALL_PREFIXES = ("check", "only", "require", "verify", "assert", "ensure")
# A call that is handed the caller and returns a verdict, inside a condition:
# solmate `isAuthorized(msg.sender, msg.sig)`, `canCall(...)`, `isWhitelisted(...)`.
AUTH_CALL_HINTS = (
    "auth",
    "role",
    "allowed",
    "whitelist",
    "allowlist",
    "owner",
    "admin",
    "access",
    "cancall",
    "permission",
    "trusted",
    "operator",
    "keeper",
    "guardian",
    "governor",
    "minter",
)
# Calls that return the caller: OpenZeppelin `Context` and ERC-2771 forwarders.
SENDER_CALLS = {"_msgSender", "msgSender"}
# A mapping indexed by the caller whose name says it decides who may act:
# `wards[msg.sender]`, `isAdmin[msg.sender]`, `authorized[_msgSender()]`.
MEMBERSHIP_HINTS = (
    "admin",
    "owner",
    "auth",
    "ward",
    "role",
    "whitelist",
    "allowlist",
    "operator",
    "minter",
    "keeper",
    "govern",
    "manager",
    "guardian",
    "trusted",
    "controller",
)


def call_signature(name: str, inputs: list[dict[str, Any]]) -> str:
    return f"{name}({','.join(ast.type_name_of(p) for p in inputs)})"


def event_signature(node: dict[str, Any]) -> str:
    params = node.get("parameters", {}).get("parameters", [])
    return call_signature(node.get("name", ""), [p for p in params if isinstance(p, dict)])


def error_signature(node: dict[str, Any]) -> str:
    return event_signature(node)


def role_constant_names(contract_node: dict[str, Any]) -> dict[str, str]:
    """``MINTER_ROLE`` -> ``minter`` for constants declared in this contract."""

    roles: dict[str, str] = {}
    for node in ast.children(contract_node, "nodes"):
        if node.get("nodeType") != "VariableDeclaration":
            continue
        name = node.get("name", "")
        if name.endswith("_ROLE") and node.get("constant"):
            roles[name] = name.removesuffix("_ROLE").lower()
    return roles


def role_from_name(name: str) -> str:
    lowered = name.lower()
    for hint in PRIVILEGED_NAME_HINTS:
        if hint in lowered:
            return hint
    stripped = lowered.replace("only", "").replace("require", "").replace("_", "").strip()
    return stripped or "privileged"


def guard_in_expression(expression: Any, roles: dict[str, str]) -> tuple[str, str] | None:
    """Return ``(role, detail)`` when a subtree contains a real authorization check.

    Only two shapes count: a call to a known authorization helper, and an equality
    test against a privileged value. Reading ``msg.sender`` for bookkeeping is not
    a guard, and neither is a balance comparison.
    """

    if not isinstance(expression, dict):
        return None
    # `address sender = _msgSender();` makes `sender` the caller for the checks below.
    aliases = frozenset(
        str(declaration.get("name"))
        for node in ast.walk(expression)
        if node.get("nodeType") == "VariableDeclarationStatement"
        and _is_sender(node.get("initialValue"))
        for declaration in node.get("declarations") or []
        if isinstance(declaration, dict) and declaration.get("name")
    )

    for node in ast.walk(expression):
        kind = node.get("nodeType")
        if kind == "FunctionCall":
            _, member = ast.called_function(node)
            # `hasRole(role, account)` about some other account is a lookup, not a
            # guard: OpenZeppelin's `_grantRole` asks it before granting.
            about_other = len(node.get("arguments") or []) >= 2 and not _passes_sender(
                node, aliases
            )
            if member in ROLE_GUARDS and not about_other:
                return _role_guard_role(node)
            if member in OWNER_GUARDS:
                return "owner", f"{member}()"
            if member == "_checkAdmin":
                return "admin", "_checkAdmin()"
            checks = member and member.lower().lstrip("_").startswith(CHECK_CALL_PREFIXES)
            if member and checks and _passes_sender(node, aliases):
                return _hint(member, PRIVILEGE_VARIABLES) or "role", f"{member}(msg.sender)"
        elif kind == "BinaryOperation" and node.get("operator") in COMPARISON_OPERATORS:
            found = _identity_comparison(node, roles, aliases)
            if found is not None:
                return found
    # A caller-indexed mapping only counts inside a check: `operators[msg.sender] = true`
    # is bookkeeping, `require(operators[msg.sender])` is a guard.
    for condition in _conditions(expression):
        for node in ast.walk(condition):
            if node.get("nodeType") == "FunctionCall" and _passes_sender(node, aliases):
                member = ast.called_function(node)[1]
                if member and _hint(member, AUTH_CALL_HINTS):
                    return _hint(member, PRIVILEGE_VARIABLES) or "role", f"{member}(msg.sender)"
            index = node.get("indexExpression")
            if node.get("nodeType") == "IndexAccess" and _is_sender(index, aliases):
                base = node.get("baseExpression")
                name = ast.identifier_name(base) or ast.member_name(base)
                hint = _hint(name, MEMBERSHIP_HINTS)
                if name and hint:
                    return hint, f"{name}[msg.sender]"
    return None


def _passes_sender(node: dict[str, Any], aliases: frozenset[str] = frozenset()) -> bool:
    return any(_is_sender(argument, aliases) for argument in node.get("arguments") or [])


def _conditions(expression: Any) -> list[Any]:
    """The expressions that decide whether execution continues."""

    found: list[Any] = []
    for node in ast.walk(expression):
        if node.get("nodeType") == "FunctionCall" and node.get("arguments"):
            if ast.called_function(node)[1] in {"require", "assert"}:
                found.append(node["arguments"][0])
        elif node.get("nodeType") in {"IfStatement", "Conditional"}:
            found.append(node.get("condition"))
    return found


def _hint(name: str | None, hints: tuple[str, ...]) -> str | None:
    lowered = (name or "").lower()
    return next((hint for hint in hints if hint in lowered), None)


def _unwrap_conversion(node: Any) -> Any:
    """``address(x)`` -> ``x``: a type conversion does not change who is compared."""

    if isinstance(node, dict) and node.get("kind") == "typeConversion":
        arguments = node.get("arguments") or []
        if len(arguments) == 1:
            return _unwrap_conversion(arguments[0])
    return node


def _role_guard_role(node: dict[str, Any]) -> tuple[str, str]:
    _, member = ast.called_function(node)
    for argument in node.get("arguments", []):
        if not isinstance(argument, dict):
            continue
        name = ast.identifier_name(argument)
        if name and name.endswith("_ROLE"):
            return name.removesuffix("_ROLE").lower(), f"{member}({name}, ...)"
        literal = ast.literal_string(argument)
        if literal:
            return literal.lower(), f"{member}({literal!r}, ...)"
    return "role", f"{member}(...) without a statically resolvable role id"


def _identity_comparison(
    node: dict[str, Any], roles: dict[str, str], aliases: frozenset[str] = frozenset()
) -> tuple[str, str] | None:
    """``msg.sender == owner`` counts; ``balances[msg.sender] < amount`` does not."""

    sides = [node.get("leftExpression"), node.get("rightExpression")]
    sender_side = next((side for side in sides if _is_sender(side, aliases)), None)
    if sender_side is None:
        return None
    other = sides[0] if sender_side is sides[1] else sides[1]
    reference = _privileged_reference(other, roles)
    if reference is None:
        return None
    role, label = reference
    operator = node.get("operator")
    return role, f"msg.sender {operator} {label}"


def _is_sender(node: Any, aliases: frozenset[str] = frozenset()) -> bool:
    node = _unwrap_conversion(node)
    if not isinstance(node, dict):
        return False
    if aliases and ast.identifier_name(node) in aliases:
        return True
    if node.get("nodeType") == "MemberAccess" and node.get("memberName") == "sender":
        return ast.identifier_name(node.get("expression")) == "msg"
    if node.get("nodeType") == "FunctionCall" and not node.get("arguments"):
        return ast.called_function(node)[1] in SENDER_CALLS
    return False


def _privileged_reference(node: Any, roles: dict[str, str]) -> tuple[str, str] | None:
    node = _unwrap_conversion(node)
    if not isinstance(node, dict):
        return None
    if node.get("nodeType") == "FunctionCall" and not node.get("arguments"):
        # A getter: `owner()`, `getGovernance()`, `registry.admin()`.
        getter = ast.called_function(node)[1]
        hint = _hint(getter, PRIVILEGE_VARIABLES)
        return (hint, f"{getter}()") if getter and hint else None
    # A state variable, or a field such as diamond storage's `ds.contractOwner`.
    name = ast.identifier_name(node) or ast.member_name(node)
    if name:
        if name.endswith("_ROLE"):
            return roles.get(name, name.removesuffix("_ROLE").lower()), name
        hint = _hint(name, PRIVILEGE_VARIABLES)
        return (hint, name) if hint else None
    if node.get("nodeType") == "IndexAccess":
        base = ast.identifier_name(node.get("baseExpression"))
        if base and any(hint in base.lower() for hint in ("role", "admin", "owner")):
            return "role", f"{base}[...]"
    return None


def modifier_facts(contract_node: dict[str, Any], roles: dict[str, str]) -> dict[str, ModifierFact]:
    facts: dict[str, ModifierFact] = {}
    for node in ast.children(contract_node, "nodes"):
        if node.get("nodeType") != "ModifierDefinition":
            continue
        name = node.get("name") or ""
        body = node.get("body")
        guard = guard_in_expression(body, roles) if isinstance(body, dict) else None
        if guard is not None:
            role, detail = guard
            facts[name] = ModifierFact(
                name=name,
                role=role,
                kind="confirmed",
                detail=f"guard body checks {detail}",
                source=ast.source_location(node),
            )
        elif any(hint in name.lower().replace("_", "") for hint in AUTHORIZATION_MODIFIER_HINTS):
            facts[name] = ModifierFact(
                name=name,
                role=role_from_name(name),
                kind="inferred",
                detail="name indicates authorization but the guard body was not resolved",
                source=ast.source_location(node),
            )
    return facts
