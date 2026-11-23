"""Per-function extraction: signature, visibility, authorization and calls."""

from __future__ import annotations

from typing import Any

from contractmap.sources import astutil as ast
from contractmap.sources.facts import (
    AUTHORIZATION_MODIFIER_HINTS,
    CallFact,
    FunctionFact,
    ModifierFact,
)
from contractmap.sources.guards import call_signature, guard_in_expression

LOW_LEVEL_CALLS = {"call", "delegatecall", "staticcall", "callcode"}
VALUE_TRANSFERS = {"transfer", "send"}


def function_fact(
    node: dict[str, Any],
    modifiers: dict[str, ModifierFact],
    roles: dict[str, str],
    source_name: str,
) -> FunctionFact | None:
    kind = node.get("kind", "function")
    name = node.get("name", "")
    inputs = [p for p in node.get("parameters", {}).get("parameters", []) if isinstance(p, dict)]
    outputs = [
        p for p in node.get("returnParameters", {}).get("parameters", []) if isinstance(p, dict)
    ]
    is_constructor = kind == "constructor" or bool(node.get("isConstructor"))
    is_receive = kind == "receive"
    is_fallback = kind == "fallback" or (name == "" and not is_constructor and not is_receive)
    display_name = name or (
        "constructor" if is_constructor else "fallback" if is_fallback else "receive"
    )

    modifier_names: list[str] = []
    modifier_roles: list[str] = []
    for invocation in node.get("modifiers", []) or []:
        if not isinstance(invocation, dict):
            continue
        modifier_node = invocation.get("modifierName", {})
        modifier_name = modifier_node.get("name") or modifier_node.get("namePath")
        if modifier_name:
            modifier_names.append(str(modifier_name))
        for argument in invocation.get("arguments") or []:
            role = ast.identifier_name(argument) or ast.member_name(argument) or ""
            if role.endswith("_ROLE"):
                modifier_roles.append(role.removesuffix("_ROLE").lower())

    body = node.get("body")
    access_kind, access_roles, detail = resolve_access(modifier_names, modifiers, body, roles)
    calls = collect_calls(body, source_name) if isinstance(body, dict) else []
    parameters = [str(p["name"]) for p in inputs if p.get("name")]
    returns = [str(p["name"]) for p in outputs if p.get("name")]

    return FunctionFact(
        name=display_name,
        signature="constructor(...)" if is_constructor else call_signature(display_name, inputs),
        visibility=node.get("visibility", "public") if not is_fallback else "external",
        mutability=node.get("stateMutability", "nonpayable"),
        is_constructor=is_constructor,
        is_fallback=is_fallback,
        is_receive=is_receive,
        modifiers=modifier_names,
        inputs=[ast.type_name_of(p) for p in inputs],
        outputs=[ast.type_name_of(p) for p in outputs],
        access_kind=access_kind,  # type: ignore[arg-type]
        access_roles=access_roles,
        access_detail=detail,
        calls=calls,
        source=ast.source_location(node, source_name),
        implemented=bool(node.get("implemented", isinstance(body, dict))),
        parameters=parameters,
        writes=state_writes(body, {*parameters, *returns}) if isinstance(body, dict) else [],
        modifier_roles=sorted(set(modifier_roles)),
    )


def state_writes(body: dict[str, Any], names: set[str]) -> list[str]:
    """State variables a body assigns, increments or deletes.

    Anything not declared inside the function is state. A write through a local
    storage pointer (diamond storage, `Data storage d = ...; d.owner = x`) is
    recorded by the field it writes, since that field is the state.
    """

    local = set(names)
    storage_pointers: set[str] = set()
    for node in ast.walk(body):
        if node.get("nodeType") == "VariableDeclaration" and node.get("name"):
            local.add(node["name"])
            if node.get("storageLocation") == "storage":
                storage_pointers.add(node["name"])

    written: set[str] = set()
    for node in ast.walk(body):
        kind = node.get("nodeType")
        targets: list[Any] = []
        if kind == "Assignment":
            targets = [node.get("leftHandSide")]
        elif kind == "UnaryOperation" and node.get("operator") in {"++", "--", "delete"}:
            targets = [node.get("subExpression")]
        for target in targets:
            if isinstance(target, dict) and target.get("nodeType") == "TupleExpression":
                targets.extend(c for c in target.get("components") or [] if c)
                continue
            name = _written_name(target, local, storage_pointers)
            if name:
                written.add(name)
    return sorted(written)


def _written_name(node: Any, local: set[str], storage_pointers: set[str]) -> str | None:
    member: str | None = None
    while isinstance(node, dict) and node.get("nodeType") in {"IndexAccess", "MemberAccess"}:
        if node.get("nodeType") == "MemberAccess":
            member = node.get("memberName")
            node = node.get("expression")
        else:
            node = node.get("baseExpression")
    root = ast.identifier_name(node)
    if root is None:
        return None
    if root in storage_pointers:
        return member
    return None if root in local else root


def resolve_access(
    modifier_names: list[str],
    modifiers: dict[str, ModifierFact],
    body: Any,
    roles: dict[str, str],
) -> tuple[str, list[str], str]:
    """Decide one function's access state from modifiers, then from its body.

    A function is only reported as unrestricted when the walker saw its body and
    found no guard in it. Anything the walker could not resolve stays unresolved.
    """

    roles_found: list[str] = []
    kinds: list[str] = []
    details: list[str] = []
    for name in modifier_names:
        fact = modifiers.get(name)
        if fact is None:
            continue
        kinds.append(fact.kind)
        details.append(f"{name}: {fact.detail}")
        if fact.role:
            roles_found.append(fact.role)

    if not isinstance(body, dict):
        return "unresolved", sorted(set(roles_found)), "function body not present in the AST"

    guard = guard_in_expression(body, roles)
    if guard is not None:
        role, detail = guard
        kinds.append("confirmed")
        details.append(f"body: {detail}")
        if role:
            roles_found.append(role)

    if "confirmed" in kinds:
        return "confirmed", sorted(set(roles_found)), "; ".join(details)
    if "inferred" in kinds:
        return "inferred", sorted(set(roles_found)), "; ".join(details)
    joined = " ".join(modifier_names).lower().replace("_", "")
    if any(hint in joined for hint in AUTHORIZATION_MODIFIER_HINTS):
        return "inferred", sorted(set(roles_found)), "modifier name suggests authorization"
    return "none_identified", [], "no guard found in modifiers or body"


def collect_calls(body: dict[str, Any], source_name: str) -> list[CallFact]:
    calls: list[CallFact] = []
    for node in ast.walk(body):
        node_kind = node.get("nodeType")
        location = ast.source_location(node, source_name)
        if node_kind == "FunctionCall":
            receiver, member = ast.called_function(node)
            if member in LOW_LEVEL_CALLS:
                calls.append(
                    CallFact(
                        callee=f".{member}",
                        kind=member,  # type: ignore[arg-type]
                        receiver=receiver,
                        source=location,
                    )
                )
            elif member in VALUE_TRANSFERS:
                calls.append(
                    CallFact(callee=f".{member}", kind="call", receiver=receiver, source=location)
                )
            elif member and receiver == "super":
                calls.append(
                    CallFact(callee=member, kind="internal", receiver="super", source=location)
                )
            elif member and receiver != "this" and _is_member_call(node):
                # The receiver's type decides: a contract or address is an external call;
                # `Lib.f()` and `amount.applyFee()` (using-for on a value) run in place.
                # `IERC20(token).transfer()` has no receiver name but is external.
                target = _receiver_type(node)
                external = (
                    target.startswith(("contract ", "address"))
                    if target is not None
                    else receiver is not None
                )
                if external:
                    label = receiver or (target or "").removeprefix("contract ").split(" ")[0]
                    calls.append(
                        CallFact(
                            callee=f"{label}.{member}",
                            kind="call",
                            receiver=receiver,
                            source=location,
                        )
                    )
            else:
                expression = node.get("expression", {})
                if isinstance(expression, dict) and expression.get("nodeType") == "Identifier":
                    calls.append(
                        CallFact(
                            callee=str(expression.get("name", "")),
                            kind="internal",
                            source=location,
                        )
                    )
        elif node_kind == "NewExpression":
            type_name = node.get("typeName", {})
            created = type_name.get("namePath") or type_name.get("name")
            if created:
                calls.append(CallFact(callee=str(created), kind="create", source=location))
    return calls


def _is_member_call(call: dict[str, Any]) -> bool:
    expression = call.get("expression", {})
    if isinstance(expression, dict) and expression.get("nodeType") == "FunctionCallOptions":
        expression = expression.get("expression", {})
    return isinstance(expression, dict) and expression.get("nodeType") == "MemberAccess"


def _receiver_type(call: dict[str, Any]) -> str | None:
    """solc's type string for the `x` in `x.f()`, or None when the AST has none."""

    expression = call.get("expression", {})
    if isinstance(expression, dict) and expression.get("nodeType") == "FunctionCallOptions":
        expression = expression.get("expression", {})
    if not isinstance(expression, dict) or expression.get("nodeType") != "MemberAccess":
        return None
    receiver = expression.get("expression")
    described = receiver.get("typeDescriptions", {}) if isinstance(receiver, dict) else {}
    value = described.get("typeString") if isinstance(described, dict) else None
    return value if isinstance(value, str) else None
