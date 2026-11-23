"""Solidity AST -> facts. No regex, no source text scanning."""

from __future__ import annotations

from typing import Any

from contractmap.sources import astutil as ast
from contractmap.sources.facts import ContractFacts, StateVarFact
from contractmap.sources.functions import function_fact
from contractmap.sources.guards import (
    error_signature,
    event_signature,
    modifier_facts,
    role_constant_names,
)


def analyze(source_ast: dict[str, Any], source_name: str) -> list[ContractFacts]:
    """Extract facts for every contract, interface and library in one AST."""

    facts: list[ContractFacts] = []
    for node in ast.walk(source_ast):
        if node.get("nodeType") == "ContractDefinition":
            facts.append(contract_facts(node, source_name))
    return facts


def contract_facts(node: dict[str, Any], source_name: str) -> ContractFacts:
    name = node.get("name", "<unnamed>")
    kind = node.get("contractKind", "contract")
    if kind == "contract" and node.get("abstract"):
        kind = "abstract"
    roles = role_constant_names(node)
    modifiers = modifier_facts(node, roles)
    result = ContractFacts(
        name=name,
        kind=kind,
        source_name=source_name,
        modifiers=modifiers,
        roles=roles,
    )
    for base in ast.children(node, "baseContracts"):
        base_name = base.get("baseName", {})
        if not isinstance(base_name, dict):
            continue
        # solc emits IdentifierPath ({name: "Ownable"}); older/nested forms use
        # namePath or pathNode.
        resolved = (
            base_name.get("name")
            or base_name.get("namePath")
            or (base_name.get("pathNode") or {}).get("name")
        )
        if resolved:
            result.bases.append(str(resolved))

    for child in ast.children(node, "nodes"):
        child_type = child.get("nodeType")
        if child_type == "VariableDeclaration":
            result.state_vars.append(
                StateVarFact(
                    name=child.get("name", ""),
                    type=ast.type_name_of(child),
                    visibility=child.get("visibility"),
                    constant=bool(child.get("constant")),
                    immutable=bool(child.get("mutability") == "immutable"),
                    source=ast.source_location(child, source_name),
                )
            )
        elif child_type == "FunctionDefinition":
            fact = function_fact(child, modifiers, roles, source_name)
            if fact is not None:
                result.functions.append(fact)
                if any(call.kind == "delegatecall" for call in fact.calls):
                    result.uses_delegatecall = True
        elif child_type == "EventDefinition":
            result.events.append(event_signature(child))
        elif child_type == "ErrorDefinition":
            result.errors.append(error_signature(child))
    return result


def analyze_one(source_ast: dict[str, Any], name: str, source_name: str) -> ContractFacts | None:
    """Extract one named contract from a compilation-unit AST, ignoring the rest."""

    for node in ast.walk(source_ast):
        if node.get("nodeType") == "ContractDefinition" and node.get("name") == name:
            return contract_facts(node, source_name)
    return None
