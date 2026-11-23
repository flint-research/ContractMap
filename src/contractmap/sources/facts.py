"""Intermediate facts extracted from a Solidity AST before graph construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AccessKind = Literal["confirmed", "inferred", "unresolved", "none_identified"]
CallKind = Literal["call", "delegatecall", "staticcall", "callcode", "internal", "create"]

AUTHORIZATION_MODIFIER_HINTS = (
    "onlyowner",
    "onlyadmin",
    "onlygovernance",
    "onlygovernor",
    "onlyrole",
    "onlyminter",
    "onlypauser",
    "onlyoperator",
    "onlymanager",
    "onlytimelock",
    "onlykeeper",
    "adminonly",
    "restricted",
    "authorized",
)

PRIVILEGED_NAME_HINTS = ("owner", "admin", "governance", "governor", "timelock", "controller")


@dataclass(slots=True)
class ModifierFact:
    name: str
    role: str | None = None
    kind: AccessKind = "unresolved"
    detail: str = ""
    source: str | None = None


@dataclass(slots=True)
class CallFact:
    callee: str
    kind: CallKind
    receiver: str | None = None
    source: str | None = None


@dataclass(slots=True)
class FunctionFact:
    name: str
    signature: str
    visibility: str
    mutability: str
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    modifiers: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    access_kind: AccessKind = "unresolved"
    access_roles: list[str] = field(default_factory=list)
    access_detail: str = ""
    calls: list[CallFact] = field(default_factory=list)
    source: str | None = None
    # False for interface and abstract declarations, which have no body.
    implemented: bool = True
    parameters: list[str] = field(default_factory=list)
    # Root names assigned in the body that are not locals: state variables.
    writes: list[str] = field(default_factory=list)
    # `onlyRole(FEE_ROLE)` -> ["fee"]: the role named at the call site.
    modifier_roles: list[str] = field(default_factory=list)
    # Set on copies of inherited functions: the contract that declares them.
    declared_in: str | None = None


@dataclass(slots=True)
class StateVarFact:
    name: str
    type: str
    visibility: str | None = None
    constant: bool = False
    immutable: bool = False
    source: str | None = None


@dataclass(slots=True)
class ContractFacts:
    name: str
    kind: str
    source_name: str
    bases: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    state_vars: list[StateVarFact] = field(default_factory=list)
    functions: list[FunctionFact] = field(default_factory=list)
    modifiers: dict[str, ModifierFact] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    roles: dict[str, str] = field(default_factory=dict)
    uses_delegatecall: bool = False
