"""Validated data model shared by the analysis engine, exporters and API users."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.1"

# Display order for observations: direct takeover paths first, context last.
OBSERVATION_PRIORITY = (
    "unguarded_dangerous_operation",
    "unguarded_privileged_write",
    "administrative_function",
    "authorization_unresolved",
    "proxy_upgrade",
    "diamond_architecture",
    "delegatecall_usage",
    "unverified_dispatch",
    "external_call",
    "token_interaction",
    "oracle_dependency",
    "payable_entry_point",
    "inheritance_structure",
)


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ContractKind(StrEnum):
    CONTRACT = "contract"
    ABSTRACT = "abstract"
    INTERFACE = "interface"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class Visibility(StrEnum):
    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"


class Mutability(StrEnum):
    PURE = "pure"
    VIEW = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE = "payable"


class NodeKind(StrEnum):
    CONTRACT = "contract"
    PROXY = "proxy"
    IMPLEMENTATION = "implementation"
    BEACON = "beacon"
    FACET = "facet"
    LIBRARY = "library"
    FUNCTION = "function"
    ROLE = "role"
    PRIVILEGED_ACCOUNT = "privileged_account"
    EXTERNAL_TARGET = "external_target"


class EdgeKind(StrEnum):
    INHERITS = "inherits"
    IMPLEMENTS = "implements"
    CALLS = "calls"
    DELEGATECALLS = "delegatecalls"
    USES_LIBRARY = "uses_library"
    CONTROLLED_BY = "controlled_by"
    PROTECTED_BY = "protected_by"
    PROXIES_TO = "proxies_to"
    RESOLVES_VIA_BEACON = "resolves_via_beacon"
    HAS_FACET = "has_facet"
    REFERENCES_DEPENDENCY = "references_dependency"
    EXPOSES = "exposes"


class Resolution(StrEnum):
    """How strongly an extracted relationship or permission is established."""

    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNRESOLVED = "unresolved"


class AccessRestriction(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    NONE_IDENTIFIED = "none_identified"
    UNRESOLVED = "unresolved"


class ProxyKind(StrEnum):
    ERC1967 = "erc1967"
    ERC1967_BEACON = "erc1967_beacon"
    ERC1167 = "erc1167"
    DIAMOND = "diamond"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class SourceKind(StrEnum):
    """Provenance of the bytecode and ABI used for a contract."""

    COMPILED_SOURCE = "compiled_source"
    BUILD_ARTIFACT = "build_artifact"
    VERIFIED_SOURCE = "verified_source"
    DEPLOYED_BYTECODE = "deployed_bytecode"


class Evidence(Base):
    kind: str
    detail: str
    source: str | None = None
    value: str | None = None


class ChainInfo(Base):
    chain_id: int | None = None
    name: str | None = None
    block_number: int | None = None
    block_hash: str | None = None


class TargetInfo(Base):
    kind: Literal["local", "address"]
    identifier: str
    chain_id: int | None = None
    block_number: int | None = None
    code_hash: str | None = None
    build_system: str | None = None
    resolved_paths: list[str] = Field(default_factory=list)


class StateVariable(Base):
    id: str
    name: str
    type: str
    visibility: Visibility | None = None
    constant: bool = False
    immutable: bool = False
    slot: str | None = None
    offset: int | None = None
    source: str | None = None


class StorageEntry(Base):
    label: str
    slot: str
    offset: int
    type: str


class EventItem(Base):
    name: str
    signature: str
    topic0: str
    source: str | None = None


class ErrorItem(Base):
    name: str
    signature: str
    selector: str
    source: str | None = None


class AccessAssessment(Base):
    restriction: AccessRestriction = AccessRestriction.UNRESOLVED
    roles: list[str] = Field(default_factory=list)
    modifiers: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class FunctionModel(Base):
    id: str
    contract_id: str
    name: str
    signature: str
    selector: str | None = None
    visibility: Visibility = Visibility.PUBLIC
    mutability: Mutability = Mutability.NONPAYABLE
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    modifiers: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    calls_external: bool = False
    access: AccessAssessment = Field(default_factory=AccessAssessment)
    source: str | None = None
    provenance: SourceKind = SourceKind.COMPILED_SOURCE
    # Set when the function is inherited: the contract that declares it.
    declared_in: str | None = None
    # State variables the function writes, directly or through internal calls.
    writes: list[str] = Field(default_factory=list)

    @property
    def is_entry_point(self) -> bool:
        return self.is_constructor or self.visibility in (Visibility.PUBLIC, Visibility.EXTERNAL)


class RoleModel(Base):
    id: str
    name: str
    kind: Literal["ownable", "access_control", "custom", "governance", "timelock"] = "custom"
    contract_id: str | None = None
    description: str = ""
    evidence: list[Evidence] = Field(default_factory=list)


class ProxyInfo(Base):
    kind: ProxyKind = ProxyKind.UNKNOWN
    implementation: str | None = None
    admin: str | None = None
    beacon: str | None = None
    facets: dict[str, str] = Field(default_factory=dict)
    resolution: Resolution = Resolution.UNRESOLVED
    evidence: list[Evidence] = Field(default_factory=list)


class ContractModel(Base):
    id: str
    name: str
    kind: ContractKind = ContractKind.UNKNOWN
    address: str | None = None
    chain_id: int | None = None
    code_hash: str | None = None
    source_kind: SourceKind = SourceKind.COMPILED_SOURCE
    compiler_version: str | None = None
    verified: bool = False
    abi_available: bool = False
    is_proxy: bool = False
    proxy: ProxyInfo | None = None
    base_contracts: list[str] = Field(default_factory=list)
    interfaces: list[str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    state_variables: list[StateVariable] = Field(default_factory=list)
    storage_layout: list[StorageEntry] = Field(default_factory=list)
    events: list[EventItem] = Field(default_factory=list)
    errors: list[ErrorItem] = Field(default_factory=list)
    unresolved: bool = False
    notes: list[str] = Field(default_factory=list)

    @field_validator("address")
    @classmethod
    def _lower_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not (value.startswith("0x") and len(value) == 42):
            raise ValueError(f"not a 20-byte hex address: {value!r}")
        if any(c not in "0123456789abcdefABCDEF" for c in value[2:]):
            raise ValueError(f"not a hex address: {value!r}")
        return value.lower()


class Node(Base):
    id: str
    kind: NodeKind
    label: str
    contract_id: str | None = None
    address: str | None = None
    detail: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class Edge(Base):
    id: str
    kind: EdgeKind
    source: str
    target: str
    label: str | None = None
    resolution: Resolution = Resolution.CONFIRMED
    confidence: float = 1.0
    evidence: list[Evidence] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def _bound(cls, value: float) -> float:
        return min(1.0, max(0.0, value))


class Observation(Base):
    id: str
    category: str
    subject: str
    title: str
    explanation: str
    evidence: list[Evidence] = Field(default_factory=list)
    resolution: Resolution = Resolution.CONFIRMED
    confidence: float = 1.0
    review_area: str | None = None


class WarningItem(Base):
    code: str
    message: str
    subject: str | None = None
    fatal: bool = False


class Metadata(Base):
    generated_at: str
    tool_version: str
    schema_version: str = SCHEMA_VERSION
    duration_ms: int | None = None
    analysis_complete: bool = True
    compiler: str | None = None
    build_system: str | None = None
    source_provenance: list[str] = Field(default_factory=list)
    limits: dict[str, Any] = Field(default_factory=dict)
    digest: str | None = None


class AnalysisResult(Base):
    schema_version: str = SCHEMA_VERSION
    tool: Literal["contractmap"] = "contractmap"
    target: TargetInfo
    chain: ChainInfo = Field(default_factory=ChainInfo)
    metadata: Metadata
    contracts: list[ContractModel] = Field(default_factory=list)
    functions: list[FunctionModel] = Field(default_factory=list)
    roles: list[RoleModel] = Field(default_factory=list)
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    warnings: list[WarningItem] = Field(default_factory=list)

    def sorted_copy(self) -> AnalysisResult:
        """Deterministically ordered copy, so identical analyses serialise identically."""

        clone = self.model_copy(deep=True)
        clone.contracts = sorted(self.contracts, key=lambda c: c.id)
        clone.functions = sorted(self.functions, key=lambda f: f.id)
        clone.roles = sorted(self.roles, key=lambda r: r.id)
        clone.nodes = sorted(self.nodes, key=lambda n: n.id)
        clone.edges = sorted(self.edges, key=lambda e: e.id)
        clone.observations = sorted(self.observations, key=lambda o: o.id)
        clone.warnings = sorted(self.warnings, key=lambda w: (w.code, w.subject or "", w.message))
        for contract in clone.contracts:
            contract.state_variables = sorted(contract.state_variables, key=lambda v: v.id)
            contract.events = sorted(contract.events, key=lambda e: e.signature)
            contract.errors = sorted(contract.errors, key=lambda e: e.signature)
            contract.base_contracts = sorted(set(contract.base_contracts))
            contract.interfaces = sorted(set(contract.interfaces))
            contract.libraries = sorted(set(contract.libraries))
            if contract.proxy is not None:
                contract.proxy.facets = dict(sorted(contract.proxy.facets.items()))
        return clone

    def canonical_json(self) -> str:
        """Semantic form used for digests and comparison: no run-specific metadata."""

        payload = json.loads(self.sorted_copy().model_dump_json())
        payload.pop("metadata", None)
        payload["target"].pop("resolved_paths", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_json().encode()).hexdigest()

    def contract_by_id(self, contract_id: str) -> ContractModel | None:
        return next((c for c in self.contracts if c.id == contract_id), None)

    def entry_points(self) -> list[FunctionModel]:
        return [f for f in self.functions if f.is_entry_point]

    def observations_by_priority(self) -> list[Observation]:
        """Findings that are most likely to matter first; ties keep a stable order."""

        rank = {category: i for i, category in enumerate(OBSERVATION_PRIORITY)}
        return sorted(self.observations, key=lambda o: (rank.get(o.category, len(rank)), o.id))

    def deployable_entry_points(self) -> list[FunctionModel]:
        """Entry points of contracts that can be deployed.

        Abstract bases and interfaces are reached through the contracts that inherit
        them, which list those functions with ``declared_in`` set. They are kept only
        when nothing deployable was scanned.
        """

        bases = {
            c.id
            for c in self.contracts
            if c.kind in (ContractKind.ABSTRACT, ContractKind.INTERFACE)
        }
        if len(bases) == len(self.contracts):
            return self.entry_points()
        return [f for f in self.entry_points() if f.contract_id not in bases]
