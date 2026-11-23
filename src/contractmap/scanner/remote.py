"""Deployed contract scanning over read-only JSON-RPC.

Every read is pinned to a single block: the block is resolved first, then all
subsequent calls use that number, and the chain id is checked before any contract
data is trusted. When a provider cannot honour the pinned block the scan reports a
warning rather than mixing state from different heights.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from contractmap import __version__
from contractmap.analysis.functions import (
    dangerous_operation_observations,
    privileged_write_observations,
    selector_observations,
)
from contractmap.analysis.observations import build_observations
from contractmap.config import Settings
from contractmap.errors import ContractMapError, InputError, OperationalError
from contractmap.evm import abi
from contractmap.evm.bytecode import code_hash, extract_selectors, is_contract_code
from contractmap.evm.hashing import is_address, selector
from contractmap.graph.assemble import add_access, add_contract, add_functions
from contractmap.graph.builder import GraphBuilder
from contractmap.graph.identity import contract_id, function_id
from contractmap.models import (
    AccessAssessment,
    AccessRestriction,
    AnalysisResult,
    ChainInfo,
    ContractModel,
    Evidence,
    FunctionModel,
    Metadata,
    Mutability,
    Node,
    NodeKind,
    Observation,
    ProxyInfo,
    ProxyKind,
    SourceKind,
    TargetInfo,
    Visibility,
)
from contractmap.proxies.detect import detect_proxy
from contractmap.rpc import RpcClient, RpcError, UnsupportedMethod
from contractmap.scanner.local import (
    apply_inherited_guards,
    call_site_roles,
    dangerous_operations,
    resolve_surface,
)
from contractmap.sources.analyze import analyze
from contractmap.sources.compiler import CompiledContract, compile_sources, iter_compiled
from contractmap.sources.facts import ContractFacts, FunctionFact
from contractmap.sources.solc import find_solc
from contractmap.sources.verified import VerifiedSource, fetch_verified

# Standard getters probed for privileged accounts. A getter is only reported when
# the call succeeds and returns a plausible address, so no name guessing is used.
ACCOUNT_PROBES: tuple[tuple[str, str], ...] = (
    ("0x8da5cb5b", "owner"),
    ("0xf851a440", "admin"),
    ("0xe30c3978", "pending owner"),
)


@dataclass(slots=True)
class Entity:
    address: str
    depth: int
    via: str = "root"
    code: str = ""
    proxy: ProxyInfo | None = None
    verified: VerifiedSource | None = None
    contract: ContractModel | None = None
    accounts: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class ScanContext:
    client: RpcClient
    settings: Settings
    builder: GraphBuilder
    chain_id: int
    block: int
    block_hash: str | None = None
    sources: dict[str, list[FunctionFact]] = field(default_factory=dict)

    def warn(
        self, code: str, message: str, subject: str | None = None, *, partial: bool = False
    ) -> None:
        self.builder.warn(code, message, subject, partial=partial)

    def pinned(self) -> int:
        return self.settings.block if self.settings.block is not None else self.block


async def _read_entity(ctx: ScanContext, address: str, depth: int, via: str) -> Entity:
    entity = Entity(address=address, depth=depth, via=via)
    try:
        entity.code = await ctx.client.get_code(address, ctx.pinned())
    except (RpcError, ValueError) as exc:
        ctx.warn("code_unavailable", f"eth_getCode failed for {address}: {exc}", subject=address)
        return entity
    if not is_contract_code(entity.code):
        ctx.warn(
            "no_code",
            f"{address} has no runtime code at block {ctx.block}: an EOA, an empty account, "
            "or not deployed on this chain",
            subject=address,
        )
        return entity
    entity.proxy = await detect_proxy(ctx.client, address, entity.code)
    return entity


async def _traverse(ctx: ScanContext, root: str) -> list[Entity]:
    """Breadth-first discovery bounded by depth, node budget and cycle detection."""

    level: list[tuple[str, str]] = [(root, "root")]
    seen: set[str] = {root}
    ordered: list[Entity] = []
    depth = 0
    while level:
        # One level at a time, read concurrently; the client's semaphore bounds load.
        entities = await asyncio.gather(
            *(_read_entity(ctx, address, depth, via) for address, via in level)
        )
        ordered.extend(entity for entity in entities if entity.code)
        if depth >= ctx.settings.limits.depth:
            break
        level = []
        for entity in entities:
            for child, relation in _children(entity):
                if child not in seen and len(seen) < ctx.settings.limits.max_nodes:
                    seen.add(child)
                    level.append((child, relation))
        depth += 1
    if len(seen) >= ctx.settings.limits.max_nodes:
        ctx.warn(
            "node_budget",
            f"stopped after {len(seen)} addresses; raise --max-nodes to follow more",
            partial=True,
        )
    return ordered


def _children(entity: Entity) -> list[tuple[str, str]]:
    if entity.proxy is None:
        return []
    pairs: list[tuple[str, str]] = []
    if entity.proxy.implementation:
        pairs.append((entity.proxy.implementation, "implementation"))
    if entity.proxy.beacon:
        pairs.append((entity.proxy.beacon, "beacon"))
    for facet in sorted(set(entity.proxy.facets.values())):
        pairs.append((facet, "facet"))
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for address, relation in pairs:
        if address in seen:
            continue
        seen.add(address)
        unique.append((address, relation))
    return unique


async def _resolve_verified(ctx: ScanContext, entity: Entity) -> None:
    if not (ctx.settings.sources.sourcify or ctx.settings.sources.etherscan):
        return
    try:
        source, messages = await fetch_verified(
            entity.address, ctx.chain_id, ctx.settings.sources, ctx.settings.limits.timeout
        )
    except ValueError:
        return
    for message in messages:
        ctx.warn("source_lookup", message, subject=entity.address)
    entity.verified = source


async def _probe_accounts(ctx: ScanContext, address: str) -> list[tuple[str, str]]:
    """Standard privileged-account getters. An absent getter is not reported."""

    found: list[tuple[str, str]] = []
    for sel, label in ACCOUNT_PROBES:
        try:
            raw = await ctx.client.eth_call(address, sel, ctx.pinned())
        except (RpcError, UnsupportedMethod, ValueError):
            continue
        candidate = abi.decode_address(raw)
        if candidate and candidate not in {address.lower()}:
            found.append((label, candidate))
    return found


def _abi_functions(entries: list[object]) -> list[FunctionFact]:
    facts: list[FunctionFact] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type")
        if entry_type == "function":
            facts.append(
                FunctionFact(
                    name=str(entry.get("name") or ""),
                    signature=abi.canonical_signature(entry),
                    visibility="external",
                    mutability=str(entry.get("stateMutability") or "nonpayable"),
                    inputs=[abi.canonical_type(p) for p in entry.get("inputs") or []],
                    outputs=[abi.canonical_type(p) for p in entry.get("outputs") or []],
                    access_kind="unresolved",
                    access_detail=(
                        "verified ABI only: modifiers and inline guards need source analysis"
                    ),
                )
            )
        elif entry_type == "constructor":
            facts.append(
                FunctionFact(
                    name="constructor",
                    signature="constructor(...)",
                    visibility="public",
                    mutability=str(entry.get("stateMutability") or "nonpayable"),
                    is_constructor=True,
                    access_kind="unresolved",
                )
            )
        elif entry_type == "fallback":
            facts.append(
                FunctionFact(
                    name="fallback",
                    signature="fallback()",
                    visibility="external",
                    mutability=str(entry.get("stateMutability") or "nonpayable"),
                    is_fallback=True,
                    access_kind="unresolved",
                )
            )
        elif entry_type == "receive":
            facts.append(
                FunctionFact(
                    name="receive",
                    signature="receive()",
                    visibility="external",
                    mutability="payable",
                    is_receive=True,
                    access_kind="none_identified",
                )
            )
    return facts


def _dispatch_only(facts: list[FunctionFact], selectors: dict[str, int]) -> list[FunctionFact]:
    """Dispatcher entries that no verified ABI explains, kept selector-only."""

    known = {selector(fact.signature) for fact in facts if not fact.is_constructor}
    extra: list[FunctionFact] = []
    for sel in selectors:
        if sel in known:
            continue
        extra.append(
            FunctionFact(
                name=f"entry_{sel[2:]}",
                signature=f"unknown_{sel[2:]}()",
                visibility="external",
                mutability="nonpayable",
                access_kind="unresolved",
                access_detail=(
                    "dispatcher entry without verified ABI: a four-byte selector does not "
                    "determine a signature"
                ),
            )
        )
    return extra


def _display_name(entity: Entity) -> str:
    if entity.verified and entity.verified.contract_name:
        return entity.verified.contract_name
    kind = entity.proxy.kind.value if entity.proxy else "contract"
    return f"{kind}@{(entity.address or '')[:10]}"


def _contract_from_entity(ctx: ScanContext, entity: Entity) -> ContractModel:
    verified = entity.verified
    return ContractModel(
        id=contract_id(entity.address, ctx.chain_id, None, entity.address),
        name=_display_name(entity),
        address=entity.address,
        chain_id=ctx.chain_id,
        code_hash=code_hash(entity.code),
        source_kind=SourceKind.VERIFIED_SOURCE if verified else SourceKind.DEPLOYED_BYTECODE,
        compiler_version=verified.compiler_version if verified else None,
        verified=verified is not None,
        abi_available=bool(verified and verified.abi),
        is_proxy=entity.proxy is not None and entity.proxy.kind != ProxyKind.UNKNOWN,
        proxy=entity.proxy,
        unresolved=verified is None,
        notes=(
            []
            if verified
            else [
                "no verified source was retrieved: entry points come from the dispatcher and "
                "authorization stays unresolved"
            ]
        ),
    )


def _functions_from_facts(
    contract: ContractModel, facts: list[FunctionFact]
) -> list[FunctionModel]:
    models: list[FunctionModel] = []
    for fact in facts:
        restriction = (
            AccessRestriction(fact.access_kind)
            if fact.access_kind in AccessRestriction._value2member_map_
            else AccessRestriction.UNRESOLVED
        )
        if fact.is_constructor or fact.is_fallback or fact.is_receive:
            function_selector: str | None = None
        elif fact.signature.startswith("unknown_"):
            function_selector = "0x" + fact.signature.removeprefix("unknown_")[:8]
        else:
            function_selector = selector(fact.signature)
        models.append(
            FunctionModel(
                id=function_id(contract.id, fact.signature),
                contract_id=contract.id,
                name=fact.name,
                signature=fact.signature,
                selector=function_selector,
                visibility=(
                    Visibility(fact.visibility)
                    if fact.visibility in Visibility._value2member_map_
                    else Visibility.EXTERNAL
                ),
                mutability=(
                    Mutability(fact.mutability)
                    if fact.mutability in Mutability._value2member_map_
                    else Mutability.NONPAYABLE
                ),
                is_constructor=fact.is_constructor,
                is_fallback=fact.is_fallback,
                is_receive=fact.is_receive,
                inputs=fact.inputs,
                outputs=fact.outputs,
                access=AccessAssessment(
                    restriction=restriction,
                    roles=call_site_roles(fact),
                    modifiers=fact.modifiers,
                    evidence=(
                        [Evidence(kind="abi", detail=fact.access_detail)]
                        if fact.access_detail
                        else []
                    ),
                ),
                provenance=contract.source_kind,
                declared_in=fact.declared_in,
                writes=fact.writes,
            )
        )
    return models


def _facts_for(ctx: ScanContext, entity: Entity) -> list[FunctionFact]:
    facts = _source_facts(ctx, entity)
    if facts:
        return facts
    if entity.verified and entity.verified.abi:
        abi_facts = _abi_functions(list(entity.verified.abi))
        return [*abi_facts, *_dispatch_only(abi_facts, extract_selectors(entity.code))]
    return _dispatch_only([], extract_selectors(entity.code))


def _source_facts(ctx: ScanContext, entity: Entity) -> list[FunctionFact]:
    """Function facts from verified source, where modifier guards become resolvable.

    The ABI alone cannot say how a function is protected, so a verified contract is
    reported as unresolved without this. Compiling is opt-in, and every failure path
    degrades to the ABI instead of failing the scan.
    """

    verified = entity.verified
    if verified is None or not verified.source_files:
        return []
    cached = ctx.sources.get(entity.address)
    if cached is not None:
        return cached

    facts: list[FunctionFact] = []
    if not ctx.settings.allow_build:
        ctx.warn(
            "source_analysis_skipped",
            "verified source was not compiled, so modifiers and inline guards stay "
            "unresolved; pass --allow-build to analyse it",
            subject=entity.address,
        )
    else:
        facts = _compile_verified_facts(ctx, entity, verified)
    ctx.sources[entity.address] = facts
    return facts


def _compile_verified_facts(
    ctx: ScanContext, entity: Entity, verified: VerifiedSource
) -> list[FunctionFact]:
    pinned = (verified.compiler_version or "").split("+")[0].strip()
    solc = find_solc(ctx.settings.solc_path, prefer_version=pinned or None)
    if solc is None:
        ctx.warn(
            "source_analysis_skipped",
            "verified source found but no solc binary is available, so guards stay unresolved",
            subject=entity.address,
        )
        return []
    try:
        output = compile_sources(verified.source_files, solc=solc, allow_build=True)
    except ContractMapError as exc:
        ctx.warn(
            "source_analysis_failed",
            f"verified source did not compile, so guards stay unresolved: {exc}",
            subject=entity.address,
        )
        return []

    units = iter_compiled(output)
    target = _select_unit(units, verified)
    if target is None:
        ctx.warn(
            "source_analysis_failed",
            "verified source compiled to no contracts",
            subject=entity.address,
        )
        return []
    # Every contract in the verified sources, so inherited functions and guards
    # behind internal calls resolve the same way as in a local scan.
    everything: list[ContractFacts] = []
    analyzed: set[str] = set()
    for unit in units:
        if unit.ast and unit.source_name not in analyzed:
            analyzed.add(unit.source_name)
            everything.extend(analyze(unit.ast, unit.source_name))
    apply_inherited_guards(everything)
    resolve_surface(everything)
    facts = next(
        (
            f
            for f in everything
            if f.name == target.contract_name and f.source_name == target.source_name
        ),
        None,
    )
    if facts is None:
        ctx.warn(
            "source_analysis_failed",
            f"compiled source has no contract named {target.contract_name!r}",
            subject=entity.address,
        )
        return []
    if target.compiler_version and not verified.compiler_version:
        verified.compiler_version = target.compiler_version
    return facts.functions


def _select_unit(
    units: Sequence[CompiledContract], verified: VerifiedSource
) -> CompiledContract | None:
    """Pick the compiled contract the verified metadata names."""

    named = verified.contract_name
    for unit in units:
        if named is None or unit.contract_name == named:
            return unit
    return units[0] if units else None


def _assemble(
    ctx: ScanContext,
    entities: list[Entity],
    root: str,
    started: float,
) -> AnalysisResult:
    contracts: list[ContractModel] = []
    functions: list[FunctionModel] = []
    observations: list[Observation] = []
    node_of: dict[str, str] = {}
    by_address: dict[str, ContractModel] = {}

    for entity in entities:
        contract = _contract_from_entity(ctx, entity)
        entity.contract = contract
        contracts.append(contract)
        by_address[entity.address] = contract

    # Contract nodes first, so a proxy's edge reaches the scanned implementation,
    # beacon or facet instead of an empty stub for the same address.
    for contract in contracts:
        node_of[contract.id] = ctx.builder.contract_node(contract)
    scanned = {contract.address: node_of[contract.id] for contract in contracts if contract.address}

    for entity in entities:
        owner = entity.contract
        if owner is None:
            continue
        node_of[owner.id] = add_contract(ctx.builder, owner, scanned)
        facts = _facts_for(ctx, entity)
        models = _functions_from_facts(owner, facts)
        functions.extend(models)
        add_functions(ctx.builder, owner, models, node_of[owner.id])
        add_access(ctx.builder, owner, models, [], node_of[owner.id])
        add_accounts(ctx, entity, owner, node_of[owner.id])
        known = {model.selector for model in models if model.selector}
        observations.extend(selector_observations(owner, extract_selectors(entity.code), known))
        observations.extend(
            dangerous_operation_observations(owner, models, dangerous_operations(facts))
        )
        observations.extend(privileged_write_observations(owner, models))

    observations.extend(
        build_observations(
            AnalysisResult(
                target=TargetInfo(kind="address", identifier=root),
                metadata=Metadata(generated_at="", tool_version=__version__),
                contracts=contracts,
                functions=functions,
            )
        )
    )

    metadata = Metadata(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=__version__,
        duration_ms=int((time.perf_counter() - started) * 1000),
        source_provenance=sorted(
            {str(entity.verified.provider) for entity in entities if entity.verified is not None}
        ),
        limits={
            "depth": ctx.settings.limits.depth,
            "max_nodes": ctx.settings.limits.max_nodes,
            "max_requests": ctx.settings.limits.max_requests,
        },
    )

    result = ctx.builder.result(
        target=TargetInfo(
            kind="address",
            identifier=root,
            chain_id=ctx.chain_id,
            block_number=ctx.block,
            code_hash=by_address[root].code_hash if root in by_address else None,
        ),
        chain=ChainInfo(
            chain_id=ctx.chain_id,
            block_number=ctx.block,
            block_hash=ctx.block_hash,
        ),
        metadata=metadata,
        contracts=contracts,
        functions=functions,
        roles=[],
        observations=observations,
    )
    return result.sorted_copy()


def add_accounts(
    ctx: ScanContext, entity: Entity, contract: ContractModel, owner_node: str
) -> None:
    from contractmap.models import EdgeKind

    for label, address in entity.accounts:
        node_id = f"node:account:{ctx.chain_id}:{address}"
        node = Node(
            id=node_id,
            kind=NodeKind.PRIVILEGED_ACCOUNT,
            label=f"{label}",
            contract_id=contract.id,
            address=address,
            detail=f"{label} of {contract.name}",
            attributes={"chain_id": str(ctx.chain_id), "source": "eth_call getter"},
        )
        if not ctx.builder.add_node(node):
            continue
        ctx.builder.add_edge(
            EdgeKind.CONTROLLED_BY,
            owner_node,
            node_id,
            label=label,
            evidence=[
                Evidence(
                    kind="call",
                    detail=f"{label}() returned this address on chain {ctx.chain_id}",
                    source=entity.address,
                    value=address,
                )
            ],
        )


async def _block_hash(client: RpcClient, number: int) -> str | None:
    try:
        block = await client.get_block(number)
    except (RpcError, UnsupportedMethod):
        return None
    value = block.get("hash")
    return str(value).lower() if isinstance(value, str) else None


async def scan_address(
    address: str,
    settings: Settings | None = None,
    *,
    chain_id: int | None = None,
) -> AnalysisResult:
    """Read-only architecture scan of one deployed address and its dependencies."""

    settings = settings or Settings.from_env()
    if not is_address(address):
        raise InputError(f"not a 20-byte hex address: {address!r}")
    if not settings.rpc_url:
        raise InputError("an RPC endpoint is required; pass --rpc or set CONTRACTMAP_RPC_URL")
    expected_chain = chain_id if chain_id is not None else settings.chain_id

    started = time.perf_counter()
    root = address.lower()
    builder = GraphBuilder(max_nodes=settings.limits.max_nodes)

    async with RpcClient(url=settings.rpc_url, limits=settings.limits) as client:
        try:
            actual_chain = await client.get_chain_id()
        except RpcError as exc:
            raise OperationalError(f"could not read eth_chainId: {exc}") from exc
        if expected_chain is not None and actual_chain != expected_chain:
            raise InputError(
                f"RPC serves chain {actual_chain} but chain {expected_chain} was requested"
            )

        if settings.block is not None:
            pinned = settings.block
            block_hash = await _block_hash(client, pinned)
            if block_hash is None:
                builder.warn(
                    "block_unavailable",
                    f"block {pinned} was not returned by the provider; state is read at that "
                    "height but cannot be cross-checked",
                )
        else:
            try:
                pinned = await client.block_number()
            except RpcError as exc:
                raise OperationalError(f"could not read the head block: {exc}") from exc
            block_hash = await _block_hash(client, pinned)
            if block_hash is None:
                builder.warn(
                    "block_hash_unavailable",
                    "the provider did not return block data for the analysed height",
                )

        client.pin_block(pinned)
        ctx = ScanContext(
            client=client,
            settings=settings,
            builder=builder,
            chain_id=actual_chain,
            block=pinned,
            block_hash=block_hash,
        )

        entities = await _traverse(ctx, root)
        if not entities:
            raise OperationalError(
                f"{root} has no runtime code on chain {actual_chain} at block {pinned}"
            )
        await asyncio.gather(*(_enrich(ctx, entity) for entity in entities))
        if client.stats.budget_hits:
            ctx.warn(
                "request_budget",
                f"the request budget of {settings.limits.max_requests} ran out, so some "
                "reads were skipped; raise --max-requests",
                partial=True,
            )

    return _assemble(ctx, entities, root, started)


async def _enrich(ctx: ScanContext, entity: Entity) -> None:
    await _resolve_verified(ctx, entity)
    entity.accounts = await _probe_accounts(ctx, entity.address)
