"""Local project scanning: file, directory, Foundry, Hardhat and raw artifacts."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

from contractmap import __version__
from contractmap.analysis.functions import (
    dangerous_operation_observations,
    dependency_observations,
    function_observations,
    inheritance_observations,
    privileged_write_observations,
)
from contractmap.analysis.observations import build_observations
from contractmap.config import Settings
from contractmap.errors import InputError
from contractmap.evm import abi
from contractmap.evm.hashing import selector, topic
from contractmap.graph import identity
from contractmap.graph.assemble import (
    add_access,
    add_call_edges,
    add_contract,
    add_functions,
    add_inheritance,
)
from contractmap.graph.builder import GraphBuilder
from contractmap.models import (
    AccessAssessment,
    AccessRestriction,
    AnalysisResult,
    ChainInfo,
    ContractKind,
    ContractModel,
    ErrorItem,
    EventItem,
    Evidence,
    FunctionModel,
    Metadata,
    Mutability,
    Observation,
    RoleModel,
    SourceKind,
    StateVariable,
    TargetInfo,
    Visibility,
    WarningItem,
)
from contractmap.sources.analyze import analyze, analyze_one
from contractmap.sources.artifacts import (
    Artifact,
    detect_build_system,
    load_artifact_file,
    load_artifacts,
)
from contractmap.sources.compiler import (
    compile_sources,
    find_solc,
    forge_build,
    iter_compiled,
    solc_version,
)
from contractmap.sources.facts import ContractFacts, FunctionFact
from contractmap.sources.solc import installed_versions

MAX_SOLIDITY_FILES = 500
SKIP_DIRS = {
    ".git",
    "node_modules",
    "lib",
    ".venv",
    "venv",
    "__pycache__",
    "out",
    "artifacts",
    "cache",
    "build-info",
}
# shortcut: path conventions, not import resolution, decide what is "not your code".
# Foundry libs, npm packages, tests and scripts; `--all` brings them back.
DEPENDENCY_PREFIXES = ("lib/", "node_modules/", "test/", "tests/", "script/", "@", "hardhat/")
DEPENDENCY_SUFFIXES = (".t.sol", ".s.sol")


def is_dependency(source_name: str) -> bool:
    name = source_name.replace("\\", "/").removeprefix("./")
    return name.startswith(DEPENDENCY_PREFIXES) or name.endswith(DEPENDENCY_SUFFIXES)


@dataclass(slots=True)
class ScanState:
    builder: GraphBuilder
    contracts: list[ContractModel] = field(default_factory=list)
    functions: list[FunctionModel] = field(default_factory=list)
    roles: list[RoleModel] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    warnings: list[WarningItem] = field(default_factory=list)
    node_of: dict[str, str] = field(default_factory=dict)


def scan_local(target: str | Path, settings: Settings | None = None) -> AnalysisResult:
    """Analyse a Solidity file, project directory or build artifact directory."""

    settings = settings or Settings.from_env()
    started = time.perf_counter()
    path = Path(target).expanduser()
    if not path.exists():
        raise InputError(f"target does not exist: {path}")

    state = ScanState(builder=GraphBuilder(max_nodes=settings.limits.max_nodes))
    build_system: str | None = None
    sources: dict[str, str] = {}
    artifacts: list[Artifact] = []

    if path.is_file():
        if path.suffix == ".sol":
            # A lone file usually imports its neighbours, and solc resolves imports
            # against the source units it is given. Compiling the file's directory
            # tree keeps those imports resolvable; point at a directory to widen it.
            sources = load_solidity_files(discover_solidity(path.parent))
            sources.setdefault(path.name, path.read_text(encoding="utf-8"))
        elif path.suffix == ".json":
            build_system = "solc"
            artifacts = load_artifact_file(path)
        else:
            raise InputError(f"unsupported file type: {path.suffix or path.name}")
    else:
        build_system = detect_build_system(path)
        artifacts, detected = load_artifacts(path)
        build_system = build_system or detected
        if (
            build_system == "foundry"
            and settings.allow_build
            and shutil.which("forge")
            and not any(artifact.ast for artifact in artifacts)
        ):
            with tempfile.TemporaryDirectory(prefix="contractmap-") as scratch:
                forge_build(path, Path(scratch))
                artifacts, _ = load_artifacts(Path(scratch))
        if not artifacts:
            sources = load_solidity_files(discover_solidity(path))

    facts: list[ContractFacts] = []
    compiler: str | None = None

    if artifacts:
        for artifact in artifacts:
            facts.extend(facts_from_artifact(artifact))
            if artifact.compiler_version and not compiler:
                compiler = artifact.compiler_version
        no_ast = [
            a.contract_name
            for a in artifacts
            if not a.ast
            and (settings.include_dependencies or not is_dependency(a.source_name or ""))
        ]
        if no_ast:
            state.builder.warn(
                "abi_only_artifact",
                f"{len(no_ast)} artifact(s) have no AST, so access control is unresolved "
                f"({', '.join(sorted(no_ast)[:5])}{', ...' if len(no_ast) > 5 else ''}). "
                "Re-run with --allow-build to rebuild with `forge build --ast`.",
            )
    else:
        if not sources:
            raise InputError(f"no Solidity sources or build artifacts found under {path}")
        if not settings.allow_build:
            raise InputError(
                f"{len(sources)} Solidity source(s) need compiling, which runs an external "
                "binary. Re-run with --allow-build, or scan a directory that already "
                "contains Foundry/Hardhat artifacts."
            )
        solc = find_solc(settings.solc_path, prefer_version=declared_solc_version(path, sources))
        if solc is None:
            available = installed_versions()
            hint = (
                f" Foundry has {', '.join(available)} installed but none is on PATH."
                if available
                else ""
            )
            raise InputError(
                "no Solidity compiler found. Install solc (or run `foundryup`), put it on "
                f"PATH, or point --solc at the binary.{hint}"
            )
        compiler = solc_version(solc)
        compiled = compile_sources(sources, solc=solc, allow_build=True)
        analyzed: set[str] = set()
        for unit in iter_compiled(compiled):
            # Every contract in a file carries that file's AST, so analysing per
            # compilation unit would report each contract once per sibling.
            if unit.ast and unit.source_name not in analyzed:
                analyzed.add(unit.source_name)
                facts.extend(analyze(unit.ast, unit.source_name))
            if unit.compiler_version and not compiler:
                compiler = unit.compiler_version

    if not facts:
        raise InputError("no analyzable contracts were found in the target")

    # Guards are resolved before dependencies are hidden: `onlyOwner` usually lives
    # in a library contract the user never wants listed.
    apply_inherited_guards(facts)
    resolve_surface(facts)
    if not settings.include_dependencies:
        own = [f for f in facts if not is_dependency(f.source_name)]
        if own and len(own) < len(facts):
            state.builder.warn(
                "dependencies_hidden",
                f"{len(facts) - len(own)} contract(s) from libraries, tests and scripts "
                "are hidden; pass --all to include them",
            )
            facts = own
    contracts, functions, roles, calls, observations = models_from_facts(facts, compiler)
    assemble_contracts(state, contracts, functions, roles, calls)
    observations.extend(
        build_observations(_partial_result(state, contracts, functions, roles, observations))
    )
    state.observations.extend(observations)

    metadata = Metadata(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=__version__,
        duration_ms=int((time.perf_counter() - started) * 1000),
        compiler=compiler,
        build_system=build_system,
        limits={
            "depth": settings.limits.depth,
            "max_nodes": settings.limits.max_nodes,
            "max_requests": settings.limits.max_requests,
        },
    )
    result = state.builder.result(
        target=TargetInfo(
            kind="local",
            identifier=str(path),
            build_system=build_system,
            resolved_paths=sorted(sources)[:50],
        ),
        chain=ChainInfo(),
        metadata=metadata,
        contracts=contracts,
        functions=state.functions,
        roles=roles,
        observations=state.observations,
    )
    result.warnings.extend(state.warnings)
    return result.sorted_copy()


def _partial_result(
    state: ScanState,
    contracts: list[ContractModel],
    functions: list[FunctionModel],
    roles: list[RoleModel],
    observations: list[Observation],
) -> AnalysisResult:
    """Build a throwaway result so contract-level observations can be generated."""

    return AnalysisResult(
        target=TargetInfo(kind="local", identifier=""),
        metadata=Metadata(generated_at="", tool_version=__version__),
        contracts=contracts,
        functions=functions,
        roles=roles,
        observations=observations,
    )


PRAGMA_PATTERN = re.compile(r"pragma\s+solidity\s+([^;]+);")
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+")
# `=0.8.20` pins one version; `^0.8.20` and `>=0.8.0` are ranges and say nothing
# about which installed compiler to prefer.
EXACT_PIN = re.compile(r"=\s*\d+\.\d+\.\d+")


def declared_solc_version(root: Path, sources: dict[str, str]) -> str | None:
    """The exact version the target pins, if it pins one.

    ``foundry.toml`` wins, since it configures the build. Otherwise a source whose
    ``pragma`` names a single exact version is honoured. Ranges such as ``>=0.8.0``
    say nothing about which installed compiler to prefer, so they return ``None``
    and let :func:`find_solc` fall back to the newest build on the machine.
    """

    config = root / "foundry.toml" if root.is_dir() else None
    if config is None and root.is_file() and root.name == "foundry.toml":
        config = root
    if config is not None and config.is_file():
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            pinned = re.match(r"\s*solc_version\s*=\s*[\"']([^\"']+)[\"']", line)
            if pinned and EXACT_VERSION.fullmatch(pinned.group(1).split("+")[0].strip()):
                return pinned.group(1).split("+")[0].strip()

    for content in sources.values():
        for pragma in PRAGMA_PATTERN.findall(content):
            candidate = pragma.strip()
            exact = EXACT_VERSION.fullmatch(candidate) or EXACT_PIN.fullmatch(candidate)
            if exact:
                return candidate.lstrip("=").strip()
    return None


def discover_solidity(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*.sol")):
        # Only parts below the root: a project that lives under `~/lib/` or `/build/`
        # must not have every file skipped.
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        files.append(path)
        if len(files) > MAX_SOLIDITY_FILES:
            raise InputError(
                f"more than {MAX_SOLIDITY_FILES} Solidity files found; scan a narrower "
                "directory or provide build artifacts"
            )
    return files


def load_solidity_files(paths: list[Path]) -> dict[str, str]:
    """Map each file to a source-unit name relative to the common root."""

    if not paths:
        return {}
    parents = sorted({str(p.parent.resolve()) for p in paths})
    root = Path(os.path.commonpath(parents))
    units: dict[str, str] = {}
    for path in paths:
        try:
            units[path.resolve().relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise InputError(f"cannot read {path}: {exc}") from exc
        except ValueError:
            units[path.name] = path.read_text(encoding="utf-8")
    return units


def contract_from_facts(
    facts: ContractFacts,
    *,
    chain_id: int | None = None,
    address: str | None = None,
    source_kind: SourceKind = SourceKind.COMPILED_SOURCE,
    compiler: str | None = None,
) -> ContractModel:
    contract_id = identity.contract_id(address, chain_id, facts.source_name, facts.name)
    kind = (
        ContractKind(facts.kind)
        if facts.kind in ContractKind._value2member_map_
        else ContractKind.UNKNOWN
    )
    state_vars = [
        StateVariable(
            id=f"{contract_id}:var:{variable.name}",
            name=variable.name,
            type=variable.type,
            visibility=(
                Visibility(variable.visibility)
                if variable.visibility and variable.visibility in Visibility._value2member_map_
                else None
            ),
            constant=variable.constant,
            immutable=variable.immutable,
            source=variable.source,
        )
        for variable in facts.state_vars
    ]
    events = []
    for signature in sorted(set(facts.events)):
        events.append(
            EventItem(name=signature.split("(")[0], signature=signature, topic0=topic(signature))
        )
    errors = [
        ErrorItem(
            name=signature.split("(")[0],
            signature=signature,
            selector=selector(signature),
        )
        for signature in sorted(set(facts.errors))
    ]
    return ContractModel(
        id=contract_id,
        name=facts.name,
        kind=kind,
        address=address,
        chain_id=chain_id,
        source_kind=source_kind,
        compiler_version=compiler,
        base_contracts=list(dict.fromkeys(facts.bases)),
        libraries=list(dict.fromkeys(facts.libraries)),
        source_files=[facts.source_name],
        state_variables=state_vars,
        events=events,
        errors=errors,
    )


def functions_from_facts(facts: ContractFacts, contract: ContractModel) -> list[FunctionModel]:
    models: list[FunctionModel] = []
    for fact in facts.functions:
        models.append(function_from_fact(fact, contract))
    return models


def call_site_roles(fact: FunctionFact) -> list[str]:
    """`onlyRole(FEE_ROLE)` names the role; the modifier body alone only says "a role"."""

    generic = {"role"} if fact.modifier_roles else set()
    return sorted({*fact.access_roles, *fact.modifier_roles} - generic)


def dangerous_operations(functions: list[FunctionFact]) -> dict[str, str]:
    """Signature -> the dangerous operation its body performs directly.

    shortcut: direct calls in the function body only; a helper that does the
    selfdestruct is missed. Follow internal calls if that becomes common.
    """

    found: dict[str, str] = {}
    for fact in functions:
        for call in fact.calls:
            if call.callee in {".call", ".delegatecall"} and call.receiver in fact.parameters:
                found[fact.signature] = f"{call.kind} to an address the caller picks"
            elif call.callee == "selfdestruct" or call.kind == "delegatecall":
                found.setdefault(
                    fact.signature, "selfdestruct" if call.callee == "selfdestruct" else call.kind
                )
    return found


def function_from_fact(fact: FunctionFact, contract: ContractModel) -> FunctionModel:
    function_id = identity.function_id(contract.id, fact.signature)
    roles = call_site_roles(fact)
    restriction = (
        AccessRestriction(fact.access_kind)
        if fact.access_kind != "none_identified"
        else (AccessRestriction.NONE_IDENTIFIED)
    )
    evidence = (
        [Evidence(kind="ast", detail=fact.access_detail, source=fact.source)]
        if fact.access_detail
        else []
    )
    external_calls = [
        call for call in fact.calls if call.kind in {"call", "delegatecall", "staticcall"}
    ]
    return FunctionModel(
        id=function_id,
        contract_id=contract.id,
        name=fact.name,
        signature=fact.signature,
        selector=(
            None
            if fact.is_constructor or fact.is_fallback or fact.is_receive
            else selector(fact.signature)
        ),
        visibility=Visibility(fact.visibility)
        if fact.visibility in Visibility._value2member_map_
        else Visibility.PUBLIC,
        mutability=Mutability(fact.mutability)
        if fact.mutability in Mutability._value2member_map_
        else Mutability.NONPAYABLE,
        is_constructor=fact.is_constructor,
        is_fallback=fact.is_fallback,
        is_receive=fact.is_receive,
        modifiers=fact.modifiers,
        inputs=fact.inputs,
        outputs=fact.outputs,
        calls_external=bool(external_calls),
        access=AccessAssessment(
            restriction=restriction,
            roles=roles,
            modifiers=fact.modifiers,
            evidence=evidence,
        ),
        source=fact.source,
        declared_in=fact.declared_in,
        writes=fact.writes,
    )


def apply_inherited_guards(facts_list: list[ContractFacts]) -> None:
    """Resolve modifier guards declared in base contracts.

    A function guarded by ``onlyOwner`` is only as resolvable as the contract that
    defines ``onlyOwner``. When a project is scanned from artifacts, each contract
    is analyzed from its own compilation unit, so the base contract's modifier body
    is in a different ``ContractFacts``. Merging ancestor modifiers turns
    ``inferred`` into ``confirmed`` without guessing.
    """

    by_name: dict[str, ContractFacts] = {}
    for facts in facts_list:
        by_name.setdefault(facts.name, facts)

    for facts in facts_list:
        for ancestor in _ancestors(facts, by_name):
            base = by_name.get(ancestor)
            if base is None:
                continue
            for name, modifier in base.modifiers.items():
                facts.modifiers.setdefault(name, modifier)

        for function in facts.functions:
            if function.access_kind == "confirmed":
                continue
            confirmed = [
                facts.modifiers[name]
                for name in function.modifiers
                if name in facts.modifiers and facts.modifiers[name].kind == "confirmed"
            ]
            if not confirmed:
                continue
            function.access_kind = "confirmed"
            function.access_roles = sorted(
                {*function.access_roles, *(m.role for m in confirmed if m.role)}
            )
            detail = "; ".join(f"{m.name}: {m.detail}" for m in confirmed)
            function.access_detail = (
                f"{detail}; {function.access_detail}" if function.access_detail else detail
            )


ENTRY_VISIBILITY = {"public", "external"}
CALL_DEPTH = 4


def resolve_surface(facts_list: list[ContractFacts]) -> None:
    """Give each contract its whole callable surface, then look through internal calls.

    A deployed `Vault is AccessControl, UUPSUpgradeable` answers `grantRole` and
    `upgradeToAndCall` even though it declares neither, so inherited public and
    external functions are copied onto it with ``declared_in`` set. Then, in the
    context of that contract, each entry point follows its internal calls: a guard
    in `_authorizeUpgrade` or `_onlyOwner()` protects the caller, and state written
    by `_transferOwnership` is written by `transferOwnership`.

    Both passes read the facts as the AST gave them, so a contract that overrides
    `_authorizeUpgrade` without a guard is not credited with its base's guard.
    """

    by_name: dict[str, ContractFacts] = {}
    for facts in facts_list:
        by_name.setdefault(facts.name, facts)
    lineages = {
        id(facts): [facts, *(by_name[n] for n in _ancestors(facts, by_name) if n in by_name)]
        for facts in facts_list
    }
    depth_of = {name: len(_ancestors(facts, by_name)) for name, facts in by_name.items()}

    def most_derived(options: list[tuple[ContractFacts, FunctionFact]]) -> FunctionFact:
        # Valid Solidity has one most-derived implementer; it has the most ancestors.
        return max(options, key=lambda option: depth_of.get(option[0].name, 0))[1]

    copies: list[tuple[ContractFacts, list[FunctionFact]]] = []
    for facts in facts_list:
        if facts.kind != "contract":
            continue
        own = {f.signature for f in facts.functions}
        inherited: dict[str, list[tuple[ContractFacts, FunctionFact]]] = {}
        for base in lineages[id(facts)][1:]:
            for function in base.functions:
                if (
                    function.signature not in own
                    and function.implemented
                    and not function.is_constructor
                    and function.visibility in ENTRY_VISIBILITY
                ):
                    inherited.setdefault(function.signature, []).append((base, function))
        added = []
        for options in inherited.values():
            chosen = most_derived(options)
            origin = next(c for c, f in options if f is chosen)
            added.append(
                replace(
                    chosen,
                    declared_in=origin.name,
                    access_roles=list(chosen.access_roles),
                    modifier_roles=list(chosen.modifier_roles),
                    writes=list(chosen.writes),
                )
            )
        copies.append((facts, added))
    for facts, added in copies:
        facts.functions.extend(added)

    # What the AST said, before any propagation below changes an entry point.
    pristine: dict[int, tuple[str, frozenset[str]]] = {
        id(f): (f.access_kind, frozenset(f.writes)) for c in facts_list for f in c.functions
    }
    ancestry = {name: set(_ancestors(facts, by_name)) for name, facts in by_name.items()}
    for facts in facts_list:
        _resolve_calls(facts, lineages[id(facts)], pristine, most_derived, ancestry)


def _resolve_calls(
    facts: ContractFacts,
    lineage: list[ContractFacts],
    pristine: dict[int, tuple[str, frozenset[str]]],
    most_derived: Callable[[list[tuple[ContractFacts, FunctionFact]]], FunctionFact],
    ancestry: dict[str, set[str]],
) -> None:
    owner_of = {id(f): c for c in lineage for f in c.functions if f.declared_in is None}

    def lookup(name: str, above: ContractFacts | None) -> FunctionFact | None:
        """Resolve an internal call; ``above`` is the caller's contract for `super.f()`."""

        scope = ancestry.get(above.name, set()) if above is not None else None
        options = [
            (c, f)
            for c in lineage
            for f in c.functions
            if f.name == name
            and f.implemented
            and f.declared_in is None
            and (scope is None or c.name in scope)
        ]
        mine = [f for c, f in options if c is facts and scope is None]
        return mine[0] if mine else (most_derived(options) if options else None)

    def follow(
        function: FunctionFact, depth: int, seen: frozenset[int]
    ) -> tuple[FunctionFact | None, set[str]]:
        """(a function on the path with a confirmed guard, every state write reached)."""

        kind, writes_here = pristine.get(id(function), (function.access_kind, frozenset()))
        writes = set(writes_here)
        guard = function if kind == "confirmed" else None
        if depth == 0:
            return guard, writes
        for call in function.calls:
            above = owner_of.get(id(function)) if call.receiver == "super" else None
            if call.receiver == "super" and above is None:
                continue
            callee = lookup(call.callee, above) if call.kind == "internal" else None
            if callee is None or id(callee) in seen:
                continue
            found, reached = follow(callee, depth - 1, seen | {id(callee)})
            writes |= reached
            guard = guard or found
        return guard, writes

    for function in facts.functions:
        if function.visibility not in ENTRY_VISIBILITY or function.is_constructor:
            continue
        guard, writes = follow(function, CALL_DEPTH, frozenset({id(function)}))
        function.writes = sorted(writes)
        if guard is None or guard is function:
            continue
        function.access_kind = "confirmed"
        function.access_roles = sorted({*function.access_roles, *guard.access_roles})
        function.modifier_roles = sorted({*function.modifier_roles, *guard.modifier_roles})
        function.access_detail = f"via {guard.name}(): {guard.access_detail}"


def _ancestors(contract: ContractFacts, by_name: dict[str, ContractFacts]) -> list[str]:
    """Transitive bases, breadth-first, so a diamond's shared base is visited once."""

    found: list[str] = []
    seen: set[str] = set()
    queue = list(contract.bases)
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        found.append(name)
        base = by_name.get(name)
        if base is not None:
            queue.extend(base.bases)
    return found


def facts_from_artifact(artifact: Artifact) -> list[ContractFacts]:
    """Extract only the contract this artifact describes.

    Foundry embeds the whole compilation-unit AST in every artifact, so walking it
    per artifact would report each contract once per sibling artifact. The artifact's
    own ``contractName`` is what the build system compiled here, so that is the only
    contract taken from it.
    """

    source_name = artifact.source_name or artifact.contract_name
    if artifact.ast:
        facts = analyze_one(artifact.ast, artifact.contract_name, source_name)
        if facts is not None:
            return [facts]
    return [facts_from_abi(artifact)]


def facts_from_abi(artifact: Artifact) -> ContractFacts:

    facts = ContractFacts(
        name=artifact.contract_name,
        kind="contract",
        source_name=artifact.source_name or artifact.contract_name,
    )
    for entry in artifact.abi:
        entry_type = entry.get("type")
        if entry_type == "function":
            signature = abi.canonical_signature(entry)
            facts.functions.append(
                FunctionFact(
                    name=str(entry.get("name", "")),
                    signature=signature,
                    visibility="external",
                    mutability=str(entry.get("stateMutability", "nonpayable")),
                    inputs=[abi.canonical_type(p) for p in entry.get("inputs", [])],
                    outputs=[abi.canonical_type(p) for p in entry.get("outputs", [])],
                    access_kind="unresolved",
                    access_detail="analyzed from ABI only; no AST available",
                )
            )
        elif entry_type == "constructor":
            facts.functions.append(
                FunctionFact(
                    name="constructor",
                    signature="constructor(...)",
                    visibility="public",
                    mutability=str(entry.get("stateMutability", "nonpayable")),
                    is_constructor=True,
                    access_kind="unresolved",
                )
            )
        elif entry_type == "fallback":
            facts.functions.append(
                FunctionFact(
                    name="fallback",
                    signature="fallback()",
                    visibility="external",
                    mutability=str(entry.get("stateMutability", "nonpayable")),
                    is_fallback=True,
                    access_kind="unresolved",
                )
            )
        elif entry_type == "receive":
            facts.functions.append(
                FunctionFact(
                    name="receive",
                    signature="receive()",
                    visibility="external",
                    mutability="payable",
                    is_receive=True,
                    access_kind="none_identified",
                )
            )
        elif entry_type == "event":
            facts.events.append(abi.canonical_signature(entry))
        elif entry_type == "error":
            facts.errors.append(abi.canonical_signature(entry))
    return facts


def derive_roles(
    facts: ContractFacts, contract: ContractModel, evidence_source: str | None
) -> list[RoleModel]:
    """Roles come from declared role constants and from resolved guard identifiers."""

    roles: dict[str, str] = {}
    for role_name in facts.roles.values():
        roles.setdefault(role_name, "access_control")
    for modifier in facts.modifiers.values():
        if modifier.role and modifier.kind == "confirmed" and modifier.role != "caller-identity":
            roles.setdefault(
                modifier.role, "ownable" if modifier.role == "owner" else "access_control"
            )
    for function in facts.functions:
        for role_name in function.access_roles:
            if role_name in {"caller-identity", "role"}:
                continue
            roles.setdefault(role_name, "custom")

    return [
        RoleModel(
            id=identity.role_id(contract.id, name),
            name=name,
            kind=kind,  # type: ignore[arg-type]
            contract_id=contract.id,
            description=f"role `{name}` referenced by {contract.name}",
            evidence=[Evidence(kind="ast", detail=f"role {name}", source=evidence_source)],
        )
        for name, kind in sorted(roles.items())
    ]


def assemble_contracts(
    state: ScanState,
    contracts: list[ContractModel],
    functions: list[FunctionModel],
    roles: list[RoleModel],
    call_facts: dict[str, list[tuple[FunctionModel, str, str]]],
) -> None:
    for contract in contracts:
        state.node_of[contract.id] = add_contract(state.builder, contract)
    add_inheritance(state.builder, contracts, state.node_of)
    by_name = {contract.name: contract for contract in contracts}

    for contract in contracts:
        owner = state.node_of[contract.id]
        contract_functions = [f for f in functions if f.contract_id == contract.id]
        add_functions(state.builder, contract, contract_functions, owner)
        add_access(
            state.builder,
            contract,
            contract_functions,
            [r for r in roles if r.contract_id == contract.id],
            owner,
        )
        add_call_edges(
            state.builder,
            contract,
            call_facts.get(contract.id, []),
            state.node_of,
            by_name,
        )
        state.functions.extend(contract_functions)


def models_from_facts(
    facts_list: list[ContractFacts],
    compiler: str | None,
) -> tuple[
    list[ContractModel],
    list[FunctionModel],
    list[RoleModel],
    dict[str, list[tuple[FunctionModel, str, str]]],
    list[Observation],
]:
    contracts: list[ContractModel] = []
    functions: list[FunctionModel] = []
    roles: list[RoleModel] = []
    calls: dict[str, list[tuple[FunctionModel, str, str]]] = {}
    observations: list[Observation] = []

    for facts in facts_list:
        contract = contract_from_facts(facts, compiler=compiler)
        contracts.append(contract)
        models = functions_from_facts(facts, contract)
        functions.extend(models)
        roles.extend(derive_roles(facts, contract, facts.source_name))

        by_signature = {model.signature: model for model in models}
        entries: list[tuple[FunctionModel, str, str]] = []
        for fact in facts.functions:
            model = by_signature.get(fact.signature)
            if model is None:
                continue
            for call in fact.calls:
                if call.kind in {"call", "delegatecall", "staticcall"}:
                    kind = "calls" if call.kind == "call" else call.kind
                    entries.append((model, call.callee, kind))
        calls[contract.id] = entries

        targets = [entry[1] for entry in entries]
        observations.extend(
            function_observations(contract, models, uses_delegatecall=facts.uses_delegatecall)
        )
        observations.extend(dependency_observations(contract, models, targets))
        # Only a deployable contract can be called; an abstract base is judged
        # through the contracts that inherit it.
        if contract.kind is ContractKind.CONTRACT:
            dangerous = dangerous_operations(facts.functions)
            observations.extend(dangerous_operation_observations(contract, models, dangerous))
            observations.extend(privileged_write_observations(contract, models))

    observations.extend(inheritance_observations(contracts))
    return contracts, functions, roles, calls, observations
