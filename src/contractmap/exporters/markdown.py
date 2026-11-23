"""Markdown reports, for pull request comments, issues and audit notes."""

from __future__ import annotations

from contractmap.diff import AnalysisDiff
from contractmap.exporters.terminal import ACCESS_STYLE
from contractmap.models import (
    AccessRestriction,
    AnalysisResult,
    FunctionModel,
    Mutability,
    ProxyKind,
)


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    lines.extend("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows)
    return [*lines, ""]


def _who(function: FunctionModel) -> str:
    if function.access.restriction is AccessRestriction.NONE_IDENTIFIED:
        return "anyone"
    if function.access.roles:
        return ", ".join(function.access.roles)
    return ", ".join(function.access.modifiers) or "-"


def to_markdown(result: AnalysisResult) -> str:
    names = {c.id: c.name for c in result.contracts}
    details: list[str] = []
    if result.chain.chain_id is not None:
        details += [f"chain {result.chain.chain_id}", f"block {result.chain.block_number}"]
    if result.target.build_system:
        details.append(result.target.build_system)
    if result.metadata.compiler:
        details.append(f"solc {result.metadata.compiler}")
    lines = [
        f"# ContractMap: `{result.target.identifier}`",
        "",
        " · ".join(details),
        "",
        f"{len(result.contracts)} contracts, {len(result.entry_points())} entry points, "
        f"{len(result.observations)} observations.",
        "",
    ]
    if not result.metadata.analysis_complete:
        lines += ["> **Partial analysis:** a budget ran out, so this map is incomplete.", ""]

    lines += ["## Contracts", ""]
    rows = []
    for contract in result.contracts:
        entries = [f for f in result.entry_points() if f.contract_id == contract.id]
        proxy = "-"
        if contract.proxy is not None and contract.proxy.kind != ProxyKind.UNKNOWN:
            proxy = contract.proxy.kind.value
        rows.append(
            [contract.name, contract.kind.value, contract.address or "-", proxy, str(len(entries))]
        )
    lines += _table(["contract", "kind", "address", "proxy", "entry points"], rows)

    # View and pure functions cannot change state, so they are left out.
    changing = [
        f
        for f in result.deployable_entry_points()
        if f.mutability not in (Mutability.VIEW, Mutability.PURE) and not f.is_constructor
    ]
    if changing:
        lines += ["## State-changing entry points", ""]
        lines += _table(
            ["function", "access", "who can call", "writes", "declared in"],
            [
                [
                    f"`{names.get(f.contract_id, '?')}.{f.signature}`",
                    ACCESS_STYLE[f.access.restriction][0],
                    _who(f),
                    ", ".join(f.writes) or "-",
                    f.declared_in or "-",
                ]
                for f in changing
            ],
        )

    if result.observations:
        lines += ["## Observations", ""]
        lines += _table(
            ["contract", "finding", "functions", "resolution"],
            [
                [
                    names.get(o.subject, "-"),
                    o.title,
                    ", ".join(e.detail for e in o.evidence if e.kind == "function") or "-",
                    o.resolution.value,
                ]
                for o in result.observations_by_priority()
            ],
        )

    if result.warnings:
        lines += ["## Warnings", ""]
        lines += [f"- {w.message}" for w in result.warnings] + [""]
    return "\n".join(lines)


def diff_to_markdown(changes: AnalysisDiff) -> str:
    lines = ["# ContractMap diff", ""]
    lines += [f"> {caveat}" for caveat in changes.caveats]
    if changes.caveats:
        lines.append("")
    if not changes.changes:
        return "\n".join([*lines, "No architectural changes.", ""])
    lines += [f"{len(changes.changes)} change(s).", ""]
    lines += _table(
        ["change", "category", "subject", "before", "after"],
        [
            [e.kind.value, e.category.value, e.label, e.before or "-", e.after or "-"]
            for e in changes.significant()
        ],
    )
    return "\n".join(lines)
