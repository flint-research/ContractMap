"""Rich terminal rendering of an analysis."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from contractmap.models import (
    AccessRestriction,
    AnalysisResult,
    NodeKind,
    ProxyKind,
    Resolution,
)

RESOLUTION_STYLE = {
    Resolution.CONFIRMED: "green",
    Resolution.INFERRED: "yellow",
    Resolution.UNRESOLVED: "red",
}

ACCESS_STYLE = {
    AccessRestriction.CONFIRMED: ("restricted", "green"),
    AccessRestriction.INFERRED: ("likely restricted", "yellow"),
    AccessRestriction.NONE_IDENTIFIED: ("no guard found", "yellow"),
    AccessRestriction.UNRESOLVED: ("unresolved", "red"),
}

MAX_ROWS = 40


def _header(result: AnalysisResult) -> Panel:
    lines = [Text(result.target.identifier, style="bold")]
    details: list[str] = []
    if result.chain.chain_id is not None:
        details.append(f"chain {result.chain.chain_id}")
    if result.chain.block_number is not None:
        details.append(f"block {result.chain.block_number}")
    if result.target.build_system:
        details.append(result.target.build_system)
    if result.metadata.compiler:
        details.append(f"solc {result.metadata.compiler}")
    if details:
        lines.append(Text(" \u00b7 ".join(details), style="dim"))
    lines.append(
        Text(
            f"{len(result.contracts)} contracts \u00b7 {len(result.functions)} functions "
            f"\u00b7 {len(result.observations)} observations \u00b7 {len(result.edges)} edges",
            style="dim",
        )
    )
    if not result.metadata.analysis_complete:
        lines.append(Text("partial analysis", style="yellow"))
    return Panel(Text("\n").join(lines), title="contractmap", title_align="left", expand=False)


def _contracts_table(result: AnalysisResult) -> Table | None:
    if not result.contracts:
        return None
    table = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
    table.add_column("contract", overflow="fold")
    table.add_column("kind", style="dim")
    table.add_column("address", style="dim")
    table.add_column("proxy")
    table.add_column("entries", justify="right")
    table.add_column("privileged", justify="right")
    for contract in result.contracts[:MAX_ROWS]:
        entry_points = [
            f for f in result.functions if f.contract_id == contract.id and f.is_entry_point
        ]
        privileged = [
            f
            for f in entry_points
            if f.access.restriction in (AccessRestriction.CONFIRMED, AccessRestriction.INFERRED)
        ]
        proxy = "-"
        if contract.proxy is not None and contract.proxy.kind != ProxyKind.UNKNOWN:
            proxy = f"{contract.proxy.kind.value} ({contract.proxy.resolution.value})"
        table.add_row(
            contract.name,
            contract.kind.value,
            contract.address or "-",
            proxy,
            str(len(entry_points)),
            str(len(privileged)),
        )
    return table


def _privileged_table(result: AnalysisResult) -> Table | None:
    rows = [
        f
        for f in result.deployable_entry_points()
        if f.is_entry_point
        and f.access.restriction in (AccessRestriction.CONFIRMED, AccessRestriction.INFERRED)
    ]
    if not rows:
        return None
    names = {c.id: c.name for c in result.contracts}
    table = Table(
        title="Privileged entry points", box=None, header_style="dim", title_justify="left"
    )
    table.add_column("function", overflow="fold")
    table.add_column("access")
    table.add_column("roles", style="dim")
    for function in rows[:MAX_ROWS]:
        label, colour = ACCESS_STYLE[function.access.restriction]
        table.add_row(
            f"{names.get(function.contract_id, '?')}.{function.signature}",
            f"[{colour}]{label}[/]",
            ", ".join(function.access.roles) or "-",
        )
    return table


def _observations_table(result: AnalysisResult) -> Table | None:
    if not result.observations:
        return None
    names = {c.id: c.name for c in result.contracts}
    table = Table(title="Observations", box=None, header_style="dim", title_justify="left")
    table.add_column("contract")
    table.add_column("finding", overflow="fold")
    table.add_column("resolution")
    for observation in result.observations_by_priority()[:MAX_ROWS]:
        colour = RESOLUTION_STYLE.get(observation.resolution, "white")
        # Name the functions, so the row says where to look.
        functions = [e.detail for e in observation.evidence if e.kind == "function"]
        finding = Text(observation.title)
        if functions:
            shown = ", ".join(functions[:4]) + (", ..." if len(functions) > 4 else "")
            finding.append(f"\n{shown}", style="dim")
        table.add_row(
            names.get(observation.subject, "-"),
            finding,
            f"[{colour}]{observation.resolution.value}[/]",
        )
    if len(result.observations) > MAX_ROWS:
        table.add_row("", f"[dim]{len(result.observations) - MAX_ROWS} more[/dim]", "")
    return table


def render_summary(result: AnalysisResult, console: Console | None = None) -> str:
    buffer = None
    target = console
    if target is None:
        buffer = StringIO()
        target = Console(file=buffer, width=100, highlight=False)

    target.print(_header(result))
    for block in (
        _contracts_table(result),
        _privileged_table(result),
        _observations_table(result),
    ):
        if block is not None:
            target.print(block)

    kinds: dict[NodeKind, int] = {}
    for node in result.nodes:
        kinds[node.kind] = kinds.get(node.kind, 0) + 1
    if kinds:
        breakdown = ", ".join(
            f"{count} {kind.value}"
            for kind, count in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0].value))
        )
        target.print(Text(f"graph: {breakdown}", style="dim"))

    # The first few warnings usually say how to get a better result, so show them.
    for warning in result.warnings[:3]:
        target.print(Text(f"warning: {warning.message}", style="yellow"))
    if len(result.warnings) > 3:
        target.print(
            Text(f"{len(result.warnings) - 3} more warning(s); rerun with --verbose", style="dim")
        )
    return buffer.getvalue() if buffer is not None else ""


def render_warnings(result: AnalysisResult, console: Console) -> None:
    if not result.warnings:
        return
    table = Table(title="Warnings", box=None, header_style="dim", title_justify="left")
    table.add_column("code", style="dim")
    table.add_column("message", overflow="fold")
    for warning in result.warnings[:MAX_ROWS]:
        table.add_row(warning.code, warning.message)
    console.print(table)
