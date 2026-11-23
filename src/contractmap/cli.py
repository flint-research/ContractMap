"""Command line interface.

Exit codes: 0 success, 1 changes found (`diff --exit-code`), 2 invalid input,
3 operational failure, 4 partial analysis.
Expected failures are reported as one actionable line; tracebacks are only shown
when CONTRACTMAP_DEBUG is set, and credentials are redacted from RPC URLs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from contractmap import __version__
from contractmap.config import Limits, Settings
from contractmap.diff import AnalysisDiff, compare
from contractmap.errors import ContractMapError
from contractmap.evm.hashing import is_address
from contractmap.exporters.dot import to_dot
from contractmap.exporters.html import to_html
from contractmap.exporters.json_export import load_json, to_json
from contractmap.exporters.markdown import diff_to_markdown, to_markdown
from contractmap.exporters.schema import diff_schema, json_schema
from contractmap.exporters.svg import render_svg
from contractmap.exporters.terminal import render_summary, render_warnings
from contractmap.models import AnalysisResult

EXIT_OK = 0
EXIT_CHANGED = 1
EXIT_INPUT = 2
EXIT_FAILURE = 3
EXIT_PARTIAL = 4


class OutputFormat(StrEnum):
    terminal = "terminal"
    json = "json"
    dot = "dot"
    svg = "svg"
    html = "html"
    markdown = "markdown"


app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Map the architecture, dependencies and access control of EVM contracts.",
)


def _use_utf8_streams() -> None:
    """Rich draws box characters that cp1252 cannot encode; Windows needs this."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if reconfigure is None or encoding in {"utf8", "utf_8"}:
            continue
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")


_use_utf8_streams()
console = Console()
error_console = Console(stderr=True)

Format = Annotated[
    OutputFormat | None,
    typer.Option(
        "--format",
        "-f",
        case_sensitive=False,
        help="Output format. Default: taken from the --output extension, else terminal.",
    ),
]
SUFFIX_FORMATS = {
    ".json": OutputFormat.json,
    ".html": OutputFormat.html,
    ".htm": OutputFormat.html,
    ".dot": OutputFormat.dot,
    ".gv": OutputFormat.dot,
    ".svg": OutputFormat.svg,
    ".md": OutputFormat.markdown,
}
Output = Annotated[Path | None, typer.Option("--output", "-o", help="Write to this path.")]
Quiet = Annotated[bool, typer.Option("--quiet", "-q", help="Suppress the terminal summary.")]
Verbose = Annotated[bool, typer.Option("--verbose", help="List warnings and limits.")]
Rpc = Annotated[str | None, typer.Option("--rpc", help="JSON-RPC endpoint for address scans.")]
ChainId = Annotated[int | None, typer.Option("--chain-id", help="Expected chain id.")]
Block = Annotated[int | None, typer.Option("--block", help="Pin every read to this block.")]
Depth = Annotated[int | None, typer.Option("--depth", help="Proxy traversal depth.")]
MaxNodes = Annotated[int | None, typer.Option("--max-nodes", help="Graph node budget.")]
MaxRequests = Annotated[int | None, typer.Option("--max-requests", help="RPC request budget.")]
Concurrency = Annotated[int | None, typer.Option("--concurrency", help="Concurrent RPC requests.")]
Timeout = Annotated[float | None, typer.Option("--timeout", help="Per-request timeout, seconds.")]
NoSourcify = Annotated[bool, typer.Option("--no-sourcify", help="Skip Sourcify lookups.")]
Etherscan = Annotated[
    bool, typer.Option("--etherscan", help="Also query Etherscan v2 when a key is configured.")
]


def _settings(
    *,
    rpc: str | None,
    chain_id: int | None,
    block: int | None,
    depth: int | None,
    max_nodes: int | None,
    max_requests: int | None,
    concurrency: int | None,
    timeout: float | None,
    allow_build: bool,
    solc: str | None,
    no_sourcify: bool,
    etherscan: bool,
    verbose: bool,
    include_dependencies: bool = False,
) -> Settings:
    settings = Settings.from_env()
    settings.verbose = verbose
    settings.allow_build = allow_build
    settings.include_dependencies = include_dependencies
    if rpc:
        settings.rpc_url = rpc
    if chain_id is not None:
        settings.chain_id = chain_id
    if block is not None:
        settings.block = block
    if solc:
        settings.solc_path = solc
    current = settings.limits
    settings.limits = Limits(
        depth=depth if depth is not None else current.depth,
        max_nodes=max_nodes if max_nodes is not None else current.max_nodes,
        max_requests=max_requests if max_requests is not None else current.max_requests,
        concurrency=concurrency if concurrency is not None else current.concurrency,
        timeout=timeout if timeout is not None else current.timeout,
        max_response_bytes=current.max_response_bytes,
        retries=current.retries,
    )
    if no_sourcify:
        settings.sources.sourcify = False
    if etherscan:
        settings.sources.etherscan = True
    return settings


def _render(result: AnalysisResult, fmt: OutputFormat) -> str:
    if fmt is OutputFormat.json:
        return to_json(result)
    if fmt is OutputFormat.dot:
        return to_dot(result)
    if fmt is OutputFormat.svg:
        return render_svg(result)
    if fmt is OutputFormat.markdown:
        return to_markdown(result)
    if fmt is OutputFormat.html:
        return to_html(result)
    return render_summary(result)


def _resolve_format(fmt: OutputFormat | None, output: Path | None) -> OutputFormat:
    if fmt is not None:
        return fmt
    if output is not None:
        return SUFFIX_FORMATS.get(output.suffix.lower(), OutputFormat.terminal)
    return OutputFormat.terminal


def _write(text: str, output: Path, quiet: bool) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    if not quiet:
        console.print(f"[dim]wrote[/dim] {output}")


def _emit(result: AnalysisResult, fmt: OutputFormat, output: Path | None, quiet: bool) -> None:
    text = _render(result, fmt)
    if output is None:
        sys.stdout.write(text)
        return
    _write(text, output, quiet)


def _debug_enabled() -> bool:
    return os.environ.get("CONTRACTMAP_DEBUG", "").strip().lower() in {"1", "true", "yes"}


def _fail(exc: Exception) -> None:
    if _debug_enabled():
        raise exc
    if isinstance(exc, ContractMapError):
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(exc.exit_code) from None
    error_console.print(f"[red]error:[/red] {type(exc).__name__}: {exc}")
    raise typer.Exit(EXIT_FAILURE) from None


def _exit_code(result: AnalysisResult) -> int:
    return EXIT_OK if result.metadata.analysis_complete else EXIT_PARTIAL


@app.command()
def scan(
    target: Annotated[
        str, typer.Argument(help="Project directory, .sol or artifact file, or 0x address.")
    ] = ".",
    format: Format = None,
    output: Output = None,
    rpc: Rpc = None,
    chain_id: ChainId = None,
    block: Block = None,
    depth: Depth = None,
    max_nodes: MaxNodes = None,
    max_requests: MaxRequests = None,
    concurrency: Concurrency = None,
    timeout: Timeout = None,
    allow_build: Annotated[
        bool,
        typer.Option(
            "--allow-build", help="Let ContractMap run forge or solc to compile the sources."
        ),
    ] = False,
    include_all: Annotated[
        bool, typer.Option("--all", help="Also list library, test and script contracts.")
    ] = False,
    solc: Annotated[str | None, typer.Option("--solc", help="Path to a solc binary.")] = None,
    no_sourcify: NoSourcify = False,
    etherscan: Etherscan = False,
    quiet: Quiet = False,
    verbose: Verbose = False,
) -> None:
    """Map a local project (default: the current directory) or a deployed address."""

    format = _resolve_format(format, output)

    settings = _settings(
        rpc=rpc,
        chain_id=chain_id,
        block=block,
        depth=depth,
        max_nodes=max_nodes,
        max_requests=max_requests,
        concurrency=concurrency,
        timeout=timeout,
        allow_build=allow_build,
        solc=solc,
        no_sourcify=no_sourcify,
        etherscan=etherscan,
        verbose=verbose,
        include_dependencies=include_all,
    )

    try:
        if is_address(target):
            from contractmap.scanner.remote import scan_address

            result = asyncio.run(scan_address(target, settings))
        else:
            from contractmap.scanner.local import scan_local

            result = scan_local(target, settings)
        _emit(result, format, output, quiet)
    except Exception as exc:
        _fail(exc)
        return

    if not quiet and output is not None:
        console.print(_render(result, OutputFormat.terminal))
    if verbose and not quiet:
        render_warnings(result, console)
    raise typer.Exit(_exit_code(result))


@app.command()
def inspect(
    address: Annotated[str, typer.Argument(help="Deployed contract address.")],
    rpc: Rpc = None,
    chain_id: ChainId = None,
    block: Block = None,
    depth: Depth = 1,
    max_requests: MaxRequests = None,
    timeout: Timeout = None,
    allow_build: Annotated[
        bool, typer.Option("--allow-build", help="Compile verified source to resolve guards.")
    ] = False,
    solc: Annotated[str | None, typer.Option("--solc", help="Path to a solc binary.")] = None,
    no_sourcify: NoSourcify = False,
    quiet: Quiet = False,
    verbose: Verbose = False,
) -> None:
    """Console view of one deployed contract: proxy, entry points, privileged accounts."""

    if not is_address(address):
        error_console.print(f"[red]error:[/red] not a 20-byte hex address: {address!r}")
        raise typer.Exit(EXIT_INPUT)

    settings = _settings(
        rpc=rpc,
        chain_id=chain_id,
        block=block,
        depth=depth,
        max_nodes=None,
        max_requests=max_requests,
        concurrency=None,
        timeout=timeout,
        allow_build=allow_build,
        solc=solc,
        no_sourcify=no_sourcify,
        etherscan=False,
        verbose=verbose,
    )

    try:
        from contractmap.scanner.remote import scan_address

        result = asyncio.run(scan_address(address, settings))
    except Exception as exc:
        _fail(exc)
        return

    if quiet:
        raise typer.Exit(_exit_code(result))
    console.print(_render(result, OutputFormat.terminal))
    if verbose:
        render_warnings(result, console)
    raise typer.Exit(_exit_code(result))


@app.command()
def diff(
    before: Annotated[Path, typer.Argument(help="Earlier JSON analysis.")],
    after: Annotated[Path, typer.Argument(help="Later JSON analysis.")],
    format: Annotated[
        str | None,
        typer.Option("--format", "-f", help="terminal, json or markdown. Default: from --output."),
    ] = None,
    output: Output = None,
    exit_code: Annotated[
        bool, typer.Option("--exit-code", help="Exit 1 when there are changes (for CI).")
    ] = False,
    quiet: Quiet = False,
    verbose: Verbose = False,
) -> None:
    """Compare two JSON analyses and report architectural changes."""

    if format is None:
        suffix = output.suffix.lower() if output is not None else ""
        format = {".json": "json", ".md": "markdown"}.get(suffix, "terminal")

    try:
        earlier = load_json(before)
        later = load_json(after)
    except FileNotFoundError as exc:
        error_console.print(f"[red]error:[/red] {exc.filename} does not exist")
        raise typer.Exit(EXIT_INPUT) from None
    except (ValueError, json.JSONDecodeError) as exc:
        error_console.print(f"[red]error:[/red] not a contractmap JSON analysis: {exc}")
        raise typer.Exit(EXIT_INPUT) from None

    if format not in {"json", "terminal", "markdown"}:
        error_console.print(f"[red]error:[/red] unknown diff format {format!r}")
        raise typer.Exit(EXIT_INPUT)

    changes = compare(earlier, later)
    if format == "json":
        text = changes.model_dump_json(indent=2) + "\n"
    elif format == "markdown":
        text = diff_to_markdown(changes)
    else:
        text = _diff_text(changes)
    if output is not None:
        _write(text, output, quiet)
    elif format != "terminal":
        sys.stdout.write(text)

    if not quiet and (format == "terminal" or output is not None):
        _render_diff(changes, verbose)
    raise typer.Exit(EXIT_CHANGED if exit_code and changes.changes else EXIT_OK)


def _diff_text(changes: AnalysisDiff) -> str:
    lines = list(changes.caveats)
    if not changes.changes:
        lines.append("no architectural changes")
        return "\n".join(lines) + "\n"
    for entry in changes.significant():
        lines.append(
            f"{entry.kind.value:8} {entry.category.value:12} {entry.label}"
            f"  [{entry.before or '-'} -> {entry.after or '-'}]"
        )
    return "\n".join(lines) + "\n"


def _render_diff(changes: AnalysisDiff, verbose: bool) -> None:
    for caveat in changes.caveats:
        console.print(f"[yellow]note:[/yellow] {caveat}")
    if not changes.changes:
        console.print("[green]no architectural changes[/green]")
        return

    table = Table(title="Architectural changes", show_lines=False)
    table.add_column("change", style="bold")
    table.add_column("category")
    table.add_column("subject")
    table.add_column("before")
    table.add_column("after")
    colours = {"added": "green", "removed": "red", "changed": "yellow"}
    entries = changes.significant()
    limit = len(entries) if verbose else 40
    for entry in entries[:limit]:
        table.add_row(
            f"[{colours[entry.kind.value]}]{entry.kind.value}[/]",
            entry.category.value,
            entry.label,
            entry.before or "-",
            entry.after or "-",
        )
    console.print(table)
    if len(entries) > limit:
        console.print(f"[dim]{len(entries) - limit} more changes; use --verbose[/dim]")


@app.command("schema")
def schema_command(
    output: Output = None,
    diff_output: Annotated[
        bool, typer.Option("--diff", help="Emit the schema of diff output instead.")
    ] = False,
) -> None:
    """Print the JSON Schema of analysis (or diff) output."""

    schema = diff_schema() if diff_output else json_schema()
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    if output is not None:
        _write(text, output, quiet=False)
        return
    sys.stdout.write(text)


@app.command()
def version() -> None:
    """Print the installed version."""

    console.print(f"contractmap {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
