"""Command-line behaviour: exit codes, formats, and error messages.

These drive the real Typer app, so a regression in argument wiring or exit-code
mapping fails here rather than in someone's pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from contractmap.cli import app
from contractmap.sources.solc import find_solc

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FOUNDRY = FIXTURES / "foundry"
PROJECT = FIXTURES / "project"
ARTIFACT = FOUNDRY / "out" / "Vault.sol" / "Vault.json"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_version(runner: CliRunner) -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "contractmap" in result.stdout


@pytest.mark.parametrize("args", [["scan", "--help"], ["inspect", "--help"], ["diff", "--help"]])
def test_help_exits_cleanly(runner: CliRunner, args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "Usage" in result.stdout


def test_no_arguments_prints_help(runner: CliRunner) -> None:
    """Click reports missing arguments as a usage error, so 2 is the expected code."""

    result = runner.invoke(app, [])
    assert result.exit_code == 2
    assert "Usage" in result.stdout


def test_missing_target_is_exit_two(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", "does-not-exist-anywhere"])
    assert result.exit_code == 2
    assert "does not exist" in result.stderr


def test_source_scan_without_build_permission_is_exit_two(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", str(PROJECT)])
    assert result.exit_code == 2
    assert "--allow-build" in result.stderr


def test_scan_writes_json(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "analysis.json"
    result = runner.invoke(
        app, ["scan", str(FOUNDRY), "--format", "json", "--output", str(destination)]
    )
    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["schema_version"]
    assert {contract["name"] for contract in payload["contracts"]} >= {"Vault", "Ownable"}


def test_json_has_the_documented_top_level_keys(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "keys.json"
    runner.invoke(app, ["scan", str(ARTIFACT), "-f", "json", "-o", str(destination)])
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert set(payload) == {
        "chain",
        "contracts",
        "edges",
        "functions",
        "metadata",
        "nodes",
        "observations",
        "roles",
        "schema_version",
        "target",
        "tool",
        "warnings",
    }


@pytest.mark.parametrize("fmt", ["dot", "svg", "html"])
def test_graph_formats_produce_output(runner: CliRunner, tmp_path: Path, fmt: str) -> None:
    destination = tmp_path / f"graph.{fmt}"
    result = runner.invoke(app, ["scan", str(ARTIFACT), "-f", fmt, "-o", str(destination)])
    assert result.exit_code == 0
    assert destination.stat().st_size > 0


def test_html_output_is_offline(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "map.html"
    runner.invoke(app, ["scan", str(ARTIFACT), "-f", "html", "-o", str(destination)])
    html = destination.read_text(encoding="utf-8")
    # A remote script or stylesheet would break the promise of an offline viewer.
    assert 'src="http' not in html
    assert 'href="http' not in html


def test_html_report_embeds_the_whole_analysis(runner: CliRunner, tmp_path: Path) -> None:
    """The report shows evidence, writes and findings, so it needs more than the graph."""

    destination = tmp_path / "map.html"
    runner.invoke(app, ["scan", str(FOUNDRY), "-o", str(destination), "-q"])
    page = destination.read_text(encoding="utf-8")
    raw = page.split('<script id="analysis" type="application/json">', 1)[1].split("</script>", 1)[
        0
    ]
    payload = json.loads(raw)
    destroy = next(f for f in payload["functions"] if f["name"] == "destroy")
    assert destroy["access"]["restriction"] == "none_identified"
    assert "writes" in destroy and "declared_in" in destroy
    # Findings arrive in the same priority order terminal and Markdown use.
    first = next(o for o in payload["observations"] if o["id"] == payload["observation_order"][0])
    assert first["category"] == "unguarded_dangerous_operation"


def test_quiet_still_writes_the_file(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "quiet.json"
    result = runner.invoke(app, ["scan", str(ARTIFACT), "-f", "json", "-o", str(destination), "-q"])
    assert result.exit_code == 0
    assert destination.exists()
    assert result.stdout.strip() == ""


def test_diff_of_identical_analyses_reports_no_changes(runner: CliRunner, tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    for path in (first, second):
        runner.invoke(app, ["scan", str(FOUNDRY), "-f", "json", "-o", str(path), "-q"])
    result = runner.invoke(app, ["diff", str(first), str(second)])
    assert result.exit_code == 0
    assert "no architectural changes" in result.stdout


def test_diff_rejects_missing_files(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(app, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json")])
    assert result.exit_code == 2


def test_diff_rejects_non_analysis_json(runner: CliRunner, tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.json"
    bogus.write_text('{"hello": "world"}', encoding="utf-8")
    result = runner.invoke(app, ["diff", str(bogus), str(bogus)])
    assert result.exit_code == 2


def test_schema_is_valid_json(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "schema.json"
    assert runner.invoke(app, ["schema", "-o", str(destination)]).exit_code == 0
    schema = json.loads(destination.read_text(encoding="utf-8"))
    assert schema.get("$schema") or schema.get("type")


def test_diff_schema_differs_from_the_analysis_schema(runner: CliRunner, tmp_path: Path) -> None:
    analysis = tmp_path / "analysis.json"
    changes = tmp_path / "diff.json"
    runner.invoke(app, ["schema", "-o", str(analysis)])
    runner.invoke(app, ["schema", "--diff", "-o", str(changes)])
    assert analysis.read_text(encoding="utf-8") != changes.read_text(encoding="utf-8")


def test_inspect_rejects_a_non_address(runner: CliRunner) -> None:
    result = runner.invoke(app, ["inspect", "not-an-address"])
    assert result.exit_code == 2
    assert "20-byte hex address" in result.stderr


def test_scan_of_one_artifact_file(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "vault.json"
    result = runner.invoke(app, ["scan", str(ARTIFACT), "-f", "json", "-o", str(destination)])
    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert [contract["name"] for contract in payload["contracts"]] == ["Vault"]


def test_a_truncated_graph_exits_four(runner: CliRunner, tmp_path: Path) -> None:
    """Exit 4 means output exists but a budget cut the graph short."""

    destination = tmp_path / "tiny.json"
    result = runner.invoke(
        app, ["scan", str(FOUNDRY), "-f", "json", "-o", str(destination), "--max-nodes", "3"]
    )
    assert result.exit_code == 4
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["metadata"]["analysis_complete"] is False
    assert any("budget" in warning["message"] for warning in payload["warnings"])


@pytest.mark.skipif(find_solc() is None, reason="needs a solc binary")
def test_scan_of_a_source_project_records_the_compiler(runner: CliRunner, tmp_path: Path) -> None:
    destination = tmp_path / "source.json"
    result = runner.invoke(
        app, ["scan", str(PROJECT), "--allow-build", "-f", "json", "-o", str(destination), "-q"]
    )
    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["metadata"]["compiler"]
    assert payload["target"]["resolved_paths"]


@pytest.mark.parametrize(("suffix", "marker"), [(".html", "<!doctype html>"), (".json", '"tool"')])
def test_format_follows_the_output_extension(
    runner: CliRunner, tmp_path: Path, suffix: str, marker: str
) -> None:
    destination = tmp_path / f"map{suffix}"
    result = runner.invoke(app, ["scan", str(FOUNDRY), "-o", str(destination)])
    assert result.exit_code == 0
    assert marker in destination.read_text(encoding="utf-8")


def test_scan_defaults_to_the_current_directory(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(FOUNDRY)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert "Vault" in result.stdout


def test_diff_exit_code_flags_changes(runner: CliRunner, tmp_path: Path) -> None:
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    runner.invoke(app, ["scan", str(FOUNDRY), "-o", str(before), "-q"])
    runner.invoke(app, ["scan", str(ARTIFACT), "-o", str(after), "-q"])
    same = runner.invoke(app, ["diff", str(before), str(before), "--exit-code"])
    changed = runner.invoke(app, ["diff", str(before), str(after), "--exit-code"])
    assert same.exit_code == 0
    assert changed.exit_code == 1


def test_markdown_report_lists_unguarded_functions(runner: CliRunner, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    assert runner.invoke(app, ["scan", str(FOUNDRY), "-o", str(report), "-q"]).exit_code == 0
    text = report.read_text(encoding="utf-8")
    assert "## State-changing entry points" in text
    assert "| `Upgradable.destroy()` | no guard found | anyone | - | - |" in text


def test_markdown_diff(runner: CliRunner, tmp_path: Path) -> None:
    before, after, report = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "diff.md"
    runner.invoke(app, ["scan", str(FOUNDRY), "-o", str(before), "-q"])
    runner.invoke(app, ["scan", str(ARTIFACT), "-o", str(after), "-q"])
    runner.invoke(app, ["diff", str(before), str(after), "-o", str(report), "-q"])
    text = report.read_text(encoding="utf-8")
    assert text.startswith("# ContractMap diff")
    assert "| changed | access | Vault.setFee(uint256) |" in text
