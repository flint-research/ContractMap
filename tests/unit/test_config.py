"""Environment handling and compiler discovery.

Both read the host machine, so each test isolates the variables it depends on and
builds a fake version store rather than relying on what happens to be installed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from contractmap import config as config_module
from contractmap.config import Settings, load_env_file, load_env_files
from contractmap.sources import solc as solc_module
from contractmap.sources.solc import find_solc, installed_versions, solc_version

ENV_NAMES = (
    "CONTRACTMAP_RPC_URL",
    "CONTRACTMAP_DEPTH",
    "CONTRACTMAP_MAX_NODES",
    "CONTRACTMAP_MAX_REQUESTS",
    "CONTRACTMAP_CONCURRENCY",
    "CONTRACTMAP_ENV_FILE",
    "CONTRACTMAP_NO_SOURCIFY",
    "CONTRACTMAP_ETHERSCAN",
    "CONTRACTMAP_DEBUG",
    "ETH_RPC_URL",
    "ETHERSCAN_API_KEY",
    "SOURCIFY_URL",
    "SVM_HOME",
    "FOUNDRY_DIR",
    "PATH",
)


@pytest.fixture
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    # The loader remembers which values it planted and which files it read; both are
    # module state, so reset them or one test leaks into the next.
    monkeypatch.setattr(config_module, "_planted_values", {})
    monkeypatch.setattr(config_module, "_loaded_env_files", [])
    return monkeypatch


@pytest.fixture
def only_store_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Point compiler discovery at one fake store and nothing else.

    Without this the host's own Foundry store is searched, which would make the
    assertions depend on whatever compilers happen to be installed.
    """

    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    store = tmp_path / "svm"
    monkeypatch.setenv("SVM_HOME", str(store))
    monkeypatch.setattr(solc_module, "_roots", lambda: [store] if store.is_dir() else [])
    return store


def test_dotenv_is_loaded(isolated_env, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "CONTRACTMAP_RPC_URL=http://localhost:8545\n"
        "# a comment\n"
        "export CONTRACTMAP_DEPTH=5\n"
        "CONTRACTMAP_MAX_NODES=42\n",
        encoding="utf-8",
    )
    assert load_env_file(tmp_path / ".env") is True
    assert os.environ["CONTRACTMAP_RPC_URL"] == "http://localhost:8545"
    assert os.environ["CONTRACTMAP_DEPTH"] == "5"
    assert Settings.from_env().limits.max_nodes == 42


def test_real_environment_wins_over_the_file(isolated_env, tmp_path: Path) -> None:
    """A CI secret must never be shadowed by a developer's local dotenv."""

    isolated_env.setenv("CONTRACTMAP_RPC_URL", "http://from-shell:8545")
    (tmp_path / ".env").write_text("CONTRACTMAP_RPC_URL=http://from-file:8545\n", "utf-8")
    load_env_files(tmp_path)
    assert Settings.from_env().rpc_url == "http://from-shell:8545"


def test_env_file_variable_selects_one_file(isolated_env, tmp_path: Path) -> None:
    chosen = tmp_path / "custom.env"
    chosen.write_text("CONTRACTMAP_CHAIN_HINT=1\nCONTRACTMAP_DEPTH=7\n", encoding="utf-8")
    (tmp_path / ".env").write_text("CONTRACTMAP_DEPTH=1\n", encoding="utf-8")
    isolated_env.setenv("CONTRACTMAP_ENV_FILE", str(chosen))
    isolated_env.setenv("CONTRACTMAP_RPC_URL", "http://x:1")
    loaded = load_env_files(tmp_path)
    assert os.environ["CONTRACTMAP_DEPTH"] == "7"
    assert loaded == [str(chosen)]


def test_env_local_overrides_env(isolated_env, tmp_path: Path) -> None:
    """`.env` holds defaults, `.env.local` holds this machine; local must win."""

    (tmp_path / ".env").write_text("CONTRACTMAP_DEPTH=2\nCONTRACTMAP_MAX_NODES=400\n", "utf-8")
    (tmp_path / ".env.local").write_text("CONTRACTMAP_DEPTH=5\n", encoding="utf-8")
    load_env_files(tmp_path)
    assert os.environ["CONTRACTMAP_DEPTH"] == "5"
    assert os.environ["CONTRACTMAP_MAX_NODES"] == "400"


def test_an_empty_placeholder_does_not_block_a_later_file(isolated_env, tmp_path: Path) -> None:
    """`.env.example` ships `CONTRACTMAP_RPC_URL=`; copying it to `.env` must not
    stop `.env.local` from supplying the real endpoint."""

    (tmp_path / ".env").write_text("CONTRACTMAP_RPC_URL=\nETHERSCAN_API_KEY=\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text(
        "CONTRACTMAP_RPC_URL=http://local:8545\n", encoding="utf-8"
    )
    load_env_files(tmp_path)
    assert Settings.from_env().rpc_url == "http://local:8545"


def test_the_shell_still_beats_every_file(isolated_env, tmp_path: Path) -> None:
    isolated_env.setenv("CONTRACTMAP_DEPTH", "9")
    (tmp_path / ".env").write_text("CONTRACTMAP_DEPTH=2\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("CONTRACTMAP_DEPTH=5\n", encoding="utf-8")
    load_env_files(tmp_path)
    assert os.environ["CONTRACTMAP_DEPTH"] == "9"


def test_quoted_values_lose_their_quotes(isolated_env, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text('CONTRACTMAP_RPC_URL="http://a:1/?k=v"\n', encoding="utf-8")
    load_env_file(tmp_path / ".env")
    assert os.environ["CONTRACTMAP_RPC_URL"] == "http://a:1/?k=v"


def test_missing_env_file_is_not_an_error(tmp_path: Path) -> None:
    assert load_env_file(tmp_path / "absent.env") is False


def test_bad_numbers_fall_back_to_defaults(isolated_env) -> None:
    isolated_env.setenv("CONTRACTMAP_DEPTH", "deep")
    assert Settings.from_env().limits.depth == 2


def _make_store(root: Path, versions: list[str]) -> None:
    for version in versions:
        directory = root / version
        directory.mkdir(parents=True, exist_ok=True)
        binary = directory / f"solc-{version}"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)


def test_finds_a_compiler_in_the_version_store(only_store_env: Path, tmp_path: Path) -> None:
    """Foundry's svm store is where `foundryup` puts compilers, so a machine that
    builds with Foundry does not need a second solc install."""

    _make_store(only_store_env, ["0.8.19", "0.8.24"])

    found = find_solc()
    assert found is not None
    assert Path(found).name == "solc-0.8.24"


def test_preferred_version_is_honoured(only_store_env: Path, tmp_path: Path) -> None:
    _make_store(only_store_env, ["0.8.19", "0.8.24", "0.8.26"])

    found = find_solc(prefer_version="0.8.24")
    assert found is not None
    assert Path(found).name == "solc-0.8.24"


def test_unknown_preferred_version_falls_back_to_the_newest(
    only_store_env: Path, tmp_path: Path
) -> None:
    _make_store(only_store_env, ["0.8.19", "0.8.24"])

    found = find_solc(prefer_version="0.7.6")
    assert found is not None
    assert Path(found).name == "solc-0.8.24"


def test_explicit_path_wins(only_store_env: Path, tmp_path: Path) -> None:
    binary = tmp_path / "my-solc"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    assert find_solc(str(binary)) == str(binary)


def test_missing_compiler_returns_none(only_store_env: Path, tmp_path: Path) -> None:
    assert find_solc() is None


def test_installed_versions_are_sorted(only_store_env: Path, tmp_path: Path) -> None:
    _make_store(only_store_env, ["0.8.26", "0.8.19", "0.8.24"])
    assert installed_versions() == ["0.8.19", "0.8.24", "0.8.26"]


def test_version_query_on_a_missing_binary_returns_none(tmp_path: Path) -> None:
    """A path that cannot be executed is reported, never raised."""

    assert solc_version(str(tmp_path / "absent-solc")) is None


def test_metadata_files_next_to_a_binary_are_ignored(only_store_env: Path, tmp_path: Path) -> None:
    _make_store(only_store_env, ["0.8.24"])
    (only_store_env / "0.8.24" / "solc-0.8.24.json").write_text("{}", encoding="utf-8")

    found = find_solc()
    assert found is not None
    assert found.endswith("solc-0.8.24")
    assert installed_versions() == ["0.8.24"]


def test_the_same_store_found_twice_is_collapsed(monkeypatch, tmp_path: Path) -> None:
    """`SVM_HOME` and `FOUNDRY_DIR` can point at overlapping stores; a compiler must
    not be listed twice."""

    store = tmp_path / "svm"
    _make_store(store, ["0.8.24"])
    monkeypatch.setenv("SVM_HOME", str(store))
    monkeypatch.setattr(solc_module, "_roots", lambda: [store, store])
    assert installed_versions() == ["0.8.24"]


def test_solc_module_reads_the_environment(monkeypatch, tmp_path: Path) -> None:
    store = tmp_path / "custom"
    _make_store(store, ["0.8.24"])
    monkeypatch.setenv("SVM_HOME", str(store))
    assert store in solc_module._roots()
