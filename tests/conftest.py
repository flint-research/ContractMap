"""Shared fixtures: analysis results from the checked-in Foundry project."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from contractmap.config import Settings
from contractmap.models import AnalysisResult
from contractmap.scanner.local import scan_local
from contractmap.sources.solc import find_solc

FIXTURES = Path(__file__).parent / "fixtures"
FOUNDRY_PROJECT = FIXTURES / "foundry"
SOURCE_PROJECT = FIXTURES / "project"


@pytest.fixture(scope="session")
def foundry_result() -> AnalysisResult:
    return scan_local(FOUNDRY_PROJECT, Settings())


@pytest.fixture(scope="session")
def source_result() -> AnalysisResult:
    """The same contracts compiled from source, so the AST path is exercised."""

    if find_solc() is None:
        pytest.skip("needs a solc binary to compile the source fixture")
    return scan_local(SOURCE_PROJECT, Settings(allow_build=True))


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """Isolate ``CONTRACTMAP_*`` and provider variables from the host machine."""

    for name in (
        "CONTRACTMAP_RPC_URL",
        "CONTRACTMAP_DEPTH",
        "CONTRACTMAP_MAX_NODES",
        "CONTRACTMAP_MAX_REQUESTS",
        "CONTRACTMAP_CONCURRENCY",
        "CONTRACTMAP_ENV_FILE",
        "CONTRACTMAP_NO_SOURCIFY",
        "CONTRACTMAP_ETHERSCAN",
        "ETH_RPC_URL",
        "ETHERSCAN_API_KEY",
        "SOURCIFY_URL",
        "SVM_HOME",
        "FOUNDRY_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    yield monkeypatch
