"""Address scans against a scripted JSON-RPC endpoint. No network, no Sourcify."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from contractmap.config import Limits, Settings
from contractmap.models import AccessRestriction, ProxyKind, Resolution
from contractmap.rpc.client import BudgetExceeded, RpcClient, RpcError
from contractmap.scanner.remote import scan_address

ROOT = "0x" + "11" * 20
IMPLEMENTATION = "0x" + "22" * 20
OWNER = "0x" + "33" * 20

ERC1967_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# Ordinary runtime code containing one dispatcher comparison (PUSH4 <sel> EQ), so
# extraction finds a selector without the bytecode resembling a minimal proxy.
RUNTIME_CODE = (
    "0x6080604052348015600f57600080fd5b506004361060285760003560e01c80638da5cb5b14602d575b600080fd"
)


class ScriptedRpc:
    """Answers the methods a scan uses, and records what was asked for."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[Any]]] = []

    def handle(self, method: str, params: list[Any]) -> Any:
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(1)
        if method == "eth_blockNumber":
            return hex(0x1000)
        if method == "eth_getBlockByNumber":
            return {"number": hex(0x1000), "hash": "0x" + "ab" * 32}
        if method == "eth_getCode":
            address = str(params[0]).lower()
            return RUNTIME_CODE if address in {ROOT, IMPLEMENTATION} else "0x"
        if method == "eth_getStorageAt":
            slot = str(params[1]).lower()
            if str(params[0]).lower() == ROOT and slot == ERC1967_SLOT:
                return "0x" + "00" * 12 + IMPLEMENTATION[2:]
            return "0x" + "00" * 32
        if method == "eth_call":
            data = str(params[0].get("data", ""))
            if data.startswith("0x8da5cb5b"):  # owner()
                return "0x" + "00" * 12 + OWNER[2:]
            # A getter the contract does not implement reverts, which is what a
            # provider reports as an error.
            raise RpcError("execution reverted", code=3)
        if method == "eth_getBalance":
            return "0x0"
        raise AssertionError(f"unexpected method {method}")


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch) -> ScriptedRpc:
    rpc = ScriptedRpc()

    async def post(self: RpcClient, method: str, params: list[Any]) -> Any:
        self.stats.requests += 1
        return rpc.handle(method, params)

    monkeypatch.setattr(RpcClient, "_post", post)
    return rpc


def _settings(**overrides: object) -> Settings:
    settings = Settings(
        rpc_url="http://scripted.invalid",
        limits=Limits(max_requests=200),
        **overrides,  # type: ignore[arg-type]
    )
    settings.sources.sourcify = False
    settings.sources.etherscan = False
    return settings


async def test_address_scan_resolves_the_proxy(scripted: ScriptedRpc) -> None:
    result = await scan_address(ROOT, _settings())
    root_contract = next(c for c in result.contracts if (c.address or "").lower() == ROOT)
    assert root_contract.is_proxy
    assert root_contract.proxy is not None
    assert root_contract.proxy.kind is ProxyKind.ERC1967
    assert (root_contract.proxy.implementation or "").lower() == IMPLEMENTATION
    assert root_contract.proxy.resolution is Resolution.CONFIRMED


async def test_scan_pins_every_read_to_one_block(scripted: ScriptedRpc) -> None:
    result = await scan_address(ROOT, _settings())
    assert result.chain.block_number == 0x1000
    assert result.chain.block_hash == "0x" + "ab" * 32

    block_params = [
        params[-1]
        for method, params in scripted.calls
        if method in {"eth_getCode", "eth_getStorageAt", "eth_call"} and params
    ]
    # eth_call passes [tx, block]; the others pass [arg, block].
    assert block_params
    assert set(block_params) == {hex(0x1000)}


async def test_privileged_account_is_recorded(scripted: ScriptedRpc) -> None:
    result = await scan_address(ROOT, _settings())
    controlled = {edge.target for edge in result.edges if edge.kind.value == "controlled_by"}
    assert any(OWNER.replace("0x", "") in target.replace("0x", "") for target in controlled)


async def test_unverified_contract_reports_unresolved_access(scripted: ScriptedRpc) -> None:
    """Without source, entry points come from the dispatcher and authorization is
    explicitly unresolved rather than assumed open."""

    result = await scan_address(ROOT, _settings())
    root_contract = next(c for c in result.contracts if (c.address or "").lower() == ROOT)
    assert root_contract.source_kind.value == "deployed_bytecode"
    assert root_contract.verified is False
    functions = [f for f in result.functions if f.contract_id == root_contract.id]
    assert functions
    assert all(f.access.restriction is AccessRestriction.UNRESOLVED for f in functions)


async def test_chain_id_mismatch_is_refused(scripted: ScriptedRpc) -> None:
    with pytest.raises(Exception) as excinfo:
        await scan_address(ROOT, _settings(), chain_id=137)
    assert "chain" in str(excinfo.value).lower()


async def test_an_address_without_code_is_reported(scripted: ScriptedRpc) -> None:
    empty = "0x" + "99" * 20
    result = await scan_address(empty, _settings())
    assert any(item.code == "no_code" for item in result.warnings)


async def test_request_budget_is_enforced_before_any_request() -> None:
    """The budget is checked before a request is issued, so a runaway scan stops
    without touching the network. A zero budget fails on the first call."""

    client = RpcClient(url="http://scripted.invalid", limits=Limits(max_requests=0))
    async with client:
        with pytest.raises(BudgetExceeded):
            await client.get_chain_id()


async def test_chain_id_is_read_once(scripted: ScriptedRpc) -> None:
    await scan_address(ROOT, _settings())
    assert len([call for call in scripted.calls if call[0] == "eth_chainId"]) == 1


async def test_proxy_edge_reaches_the_scanned_implementation(scripted: ScriptedRpc) -> None:
    """The implementation is scanned, so the proxy must point at that node, not a stub."""

    result = await scan_address(ROOT, _settings())
    edge = next(e for e in result.edges if e.kind.value == "proxies_to")
    target = next(n for n in result.nodes if n.id == edge.target)
    assert target.contract_id is not None
    contracts = [n for n in result.nodes if n.address == IMPLEMENTATION and n.kind != "function"]
    assert len(contracts) == 1


async def test_warnings_are_reported_once(scripted: ScriptedRpc) -> None:
    result = await scan_address("0x" + "99" * 20, _settings())
    keys = [(w.code, w.subject) for w in result.warnings]
    assert len(keys) == len(set(keys))


async def test_running_out_of_requests_is_a_partial_analysis() -> None:
    """Runs the real client over a mocked transport, so the budget check is the real one."""

    rpc = ScriptedRpc()

    def reply(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        try:
            result = {"result": rpc.handle(body["method"], body["params"])}
        except RpcError as exc:
            result = {"error": {"code": exc.code, "message": str(exc)}}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], **result})

    settings = _settings()
    settings.limits.max_requests = 6
    with respx.mock:
        respx.post("http://scripted.invalid").mock(side_effect=reply)
        result = await scan_address(ROOT, settings)
    assert result.metadata.analysis_complete is False
    assert any(w.code == "request_budget" for w in result.warnings)
