"""Proxy discovery against a scripted chain, with no network access.

The fake view returns exactly what a provider would return for each storage slot or
eth_call, so the tests assert on classification and evidence rather than on mocks
being called.
"""

from __future__ import annotations

import json
from pathlib import Path

from contractmap.evm import abi
from contractmap.evm.storage import (
    DIAMOND_CUT,
    DIAMOND_LOUPE_FACET_ADDRESSES,
    DIAMOND_LOUPE_FACET_SELECTORS,
    ERC1967_ADMIN_SLOT,
    ERC1967_BEACON_SLOT,
    ERC1967_IMPLEMENTATION_SLOT,
)
from contractmap.models import ProxyKind, Resolution
from contractmap.proxies.detect import detect_proxy
from contractmap.rpc.client import RpcError

IMPLEMENTATION = "0x" + "aa" * 20
ADMIN = "0x" + "bb" * 20
BEACON = "0x" + "cc" * 20
FACET_A = "0x" + "d1" * 20
FACET_B = "0x" + "d2" * 20
ZERO_WORD = "0x" + "00" * 32


class FakeChain:
    """Minimal stand-in for :class:`contractmap.evm.storage.ChainView`."""

    def __init__(
        self,
        storage: dict[str, str] | None = None,
        calls: dict[str, str | Exception] | None = None,
        code: dict[str, str] | None = None,
    ) -> None:
        self.storage = storage or {}
        self.calls = calls or {}
        self.code = code or {}
        self.storage_reads: list[str] = []
        self.call_log: list[tuple[str, str]] = []

    async def get_code(self, address: str, block: int | None = None) -> str:
        return self.code.get(address.lower(), "0x")

    async def get_storage(self, address: str, slot: str, block: int | None = None) -> str:
        self.storage_reads.append(slot)
        return self.storage.get(slot.lower(), ZERO_WORD)

    async def eth_call(self, to: str, data: str, block: int | None = None) -> str:
        self.call_log.append((to.lower(), data))
        # Facet lookups reuse one selector with different arguments, so match the full
        # calldata first and only fall back to the bare selector.
        result = self.calls.get(data, self.calls.get(data[:10]))
        if isinstance(result, Exception):
            raise result
        return result if isinstance(result, str) else "0x"


def address_call_result(address: str) -> str:
    return "0x" + abi.address_word(address)


def address_array_result(addresses: list[str]) -> str:
    body = "0x" + abi.uint_word(32) + abi.uint_word(len(addresses))
    return body + "".join(abi.address_word(a) for a in addresses)


def bytes4_array_result(selectors: list[str]) -> str:
    body = "0x" + abi.uint_word(32) + abi.uint_word(len(selectors))
    return body + "".join(s[2:].ljust(64, "0") for s in selectors)


async def test_erc1967_implementation_is_confirmed_from_the_storage_slot() -> None:
    chain = FakeChain(storage={ERC1967_IMPLEMENTATION_SLOT: address_call_result(IMPLEMENTATION)})
    proxy = await detect_proxy(chain, "0x" + "01" * 20, "0x6080604052")

    assert proxy.kind == ProxyKind.ERC1967
    assert proxy.implementation == IMPLEMENTATION
    assert proxy.resolution == Resolution.CONFIRMED
    assert any("eip-1967" in e.detail.lower() for e in proxy.evidence)


async def test_erc1967_records_admin_when_present() -> None:
    chain = FakeChain(
        storage={
            ERC1967_IMPLEMENTATION_SLOT: address_call_result(IMPLEMENTATION),
            ERC1967_ADMIN_SLOT: address_call_result(ADMIN),
        }
    )
    proxy = await detect_proxy(chain, "0x" + "01" * 20, "0x6080604052")

    assert proxy.admin == ADMIN
    assert proxy.kind == ProxyKind.ERC1967


async def test_empty_slots_do_not_produce_a_proxy() -> None:
    proxy = await detect_proxy(FakeChain(), "0x" + "01" * 20, "0x6080604052")

    assert proxy.kind == ProxyKind.UNKNOWN
    assert proxy.implementation is None
    assert proxy.resolution == Resolution.UNRESOLVED


async def test_rpc_error_on_storage_degrades_instead_of_raising() -> None:
    class Broken(FakeChain):
        async def get_storage(self, address: str, slot: str, block: int | None = None) -> str:
            raise RpcError("provider refused")

    proxy = await detect_proxy(Broken(), "0x" + "01" * 20, "0x6080604052")
    assert proxy.kind == ProxyKind.UNKNOWN


async def test_erc1167_is_detected_from_bytecode_without_any_rpc_call() -> None:
    runtime = "0x363d3d373d3d3d363d73" + IMPLEMENTATION[2:] + "5af43d82803e903d91602b57fd5bf3"
    chain = FakeChain()
    proxy = await detect_proxy(chain, "0x" + "01" * 20, runtime)

    assert proxy.kind == ProxyKind.ERC1167
    assert proxy.implementation is not None
    assert proxy.implementation.startswith(IMPLEMENTATION)
    assert proxy.resolution == Resolution.CONFIRMED
    assert chain.storage_reads == [], "ERC-1167 must not read storage slots"


async def test_beacon_proxy_resolves_implementation_through_the_beacon() -> None:
    chain = FakeChain(
        storage={ERC1967_BEACON_SLOT: address_call_result(BEACON)},
        calls={"0x5c60da1b": address_call_result(IMPLEMENTATION)},
    )
    proxy = await detect_proxy(chain, "0x" + "01" * 20, "0x6080604052")

    assert proxy.kind == ProxyKind.ERC1967_BEACON
    assert proxy.beacon == BEACON
    assert proxy.implementation == IMPLEMENTATION
    assert proxy.resolution == Resolution.CONFIRMED
    assert ("0x" + "01" * 20, "0x5c60da1b") not in chain.call_log
    assert (BEACON, "0x5c60da1b") in chain.call_log


async def test_beacon_without_a_working_getter_stays_unresolved() -> None:
    chain = FakeChain(
        storage={ERC1967_BEACON_SLOT: address_call_result(BEACON)},
        calls={"0x5c60da1b": RpcError("execution reverted")},
    )
    proxy = await detect_proxy(chain, "0x" + "01" * 20, "0x6080604052")

    assert proxy.kind == ProxyKind.ERC1967_BEACON
    assert proxy.beacon == BEACON
    assert proxy.implementation is None
    assert proxy.resolution == Resolution.INFERRED
    assert any("did not return" in e.detail for e in proxy.evidence)


async def test_diamond_maps_selectors_to_facets_through_the_loupe() -> None:
    chain = FakeChain(
        calls={
            DIAMOND_LOUPE_FACET_ADDRESSES: address_array_result([FACET_A, FACET_B]),
            DIAMOND_LOUPE_FACET_SELECTORS + abi.address_word(FACET_A): bytes4_array_result(
                ["0xaaaaaaaa", "0xbbbbbbbb"]
            ),
            DIAMOND_LOUPE_FACET_SELECTORS + abi.address_word(FACET_B): bytes4_array_result(
                ["0xcccccccc"]
            ),
        }
    )
    runtime = "0x" + "63" + DIAMOND_CUT[2:] + "50"
    proxy = await detect_proxy(chain, "0x" + "01" * 20, runtime)

    assert proxy.kind == ProxyKind.DIAMOND
    assert proxy.facets == {
        "0xaaaaaaaa": FACET_A,
        "0xbbbbbbbb": FACET_A,
        "0xcccccccc": FACET_B,
    }
    assert proxy.resolution == Resolution.CONFIRMED


async def test_diamond_cut_selector_without_a_loupe_stays_unresolved() -> None:
    chain = FakeChain(calls={DIAMOND_LOUPE_FACET_ADDRESSES: RpcError("execution reverted")})
    runtime = "0x" + "63" + DIAMOND_CUT[2:] + "50"
    proxy = await detect_proxy(chain, "0x" + "01" * 20, runtime)

    assert proxy.kind == ProxyKind.DIAMOND
    assert proxy.facets == {}
    assert proxy.resolution == Resolution.UNRESOLVED


async def test_diamond_cut_absent_means_not_a_diamond() -> None:
    proxy = await detect_proxy(FakeChain(), "0x" + "01" * 20, "0x6080604052")
    assert proxy.kind == ProxyKind.UNKNOWN


async def test_partial_facet_failure_marks_the_diamond_unresolved() -> None:
    chain = FakeChain(
        calls={
            DIAMOND_LOUPE_FACET_ADDRESSES: address_array_result([FACET_A, FACET_B]),
            DIAMOND_LOUPE_FACET_SELECTORS + abi.address_word(FACET_A): bytes4_array_result(
                ["0xaaaaaaaa"]
            ),
            DIAMOND_LOUPE_FACET_SELECTORS + abi.address_word(FACET_B): RpcError("reverted"),
        }
    )
    runtime = "0x" + "63" + DIAMOND_CUT[2:] + "50"
    proxy = await detect_proxy(chain, "0x" + "01" * 20, runtime)

    assert proxy.facets == {"0xaaaaaaaa": FACET_A}
    assert proxy.resolution == Resolution.UNRESOLVED


async def test_unrelated_bytecode_with_no_slots_is_never_labelled_a_proxy() -> None:
    # Real Vault runtime code: has a dispatcher, no proxy slots, no diamondCut.
    path = Path(__file__).parents[1] / "fixtures" / "foundry" / "out" / "Vault.sol" / "Vault.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    runtime = payload["deployedBytecode"]["object"]

    proxy = await detect_proxy(FakeChain(), "0x" + "01" * 20, runtime)
    assert proxy.kind == ProxyKind.UNKNOWN
