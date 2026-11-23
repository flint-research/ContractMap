"""EVM primitive tests: hashing, selectors, bytecode scanning, proxy templates."""

from __future__ import annotations

import json
from pathlib import Path

from contractmap.evm import abi, bytecode
from contractmap.evm.hashing import (
    address_from_word,
    checksum,
    is_address,
    is_hex_data,
    keccak_hex,
    selector,
    topic,
)
from contractmap.evm.storage import (
    ERC1967_ADMIN_SLOT,
    ERC1967_BEACON_SLOT,
    ERC1967_IMPLEMENTATION_SLOT,
    slot_address,
)


def test_erc1967_slots_match_the_specification() -> None:
    # EIP-1967 defines each slot as keccak256(name) - 1.
    assert hex(int(keccak_hex(b"eip1967.proxy.implementation"), 16) - 1) == (
        ERC1967_IMPLEMENTATION_SLOT
    )
    assert hex(int(keccak_hex(b"eip1967.proxy.admin"), 16) - 1) == ERC1967_ADMIN_SLOT
    assert hex(int(keccak_hex(b"eip1967.proxy.beacon"), 16) - 1) == ERC1967_BEACON_SLOT


def test_known_selectors() -> None:
    assert selector("transfer(address,uint256)") == "0xa9059cbb"
    assert selector("balanceOf(address)") == "0x70a08231"
    assert selector("owner()") == "0x8da5cb5b"
    assert selector("upgradeToAndCall(address,bytes)") == "0x4f1ef286"


def test_event_topic_matches_erc20_transfer() -> None:
    assert topic("Transfer(address,address,uint256)") == (
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_address_validation_rejects_short_and_non_hex() -> None:
    assert is_address("0x" + "ab" * 20)
    assert is_address("0x" + "AB" * 20)
    assert not is_address("0x" + "ab" * 19)
    assert not is_address("0x" + "zz" * 20)
    assert not is_address("ab" * 20)
    assert not is_address("")


def test_hex_data_requires_even_length() -> None:
    assert is_hex_data("0x")
    assert is_hex_data("0xdeadbeef")
    assert not is_hex_data("0xdeadbee")
    assert not is_hex_data("deadbeef")


def test_checksum_matches_eip55_vector() -> None:
    lower = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
    assert checksum(lower) == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def test_address_word_round_trip() -> None:
    address = "0x" + "12" * 20
    word = "0x" + abi.address_word(address)
    assert address_from_word(word) == address
    assert address_from_word("0x" + "00" * 32) is None
    # High bytes set means this is a uint256, not a left-padded address.
    assert address_from_word("0x" + "ff" * 12 + "11" * 20) is None
    assert slot_address(word) == address


def test_canonical_signature_handles_tuple_and_array() -> None:
    entry = {
        "name": "fill",
        "inputs": [
            {"type": "uint256"},
            {"type": "tuple[]", "components": [{"type": "address"}, {"type": "bytes"}]},
        ],
    }
    assert abi.canonical_signature(entry) == "fill(uint256,(address,bytes)[])"
    assert abi.entry_selector(entry) == selector("fill(uint256,(address,bytes)[])")


def test_entry_selector_ignores_non_functions() -> None:
    assert abi.entry_selector({"type": "event", "name": "Ping", "inputs": []}) is None
    assert abi.entry_selector({"type": "function", "name": "", "inputs": []}) is None


def test_decode_address_array_rejects_malformed_payloads() -> None:
    good = (
        "0x"
        + abi.uint_word(32)
        + abi.uint_word(2)
        + abi.address_word("0x" + "11" * 20)
        + abi.address_word("0x" + "22" * 20)
    )
    assert abi.decode_address_array(good) == ["0x" + "11" * 20, "0x" + "22" * 20]
    assert abi.decode_address_array("0x") is None
    assert abi.decode_address_array("0x" + abi.uint_word(32) + abi.uint_word(99)) is None


def test_decode_string_round_trip() -> None:
    encoded = "0x" + abi.uint_word(32) + abi.uint_word(5) + b"hello".hex().ljust(64, "0")
    assert abi.decode_string(encoded) == "hello"
    assert abi.decode_string("0x") is None


ERC1167_RUNTIME = "363d3d373d3d3d363d73" + "11" * 10 + "5af43d82803e903d91602b57fd5bf3"


def test_erc1167_template_detection() -> None:
    assert bytecode.is_minimal_proxy("0x" + ERC1167_RUNTIME)
    target = bytecode.minimal_proxy_target("0x" + ERC1167_RUNTIME)
    assert target is not None
    assert target.startswith("0x" + "11" * 10)
    assert not bytecode.is_minimal_proxy("0x6080604052")
    assert bytecode.minimal_proxy_target("0x6080604052") is None


def test_erc1167_template_rejects_zero_target() -> None:
    zeroed = "363d3d373d3d3d363d73" + "00" * 20 + "5af43d82803e903d91602b57fd5bf3"
    assert bytecode.is_minimal_proxy("0x" + zeroed)
    assert bytecode.minimal_proxy_target("0x" + zeroed) is None


def test_selector_extraction_uses_compare_pattern() -> None:
    # Strict pass requires the EQ comparison that follows a dispatched PUSH4.
    code = "0x" + "63" + "a9059cbb" + "14" + "00" + "63" + "70a08231" + "14" + "00"
    assert set(bytecode.extract_selectors(code)) == {"0xa9059cbb", "0x70a08231"}


def test_selector_extraction_records_the_push_offset() -> None:
    code = "0x" + "6001" + "63" + "a9059cbb" + "50"
    # Offsets are byte offsets into the runtime code: PUSH1 takes two bytes,
    # so the PUSH4 opcode sits at offset 2.
    assert bytecode.extract_selectors(code) == {"0xa9059cbb": 2}


def test_iter_instructions_skips_push_immediates() -> None:
    instructions = list(bytecode.iter_instructions("0x" + "7f" + "11" * 32 + "00"))
    assert [i.mnemonic for i in instructions] == ["PUSH32", "STOP"]
    assert instructions[0].push_data == bytes.fromhex("11" * 32)


def test_summarize_flags_risky_opcodes() -> None:
    summary = bytecode.summarize("0x" + "f4" + "ff" + "f0")
    assert summary.delegatecall
    assert summary.selfdestruct
    assert summary.create
    assert summary.size == 3


def test_non_contract_code_detection() -> None:
    assert not bytecode.is_contract_code("0x")
    assert not bytecode.is_contract_code("0x000000")
    assert bytecode.is_contract_code("0x6080")


def test_metadata_suffix_detection_on_compiler_output() -> None:
    path = (
        Path(__file__).parents[2]
        / "tests"
        / "fixtures"
        / "foundry"
        / "out"
        / "Vault.sol"
        / "Vault.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    # Foundry already prefixes the object, so it is used as-is.
    runtime = payload["deployedBytecode"]["object"]
    assert runtime.startswith("0x")
    assert bytecode.has_metadata_suffix(runtime)
    assert not bytecode.has_metadata_suffix("0x6080604052")


def test_code_hash_is_deterministic_and_address_independent() -> None:
    assert bytecode.code_hash("0x6080") == bytecode.code_hash("0x6080")
    assert bytecode.code_hash("0x6080") != bytecode.code_hash("0x6081")
