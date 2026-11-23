"""Bytecode-level analysis.

Solidity dispatchers compare selectors pushed with PUSH4, so selector extraction
is a bytecode scan rather than source parsing. Everything here operates on runtime
bytecode, which is what ``eth_getCode`` returns and what a fallback actually runs.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from contractmap.evm.hashing import keccak_hex

OP_SELFDESTRUCT = 0xFF
OP_CREATE = 0xF0
OP_CREATE2 = 0xF5

SELECTOR_STRICT_RE = re.compile(r"63([0-9a-f]{8})14")
SELECTOR_BROAD_RE = re.compile(r"63([0-9a-f]{8})")


@dataclass(slots=True)
class Instruction:
    offset: int
    opcode: int
    mnemonic: str
    push_data: bytes | None = None


MNEMONICS: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBBASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}
MNEMONICS.update({0x5F + i: f"PUSH{i}" for i in range(1, 33)})
MNEMONICS.update({0x7F + i: f"DUP{i}" for i in range(1, 17)})
MNEMONICS.update({0x8F + i: f"SWAP{i}" for i in range(1, 17)})
MNEMONICS.update({0xA0 + i: f"LOG{i}" for i in range(5)})


def strip_hex(code: str) -> str:
    return code[2:].lower() if code.startswith(("0x", "0X")) else code.lower()


def is_contract_code(code: str) -> bool:
    stripped = strip_hex(code)
    return bool(stripped) and set(stripped) != {"0"}


def code_hash(code: str) -> str:
    return "0x" + keccak_hex(bytes.fromhex(strip_hex(code)))


def iter_instructions(code: str) -> Iterator[Instruction]:
    """Linear sweep. PUSH immediates are consumed so data is not decoded as opcodes."""

    data = bytes.fromhex(strip_hex(code))
    pc = 0
    while pc < len(data):
        opcode = data[pc]
        if 0x60 <= opcode <= 0x7F:
            width = opcode - 0x5F
            payload = data[pc + 1 : pc + 1 + width]
            yield Instruction(pc, opcode, f"PUSH{width}", payload)
            pc += 1 + width
            continue
        yield Instruction(pc, opcode, MNEMONICS.get(opcode, f"UNKNOWN_{opcode:#04x}"))
        pc += 1


def extract_selectors(code: str) -> dict[str, int]:
    """Selector -> bytecode offset of the first dispatcher comparison.

    The strict ``PUSH4 <sel> EQ`` pattern excludes pushed constants and metadata in
    normal compiler output; the broad pattern is only a fallback for hand-written or
    optimiser-obscured dispatchers.
    """

    stripped = strip_hex(code)
    offsets: dict[str, int] = {}
    for match in SELECTOR_STRICT_RE.finditer(stripped):
        offsets.setdefault("0x" + match.group(1), match.start() // 2)
    if offsets:
        return dict(sorted(offsets.items()))
    for match in SELECTOR_BROAD_RE.finditer(stripped):
        offsets.setdefault("0x" + match.group(1), match.start() // 2)
    return dict(sorted(offsets.items()))


def call_opcodes(code: str) -> list[tuple[int, str]]:
    interesting = {"CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"}
    return [(i.offset, i.mnemonic) for i in iter_instructions(code) if i.mnemonic in interesting]


def has_opcode(code: str, opcode: int) -> bool:
    return any(i.opcode == opcode for i in iter_instructions(code))


def pushed_addresses(code: str) -> list[str]:
    """PUSH20 immediates. These are candidate constants, not proof of a call target."""

    return [
        "0x" + instruction.push_data.hex()
        for instruction in iter_instructions(code)
        if instruction.opcode == 0x73 and instruction.push_data and len(instruction.push_data) == 20
    ]


def has_metadata_suffix(code: str) -> bool:
    """Solidity appends CBOR metadata plus a two-byte big-endian length."""

    data = bytes.fromhex(strip_hex(code))
    if len(data) < 4:
        return False
    length = int.from_bytes(data[-2:], "big")
    if length <= 0 or length + 2 > len(data):
        return False
    marker = data[-2 - length : -2][:1]
    return marker in {b"\xa1", b"\xa2", b"\xa3", b"\xa4", b"\xa5"}


# 363d3d373d3d3d363d73<target>5af43d82803e903d91602b57fd5bf3
MINIMAL_PROXY_PREFIX = "363d3d373d3d3d363d73"
MINIMAL_PROXY_SUFFIXES = (
    "5af43d82803e903d91602b57fd5bf3",
    "5af43d3d93803e602a57fd5bf3",
    "5af43d82803e903d91602b57fd5bf300",
)


def is_minimal_proxy(code: str) -> bool:
    stripped = strip_hex(code)
    return stripped.startswith(MINIMAL_PROXY_PREFIX) and any(
        suffix in stripped for suffix in MINIMAL_PROXY_SUFFIXES
    )


def minimal_proxy_target(code: str) -> str | None:
    stripped = strip_hex(code)
    if not stripped.startswith(MINIMAL_PROXY_PREFIX):
        return None
    target = stripped[len(MINIMAL_PROXY_PREFIX) : len(MINIMAL_PROXY_PREFIX) + 40]
    if len(target) != 40 or int(target, 16) == 0:
        return None
    return "0x" + target


@dataclass(slots=True)
class BytecodeSummary:
    size: int
    selectors: dict[str, int] = field(default_factory=dict)
    calls: list[tuple[int, str]] = field(default_factory=list)
    delegatecall: bool = False
    selfdestruct: bool = False
    create: bool = False
    metadata: bool = False
    pushed_addresses: list[str] = field(default_factory=list)


def summarize(code: str) -> BytecodeSummary:
    calls = call_opcodes(code)
    return BytecodeSummary(
        size=len(strip_hex(code)) // 2,
        selectors=extract_selectors(code),
        calls=calls,
        delegatecall=any(name in {"DELEGATECALL", "CALLCODE"} for _, name in calls),
        selfdestruct=has_opcode(code, OP_SELFDESTRUCT),
        create=has_opcode(code, OP_CREATE) or has_opcode(code, OP_CREATE2),
        metadata=has_metadata_suffix(code),
        pushed_addresses=pushed_addresses(code),
    )
