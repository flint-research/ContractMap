"""Keccak-256 and strict address/hex validation."""

from __future__ import annotations

import re

from Crypto.Hash import keccak

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")


def keccak256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def keccak_hex(data: bytes) -> str:
    return keccak256(data).hex()


def selector(signature: str) -> str:
    """First four bytes of keccak256 over the canonical signature, as ``0x``-hex."""

    return "0x" + keccak_hex(signature.encode())[:8]


def topic(signature: str) -> str:
    return "0x" + keccak_hex(signature.encode())


def is_address(value: str) -> bool:
    return bool(ADDRESS_RE.match(value))


def is_hex_data(value: str) -> bool:
    return bool(HEX_RE.match(value)) and len(value) % 2 == 0


def normalize_address(value: str) -> str:
    if not is_address(value):
        raise ValueError(f"invalid address: {value!r}")
    return value.lower()


def checksum(address: str) -> str:
    """EIP-55 mixed-case encoding."""

    if not is_address(address):
        raise ValueError(f"invalid address: {address!r}")
    body = address[2:].lower()
    digest = keccak_hex(body.encode())
    return "0x" + "".join(
        ch.upper() if ch.isalpha() and int(digest[i], 16) >= 8 else ch for i, ch in enumerate(body)
    )


def address_from_word(word: str) -> str | None:
    """Read the low 20 bytes of a 32-byte ABI word, rejecting non-address shapes."""

    cleaned = word[2:] if word.startswith("0x") else word
    if len(cleaned) != 64 or int(cleaned[:24], 16) != 0:
        return None
    candidate = "0x" + cleaned[24:].lower()
    return None if candidate == "0x" + "00" * 20 else candidate
