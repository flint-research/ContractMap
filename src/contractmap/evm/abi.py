"""Minimal ABI helpers: canonical signatures, argument encoding, small decoders.

The scanner needs only the shapes a proxy or loupe interface returns, so this is
deliberately smaller than a general-purpose ABI library.
"""

from __future__ import annotations

from typing import Any

from contractmap.evm.hashing import selector

_tuple_component_cache: dict[str, str] = {}


def _canonical(param: dict[str, Any]) -> str:
    type_name = str(param.get("type", ""))
    if type_name.startswith("tuple"):
        inner = ",".join(_canonical(c) for c in param.get("components", []))
        return f"({inner}){type_name[len('tuple') :]}"
    return type_name


def canonical_type(param: dict[str, Any]) -> str:
    return _canonical(param)


def canonical_signature(entry: dict[str, Any]) -> str:
    inputs = ",".join(_canonical(p) for p in entry.get("inputs", []) or [])
    return f"{entry.get('name', '')}({inputs})"


def entry_selector(entry: dict[str, Any]) -> str | None:
    if entry.get("type") not in (None, "function"):
        return None
    name = entry.get("name")
    if not name:
        return None
    return selector(canonical_signature(entry))


def encode_call(function_selector: str, *words: str) -> str:
    body = "".join(words)
    return function_selector + body


def address_word(address: str) -> str:
    return address.lower()[2:].rjust(64, "0")


def uint_word(value: int) -> str:
    return format(value, "x").rjust(64, "0")


def _words(data: str) -> list[str]:
    body = data[2:] if data.startswith("0x") else data
    return [body[i : i + 64] for i in range(0, len(body) - len(body) % 64, 64)]


def decode_address_array(data: str) -> list[str] | None:
    """Decode ``address[]`` from an eth_call result, or None if the shape is wrong."""

    words = _words(data)
    if len(words) < 2:
        return None
    try:
        offset_words = int(words[0], 16) // 32
        length = int(words[offset_words], 16)
    except ValueError:
        return None
    if length < 0 or offset_words + 1 + length > len(words):
        return None
    result: list[str] = []
    for word in words[offset_words + 1 : offset_words + 1 + length]:
        if len(word) != 64 or int(word[:24], 16) != 0:
            return None
        result.append("0x" + word[24:].lower())
    return result


def decode_bytes4_array(data: str) -> list[str] | None:
    words = _words(data)
    if len(words) < 2:
        return None
    try:
        offset_words = int(words[0], 16) // 32
        length = int(words[offset_words], 16)
    except ValueError:
        return None
    if length < 0 or offset_words + 1 + length > len(words):
        return None
    return ["0x" + word[:8].lower() for word in words[offset_words + 1 : offset_words + 1 + length]]


def decode_address(data: str) -> str | None:
    words = _words(data)
    if not words or len(words[0]) != 64 or int(words[0][:24], 16) != 0:
        return None
    candidate = "0x" + words[0][24:].lower()
    return None if int(candidate, 16) == 0 else candidate


def decode_uint(data: str) -> int | None:
    words = _words(data)
    if not words:
        return None
    try:
        return int(words[0], 16)
    except ValueError:
        return None


def decode_string(data: str) -> str | None:
    words = _words(data)
    if len(words) < 2:
        return None
    try:
        offset_words = int(words[0], 16) // 32
        length = int(words[offset_words], 16)
    except ValueError:
        return None
    body = "".join(words[offset_words + 1 :])
    raw = body[: length * 2]
    if len(raw) != length * 2:
        return None
    try:
        return bytes.fromhex(raw).decode("utf-8")
    except UnicodeDecodeError:
        return None
