"""Standard storage slots and the on-chain view required to read them."""

from __future__ import annotations

from typing import Protocol

from contractmap.evm.hashing import address_from_word

# EIP-1967: keccak256("eip1967.proxy.implementation") - 1, and neighbours.
ERC1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ERC1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
ERC1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# EIP-1822 (UUPS) uses keccak256("PROXIABLE"); some UUPS deployments only set this.
EIP1822_PROXIABLE_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

# OpenZeppelin/zeppelinos proxy storage from pre-1967 releases.
ZEPPELINOS_IMPLEMENTATION_SLOT = (
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
)
ZEPPELINOS_ADMIN_SLOT = "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b"

IMPLEMENTATION_SLOTS: tuple[tuple[str, str], ...] = (
    (ERC1967_IMPLEMENTATION_SLOT, "EIP-1967 implementation slot"),
    (EIP1822_PROXIABLE_SLOT, "EIP-1822 PROXIABLE slot"),
    (ZEPPELINOS_IMPLEMENTATION_SLOT, "zeppelinos implementation slot"),
)
ADMIN_SLOTS: tuple[tuple[str, str], ...] = (
    (ERC1967_ADMIN_SLOT, "EIP-1967 admin slot"),
    (ZEPPELINOS_ADMIN_SLOT, "zeppelinos admin slot"),
)

BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"  # implementation()

DIAMOND_LOUPE_FACETS = "0x7a0ed627"
DIAMOND_LOUPE_FACET_ADDRESSES = "0x52ef6b2c"
DIAMOND_LOUPE_FACET_SELECTORS = "0xadfca15e"
DIAMOND_LOUPE_FACET_ADDRESS = "0xcdffacc6"
DIAMOND_CUT = "0x1f931c1c"


class ChainView(Protocol):
    """The chain reads proxy discovery needs. Implemented by the RPC client and by tests."""

    async def get_code(self, address: str, block: int | None = None) -> str: ...

    async def get_storage(self, address: str, slot: str, block: int | None = None) -> str: ...

    async def eth_call(self, to: str, data: str, block: int | None = None) -> str: ...


def slot_address(word: str) -> str | None:
    return address_from_word(word)
