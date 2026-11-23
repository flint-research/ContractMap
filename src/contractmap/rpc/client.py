"""Read-only JSON-RPC access with budgets, caching and retry handling.

Only methods used by the scanner are exposed. Nothing here can mutate chain state;
there is no signing, sending, or key handling anywhere in the package.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import random
from dataclasses import dataclass, field
from typing import Any

import httpx

from contractmap.config import Limits
from contractmap.evm.hashing import is_address, is_hex_data


class RpcError(Exception):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class BudgetExceeded(RpcError):
    def __init__(self, budget: int) -> None:
        super().__init__(f"request budget of {budget} exceeded")
        self.budget = budget


class UnsupportedMethod(RpcError):
    """Provider does not implement the method; callers degrade instead of failing."""


@dataclass(slots=True)
class RpcStats:
    requests: int = 0
    retries: int = 0
    cache_hits: int = 0
    errors: int = 0
    budget_hits: int = 0


@dataclass(slots=True)
class RpcClient:
    url: str = field(repr=False)
    limits: Limits = field(default_factory=Limits)
    chain_id: int | None = None
    block: int | None = None
    stats: RpcStats = field(default_factory=RpcStats)
    _ids: itertools.count = field(default_factory=lambda: itertools.count(1), repr=False)
    _cache: dict[tuple[str, str], Any] = field(default_factory=dict, repr=False)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _sem: asyncio.Semaphore | None = field(default=None, repr=False)

    async def __aenter__(self) -> RpcClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.limits.timeout),
            limits=httpx.Limits(max_connections=self.limits.concurrency * 2),
            headers={"content-type": "application/json", "user-agent": "contractmap"},
            follow_redirects=False,
            trust_env=True,
        )
        self._sem = asyncio.Semaphore(self.limits.concurrency)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def remaining(self) -> int:
        return max(0, self.limits.max_requests - self.stats.requests)

    def pin_block(self, block: int | None) -> None:
        self.block = block
        self._cache.clear()

    def _block_param(self, block: int | None) -> str:
        resolved = block if block is not None else self.block
        if resolved is None:
            return "latest"
        return hex(resolved)

    async def _post(self, method: str, params: list[Any]) -> Any:
        assert self._client is not None, "RpcClient must be used as an async context manager"
        assert self._sem is not None
        if self.stats.requests >= self.limits.max_requests:
            self.stats.budget_hits += 1
            raise BudgetExceeded(self.limits.max_requests)
        payload = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params}
        delay = 0.35
        last_error: Exception | None = None
        for attempt in range(self.limits.retries + 1):
            if attempt:
                self.stats.retries += 1
                await asyncio.sleep(delay + random.random() * 0.15)
                delay = min(delay * 2, 8.0)
            async with self._sem:
                self.stats.requests += 1
                try:
                    response = await self._client.post(self.url, json=payload)
                except httpx.HTTPError as exc:
                    last_error = RpcError(f"transport failure: {type(exc).__name__}")
                    continue
            if response.status_code == 429 or response.status_code >= 500:
                last_error = RpcError(f"provider returned HTTP {response.status_code}")
                continue
            if response.status_code >= 400:
                self.stats.errors += 1
                raise RpcError(f"provider returned HTTP {response.status_code}")
            if len(response.content) > self.limits.max_response_bytes:
                raise RpcError("response exceeded the configured size limit")
            try:
                body = response.json()
            except json.JSONDecodeError:
                last_error = RpcError("provider returned malformed JSON")
                continue
            if not isinstance(body, dict):
                last_error = RpcError("provider returned an unexpected payload")
                continue
            error = body.get("error")
            if error:
                code = error.get("code") if isinstance(error, dict) else None
                message = str(error.get("message") if isinstance(error, dict) else error)[:300]
                if code in (-32601, -32004):
                    raise UnsupportedMethod(message, code=code)
                if code == -32005 or "rate limit" in message.lower():
                    last_error = RpcError(message, code=code)
                    continue
                self.stats.errors += 1
                raise RpcError(message, code=code if isinstance(code, int) else None)
            if "result" not in body:
                last_error = RpcError("provider response had no result")
                continue
            return body["result"]
        self.stats.errors += 1
        raise last_error or RpcError("request failed")

    async def cached(self, method: str, params: list[Any]) -> Any:
        """Cache only data pinned to a block; unpinned scans re-read chain state."""

        block_sensitive = self.block is not None or method in {
            "eth_chainId",
            "eth_getCode",
            "eth_getStorageAt",
        }
        key = (method, json.dumps(params, sort_keys=True))
        if block_sensitive and key in self._cache:
            self.stats.cache_hits += 1
            return self._cache[key]
        result = await self._post(method, params)
        if block_sensitive:
            self._cache[key] = result
        return result

    async def get_chain_id(self) -> int:
        result = await self.cached("eth_chainId", [])
        try:
            return int(str(result), 16)
        except (TypeError, ValueError) as exc:
            raise RpcError("eth_chainId returned a non-numeric value") from exc

    async def block_number(self) -> int:
        result = await self.cached("eth_blockNumber", [])
        try:
            return int(str(result), 16)
        except (TypeError, ValueError) as exc:
            raise RpcError("eth_blockNumber returned a non-numeric value") from exc

    async def get_block(self, block: int | None = None) -> dict[str, Any]:
        tag = hex(block) if block is not None else self._block_param(None)
        result = await self.cached("eth_getBlockByNumber", [tag, False])
        if not isinstance(result, dict):
            raise RpcError(f"block {tag} is not available from this provider")
        return result

    async def get_code(self, address: str, block: int | None = None) -> str:
        if not is_address(address):
            raise ValueError(f"invalid address: {address!r}")
        result = await self.cached("eth_getCode", [address.lower(), self._block_param(block)])
        if not isinstance(result, str) or not is_hex_data(result):
            raise RpcError(f"eth_getCode returned malformed data for {address}")
        return result

    async def get_storage(self, address: str, slot: str, block: int | None = None) -> str:
        if not is_address(address):
            raise ValueError(f"invalid address: {address!r}")
        if not slot.startswith("0x"):
            raise ValueError("storage slot must be a hex quantity")
        result = await self.cached(
            "eth_getStorageAt", [address.lower(), slot, self._block_param(block)]
        )
        if not isinstance(result, str) or not is_hex_data(result):
            raise RpcError("eth_getStorageAt returned malformed data")
        return result

    async def eth_call(self, to: str, data: str, block: int | None = None) -> str:
        if not is_address(to) or not is_hex_data(data):
            raise ValueError("eth_call requires a valid address and hex calldata")
        result = await self.cached(
            "eth_call", [{"to": to.lower(), "data": data}, self._block_param(block)]
        )
        if not isinstance(result, str) or not is_hex_data(result):
            raise RpcError("eth_call returned malformed data")
        return result

    async def get_balance(self, address: str, block: int | None = None) -> int:
        result = await self.cached("eth_getBalance", [address.lower(), self._block_param(block)])
        try:
            return int(str(result), 16)
        except (TypeError, ValueError) as exc:
            raise RpcError("eth_getBalance returned a non-numeric value") from exc
