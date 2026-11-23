"""Runtime configuration and environment handling."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT = 20.0
DEFAULT_CONCURRENCY = 4
DEFAULT_DEPTH = 2
DEFAULT_MAX_NODES = 400
DEFAULT_MAX_REQUESTS = 300
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

ENV_FILE_VARIABLE = "CONTRACTMAP_ENV_FILE"
DEFAULT_ENV_FILES = (".env", ".env.local")

_loaded_env_files: list[str] = []
# Values this process itself planted from a dotenv file. They are remembered so a
# later file (`.env.local`) may refine an earlier one (`.env`), while a value that
# came from the real environment is never overwritten.
_planted_values: dict[str, str] = {}


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    key, separator, value = stripped.partition("=")
    key = key.strip()
    if not separator or not key:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    else:
        value = value.split(" #", 1)[0].strip()
    return key, value


def load_env_file(path: Path) -> bool:
    """Read a dotenv file into ``os.environ``. Real environment variables win.

    Shell-provided values are never overwritten: a CI job or an explicit
    ``CONTRACTMAP_RPC_URL=...`` prefix must beat whatever is on disk. A *later*
    dotenv file may refine a value an earlier one supplied, so `.env.local` can
    override `.env`.
    """

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    loaded = False
    for line in content.splitlines():
        parsed = _parse_env_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if not value:
            # `KEY=` is a placeholder, not a value: `.env.example` is full of them,
            # and a copied-but-unfilled `.env` must not shadow a real one.
            continue
        current = os.environ.get(key)
        if current is not None and _planted_values.get(key) != current:
            # Set by the shell, not by us: leave it alone.
            continue
        if current == value:
            continue
        os.environ[key] = value
        _planted_values[key] = value
        loaded = True
    if loaded:
        _loaded_env_files.append(str(path))
    return loaded


def load_env_files(base: Path | None = None) -> list[str]:
    """Load the env files that exist. Returns the paths that were read.

    Files are read in order, so `./.env.local` can override `./.env`. The returned
    list covers this call only; a second call does not re-report earlier files.
    """

    start = len(_loaded_env_files)
    explicit = os.environ.get(ENV_FILE_VARIABLE)
    if explicit:
        load_env_file(Path(explicit).expanduser())
        return list(_loaded_env_files[start:])
    root = base or Path.cwd()
    for name in DEFAULT_ENV_FILES:
        candidate = root / name
        if candidate.is_file():
            load_env_file(candidate)
    return list(_loaded_env_files[start:])


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Limits:
    """Budgets that bound network cost and graph size."""

    depth: int = DEFAULT_DEPTH
    max_nodes: int = DEFAULT_MAX_NODES
    max_requests: int = DEFAULT_MAX_REQUESTS
    concurrency: int = DEFAULT_CONCURRENCY
    timeout: float = DEFAULT_TIMEOUT
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    retries: int = 3


@dataclass(slots=True)
class SourceConfig:
    sourcify: bool = True
    etherscan: bool = False
    sourcify_url: str = "https://sourcify.dev/server"
    etherscan_url: str = "https://api.etherscan.io/v2/api"
    etherscan_api_key: str | None = field(default=None, repr=False)

    def masked_key(self) -> str | None:
        if not self.etherscan_api_key:
            return None
        return self.etherscan_api_key[:4] + "…"


@dataclass(slots=True)
class Settings:
    rpc_url: str | None = field(default=None, repr=False)
    chain_id: int | None = None
    block: int | None = None
    limits: Limits = field(default_factory=Limits)
    sources: SourceConfig = field(default_factory=SourceConfig)
    allow_build: bool = False
    include_dependencies: bool = False
    solc_path: str | None = None
    verbose: bool = False

    @classmethod
    def from_env(cls, **overrides: object) -> Settings:
        load_env_files()
        sources = SourceConfig(
            sourcify=not _env_flag("CONTRACTMAP_NO_SOURCIFY"),
            etherscan=_env_flag("CONTRACTMAP_ETHERSCAN")
            or bool(os.environ.get("ETHERSCAN_API_KEY")),
            etherscan_api_key=os.environ.get("ETHERSCAN_API_KEY") or None,
            sourcify_url=os.environ.get("SOURCIFY_URL", "https://sourcify.dev/server"),
        )
        limits = Limits(
            depth=_env_int("CONTRACTMAP_DEPTH", DEFAULT_DEPTH),
            max_nodes=_env_int("CONTRACTMAP_MAX_NODES", DEFAULT_MAX_NODES),
            max_requests=_env_int("CONTRACTMAP_MAX_REQUESTS", DEFAULT_MAX_REQUESTS),
            concurrency=_env_int("CONTRACTMAP_CONCURRENCY", DEFAULT_CONCURRENCY),
        )
        base = cls(
            rpc_url=os.environ.get("CONTRACTMAP_RPC_URL") or os.environ.get("ETH_RPC_URL"),
            limits=limits,
            sources=sources,
        )
        for key, value in overrides.items():
            if value is None:
                continue
            if hasattr(base, key):
                setattr(base, key, value)
        return base

    def redacted_rpc(self) -> str | None:
        """RPC URL safe to print: provider API keys usually live in the path."""

        if not self.rpc_url:
            return None
        url = self.rpc_url
        if "://" in url:
            scheme, rest = url.split("://", 1)
            host, _, path = rest.partition("/")
            if path:
                return f"{scheme}://{host}/…"
            return f"{scheme}://{host}"
        return "…"
