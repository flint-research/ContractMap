"""Locating a Solidity compiler.

Foundry downloads compilers into a per-user version store, so a machine that
already builds with Foundry does not need a second `solc` install. Nothing here
downloads anything: a missing compiler is reported to the caller, which turns it
into an actionable message.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

_VERSION_IN_NAME = re.compile(r"solc-?(\d+\.\d+\.\d+)")
_VERSION_TOKEN = re.compile(r"^(\d+\.\d+\.\d+)")


def find_solc(explicit: str | None = None, *, prefer_version: str | None = None) -> str | None:
    """Return a usable ``solc`` path, preferring ``prefer_version`` when given."""

    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate)
        return shutil.which(explicit)

    for name in ("solc", "solcjs"):
        found = shutil.which(name)
        if found:
            return found

    stored = _stored_compilers()
    if not stored:
        return None
    if prefer_version:
        wanted = prefer_version.split("+")[0].strip()
        for version, path in stored:
            if version == wanted:
                return str(path)
    return str(stored[-1][1])


def installed_versions() -> list[str]:
    return [version for version, _ in _stored_compilers()]


def _stored_compilers() -> list[tuple[str, Path]]:
    """Compiler binaries in the local version stores, oldest first."""

    found: list[tuple[tuple[int, ...], str, Path]] = []
    seen: set[Path] = set()
    for root in _roots():
        for path in _candidates_in(root):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            version = _version_of(path)
            if version is None:
                continue
            found.append((tuple(int(part) for part in version.split(".")), version, path))
    found.sort()
    return [(version, path) for _, version, path in found]


def _roots() -> list[Path]:
    """Version stores to search. Foundry's svm home differs per platform."""

    home = Path.home()
    roots: list[Path] = []
    override = os.environ.get("SVM_HOME")
    if override:
        roots.append(Path(override).expanduser())
    roots.append(home / ".svm")
    # Foundry's svm crate uses the OS data directory on Windows and macOS.
    for variable in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            roots.append(Path(base) / "svm")
    roots.append(home / "Library" / "Application Support" / "svm")
    roots.append(home / ".foundry" / "versions")
    foundry_dir = os.environ.get("FOUNDRY_DIR")
    if foundry_dir:
        roots.append(Path(foundry_dir).expanduser() / "versions")
    return [root for root in dict.fromkeys(roots) if root.is_dir()]


def _candidates_in(root: Path) -> list[Path]:
    """Version stores keep one binary per version directory: ``<root>/<ver>/solc-<ver>``."""

    found: list[Path] = []
    for pattern in ("solc*", "*/solc*", "*/*/solc*"):
        for path in root.glob(pattern):
            if path.is_file() and path.suffix.lower() not in {".json", ".txt", ".md", ".lock"}:
                found.append(path)
    return found


def _version_of(path: Path) -> str | None:
    for part in reversed(path.parts):
        match = _VERSION_IN_NAME.search(part) or _VERSION_TOKEN.match(part)
        if match:
            return match.group(1)
    return None


def solc_version(path: str) -> str | None:
    """Ask the binary. A wrapper that does not answer is not an error by itself."""

    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for token in proc.stdout.split():
        if token.startswith("0."):
            return token
    return None
