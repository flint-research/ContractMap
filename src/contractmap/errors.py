"""Errors surfaced by the CLI with explicit exit codes."""

from __future__ import annotations


class ContractMapError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 3


class InputError(ContractMapError):
    """Invalid target, malformed file, or unusable argument."""

    exit_code = 2


class OperationalError(ContractMapError):
    """Network, compiler or provider failure that stopped the analysis."""

    exit_code = 3
