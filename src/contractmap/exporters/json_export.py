"""Canonical JSON serialisation.

Output is deterministic: keys sorted, collections ordered by stable identity, and
``generated_at`` kept out of the canonical form used for digests.
"""

from __future__ import annotations

import json
from pathlib import Path

from contractmap.models import AnalysisResult


def to_json(result: AnalysisResult, *, indent: int = 2) -> str:
    payload = json.loads(result.sorted_copy().model_dump_json(exclude_none=False))
    return json.dumps(payload, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(result: AnalysisResult, path: Path, *, indent: int = 2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(result, indent=indent), encoding="utf-8")
    return path


def load_json(path: Path) -> AnalysisResult:
    return AnalysisResult.model_validate_json(path.read_text(encoding="utf-8"))
