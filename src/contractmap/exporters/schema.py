"""Published JSON Schema for analysis output."""

from __future__ import annotations

from typing import Any

from contractmap.diff import AnalysisDiff
from contractmap.models import AnalysisResult


def json_schema() -> dict[str, Any]:
    schema = AnalysisResult.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "contractmap analysis"
    return schema


def diff_schema() -> dict[str, Any]:
    return AnalysisDiff.model_json_schema()
