"""ContractMap public API.

The analysis pipeline is synchronous at the top level and returns a fully
resolved :class:`AnalysisResult`. Rendering lives in ``contractmap.exporters``
and is never a dependency of the analysis engine.
"""

from typing import TYPE_CHECKING, Any

from contractmap.models import SCHEMA_VERSION, AnalysisResult

if TYPE_CHECKING:
    from contractmap.scanner.local import scan_local
    from contractmap.scanner.remote import scan_address

__version__ = "1.0.0"

__all__ = ["SCHEMA_VERSION", "AnalysisResult", "__version__", "scan_address", "scan_local"]


def __getattr__(name: str) -> Any:
    if name == "scan_local":
        from contractmap.scanner.local import scan_local

        return scan_local
    if name == "scan_address":
        from contractmap.scanner.remote import scan_address

        return scan_address
    raise AttributeError(name)
