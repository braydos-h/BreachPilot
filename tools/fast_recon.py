"""Fast Recon coordinator — thin wrapper over :mod:`tools.recon.service`.

The orchestration (``FastReconCoordinator``), config/result bundles, shared
CVE-enrichment helpers, and disk cache now live in the unified
``ReconService`` module. This file re-exports them so existing imports
(``tools.run_service.tasks``, tests) keep working unchanged.
"""

from __future__ import annotations

from tools.recon.service import (
    FastReconConfig,
    FastReconCoordinator,
    FastReconResult,
    ReconService,
)
from tools.recon.service import (
    build_compact_summary as _build_compact_summary,
)
from tools.recon.service import (
    cve_query_from_banner as _cve_query_from_banner,
)
from tools.recon.service import (
    extract_tool_text as _extract_tool_text,
)
from tools.recon.service import (
    fast_cache_key as _cache_key,
)
from tools.recon.service import (
    fast_cache_path as _cache_path,
)
from tools.recon.service import (
    parse_os_result as _parse_os_result,
)
from tools.recon.service import (
    parse_scan_ports as _parse_scan_ports,
)
from tools.recon.service import (
    save_fast_cache as _save_cache,
)
from tools.recon.service import (
    try_load_fast_cache as _try_load_cache,
)

__all__ = [
    "FastReconConfig",
    "FastReconCoordinator",
    "FastReconResult",
    "ReconService",
    "_build_compact_summary",
    "_cache_key",
    "_cache_path",
    "_cve_query_from_banner",
    "_extract_tool_text",
    "_parse_os_result",
    "_parse_scan_ports",
    "_save_cache",
    "_try_load_cache",
]
