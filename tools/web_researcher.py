"""Thin compat shim — implementation lives in :mod:`tools.research`.

Split by responsibility (todo 06): ``tools/research/models.py``,
``providers.py``, ``facade.py``, ``text_utils.py``.
"""

from __future__ import annotations

from tools.research import (
    RESEARCH_API_KEY_MISSING as RESEARCH_API_KEY_MISSING,
)
from tools.research import (
    RESEARCH_DISABLED as RESEARCH_DISABLED,
)
from tools.research import (
    RESEARCH_FETCH_FAILED as RESEARCH_FETCH_FAILED,
)
from tools.research import (
    RESEARCH_PROVIDER_UNAVAILABLE as RESEARCH_PROVIDER_UNAVAILABLE,
)
from tools.research import (
    RESEARCH_SEARCH_FAILED as RESEARCH_SEARCH_FAILED,
)
from tools.research import (
    FetchResult as FetchResult,
)
from tools.research import (
    OllamaResearchProvider as OllamaResearchProvider,
)
from tools.research import (
    OllamaResearchSettings as OllamaResearchSettings,
)
from tools.research import (
    ResearchBrief as ResearchBrief,
)
from tools.research import (
    ResearchProvider as ResearchProvider,
)
from tools.research import (
    ResearchProviderError as ResearchProviderError,
)
from tools.research import (
    ResearchSource as ResearchSource,
)
from tools.research import (
    SearchResult as SearchResult,
)
from tools.research import (
    SerpAPIResearchProvider as SerpAPIResearchProvider,
)
from tools.research import (
    SerpAPIResearchSettings as SerpAPIResearchSettings,
)
from tools.research import (
    StdlibFetchProvider as StdlibFetchProvider,
)
from tools.research import (
    WebResearcher as WebResearcher,
)
from tools.research import (
    WebResearcherSettings as WebResearcherSettings,
)

__all__ = [
    "RESEARCH_API_KEY_MISSING",
    "RESEARCH_DISABLED",
    "RESEARCH_FETCH_FAILED",
    "RESEARCH_PROVIDER_UNAVAILABLE",
    "RESEARCH_SEARCH_FAILED",
    "FetchResult",
    "OllamaResearchProvider",
    "OllamaResearchSettings",
    "ResearchBrief",
    "ResearchProvider",
    "ResearchProviderError",
    "ResearchSource",
    "SearchResult",
    "SerpAPIResearchProvider",
    "SerpAPIResearchSettings",
    "StdlibFetchProvider",
    "WebResearcher",
    "WebResearcherSettings",
]
