"""Research package — canonical location for provider-backed web research.

Split from ``tools.web_researcher`` (todo 06) by responsibility:

  - ``models`` — SearchResult / FetchResult / ResearchSource / ResearchBrief,
    provider settings, error codes, ResearchProviderError.
  - ``providers`` — ResearchProvider base + Ollama / SerpAPI / stdlib-fetch.
  - ``facade`` — the WebResearcher search / fetch / deep-research facade.
  - ``text_utils`` — HTML extraction, URL validation, quality scoring.

``tools.web_researcher`` is a thin compat shim.
"""

from __future__ import annotations

from tools.research.facade import WebResearcher as WebResearcher
from tools.research.models import RESEARCH_API_KEY_MISSING as RESEARCH_API_KEY_MISSING
from tools.research.models import RESEARCH_DISABLED as RESEARCH_DISABLED
from tools.research.models import RESEARCH_FETCH_FAILED as RESEARCH_FETCH_FAILED
from tools.research.models import RESEARCH_PROVIDER_UNAVAILABLE as RESEARCH_PROVIDER_UNAVAILABLE
from tools.research.models import RESEARCH_SEARCH_FAILED as RESEARCH_SEARCH_FAILED
from tools.research.models import FetchResult as FetchResult
from tools.research.models import OllamaResearchSettings as OllamaResearchSettings
from tools.research.models import ResearchBrief as ResearchBrief
from tools.research.models import ResearchProviderError as ResearchProviderError
from tools.research.models import ResearchSource as ResearchSource
from tools.research.models import SearchResult as SearchResult
from tools.research.models import SerpAPIResearchSettings as SerpAPIResearchSettings
from tools.research.models import WebResearcherSettings as WebResearcherSettings
from tools.research.providers import OllamaResearchProvider as OllamaResearchProvider
from tools.research.providers import ResearchProvider as ResearchProvider
from tools.research.providers import SerpAPIResearchProvider as SerpAPIResearchProvider
from tools.research.providers import StdlibFetchProvider as StdlibFetchProvider

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
    "StdlibFetchProvider",
    "WebResearcher",
    "WebResearcherSettings",
]
