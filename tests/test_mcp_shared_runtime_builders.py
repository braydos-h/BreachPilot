from __future__ import annotations


def test_cve_builder_resolves_runtime_dependencies() -> None:
    from tools.cve_lookup import NVDClient
    from tools.mcp_shared import build_cve_search

    assert isinstance(build_cve_search({}), NVDClient)


def test_research_builder_resolves_runtime_dependencies() -> None:
    from tools.mcp_shared import build_researcher
    from tools.research.facade import WebResearcher

    assert isinstance(build_researcher({"research": {"enabled": False}}), WebResearcher)
