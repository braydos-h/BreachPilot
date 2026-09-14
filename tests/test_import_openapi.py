"""OpenAPI import into an operation graph (#24, slice 1)."""

from __future__ import annotations

import json

import pytest

from tools.importers.openapi import OperationGraph, load_openapi_file, parse_openapi

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Shop", "version": "1.0"},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {
        "/login": {
            "post": {
                "operationId": "login",
                "tags": ["auth"],
                "summary": "Get a token",
                "security": [],
                "parameters": [{"name": "username", "in": "query"}],
            }
        },
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {"operationId": "getUser", "tags": ["users"]},
            "delete": {"operationId": "deleteUser", "tags": ["users"]},
        },
    },
}


def test_parse_operations_with_auth_and_params():
    graph = parse_openapi(json.dumps(SPEC), source="test")
    assert isinstance(graph, OperationGraph)
    by_id = {o.operation_id: o for o in graph.operations}
    assert set(by_id) == {"login", "getUser", "deleteUser"}
    assert by_id["login"].requires_auth is False  # security: [] overrides global
    assert by_id["getUser"].requires_auth is True
    assert by_id["getUser"].auth_schemes == ("bearer",)
    assert by_id["getUser"].parameters == ("id",)


def test_graph_links_shared_tags_and_paths():
    graph = parse_openapi(json.dumps(SPEC))
    assert "deleteUser" in graph.edges["getUser"]  # shared tag + path
    assert "getUser" in graph.edges["deleteUser"]


def test_rejects_non_object_and_bad_version():
    with pytest.raises(ValueError):
        parse_openapi("[1, 2, 3]")
    with pytest.raises(ValueError):
        parse_openapi(json.dumps({"openapi": "4.0.0", "paths": {}}))


def test_local_ref_params_resolve():
    doc = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/a": {
                "get": {
                    "operationId": "a",
                    "parameters": [{"$ref": "#/components/parameters/Page"}],
                }
            }
        },
        "components": {"parameters": {"Page": {"name": "page", "in": "query"}}},
    }
    graph = parse_openapi(json.dumps(doc))
    assert graph.operations[0].parameters == ("page",)


def test_load_openapi_file(tmp_path):
    path = tmp_path / "api.json"
    path.write_text(json.dumps(SPEC), encoding="utf-8")
    graph = load_openapi_file(str(path))
    assert len(graph.operations) == 3
