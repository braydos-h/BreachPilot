"""Tests for the typed AttackGraph v2 model (enums, dataclasses, redaction, traversal).

Pure stdlib, no live network, no store dependency.
"""

from tools.intelligence.graph import (
    REDACTED_CRED_VALUE,
    CredentialRef,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphTraversal,
    GraphUpdate,
    NodeStatus,
    NodeType,
    redact_properties,
)

ALL_NODE_TYPES = [
    "ASSET",
    "HOST",
    "DOMAIN",
    "IP",
    "SERVICE",
    "PORT",
    "ENDPOINT",
    "APPLICATION",
    "TECHNOLOGY",
    "VERSION",
    "IDENTITY",
    "ROLE",
    "CREDENTIAL_REFERENCE",
    "TRUST_BOUNDARY",
    "NETWORK_SEGMENT",
    "VULNERABILITY_CANDIDATE",
    "FINDING",
    "HYPOTHESIS",
    "EVIDENCE",
    "CAPABILITY",
    "SECURITY_CONTROL",
    "OBSERVATION",
]

ALL_EDGE_TYPES = [
    "RESOLVES_TO",
    "HOSTS",
    "EXPOSES",
    "RUNS",
    "DEPENDS_ON",
    "REACHABLE_FROM",
    "AUTHENTICATES_TO",
    "HAS_ROLE",
    "TRUSTS",
    "RELATED_TO",
    "SUPPORTED_BY",
    "CONTRADICTED_BY",
    "DERIVED_FROM",
    "AFFECTED_BY",
    "PROTECTED_BY",
    "CONNECTED_TO",
    "SAME_AS",
    "OBSERVED_ON",
]

ALL_NODE_STATUSES = ["UNKNOWN", "SUSPECTED", "LIKELY", "CONFIRMED", "REFUTED", "EXHAUSTED"]


# -- enum membership ------------------------------------------------------------


def test_node_type_membership():
    for name in ALL_NODE_TYPES:
        assert hasattr(NodeType, name), f"missing NodeType.{name}"
    assert len(NodeType) == 22


def test_edge_type_membership():
    for name in ALL_EDGE_TYPES:
        assert hasattr(EdgeType, name), f"missing EdgeType.{name}"
    assert len(EdgeType) == 18


def test_node_status_membership():
    for name in ALL_NODE_STATUSES:
        assert hasattr(NodeStatus, name), f"missing NodeStatus.{name}"
    assert len(NodeStatus) == 6


def test_unknown_node_type_fallback():
    assert NodeType._unknown_fallback("garbage") is NodeType.OBSERVATION
    assert NodeType._unknown_fallback(123) is NodeType.OBSERVATION


# -- dataclass round trips -------------------------------------------------------


def _sample_node() -> GraphNode:
    return GraphNode(
        node_id="n1",
        node_type=NodeType.HOST,
        value="10.0.0.5",
        scope="run-1",
        properties={"os": "linux"},
        confidence=0.9,
        first_seen="t0",
        last_seen="t1",
        evidence_refs=("ev:nmap:10.0.0.5:abc123def456:t0",),
        observation_count=3,
        contradiction_count=1,
        status=NodeStatus.LIKELY,
        source="nmap",
    )


def _sample_edge() -> GraphEdge:
    return GraphEdge(
        edge_id="e-1",
        source_node_id="n-1",
        target_node_id="n-2",
        edge_type=EdgeType.HOSTS,
        scope="run-1",
        properties={"port": 80},
        confidence=0.8,
        source="nmap",
        evidence_refs=("ev:nmap:n-2:abcdef123456:t0",),
    )


def test_node_round_trip():
    node = _sample_node()
    rebuilt = GraphNode.from_dict(node.to_dict())
    assert rebuilt == node


def test_edge_round_trip():
    edge = _sample_edge()
    restored = GraphEdge.from_dict(edge.to_dict())
    assert restored == edge


def test_node_unknown_type_fallback_on_load():
    data = _sample_node().to_dict()
    data["node_type"] = "ancient_legacy_type"
    restored = GraphNode.from_dict(data)
    assert restored.node_type is NodeType.OBSERVATION


def test_edge_unknown_type_fallback_on_load():
    data = _sample_edge().to_dict()
    data["edge_type"] = "wormhole"
    restored = GraphEdge.from_dict(data)
    assert restored.edge_type is EdgeType.RELATED_TO


def test_node_missing_keys_get_defaults():
    restored = GraphNode.from_dict({"node_id": "x"})
    assert restored.node_type is NodeType.OBSERVATION
    assert restored.value == ""
    assert restored.status is NodeStatus.UNKNOWN
    assert restored.confidence == 0.5
    assert restored.evidence_refs == ()


def test_edge_missing_keys_get_defaults():
    restored = GraphEdge.from_dict({})
    assert restored.edge_id == ""
    assert restored.edge_type is EdgeType.RELATED_TO
    assert restored.scope == ""


def test_node_status_round_trip():
    data = _sample_node().to_dict()
    assert data["status"] == "likely"
    assert GraphNode.from_dict(data).status is NodeStatus.LIKELY


def test_graph_update_defaults():
    update = GraphUpdate(source_agent="correlation")
    assert update.node_updates == []
    assert update.edge_updates == []
    assert update.reason == ""
    assert update.timestamp == ""


def test_credential_ref_from_evidence():
    ref = CredentialRef.from_reference("ev:credential:store-42:abc123def456:t0")
    assert ref.value_ref == "store-42"
    assert CredentialRef.from_reference("plain").value_ref == "plain"


# -- redaction -------------------------------------------------------------------


def test_redact_properties_masks_credential_keys():
    props = {
        "user": "alice",
        "password": "hunter2",
        "api_secret": "shh",
        "session_token": "tok",
        "ssh_key": "k",
        "credential_value": "raw",
        "hostname": "target",
    }
    out = redact_properties(props)
    for key in ("password", "api_secret", "session_token", "ssh_key", "credential_value"):
        assert out[key] == REDACTED_CRED_VALUE, key
    assert out["user"] == "alice"
    assert out["hostname"] == "target"


def test_redact_properties_does_not_mutate_input():
    props = {"password": "hunter2"}
    redact_properties(props)
    assert props == {"password": "hunter2"}


def test_to_dict_redacts_embedded_credentials():
    node = GraphNode(
        node_id="n",
        node_type=NodeType.FINDING,
        value="x",
        scope="s",
        properties={"username": "alice", "password": "hunter2"},
    )
    serialized = node.to_dict()
    assert serialized["properties"]["password"] == REDACTED_CRED_VALUE
    assert serialized["properties"]["username"] == "alice"


# -- traversal helpers ------------------------------------------------------------


def _small_graph() -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes = [
        GraphNode(node_id="a", node_type=NodeType.HOST, value="a", scope="s1"),
        GraphNode(node_id="b", node_type=NodeType.SERVICE, value="b", scope="s1"),
        GraphNode(node_id="c", node_type=NodeType.SERVICE, value="c", scope="s1"),
        GraphNode(node_id="d", node_type=NodeType.HOST, value="d", scope="s1"),
        GraphNode(node_id="z", node_type=NodeType.HOST, value="z", scope="s2"),
    ]
    edges = [
        GraphEdge(edge_id="e1", source_node_id="a", target_node_id="b", edge_type=EdgeType.HOSTS, scope="s1"),
        GraphEdge(edge_id="e2", source_node_id="b", target_node_id="c", edge_type=EdgeType.DEPENDS_ON, scope="s1"),
        GraphEdge(edge_id="e3", source_node_id="c", target_node_id="d", edge_type=EdgeType.CONNECTED_TO, scope="s1"),
        GraphEdge(edge_id="e4", source_node_id="a", target_node_id="z", edge_type=EdgeType.RELATED_TO, scope="s1"),
    ]
    return nodes, edges


def test_neighbors_one_hop():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    result = trav.neighbors("a")
    assert [(n.node_id, e.edge_id, d) for n, e, d in result] == [("b", "e1", 1), ("z", "e4", 1)]


def test_neighbors_relation_filter():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    result = trav.neighbors("a", relation=EdgeType.DEPENDS_ON)
    assert result == []


def test_neighbors_max_hops():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    result = trav.neighbors("a", max_hops=3)
    assert {n.node_id for n, _, _ in result} == {"b", "z", "c", "d"}


def test_neighbors_bounded_by_max_nodes():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    result = trav.neighbors("a", max_hops=3, max_nodes=2)
    assert len(result) == 2


def test_neighbors_unknown_node():
    nodes, edges = _small_graph()
    assert GraphTraversal(nodes, edges).neighbors("missing") == []


def test_paths_found_and_deduped():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    found = trav.paths("a", "d")
    assert len(found) == 1
    assert [step[0].node_id for step in found[0]] == ["b", "c", "d"]


def test_paths_max_length_and_max_paths_bounds():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    assert trav.paths("a", "d", max_length=1) == []
    chain_nodes = [GraphNode(node_id=f"n{i}", node_type=NodeType.HOST, value="x", scope="s") for i in range(8)]
    chain_edges = [
        GraphEdge(
            edge_id=f"e{i}",
            source_node_id=f"n{i}",
            target_node_id=f"n{i + 1}",
            edge_type=EdgeType.CONNECTED_TO,
            scope="s",
        )
        for i in range(7)
    ]
    hub = GraphNode(node_id="hub", node_type=NodeType.HOST, value="x", scope="s")
    hub_edges = [
        GraphEdge(
            edge_id=f"h{i}", source_node_id=f"n{i}", target_node_id="hub", edge_type=EdgeType.CONNECTED_TO, scope="s"
        )
        for i in range(7)
    ]
    fork = GraphTraversal(chain_nodes + [hub], chain_edges + hub_edges)
    # default max_length=4 caps paths to 4 edges: n0->hub and via n1..n3
    assert len(fork.paths("n0", "hub")) == 4
    assert len(fork.paths("n0", "hub", max_length=8)) == 7
    assert len(fork.paths("n0", "hub", max_paths=3)) == 3


def test_path_exists():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    assert trav.path_exists("a", "d")
    assert not trav.path_exists("a", "d", max_hops=1)
    assert not trav.path_exists("z", "d")


def test_paths_deduplicate_nodes_within_a_path():
    cycle_nodes = [GraphNode(node_id=f"n{i}", node_type=NodeType.HOST, value="x", scope="s") for i in range(4)]
    cycle_edges = [
        GraphEdge(
            edge_id=f"e{i}",
            source_node_id=f"n{i}",
            target_node_id=f"n{(i + 1) % 4}",
            edge_type=EdgeType.CONNECTED_TO,
            scope="s",
        )
        for i in range(4)
    ]
    trav = GraphTraversal(cycle_nodes, cycle_edges)
    for path in trav.paths("n0", "n2", max_length=4):
        ids = [step[0].node_id for step in path]
        assert len(ids) == len(set(ids)), f"duplicate node in path: {ids}"


def test_subgraph_returns_induced_edges_and_boundary():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    included, internal, boundary = trav.subgraph(["a", "b"])
    assert {n.node_id for n in included} == {"a", "b"}
    assert [e.edge_id for e in internal] == ["e1"]
    assert {n.node_id for n, _ in boundary} == {"c", "z"}
    assert [e.edge_id for _, e in boundary] == ["e2", "e4"]


def test_subgraph_unknown_ids_skipped():
    nodes, edges = _small_graph()
    included, internal, boundary = GraphTraversal(nodes, edges).subgraph(["ghost"])
    assert included == []
    assert internal == []
    assert boundary == []


def test_nodes_of_type_with_scope():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    assert [n.node_id for n in trav.nodes_of_type(NodeType.HOST)] == ["a", "d", "z"]
    assert [n.node_id for n in trav.nodes_of_type(NodeType.HOST, scope="s1")] == ["a", "d"]
    assert trav.nodes_of_type(NodeType.HOST, scope="nope") == []


def test_edges_of_type_with_scope():
    nodes, edges = _small_graph()
    trav = GraphTraversal(nodes, edges)
    assert [e.edge_id for e in trav.edges_of_type(EdgeType.CONNECTED_TO)] == ["e3"]
    assert trav.edges_of_type(EdgeType.RESOLVES_TO) == []
    assert [e.edge_id for e in trav.edges_of_type(EdgeType.RELATED_TO, scope="s1")] == ["e4"]


def test_empty_graph_behavior():
    trav = GraphTraversal([], [])
    assert trav.neighbors("a") == []
    assert trav.paths("a", "b") == []
    assert not trav.path_exists("a", "b")
    assert trav.subgraph(["a"]) == ([], [], [])
    assert trav.nodes_of_type(NodeType.HOST) == []
    assert trav.edges_of_type(EdgeType.HOSTS) == []
