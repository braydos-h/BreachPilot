"""Concurrency + correctness tests for the swarm ``Blackboard``.

These directly exercise the 5 hazards named in the ``route_parallel`` warning
(``tools/swarm/orchestrator.py``):

1. List read-modify-write races — ``append_to`` / ``extend_list`` are atomic.
2. Per-target namespacing — parallel recon on N hosts keeps all N service
   lists, last-writer-no-longer-wins.
3. Scalar overwrite / first-write-wins semantics.
4. Snapshot / merge round-trip (resume).
5. Backward-compat: a plain ``{}`` blackboard still works through
   ``bb_compat`` so legacy direct callers (tests that construct an agent
   with ``context={"blackboard": {}}``) don't break.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tools.swarm.blackboard import Blackboard
from tools.swarm.bb_compat import bb_set, bb_append, bb_extend, bb_remove


# ── Atomic list ops ───────────────────────────────────────────────────────


def test_append_to_is_atomic_under_concurrency():
    """N threads each append 1000 items to the same list key; the result must
    contain exactly N*1000 items (no lost appends). The old plain-dict
    ``bb[k] = bb.get(k, []) + [x]`` would lose most of them under this race.
    """
    bb = Blackboard()
    N_THREADS = 8
    N_PER_THREAD = 1000

    def worker(tid: int) -> None:
        for i in range(N_PER_THREAD):
            bb.append_to("compromised_hosts", f"host-{tid}-{i}")

    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        list(ex.map(worker, range(N_THREADS)))

    assert len(bb.get("compromised_hosts")) == N_THREADS * N_PER_THREAD


def test_extend_list_is_atomic_under_concurrency():
    """Same race as above but via extend_list (the dedupe path)."""
    bb = Blackboard()
    N_THREADS = 8
    N_PER_BATCH = 500

    def worker(tid: int) -> None:
        bb.extend_list("credentials_found", [f"cred-{tid}-{i}" for i in range(N_PER_BATCH)])

    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        list(ex.map(worker, range(N_THREADS)))

    assert len(bb.get("credentials_found")) == N_THREADS * N_PER_BATCH


def test_extend_list_dedupe_preserves_order_and_dedupes():
    bb = Blackboard()
    bb.extend_list("loot", ["a", "b", "c"])
    bb.extend_list("loot", ["b", "d", "a"])  # b and a already present
    assert bb.get("loot") == ["a", "b", "c", "d"]


def test_extend_list_no_dedupe_allows_duplicates():
    bb = Blackboard()
    bb.extend_list("events", ["x", "y"], dedupe=False)
    bb.extend_list("events", ["x", "z"], dedupe=False)
    assert bb.get("events") == ["x", "y", "x", "z"]


def test_remove_from_list_is_atomic():
    bb = Blackboard()
    bb.extend_list("failed_modules", ["a", "b", "c", "d", "e"])

    def remove_one(item: str) -> None:
        bb.remove_from_list("failed_modules", item)

    with ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(remove_one, ["a", "b", "c", "d", "e"]))

    assert bb.get("failed_modules") == []


# ── Per-target namespacing ────────────────────────────────────────────────


def test_per_target_namespacing_isolates_findings():
    """The cross-target-race hazard: parallel recon on 3 hosts must keep all 3
    service lists. With a namespaced write, each host's discovered_services
    lands in its own bucket; the global bucket stays empty for that key.
    """
    bb = Blackboard()

    def recon_host(ip: str) -> None:
        bb.set_scalar("discovered_services", [{"service": "ssh", "target": ip}], target=ip)
        bb.set_scalar("recon_complete", True, target=ip)

    hosts = ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    with ThreadPoolExecutor(max_workers=3) as ex:
        list(ex.map(recon_host, hosts))

    # Each target has its own services (last-writer-no-longer-wins).
    for ip in hosts:
        svc = bb.get("discovered_services", target=ip)
        assert len(svc) == 1
        assert svc[0]["target"] == ip
        assert bb.get("recon_complete", target=ip) is True

    # The global bucket was NOT touched by the namespaced writes. Neither key
    # exists in the global bucket, so get returns the default (None) —
    # confirming the namespaced writes did not leak into the global view.
    assert bb.get("discovered_services") is None
    assert bb.get("recon_complete") is None
    assert set(bb.targets()) == set(hosts)


def test_global_and_target_scopes_are_independent():
    bb = Blackboard()
    bb.set_scalar("access_achieved", True)  # global milestone
    bb.set_scalar("discovered_services", [{"port": 22}], target="10.0.0.5")
    bb.append_to("compromised_hosts", "10.0.0.5")  # global list

    assert bb.get("access_achieved") is True
    assert bb.get("access_achieved", target="10.0.0.5") is None  # not set in target scope
    assert bb.get("compromised_hosts") == ["10.0.0.5"]


def test_get_target_returns_copy():
    bb = Blackboard()
    bb.set_scalar("recon_complete", True, target="10.0.0.5")
    snap = bb.get_target("10.0.0.5")
    snap["recon_complete"] = False  # mutate the copy
    assert bb.get("recon_complete", target="10.0.0.5") is True  # original unchanged


def test_set_target_merges_scalars_and_lists():
    bb = Blackboard()
    bb.set_target("10.0.0.5", {"recon_complete": True, "discovered_services": [{"port": 22}]})
    bb.set_target("10.0.0.5", {"recon_complete": False, "discovered_services": [{"port": 80}]})

    # Scalar overwrites, list extends (dedupe).
    assert bb.get("recon_complete", target="10.0.0.5") is False
    assert bb.get("discovered_services", target="10.0.0.5") == [{"port": 22}, {"port": 80}]


# ── Scalar overwrite / first-write-wins ──────────────────────────────────


def test_set_scalar_overwrites():
    bb = Blackboard({"access_achieved": False})
    bb.set_scalar("access_achieved", True)
    assert bb.get("access_achieved") is True
    bb.set_scalar("access_achieved", False)
    assert bb.get("access_achieved") is False


def test_dict_subclass_setitem_routes_to_set_scalar():
    """Bare ``bb[k] = v`` (legacy write site we might have missed) must still
    hit the global bucket atomically via ``__setitem__`` → ``set_scalar``."""
    bb = Blackboard()
    bb["strategy_shift"] = "PIVOT"
    assert bb.get("strategy_shift") == "PIVOT"
    assert "strategy_shift" in bb


def test_dict_subclass_getitem_reads_global_bucket():
    bb = Blackboard({"k": "v"})
    assert bb["k"] == "v"
    # A namespaced write does NOT pollute the global read.
    bb.set_scalar("k", "target-val", target="10.0.0.5")
    assert bb["k"] == "v"  # global still "v"
    assert bb.get("k", target="10.0.0.5") == "target-val"


# ── Snapshot / merge (resume) ─────────────────────────────────────────────


def test_snapshot_merge_round_trip():
    bb = Blackboard()
    bb.set_scalar("recon_complete", True)
    bb.extend_list("compromised_hosts", ["10.0.0.5"])
    bb.set_scalar("discovered_services", [{"port": 22}], target="10.0.0.5")
    bb.set_scalar("recon_complete", True, target="10.0.0.5")

    snap = bb.snapshot()
    assert "__global__" in snap
    assert "10.0.0.5" in snap

    bb2 = Blackboard()
    bb2.merge_snapshot(snap)
    assert bb2.get("recon_complete") is True
    assert bb2.get("compromised_hosts") == ["10.0.0.5"]
    assert bb2.get("recon_complete", target="10.0.0.5") is True
    assert bb2.get("discovered_services", target="10.0.0.5") == [{"port": 22}]


def test_merge_snapshot_extends_lists_not_replaces():
    """Resume semantics: a resumed run's new findings append to the prior
    run's, with dedupe."""
    bb = Blackboard()
    bb.extend_list("credentials_found", ["cred-1", "cred-2"])
    snap = bb.snapshot()

    bb2 = Blackboard()
    bb2.extend_list("credentials_found", ["cred-2", "cred-3"])  # cred-2 dup
    bb2.merge_snapshot(snap)
    # cred-2 already present, so only cred-1 appended.
    assert bb2.get("credentials_found") == ["cred-2", "cred-3", "cred-1"]


def test_flat_returns_global_view():
    bb = Blackboard({"k": "v"})
    bb.set_scalar("target_k", "tv", target="10.0.0.5")
    flat = bb.flat()
    assert flat == {"k": "v"}
    assert "target_k" not in flat


# ── bb_compat backward compat ─────────────────────────────────────────────


def test_bb_compat_falls_back_to_plain_dict():
    """A plain ``{}`` blackboard (legacy test/legacy caller path) must work
    through the compat helpers — no AttributeError. Not atomic, but safe
    in the single-threaded legacy path.
    """
    bb: dict = {}
    bb_set(bb, "recon_complete", True)
    bb_append(bb, "compromised_hosts", "10.0.0.5")
    bb_extend(bb, "loot", ["item-1", "item-2"])
    bb_extend(bb, "loot", ["item-2", "item-3"])  # dedupe
    bb_remove(bb, "loot", "item-1")

    assert bb["recon_complete"] is True
    assert bb["compromised_hosts"] == ["10.0.0.5"]
    assert bb["loot"] == ["item-2", "item-3"]


def test_bb_compat_uses_blackboard_when_available():
    """When the blackboard IS a Blackboard, compat helpers must route through
    the atomic methods (verified by checking the result matches Blackboard
    semantics, not plain-dict)."""
    bb = Blackboard()
    bb_set(bb, "k", "v")
    bb_append(bb, "lst", "a")
    bb_extend(bb, "lst", ["a", "b"])  # dedupe via Blackboard
    bb_remove(bb, "lst", "a")
    assert bb.get("k") == "v"
    assert bb.get("lst") == ["b"]


# ── Lock contention smoke (no deadlock) ───────────────────────────────────


def test_mixed_reads_and_writes_do_not_deadlock():
    """A mix of concurrent reads and writes across different keys must not
    deadlock (the single threading.Lock is re-entrant-free; this is a smoke
    test that the lock is released properly)."""
    bb = Blackboard()
    for i in range(100):
        bb.append_to("seed", i)

    stop = threading.Event()

    def reader() -> None:
        while not stop.is_set():
            bb.get("seed")
            bb.snapshot()

    def writer() -> None:
        for i in range(500, 600):
            bb.append_to("seed", i)

    threads = [threading.Thread(target=reader) for _ in range(4)] + [threading.Thread(target=writer) for _ in range(2)]
    for t in threads:
        t.start()
    # Let them run briefly.
    import time as _t
    _t.sleep(0.3)
    stop.set()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "thread deadlocked"