"""P1-09: ApiPersistence reuses one persistent connection."""

from __future__ import annotations


def test_persistent_connection_reused(tmp_path):
    from tools.api.persistence import ApiPersistence

    p = ApiPersistence(tmp_path)
    first = p._conn if hasattr(p, "_conn") else None
    assert first is not None, "expected persistent self._conn"
    for _ in range(5):
        p.list_runs() if hasattr(p, "list_runs") else None
    assert p._conn is first


def test_crud_works_on_persistent_conn(tmp_path):
    from tools.api.persistence import ApiPersistence

    p = ApiPersistence(tmp_path)
    p.create_run(run_id="r1", request={"target": "10.0.0.1"}, preview={"goal": "recon"})
    assert p.get_run("r1")["state"] == "draft"
    p.update_run_state("r1", "completed", result={"ok": True})
    assert p.get_run("r1")["state"] == "completed"
    assert p.count_runs() == 1
    assert p.delete_run("r1") is True
    assert p.count_runs() == 0


def test_close_and_use_after_close(tmp_path):
    from tools.api.persistence import ApiPersistence

    p = ApiPersistence(tmp_path)
    p.create_run(run_id="r1", request={}, preview={})
    p.close()
    p.close()  # idempotent
    try:
        p.list_runs()
    except RuntimeError:
        pass
    else:
        raise AssertionError("use after close should raise cleanly")
