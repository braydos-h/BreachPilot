"""File APIs preserve bytes and tail contracts without blocking whole-file reads."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import HTTPException

from tests.test_api_frontend import _auth, _create_run, _make_client
from tools.api.routes.runs import _open_contained_file, _read_log_tail, _stream_file


def test_contained_file_descriptor_does_not_follow_path_replacement(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    candidate = root / "capture.bin"
    candidate.write_bytes(b"validated workspace content")
    outside = tmp_path / "host-secret.txt"
    outside.write_bytes(b"host secret")

    handle, size = _open_contained_file(root, candidate)
    candidate.unlink()
    candidate.symlink_to(outside)
    try:
        assert size == len(b"validated workspace content")
        assert handle.read() == b"validated workspace content"
    finally:
        handle.close()


def test_contained_file_open_refuses_symlink_components(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "host-secret.txt"
    outside.write_text("host secret", encoding="utf-8")
    link = root / "host-secret.txt"
    link.symlink_to(outside)

    with pytest.raises(HTTPException) as exc:
        _open_contained_file(root, link)
    assert exc.value.status_code == 404


def test_contained_file_open_is_nonblocking_before_rejecting_fifo(tmp_path, monkeypatch):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO race protection requires POSIX")

    root = tmp_path / "workspace"
    root.mkdir()
    fifo = root / "capture.pipe"
    os.mkfifo(fifo)
    original_open = os.open
    original_dir_fd_support = os.supports_dir_fd
    fifo_open_flags: list[int] = []

    def guarded_open(path, flags, *args, **kwargs):
        if path == fifo.name:
            fifo_open_flags.append(flags)
            assert flags & os.O_NONBLOCK
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    monkeypatch.setattr(os, "supports_dir_fd", original_dir_fd_support | {guarded_open})
    with pytest.raises(HTTPException) as exc:
        _open_contained_file(root, fifo)
    assert exc.value.status_code == 404
    assert len(fifo_open_flags) == 1


def test_stream_is_capped_to_opened_file_size_when_file_grows(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    candidate = root / "capture.bin"
    candidate.write_bytes(b"stable")
    handle, size = _open_contained_file(root, candidate)
    with candidate.open("ab") as writer:
        writer.write(b"-later")

    assert b"".join(_stream_file(handle, size, chunk_size=2)) == b"stable"


def test_stream_fails_if_file_is_truncated_after_open(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    candidate = root / "capture.bin"
    candidate.write_bytes(b"stable")
    handle, size = _open_contained_file(root, candidate)
    candidate.write_bytes(b"s")

    with pytest.raises(OSError, match="file changed during download"):
        list(_stream_file(handle, size, chunk_size=2))


@pytest.mark.parametrize(
    "content", [b"", b"one\n", b"one\r\ntwo\rthree\n\n", "a\u2028b\u0085c".encode(), b"bad\xff\nlast"]
)
def test_log_tail_preserves_splitlines_and_total(tmp_path, content):
    path = tmp_path / "log.txt"
    path.write_bytes(content)
    expected = content.decode("utf-8", errors="replace").splitlines()
    for tail in (1, 2, 2000):
        recent, total = _read_log_tail(path, tail)
        assert recent == expected[-tail:]
        assert total == len(expected)


def test_log_tail_rejects_path_replaced_with_out_of_root_symlink(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    run_id = _create_run(client)["run_id"]
    run_dir = (Path("reports") / run_id).resolve()
    log_path = run_dir / "session_error.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("safe log entry\n", encoding="utf-8")
    outside = tmp_path / "host-secret.log"
    outside.write_text("host secret must not be returned\n", encoding="utf-8")

    original_is_file = Path.is_file
    replaced = False

    def replace_after_validation(path: Path) -> bool:
        nonlocal replaced
        result = original_is_file(path)
        if path == log_path and result and not replaced:
            log_path.unlink()
            log_path.symlink_to(outside)
            replaced = True
        return result

    monkeypatch.setattr(Path, "is_file", replace_after_validation)
    response = client.get(f"/api/v1/runs/{run_id}/logs/session_error.log", headers=_auth())

    assert replaced
    assert response.status_code == 404
    assert response.json()["error"]["message"] == "Log not found"
    assert "host secret" not in response.text


@pytest.mark.parametrize("resource", ["artifacts/session_error.log", "workspace/capture.bin"])
def test_file_download_streams_exact_bytes_without_read_bytes(tmp_path, monkeypatch, resource):
    client = _make_client(tmp_path, monkeypatch)
    run_id = _create_run(client)["run_id"]
    run_dir = tmp_path / "reports" / run_id
    relative = resource.replace("artifacts/", "").replace("workspace/", "exploit_workspace/")
    path = run_dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    content = bytes(range(256)) * 1024
    path.write_bytes(content)
    original = Path.read_bytes

    def guarded_read_bytes(self):
        if self == path:
            raise AssertionError("download must stream rather than materialize the complete file")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    response = client.get(f"/api/v1/runs/{run_id}/{resource}", headers=_auth())
    assert response.status_code == 200
    assert response.content == content
    assert int(response.headers["content-length"]) == len(content)


@pytest.mark.parametrize(
    "endpoint,filename",
    [
        ("logs/session_error.log?tail=2", "session_error.log"),
        ("sandbox", "events.jsonl"),
        ("errors", "errors.jsonl"),
        ("audit", "exploit_audit.jsonl"),
        ("workspace", "exploit_workspace/nested/capture.txt"),
    ],
)
def test_file_aggregation_runs_off_event_loop(tmp_path, monkeypatch, endpoint, filename):
    client = _make_client(tmp_path, monkeypatch)
    run_id = _create_run(client)["run_id"]
    path = tmp_path / "reports" / run_id / filename
    if endpoint == "workspace":
        workspace_root = tmp_path / "reports" / run_id / "exploit_workspace"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("workspace entry", encoding="utf-8")
    else:
        workspace_root = None
        path.parent.mkdir(parents=True, exist_ok=True)
        content = '{"kind":"test"}\n' if filename.endswith(".jsonl") else "one\ntwo\nthree\n"
        path.write_text(content, encoding="utf-8")
    observed = []

    if filename.endswith(".log"):
        import tools.api.routes.runs as runs_routes

        original_read = runs_routes._read_log_tail_from_handle

        def guarded_read(handle, tail):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                observed.append(True)
            else:
                raise AssertionError("log aggregation must run off the event loop")
            return original_read(handle, tail)

        monkeypatch.setattr(runs_routes, "_read_log_tail_from_handle", guarded_read)
    elif endpoint == "workspace":
        original_rglob = Path.rglob

        def guarded_rglob(self, pattern):
            if self == workspace_root:
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    observed.append(True)
                else:
                    raise AssertionError("workspace traversal must run off the event loop")
            return original_rglob(self, pattern)

        monkeypatch.setattr(Path, "rglob", guarded_rglob)
    else:
        original = Path.open

        def guarded_open(self, *args, **kwargs):
            if self == path:
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    observed.append(True)
                else:
                    raise AssertionError("file aggregation must run off the event loop")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", guarded_open)
    response = client.get(f"/api/v1/runs/{run_id}/{endpoint}", headers=_auth())
    assert response.status_code == 200
    assert observed
    if filename.endswith(".log"):
        assert response.json()["lines"] == ["two", "three"]
        assert response.json()["total_lines_in_file"] == 3
    elif endpoint == "errors":
        assert response.json()["records"] == [{"kind": "test"}]
    elif endpoint == "audit":
        assert response.json()["records"] == [{"kind": "test"}]
        assert response.json()["chain_valid"] is True
    elif endpoint == "workspace":
        assert response.json()["files"] == [{"path": "nested/capture.txt", "bytes": len("workspace entry")}]
