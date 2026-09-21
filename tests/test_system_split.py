"""p2-02: system routes split — all paths mount, helpers de-duplicated, seams intact."""

from __future__ import annotations

from pathlib import Path

EXPECTED_PATHS = {
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/capabilities"),
    ("GET", "/api/v1/config"),
    ("PATCH", "/api/v1/config"),
    ("GET", "/api/v1/secrets"),
    ("PUT", "/api/v1/secrets"),
    ("GET", "/api/v1/models"),
    ("POST", "/api/v1/models"),
    ("DELETE", "/api/v1/models/{alias}"),
    ("POST", "/api/v1/models/provider"),
    ("POST", "/api/v1/models/refresh"),
    ("GET", "/api/v1/system/info"),
    ("GET", "/api/v1/system/telemetry"),
    ("GET", "/api/v1/system/memory"),
    ("GET", "/api/v1/system/sandbox"),
    ("GET", "/api/v1/system/browser"),
    ("GET", "/api/v1/system/sandbox/fix/plan"),
    ("POST", "/api/v1/system/sandbox/fix"),
    ("GET", "/api/v1/system/sandbox/fix/{job_id}"),
    ("POST", "/api/v1/system/reset"),
    ("GET", "/api/v1/plugins"),
    ("GET", "/api/v1/skills"),
    ("GET", "/api/v1/skills/search"),
    ("POST", "/api/v1/diagnostics/doctor"),
    ("POST", "/api/v1/diagnostics/self-test"),
    ("GET", "/api/v1/attack/modules"),
    ("GET", "/api/v1/goals"),
    ("POST", "/api/v1/goals"),
    ("PATCH", "/api/v1/goals/{goal_id}"),
    ("DELETE", "/api/v1/goals/{goal_id}"),
    ("GET", "/api/v1/config/schema"),
    ("GET", "/api/v1/models/live"),
    ("GET", "/api/v1/providers"),
    ("POST", "/api/v1/providers/chatgpt/login"),
    ("POST", "/api/v1/providers/chatgpt/proxy/start"),
    ("POST", "/api/v1/providers/chatgpt/proxy/stop"),
    ("GET", "/api/v1/skills/{name}"),
    ("POST", "/api/v1/skills"),
    ("DELETE", "/api/v1/skills/{name}"),
}

SINGLE_SOURCE_HELPERS = (
    "def _safe_json",
    "def _read_attack_memory_db",
    "def _load_memory_sync",
    "def _chatgpt_status_sync",
    "def _opencode_go_status_sync",
    "def _run_doctor_sync",
    "def _validate_skill_name",
    "def _resolve_skill_dir",
    "def _plugin_skill_dirs",
)


def _package_dir() -> Path:
    import tools.api.routes.system as sysmod

    return Path(sysmod.__file__).resolve().parent


def test_sub_routers_mount_all_paths():
    from tools.api.routes.system import create_router

    router = create_router(auth=object(), config={}, config_path=Path("/tmp/x"))
    mounted = {(m, r.path) for r in router.routes for m in (r.methods or ())}
    assert EXPECTED_PATHS <= mounted, EXPECTED_PATHS - mounted


def test_overlap_precedence_preserved():
    from tools.api.routes.system import create_router

    router = create_router(auth=object(), config={}, config_path=Path("/tmp/x"))
    get_order = [r.path for r in router.routes if r.methods and "GET" in r.methods]
    assert get_order.index("/api/v1/skills/search") < get_order.index("/api/v1/skills/{name}")
    assert get_order.index("/api/v1/system/sandbox/fix/plan") < get_order.index("/api/v1/system/sandbox/fix/{job_id}")


def test_no_duplicate_helpers():
    texts = {p.name: p.read_text(encoding="utf-8") for p in _package_dir().glob("*.py")}
    for helper in SINGLE_SOURCE_HELPERS:
        hits = sorted(name for name, text in texts.items() if helper in text)
        assert hits == ["_shared.py"], (helper, hits)


def test_back_compat_import_path():
    import tools.api.routes.system as sysmod
    from tools.api.routes.system import _opencode_go_status_sync, create_router

    assert callable(create_router)
    assert callable(_opencode_go_status_sync)
    assert sysmod.SystemContext is not None
    assert sysmod.create_router is create_router
