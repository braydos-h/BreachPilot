"""TEMP conftest: workaround for pytest 9.0.3 PosixPath INTERNALERROR on Windows.

Deletes itself after the verification run — not committed.
"""
import traceback

try:
    import _pytest.nodes as _n

    _orig = _n.Node._repr_failure_py

    def _safe(self, excinfo, *a, **k):
        try:
            return _orig(self, excinfo, *a, **k)
        except NotImplementedError:
            return "".join(traceback.format_exception(excinfo.type, excinfo.value, excinfo.tb))

    _n.Node._repr_failure_py = _safe
except Exception:
    pass