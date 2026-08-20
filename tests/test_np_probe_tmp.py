import sys
import traceback

_ORIG = __import__
_calls = []


def _patched(name, *a, **k):
    if name == "numpy._core._multiarray_umath":
        _calls.append(len(_calls))
        print(f"=== umath import #{len(_calls)} ===", flush=True)
        traceback.print_stack(limit=14, file=sys.stdout)
        print(flush=True)
    return _ORIG(name, *a, **k)


sys.modules["builtins"].__dict__["__import__"] = _patched


def test_probe():
    import numpy as np

    assert np.__version__
