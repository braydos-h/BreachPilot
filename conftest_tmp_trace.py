import sys
import traceback

_ORIG = None


def _patched(name, *a, **k):
    if name == "main":
        print("=== IMPORTING main ===", flush=True)
        traceback.print_stack(limit=20, file=sys.stdout)
        print("=== END STACK ===", flush=True)
    return _ORIG(name, *a, **k)


def pytest_configure(config):
    import builtins

    global _ORIG
    _ORIG = builtins.__import__
    builtins.__import__ = _patched
