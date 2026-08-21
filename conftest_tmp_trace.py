import sys
import traceback

_orig_import = builtins_import = None


def pytest_configure(config):
    import builtins

    global _orig_import
    _orig_import = builtins.__import__

    def _patched(name, *a, **k):
        if name == "main":
            print("=== IMPORTING main, stack ===", flush=True)
            traceback.print_stack(limit=16, file=sys.stdout)
        return _orig_import(name, *a, **k)

    builtins.__import__ = _patched
