import sys


def pytest_configure(config):
    np_mods = [k for k in sys.modules if k.startswith("numpy")]
    print("CONFIGURE numpy mods:", np_mods, flush=True)
    print("CONFIGURE umath loaded:", "numpy._core._multiarray_umath" in sys.modules, flush=True)
