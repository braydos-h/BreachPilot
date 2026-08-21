import sys

print("NUMPY-IN-SYSMODULES-AT-COLLECT:", sorted(k for k in sys.modules if k.startswith("numpy")), flush=True)
print("MAIN-IN-SYSMODULES:", "main" in sys.modules, flush=True)


def test_probe():
    import numpy as np

    assert np.__version__
