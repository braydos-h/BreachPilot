"""Single-source versioning guard (todo 53).

Canonical source version lives in pyproject.toml [project.version].
webui/package.json and main.py __version__ must match it.
Release bootstrap URLs in README/docs pin a *released* tag and are
intentionally excluded (they point at an immutable release artifact,
not the working-tree version).
"""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_pyproject_version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as f:
        return tomllib.load(f)["project"]["version"]


def test_source_versions_match():
    pyproject_version = read_pyproject_version()

    webui_pkg = json.loads((ROOT / "webui" / "package.json").read_text())
    assert webui_pkg["version"] == pyproject_version, (
        f"webui/package.json {webui_pkg['version']} != pyproject.toml {pyproject_version}"
    )

    main_py = (ROOT / "main.py").read_text()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', main_py)
    assert m, "main.py __version__ not found"
    assert m.group(1) == pyproject_version, f"main.py {m.group(1)} != pyproject.toml {pyproject_version}"


def test_webui_uses_version_module():
    # All surfaces must render via lib/version.ts, not hardcoded strings.
    layout = (ROOT / "webui" / "src" / "components" / "Layout.tsx").read_text()
    assert "APP_VERSION" in layout, "Layout must render via APP_VERSION from lib/version"
    assert "v{__APP_VERSION__}" not in layout, "Layout must not interpolate __APP_VERSION__ directly"
