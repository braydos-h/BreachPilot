"""Packaging regression tests for the canonical exploit-loop location.

The canonical loop once lived outside the ``tools*`` package tree (in the
repo-only ``scripts/`` directory) and was loaded by
``tools/exploit_agent/runner/loop.py`` through an importlib
``spec_from_file_location`` call. Built wheels never contained that
directory, so every installed-wheel import of ``tools.exploit_agent`` died
with ``FileNotFoundError``. The loop now lives at
``tools/exploit_agent/runner/_impl.py`` — a normal package submodule covered
by ``[tool.setuptools.packages.find]`` — and is imported with a plain
relative import.

These tests guard the source layout that makes that importable from an
installed wheel WITHOUT building a wheel in pytest (too slow). The real
wheel smoke test lives in ``.github/workflows/ci.yml`` (package job).
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import tomllib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_runner_impl_exists_as_package_submodule() -> None:
    impl = REPO_ROOT / "tools" / "exploit_agent" / "runner" / "_impl.py"
    assert impl.is_file(), "canonical loop must live at tools/exploit_agent/runner/_impl.py"
    assert (REPO_ROOT / "tools" / "exploit_agent" / "runner" / "__init__.py").is_file()


def test_packages_find_include_patterns_cover_tools() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    find = pyproject["tool"]["setuptools"]["packages"]["find"]
    assert any(p == "tools" or p.startswith("tools*") for p in find.get("include", [])), (
        "[tool.setuptools.packages.find] must include tools* so the runner subpackage ships in the wheel"
    )


def test_runner_loop_uses_plain_import_no_importlib_regression() -> None:
    """Source-level guard: loop.py must not go back to importlib file loading.

    AST-based because the module docstring legitimately *mentions* the old
    ``spec_from_file_location`` mechanism by name.
    """
    loop_path = REPO_ROOT / "tools" / "exploit_agent" / "runner" / "loop.py"
    tree = ast.parse(loop_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        assert not isinstance(node, ast.Import) or not any(a.name.split(".")[0] == "importlib" for a in node.names), (
            "runner/loop.py regressed to importlib-based loading"
        )
        assert not isinstance(node, ast.ImportFrom) or node.module != "importlib"
        if isinstance(node, ast.Call):
            fn = node.func
            assert not (isinstance(fn, ast.Attribute) and fn.attr == "spec_from_file_location"), (
                "runner/loop.py must not spec_from_file_location-load the loop"
            )
    loop_src = loop_path.read_text(encoding="utf-8")
    assert "parents[3]" not in loop_src
    assert "from ._impl import" in loop_src


def test_impl_imports_and_resolves_inside_tools_tree() -> None:
    """The module must resolve as a real file under a tools/ tree — either the
    repo checkout (repo run) or site-packages (installed wheel), never a
    phantom spec-from-file path."""
    mod = importlib.import_module("tools.exploit_agent.runner._impl")
    assert callable(getattr(mod, "run_exploit_agent", None))
    mod_file = pathlib.Path(mod.__file__).resolve()
    assert mod_file.name == "_impl.py"
    assert mod_file.parts[-3] == "exploit_agent" or "runner" in mod_file.parts
    parts = [p.lower() for p in mod_file.parts]
    in_repo_tools = "tools" in parts and "exploit_agent" in parts
    in_site_packages = "site-packages" in parts
    assert in_repo_tools or in_site_packages, f"unexpected module location: {mod_file}"
