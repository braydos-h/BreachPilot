"""Regression tests for WebUI resources in source checkouts and wheels."""

from __future__ import annotations

from pathlib import Path

import pytest

import scripts.package_webui as package_webui
from scripts.package_webui import copy_webui_bundle
from tools import paths


def test_package_webui_replaces_destination_with_complete_build(tmp_path: Path) -> None:
    source = tmp_path / "webui" / "dist"
    (source / "assets" / "nested").mkdir(parents=True)
    (source / "index.html").write_text("<main>built</main>", encoding="utf-8")
    (source / "assets" / "nested" / "app.js").write_text("console.log('built')", encoding="utf-8")

    destination = tmp_path / "tools" / "webui" / "dist"
    destination.mkdir(parents=True)
    (destination / "old-hash.js").write_text("stale", encoding="utf-8")

    copy_webui_bundle(source, destination)

    assert (destination / "index.html").read_text(encoding="utf-8") == "<main>built</main>"
    assert (destination / "assets" / "nested" / "app.js").read_text(encoding="utf-8") == "console.log('built')"
    assert not (destination / "old-hash.js").exists()


def test_package_webui_requires_a_completed_vite_build(tmp_path: Path) -> None:
    source = tmp_path / "empty-dist"
    source.mkdir()

    with pytest.raises(FileNotFoundError, match="npm run build first"):
        copy_webui_bundle(source, tmp_path / "package" / "dist")


def test_package_webui_rejects_symlinks_in_source_bundle(tmp_path: Path) -> None:
    source = tmp_path / "webui" / "dist"
    (source / "assets").mkdir(parents=True)
    (source / "index.html").write_text("<main>built</main>", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("must not be packaged", encoding="utf-8")
    try:
        (source / "assets" / "private.txt").symlink_to(outside / "private.txt")
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    destination = tmp_path / "tools" / "webui" / "dist"
    with pytest.raises(ValueError, match="symlink"):
        copy_webui_bundle(source, destination, repository_root=tmp_path)

    assert not destination.exists()


def test_package_webui_rejects_symlinked_source_ancestors(tmp_path: Path) -> None:
    repository = tmp_path / "checkout"
    external_webui = tmp_path / "external-webui"
    source = external_webui / "dist"
    source.mkdir(parents=True)
    (source / "index.html").write_text("<main>built</main>", encoding="utf-8")
    repository.mkdir()
    try:
        (repository / "webui").symlink_to(external_webui, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    destination = repository / "tools" / "webui" / "dist"

    with pytest.raises(ValueError, match="symlink"):
        copy_webui_bundle(repository / "webui" / "dist", destination, repository_root=repository)

    assert (source / "index.html").is_file()
    assert not destination.exists()


@pytest.mark.parametrize("symlinked_component", ["tools", "webui"])
def test_package_webui_rejects_symlinked_destination_ancestors(tmp_path: Path, symlinked_component: str) -> None:
    repository = tmp_path / "checkout"
    source = repository / "webui" / "dist"
    source.mkdir(parents=True)
    (source / "index.html").write_text("<main>built</main>", encoding="utf-8")
    external = tmp_path / "outside"
    external.mkdir()
    (external / "keep.txt").write_text("preserve", encoding="utf-8")

    tools_dir = repository / "tools"
    webui_dir = tools_dir / "webui"
    if symlinked_component == "tools":
        tools_dir.symlink_to(external, target_is_directory=True)
    else:
        tools_dir.mkdir(parents=True)
        webui_dir.symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        copy_webui_bundle(source, webui_dir / "dist", repository_root=repository)

    assert (external / "keep.txt").read_text(encoding="utf-8") == "preserve"
    assert not (external / "dist").exists()


@pytest.mark.parametrize("overlap", ["same", "destination-inside-source", "source-inside-destination"])
def test_package_webui_rejects_overlapping_source_and_destination(tmp_path: Path, overlap: str) -> None:
    if overlap == "same":
        source = destination = tmp_path / "bundle"
    elif overlap == "destination-inside-source":
        source = tmp_path / "bundle"
        destination = source / "nested" / "dist"
    else:
        destination = tmp_path / "bundle"
        source = destination / "input"

    source.mkdir(parents=True)
    (source / "index.html").write_text("<main>built</main>", encoding="utf-8")
    marker = destination / "old.txt"
    if destination != source:
        destination.mkdir(parents=True, exist_ok=True)
        marker.write_text("previous bundle", encoding="utf-8")

    with pytest.raises(ValueError, match="must not overlap"):
        copy_webui_bundle(source, destination, repository_root=tmp_path)

    assert (source / "index.html").read_text(encoding="utf-8") == "<main>built</main>"
    if destination != source:
        assert marker.read_text(encoding="utf-8") == "previous bundle"


def test_package_webui_copy_failure_preserves_existing_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "webui" / "dist"
    source.mkdir(parents=True)
    (source / "index.html").write_text("<main>new</main>", encoding="utf-8")
    destination = tmp_path / "tools" / "webui" / "dist"
    destination.mkdir(parents=True)
    (destination / "index.html").write_text("<main>previous</main>", encoding="utf-8")
    (destination / "old.js").write_text("previous asset", encoding="utf-8")

    def fail_after_partial_copy(_source: Path, staged: Path, *, symlinks: bool) -> None:
        assert symlinks is True
        staged.mkdir(parents=True)
        (staged / "partial.js").write_text("partial", encoding="utf-8")
        raise OSError("simulated copy failure")

    monkeypatch.setattr(package_webui.shutil, "copytree", fail_after_partial_copy)

    with pytest.raises(OSError, match="simulated copy failure"):
        copy_webui_bundle(source, destination, repository_root=tmp_path)

    assert (destination / "index.html").read_text(encoding="utf-8") == "<main>previous</main>"
    assert (destination / "old.js").read_text(encoding="utf-8") == "previous asset"
    assert not (destination / "partial.js").exists()
    assert not list(destination.parent.glob(f".{destination.name}.staging-*"))


def test_package_webui_promotion_failure_restores_existing_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "webui" / "dist"
    source.mkdir(parents=True)
    (source / "index.html").write_text("<main>new</main>", encoding="utf-8")
    destination = tmp_path / "tools" / "webui" / "dist"
    destination.mkdir(parents=True)
    (destination / "index.html").write_text("<main>previous</main>", encoding="utf-8")

    real_replace = package_webui.os.replace

    def fail_new_bundle_promotion(source_path: Path, destination_path: Path) -> None:
        if Path(source_path).name == "new" and Path(destination_path) == destination:
            raise OSError("simulated promotion failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(package_webui.os, "replace", fail_new_bundle_promotion)

    with pytest.raises(OSError, match="simulated promotion failure"):
        copy_webui_bundle(source, destination, repository_root=tmp_path)

    assert (destination / "index.html").read_text(encoding="utf-8") == "<main>previous</main>"
    assert not list(destination.parent.glob(f".{destination.name}.staging-*"))


def test_webui_dist_lookup_prefers_source_checkout_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkout_dist = tmp_path / "checkout" / "webui" / "dist"
    checkout_dist.mkdir(parents=True)
    (checkout_dist / "index.html").write_text("source bundle", encoding="utf-8")
    packaged_dist = tmp_path / "site-packages" / "tools" / "webui" / "dist"
    packaged_dist.mkdir(parents=True)
    (packaged_dist / "index.html").write_text("wheel bundle", encoding="utf-8")

    class PackageResources:
        @staticmethod
        def files(_package: str) -> Path:
            return packaged_dist.parents[1]

    monkeypatch.setattr(paths, "_repo_root_from_this_file", lambda: checkout_dist.parents[1])
    monkeypatch.setattr(paths, "_resources", PackageResources)

    assert paths.get_webui_dist_dir() == checkout_dist


def test_webui_dist_lookup_finds_installed_package_resource(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site_packages = tmp_path / "site-packages"
    packaged_dist = site_packages / "tools" / "webui" / "dist"
    packaged_dist.mkdir(parents=True)
    (packaged_dist / "index.html").write_text("wheel bundle", encoding="utf-8")

    class PackageResources:
        @staticmethod
        def files(_package: str) -> Path:
            return site_packages / "tools"

    monkeypatch.setattr(paths, "_repo_root_from_this_file", lambda: tmp_path / "not-a-checkout")
    monkeypatch.setattr(paths, "_resources", PackageResources)

    assert paths.get_webui_dist_dir() == packaged_dist


def test_installed_webui_bundle_skips_node_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import webui_boot

    packaged_dist = tmp_path / "site-packages" / "tools" / "webui" / "dist"
    packaged_dist.mkdir(parents=True)
    (packaged_dist / "index.html").write_text("wheel bundle", encoding="utf-8")
    monkeypatch.setattr(webui_boot, "REPO_ROOT", tmp_path / "site-packages")

    class Ui:
        errors: list[str] = []

        @staticmethod
        def error(message: str) -> None:
            Ui.errors.append(message)

    assert webui_boot._ensure_webui_build(Ui()) == 0
    assert not Ui.errors
