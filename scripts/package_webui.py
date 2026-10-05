"""Copy Vite's build output into the Python package's static-resource tree."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _reject_symlink_components(path: Path, root: Path, *, label: str) -> None:
    """Reject symlinks below ``root`` before following any path components."""
    if path == root:
        if path.is_symlink():
            raise ValueError(f"Refusing symlink {label} root: {path}")
        return
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} path escapes package root {root}: {path}") from exc

    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Refusing symlink in {label} path: {current}")


def _reject_bundle_symlinks(bundle: Path, *, label: str) -> None:
    """Reject links in a bundle without ever traversing their targets."""
    if bundle.is_symlink():
        raise ValueError(f"Refusing symlink {label} bundle: {bundle}")
    for current, directories, files in os.walk(bundle, followlinks=False):
        for name in (*directories, *files):
            entry = Path(current) / name
            if entry.is_symlink():
                raise ValueError(f"Refusing symlink in {label} bundle: {entry}")


def copy_webui_bundle(source: Path, destination: Path, *, repository_root: Path | None = None) -> None:
    """Stage and safely replace ``destination`` with a complete Vite bundle."""
    source = _absolute(source)
    destination = _absolute(destination)
    if source == destination or _is_within(source, destination) or _is_within(destination, source):
        raise ValueError(f"WebUI source and package destination must not overlap: {source} and {destination}")

    if repository_root is None:
        root = Path(os.path.commonpath((source, destination)))
    else:
        root = _absolute(repository_root)
    if root.is_symlink():
        raise ValueError(f"Refusing symlink package root: {root}")
    _reject_symlink_components(source, root, label="WebUI source")
    _reject_symlink_components(destination, root, label="WebUI destination")

    if not source.is_dir():
        raise FileNotFoundError(f"WebUI build directory is missing: {source}; run npm run build first")
    _reject_bundle_symlinks(source, label="WebUI source")
    if not (source / "index.html").is_file():
        raise FileNotFoundError(f"WebUI build is missing {source / 'index.html'}; run npm run build first")

    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(destination.parent, root, label="WebUI destination")

    if destination.exists() and not destination.is_dir():
        raise ValueError(f"WebUI package destination is not a directory: {destination}")

    staging_root = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent))
    keep_staging_for_recovery = False
    try:
        staged_bundle = staging_root / "new"
        backup_bundle = staging_root / "previous"
        # Preserve symlinks during copy so even a source-tree race cannot make
        # copytree follow a link and pull files from outside the bundle. The
        # staged result is checked again before promotion.
        shutil.copytree(source, staged_bundle, symlinks=True)
        _reject_bundle_symlinks(staged_bundle, label="staged WebUI")
        if not (staged_bundle / "index.html").is_file():
            raise FileNotFoundError(f"Staged WebUI build is missing {staged_bundle / 'index.html'}")

        _reject_symlink_components(destination, root, label="WebUI destination")
        try:
            if destination.exists():
                os.replace(destination, backup_bundle)
            os.replace(staged_bundle, destination)
        except BaseException:
            if backup_bundle.exists():
                try:
                    if destination.exists():
                        raise OSError(f"WebUI destination reappeared during replacement: {destination}")
                    os.replace(backup_bundle, destination)
                except OSError as restore_error:
                    keep_staging_for_recovery = True
                    raise RuntimeError(
                        f"Could not install the new WebUI bundle or restore the previous one; "
                        f"the previous bundle remains at {backup_bundle}"
                    ) from restore_error
            raise
    finally:
        if not keep_staging_for_recovery:
            shutil.rmtree(staging_root, ignore_errors=True)


def main() -> int:
    source = REPO_ROOT / "webui" / "dist"
    destination = REPO_ROOT / "tools" / "webui" / "dist"
    copy_webui_bundle(source, destination, repository_root=REPO_ROOT)
    print(f"Prepared WebUI package resources: {destination.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
