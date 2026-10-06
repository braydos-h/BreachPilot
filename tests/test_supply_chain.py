"""TODO 024: supply-chain artifacts wired (pins, SBOM/Trivy, digests)."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent


def test_actions_sha_pinned():
    offender: list[str] = []
    for yml in (REPO / ".github" / "workflows").glob("*.yml"):
        for i, line in enumerate(yml.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.search(r"uses:\s*([^\s#]+)@([^\s#]+)", line)
            if not m:
                continue
            ref = m.group(2)
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            # Allow local/.docker actions.
            if m.group(1).startswith(("./", "docker/")):
                continue
            offender.append(f"{yml.name}:{i}:{line.strip()}")
    assert not offender, "unpinned actions:\n" + "\n".join(offender)


def test_action_pin_guard_rejects_mutable_refs(tmp_path):
    from scripts.check_action_pins import find_unpinned_actions

    (tmp_path / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@main\n      - uses: ./local/action\n",
        encoding="utf-8",
    )
    assert find_unpinned_actions(tmp_path) == ["ci.yml:4:- uses: actions/checkout@main"]


def test_requirements_sync_rejects_version_range_drift(tmp_path):
    from scripts.check_requirements_sync import check_requirements_sync

    pyproject = tmp_path / "pyproject.toml"
    requirements = tmp_path / "requirements.txt"
    pyproject.write_text(
        '[project]\ndependencies = ["demo>=1.0,<2.0"]\n[project.optional-dependencies]\n'
        'ollama = []\ndev = []\nbrowser = ["playwright>=1.44"]\n',
        encoding="utf-8",
    )
    requirements.write_text("demo>=1.0,<3.0\n", encoding="utf-8")
    findings = check_requirements_sync(pyproject, requirements)
    assert any("range for demo" in finding for finding in findings)
    assert not any("playwright" in finding for finding in findings)


def test_browser_worker_and_ci_share_exact_playwright_pin():
    constraint = next(
        line
        for line in (REPO / "constraints-dev.txt").read_text(encoding="utf-8").splitlines()
        if line.lower().startswith("playwright==")
    )
    version = constraint.split("==", 1)[1]
    dockerfile = (REPO / "docker/sandbox/Dockerfile.browser").read_text(encoding="utf-8")
    assert f"ARG PLAYWRIGHT_VERSION={version}" in dockerfile
    assert 'pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}"' in dockerfile
    ci = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "optional-dependencies'][extra]" in ci or "optional-dependencies[extra]" in ci
    assert "('ollama', 'dev', 'browser')" in ci


def test_release_workflow_publishes_supply_chain():
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    text = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for needle in (
        "sbom-python.json",
        "sbom-webui.json",
        "sbom-sandbox.json",
        "sbom-sandbox-browser.json",
        "trivy",
        "attest-build-provenance",
        "install-",
    ):
        assert needle in text, f"release.yml missing {needle}"
    assert "sandbox-image-refs.txt" in text
    assert "buildx imagetools inspect debian:12-slim" not in text
    assert "docker build -t breachpilot-sandbox:" not in text
    assert workflow["jobs"]["build"]["needs"] == ["gate"]


def test_release_distribution_checksums_match_flat_uploaded_asset_names(tmp_path):
    """Release manifests use asset basenames because GitHub flattens uploads."""
    workflow = yaml.safe_load((REPO / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build"]["steps"]
    checksum_step = next(step for step in steps if step.get("name") == "SHA256SUMS")
    distribution_dir = tmp_path / "dist"
    distribution_dir.mkdir()
    distribution_names = {
        "breachpilot-0.69.0.tar.gz",
        "breachpilot-0.69.0-py3-none-any.whl",
    }
    for name in distribution_names:
        (distribution_dir / name).write_text(name, encoding="utf-8")

    subprocess.run(["bash", "-e", "-c", checksum_step["run"]], cwd=tmp_path, check=True, capture_output=True)

    manifest_names = {
        line.split(maxsplit=1)[1].lstrip(" *")
        for line in (tmp_path / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    }
    assert manifest_names == distribution_names

    publish_step = next(step for step in steps if step.get("name") == "Publish GitHub Release assets")
    assert "assets=(dist/* SHA256SUMS" in publish_step["run"]


def test_release_docs_link_evidence():
    text = (REPO / "docs" / "release.md").read_text(encoding="utf-8")
    assert "branch-rules.json" in text
    assert "DIGESTS.md" in text
    assert "green HEAD" in text or "green head" in text.lower()


def test_release_sbom_and_trivy_use_cosign_verified_sandbox_digests():
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    gate = jobs["gate"]
    build = jobs["build"]

    verified = next(step for step in gate["steps"] if step.get("id") == "verify-images")
    assert 'cosign verify "$image_ref"' in verified["run"]
    assert "steps.verify-images.outputs.base_image_ref" == gate["outputs"]["sandbox_base_image_ref"].removeprefix(
        "${{ "
    ).removesuffix(" }}")
    assert "steps.verify-images.outputs.browser_image_ref" == gate["outputs"]["sandbox_browser_image_ref"].removeprefix(
        "${{ "
    ).removesuffix(" }}")

    base_ref = "${{ needs.gate.outputs.sandbox_base_image_ref }}"
    browser_ref = "${{ needs.gate.outputs.sandbox_browser_image_ref }}"
    steps = build["steps"]
    pull = next(step for step in steps if step.get("name") == "Pull cosign-verified sandbox image digests")
    assert pull["env"] == {"BASE_IMAGE_REF": base_ref, "BROWSER_IMAGE_REF": browser_ref}
    assert 'docker pull "$BASE_IMAGE_REF"' in pull["run"]
    assert 'docker pull "$BROWSER_IMAGE_REF"' in pull["run"]

    expected = {
        "SBOM (sandbox base image, Syft)": ("image", base_ref),
        "SBOM (sandbox browser image, Syft)": ("image", browser_ref),
        "Scan sandbox base image (Trivy, HIGH/CRITICAL fail gate)": ("image-ref", base_ref),
        "Scan sandbox browser image (Trivy, HIGH/CRITICAL fail gate)": ("image-ref", browser_ref),
    }
    for name, (field, image_ref) in expected.items():
        step = next(step for step in steps if step.get("name") == name)
        assert step["with"][field] == image_ref
        if "Trivy" in name:
            assert step["with"]["exit-code"] == "1"

    artifact = next(step for step in steps if step.get("name") == "Upload release assets")
    for filename in (
        "sbom-sandbox.json",
        "sbom-sandbox-browser.json",
        "sandbox-image-refs.txt",
        "trivy-sandbox-base.sarif",
        "trivy-sandbox-browser.sarif",
    ):
        assert filename in artifact["with"]["path"]


def test_published_browser_worker_inherits_same_run_base_digest():
    """A clean Buildx runner must use the pushed base, never an absent local tag."""
    workflow = yaml.safe_load((REPO / ".github/workflows/sandbox-image.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build-push-sign"]["steps"]
    base = next(step for step in steps if step.get("id") == "base")
    browser = next(step for step in steps if step.get("id") == "browser")
    assert steps.index(base) < steps.index(browser)
    assert base["with"]["push"] is True
    arguments = dict(line.split("=", 1) for line in browser["with"]["build-args"].splitlines() if line.strip())
    assert (
        arguments["BASE_WORKER_IMAGE"] == "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.base.outputs.digest }}"
    )
    instructions = [
        line.strip()
        for line in (REPO / "docker/sandbox/Dockerfile.browser").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert instructions[:2] == ["ARG BASE_WORKER_IMAGE=breachpilot-sandbox:latest", "FROM ${BASE_WORKER_IMAGE}"]


def test_secret_bearing_manual_jobs_are_restricted_to_main():
    for workflow_name, job_name in (("eval.yml", "nightly-eval"), ("benchmark.yml", "nightly-live-benchmark")):
        workflow = yaml.safe_load((REPO / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8"))
        condition = workflow["jobs"][job_name]["if"]
        assert "github.ref == 'refs/heads/main'" in condition
        assert "github.event_name == 'workflow_dispatch'" in condition


def test_release_installer_paths_validate_ref_before_using_step_output():
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build"]["steps"]
    freeze = next(step for step in steps if step.get("id") == "freeze-installer")
    assert freeze["env"]["RELEASE_REF_NAME"] == "${{ github.ref_name }}"
    assert "${{ github.ref_name }}" not in freeze["run"]
    assert '[[ ! "$release_tag" =~ ^v[0-9]+(\\.[0-9]+){2}' in freeze["run"]
    assert 'cp install.sh "$installer_prefix.sh"' in freeze["run"]
    attestation = next(step for step in steps if step.get("name") == "Attest installer provenance (TODO 013)")
    assert "${{ steps.freeze-installer.outputs.installer_prefix }}" in attestation["with"]["subject-path"]


def test_python_sbom_targets_isolated_installed_wheel_environment():
    """SBOM inventory must describe wheel dependencies, not release tooling."""
    workflow = yaml.safe_load((REPO / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build"]["steps"]
    sbom = next(step for step in steps if step.get("name") == "SBOM (Python, CycloneDX)")
    commands = [
        shlex.split(line) for line in sbom["run"].splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    create = next(
        command for command in commands if command[:4] == ["python", "-m", "venv", "$RUNNER_TEMP/breachpilot-runtime"]
    )
    python = f"{create[3]}/bin/python"
    install = next(command for command in commands if command[:4] == [python, "-m", "pip", "install"])
    assert "dist/*.whl" in install
    assert install[install.index("-c") + 1] == "constraints-dev.txt"
    assert not any(item in install for item in ("build", "twine", "cyclonedx-bom", ".[dev]"))
    inventory = next(command for command in commands if command[:4] == ["python", "-m", "cyclonedx_py", "environment"])
    assert inventory[4] == python
    assert inventory[inventory.index("--output-file") + 1] == "sbom-python.json"
    assert commands.index(create) < commands.index(install) < commands.index(inventory)


def test_installer_verifier_fails_closed_on_missing_attestation(tmp_path):
    installer = tmp_path / "install.sh"
    installer.write_text("echo safe\n", encoding="utf-8")
    checksum = tmp_path / "install.sh.sha256"
    checksum.write_text(f"{hashlib.sha256(installer.read_bytes()).hexdigest()}  install.sh\n", encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_gh.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"}
    script = REPO / "scripts" / "verify-installer.sh"

    verified = subprocess.run(
        ["/bin/bash", str(script), str(installer), str(checksum)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    checksum_only = subprocess.run(
        ["/bin/bash", str(script), "--checksum-only", str(installer), str(checksum)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert verified.returncode != 0
    assert "attestation verification failed" in verified.stderr
    assert checksum_only.returncode == 0
    assert "checksum-only mode" in checksum_only.stderr
