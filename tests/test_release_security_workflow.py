"""Regression checks for credential separation in privileged workflows."""

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow(path: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_release_build_and_publisher_permissions_are_separated() -> None:
    workflow = _workflow(".github/workflows/release.yml")
    jobs = workflow["jobs"]
    build = jobs["build"]
    attest = jobs["attest"]
    publish = jobs["publish"]

    assert workflow["permissions"] == {"contents": "read"}
    assert build["permissions"] == {"contents": "read", "actions": "read", "packages": "read"}
    assert attest["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert publish["permissions"] == {"contents": "write"}
    assert set(publish["needs"]) == {"gate", "build", "attest"}
    assert not any(step.get("uses", "").startswith("actions/checkout@") for step in publish["steps"])
    for job in (jobs["gate"], build):
        checkout_steps = [step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")]
        assert checkout_steps
        assert all(step.get("with", {}).get("persist-credentials") is False for step in checkout_steps)


def test_live_eval_secret_is_scoped_to_invocation_steps() -> None:
    workflow = _workflow(".github/workflows/eval.yml")
    job = workflow["jobs"]["nightly-eval"]

    assert "OLLAMA_API_KEY" not in job.get("env", {})
    assert workflow["permissions"]["actions"] == "read"
    triggers = workflow.get("on", workflow.get(True, {}))
    assert triggers["workflow_dispatch"]["inputs"]["baseline_mode"]["options"] == ["check", "initialize"]
    credential_steps = [step for step in job["steps"] if step.get("id") == "credentials"]
    assert len(credential_steps) == 1
    assert credential_steps[0]["env"]["OLLAMA_API_KEY"] == "${{ secrets.OLLAMA_API_KEY }}"

    baseline_restore = next(step for step in job["steps"] if step.get("id") == "baseline")
    assert "gh run download" in baseline_restore["run"]
    assert "gh run list" in baseline_restore["run"]
    eval_steps = [step for step in job["steps"] if "python main.py --eval" in step.get("run", "")]
    assert len(eval_steps) == 1
    assert "--check-regression" in eval_steps[0]["run"]
    assert "BASELINE_MODE" in eval_steps[0]["run"]
    assert "--save-baseline" in eval_steps[0]["run"]

    key_users = [step for step in job["steps"] if "OLLAMA_API_KEY" in step.get("env", {})]
    assert {step["name"] for step in key_users} == {
        "Check whether live eval credentials are configured",
        "Run graded eval and regression gate",
        "Single-trial XBEN lab smoke (host targets do not support automatic reset)",
    }


def test_sandbox_digest_guide_pins_the_workflow_identity() -> None:
    workflow = (ROOT / ".github/workflows/sandbox-image.yml").read_text(encoding="utf-8")

    assert ".github/workflows/sandbox-image.yml@$WORKFLOW_REF" in workflow
    assert "--certificate-identity-regexp '.*'" not in workflow


def test_release_gate_uses_run_scoped_cross_workflow_artifacts_and_ci_admission() -> None:
    workflow = _workflow(".github/workflows/release.yml")
    jobs = workflow["jobs"]
    gate = jobs["gate"]
    assert gate["permissions"]["actions"] == "read"
    assert gate["permissions"]["administration"] == "read"
    assert "actions:read" in gate["steps"][1]["run"] or "gh run list --workflow ci.yml" in gate["steps"][1]["run"]

    downloads = [step for step in gate["steps"] if step.get("uses", "").startswith("actions/download-artifact@")]
    assert {step["with"]["name"] for step in downloads} == {"sandbox-digests"}
    eval_download = next(step for step in gate["steps"] if "gh run download" in step.get("run", ""))
    assert "--name eval-reports" in eval_download["run"]
    assert "EVAL_RUN_IDS" in eval_download.get("env", {})
    assert "--limit 100" in next(step for step in gate["steps"] if "--status success" in step.get("run", ""))["run"]
    assert (
        "--source-revision $GITHUB_SHA"
        in next(step for step in gate["steps"] if "Run release gate" in step.get("name", ""))["run"]
    )
    assert any(
        "refs/tags/v" in step.get("run", "") and "merge-base --is-ancestor" in step.get("run", "")
        for step in gate["steps"]
    )
    evidence = next(step for step in gate["steps"] if step.get("id") == "evidence")
    assert 'r.get("headSha")==sha' in evidence["run"]
    assert "Selected exact-source evidence" in evidence["run"]

    sandbox_run = jobs["build"]["steps"]
    assert any(step.get("with", {}).get("name") == "sandbox-digests" for step in sandbox_run)
    scan = next(
        step for step in sandbox_run if step.get("name") == "Verify and pull the tag-built digest-pinned worker image"
    )
    assert "cosign verify" in scan["run"]
    assert 'docker pull "$base_ref"' in scan["run"]
    assert "@$WORKFLOW_REF" in scan["run"]


def test_python_sbom_uses_the_built_wheels_runtime_dependency_graph() -> None:
    workflow = _workflow(".github/workflows/release.yml")
    steps = workflow["jobs"]["build"]["steps"]
    resolve = next(step for step in steps if step.get("name") == "Resolve the shipped Python runtime dependency graph")
    assert "pip install" in resolve["run"] and "dist/breachpilot-*.whl" in resolve["run"]
    assert "-c constraints-dev.txt" in resolve["run"]
    assert "pip freeze > python-runtime-requirements.txt" in resolve["run"]

    sbom = next(step for step in steps if step.get("name") == "SBOM (Python, CycloneDX)")
    assert "requirements python-runtime-requirements.txt" in sbom["run"]
    assert "environment" not in sbom["run"]


def test_privileged_workflows_reject_untrusted_refs_and_avoid_ref_shell_interpolation() -> None:
    sandbox = _workflow(".github/workflows/sandbox-image.yml")
    image_job = sandbox["jobs"]["build-push-sign"]
    assert image_job["permissions"]["packages"] == "write"
    assert image_job["permissions"]["id-token"] == "write"
    checkout = next(step for step in image_job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    assert any(
        "merge-base --is-ancestor" in step.get("run", "") and "gh run list --workflow ci.yml" in step.get("run", "")
        for step in image_job["steps"]
    )
    assert any("BASE_IMAGE=" in step.get("with", {}).get("build-args", "") for step in image_job["steps"])

    dockerfile = (ROOT / "docker/sandbox/Dockerfile.browser").read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE=breachpilot-sandbox:latest" in dockerfile
    assert "FROM ${BASE_IMAGE}" in dockerfile

    for path in (".github/workflows/release.yml", ".github/workflows/sandbox-image.yml"):
        workflow = _workflow(path)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                body = step.get("run", "")
                assert "${{ github.ref }}" not in body
                assert "${{ github.ref_name }}" not in body

    for path, job_name in (
        (".github/workflows/eval.yml", "nightly-eval"),
        (".github/workflows/benchmark.yml", "nightly-live-benchmark"),
    ):
        job = _workflow(path)["jobs"][job_name]
        assert "github.ref == 'refs/heads/main'" in job["if"]
