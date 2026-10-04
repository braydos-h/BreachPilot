"""The root image build must not copy local credentials from its context."""

from pathlib import Path


def test_dockerignore_excludes_runtime_secrets_and_private_keys() -> None:
    patterns = set(Path(".dockerignore").read_text(encoding="utf-8").splitlines())

    assert ".webui_secret_key" in patterns
    assert ".vault_key" in patterns
    assert "secr.json" in patterns
    assert ".env" in patterns
    assert ".env.*" in patterns
    assert "!.env.example" in patterns
    assert "*.pem" in patterns
    assert "*.p12" in patterns
    assert "*.pfx" in patterns
    assert "id_rsa*" in patterns
    assert "id_ed25519*" in patterns
