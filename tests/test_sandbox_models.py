"""Unit tests for sandbox configuration parsing (tools/sandbox/models.py).

Security invariants covered:
- Missing ``sandbox`` section => CONTAINED defaults (never silent host mode;
  disabling containment is rejected).
- Present-but-partial section => fail-closed defaults (enforce, fail_closed,
  read_only_rootfs), never silently uncontained.
- Garbage values fall back to safe defaults instead of crashing.
- Resource limits always stay above sane minimums.
"""

from __future__ import annotations

import pytest

from tools.sandbox.models import SandboxConfig


class TestSandboxConfigFromConfig:
    def test_missing_section_means_contained(self):
        cfg = SandboxConfig.from_config({})
        assert cfg.enabled is True
        assert cfg.network_enforce is True  # defaults stay fail-closed
        assert cfg.network_fail_closed is True

    def test_none_config_means_contained(self):
        assert SandboxConfig.from_config(None).enabled is True

    def test_explicit_disabled_is_rejected(self):
        with pytest.raises(ValueError, match="sandbox.enabled=false is unsafe"):
            SandboxConfig.from_config({"sandbox": {"enabled": False}})

    def test_native_fallback_is_rejected(self):
        with pytest.raises(ValueError, match="sandbox.fallback_native is unsupported"):
            SandboxConfig.from_config({"sandbox": {"enabled": True, "fallback_native": True}})

    def test_enabled_section_parses(self):
        cfg = SandboxConfig.from_config(
            {
                "sandbox": {
                    "enabled": True,
                    "backend": "docker",
                    "image": "breachpilot-sandbox:latest",
                    "user": "sandbox",
                    "read_only_rootfs": True,
                    "env_passthrough": ["OLLAMA_HOST"],
                    "resources": {
                        "memory_mb": 2048,
                        "cpus": 1.5,
                        "pids": 256,
                        "timeout_seconds": 120,
                        "output_max_bytes": 100_000,
                    },
                    "network": {
                        "enforce": True,
                        "fail_closed": True,
                        "allow_dns": "controlled",
                        "map_host_loopback": False,
                        "extra_allow_cidrs": ["10.10.0.0/16"],
                        "allow_gateway": False,
                        "allow_research_hosts": False,
                    },
                    "cleanup": {"remove_on_exit": True, "remove_stale_on_startup": True},
                    "multi_net_raw": False,
                }
            }
        )
        assert cfg.enabled is True
        assert cfg.image == "breachpilot-sandbox:latest"
        assert cfg.user == "sandbox"
        assert cfg.read_only_rootfs is True
        assert cfg.env_passthrough == ["OLLAMA_HOST"]
        assert cfg.memory_mb == 2048
        assert cfg.cpus == 1.5
        assert cfg.pids_limit == 256
        assert cfg.exec_timeout_seconds == 120
        assert cfg.output_max_bytes == 100_000
        assert cfg.network_enforce is True
        assert cfg.allow_dns == "controlled"
        assert cfg.extra_allow_cidrs == ["10.10.0.0/16"]
        assert cfg.allow_research_hosts is False
        assert cfg.multi_net_raw is False

    def test_enforce_defaults_true_when_absent(self):
        # A present section without network.enforce must default to ENFORCED.
        cfg = SandboxConfig.from_config({"sandbox": {"enabled": True}})
        assert cfg.network_enforce is True
        assert cfg.network_fail_closed is True
        assert cfg.read_only_rootfs is True

    def test_garbage_values_fall_back_to_safe_defaults(self):
        cfg = SandboxConfig.from_config(
            {
                "sandbox": {
                    "enabled": "yes-please",
                    "resources": {"memory_mb": "huge", "cpus": None, "pids": -5},
                    "network": {"allow_dns": "wildcard-everything"},
                    "cleanup": {"remove_on_exit": "no"},
                }
            }
        )
        # bool garbage -> default (True for enabled: contained defaults)
        assert cfg.enabled is True
        assert cfg.memory_mb == 4096
        assert cfg.cpus == 2.0
        # pids below minimum falls back to the default, never 0/negative
        assert cfg.pids_limit == 512
        assert cfg.allow_dns == "controlled"
        assert cfg.remove_on_exit is True

    @pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
    def test_extra_allow_cidr_cannot_disable_target_lock(self, cidr):
        with pytest.raises(ValueError, match="authorizes all destinations"):
            SandboxConfig.from_config({"sandbox": {"network": {"extra_allow_cidrs": [cidr]}}})

    def test_disabling_network_enforcement_is_rejected(self):
        with pytest.raises(ValueError, match="network.enforce=false is unsafe"):
            SandboxConfig.from_config({"sandbox": {"enabled": True, "network": {"enforce": False}}})

    def test_disabling_fail_closed_behavior_is_rejected(self):
        with pytest.raises(ValueError, match="network.fail_closed=false is unsafe"):
            SandboxConfig.from_config({"sandbox": {"enabled": True, "network": {"fail_closed": False}}})
        assert SandboxConfig.from_config({"sandbox": {"enabled": True}}).network_fail_closed is True
        garbage = SandboxConfig.from_config({"sandbox": {"enabled": True, "network": {"fail_closed": "sometimes"}}})
        assert garbage.network_fail_closed is True

    def test_raw_packet_capability_is_rejected(self):
        with pytest.raises(ValueError, match="multi_net_raw=true is unsafe"):
            SandboxConfig.from_config({"sandbox": {"enabled": True, "multi_net_raw": True}})
        with pytest.raises(ValueError, match="NET_RAW is disabled"):
            SandboxConfig(
                enabled=True,
                backend="docker",
                image="breachpilot-sandbox:latest",
                user="sandbox",
                read_only_rootfs=True,
                multi_net_raw=True,
            )

    def test_config_schema_default_is_enabled(self):
        # The shipped default (CONFIG_SCHEMA + config.yaml) enables the sandbox
        # with enforcement on: the documented secure-by-default posture.
        from tools.config.schema import CONFIG_SCHEMA

        sec = CONFIG_SCHEMA.get("sandbox", {})
        assert sec.get("enabled") is True
        assert sec.get("network", {}).get("enforce") is True
        assert sec.get("network", {}).get("fail_closed") is True
        assert sec.get("network", {}).get("map_host_loopback") is False
        assert sec.get("multi_net_raw") is False

    def test_config_yaml_and_schema_stay_in_sync(self):
        import yaml

        from tools.config.schema import CONFIG_SCHEMA

        with open("config.yaml", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        # Subset, not strict equality: the schema still carries the legacy
        # top-level ``chatgpt`` / ``opencode_go`` blocks (supported fallbacks
        # normalized by tools.config.loader.get_provider_config), but
        # config.yaml intentionally uses the modern ``providers.<id>`` layout.
        extra = sorted(set(cfg) - set(CONFIG_SCHEMA))
        assert not extra, f"config.yaml has top-level keys unknown to CONFIG_SCHEMA: {extra}"
