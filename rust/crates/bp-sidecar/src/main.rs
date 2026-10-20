//! bp-sidecar: loopback TCP server speaking the v1 JSON IPC envelope.
//! Ops: health, exec, sandbox_status, sandbox_rules, sandbox_cleanup.
//! One JSON object per line. Version mismatch => error.

use bp_exec::sandbox::{
    build_firewall_ruleset, build_ipv6_rules, build_network_policy, CliDockerRunner, SandboxConfig,
    SandboxManager,
};
use bp_exec::{execute, ExecRequest};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Envelope {
    version: String,
    id: String,
    op: String,
    #[serde(default)]
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct RespEnvelope {
    version: &'static str,
    id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrBody>,
}

#[derive(Serialize)]
struct ErrBody {
    code: &'static str,
    message: String,
}

#[derive(Deserialize, Default)]
struct RulesRequest {
    #[serde(default)]
    allowed_targets: Vec<String>,
    #[serde(default)]
    gateway: String,
}

fn handle(env: Envelope) -> RespEnvelope {
    if env.version != "v1" {
        return RespEnvelope {
            version: "v1",
            id: env.id,
            ok: false,
            result: None,
            error: Some(ErrBody {
                code: "SANDBOX_INVALID",
                message: "version must be v1".into(),
            }),
        };
    }
    match env.op.as_str() {
        "health" => RespEnvelope {
            version: "v1",
            id: env.id,
            ok: true,
            result: Some(serde_json::json!({"status": "ok"})),
            error: None,
        },
        "sandbox_status" => {
            let cfg = SandboxConfig::default();
            let mgr =
                SandboxManager::new(cfg.clone(), std::env::temp_dir(), "probe", CliDockerRunner);
            let (docker_ok, docker_info) = match mgr.ensure_docker() {
                Ok(v) => (true, v),
                Err(e) => (false, e.to_string()),
            };
            let image_ok = docker_ok && mgr.ensure_image().is_ok();
            RespEnvelope {
                version: "v1",
                id: env.id,
                ok: true,
                result: Some(serde_json::json!({
                    "docker_available": docker_ok,
                    "docker_info": docker_info,
                    "image": cfg.image,
                    "image_present": image_ok,
                    "isolated_ready": docker_ok && image_ok,
                })),
                error: None,
            }
        }
        "sandbox_rules" => {
            let req: RulesRequest = serde_json::from_value(env.payload).unwrap_or_default();
            let cfg = SandboxConfig::default();
            match build_network_policy(&cfg, &req.allowed_targets, &req.gateway, |_| vec![]) {
                Ok(pol) => RespEnvelope {
                    version: "v1",
                    id: env.id,
                    ok: true,
                    result: Some(serde_json::json!({
                        "fingerprint": pol.fingerprint(),
                        "ipv4_rules": build_firewall_ruleset(&pol, &req.gateway),
                        "ipv6_rules": build_ipv6_rules(&pol).join("\n") + "\n",
                        "authorized_destinations": pol.authorized_destinations,
                        "explicitly_blocked": pol.explicitly_blocked,
                    })),
                    error: None,
                },
                Err(e) => RespEnvelope {
                    version: "v1",
                    id: env.id,
                    ok: false,
                    result: None,
                    error: Some(ErrBody {
                        code: e.code(),
                        message: e.to_string(),
                    }),
                },
            }
        }
        "sandbox_cleanup" => {
            let cfg = SandboxConfig::default();
            let mgr = SandboxManager::new(cfg, PathBuf::from("."), "cleanup", CliDockerRunner);
            let removed = mgr.cleanup_stale();
            RespEnvelope {
                version: "v1",
                id: env.id,
                ok: true,
                result: Some(serde_json::json!({"removed": removed})),
                error: None,
            }
        }
        "exec" => {
            let req: Result<ExecRequest, _> = serde_json::from_value(env.payload);
            match req {
                Err(e) => RespEnvelope {
                    version: "v1",
                    id: env.id,
                    ok: false,
                    result: None,
                    error: Some(ErrBody {
                        code: "SANDBOX_INVALID",
                        message: e.to_string(),
                    }),
                },
                Ok(r) => match execute(&r) {
                    Ok(res) => RespEnvelope {
                        version: "v1",
                        id: env.id,
                        ok: true,
                        result: Some(serde_json::json!(res)),
                        error: None,
                    },
                    Err(e) => RespEnvelope {
                        version: "v1",
                        id: env.id,
                        ok: false,
                        result: None,
                        error: Some(ErrBody {
                            code: e.code(),
                            message: e.to_string(),
                        }),
                    },
                },
            }
        }
        _ => RespEnvelope {
            version: "v1",
            id: env.id,
            ok: false,
            result: None,
            error: Some(ErrBody {
                code: "SANDBOX_INVALID",
                message: "unknown op".into(),
            }),
        },
    }
}

fn main() {
    let addr = std::env::var("BP_SIDECAR_ADDR").unwrap_or_else(|_| "127.0.0.1:18765".into());
    let listener = TcpListener::bind(&addr).expect("bind sidecar");
    for conn in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            let mut writer = conn;
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let env: Result<Envelope, _> = serde_json::from_str(&line);
                let resp = match env {
                    Ok(e) => handle(e),
                    Err(e) => RespEnvelope {
                        version: "v1",
                        id: String::new(),
                        ok: false,
                        result: None,
                        error: Some(ErrBody {
                            code: "SANDBOX_INVALID",
                            message: e.to_string(),
                        }),
                    },
                };
                let mut out = serde_json::to_string(&resp).unwrap();
                out.push('\n');
                if writer.write_all(out.as_bytes()).is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_sandbox_rules_and_rejects_wildcard_all() {
        let ok_resp = handle(Envelope {
            version: "v1".into(),
            id: "1".into(),
            op: "sandbox_rules".into(),
            payload: serde_json::json!({
                "allowed_targets": ["10.0.0.5"],
                "gateway": "172.18.0.1"
            }),
        });
        assert!(ok_resp.ok);
        let rules = ok_resp
            .result
            .unwrap()
            .get("ipv4_rules")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert!(rules.contains("-A NAI-OUTPUT -d 10.0.0.5 -j ACCEPT"));
        assert!(rules.contains("-A NAI-OUTPUT -j DROP"));

        let bad_resp = handle(Envelope {
            version: "v1".into(),
            id: "2".into(),
            op: "sandbox_rules".into(),
            payload: serde_json::json!({
                "allowed_targets": ["0.0.0.0/0"]
            }),
        });
        assert!(!bad_resp.ok);
        assert_eq!(bad_resp.error.unwrap().code, "SANDBOX_POLICY_FAILED");
    }
}
