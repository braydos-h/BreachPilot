//! bp-sidecar: loopback TCP server speaking the v1 JSON IPC envelope.
//! Ops: health, exec. One JSON object per line. Version mismatch => error.

use bp_exec::{execute, ExecRequest};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

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
                    Err(e) => {
                        let code = match e {
                            bp_exec::ExecError::ScopeDenied(_) => "SANDBOX_SCOPE_DENIED",
                            bp_exec::ExecError::Timeout => "SANDBOX_TIMEOUT",
                            bp_exec::ExecError::Spawn(_) => "SANDBOX_SPAWN_FAILED",
                        };
                        RespEnvelope {
                            version: "v1",
                            id: env.id,
                            ok: false,
                            result: None,
                            error: Some(ErrBody {
                                code,
                                message: e.to_string(),
                            }),
                        }
                    }
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
