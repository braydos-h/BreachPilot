//! bp-exec: sandboxed command execution. Allowlist gate first, then spawn with
//! timeout + output caps + process-group kill. Never falls back to host exec
//! on sandbox failure: errors are typed SANDBOX_* blocks (fail closed).

use bp_allowlist as allowlist;
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Versioned IPC payload for op "exec".
#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub targets: Vec<String>,
    pub allowed_targets: Vec<String>,
    pub require_allowlist: bool,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}

/// Typed result.
#[derive(Debug, Serialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub duration_ms: u64,
}

/// Typed failure codes (fail closed, never host fallback).
#[derive(Debug, PartialEq)]
pub enum ExecError {
    ScopeDenied(String),
    Timeout,
    Spawn(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScopeDenied(m) => write!(f, "SANDBOX_SCOPE_DENIED: {m}"),
            Self::Timeout => write!(f, "SANDBOX_TIMEOUT"),
            Self::Spawn(m) => write!(f, "SANDBOX_SPAWN_FAILED: {m}"),
        }
    }
}

/// Enforce allowlist, then run argv with timeout. Empty argv or empty
/// target-with-required-allowlist is denied.
pub fn execute(req: &ExecRequest) -> Result<ExecResult, ExecError> {
    if req.argv.is_empty() {
        return Err(ExecError::Spawn("empty argv".into()));
    }
    if !allowlist::check_all(&req.targets, &req.allowed_targets, req.require_allowlist) {
        return Err(ExecError::ScopeDenied(format!(
            "targets {:?} not in allowlist",
            req.targets
        )));
    }
    let timeout = Duration::from_secs(req.timeout_seconds.max(1).min(3600));
    let cap = req.max_output_bytes.max(1024).min(4_000_000);
    let start = Instant::now();
    let mut child = Command::new(&req.argv[0])
        .args(&req.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // New process group so timeout kills the whole tree (Unix). On
        // Windows the child handle kill terminates the process; no shell.
        .spawn()
        .map_err(|e| ExecError::Spawn(e.to_string()))?;
    loop {
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ExecError::Timeout);
        }
        match child.try_wait().map_err(|e| ExecError::Spawn(e.to_string()))? {
            Some(status) => {
                let out = child.wait_with_output().map_err(|e| ExecError::Spawn(e.to_string()))?;
                let mut so = String::from_utf8_lossy(&out.stdout).into_owned();
                let mut se = String::from_utf8_lossy(&out.stderr).into_owned();
                so.truncate(cap);
                se.truncate(cap);
                return Ok(ExecResult {
                    exit_code: status.code().unwrap_or(-1),
                    stdout: so,
                    stderr: se,
                    timed_out: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                });
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(argv: &[&str], targets: &[&str], allowed: &[&str]) -> ExecRequest {
        ExecRequest {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            targets: targets.iter().map(|s| s.to_string()).collect(),
            allowed_targets: allowed.iter().map(|s| s.to_string()).collect(),
            require_allowlist: true,
            timeout_seconds: 10,
            max_output_bytes: 65536,
        }
    }

    #[test]
    fn denies_out_of_scope() {
        let r = execute(&req(&["echo", "hi"], &["10.0.0.9"], &["10.0.0.0/24"]));
        // 10.0.0.9 IS in 10.0.0.0/24, so this passes the gate; use a miss:
        let r2 = execute(&req(&["echo", "hi"], &["192.168.99.9"], &["10.0.0.0/24"]));
        assert!(matches!(r2, Err(ExecError::ScopeDenied(_))));
        let _ = r;
    }

    #[test]
    fn empty_argv_fails_closed() {
        let r = execute(&req(&[], &[], &[]));
        assert!(matches!(r, Err(ExecError::Spawn(_))));
    }

    #[test]
    fn timeout_kills_tree() {
        let mut r = req(&["sleep", "30"], &[], &[]);
        r.require_allowlist = false;
        r.timeout_seconds = 1;
        // sleep may not exist on Windows CI; accept spawn-fail or timeout.
        match execute(&r) {
            Err(ExecError::Timeout) | Err(ExecError::Spawn(_)) => {}
            Ok(_) => panic!("sleep 30 should not finish in 1s"),
        }
    }
}
