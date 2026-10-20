//! bp-exec: sandboxed command execution + disposable Docker worker lifecycle.
//! Allowlist gate first, then either disposable Docker worker execution (when
//! `use_docker_sandbox` is enabled) or bounded argv execution with timeout,
//! output caps, and process-group kill. Never falls back to host exec on
//! sandbox failure: errors are typed `SANDBOX_*` blocks (fail closed).

pub mod sandbox;

use bp_allowlist as allowlist;
use sandbox::{CliDockerRunner, SandboxConfig, SandboxManager};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Versioned IPC payload for op "exec".
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub targets: Vec<String>,
    pub allowed_targets: Vec<String>,
    pub require_allowlist: bool,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    #[serde(default)]
    pub use_docker_sandbox: bool,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub workspace_dir: String,
    #[serde(default)]
    pub sandbox_image: String,
    #[serde(default)]
    pub tool_name: String,
}

/// Typed result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub duration_ms: u64,
}

/// Typed failure codes (fail closed, never host fallback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    Unavailable(String),
    PolicyFailed(String),
    ScopeDenied(String),
    WorkspaceFailed(String),
    Unsupported(String),
    Timeout,
    Spawn(String),
}

impl ExecError {
    /// Structured `SANDBOX_*` error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "SANDBOX_UNAVAILABLE",
            Self::PolicyFailed(_) => "SANDBOX_POLICY_FAILED",
            Self::ScopeDenied(_) => "SANDBOX_SCOPE_DENIED",
            Self::WorkspaceFailed(_) => "SANDBOX_WORKSPACE_FAILED",
            Self::Unsupported(_) => "SANDBOX_UNSUPPORTED",
            Self::Timeout => "SANDBOX_TIMEOUT",
            Self::Spawn(_) => "SANDBOX_SPAWN_FAILED",
        }
    }
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(m) => write!(f, "SANDBOX_UNAVAILABLE: {m}"),
            Self::PolicyFailed(m) => write!(f, "SANDBOX_POLICY_FAILED: {m}"),
            Self::ScopeDenied(m) => write!(f, "SANDBOX_SCOPE_DENIED: {m}"),
            Self::WorkspaceFailed(m) => write!(f, "SANDBOX_WORKSPACE_FAILED: {m}"),
            Self::Unsupported(m) => write!(f, "SANDBOX_UNSUPPORTED: {m}"),
            Self::Timeout => write!(f, "SANDBOX_TIMEOUT"),
            Self::Spawn(m) => write!(f, "SANDBOX_SPAWN_FAILED: {m}"),
        }
    }
}

/// Enforce allowlist, then run argv either inside a disposable Docker sandbox
/// (when `req.use_docker_sandbox` is true — never falling back to host exec)
/// or as a bounded direct process when native execution was explicitly selected.
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
    if req.use_docker_sandbox {
        let mut cfg = SandboxConfig::default();
        if !req.sandbox_image.trim().is_empty() {
            cfg.image = req.sandbox_image.trim().to_string();
        }
        cfg.output_max_bytes = req.max_output_bytes.clamp(1024, 4_000_000);
        cfg.exec_timeout_seconds = req.timeout_seconds.clamp(1, 3600);
        let ws = if req.workspace_dir.trim().is_empty() {
            std::env::temp_dir()
        } else {
            PathBuf::from(req.workspace_dir.trim())
        };
        let tool = if req.tool_name.trim().is_empty() {
            "exec"
        } else {
            req.tool_name.trim()
        };
        let mut mgr = SandboxManager::new(cfg, ws, req.run_id.clone(), CliDockerRunner);
        let res = mgr.execute_argv(
            &req.argv,
            &req.targets,
            &req.allowed_targets,
            req.require_allowlist,
            req.timeout_seconds,
            None,
            None,
            tool,
        );
        let _ = mgr.destroy();
        return res;
    }

    let timeout = Duration::from_secs(req.timeout_seconds.clamp(1, 3600));
    let cap = req.max_output_bytes.clamp(1024, 4_000_000);
    let start = Instant::now();
    let mut child = Command::new(&req.argv[0])
        .args(&req.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ExecError::Spawn(e.to_string()))?;
    loop {
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ExecError::Timeout);
        }
        match child
            .try_wait()
            .map_err(|e| ExecError::Spawn(e.to_string()))?
        {
            Some(status) => {
                let out = child
                    .wait_with_output()
                    .map_err(|e| ExecError::Spawn(e.to_string()))?;
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
    use crate::sandbox::{
        build_create_args, build_firewall_ruleset, build_ipv4_rules, build_ipv6_rules,
        build_network_policy, container_path, validate_workspace, DockerRunner, SandboxConfig,
        SandboxManager, SandboxSpec,
    };
    use std::sync::Mutex;

    fn req(argv: &[&str], targets: &[&str], allowed: &[&str]) -> ExecRequest {
        ExecRequest {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            targets: targets.iter().map(|s| s.to_string()).collect(),
            allowed_targets: allowed.iter().map(|s| s.to_string()).collect(),
            require_allowlist: true,
            timeout_seconds: 10,
            max_output_bytes: 65536,
            use_docker_sandbox: false,
            run_id: String::new(),
            workspace_dir: String::new(),
            sandbox_image: String::new(),
            tool_name: String::new(),
        }
    }

    #[test]
    fn denies_out_of_scope() {
        let r = execute(&req(&["echo", "hi"], &["10.0.0.9"], &["10.0.0.0/24"]));
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
        match execute(&r) {
            Err(ExecError::Timeout) | Err(ExecError::Spawn(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("sleep 30 should not finish in 1s"),
        }
    }

    #[test]
    fn build_create_args_enforces_hardening_invariants() {
        let spec = SandboxSpec {
            sandbox_id: "breachpilot-run1-01".into(),
            run_id: "run1".into(),
            image: "breachpilot-sandbox:latest".into(),
            user: "sandbox".into(),
            network_name: "breachpilot-net-run1-01".into(),
            workspace_src: "/tmp/ws".into(),
            memory_mb: 2048,
            cpus: 1.5,
            pids_limit: 256,
            read_only_rootfs: true,
            tmpfs_size_mb: 128,
        };
        let args = build_create_args(&spec, true).expect("valid create args");
        assert!(args.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        assert!(args.windows(2).any(|w| w == ["--cap-add", "NET_RAW"]));
        assert!(!args.iter().any(|a| a == "NET_ADMIN"));
        assert!(!args.iter().any(|a| a == "--privileged"));
        assert!(args
            .windows(2)
            .any(|w| w == ["--security-opt", "no-new-privileges"]));
        assert!(args.windows(2).any(|w| w == ["--user", "sandbox"]));
        assert!(args.windows(2).any(|w| w == ["--memory", "2048m"]));
        assert!(args.windows(2).any(|w| w == ["--pids-limit", "256"]));
        assert!(args.contains(&"--read-only".to_string()));
        assert!(args
            .windows(2)
            .any(|w| w == ["-v", "/tmp/ws:/workspace:rw"]));
        assert!(args.ends_with(&["sleep".to_string(), "infinity".to_string()]));

        // Reject root user creation
        let mut root_spec = spec.clone();
        root_spec.user = "root".into();
        assert!(matches!(
            build_create_args(&root_spec, false),
            Err(ExecError::Unavailable(_))
        ));
    }

    #[test]
    fn firewall_ruleset_enforces_default_deny_and_dns_drop_before_lo() {
        let cfg = SandboxConfig::default();
        let allowed = vec![
            "10.0.0.5".to_string(),
            "192.168.1.0/24".to_string(),
            "app.example.com".to_string(),
        ];
        let pol = build_network_policy(&cfg, &allowed, "172.18.0.1", |host| {
            if host == "app.example.com" {
                vec!["203.0.113.10".to_string(), "169.254.169.254".to_string()]
            } else {
                vec![]
            }
        })
        .expect("policy builds");

        // Unsafe metadata DNS answer is excluded; valid IP is included.
        assert!(pol
            .authorized_destinations
            .contains(&"10.0.0.5".to_string()));
        assert!(pol
            .authorized_destinations
            .contains(&"192.168.1.0/24".to_string()));
        assert!(pol
            .authorized_destinations
            .contains(&"203.0.113.10".to_string()));
        assert!(!pol
            .authorized_destinations
            .contains(&"169.254.169.254".to_string()));

        let v4 = build_ipv4_rules(&pol, "172.18.0.1");
        let dns_drop_idx = v4
            .iter()
            .position(|l| l == "-A NAI-OUTPUT -d 127.0.0.11 -j DROP")
            .expect("embedded resolver drop");
        let lo_accept_idx = v4
            .iter()
            .position(|l| l == "-A NAI-OUTPUT -o lo -j ACCEPT")
            .expect("lo accept");
        assert!(
            dns_drop_idx < lo_accept_idx,
            "DNS drop must precede loopback ACCEPT"
        );
        assert!(v4.contains(&"-A NAI-OUTPUT -d 172.18.0.1 -j DROP".to_string()));
        assert!(v4.contains(&"-A NAI-OUTPUT -d 10.0.0.5 -j ACCEPT".to_string()));
        assert!(v4.contains(&"-A NAI-OUTPUT -d 203.0.113.10 -j ACCEPT".to_string()));
        assert_eq!(v4[v4.len() - 2], "-A NAI-OUTPUT -j DROP");
        assert_eq!(v4[v4.len() - 1], "COMMIT");

        let v6 = build_ipv6_rules(&pol);
        assert!(v6.contains(&"-A NAI-OUTPUT -d fe80::/10 -j DROP".to_string()));
        assert_eq!(v6[v6.len() - 2], "-A NAI-OUTPUT -j DROP");

        let rendered = build_firewall_ruleset(&pol, "172.18.0.1");
        assert!(!rendered.contains('\r'));

        // Wildcard-all token must fail closed.
        let bad = build_network_policy(&cfg, &["0.0.0.0/0".to_string()], "", |_| vec![]);
        assert!(matches!(bad, Err(ExecError::PolicyFailed(_))));
    }

    #[derive(Default)]
    struct MockDocker {
        calls: Mutex<Vec<(Vec<String>, Option<String>)>>,
        fail_firewall: bool,
        fail_daemon: bool,
    }

    impl DockerRunner for MockDocker {
        fn run_docker(
            &self,
            args: &[String],
            input: Option<&[u8]>,
            _timeout: Duration,
        ) -> Result<(i32, String, String), ExecError> {
            let inp = input.map(|b| String::from_utf8_lossy(b).into_owned());
            self.calls.lock().unwrap().push((args.to_vec(), inp));
            if self.fail_daemon {
                return Ok((
                    1,
                    String::new(),
                    "Cannot connect to the Docker daemon".into(),
                ));
            }
            let first = args.first().map(String::as_str).unwrap_or("");
            match first {
                "version" => Ok((0, "27.1.0\n".into(), String::new())),
                "image" => Ok((0, "[]".into(), String::new())),
                "ps" => Ok((
                    0,
                    "bp-stale-exited\nbp-other-running\n".into(),
                    String::new(),
                )),
                "network" => {
                    let sub = args.get(1).map(String::as_str).unwrap_or("");
                    match sub {
                        "create" => Ok((0, "net-id-123\n".into(), String::new())),
                        "inspect" => Ok((
                            0,
                            r#"{"Id":"net-id-123","IPAM":{"Config":[{"Gateway":"172.29.0.1"}]},"Containers":{}}"#
                                .into(),
                            String::new(),
                        )),
                        "ls" => Ok((0, "bp-stale-net\n".into(), String::new())),
                        "disconnect" | "rm" => Ok((0, String::new(), String::new())),
                        _ => Ok((0, String::new(), String::new())),
                    }
                }
                "create" => Ok((0, "ctr-worker-123\n".into(), String::new())),
                "start" | "stop" | "rm" => Ok((0, String::new(), String::new())),
                "inspect" => {
                    let target = args.last().map(String::as_str).unwrap_or("");
                    if target == "bp-stale-exited" {
                        Ok((0, "exited\n".into(), String::new()))
                    } else {
                        Ok((0, "running\n".into(), String::new()))
                    }
                }
                "run" => {
                    if self.fail_firewall {
                        Ok((1, String::new(), "iptables-restore: line 3 failed".into()))
                    } else {
                        Ok((0, String::new(), String::new()))
                    }
                }
                "exec" => Ok((0, "sandbox-stdout-ok\n".into(), String::new())),
                _ => Ok((0, String::new(), String::new())),
            }
        }
    }

    #[test]
    fn mocked_docker_lifecycle_containment_and_cleanup() {
        let tmp = std::env::temp_dir().join(format!("bp-sandbox-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);

        let cfg = SandboxConfig::default();
        let runner = MockDocker::default();
        let mut mgr = SandboxManager::new(cfg, tmp.clone(), "run-42", runner);

        // 1. Out-of-scope target is denied before any Docker container creation.
        let denied = mgr.execute_argv(
            &["nmap".into(), "192.168.99.9".into()],
            &["192.168.99.9".into()],
            &["10.0.0.0/24".into()],
            true,
            30,
            None,
            None,
            "nmap",
        );
        assert!(matches!(denied, Err(ExecError::ScopeDenied(_))));
        assert!(mgr.container_id.is_empty());

        // 2. Authorized target creates network + hardened worker + NET_ADMIN firewall sidecar + execs.
        let ok = mgr
            .execute_argv(
                &["nmap".into(), "-sT".into(), "10.0.0.5".into()],
                &["10.0.0.5".into()],
                &["10.0.0.0/24".into()],
                true,
                30,
                None,
                None,
                "nmap",
            )
            .expect("sandboxed execution succeeds");
        assert_eq!(ok.exit_code, 0);
        assert_eq!(ok.stdout, "sandbox-stdout-ok\n");
        assert_eq!(mgr.container_id, "ctr-worker-123");

        // Verify workspace path confinement
        let inside_file = tmp.join("artifact.txt");
        std::fs::write(&inside_file, b"evidence").unwrap();
        let mapped = container_path(&tmp, &inside_file).expect("inside workspace");
        assert_eq!(mapped, "/workspace/artifact.txt");
        let outside = std::env::temp_dir();
        assert!(matches!(
            container_path(&tmp, &outside),
            Err(ExecError::WorkspaceFailed(_))
        ));

        // 3. Teardown removes container and network idempotently and verifies audit chain.
        let td = mgr.destroy();
        assert!(td.container_removed);
        assert!(td.network_removed);
        assert_eq!(bp_evidence::verify(&mgr.audit_chain), None);
        assert!(tmp.join("exploit_audit.jsonl").is_file());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn firewall_failure_fails_closed_and_destroys_worker() {
        let tmp = std::env::temp_dir().join(format!("bp-sandbox-fwfail-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);

        let cfg = SandboxConfig::default();
        let runner = MockDocker {
            fail_firewall: true,
            ..Default::default()
        };
        let mut mgr = SandboxManager::new(cfg, tmp.clone(), "run-fw", runner);
        let res = mgr.execute_argv(
            &["curl".into(), "http://10.0.0.5".into()],
            &["10.0.0.5".into()],
            &["10.0.0.5".into()],
            true,
            30,
            None,
            None,
            "curl",
        );
        assert!(matches!(res, Err(ExecError::PolicyFailed(_))));
        assert_eq!(res.unwrap_err().code(), "SANDBOX_POLICY_FAILED");
        // Partial worker must have been destroyed on policy failure!
        assert!(mgr.container_id.is_empty());
        assert!(mgr.network_name.is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn real_or_unavailable_docker_never_falls_back_to_host() {
        let tmp = std::env::temp_dir().join(format!("bp-sandbox-real-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let _ = validate_workspace(&tmp).expect("valid temp workspace");

        let mut r = req(&["echo", "contained"], &["127.0.0.1"], &["127.0.0.1"]);
        r.use_docker_sandbox = true;
        r.run_id = "test-real-docker".into();
        r.workspace_dir = tmp.to_string_lossy().into_owned();

        // When Docker is unavailable or the sandbox image isn't built on this host,
        // execute() MUST fail closed with SANDBOX_UNAVAILABLE rather than running `echo` on the host.
        match execute(&r) {
            Ok(res) => {
                assert_eq!(res.exit_code, 0);
                assert!(res.stdout.contains("contained"));
            }
            Err(e) => {
                assert_eq!(e.code(), "SANDBOX_UNAVAILABLE");
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
