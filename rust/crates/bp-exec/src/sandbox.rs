//! Disposable Docker worker sandbox: container hardening, network-namespace
//! default-DROP firewall via ephemeral NET_ADMIN sidecar, workspace validation,
//! idempotent teardown, stale cleanup, cancellation, and hash-chained audit.
//!
//! Mirrors `tools/sandbox/{models,docker_backend,network,policy,manager}.py`.
//! Fail-closed: any Docker/image/policy/scope/workspace error returns a typed
//! `ExecError` (`SANDBOX_*`) and NEVER falls back to host execution.

use crate::{ExecError, ExecResult};
use bp_allowlist as allowlist;
use bp_evidence::{append as append_evidence, Record as EvidenceRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const CONTAINER_WORKSPACE: &str = "/workspace";
pub const EXEC_KILL_GRACE_SECONDS: u64 = 10;
pub const DEFAULT_SANDBOX_IMAGE: &str = "breachpilot-sandbox:latest";
pub const EMBEDDED_RESOLVER: &str = "127.0.0.11";

pub const COMMON_BLOCKED_NETS: &[&str] = &[
    "169.254.169.254",
    "169.254.0.0/16",
    "fd00:ec2::254",
    "100.100.100.200",
];

pub const IPV6_EXTRA_BLOCKED: &[&str] = &["fe80::/10", "::ffff:0:0/96", "2001::/32"];

pub const RESEARCH_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gitlab.com",
];

const AUTHORIZE_ALL_TOKENS: &[&str] = &["0.0.0.0/0", "::/0", "*", "any", "all"];

const NOT_FOUND_SUBSTRINGS: &[&str] = &[
    "no such network",
    "no such container",
    "no such object",
    "not found",
    "error 404",
    "404 not found",
];

const ACTIVE_ENDPOINTS_SUBSTRINGS: &[&str] = &[
    "has active endpoint",
    "active endpoint",
    "has connections",
    "is in use",
    "endpoint is still",
];

/// Validated configuration for a disposable Docker sandbox worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub image: String,
    pub user: String,
    pub read_only_rootfs: bool,
    pub memory_mb: u64,
    pub cpus: f64,
    pub pids_limit: u64,
    pub exec_timeout_seconds: u64,
    pub output_max_bytes: usize,
    pub tmpfs_size_mb: u64,
    pub network_enforce: bool,
    pub network_fail_closed: bool,
    pub allow_dns: String,
    pub map_host_loopback: bool,
    pub extra_allow_cidrs: Vec<String>,
    pub allow_gateway: bool,
    pub allow_research_hosts: bool,
    pub remove_on_exit: bool,
    pub remove_stale_on_startup: bool,
    pub cap_raw: bool,
    pub env_passthrough: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            image: DEFAULT_SANDBOX_IMAGE.into(),
            user: "sandbox".into(),
            read_only_rootfs: true,
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            exec_timeout_seconds: 300,
            output_max_bytes: 2_000_000,
            tmpfs_size_mb: 256,
            network_enforce: true,
            network_fail_closed: true,
            allow_dns: "controlled".into(),
            map_host_loopback: false,
            extra_allow_cidrs: Vec::new(),
            allow_gateway: false,
            allow_research_hosts: false,
            remove_on_exit: true,
            remove_stale_on_startup: true,
            cap_raw: true,
            env_passthrough: Vec::new(),
        }
    }
}

/// Immutable worker specification passed to `build_create_args`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub sandbox_id: String,
    pub run_id: String,
    pub image: String,
    pub user: String,
    pub network_name: String,
    pub workspace_src: String,
    pub memory_mb: u64,
    pub cpus: f64,
    pub pids_limit: u64,
    pub read_only_rootfs: bool,
    pub tmpfs_size_mb: u64,
}

/// Concrete egress authorization for the worker network namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub authorized_destinations: Vec<String>,
    pub explicitly_blocked: Vec<String>,
    pub allow_dns: String,
    pub allow_gateway: bool,
    pub resolved_domains: BTreeMap<String, Vec<String>>,
    pub unresolved_targets: Vec<String>,
    pub enforced: bool,
}

impl NetworkPolicy {
    /// Deterministic SHA-256 fingerprint of the policy for change detection.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        for d in &self.authorized_destinations {
            h.update(d.as_bytes());
            h.update(b",");
        }
        h.update(b"|");
        for b in &self.explicitly_blocked {
            h.update(b.as_bytes());
            h.update(b",");
        }
        h.update(self.allow_dns.as_bytes());
        h.update(if self.allow_gateway { b"1" } else { b"0" });
        hex::encode(h.finalize())
    }
}

/// Result of tearing down a worker and its dedicated bridge network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TeardownResult {
    pub container_removed: bool,
    pub network_removed: bool,
}

/// Validate a container ID or name against shell/flag injection.
pub fn validate_container_id(container_id: &str) -> Result<String, ExecError> {
    let cid = container_id.trim();
    if cid.is_empty()
        || cid.starts_with('-')
        || cid.chars().any(|c| {
            matches!(
                c,
                ' ' | ';' | '|' | '`' | '$' | '\n' | '\r' | '\\' | '"' | '\''
            )
        })
    {
        return Err(ExecError::Unavailable(
            "invalid sandbox container id".into(),
        ));
    }
    Ok(cid.to_string())
}

/// Validate an environment variable name before passing `--env KEY=VALUE`.
pub fn validate_env_key(key: &str) -> Result<(), ExecError> {
    let k = key.trim();
    if k.is_empty() || k.starts_with('-') || k.chars().any(|c| matches!(c, '=' | ' ' | '\n' | '\r'))
    {
        return Err(ExecError::Unavailable(format!(
            "invalid sandbox env key {key:?}"
        )));
    }
    Ok(())
}

/// Build the hardened `docker create` argument vector.
///
/// Enforces:
/// - `--cap-drop ALL` (with `--cap-add NET_RAW` only when `cap_raw` is true;
///   `NET_ADMIN` is NEVER granted to the worker)
/// - `--security-opt no-new-privileges`, non-root `--user`, no `--privileged`
/// - `--memory`, `--memory-swap`, `--cpus`, `--pids-limit`
/// - `--read-only` rootfs + `--tmpfs /tmp:rw,noexec,nosuid,size=<N>m`
/// - restricted `/workspace` bind mount only (no docker.sock, no host root/home)
pub fn build_create_args(spec: &SandboxSpec, cap_raw: bool) -> Result<Vec<String>, ExecError> {
    let image = spec.image.trim();
    if image.is_empty()
        || image.starts_with('-')
        || image
            .chars()
            .any(|c| matches!(c, ';' | '|' | '`' | '$' | '\n' | '\r'))
    {
        return Err(ExecError::Unavailable(format!(
            "invalid sandbox image {image:?}"
        )));
    }
    let cid = validate_container_id(&spec.sandbox_id)?;
    let user = if spec.user.trim().is_empty() {
        "sandbox"
    } else {
        spec.user.trim()
    };
    if user == "root" || user == "0" {
        return Err(ExecError::Unavailable(
            "worker container must not be created with root user".into(),
        ));
    }
    let src = spec.workspace_src.trim();
    if src.is_empty() {
        return Err(ExecError::WorkspaceFailed(
            "worker requires a validated workspace bind".into(),
        ));
    }
    let mem = spec.memory_mb.max(256);
    let pids = spec.pids_limit.max(32);
    let tmpfs_mb = spec.tmpfs_size_mb.max(64);
    let cpus = if spec.cpus >= 0.1 { spec.cpus } else { 2.0 };

    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        cid,
        "--network".to_string(),
        spec.network_name.clone(),
        "--label".to_string(),
        "breachpilot=true".to_string(),
        "--label".to_string(),
        format!("run_id={}", spec.run_id),
        "--cap-drop".to_string(),
        "ALL".to_string(),
    ];
    if cap_raw {
        args.push("--cap-add".to_string());
        args.push("NET_RAW".to_string());
    }
    args.extend([
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--user".to_string(),
        user.to_string(),
        "--memory".to_string(),
        format!("{mem}m"),
        "--memory-swap".to_string(),
        format!("{mem}m"),
        "--cpus".to_string(),
        format!("{cpus}"),
        "--pids-limit".to_string(),
        format!("{pids}"),
        "--tmpfs".to_string(),
        format!("/tmp:rw,noexec,nosuid,size={tmpfs_mb}m"),
        "-v".to_string(),
        format!("{src}:{CONTAINER_WORKSPACE}:rw"),
        "-w".to_string(),
        CONTAINER_WORKSPACE.to_string(),
    ]);
    if spec.read_only_rootfs {
        args.push("--read-only".to_string());
    }
    args.push(image.to_string());
    args.push("sleep".to_string());
    args.push("infinity".to_string());
    Ok(args)
}

/// Validate that the host workspace directory exists, is a real directory, and
/// is not a symlink.
pub fn validate_workspace(workspace: &Path) -> Result<PathBuf, ExecError> {
    let meta = fs::symlink_metadata(workspace).map_err(|e| {
        ExecError::WorkspaceFailed(format!(
            "sandbox workspace {} does not exist: {e}",
            workspace.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(ExecError::WorkspaceFailed(format!(
            "sandbox workspace {} must not be a symlink",
            workspace.display()
        )));
    }
    if !meta.is_dir() {
        return Err(ExecError::WorkspaceFailed(format!(
            "sandbox workspace {} is not a directory",
            workspace.display()
        )));
    }
    workspace.canonicalize().map_err(|e| {
        ExecError::WorkspaceFailed(format!(
            "cannot canonicalize workspace {}: {e}",
            workspace.display()
        ))
    })
}

/// Map a host path inside the validated workspace to `/workspace/...`.
/// Rejects paths outside the workspace or symlink escapes.
pub fn container_path(workspace: &Path, host_path: &Path) -> Result<String, ExecError> {
    let ws_canon = validate_workspace(workspace)?;
    let hp_canon = host_path.canonicalize().map_err(|e| {
        ExecError::WorkspaceFailed(format!("cannot resolve path {}: {e}", host_path.display()))
    })?;
    let rel = hp_canon.strip_prefix(&ws_canon).map_err(|_| {
        ExecError::WorkspaceFailed(format!(
            "path {} is outside the sandbox workspace {}",
            hp_canon.display(),
            ws_canon.display()
        ))
    })?;
    if rel.as_os_str().is_empty() {
        return Ok(CONTAINER_WORKSPACE.to_string());
    }
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Ok(format!("{CONTAINER_WORKSPACE}/{}", parts.join("/")))
}

/// Determine IP version (4 or 6) for an IP or CIDR literal. Returns `None` if invalid.
pub fn ip_version(token: &str) -> Option<u8> {
    let t = token.trim();
    if let Some((ip_part, prefix_part)) = t.split_once('/') {
        let addr: IpAddr = ip_part.parse().ok()?;
        let prefix: u8 = prefix_part.parse().ok()?;
        match addr {
            IpAddr::V4(_) if prefix <= 32 => Some(4),
            IpAddr::V6(_) if prefix <= 128 => Some(6),
            _ => None,
        }
    } else {
        match t.parse::<IpAddr>().ok()? {
            IpAddr::V4(_) => Some(4),
            IpAddr::V6(_) => Some(6),
        }
    }
}

fn is_zero_prefix_cidr(token: &str) -> bool {
    if let Some((_ip, pre)) = token.trim().split_once('/') {
        if pre.trim() == "0" {
            return true;
        }
    }
    false
}

fn is_metadata_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 169.254.0.0/16 link-local / cloud metadata or 100.100.100.200 (Alibaba IMDS)
            (o[0] == 169 && o[1] == 254) || (o == [100, 100, 100, 200])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // fd00:ec2::254 or fe80::/10 link-local
            (s[0] == 0xfd00 && s[1] == 0x0ec2 && s[7] == 0x0254) || ((s[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn is_unsafe_dns_answer(ip: &IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || is_metadata_ip(ip)
}

fn is_valid_fqdn(s: &str) -> bool {
    let t = s.trim().trim_end_matches('.');
    if t.is_empty() || t.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = t.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return false;
        }
        if !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    labels
        .last()
        .map(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()))
        .unwrap_or(false)
}

fn default_resolve_host(host: &str) -> Vec<String> {
    let Ok(addrs) = (host, 80).to_socket_addrs() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sa in addrs {
        let s = sa.ip().to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// Build the concrete egress `NetworkPolicy` from config and effective allowlist entries.
/// Refuses wildcard-all tokens (`0.0.0.0/0`, `::/0`, `*`, `any`, `all`).
pub fn build_network_policy<F>(
    cfg: &SandboxConfig,
    allowed_entries: &[String],
    gateway: &str,
    resolver: F,
) -> Result<NetworkPolicy, ExecError>
where
    F: Fn(&str) -> Vec<String>,
{
    let mut authorized: Vec<String> = Vec::new();
    let mut resolved_domains: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unresolved: Vec<String> = Vec::new();
    let mut loopback_hits = false;

    let push_unique = |vec: &mut Vec<String>, val: String| {
        if !vec.contains(&val) {
            vec.push(val);
        }
    };

    for raw in allowed_entries {
        let tok = raw.trim();
        if tok.is_empty() {
            continue;
        }
        let low = tok.to_lowercase();
        if AUTHORIZE_ALL_TOKENS.contains(&low.as_str()) || is_zero_prefix_cidr(&low) {
            return Err(ExecError::PolicyFailed(format!(
                "target {tok:?} authorizes all destinations; sandbox policy refuses it"
            )));
        }
        if matches!(low.as_str(), "localhost" | "127.0.0.1" | "::1") {
            loopback_hits = true;
            continue;
        }
        if tok.contains('/') && ip_version(tok).is_some() {
            push_unique(&mut authorized, tok.to_string());
            continue;
        }
        if let Ok(ip) = tok.parse::<IpAddr>() {
            if is_metadata_ip(&ip) {
                unresolved.push(format!("{tok} (metadata destination blocked)"));
                continue;
            }
            push_unique(&mut authorized, ip.to_string());
            continue;
        }
        if low.starts_with("*.") {
            unresolved.push(tok.to_string());
            continue;
        }
        if is_valid_fqdn(&low) {
            let answers = resolver(&low);
            let mut valid_ips = Vec::new();
            let mut excluded = Vec::new();
            for ans in answers {
                if let Ok(ip) = ans.parse::<IpAddr>() {
                    if is_unsafe_dns_answer(&ip) {
                        excluded.push(ans);
                    } else {
                        push_unique(&mut authorized, ip.to_string());
                        if !valid_ips.contains(&ip.to_string()) {
                            valid_ips.push(ip.to_string());
                        }
                    }
                }
            }
            if !valid_ips.is_empty() {
                resolved_domains.insert(low.clone(), valid_ips);
            }
            if !excluded.is_empty() {
                unresolved.push(format!(
                    "{low} (excluded unsafe DNS answers: {})",
                    excluded.join(", ")
                ));
            } else if !resolved_domains.contains_key(&low) {
                unresolved.push(low);
            }
            continue;
        }
        unresolved.push(tok.to_string());
    }

    for extra in &cfg.extra_allow_cidrs {
        let c = extra.trim();
        if c.is_empty() {
            continue;
        }
        if is_zero_prefix_cidr(c) || AUTHORIZE_ALL_TOKENS.contains(&c.to_lowercase().as_str()) {
            return Err(ExecError::PolicyFailed(format!(
                "extra CIDR {c:?} authorizes all destinations; sandbox policy refuses it"
            )));
        }
        if ip_version(c).is_some() {
            push_unique(&mut authorized, c.to_string());
        }
    }

    if cfg.map_host_loopback && loopback_hits && !gateway.trim().is_empty() {
        push_unique(&mut authorized, gateway.trim().to_string());
    }

    if cfg.allow_research_hosts {
        for &host in RESEARCH_HOSTS {
            let answers = resolver(host);
            let mut valid_ips = Vec::new();
            for ans in answers {
                if let Ok(ip) = ans.parse::<IpAddr>() {
                    if !is_unsafe_dns_answer(&ip) {
                        push_unique(&mut authorized, ip.to_string());
                        valid_ips.push(ip.to_string());
                    }
                }
            }
            if !valid_ips.is_empty() {
                resolved_domains.insert(host.to_string(), valid_ips);
            } else {
                unresolved.push(format!("{host} (unresolved at policy build)"));
            }
        }
    }

    let allow_dns = match cfg.allow_dns.trim().to_lowercase().as_str() {
        "none" => "none".to_string(),
        _ => "controlled".to_string(),
    };

    Ok(NetworkPolicy {
        authorized_destinations: authorized,
        explicitly_blocked: COMMON_BLOCKED_NETS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        allow_dns,
        allow_gateway: cfg.allow_gateway,
        resolved_domains,
        unresolved_targets: unresolved,
        enforced: cfg.network_enforce,
    })
}

/// Build IPv4 `iptables-restore` lines for the worker network namespace.
///
/// Order invariants:
/// 1. `-A OUTPUT -j NAI-OUTPUT`
/// 2. DNS drops (`127.0.0.11` and UDP/TCP port 53) BEFORE `-o lo -j ACCEPT`
/// 3. `-A NAI-OUTPUT -o lo -j ACCEPT`
/// 4. `-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT`
/// 5. Explicit metadata and bridge gateway DROPs
/// 6. Authorized IPv4 destinations ACCEPT
/// 7. Terminating `-A NAI-OUTPUT -j DROP` and `COMMIT`
pub fn build_ipv4_rules(policy: &NetworkPolicy, gateway: &str) -> Vec<String> {
    let mut lines = vec![
        "*filter".to_string(),
        ":NAI-OUTPUT - [0:0]".to_string(),
        "-A OUTPUT -j NAI-OUTPUT".to_string(),
        format!("-A NAI-OUTPUT -d {EMBEDDED_RESOLVER} -j DROP"),
        "-A NAI-OUTPUT -p udp --dport 53 -j DROP".to_string(),
        "-A NAI-OUTPUT -p tcp --dport 53 -j DROP".to_string(),
        "-A NAI-OUTPUT -o lo -j ACCEPT".to_string(),
        "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT".to_string(),
    ];

    let mut seen_blocked = BTreeSet::new();
    for b in COMMON_BLOCKED_NETS
        .iter()
        .copied()
        .chain(policy.explicitly_blocked.iter().map(String::as_str))
    {
        if ip_version(b) == Some(4) && seen_blocked.insert(b.to_string()) {
            lines.push(format!("-A NAI-OUTPUT -d {b} -j DROP"));
        }
    }

    let gw = gateway.trim();
    if !policy.allow_gateway && !gw.is_empty() && ip_version(gw) == Some(4) {
        lines.push(format!("-A NAI-OUTPUT -d {gw} -j DROP"));
    }

    for dest in &policy.authorized_destinations {
        if ip_version(dest) == Some(4) {
            lines.push(format!("-A NAI-OUTPUT -d {dest} -j ACCEPT"));
        }
    }

    lines.push("-A NAI-OUTPUT -j DROP".to_string());
    lines.push("COMMIT".to_string());
    lines
}

/// Build IPv6 `ip6tables-restore` lines for the worker network namespace.
pub fn build_ipv6_rules(policy: &NetworkPolicy) -> Vec<String> {
    let mut lines = vec![
        "*filter".to_string(),
        ":NAI-OUTPUT - [0:0]".to_string(),
        "-A OUTPUT -j NAI-OUTPUT".to_string(),
        "-A NAI-OUTPUT -p udp --dport 53 -j DROP".to_string(),
        "-A NAI-OUTPUT -p tcp --dport 53 -j DROP".to_string(),
        "-A NAI-OUTPUT -o lo -j ACCEPT".to_string(),
        "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT".to_string(),
    ];

    let mut seen_blocked = BTreeSet::new();
    for b in IPV6_EXTRA_BLOCKED
        .iter()
        .copied()
        .chain(COMMON_BLOCKED_NETS.iter().copied())
        .chain(policy.explicitly_blocked.iter().map(String::as_str))
    {
        if ip_version(b) == Some(6) && seen_blocked.insert(b.to_string()) {
            lines.push(format!("-A NAI-OUTPUT -d {b} -j DROP"));
        }
    }

    for dest in &policy.authorized_destinations {
        if ip_version(dest) == Some(6) {
            lines.push(format!("-A NAI-OUTPUT -d {dest} -j ACCEPT"));
        }
    }

    lines.push("-A NAI-OUTPUT -j DROP".to_string());
    lines.push("COMMIT".to_string());
    lines
}

/// Render the IPv4 ruleset with LF line endings for `iptables-restore`.
pub fn build_firewall_ruleset(policy: &NetworkPolicy, gateway: &str) -> String {
    let mut s = build_ipv4_rules(policy, gateway).join("\n");
    s.push('\n');
    s
}

/// Check whether a command is provably local computation that touches no network.
pub fn is_pure_local_computation(argv: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }
    let bin = Path::new(&argv[0])
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if matches!(
        bin.as_str(),
        "true" | "false" | "id" | "whoami" | "pwd" | "ls" | "cat" | "echo" | "head" | "tail" | "wc"
    ) {
        let joined = argv.join(" ").to_lowercase();
        return !joined.contains("/dev/tcp")
            && !joined.contains("http://")
            && !joined.contains("https://");
    }
    false
}

/// Seam for invoking the Docker CLI. Mocked in unit/lifecycle tests, real `docker`
/// subprocess in production and Docker integration tests.
pub trait DockerRunner: Send + Sync {
    fn run_docker(
        &self,
        args: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<(i32, String, String), ExecError>;
}

/// Production Docker runner invoking the `docker` CLI binary without a shell.
#[derive(Debug, Default, Clone)]
pub struct CliDockerRunner;

impl DockerRunner for CliDockerRunner {
    fn run_docker(
        &self,
        args: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<(i32, String, String), ExecError> {
        let start = Instant::now();
        let mut cmd = Command::new("docker");
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if input.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut child = cmd.spawn().map_err(|e| {
            ExecError::Unavailable(format!(
                "Docker CLI not available ({e}). Start/install Docker; never falling back to host execution."
            ))
        })?;
        if let Some(bytes) = input {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(bytes);
            }
        }
        loop {
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecError::Timeout);
            }
            match child
                .try_wait()
                .map_err(|e| ExecError::Unavailable(format!("docker wait failed: {e}")))?
            {
                Some(status) => {
                    let out = child.wait_with_output().map_err(|e| {
                        ExecError::Unavailable(format!("docker output failed: {e}"))
                    })?;
                    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                    return Ok((status.code().unwrap_or(-1), stdout, stderr));
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

fn is_not_found_error(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_lowercase();
    NOT_FOUND_SUBSTRINGS.iter().any(|m| combined.contains(m))
}

fn is_active_endpoints_error(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_lowercase();
    ACTIVE_ENDPOINTS_SUBSTRINGS
        .iter()
        .any(|m| combined.contains(m))
}

fn clamp_output_tail(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let tail = &bytes[bytes.len() - max_bytes..];
    format!(
        "{}\n[output truncated to last N bytes]",
        String::from_utf8_lossy(tail)
    )
}

/// Manages one disposable Docker worker container and its dedicated bridge network.
pub struct SandboxManager<R: DockerRunner = CliDockerRunner> {
    pub cfg: SandboxConfig,
    pub workspace: PathBuf,
    pub run_id: String,
    pub runner: R,
    pub container_id: String,
    pub network_name: String,
    pub gateway: String,
    pub policy: Option<NetworkPolicy>,
    pub audit_chain: Vec<EvidenceRecord>,
    pub cancelled: Arc<AtomicBool>,
    destroyed: bool,
    seq: u64,
}

impl<R: DockerRunner> SandboxManager<R> {
    pub fn new(
        cfg: SandboxConfig,
        workspace: PathBuf,
        run_id: impl Into<String>,
        runner: R,
    ) -> Self {
        let rid = run_id.into();
        let clean_rid = if rid.trim().is_empty() {
            "run-default".to_string()
        } else {
            rid.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect()
        };
        Self {
            cfg,
            workspace,
            run_id: clean_rid,
            runner,
            container_id: String::new(),
            network_name: String::new(),
            gateway: String::new(),
            policy: None,
            audit_chain: Vec::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
            destroyed: false,
            seq: 0,
        }
    }

    fn next_suffix(&mut self) -> String {
        self.seq += 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("{:x}{:02x}", self.seq, nanos & 0xff)
    }

    /// Signal cooperative + hard cancellation and tear down the worker container.
    pub fn cancel(&mut self) -> TeardownResult {
        self.cancelled.store(true, Ordering::SeqCst);
        self.destroy()
    }

    fn check_cancelled(&mut self) -> Result<(), ExecError> {
        if self.cancelled.load(Ordering::SeqCst) {
            let _ = self.destroy_resources();
            return Err(ExecError::Unavailable("sandbox run was cancelled".into()));
        }
        Ok(())
    }

    pub fn ensure_docker(&self) -> Result<String, ExecError> {
        let args = vec![
            "version".to_string(),
            "--format".to_string(),
            "{{.Server.Version}}".to_string(),
        ];
        let (rc, out, err) = self
            .runner
            .run_docker(&args, None, Duration::from_secs(20))?;
        if rc != 0 {
            let msg = if !err.trim().is_empty() {
                err.trim()
            } else if !out.trim().is_empty() {
                out.trim()
            } else {
                "docker daemon unreachable"
            };
            return Err(ExecError::Unavailable(format!(
                "Docker daemon unreachable: {msg}. Offensive execution is blocked (fail-closed)."
            )));
        }
        Ok(out.trim().to_string())
    }

    pub fn ensure_image(&self) -> Result<(), ExecError> {
        let args = vec![
            "image".to_string(),
            "inspect".to_string(),
            self.cfg.image.clone(),
        ];
        let (rc, _out, _err) = self
            .runner
            .run_docker(&args, None, Duration::from_secs(30))?;
        if rc != 0 {
            return Err(ExecError::Unavailable(format!(
                "sandbox image {:?} not found. Build it with: 'docker build -t {} docker/sandbox'.",
                self.cfg.image, self.cfg.image
            )));
        }
        Ok(())
    }

    pub fn container_state(&self, name_or_id: &str) -> String {
        if name_or_id.trim().is_empty() {
            return String::new();
        }
        let args = vec![
            "inspect".to_string(),
            "-f".to_string(),
            "{{.State.Status}}".to_string(),
            name_or_id.to_string(),
        ];
        match self.runner.run_docker(&args, None, Duration::from_secs(15)) {
            Ok((0, out, _)) => out.trim().to_string(),
            _ => String::new(),
        }
    }

    fn inspect_network_gateway(&self, network: &str) -> String {
        let args = vec![
            "network".to_string(),
            "inspect".to_string(),
            network.to_string(),
            "--format".to_string(),
            "{{json .}}".to_string(),
        ];
        let Ok((0, out, _)) = self.runner.run_docker(&args, None, Duration::from_secs(20)) else {
            return String::new();
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&out) else {
            return String::new();
        };
        val.get("IPAM")
            .and_then(|ipam| ipam.get("Config"))
            .and_then(|cfg| cfg.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("Gateway"))
            .and_then(|g| g.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    }

    /// Sweep stale `exited`/`created`/`dead` BreachPilot-labeled containers and
    /// empty labeled bridge networks. Running containers of concurrent sessions are untouched.
    pub fn cleanup_stale(&self) -> usize {
        let mut removed = 0usize;
        let ps_args = vec![
            "ps".to_string(),
            "-a".to_string(),
            "--filter".to_string(),
            "label=breachpilot=true".to_string(),
            "--format".to_string(),
            "{{.Names}}".to_string(),
        ];
        if let Ok((0, out, _)) = self
            .runner
            .run_docker(&ps_args, None, Duration::from_secs(20))
        {
            for name in out.lines().map(str::trim).filter(|s| !s.is_empty()) {
                if name == self.container_id {
                    continue;
                }
                let st = self.container_state(name);
                if matches!(st.as_str(), "exited" | "created" | "dead") && self.docker_rm(name) {
                    removed += 1;
                }
            }
        }
        let net_args = vec![
            "network".to_string(),
            "ls".to_string(),
            "--filter".to_string(),
            "label=breachpilot=true".to_string(),
            "--format".to_string(),
            "{{.Name}}".to_string(),
        ];
        if let Ok((0, out, _)) = self
            .runner
            .run_docker(&net_args, None, Duration::from_secs(20))
        {
            for net in out.lines().map(str::trim).filter(|s| !s.is_empty()) {
                if net == self.network_name {
                    continue;
                }
                let insp_args = vec![
                    "network".to_string(),
                    "inspect".to_string(),
                    net.to_string(),
                    "--format".to_string(),
                    "{{json .}}".to_string(),
                ];
                if let Ok((0, jout, _)) =
                    self.runner
                        .run_docker(&insp_args, None, Duration::from_secs(20))
                {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&jout) {
                        let empty = val
                            .get("Containers")
                            .and_then(|c| c.as_object())
                            .map(|m| m.is_empty())
                            .unwrap_or(true);
                        if empty && self.docker_network_rm(net, 2) {
                            removed += 1;
                        }
                    }
                }
            }
        }
        removed
    }

    /// Install the IPv4 + IPv6 default-DROP ruleset inside the worker's network
    /// namespace via an ephemeral `--rm` sidecar holding `NET_ADMIN`.
    pub fn apply_network_policy(
        &mut self,
        allowed_entries: &[String],
    ) -> Result<NetworkPolicy, ExecError> {
        let pol = build_network_policy(
            &self.cfg,
            allowed_entries,
            &self.gateway,
            default_resolve_host,
        )?;
        if let Some(prev) = &self.policy {
            if prev.fingerprint() == pol.fingerprint() {
                return Ok(pol);
            }
        }
        if self.cfg.network_enforce {
            let v4 = build_ipv4_rules(&pol, &self.gateway).join("\n") + "\n";
            let v6 = build_ipv6_rules(&pol).join("\n") + "\n";
            for (bin, rules) in [("iptables-restore", v4), ("ip6tables-restore", v6)] {
                let args = vec![
                    "run".to_string(),
                    "--rm".to_string(),
                    "-i".to_string(),
                    "--network".to_string(),
                    format!("container:{}", self.container_id),
                    "--cap-add".to_string(),
                    "NET_ADMIN".to_string(),
                    "--entrypoint".to_string(),
                    bin.to_string(),
                    self.cfg.image.clone(),
                ];
                let res =
                    self.runner
                        .run_docker(&args, Some(rules.as_bytes()), Duration::from_secs(60));
                match res {
                    Ok((0, _, _)) => {}
                    Ok((rc, out, err)) => {
                        let detail = if !err.trim().is_empty() {
                            err.trim()
                        } else {
                            out.trim()
                        };
                        if self.cfg.network_fail_closed {
                            self.record_audit("network_policy", "blocked", "", None, 0);
                            return Err(ExecError::PolicyFailed(format!(
                                "{bin} failed in sandbox netns (rc={rc}): {detail}"
                            )));
                        }
                        self.record_audit("network_policy", "degraded", "", None, 0);
                    }
                    Err(e) => {
                        if self.cfg.network_fail_closed {
                            self.record_audit("network_policy", "blocked", "", None, 0);
                            return Err(ExecError::PolicyFailed(format!(
                                "{bin} failed in sandbox netns: {e}"
                            )));
                        }
                        self.record_audit("network_policy", "degraded", "", None, 0);
                    }
                }
            }
        }
        self.policy = Some(pol.clone());
        Ok(pol)
    }

    /// Guarantee a running, firewall-contained disposable worker container.
    /// Any failure destroys partial resources and returns a fail-closed `ExecError`.
    pub fn ensure_sandbox(&mut self, allowed_entries: &[String]) -> Result<String, ExecError> {
        self.check_cancelled()?;
        if !self.container_id.is_empty() {
            if self.container_state(&self.container_id) == "running" {
                self.apply_network_policy(allowed_entries)?;
                return Ok(self.container_id.clone());
            }
            let _ = self.destroy_resources();
        }

        let setup_res = (|| -> Result<String, ExecError> {
            self.ensure_docker()?;
            self.ensure_image()?;
            let ws_canon = validate_workspace(&self.workspace)?;
            if self.cfg.remove_stale_on_startup {
                self.cleanup_stale();
            }
            let suffix = self.next_suffix();
            let net_name = format!("breachpilot-net-{}-{suffix}", self.run_id);
            let net_args = vec![
                "network".to_string(),
                "create".to_string(),
                "--driver".to_string(),
                "bridge".to_string(),
                "--label".to_string(),
                "breachpilot=true".to_string(),
                "--label".to_string(),
                format!("run_id={}", self.run_id),
                net_name.clone(),
            ];
            let (nrc, _nout, nerr) =
                self.runner
                    .run_docker(&net_args, None, Duration::from_secs(30))?;
            if nrc != 0 {
                return Err(ExecError::Unavailable(format!(
                    "docker network create failed: {}",
                    nerr.trim()
                )));
            }
            self.network_name = net_name.clone();
            self.gateway = self.inspect_network_gateway(&net_name);

            let spec = SandboxSpec {
                sandbox_id: format!("breachpilot-{}-{suffix}", self.run_id),
                run_id: self.run_id.clone(),
                image: self.cfg.image.clone(),
                user: self.cfg.user.clone(),
                network_name: net_name,
                workspace_src: ws_canon.to_string_lossy().into_owned(),
                memory_mb: self.cfg.memory_mb,
                cpus: self.cfg.cpus,
                pids_limit: self.cfg.pids_limit,
                read_only_rootfs: self.cfg.read_only_rootfs,
                tmpfs_size_mb: self.cfg.tmpfs_size_mb,
            };
            let create_args = build_create_args(&spec, self.cfg.cap_raw)?;
            let (crc, cout, cerr) =
                self.runner
                    .run_docker(&create_args, None, Duration::from_secs(60))?;
            if crc != 0 {
                return Err(ExecError::Unavailable(format!(
                    "docker create failed: {}",
                    if !cerr.trim().is_empty() {
                        cerr.trim()
                    } else {
                        cout.trim()
                    }
                )));
            }
            let cid = validate_container_id(cout.trim())?;
            self.container_id = cid.clone();

            let start_args = vec!["start".to_string(), cid.clone()];
            let (src, _sout, serr) =
                self.runner
                    .run_docker(&start_args, None, Duration::from_secs(30))?;
            if src != 0 {
                return Err(ExecError::Unavailable(format!(
                    "docker start failed: {}",
                    serr.trim()
                )));
            }

            let mut running = false;
            for _ in 0..10 {
                let st = self.container_state(&cid);
                if st == "running" {
                    running = true;
                    break;
                }
                if matches!(st.as_str(), "exited" | "dead") {
                    return Err(ExecError::Unavailable(format!(
                        "sandbox worker {cid} exited immediately (state={st})"
                    )));
                }
            }
            if !running {
                return Err(ExecError::Unavailable(format!(
                    "sandbox worker {cid} not running after start"
                )));
            }

            self.apply_network_policy(allowed_entries)?;
            self.destroyed = false;
            Ok(cid)
        })();

        if setup_res.is_err() {
            let _ = self.destroy_resources();
        }
        setup_res
    }

    /// Execute an argv command inside the isolated Docker worker container.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_argv(
        &mut self,
        argv: &[String],
        targets: &[String],
        allowed_targets: &[String],
        require_allowlist: bool,
        timeout_secs: u64,
        cwd: Option<&str>,
        user: Option<&str>,
        tool_name: &str,
    ) -> Result<ExecResult, ExecError> {
        self.check_cancelled()?;
        if argv.is_empty() {
            return Err(ExecError::Spawn("empty argv".into()));
        }
        // Scope gate: enforce allowlist before touching Docker.
        if targets.is_empty() {
            if require_allowlist && !is_pure_local_computation(argv) {
                self.record_audit(tool_name, "blocked", &argv.join(" "), None, 0);
                return Err(ExecError::ScopeDenied(
                    "execution names no target while require_allowlist is true".into(),
                ));
            }
        } else if !allowlist::check_all(targets, allowed_targets, require_allowlist) {
            self.record_audit(tool_name, "blocked", &argv.join(" "), None, 0);
            return Err(ExecError::ScopeDenied(format!(
                "targets {targets:?} not in allowlist"
            )));
        }

        validate_workspace(&self.workspace)?;
        if let Some(w) = cwd {
            let wt = w.trim();
            if !wt.is_empty()
                && (!wt.starts_with(CONTAINER_WORKSPACE) || wt.split('/').any(|p| p == ".."))
            {
                return Err(ExecError::WorkspaceFailed(format!(
                    "invalid container workdir {wt:?}; must stay under {CONTAINER_WORKSPACE}"
                )));
            }
        }

        let cid = self.ensure_sandbox(allowed_targets)?;
        let inner = timeout_secs.clamp(1, 3600);
        let grace = EXEC_KILL_GRACE_SECONDS;
        let host_timeout = Duration::from_secs(inner + grace + 10);

        let exec_user = user
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.cfg.user);
        let workdir = cwd
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(CONTAINER_WORKSPACE);

        let mut docker_argv = vec![
            "exec".to_string(),
            "-w".to_string(),
            workdir.to_string(),
            "--user".to_string(),
            exec_user.to_string(),
            "--env".to_string(),
            "EXPLOIT_SANDBOX=1".to_string(),
            "--env".to_string(),
            format!("EXPLOIT_WORKSPACE={CONTAINER_WORKSPACE}"),
            "--env".to_string(),
            "TERM=dumb".to_string(),
        ];
        if let Some(first_target) = targets.first() {
            validate_env_key("EXPLOIT_TARGET")?;
            docker_argv.push("--env".to_string());
            docker_argv.push(format!("EXPLOIT_TARGET={first_target}"));
        }
        docker_argv.push(cid);
        docker_argv.push("timeout".to_string());
        docker_argv.push("-k".to_string());
        docker_argv.push(grace.to_string());
        docker_argv.push(inner.to_string());
        docker_argv.extend(argv.iter().cloned());

        let start = Instant::now();
        let res = self.runner.run_docker(&docker_argv, None, host_timeout);
        let duration_ms = start.elapsed().as_millis() as u64;
        match res {
            Err(ExecError::Timeout) => {
                self.record_audit(tool_name, "timed_out", &argv.join(" "), None, duration_ms);
                Err(ExecError::Timeout)
            }
            Err(e) => {
                self.record_audit(tool_name, "failed", &argv.join(" "), None, duration_ms);
                Err(e)
            }
            Ok((rc, out, err)) => {
                // `timeout` utility returns 124 (or 137 on SIGKILL) when inner command times out
                if rc == 124 || rc == 137 {
                    self.record_audit(
                        tool_name,
                        "timed_out",
                        &argv.join(" "),
                        Some(rc),
                        duration_ms,
                    );
                    return Err(ExecError::Timeout);
                }
                let cap = self.cfg.output_max_bytes.clamp(1024, 4_000_000);
                let stdout = clamp_output_tail(&out, cap);
                let stderr = clamp_output_tail(&err, cap);
                let status = if rc == 0 { "completed" } else { "failed" };
                self.record_audit(tool_name, status, &argv.join(" "), Some(rc), duration_ms);
                Ok(ExecResult {
                    exit_code: rc,
                    stdout,
                    stderr,
                    timed_out: false,
                    duration_ms,
                })
            }
        }
    }

    pub fn docker_rm(&self, name: &str) -> bool {
        let tok = name.trim();
        if tok.is_empty() {
            return true;
        }
        let insp = vec!["inspect".to_string(), tok.to_string()];
        match self.runner.run_docker(&insp, None, Duration::from_secs(15)) {
            Ok((rc, out, err)) if rc != 0 && is_not_found_error(&out, &err) => return true,
            Err(_) => return false,
            _ => {}
        }
        let rm = vec!["rm".to_string(), "-f".to_string(), tok.to_string()];
        match self.runner.run_docker(&rm, None, Duration::from_secs(60)) {
            Ok((0, _, _)) => true,
            Ok((_, out, err)) => is_not_found_error(&out, &err),
            Err(_) => false,
        }
    }

    pub fn docker_network_disconnect(&self, network: &str, container: &str) -> bool {
        let net = network.trim();
        let ctr = container.trim();
        if net.is_empty() || ctr.is_empty() {
            return true;
        }
        let args = vec![
            "network".to_string(),
            "disconnect".to_string(),
            "-f".to_string(),
            net.to_string(),
            ctr.to_string(),
        ];
        match self.runner.run_docker(&args, None, Duration::from_secs(20)) {
            Ok((0, _, _)) => true,
            Ok((_, out, err)) => is_not_found_error(&out, &err),
            Err(_) => false,
        }
    }

    pub fn docker_network_rm(&self, name: &str, retries: usize) -> bool {
        let tok = name.trim();
        if tok.is_empty() {
            return true;
        }
        let insp = vec![
            "network".to_string(),
            "inspect".to_string(),
            tok.to_string(),
            "--format".to_string(),
            "{{json .}}".to_string(),
        ];
        let mut target = tok.to_string();
        match self.runner.run_docker(&insp, None, Duration::from_secs(20)) {
            Ok((rc, out, err)) if rc != 0 && is_not_found_error(&out, &err) => return true,
            Ok((0, out, _)) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&out) {
                    if let Some(id) = val.get("Id").and_then(|v| v.as_str()) {
                        if !id.trim().is_empty() {
                            target = id.trim().to_string();
                        }
                    }
                }
            }
            Err(_) => return false,
            _ => {}
        }

        let attempts = retries.max(1);
        for attempt in 0..attempts {
            let rm = vec!["network".to_string(), "rm".to_string(), target.clone()];
            match self.runner.run_docker(&rm, None, Duration::from_secs(30)) {
                Ok((0, _, _)) => return true,
                Ok((_, out, err)) if is_not_found_error(&out, &err) => return true,
                Ok((_, out, err)) if is_active_endpoints_error(&out, &err) => {
                    if attempt + 1 < attempts {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    return false;
                }
                _ => return false,
            }
        }
        false
    }

    fn destroy_resources(&mut self) -> TeardownResult {
        let mut res = TeardownResult {
            container_removed: false,
            network_removed: false,
        };
        if !self.container_id.is_empty() {
            let stop_args = vec![
                "stop".to_string(),
                "-t".to_string(),
                "5".to_string(),
                self.container_id.clone(),
            ];
            let _ = self
                .runner
                .run_docker(&stop_args, None, Duration::from_secs(20));
            res.container_removed = self.docker_rm(&self.container_id);
            if !self.network_name.is_empty() {
                let _ = self.docker_network_disconnect(&self.network_name, &self.container_id);
            }
            res.network_removed = self.docker_network_rm(&self.network_name, 3);
        } else if !self.network_name.is_empty() {
            res.network_removed = self.docker_network_rm(&self.network_name, 3);
        }
        self.container_id.clear();
        self.network_name.clear();
        self.policy = None;
        res
    }

    /// Terminate + remove the worker container and its network idempotently, recording an audit row.
    pub fn destroy(&mut self) -> TeardownResult {
        if self.destroyed && self.container_id.is_empty() && self.network_name.is_empty() {
            return TeardownResult {
                container_removed: true,
                network_removed: true,
            };
        }
        let res = self.destroy_resources();
        self.destroyed = true;
        let status = if res.container_removed && res.network_removed {
            "completed"
        } else {
            "failed"
        };
        self.record_audit("cleanup", status, "", None, 0);
        res
    }

    fn record_audit(
        &mut self,
        tool_name: &str,
        status: &str,
        command: &str,
        exit_code: Option<i32>,
        duration_ms: u64,
    ) {
        let body = serde_json::json!({
            "tool_name": format!("sandbox.{tool_name}"),
            "status": status,
            "command": command,
            "container_id": self.container_id,
            "network": self.network_name,
            "image": self.cfg.image,
            "user": self.cfg.user,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "policy_fingerprint": self.policy.as_ref().map(NetworkPolicy::fingerprint).unwrap_or_default(),
        })
        .to_string();
        let rec = append_evidence(&mut self.audit_chain, &self.run_id, "sandbox_audit", &body);
        if self.workspace.is_dir() {
            let audit_file = self.workspace.join("exploit_audit.jsonl");
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(audit_file)
            {
                if let Ok(line) = serde_json::to_string(&rec) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
    }
}
