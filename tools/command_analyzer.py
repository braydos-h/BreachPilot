"""Static command-content analysis for Flow A autonomous execution.

``ScopeGate`` answers *"is this asset in scope?"* -- it never inspects the
*command*. In ``full_access`` attack mode, ``ExploitPolicy.approve_action``
auto-approves after only that asset check, so an autonomous agent could
otherwise run ``rm -rf /``, exfiltrate to an attacker C2 IP, or open a reverse
shell to a host the operator never authorized -- silently breaking the
"target-locked to a single IP" contract that makes ``full_access`` safe to
hand to an LLM (see CLAUDE.md: "Still target-locked to a single IP").

This module is the command-content gate. It is pure string/AST analysis (no
execution, no DNS), deliberately conservative (block-on-hit, report why), and
reuses the existing -- previously dormant -- ``extract_ips_from_command`` /
``is_target_in_allowlist`` helpers from ``validation_utils`` so IP extraction
has one source of truth. Activating those dormant primitives is part of the
"reuse before writing new code" pattern the roadmap calls for.

A command is blocked when it contains any of:

  1. **a destructive token** (data-loss or availability destruction). The
     tool's stance is "verify, do not destroy" -- even in ``full_access``.
     This is a focused subset: we do *not* block perm-change (chmod/chown) or
     process-kill (kill/pkill), because ``full_access`` post-exploit
     legitimately needs those against the locked target. The vocabulary covers
     shell truncation/redirect-to-system-path, block-device writes (``dd of=``
     / ``> /dev/nvme``), ``truncate``, ``find -delete``, ``tar --remove-files``,
     ``mv``/``cp`` to ``/dev/null`` or system paths, DB destruction
     (``TRUNCATE``/``FLUSHALL``/``dropDatabase``), and the rm/rmdir verbs.
  2. **an egress endpoint** that is neither the locked target, an explicitly
     allowlisted operator host, nor loopback. Endpoints are extracted as URL
     authorities (``http://host``), ``/dev/tcp|udp/<host>``, ``LHOST=`` /
     ``RHOST=``, network-verb destinations (``ssh``/``nc``/``socat`` ...), and
     Python socket/connect callbacks. A hostname destination that is not in the
     allowlist is egress (this closes the IPv4-only-extraction gap: a
     ``curl http://evil.example/`` used to extract zero IPs). Integer-encodings
     (decimal ``134744072``, hex ``0x08080808``, octal) and bracketed IPv6 are
     decoded -- no DNS, just ``ipaddress``.
  3. **a reverse-shell/C2 pattern** whose *callback endpoint* is not itself
     allowlisted. A reverse shell to an operator-allowlisted callback host is
     legitimate full_access pentesting and is permitted; a reverse shell to a
     self-chosen hostname / bare pattern is egress to an uncontrolled host. The
     exemption keys on the *callback endpoint* (parsed out of the pattern), not
     "any allowlisted IP present anywhere" -- so injecting the locked target IP
     as a harmless shell comment no longer suppresses the block. A
     *bind*/*listen* shell (``bind_tcp``, ``nc -l``) is never exempted: it
     exposes the authorized target to third-party connections.
  4. **(python source only) a call to a Python destructive primitive**
     (``os.remove``/``unlink``/``rmdir``, ``shutil.rmtree``, ``Path.unlink``/
     ``rmdir``) or dynamic-code execution (``eval``/``exec``/``compile``) -- the
     Python-API equivalents a string ``rm`` scan would miss in a
     ``write_python_file`` payload. ``pathlib`` methods are matched regardless
     of receiver (``Path(x).unlink()`` collapses the receiver to ``""`` in the
     AST walker, so ``("", "unlink")`` catches it). Calls that shell out
     (``os.system``/``subprocess.*``/``os.popen``) have their string arguments
     folded (the parser already folds adjacent literals ``"r" "m" -> "rm"``) and
     scanned for destructive tokens -- this defeats the source-text-concat
     evasion where an agent splits ``rm`` across two string literals.

Legitimate ``full_access`` pentesting is preserved: commands *against the
locked target* (nmap/curl/ssh to the target IP), ``subprocess`` use against the
target, and reverse shells to an allowlisted operator callback IP all pass.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from dataclasses import dataclass, field

from tools.validation_utils import extract_ips_from_command, is_target_in_allowlist

# ── Destructive tokens ──────────────────────────────────────────────────────
#
# Bare ``rm`` / ``rmdir`` are matched with word boundaries so common substrings
# like "arm", "form", "warm", "storm", "perform", "--remove-files" (which
# contains no contiguous ``rm``) do NOT trigger a false block. The remaining
# tokens are distinctive enough that plain substring match is safe (low
# false-positive risk on real recon/exploit commands).
_DESTRUCTIVE_RE = re.compile(r"(?<![\w-])(?:rm|rmdir)(?![\w-])", re.IGNORECASE)

_DESTRUCTIVE_SUBSTRINGS = frozenset(
    {
        "dd if=",
        "dd if ",
        # dd output device prefixes -- only /dev/sd was blocked before; NVMe/virtio/
        # Xen/loop/mmc/device-mapper/md all wipe disks and were absent.
        "of=/dev/sd",
        "of=/dev/nvme",
        "of=/dev/vd",
        "of=/dev/xvd",
        "of=/dev/loop",
        "of=/dev/mmcblk",
        "of=/dev/dm-",
        "of=/dev/md",
        "mkfs",
        "fdisk",
        "parted",
        "shred",
        "wipe",
        "truncate -s",
        "truncate --size",  # long-form --size was missing
        "-delete",  # find / -delete (was missing)
        "--remove-files",
        "remove-files",  # tar --remove-files (no "rm" bigram)
        "unlink ",
        # DB-level destruction -- only DROP/DELETE were present; TRUNCATE/FLUSHALL/
        # dropDatabase (camelCase, no space) were absent. Lowercased here.
        "drop table",
        "drop database",
        "delete from",
        "truncate table",
        "flushall",
        "flushdb",
        "dropdatabase",
        "dropcollection",
        "shutdown",
        "reboot",
        "poweroff",
        ":(){ :|:& };:",
    }
)

# Destructive writes that need positional awareness a bare substring cannot
# express. ``> /dev/null`` and ``2>/dev/null`` (output suppression) are
# deliberately NOT matched: ``null`` is not a block device, and relative
# redirects (``> out.txt``) and benign work paths (``/home`` / ``/tmp`` /
# ``/srv`` / ``/opt`` / ``/run``) are excluded so saving loot / scratch does not
# false-fire. ``cp`` / ``mv`` / ``install`` are matched only when the
# *destination* (the path after the source) is a system-critical path -- copying
# *out of* /etc into the workspace is fine; overwriting /etc/passwd is not.
_SYSTEM_CRITICAL_DIRS = "etc|var|boot|usr|bin|sbin|lib|lib64|proc|sys"
_BLOCK_DEVICES = r"dev/(?:sd|nvme|vd|xvd|loop|mmcblk|dm-|md)[\w]*"
_SYSTEM_WRITE_RE = re.compile(
    r"(?:"
    r">+\s*"  # `>` / `>>` redirect
    r"|\btee\b(?:\s+-\S+)*\s+"  # tee [flags] <path>
    r"|\b(?:cp|mv|install)\b(?:\s+-\S+)*\s+\S+\s+"  # cp/mv/install <src> <dest>
    r")"
    rf"/(?:{_BLOCK_DEVICES}|{_SYSTEM_CRITICAL_DIRS})(?![\w-])",
    re.IGNORECASE,
)
# ``mv <src> /dev/null`` -- silent delete (dest is the null device). There is no
# benign reason to move a file to /dev/null. The regex requires /dev/null to be
# mv's *destination* (the last token, before a separator or end-of-command):
# ``mv`` + optional flags + one source token + optional flags + ``/dev/null``
# followed by whitespace/end. This avoids the ``\b/dev/null`` pitfall (a space
# before ``/`` is not a word boundary) and does not span ``;``/``|`` (so a
# compound ``mv a b; echo > /dev/null`` is not mis-read as mv-to-null).
_MV_DEVNULL_RE = re.compile(
    r"\bmv\b(?:\s+-[^\s]+)*\s+\S+(?:\s+-[^\s]+)*\s+/dev/null(?:\s|$)",
    re.IGNORECASE,
)
# ``cp /dev/null <dest>`` -- truncate destination (source is the null device).
# Only matches when /dev/null is the source (right after cp [+ flags]), not
# ``cp foo /dev/null`` (which harmlessly discards foo into null).
_CP_FROM_DEVNULL_RE = re.compile(r"\bcp\b(?:\s+-\S+)*\s+/dev/null\b", re.IGNORECASE)

_DESTRUCTIVE_RES = (_SYSTEM_WRITE_RE, _MV_DEVNULL_RE, _CP_FROM_DEVNULL_RE)


# ── Reverse-shell / C2 egress fingerprints ──────────────────────────────────
#
# Conservative: these almost never appear in a legitimate vulnerability-
# verification command. A reverse shell to an *allowlisted* endpoint (operator
# callback) is permitted by the callback-endpoint rule; these patterns are
# blocked only when the callback endpoint is not allowlisted (the
# domain/hostname-egress case), so legit callbacks to the operator's box are
# unaffected. ``bind_*`` / listen patterns are separated out below: a bind
# shell is never exempted (third-party exposure).
REVERSE_SHELL_PATTERNS = frozenset(
    {
        "/dev/tcp/",
        "/dev/udp/",
        "bash -i",
        "bash >&",
        "0>&1",
        "0<&1",
        "nc -e",
        "ncat -e",
        "nc -c",
        "mkfifo",
        "socat ",
        "socat tcp",
        "socat ssl",
        "openssl s_client",
        "powershell -e",
        "powershell -enc",
        "powershell -nop",
        "iex(",
        "iex (",
        "downloadstring(",
        "invoke-expression",
        "reverse_tcp",
        "bind_tcp",
        "msfvenom",
        "msfconsole",
        "py -c",
        "python -c",
        "python3 -c",
        # remote-forward C2 tunneling -- SSH -R has no benign lowercase form (scp -r
        # is a different tool), so "ssh -r" is a clean C2 indicator.
        "ssh -r",
        # gawk's /inet/<proto>/<lport>/<rhost> coprocess is the awk reverse-shell
        # primitive; bare "awk" is NOT added (it processes loot legitimately).
        "/inet/",
        "ruby -rsocket",
    }
)

# Patterns that LISTEN (bind), not call back. A bind shell hands shell access to
# anyone who reaches the target's port -- a backdoor on the authorized target
# reachable by unauthorized third parties. Never exempted in full_access.
_BIND_SHELL_INDICATORS = (
    "bind_tcp",
    "bind_",
    "shell_bind",
    " bind",
    "nc -l",
    "ncat -l",
    "-lvnp",
    "-lnp",
    "tcp-listen",
    "fork-listen",
    "socket.bind",
    ".bind(",
)


# ── Egress endpoint extraction ───────────────────────────────────────────────
#
# ``extract_ips_from_command`` (validation_utils) is IPv4-dotted-only -- its
# job is finding IPv4 *targets to sanitize*, so we leave it alone and layer a
# richer extractor here for the egress gate. This catches the verified
# bypasses: hostname exfil (``curl http://evil.example/``), integer-IP
# encodings (decimal/hex/octal), bracketed IPv6, ``/dev/tcp/<host>`` callbacks,
# msfvenom ``LHOST=``, Python ``socket.connect(("host", port))``, and bare-host
# destinations after common network verbs. No DNS -- hostnames are checked
# against the operator allowlist (which supports exact / wildcard domains /
# CIDR), and integer encodings are decoded via ``ipaddress``.
_URL_AUTHORITY_RE = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^\s/@]+@)?(\[[0-9a-fA-F:]+\]|[^\s/:@?#]+)",
)
_DEV_TCP_HOST_RE = re.compile(r"/dev/(?:tcp|udp)/([^\s/:]+)/", re.IGNORECASE)
_LHOST_RE = re.compile(r"\bLHOST\s*=\s*([^\s;|&]+)", re.IGNORECASE)
_RHOST_RE = re.compile(r"\bRHOSTS?\s*=\s*([^\s;|&]+)", re.IGNORECASE)
_PY_CONNECT_RE = re.compile(
    r"\.(?:connect|create_connection|connect_ex)\s*\(\s*\(?\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_PY_HTTPCONN_RE = re.compile(
    r"\b(?:HTTPConnection|HTTPSConnection)\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_PEERADDR_RE = re.compile(r"PeerAddr\s*=>?\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
# Bare-host destinations after network verbs. Requires a dotted FQDN, a 7+ digit
# integer (above any port number 0-65535), 0x-hex, or bracketed IPv6 -- this
# excludes bare port numbers (``nc -lvnp 4444``) which are not hosts.
_NETVERB_HOST_RE = re.compile(
    r"\b(?:ssh|scp|rsync|telnet|nc|ncat|socat|ftp|sftp|hydra)\s+"
    r"(?:-[^\s]+\s+)*(?:[^\s/@]+@)?"
    r"([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}|\d{7,}|0x[0-9a-fA-F]+|\[[0-9a-fA-F:]+\])",
    re.IGNORECASE,
)


# ── Python destructive/dynamic calls (matched via AST) ──────────────────────
#
# ``(module, attr)`` pairs; ``""`` module means "any module or bare call".
# ``os.system`` / ``subprocess.*`` / ``os.popen`` are intentionally NOT here --
# running a command *against the locked target* is legitimate full_access
# behavior. Instead, their string args are folded and scanned for destructive
# tokens (see ``_SHELL_OUT_CALLS``): the parser already folds adjacent string
# literals (``"r" "m" -> "rm"``) so the concatenated runtime value is available
# in the AST and the source-text-concat evasion does not work. We catch only
# Python primitives that delete files or execute dynamic code, which a string
# ``rm`` scan would miss.
_PYTHON_DESTRUCTIVE_CALLS = frozenset(
    {
        ("os", "remove"),
        ("os", "unlink"),
        ("os", "rmdir"),
        ("os", "removedirs"),
        ("shutil", "rmtree"),
        ("shutil", "move"),
        # pathlib equivalents -- the AST walker collapses the receiver to "" when it
        # is a Call (Path(...).unlink()), so ("", "unlink")/("", "rmdir") catch it
        # regardless of how the receiver is spelled. ".remove()" is NOT added bare
        # (it would false-fire on list.remove / set.remove); pathlib has no .remove.
        ("pathlib", "unlink"),
        ("pathlib", "rmdir"),
        ("pathlib", "remove"),
        ("", "unlink"),
        ("", "rmdir"),
        ("", "eval"),
        ("", "exec"),
        ("", "compile"),
    }
)

# Calls that shell out -- their string args are scanned for destructive tokens.
# ``("","name")`` entries catch bare ``system(...)`` / ``popen(...)`` calls.
_SHELL_OUT_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "getoutput"),
        ("subprocess", "getstatusoutput"),
        ("subprocess", "Popen"),
        ("commands", "getoutput"),
        ("commands", "getstatusoutput"),
        ("", "system"),
        ("", "popen"),
    }
)


@dataclass
class CommandAnalysis:
    """Result of analyzing a proposed command or python source."""

    allowed: bool = True
    reasons: list[str] = field(default_factory=list)
    destructive: bool = False
    python_destructive: bool = False
    reverse_shell: bool = False
    egress_ips: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # so ``if analyze_command(...)`` reads naturally
        return self.allowed

    @property
    def any_destructive(self) -> bool:
        """True if either shell-destructive tokens or python-destructive AST calls hit.

        Lets the MCP tool layer block on destruction alone (always-on
        defense-in-depth) without also blocking on egress/reverse-shell, which
        are policy decisions that belong to ``ExploitPolicy``, not the tool.
        """
        return self.destructive or self.python_destructive


# ── Helpers ─────────────────────────────────────────────────────────────────


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _is_allowlisted(ip: str, locked_ip: str, allowed_targets: list[str]) -> bool:
    if ip == locked_ip:
        return True
    if _is_loopback(ip):
        return True
    return is_target_in_allowlist(ip, allowed_targets)


def _has_destructive(text: str) -> tuple[bool, str]:
    """Return (matched, token) for the first destructive hit, else (False, "")."""
    m = _DESTRUCTIVE_RE.search(text)
    if m:
        return True, m.group(0)
    for s in _DESTRUCTIVE_SUBSTRINGS:
        if s in text:
            return True, s
    for rx in _DESTRUCTIVE_RES:
        m = rx.search(text)
        if m:
            return True, m.group(0)
    return False, ""


def _endpoint_ips(token: str) -> list[str]:
    """Decode a destination token to IP(s) if it is an IP in any encoding.

    Handles bracketed IPv6 (strips ``[]``), dotted IPv4, IPv6, and integer
    encodings (decimal / hex / octal) that ``inet_aton``-style clients accept.
    Returns ``[]`` when the token is a hostname (no IP decoding applies) -- the
    caller then treats it as a hostname and checks the operator allowlist.
    """
    t = (token or "").strip()
    if t.startswith("[") and t.endswith("]"):
        t = t[1:-1]
    if not t:
        return []
    # Direct parse covers dotted IPv4 and full IPv6 (::1, 2001:db8::1, ...).
    try:
        return [str(ipaddress.ip_address(t))]
    except ValueError:
        pass
    # Decimal integer encoding (134744072 == 8.8.8.8)
    try:
        n = int(t)
        if 0 <= n <= 0xFFFFFFFF:
            return [str(ipaddress.IPv4Address(n))]
    except ValueError:
        pass
    # Hex (0x08080808)
    if t.lower().startswith("0x"):
        try:
            n = int(t, 16)
            if 0 <= n <= 0xFFFFFFFF:
                return [str(ipaddress.IPv4Address(n))]
        except ValueError:
            pass
    # Octal (leading 0, all octal digits)
    if len(t) > 1 and t.startswith("0") and all(ch in "01234567" for ch in t):
        try:
            n = int(t, 8)
            if 0 <= n <= 0xFFFFFFFF:
                return [str(ipaddress.IPv4Address(n))]
        except ValueError:
            pass
    return []


def _endpoint_allowlisted(token: str, locked_ip: str, allowed_targets: list[str]) -> bool:
    """True if the destination token is the locked target / allowlisted / loopback.

    Decodes integer-encoded IPs first; a hostname that decodes to nothing is
    checked against the operator allowlist (supports exact/wildcard domains).
    ``localhost`` is treated as loopback (never egress).
    """
    if not token:
        return True
    low = token.lower()
    if low in ("localhost", "::1", "0.0.0.0"):
        return True
    for ip in _endpoint_ips(token):
        if _is_allowlisted(ip, locked_ip, allowed_targets):
            return True
    # hostname (no IP encoding) -- check the allowlist directly
    return _is_allowlisted(token, locked_ip, allowed_targets)


def _extract_destinations(command: str) -> list[str]:
    """Extract destination host/IP tokens from a command (URL authorities,
    /dev/tcp|udp hosts, msfvenom LHOST/RHOST, python socket.connect /
    HTTPConnection, perl PeerAddr, and bare-host args after network verbs).

    Deduped, order-preserving. These are the callback/egress endpoints the
    egress and reverse-shell-exemption checks reason about.
    """
    dests: list[str] = []
    for rx in (
        _URL_AUTHORITY_RE,
        _DEV_TCP_HOST_RE,
        _LHOST_RE,
        _RHOST_RE,
        _PY_CONNECT_RE,
        _PY_HTTPCONN_RE,
        _PEERADDR_RE,
        _NETVERB_HOST_RE,
    ):
        for m in rx.finditer(command):
            dests.append(m.group(1))
    seen: set[str] = set()
    out: list[str] = []
    for d in dests:
        if not d:
            continue
        # ``LHOST=``/``RHOST=`` captures include surrounding quotes and
        # trailing commas/parens when the value is quoted (e.g. the repr
        # ``lhost='10.0.0.99',`` yields ``"'10.0.0.99',"``). Strip that
        # punctuation so the allowlist/IP match sees the clean endpoint —
        # otherwise an allowlisted operator callback host is falsely
        # flagged as egress (bug #5).
        d = d.strip("\"' ,);")
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _egress_endpoints(command: str, locked_ip: str, allowed_targets: list[str]) -> list[str]:
    """Return destination tokens that are egress (not locked / allowlisted / loopback).

    Integer-encoded IPs are decoded and checked by IP; hostnames are checked
    against the allowlist. Bare dotted-IPv4 anywhere in the command (caught by
    ``extract_ips_from_command``) is also checked as a backstop for non-URL
    embedded IPs (e.g. ``ssh 10.0.0.99``).
    """
    egress: list[str] = []
    for token in _extract_destinations(command):
        if _endpoint_allowlisted(token, locked_ip, allowed_targets):
            continue
        if token not in egress:
            egress.append(token)
    for ip in extract_ips_from_command(command):
        if _is_allowlisted(ip, locked_ip, allowed_targets):
            continue
        if ip not in egress:
            egress.append(ip)
    return egress


def _collect_str_constants(node: ast.AST) -> list[str]:
    """Collect all str Constant values reachable from ``node``.

    Used to fold shell-out call arguments: the parser already collapses
    adjacent string literals (``"r" "m"`` -> one ``Constant("rm")``), so walking
    the arg subtree yields the concatenated runtime string the source-text regex
    never sees.
    """
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return out


def _scan_shell_out_args(node: ast.Call, reasons: list[str]) -> None:
    """Scan string args of a shell-out call for destructive tokens.

    Scans both space-joined (argv form: ``["rm", "-rf", "/"]``) and empty-joined
    (implicit-concat / BinOp(Add) form: ``"r" + "m"``) so a destructive command
    split across literals or list elements is caught from the *runtime* value,
    not the source text.
    """
    candidates = list(node.args)
    for kw in node.keywords:
        if kw.arg in ("args", "cmd", "command"):
            candidates.append(kw.value)
    for arg in candidates:
        strs = _collect_str_constants(arg)
        if not strs:
            continue
        for sep in (" ", ""):
            hit, token = _has_destructive(sep.join(strs).lower())
            if hit:
                reasons.append(f"destructive shell command embedded in subprocess/os.system call: {token!r}")
                return


def _analyze_python(source: str) -> list[str]:
    """AST-walk python source for destructive primitives / dynamic code exec /
    destructive shell-outs. Returns human-readable reasons (empty = clean).

    If the source is not parseable as Python, returns [] -- the string-level
    checks still apply.
    """
    reasons: list[str] = []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return reasons
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            mod = func.value.id if isinstance(func.value, ast.Name) else ""
            name = func.attr
            if (mod, name) in _PYTHON_DESTRUCTIVE_CALLS or ("", name) in _PYTHON_DESTRUCTIVE_CALLS:
                reasons.append(f"python destructive/dynamic call: {mod + '.' if mod else ''}{name}()")
            elif (mod, name) in _SHELL_OUT_CALLS or ("", name) in _SHELL_OUT_CALLS:
                _scan_shell_out_args(node, reasons)
        elif isinstance(func, ast.Name):
            if ("", func.id) in _PYTHON_DESTRUCTIVE_CALLS:
                reasons.append(f"python dynamic call: {func.id}()")
            elif ("", func.id) in _SHELL_OUT_CALLS:
                _scan_shell_out_args(node, reasons)
    return reasons


# ── Public API ──────────────────────────────────────────────────────────────


def analyze_command(
    command: str,
    *,
    language: str = "shell",
    locked_ip: str = "",
    allowed_targets: list[str] | None = None,
) -> CommandAnalysis:
    """Statically analyze a command / python source before autonomous execution.

    Args:
        command: The shell command or python source to inspect.
        language: ``"shell"`` (default) or ``"python"`` (enables AST checks).
        locked_ip: The single target IP the agent is authorized to test.
        allowed_targets: Additional operator-authorized IPs / hosts / CIDRs
            (e.g. a callback host). The locked IP is always implicitly allowed.

    Returns:
        ``CommandAnalysis`` with ``allowed`` and the list of block reasons
        (empty list == allowed).
    """
    allowed_targets = list(allowed_targets or [])
    if not command or not command.strip():
        return CommandAnalysis(allowed=True)

    text = command.lower()
    result = CommandAnalysis()

    # 1. Destructive tokens (shell substring/regex + word-bounded rm/rmdir;
    #    applies to python source too since a python string can shell out).
    hit, token = _has_destructive(text)
    if hit:
        result.destructive = True
        result.reasons.append(f"destructive token: {token!r}")

    # 2. Egress: any destination endpoint (IP in any encoding, or a hostname)
    #    that is not the locked target, not an allowlisted operator host, and
    #    not loopback/localhost.
    egress = _egress_endpoints(command, locked_ip, allowed_targets)
    if egress:
        result.egress_ips = egress
        result.reasons.append(
            f"egress to non-target endpoint(s): {egress} "
            f"(not in locked_ip={locked_ip!r} or allowlist={allowed_targets})"
        )

    # 3. Reverse-shell / C2 patterns. A *reverse* shell is blocked only when
    #    its callback *endpoint* is not itself allowlisted -- not when "any
    #    allowlisted IP appears anywhere" (which a harmless decoy comment could
    #    satisfy). A *bind*/listen shell is never exempted: it exposes the
    #    authorized target to third-party connections.
    shell_patterns_hit = any(pat in text for pat in REVERSE_SHELL_PATTERNS)
    if shell_patterns_hit:
        result.reverse_shell = True
        is_bind = any(b in text for b in _BIND_SHELL_INDICATORS)
        if is_bind:
            result.reasons.append(
                "bind/listen shell/C2 pattern: exposes the target to third-party "
                "connections; not auto-approved in full_access"
            )
        else:
            callback_dests = _extract_destinations(command)
            callback_allowlisted = any(_endpoint_allowlisted(d, locked_ip, allowed_targets) for d in callback_dests)
            if not callback_allowlisted:
                result.reasons.append(
                    "reverse-shell/C2 pattern with no allowlisted callback endpoint "
                    "(callback host must be the locked target or an allowlisted "
                    "operator host)"
                )

    # 4. Python-specific AST analysis (destructive primitives / dynamic code /
    #    destructive shell-outs).
    if language == "python":
        py_reasons = _analyze_python(command)
        if py_reasons:
            result.python_destructive = True
            result.reasons.extend(py_reasons)

    result.allowed = not result.reasons
    return result


def infer_language(action: str) -> str:
    """Infer the command language from the calling tool/action name.

    ``write_python_file`` / ``run_python_file`` payloads are python source;
    everything else (``run_exploit_terminal``, msf modules, etc.) is shell.
    """
    name = (action or "").lower()
    if "python" in name:
        return "python"
    return "shell"


# Tool args that name a destination host the action touches *outside* the
# command/code/options payload (see ``analysis_payload`` bug #5). These are
# surfaced to the egress scan so a ``lateral_exec``/``run_msf_module`` can't
# pivot to an arbitrary IP simply by passing it as a named arg.
_IP_ARG_NAMES = (
    "target_ip",
    "dc_ip",
    "lhost",
    "rhost",
    "rhosts",
    "callback_ip",
    "target_host",
    "source_host",
)


def analysis_payload(action: str, args: dict | None) -> str:
    """Return the raw payload string to analyze for a tool call.

    The repr'd tool-call string (``write_python_file(filename=..., code='...')``)
    wraps the payload in a string literal, so AST / destructive / egress scans
    on the repr are *inert*: the payload's ``os.remove`` / ``socket.connect``
    live inside a ``Constant`` / quoted string the walker never descends into.
    Analyzing the repr also forced a ``[:300]`` truncation that hid callback
    endpoints past character 300. This helper returns the raw payload so the
    gate sees the whole command: ``run_exploit_terminal`` -> its ``command``
    arg, ``write_python_file`` / ``run_python_file`` -> their ``code`` arg, MSF
    resource scripts -> ``script_content``, else ``options``; if none apply we
    fall back to a full (untruncated) repr so we never analyze *less* than the
    whole call.

    Bug #5: tools that take the destination IP as a *separate named arg*
    (``lateral_exec(target_ip=...)``, ``run_msf_module(target_ip=...)``,
    ``kerberoast(dc_ip=...)``, ``generate_payload(lhost=...)``) would otherwise
    pass the gate on the command/options text alone — which never mentions the
    IP — so the AI could pivot to any host. We append the IP-bearing args to
    the scanned string so ``analyze_command``'s egress check sees them (the
    locked target and allowlisted operator hosts are still exempt). Skipped for
    python-language tools, where appending would break AST parsing of the code;
    no current python tool carries an IP arg.
    """
    args = args or {}
    if isinstance(args.get("command"), str):
        primary = args["command"]
    else:
        name = (action or "").lower()
        if name in ("write_python_file", "run_python_file") and isinstance(args.get("code"), str):
            primary = args["code"]
        elif isinstance(args.get("script_content"), str):
            primary = args["script_content"]
        elif isinstance(args.get("options"), str):
            primary = args["options"]
        else:
            primary = f"{action}({', '.join(f'{k}={v!r}' for k, v in args.items())})"

    if infer_language(action) != "python":
        ip_bits = [f"{k}={args[k]}" for k in _IP_ARG_NAMES if isinstance(args.get(k), str) and args[k].strip()]
        if ip_bits:
            primary = f"{primary} " + " ".join(ip_bits) if primary else " ".join(ip_bits)
    return primary
