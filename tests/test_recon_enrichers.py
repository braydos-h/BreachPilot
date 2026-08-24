"""Tests for tools.recon_enrichers — pure parsing + bounded web spider.

All spider tests use injected ``fetch_fn`` fakes; no network is touched.
Tests are written to PASS (see Windows pytest 9.0.3 PosixPath INTERNALERROR
note in the task brief — a failing test crashes pytest before naming itself).
"""


from tools.recon_enrichers import (
    http_spider,
    parse_db_banner,
    parse_smtp_banner,
    parse_tls_info,
    parse_udp_nmap_output,
)

# ---------------------------------------------------------------------------
# parse_tls_info
# ---------------------------------------------------------------------------

NMAP_SSL_CERT = """  TLS-1.2:
    Cipher: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    Subject: CN=mail.example.com
    Issuer: CN=Let's Encrypt R3,O=Let's Encrypt,C=US
    Public Key type: rsa
    Subject Alternative Name: DNS:mail.example.com, DNS:web.example.com, DNS:example.com
    Not valid before: 2024-01-15T00:00:00
    Not valid after: 2024-04-14T23:59:59
"""


def test_parse_tls_info_text_populated():
    info = parse_tls_info(NMAP_SSL_CERT)
    assert "Let's Encrypt" in info["issuer"]
    assert "mail.example.com" in info["subject"]
    assert "mail.example.com" in info["san"]
    assert "web.example.com" in info["san"]
    assert "example.com" in info["san"]
    assert info["valid_from"].startswith("2024-01-15")
    assert info["valid_to"].startswith("2024-04-14")
    assert info["protocol"] == "TLS-1.2"
    assert "AES_256_GCM" in info["cipher"]


def test_parse_tls_info_empty_input():
    info = parse_tls_info("")
    assert info == {
        "issuer": "",
        "subject": "",
        "san": [],
        "valid_from": "",
        "valid_to": "",
        "protocol": "",
        "cipher": "",
    }


def test_parse_tls_info_none_input():
    info = parse_tls_info(None)
    assert info["san"] == []
    assert info["issuer"] == ""


def test_parse_tls_info_garbage_never_raises():
    # Random garbage must not raise and must return the empty shape.
    info = parse_tls_info("<<<!!!>>> random \x00 binary \xff junk")
    assert isinstance(info, dict)
    assert info["san"] == []


def test_parse_tls_info_dict_input():
    info = parse_tls_info({
        "issuer": {"commonName": "Test CA"},
        "subject": {"commonName": "host.test"},
        "san": ["a.test", "b.test"],
        "notBefore": "2024-01-01",
        "notAfter": "2025-01-01",
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM",
    })
    assert info["issuer"] == "Test CA"
    assert info["subject"] == "host.test"
    assert "a.test" in info["san"] and "b.test" in info["san"]
    assert info["valid_from"] == "2024-01-01"
    assert info["valid_to"] == "2025-01-01"


# ---------------------------------------------------------------------------
# parse_smtp_banner
# ---------------------------------------------------------------------------

SMTP_BANNER = (
    "220 mail.example.com ESMTP Postfix\r\n"
    "EHLO client\r\n"
    "250-mail.example.com\r\n"
    "250-PIPELINING\r\n"
    "250-SIZE 10240000\r\n"
    "250-STARTTLS\r\n"
    "250-AUTH PLAIN LOGIN CRAM-MD5\r\n"
    "250-ENHANCEDSTATUSCODES\r\n"
    "250 8BITMIME\r\n"
)


def test_parse_smtp_banner_postfix_starttls_auth():
    info = parse_smtp_banner(SMTP_BANNER)
    assert "Postfix" in info["server_software"]
    assert info["supports_starttls"] is True
    assert "PLAIN" in info["auth_methods"]
    assert "LOGIN" in info["auth_methods"]
    assert "CRAM-MD5" in info["auth_methods"]
    assert info["banner"] == SMTP_BANNER


def test_parse_smtp_banner_no_starttls():
    banner = (
        "220 relay.test Microsoft ESMTP MAIL Service\r\n"
        "250-AUTH NTLM\r\n"
        "250 OK\r\n"
    )
    info = parse_smtp_banner(banner)
    assert info["supports_starttls"] is False
    assert "NTLM" in info["auth_methods"]


def test_parse_smtp_banner_empty():
    info = parse_smtp_banner("")
    assert info["server_software"] == ""
    assert info["supports_starttls"] is False
    assert info["auth_methods"] == []


# ---------------------------------------------------------------------------
# parse_db_banner
# ---------------------------------------------------------------------------

def test_parse_db_banner_mysql():
    banner = "5.7.40-log MySQL Community Server (GPL)"
    info = parse_db_banner(banner, service="mysql")
    assert info["db_type"] == "mysql"
    assert "5.7.40" in info["version"]


def test_parse_db_banner_postgres():
    banner = "FATAL: no such role. PostgreSQL 14.2 on x86_64"
    info = parse_db_banner(banner, service="postgresql")
    assert info["db_type"] == "postgres"
    assert "14.2" in info["version"]


def test_parse_db_banner_mssql_tds():
    # TDS header 0x04 0x01 + textual marker
    banner = "\x04\x01\x00\x18Microsoft SQL Server 15.00.2000"
    info = parse_db_banner(banner, service="")
    assert info["db_type"] == "mssql"


def test_parse_db_banner_redis_pong():
    info = parse_db_banner("+PONG", service="redis")
    assert info["db_type"] == "redis"
    assert info["auth_required"] is False


def test_parse_db_banner_redis_noauth():
    info = parse_db_banner("-NOAUTH Authentication required.", service="redis")
    assert info["db_type"] == "redis"
    assert info["auth_required"] is True


def test_parse_db_banner_garbage():
    info = parse_db_banner("blah blah nothing useful here")
    assert info["db_type"] == "unknown"


# ---------------------------------------------------------------------------
# parse_udp_nmap_output
# ---------------------------------------------------------------------------

GREPABLE_UDP = (
    "Host: 10.0.0.5 (host.example)  Status: Up\n"
    "Host: 10.0.0.5 (host.example)\tPorts: 68/open|filtered/udp//tcpwrapped///, "
    "137/open/udp//netbios-ns///, 138/open/udp//netbios-dgm///, "
    "5353/open/udp//mdns//Apple Bonjour mDNS//, 123/filtered/udp/////"
)


def test_parse_udp_nmap_grepable():
    entries = parse_udp_nmap_output(GREPABLE_UDP)
    assert isinstance(entries, list)
    assert len(entries) >= 4
    udp_ports = {e["port"] for e in entries}
    assert 137 in udp_ports
    assert 138 in udp_ports
    assert 5353 in udp_ports
    # 123/filtered must be skipped (closed/filtered-uninteresting)
    assert 123 not in udp_ports
    for e in entries:
        assert e["protocol"] == "udp"
        assert isinstance(e["port"], int)


def test_parse_udp_nmap_xml():
    xml = """<nmaprun><host>
      <ports>
        <port protocol="udp" portid="161"><state state="open"/><service name="snmp" product="net-snmp"/></port>
        <port protocol="udp" portid="5000"><state state="open|filtered"/><service name="upnp"/></port>
        <port protocol="udp" portid="9999"><state state="closed"/></port>
      </ports>
    </host></nmaprun>"""
    entries = parse_udp_nmap_output(xml)
    ports = {e["port"] for e in entries}
    assert 161 in ports
    assert 5000 in ports
    assert 9999 not in ports  # closed skipped
    snmp = next(e for e in entries if e["port"] == 161)
    assert snmp["service"] == "snmp"
    assert snmp["protocol"] == "udp"


def test_parse_udp_nmap_empty():
    assert parse_udp_nmap_output("") == []
    assert parse_udp_nmap_output(None) == []


def test_parse_udp_nmap_garbage_never_raises():
    out = parse_udp_nmap_output("!!! garbage \x00 junk <<<")
    assert out == []


# ---------------------------------------------------------------------------
# http_spider
# ---------------------------------------------------------------------------

def _fake_fetch_factory(pages: dict):
    """Build a fetch_fn that returns canned (status, body) by path."""
    def fetch(url):
        # url is the full URL; match by path suffix
        for path, body in pages.items():
            if url.endswith(path):
                return (200, body)
        return (404, "")
    return fetch


def test_http_spider_basic_links_and_visited():
    pages = {
        "/": '<html><body><a href="/about">About</a><a href="/login">Login</a></body></html>',
        "/about": "<html>about</html>",
        "/login": "<html>login</html>",
    }
    result = http_spider("10.0.0.5", 8080, fetch_fn=_fake_fetch_factory(pages), max_pages=5)
    assert result["target_ip"] == "10.0.0.5"
    assert result["port"] == 8080
    assert "/" in result["urls_visited"]
    assert "/about" in result["links"]
    assert "/login" in result["links"]
    # BFS should have crawled /about and /login too
    assert "/about" in result["urls_visited"] or "/login" in result["urls_visited"]
    assert result["status_codes"]["/"] == 200


def test_http_spider_max_pages_bound():
    # Provide many links from /, ensure visited <= max_pages.
    body = "".join(f'<a href="/p{i}">x</a>' for i in range(50))
    pages = {"/": body}
    for i in range(50):
        pages[f"/p{i}"] = "<html>x</html>"
    result = http_spider("10.0.0.5", 80, fetch_fn=_fake_fetch_factory(pages), max_pages=10)
    assert len(result["urls_visited"]) <= 10


def test_http_spider_forms_counted():
    pages = {
        "/": '<html><form action="/submit"></form><a href="/x">x</a></html>',
        "/x": "<html></html>",
    }
    result = http_spider("10.0.0.5", 80, fetch_fn=_fake_fetch_factory(pages), max_pages=5)
    assert result["forms"] >= 1


def test_http_spider_fetch_exception_skipped_no_raise():
    def bad_fetch(url):
        raise RuntimeError("boom")
    # Must NOT raise even when every fetch raises.
    result = http_spider("10.0.0.5", 80, fetch_fn=bad_fetch, max_pages=5)
    assert result["target_ip"] == "10.0.0.5"
    assert "/" in result["urls_visited"]
    assert result["status_codes"]["/"] == 0
    assert result["links"] == []


def test_http_spider_required_keys():
    result = http_spider("10.0.0.5", 80, fetch_fn=lambda u: (200, ""), max_pages=1)
    for key in ("target_ip", "port", "urls_visited", "links", "forms",
                "status_codes", "technologies"):
        assert key in result


def test_http_spider_offsite_links_not_fetched():
    # Absolute off-site links must be recorded as links but never fetched.
    pages = {
        "/": '<a href="https://external.example.com/evil">ext</a><a href="/local">local</a>',
        "/local": "<html>local</html>",
    }
    fetched = []

    def fetch(url):
        fetched.append(url)
        for path, body in pages.items():
            if url.endswith(path):
                return (200, body)
        return (200, "")

    result = http_spider("10.0.0.5", 80, fetch_fn=fetch, max_pages=5)
    assert "https://external.example.com/evil" in result["links"]
    # Only same-target paths should be fetched (no external.example.com URL).
    assert all("external.example.com" not in u for u in fetched)


def test_http_spider_technologies_detected():
    pages = {
        "/": '<html><head><meta name="generator" content="WordPress 6.0"></head><body>x</body></html>',
    }
    result = http_spider("10.0.0.5", 80, fetch_fn=_fake_fetch_factory(pages), max_pages=2)
    assert any("WordPress" in t for t in result["technologies"])


def test_http_spider_javascript_links_ignored():
    pages = {
        "/": '<a href="javascript:void(0)">x</a><a href="mailto:a@b.com">m</a><a href="#anchor">a</a>',
    }
    result = http_spider("10.0.0.5", 80, fetch_fn=_fake_fetch_factory(pages), max_pages=2)
    # Only the start page visited; no further crawling of js/mailto/# links.
    assert result["urls_visited"] == ["/"]


def test_http_spider_relative_link_resolution():
    # Root links to /dir/page, which links to a relative "next" -> /dir/next.
    pages = {
        "/": '<a href="/dir/page">go</a>',
        "/dir/page": '<a href="next">next</a>',
        "/dir/next": "<html>ok</html>",
    }
    result = http_spider("10.0.0.5", 80, fetch_fn=_fake_fetch_factory(pages), max_pages=5)
    assert "/dir/next" in result["urls_visited"] or "/dir/next" in result["links"]


def test_http_spider_default_args_run_without_network_when_mocked():
    # Sanity: default scheme http, default max_pages 20 — just verify shape
    # with a mocked fetch that returns empty bodies (no network).
    result = http_spider("10.0.0.5", 80, fetch_fn=lambda u: (200, ""))
    assert result["port"] == 80
    assert result["urls_visited"] == ["/"]
