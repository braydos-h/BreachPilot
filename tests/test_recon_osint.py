"""Tests for tools.recon_osint — all fakes injected, no real network."""

from tools.recon_osint import (
    crtsh_cert_transparency,
    passive_ipv6_lookup,
    reverse_dns,
    run_osint,
    shodan_lookup,
)

# --- passive_ipv6_lookup ---------------------------------------------------


def test_passive_ipv6_lookup_returns_list():
    def fake(host):
        assert host == "example.com"
        return ["2001:db8::1"]

    assert passive_ipv6_lookup("example.com", resolver_fn=fake) == ["2001:db8::1"]


def test_passive_ipv6_lookup_resolver_raises_returns_empty():
    def boom(host):
        raise OSError("dns down")

    assert passive_ipv6_lookup("example.com", resolver_fn=boom) == []


def test_passive_ipv6_lookup_empty_host_returns_empty():
    assert passive_ipv6_lookup("", resolver_fn=lambda h: ["2001:db8::1"]) == []


# --- reverse_dns -----------------------------------------------------------


def test_reverse_dns_returns_hostname():
    def fake(ip):
        assert ip == "1.2.3.4"
        return "host.example"

    assert reverse_dns("1.2.3.4", resolver_fn=fake) == "host.example"


def test_reverse_dns_resolver_raises_returns_empty():
    def boom(ip):
        raise OSError("no ptr")

    assert reverse_dns("1.2.3.4", resolver_fn=boom) == ""


# --- crtsh_cert_transparency -----------------------------------------------


def test_crtsh_parses_json_list():
    payload = '[{"id":1,"name":"*.example.com"},{"id":2,"name":"example.com"}]'

    def fake(url):
        assert "crt.sh" in url and "example.com" in url and "output=json" in url
        return payload

    res = crtsh_cert_transparency("example.com", fetch_fn=fake)
    assert res["domain"] == "example.com"
    assert res["count"] == 2
    assert len(res["certs"]) == 2
    assert "error" not in res


def test_crtsh_fetch_raises_returns_error_shape():
    def boom(url):
        raise OSError("network down")

    res = crtsh_cert_transparency("example.com", fetch_fn=boom)
    assert res["certs"] == []
    assert res["count"] == 0
    assert "error" in res and "fetch failed" in res["error"]


def test_crtsh_empty_domain_handled():
    res = crtsh_cert_transparency("", fetch_fn=lambda u: "[]")
    assert res["certs"] == []
    assert res["count"] == 0
    assert "error" in res


def test_crtsh_bad_json_returns_error():
    res = crtsh_cert_transparency("example.com", fetch_fn=lambda u: "not json")
    assert res["certs"] == []
    assert res["count"] == 0
    assert "parse failed" in res["error"]


# --- shodan_lookup ---------------------------------------------------------


def test_shodan_no_api_key_disabled():
    res = shodan_lookup("1.2.3.4", "")
    assert res == {"enabled": False, "note": "no Shodan API key configured"}


def test_shodan_with_key_returns_data():
    payload = '{"ip_str":"1.2.3.4","ports":[80,443]}'

    def fake(url):
        assert "api.shodan.io" in url and "1.2.3.4" in url and "KEY" in url
        return payload

    res = shodan_lookup("1.2.3.4", "KEY", fetch_fn=fake)
    assert res["enabled"] is True
    assert res["ip"] == "1.2.3.4"
    assert res["data"]["ports"] == [80, 443]


def test_shodan_fetch_raises_returns_error():
    def boom(url):
        raise OSError("down")

    res = shodan_lookup("1.2.3.4", "KEY", fetch_fn=boom)
    assert res["enabled"] is True
    assert "fetch failed" in res["error"]


# --- run_osint -------------------------------------------------------------


def test_run_osint_aggregates_with_fakes():
    def resolver_fn(host):
        if host == "1.2.3.4":
            return "host.example"
        # AAAA lookup path
        return ["2001:db8::1", "2001:db8::2"]

    def fetch_fn(url):
        if "crt.sh" in url:
            return '[{"name":"host.example"}]'
        if "shodan" in url:
            return '{"ip_str":"1.2.3.4"}'
        return ""

    res = run_osint(
        "1.2.3.4",
        shodan_api_key="KEY",
        resolver_fn=resolver_fn,
        fetch_fn=fetch_fn,
    )

    assert res["target_ip"] == "1.2.3.4"
    assert res["hostname"] == "host.example"
    assert res["reverse_dns"] == "host.example"
    assert isinstance(res["ipv6_addresses"], list)
    assert "2001:db8::1" in res["ipv6_addresses"]
    assert res["cert_transparency"]["count"] == 1
    assert res["shodan"]["enabled"] is True
    assert "data" in res["shodan"]


def test_run_osint_no_shodan_key():
    res = run_osint(
        "1.2.3.4",
        hostname="host.example",
        resolver_fn=lambda h: ["2001:db8::1"] if h != "1.2.3.4" else "host.example",
        fetch_fn=lambda u: "[]",
    )
    assert res["shodan"] == {"enabled": False, "note": "no Shodan API key configured"}
    assert res["ipv6_addresses"] == ["2001:db8::1"]


def test_run_osint_never_raises_when_fakes_raise():
    def boom_resolver(x):
        raise OSError("down")

    def boom_fetch(x):
        raise OSError("down")

    res = run_osint(
        "1.2.3.4",
        shodan_api_key="KEY",
        resolver_fn=boom_resolver,
        fetch_fn=boom_fetch,
    )
    # Must still return the expected shape, never raise.
    assert res["target_ip"] == "1.2.3.4"
    assert res["ipv6_addresses"] == []
    assert res["reverse_dns"] == ""
    assert res["cert_transparency"]["certs"] == []
    assert res["shodan"]["enabled"] is True
    assert "error" in res["shodan"]


def test_run_osint_no_hostname_skips_crtsh():
    # reverse_dns returns "" and no hostname given -> no crt.sh call.
    res = run_osint(
        "1.2.3.4",
        resolver_fn=lambda ip: "",
        fetch_fn=lambda u: "should-not-be-called",
    )
    assert res["hostname"] == ""
    assert res["cert_transparency"]["count"] == 0
    assert "error" in res["cert_transparency"]
