"""Tests for tools.recon_diff — pure recon snapshot diffing."""

from tools.recon_diff import diff_recon, diff_recon_files


def _svc(port, service="http", version=None, banner=None, ssl_info=None, scripts=None):
    return {
        "port": port,
        "protocol": "tcp",
        "service": service,
        "version": version,
        "banner": banner,
        "cpe": None,
        "scripts": scripts or {},
        "ssl_info": ssl_info,
    }


def _snap(target_ip="10.0.0.50", os_family="Linux", open_ports=None, filtered_ports=None, services=None):
    return {
        "target_ip": target_ip,
        "os_family": os_family,
        "open_ports": open_ports or [],
        "filtered_ports": filtered_ports or [],
        "services": services or [],
    }


def test_identical_snapshots_no_changes():
    snap = _snap(open_ports=[22, 80], services=[_svc(22, "ssh"), _svc(80, "http")])
    d = diff_recon(snap, snap)
    assert d["added_ports"] == []
    assert d["removed_ports"] == []
    assert d["changed_services"] == []
    assert d["new_cves"] == []
    assert d["lost_cves"] == []
    assert d["os_changed"] is False
    assert d["summary"] == "no changes"


def test_added_port():
    old = _snap(open_ports=[22, 80])
    new = _snap(open_ports=[22, 80, 8080])
    d = diff_recon(old, new)
    assert d["added_ports"] == [8080]
    assert d["removed_ports"] == []


def test_removed_port():
    old = _snap(open_ports=[22, 80])
    new = _snap(open_ports=[80])
    d = diff_recon(old, new)
    assert d["removed_ports"] == [22]
    assert d["added_ports"] == []


def test_version_change():
    old = _snap(services=[_svc(80, "http", version="nginx 1.18")])
    new = _snap(services=[_svc(80, "http", version="nginx 1.19")])
    d = diff_recon(old, new)
    assert len(d["changed_services"]) == 1
    entry = d["changed_services"][0]
    assert entry["port"] == 80
    assert entry["field"] == "version"
    assert entry["old"] == "nginx 1.18"
    assert entry["new"] == "nginx 1.19"
    assert entry["service"] == "http"


def test_service_name_change():
    old = _snap(services=[_svc(80, "http")])
    new = _snap(services=[_svc(80, "https")])
    d = diff_recon(old, new)
    entries = [e for e in d["changed_services"] if e["field"] == "service"]
    assert len(entries) == 1
    assert entries[0]["old"] == "http"
    assert entries[0]["new"] == "https"


def test_banner_change():
    old = _snap(services=[_svc(22, "ssh", banner="OpenSSH 8.2")])
    new = _snap(services=[_svc(22, "ssh", banner="OpenSSH 8.9")])
    d = diff_recon(old, new)
    entries = [e for e in d["changed_services"] if e["field"] == "banner"]
    assert len(entries) == 1
    assert entries[0]["old"] == "OpenSSH 8.2"
    assert entries[0]["new"] == "OpenSSH 8.9"


def test_ssl_info_appearance():
    old = _snap(services=[_svc(443, "https")])
    new = _snap(services=[_svc(443, "https", ssl_info={"issuer": "Let's Encrypt"})])
    d = diff_recon(old, new)
    entries = [e for e in d["changed_services"] if e["field"] == "ssl_info"]
    assert len(entries) == 1


def test_new_and_lost_cves():
    old = _snap(
        services=[
            _svc(443, "https", scripts={"vulners": "CVE-2021-44228 found"}),
        ]
    )
    new = _snap(
        services=[
            _svc(443, "https", scripts={"vulners": "CVE-2022-22965 found"}),
        ]
    )
    d = diff_recon(old, new)
    assert "CVE-2022-22965" in d["new_cves"]
    assert "CVE-2021-44228" in d["lost_cves"]


def test_os_family_change():
    old = _snap(os_family="Linux")
    new = _snap(os_family="Windows")
    d = diff_recon(old, new)
    assert d["os_changed"] is True
    assert d["old_os"] == "Linux"
    assert d["new_os"] == "Windows"


def test_empty_and_none_snapshots():
    d = diff_recon({}, {})
    assert d["added_ports"] == []
    assert d["removed_ports"] == []
    assert d["changed_services"] == []
    assert d["new_cves"] == []
    assert d["lost_cves"] == []
    assert d["os_changed"] is False
    # None must not raise; treated as {}
    d2 = diff_recon(None, {})
    assert d2["added_ports"] == []
    d3 = diff_recon(None, None)
    assert d3["changed_services"] == []


def test_missing_keys_do_not_raise():
    # snapshots lacking services/open_ports entirely
    d = diff_recon({"target_ip": "10.0.0.5"}, {"target_ip": "10.0.0.5"})
    assert d["added_ports"] == []
    assert d["target_ip"] == "10.0.0.5"
    assert d["summary"] == "no changes"


def test_diff_recon_files_loads_and_diffs(tmp_path):
    old = _snap(open_ports=[22], services=[_svc(22, "ssh", version="OpenSSH 8.2")])
    new = _snap(open_ports=[22, 80], services=[_svc(22, "ssh", version="OpenSSH 8.9"), _svc(80, "http")])
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(__import__("json").dumps(old), encoding="utf-8")
    new_path.write_text(__import__("json").dumps(new), encoding="utf-8")
    d = diff_recon_files(str(old_path), str(new_path))
    assert d["added_ports"] == [80]
    entries = [e for e in d["changed_services"] if e["field"] == "version"]
    assert len(entries) == 1


def test_diff_recon_files_missing_file_returns_error(tmp_path):
    new_path = tmp_path / "new.json"
    new_path.write_text("{}", encoding="utf-8")
    d = diff_recon_files(str(tmp_path / "does_not_exist.json"), str(new_path))
    assert "error" in d
    # must not raise; no other keys present alongside error necessarily


def test_diff_recon_files_invalid_json_returns_error(tmp_path):
    old_path = tmp_path / "bad.json"
    new_path = tmp_path / "new.json"
    old_path.write_text("{not valid json", encoding="utf-8")
    new_path.write_text("{}", encoding="utf-8")
    d = diff_recon_files(str(old_path), str(new_path))
    assert "error" in d


def test_port_normalization_string_ports():
    # ports may arrive as strings; should normalize to int and diff correctly
    old = {"open_ports": ["22", "80"]}
    new = {"open_ports": [22, 80, 8080]}
    d = diff_recon(old, new)
    assert d["added_ports"] == [8080]
