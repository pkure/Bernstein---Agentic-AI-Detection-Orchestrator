"""
Admin tools — Tier 2 (service control, file read, package install)
                Tier 3 (process kill — uses SIGTERM, not SIGKILL)

Safety rules (same pattern as all other tools):
- Service names validated against ALLOWED_SERVICES allowlist
- Package names validated against ALLOWED_PACKAGES allowlist
- File paths checked for shell metacharacters before use
- PIDs cast to int() — integers cannot contain shell metacharacters
- Every write operation is appended to logs/admin_actions.log
"""
import os
import datetime
from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "linux_common"

ALLOWED_SERVICES = {
    "zeek", "snort3", "auditd", "splunk", "splunkforwarder",
    "ssh", "sshd", "cron", "networking", "ufw", "fail2ban",
    "rsyslog", "filebeat", "nginx", "apache2", "wazuh-agent",
    "wazuh-manager", "tcpdump", "arkime",
}

ALLOWED_PACKAGES = {
    "nmap", "tcpdump", "tshark", "wireshark-common", "curl", "wget",
    "net-tools", "htop", "vim", "git", "python3", "python3-pip",
    "fail2ban", "ufw", "jq", "lsof", "strace", "netcat-openbsd",
    "dnsutils", "traceroute", "iotop", "sysstat", "unzip",
}


def _audit(hostname: str, command: str, output: str) -> None:
    os.makedirs("logs", exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    with open("logs/admin_actions.log", "a", encoding="utf-8") as f:
        first_line = output.strip().splitlines()[0] if output.strip() else "(no output — likely success)"
        f.write(f"[{ts}] {hostname}: {command}\n  → {first_line}\n\n")


def _safe_path(path: str) -> bool:
    """Reject paths containing shell metacharacters."""
    return not any(c in path for c in (';', '&', '|', '`', '$', '>', '<', '\n', '\r', ' '))


# ── Tier 2: Service control ────────────────────────────────────────────────────

def service_restart(hostname: str, service: str) -> str:
    if service not in ALLOWED_SERVICES:
        return f"[BLOCKED] '{service}' is not in ALLOWED_SERVICES"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = f"sudo systemctl restart {service}"
    out = _ssh_run(ip, cmd, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out or f"Service '{service}' restarted (no output = success)"


def service_start(hostname: str, service: str) -> str:
    if service not in ALLOWED_SERVICES:
        return f"[BLOCKED] '{service}' is not in ALLOWED_SERVICES"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = f"sudo systemctl start {service}"
    out = _ssh_run(ip, cmd, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out or f"Service '{service}' started"


def service_stop(hostname: str, service: str) -> str:
    if service not in ALLOWED_SERVICES:
        return f"[BLOCKED] '{service}' is not in ALLOWED_SERVICES"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = f"sudo systemctl stop {service}"
    out = _ssh_run(ip, cmd, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out or f"Service '{service}' stopped"


def service_status(hostname: str, service: str) -> str:
    """Read-only (Tier 1) — shows full systemctl status output."""
    if service not in ALLOWED_SERVICES:
        return f"[BLOCKED] '{service}' is not in ALLOWED_SERVICES"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"sudo systemctl status {service} --no-pager", user=resolve_ssh_user(hostname))


# ── Tier 2: File read ──────────────────────────────────────────────────────────

def read_file(hostname: str, path: str) -> str:
    """Read any file on a host — useful for config inspection.
    Uses sudo so it can read protected files like /etc/hosts, /etc/passwd.
    Path is checked for metacharacters; never passes user input to the shell.
    """
    if not _safe_path(path):
        return "[BLOCKED] path contains disallowed characters"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    # Quote the path in the command to handle directories with spaces
    return _ssh_run(ip, f"sudo cat '{path}'", user=resolve_ssh_user(hostname))


def list_directory(hostname: str, path: str) -> str:
    """List a directory on a host (ls -la)."""
    if not _safe_path(path):
        return "[BLOCKED] path contains disallowed characters"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"ls -la '{path}'", user=resolve_ssh_user(hostname))


# ── Tier 2: Package management ─────────────────────────────────────────────────

def apt_install(hostname: str, package: str) -> str:
    if package not in ALLOWED_PACKAGES:
        return f"[BLOCKED] '{package}' is not in ALLOWED_PACKAGES"
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = f"sudo apt-get install -y {package}"
    out = _ssh_run(ip, cmd, timeout=120, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out


def apt_update(hostname: str) -> str:
    """Run apt-get update to refresh package lists."""
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = "sudo apt-get update"
    out = _ssh_run(ip, cmd, timeout=60, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out


# ── Tier 3: Process management ─────────────────────────────────────────────────

def process_kill(hostname: str, pid: int) -> str:
    """Send SIGTERM (graceful) to a process by PID. Use process_list first to confirm."""
    pid = int(pid)  # cast ensures no injection — integers are shell-safe
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = f"kill -15 {pid}"
    out = _ssh_run(ip, cmd, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out or f"SIGTERM sent to PID {pid} (no output = process signaled)"


def process_kill_force(hostname: str, pid: int) -> str:
    """Send SIGKILL (immediate) to a process. Use only when SIGTERM fails."""
    pid = int(pid)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    cmd = f"kill -9 {pid}"
    out = _ssh_run(ip, cmd, user=resolve_ssh_user(hostname))
    _audit(hostname, cmd, out)
    return out or f"SIGKILL sent to PID {pid}"
