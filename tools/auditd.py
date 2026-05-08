from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "auditd"

_VALID_JOURNAL_UNITS = {
    "zeek", "snort3", "auditd", "splunk", "splunkforwarder",
    "ssh", "cron", "networking", "systemd-networkd", "ufw",
}


def auditd_recent(hostname: str, lines: int = 50) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"tail -n {lines} /var/log/audit/audit.log", user=resolve_ssh_user(hostname))


def auditd_recent_execve(hostname: str, lines: int = 30) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f"grep -m 100 'type=EXECVE' /var/log/audit/audit.log | tail -n {lines}",
    )


def auditd_login_events(hostname: str, lines: int = 30) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f"grep -m 100 -E 'type=USER_LOGIN|type=USER_AUTH|type=USER_ACCT' "
        f"/var/log/audit/audit.log | tail -n {lines}",
    )


def journal_errors(hostname: str, lines: int = 50) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"journalctl -p err -n {lines} --no-pager", user=resolve_ssh_user(hostname))


def journal_since_boot(hostname: str, lines: int = 100) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"journalctl -b -n {lines} --no-pager", user=resolve_ssh_user(hostname))


def journal_unit(hostname: str, unit: str, lines: int = 50) -> str:
    lines = int(lines)
    unit = unit.strip().lower()
    if unit not in _VALID_JOURNAL_UNITS:
        return (
            f"[ERROR] Unit '{unit}' is not in the allowed list. "
            f"Allowed: {sorted(_VALID_JOURNAL_UNITS)}"
        )
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"journalctl -u {unit} -n {lines} --no-pager", user=resolve_ssh_user(hostname))