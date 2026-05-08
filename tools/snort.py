from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "snort"


def snort_alerts(hostname: str, lines: int = 50) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f"tail -n {lines} /var/log/snort/alert_fast.txt", user=resolve_ssh_user(hostname))


def snort_stats(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "tail -n 50 /var/log/snort/snort.stats", user=resolve_ssh_user(hostname))


def snort_service_status(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "systemctl status snort3 --no-pager --lines=20", user=resolve_ssh_user(hostname))