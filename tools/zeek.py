from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "zeek"

# Adjust this path if Zeek was installed via package manager (/var/log/zeek/current/)
# rather than from source (/opt/zeek/logs/current/)
_ZEEK_LOG_DIR = "/opt/zeek/logs/current"


def _zeek_log(ip: str, hostname: str, logfile: str, lines: int) -> str:
    lines = int(lines)
    return _ssh_run(ip, f"tail -n {lines} {_ZEEK_LOG_DIR}/{logfile}", user=resolve_ssh_user(hostname))


def zeek_conn_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "conn.log", lines)


def zeek_dns_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "dns.log", lines)


def zeek_http_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "http.log", lines)


def zeek_ssl_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "ssl.log", lines)


def zeek_weird_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "weird.log", lines)


def zeek_notice_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "notice.log", lines)


def zeek_files_log(hostname: str, lines: int = 50) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _zeek_log(ip, hostname, "files.log", lines)


def zeek_list_log_dates(hostname: str) -> str:
    """List available date-stamped Zeek log archives."""
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ls /opt/zeek/logs/", user=resolve_ssh_user(hostname))