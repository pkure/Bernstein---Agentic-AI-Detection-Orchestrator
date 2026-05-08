from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "linux_common"


def net_connections(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ss -tnp", user=resolve_ssh_user(hostname))


def net_listening(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ss -tlnp", user=resolve_ssh_user(hostname))


def net_udp_connections(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ss -unp", user=resolve_ssh_user(hostname))


def arp_table(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ip neigh show", user=resolve_ssh_user(hostname))


def routing_table(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ip route show", user=resolve_ssh_user(hostname))


def interface_stats(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ip -s link show", user=resolve_ssh_user(hostname))


def process_list(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ps aux --sort=-%cpu", user=resolve_ssh_user(hostname))


def process_tree(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ps auxf", user=resolve_ssh_user(hostname))


def open_connections_established(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ss -tnp state established", user=resolve_ssh_user(hostname))


def disk_usage(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "df -h", user=resolve_ssh_user(hostname))


def memory_usage(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "free -h", user=resolve_ssh_user(hostname))


def who_logged_in(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "who", user=resolve_ssh_user(hostname))


def last_logins(hostname: str, lines: int = 20, since: str | None = None) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    # `since` is a datetime string computed in Python (never raw user input)
    since_flag = f'--since "{since}"' if since else ""
    return _ssh_run(ip, f"last -n {lines} {since_flag}".strip(), user=resolve_ssh_user(hostname))


def failed_logins(hostname: str, lines: int = 20, since: str | None = None) -> str:
    lines = int(lines)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    since_flag = f'--since "{since}"' if since else ""
    return _ssh_run(ip, f"lastb -n {lines} {since_flag}".strip(), user=resolve_ssh_user(hostname))


def cron_jobs(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "crontab -l", user=resolve_ssh_user(hostname))


def system_cron(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/", user=resolve_ssh_user(hostname))


def uptime_info(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "uptime", user=resolve_ssh_user(hostname))


def hostname_info(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "uname -a", user=resolve_ssh_user(hostname))


def interface_config(hostname: str) -> str:
    """Network interface configuration — IP addresses, netmasks, state (ifconfig equivalent)."""
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "ip addr show && echo '---ROUTES---' && ip route show", user=resolve_ssh_user(hostname))


def ssh_check(hostname: str) -> str:
    """Connectivity check — confirms SSH works and returns whoami + hostname + uptime."""
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, "echo user=$(whoami) host=$(hostname) && uptime", user=resolve_ssh_user(hostname))