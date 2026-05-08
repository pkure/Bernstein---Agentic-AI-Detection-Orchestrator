from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "silk"

# SiLK flow data date range for "today" queries
_DATE_RANGE = "--start-date=now/d --end-date=now/d"


def silk_top_talkers(hostname: str, count: int = 20) -> str:
    count = int(count)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f"rwfilter {_DATE_RANGE} --type=all --pass=stdout "
        f"| rwstats --fields=sIP,dIP --values=bytes --count={count}",
        timeout=60,
    )


def silk_recent_flows(hostname: str, count: int = 30) -> str:
    count = int(count)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f"rwfilter {_DATE_RANGE} --type=all --pass=stdout "
        f"| rwcut --fields=sIP,dIP,sPort,dPort,proto,bytes,packets,sTime "
        f"--num-recs={count}",
        timeout=60,
    )


def silk_port_scan_detect(hostname: str, count: int = 20) -> str:
    count = int(count)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f"rwfilter {_DATE_RANGE} --type=all --pass=stdout "
        f"| rwstats --fields=dPort --values=records --count={count}",
        timeout=60,
    )


def silk_external_connections(hostname: str, count: int = 20) -> str:
    count = int(count)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f"rwfilter {_DATE_RANGE} --type=out --pass=stdout "
        f"| rwcut --fields=sIP,dIP,dPort,proto,bytes --num-recs={count}",
        timeout=60,
    )