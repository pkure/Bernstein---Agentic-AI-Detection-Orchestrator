"""Splunk REST API tools — uses HTTP, not SSH.

Authentication uses a token stored in config_local.py as SPLUNK_TOKEN.
All SPL search strings are hardcoded. The only variable input is `count` (integer).
"""
import time
import requests
import urllib3
from safety import HostNotAllowedError

# Splunk in the lab uses a self-signed cert — suppress the noisy warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SPLUNK_PORT = 8089
_SEARCH_ENDPOINT = "/services/search/jobs"
_HEALTH_ENDPOINT = "/services/server/health/splunkd"


def _get_token() -> str:
    try:
        from config_local import SPLUNK_TOKEN  # type: ignore[import]
        return SPLUNK_TOKEN
    except (ImportError, AttributeError):
        raise HostNotAllowedError(
            "SPLUNK_TOKEN is not set in config_local.py. "
            "Create a Splunk API token and add: SPLUNK_TOKEN = '...'"
        )


def _get_splunk_url() -> str:
    try:
        from config import ALLOWED_HOSTS
        ip = ALLOWED_HOSTS.get("splunksiem")
        if not ip:
            raise HostNotAllowedError(
                "'splunksiem' is not in ALLOWED_HOSTS. Add it to config_local.py."
            )
        return f"https://{ip}:{_SPLUNK_PORT}"
    except Exception as e:
        raise HostNotAllowedError(str(e))


def _run_search(spl: str, count: int, timeout: int = 60) -> str:
    """Submit a one-shot Splunk search and return results as text."""
    base_url = _get_splunk_url()
    token = _get_token()
    headers = {"Authorization": f"Bearer {token}"}

    try:
        # Create search job
        resp = requests.post(
            f"{base_url}{_SEARCH_ENDPOINT}",
            headers=headers,
            data={
                "search": f"search {spl}",
                "output_mode": "json",
                "exec_mode": "normal",
                "count": str(count),
            },
            verify=False,  # self-signed cert in lab environment
            timeout=30,
        )
        resp.raise_for_status()
        sid = resp.json()["sid"]

        # Poll until done
        deadline = time.time() + timeout
        while time.time() < deadline:
            status_resp = requests.get(
                f"{base_url}{_SEARCH_ENDPOINT}/{sid}",
                headers=headers,
                params={"output_mode": "json"},
                verify=False,
                timeout=15,
            )
            status_resp.raise_for_status()
            state = status_resp.json()["entry"][0]["content"]["dispatchState"]
            if state == "DONE":
                break
            time.sleep(2)
        else:
            return "[ERROR] Splunk search timed out"

        # Fetch results
        results_resp = requests.get(
            f"{base_url}{_SEARCH_ENDPOINT}/{sid}/results",
            headers=headers,
            params={"output_mode": "json", "count": str(count)},
            verify=False,
            timeout=15,
        )
        results_resp.raise_for_status()
        results = results_resp.json().get("results", [])
        if not results:
            return "(no results)"
        return "\n".join(str(r) for r in results)

    except requests.RequestException as e:
        return f"[ERROR] Splunk API request failed: {e}"


def splunk_health_check() -> str:
    base_url = _get_splunk_url()
    token = _get_token()
    try:
        resp = requests.get(
            f"{base_url}{_HEALTH_ENDPOINT}",
            headers={"Authorization": f"Bearer {token}"},
            params={"output_mode": "json"},
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        return f"[ERROR] Splunk health check failed: {e}"


def splunk_recent_alerts(count: int = 20, hours: int = 24) -> str:
    count, hours = int(count), int(hours)
    return _run_search(
        f"index=main sourcetype=WinEventLog earliest=-{hours}h | head {count}",
        count,
    )


def splunk_sysmon_process_create(count: int = 20, hours: int = 24) -> str:
    count, hours = int(count), int(hours)
    return _run_search(
        f"index=wineventlog sourcetype=XmlWinEventLog EventCode=1 earliest=-{hours}h | head {count}",
        count,
    )


def splunk_sysmon_network(count: int = 20, hours: int = 24) -> str:
    count, hours = int(count), int(hours)
    return _run_search(
        f"index=wineventlog sourcetype=XmlWinEventLog EventCode=3 earliest=-{hours}h | head {count}",
        count,
    )


def splunk_failed_logins(count: int = 20, hours: int = 24) -> str:
    count, hours = int(count), int(hours)
    # EventCode 4625 = Windows logon failure. This is a Security channel event
    # (not Sysmon), so it arrives as WinEventLog or WinEventLog:Security — NOT
    # XmlWinEventLog. Search both wineventlog and main without a sourcetype filter.
    return _run_search(
        f"(index=wineventlog OR index=main) EventCode=4625 earliest=-{hours}h | head {count}",
        count,
    )


def splunk_linux_audit(count: int = 20, hours: int = 24) -> str:
    count, hours = int(count), int(hours)
    return _run_search(
        f"index=main sourcetype=\"linux:audit\" earliest=-{hours}h | head {count}",
        count,
    )


def splunk_dns_events(count: int = 20, hours: int = 24) -> str:
    count, hours = int(count), int(hours)
    return _run_search(
        f"index=main sourcetype=dns earliest=-{hours}h | head {count}",
        count,
    )
