"""
Tool registry — maps every callable tool to its metadata.

The agent uses this to build the planning prompt and to dispatch calls.
Each entry:
  fn             - callable
  description    - one line for the planning prompt
  capability     - key from VM_CAPABILITIES
  has_host_param - whether fn(hostname, ...) is the signature
  has_lines_param - whether fn accepts lines= kwarg
  tier           - 1=read-only (auto), 2=admin (confirm), 3=destructive (type 'yes')
  params_schema  - dict of extra param names → types the LLM can pass (e.g. {"service": str})
"""
from tools.zeek import (
    zeek_conn_log, zeek_dns_log, zeek_http_log, zeek_ssl_log,
    zeek_weird_log, zeek_notice_log, zeek_files_log, zeek_list_log_dates,
)
from tools.snort import snort_alerts, snort_stats, snort_service_status
from tools.auditd import (
    auditd_recent, auditd_recent_execve, auditd_login_events,
    journal_errors, journal_since_boot,
)
from tools.linux_common import (
    net_connections, net_listening, net_udp_connections,
    arp_table, routing_table, interface_stats, interface_config,
    process_list, process_tree, open_connections_established,
    disk_usage, memory_usage,
    who_logged_in, last_logins, failed_logins,
    cron_jobs, system_cron, uptime_info, hostname_info, ssh_check,
)
from tools.silk import (
    silk_top_talkers, silk_recent_flows,
    silk_port_scan_detect, silk_external_connections,
)
from tools.splunk import (
    splunk_health_check, splunk_recent_alerts,
    splunk_sysmon_process_create, splunk_sysmon_network, splunk_failed_logins,
    splunk_linux_audit, splunk_dns_events,
)
from tools.windows import (
    win_process_list, win_network_connections, win_listening_ports,
    win_failed_logins, win_services, win_uptime, win_ssh_check,
)
from tools.admin import (
    service_restart, service_start, service_stop, service_status,
    read_file, list_directory,
    apt_install, apt_update,
    process_kill, process_kill_force,
)

# Each entry shape:
#   fn               - callable
#   description      - one line for the planning prompt
#   capability       - key from VM_CAPABILITIES
#   has_host_param   - whether fn(hostname, ...) is the signature
#   has_lines_param  - whether fn accepts lines= kwarg
TOOLS: dict[str, dict] = {
    # ── Zeek ──────────────────────────────────────────────────────────────
    "zeek_conn_log": {
        "fn": zeek_conn_log,
        "description": "Zeek TCP/UDP connection log — IPs, ports, bytes, duration",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_dns_log": {
        "fn": zeek_dns_log,
        "description": "Zeek DNS log — domain lookups, query types, responses",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_http_log": {
        "fn": zeek_http_log,
        "description": "Zeek HTTP log — web requests, URIs, user-agents, status codes",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_ssl_log": {
        "fn": zeek_ssl_log,
        "description": "Zeek SSL/TLS log — encrypted connections, certificates, versions",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_weird_log": {
        "fn": zeek_weird_log,
        "description": "Zeek weird.log — protocol anomalies flagged by Zeek",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_notice_log": {
        "fn": zeek_notice_log,
        "description": "Zeek notice.log — Zeek policy alerts and detections",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_files_log": {
        "fn": zeek_files_log,
        "description": "Zeek files.log — file transfers detected over the network",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "zeek_list_log_dates": {
        "fn": zeek_list_log_dates,
        "description": "List available date-stamped Zeek log archives",
        "capability": "zeek",
        "has_host_param": True,
        "has_lines_param": False,
    },
    # ── Snort ─────────────────────────────────────────────────────────────
    "snort_alerts": {
        "fn": snort_alerts,
        "description": "Snort IDS alerts — signature-based network intrusion detections",
        "capability": "snort",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "snort_stats": {
        "fn": snort_stats,
        "description": "Snort performance and packet stats",
        "capability": "snort",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "snort_service_status": {
        "fn": snort_service_status,
        "description": "Snort3 systemd service status — is it running?",
        "capability": "snort",
        "has_host_param": True,
        "has_lines_param": False,
    },
    # ── Auditd / Journal ──────────────────────────────────────────────────
    "auditd_recent": {
        "fn": auditd_recent,
        "description": "Recent Linux audit log entries — syscall-level activity",
        "capability": "auditd",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "auditd_recent_execve": {
        "fn": auditd_recent_execve,
        "description": "Recent EXECVE audit events — what commands were run on the host",
        "capability": "auditd",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "auditd_login_events": {
        "fn": auditd_login_events,
        "description": "Audit log login/auth events — USER_LOGIN, USER_AUTH, USER_ACCT",
        "capability": "auditd",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "journal_errors": {
        "fn": journal_errors,
        "description": "Systemd journal error-level messages",
        "capability": "auditd",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "journal_since_boot": {
        "fn": journal_since_boot,
        "description": "All systemd journal messages since last boot",
        "capability": "auditd",
        "has_host_param": True,
        "has_lines_param": True,
    },
    # ── Linux Common ──────────────────────────────────────────────────────
    "net_connections": {
        "fn": net_connections,
        "description": "Active TCP connections on a host (ss -tnp)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "net_listening": {
        "fn": net_listening,
        "description": "TCP ports currently listening on a host (ss -tlnp)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "net_udp_connections": {
        "fn": net_udp_connections,
        "description": "Active UDP sockets on a host (ss -unp)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "arp_table": {
        "fn": arp_table,
        "description": "ARP neighbor table — known MAC/IP mappings on a host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "routing_table": {
        "fn": routing_table,
        "description": "IP routing table on a host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "interface_stats": {
        "fn": interface_stats,
        "description": "Network interface packet/byte statistics on a host (ip -s link) — use interface_config instead for IP addresses",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "interface_config": {
        "fn": interface_config,
        "description": "Network interface IP addresses, netmasks, state (ifconfig/ip addr equivalent) — use for 'show network config', 'ifconfig', 'what is the IP', 'network interfaces'",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "process_list": {
        "fn": process_list,
        "description": "Running processes sorted by CPU on a host (ps aux)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "process_tree": {
        "fn": process_tree,
        "description": "Process tree showing parent/child relationships (ps auxf)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "open_connections_established": {
        "fn": open_connections_established,
        "description": "Established TCP connections only on a host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "disk_usage": {
        "fn": disk_usage,
        "description": "Filesystem disk usage on a host (df -h)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "memory_usage": {
        "fn": memory_usage,
        "description": "RAM and swap usage on a host (free -h)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "who_logged_in": {
        "fn": who_logged_in,
        "description": "Currently logged-in users on a host (who)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "last_logins": {
        "fn": last_logins,
        "description": "Login history on a host (last command)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "failed_logins": {
        "fn": failed_logins,
        "description": "Failed login attempts on a host — potential brute force (lastb)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "cron_jobs": {
        "fn": cron_jobs,
        "description": "Crontab entries for the current user on a host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "system_cron": {
        "fn": system_cron,
        "description": "System-wide cron job directories on a host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "uptime_info": {
        "fn": uptime_info,
        "description": "Uptime and load average on a host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "hostname_info": {
        "fn": hostname_info,
        "description": "OS and kernel info on a host (uname -a)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "ssh_check": {
        "fn": ssh_check,
        "description": "SSH connectivity/reachability check — confirms the host can be connected to, returns whoami + hostname + uptime",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
    },
    # ── SiLK ──────────────────────────────────────────────────────────────
    "silk_top_talkers": {
        "fn": silk_top_talkers,
        "description": "Top IP pairs by traffic volume from SiLK flow data",
        "capability": "silk",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "silk_recent_flows": {
        "fn": silk_recent_flows,
        "description": "Recent network flows from SiLK — src/dst IPs, ports, bytes",
        "capability": "silk",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "silk_port_scan_detect": {
        "fn": silk_port_scan_detect,
        "description": "Detect port scanning from SiLK flow data — top destination ports",
        "capability": "silk",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "silk_external_connections": {
        "fn": silk_external_connections,
        "description": "Outbound connections to external IPs from SiLK flow data",
        "capability": "silk",
        "has_host_param": True,
        "has_lines_param": False,
    },
    # ── Splunk (REST API — no host param) ─────────────────────────────────
    "splunk_health_check": {
        "fn": splunk_health_check,
        "description": "Check Splunk server health status via REST API",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    "splunk_recent_alerts": {
        "fn": splunk_recent_alerts,
        "description": "Recent IDS/security alerts from Splunk — accepts hours param (default 24)",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    "splunk_sysmon_process_create": {
        "fn": splunk_sysmon_process_create,
        "description": "Windows Sysmon process creation events from Splunk (EventCode 1) — accepts hours param",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    "splunk_sysmon_network": {
        "fn": splunk_sysmon_network,
        "description": "Windows Sysmon network connection events from Splunk (EventCode 3) — accepts hours param",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    "splunk_failed_logins": {
        "fn": splunk_failed_logins,
        "description": "Windows failed login events from Splunk (EventCode 4625) — accepts hours param",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    "splunk_linux_audit": {
        "fn": splunk_linux_audit,
        "description": "Linux auditd events from Splunk (linux:audit sourcetype) — accepts hours param",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    "splunk_dns_events": {
        "fn": splunk_dns_events,
        "description": "DNS query events from Splunk (Zeek DNS forwarded) — accepts hours param",
        "capability": "splunk_api",
        "has_host_param": False,
        "has_lines_param": False,
    },
    # ── Windows (PowerShell over SSH) ─────────────────────────────────────
    "win_process_list": {
        "fn": win_process_list,
        "description": "Running processes on a Windows host sorted by CPU",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "win_network_connections": {
        "fn": win_network_connections,
        "description": "Active network connections on a Windows host (netstat -ano)",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "win_listening_ports": {
        "fn": win_listening_ports,
        "description": "Listening TCP ports on a Windows host",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "win_failed_logins": {
        "fn": win_failed_logins,
        "description": "Recent Windows Security log failed login events",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": True,
    },
    "win_services": {
        "fn": win_services,
        "description": "Running Windows services on a host",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "win_uptime": {
        "fn": win_uptime,
        "description": "System uptime on a Windows host",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": False,
    },
    "win_ssh_check": {
        "fn": win_ssh_check,
        "description": "SSH connectivity/reachability check on a Windows host — confirms the host can be connected to, returns whoami and hostname",
        "capability": "windows",
        "has_host_param": True,
        "has_lines_param": False,
    },
    # ── Admin — Tier 2 (service control) ──────────────────────────────────────
    "service_status": {
        "fn": service_status,
        "description": "Show systemctl status for an allowlisted service on a Linux host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 1,
        "params_schema": {"service": str},
    },
    "service_restart": {
        "fn": service_restart,
        "description": "Restart an allowlisted service on a Linux host (zeek, snort3, auditd, splunk...)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {"service": str},
    },
    "service_start": {
        "fn": service_start,
        "description": "Start an allowlisted service on a Linux host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {"service": str},
    },
    "service_stop": {
        "fn": service_stop,
        "description": "Stop an allowlisted service on a Linux host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {"service": str},
    },
    # ── Admin — Tier 2 (file access) ──────────────────────────────────────────
    "read_file": {
        "fn": read_file,
        "description": "Read any file on a Linux host (sudo cat) — for config and log inspection",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {"path": str},
    },
    "list_directory": {
        "fn": list_directory,
        "description": "List a directory on a Linux host (ls -la)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {"path": str},
    },
    # ── Admin — Tier 2 (package management) ───────────────────────────────────
    "apt_install": {
        "fn": apt_install,
        "description": "Install an allowlisted package on a Linux host (apt-get install -y)",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {"package": str},
    },
    "apt_update": {
        "fn": apt_update,
        "description": "Run apt-get update to refresh package lists on a Linux host",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 2,
        "params_schema": {},
    },
    # ── Admin — Tier 3 (process management) ───────────────────────────────────
    "process_kill": {
        "fn": process_kill,
        "description": "Send SIGTERM (graceful stop) to a PID on a Linux host — run process_list first",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 3,
        "params_schema": {"pid": int},
    },
    "process_kill_force": {
        "fn": process_kill_force,
        "description": "Send SIGKILL (immediate kill) to a PID on a Linux host — use only if SIGTERM fails",
        "capability": "linux_common",
        "has_host_param": True,
        "has_lines_param": False,
        "tier": 3,
        "params_schema": {"pid": int},
    },
}


def tool_manifest_for_prompt(available_hosts: dict) -> str:
    """Build a plain-text tool list for injection into the planning prompt."""
    from config import VM_CAPABILITIES
    lines = []
    for name, meta in TOOLS.items():
        cap = meta["capability"]
        supported = [h for h, caps in VM_CAPABILITIES.items() if cap in caps and h in available_hosts]
        if not supported:
            continue
        hosts_str = ", ".join(supported) if meta["has_host_param"] else "n/a (API-based, targets splunksiem)"
        lines.append(f"  {name}: {meta['description']} | hosts: {hosts_str}")
    return "\n".join(lines)
