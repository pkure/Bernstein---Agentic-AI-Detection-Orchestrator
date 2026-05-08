"""
Bernstein agentic loop.

Flow:
  1. plan()     — ask Ollama which tools to call given the user's question
  2. confirm()  — show Tier 2/3 (admin/destructive) tools and ask user approval
  3. execute()  — run approved tools, collect output
  4. triage()   — ask Ollama if findings warrant follow-up queries (second round)
  5. execute()  — run any follow-up tools (also confirmed if admin)
  6. synthesize() — ask Ollama to analyze all combined data and tell the story

Tool tiers:
  1 = read-only, runs automatically
  2 = admin (service control, file reads, package install) — needs y/N confirmation
  3 = destructive (process kill) — needs 'yes' typed in full
"""

import json
import re

from analysis import ask_ollama
from tools.registry import TOOLS, tool_manifest_for_prompt
from safety import HostNotAllowedError


def _resolve_tool_name(name: str) -> str:
    """Return the exact tool name, correcting obvious LLM hallucinations."""
    if name in TOOLS:
        return name
    # Try prefix match — e.g. "splunk" → first tool starting with "splunk_"
    matches = [k for k in TOOLS if k.startswith(name + "_") or k == name]
    if len(matches) == 1:
        print(f"  [warn] corrected tool name '{name}' → '{matches[0]}'")
        return matches[0]
    # Try substring match as last resort
    substr = [k for k in TOOLS if name in k]
    if len(substr) == 1:
        print(f"  [warn] corrected tool name '{name}' → '{substr[0]}'")
        return substr[0]
    return name  # return as-is; _execute will report the error


def _extract_hours(q: str) -> int:
    """Parse a time window from natural language. Returns hours, default 24."""
    m = re.search(r'(\d+)\s*week', q)
    if m:
        return int(m.group(1)) * 168
    m = re.search(r'(\d+)\s*day', q)
    if m:
        return int(m.group(1)) * 24
    m = re.search(r'(\d+)\s*hour', q)
    if m:
        return int(m.group(1))
    if 'week' in q:
        return 168
    if 'day' in q:
        return 24
    return 24


_MAX_OUTPUT_CHARS = 2500  # per-tool truncation before sending to LLM

# Tools in these categories indicate a security investigation — triage is only run for these.
_SECURITY_TOOL_PREFIXES = (
    "zeek_", "snort_", "auditd_", "silk_", "splunk_",
    "failed_logins", "win_failed_logins",
)


def _is_security_investigation(tool_calls: list[dict]) -> bool:
    """Return True if the planned tool calls include any security/detection tools."""
    return any(
        call.get("tool", "").startswith(prefix)
        for call in tool_calls
        for prefix in _SECURITY_TOOL_PREFIXES
    )


def _keyword_plan(question: str, available_hosts: dict) -> list[dict] | None:
    """
    Deterministic keyword planner for common admin and security requests.
    Returns tool calls on a match, None to fall through to the LLM planner.
    Handles simple/common patterns directly; complex compound queries fall through to the LLM.
    """
    from config import VM_CAPABILITIES

    q = question.lower()

    windows_hosts = frozenset(
        h for h in available_hosts if "windows" in VM_CAPABILITIES.get(h, set())
    )

    # First host name mentioned in the question
    mentioned_host = next((h for h in available_hosts if h.lower() in q), None)

    def _call(linux_tool: str, windows_tool: str, host: str) -> dict:
        return {"tool": windows_tool if host in windows_hosts else linux_tool,
                "host": host, "params": {}}

    # ── Connectivity / SSH check ───────────────────────────────────────────
    if any(p in q for p in (
        "connectivity", "connect to", "test connect", "is up", "can reach",
        "reachab", "ssh check", "ssh to", "ping",
    )):
        hosts = [mentioned_host] if mentioned_host else list(available_hosts.keys())
        calls = [_call("ssh_check", "win_ssh_check", h) for h in hosts]
        return calls or None

    # ── Network interface / ifconfig ───────────────────────────────────────
    if any(p in q for p in (
        "ifconfig", "ip addr", "network config", "network interface",
        "what is the ip", "show ip", "ip address", "show interface",
    )):
        host = mentioned_host or "ubuntulab"
        return [_call("interface_config", "win_network_connections", host)]

    # ── Processes ─────────────────────────────────────────────────────────
    if any(p in q for p in (
        "process", "ps aux", "what's running", "what is running",
        "running proc", "show proc", "top ",
    )):
        host = mentioned_host or "ubuntulab"
        return [_call("process_list", "win_process_list", host)]

    # ── Disk / storage ────────────────────────────────────────────────────
    if any(p in q for p in ("disk", "storage", "disk space", "how full", "filesystem")):
        host = mentioned_host or "ubuntulab"
        if host in windows_hosts:
            return None  # no Windows disk tool yet
        return [{"tool": "disk_usage", "host": host, "params": {}}]

    # ── Memory ────────────────────────────────────────────────────────────
    if any(p in q for p in ("memory", " ram", "how much memory", " swap")):
        host = mentioned_host or "ubuntulab"
        if host in windows_hosts:
            return None
        return [{"tool": "memory_usage", "host": host, "params": {}}]

    # ── Uptime ────────────────────────────────────────────────────────────
    if any(p in q for p in ("uptime", "load average", "how long up", "system load")):
        host = mentioned_host or "ubuntulab"
        if host in windows_hosts:
            return [{"tool": "win_uptime", "host": host, "params": {}}]
        return [{"tool": "uptime_info", "host": host, "params": {}}]

    # ── Listening ports ───────────────────────────────────────────────────
    if any(p in q for p in ("listening port", "open port", "what port", "which port")):
        host = mentioned_host or "ubuntulab"
        return [_call("net_listening", "win_listening_ports", host)]

    # ── Active connections ────────────────────────────────────────────────
    if any(p in q for p in (
        "active connection", "established connection", "who is connected", "net connection",
    )):
        host = mentioned_host or "ubuntulab"
        return [_call("net_connections", "win_network_connections", host)]

    # ── Services (Windows only — Linux needs a service name so let LLM handle) ──
    if any(p in q for p in ("services", "running services", "what services", "list services")):
        host = mentioned_host
        if host and host in windows_hosts:
            return [{"tool": "win_services", "host": host, "params": {}}]
        return None

    # ── Failed / suspicious logins (Windows EventCode 4625 via Splunk, Linux lastb) ──
    _login_kw = (
        "failed login", "login fail", "login attempt", "bad login",
        "suspicious login", "login event", "brute force", "4625",
        "auth fail", "authentication fail",
    )
    if any(kw in q for kw in _login_kw):
        hours = _extract_hours(q)
        calls: list[dict] = [{"tool": "splunk_failed_logins", "params": {"hours": hours}}]
        if mentioned_host and mentioned_host not in windows_hosts:
            calls.append({"tool": "failed_logins", "host": mentioned_host, "params": {}})
        elif not mentioned_host:
            # Broad check: also pull Linux failed_logins from ubuntulab
            linux_hosts = [h for h in available_hosts if "windows" not in VM_CAPABILITIES.get(h, set())]
            for h in linux_hosts[:1]:  # one representative Linux host is enough
                calls.append({"tool": "failed_logins", "host": h, "params": {}})
        return calls

    # ── Windows login events generically (no 4625 keyword, but asking about login on Windows) ──
    if any(kw in q for kw in ("login", "logon", "sign in")) and mentioned_host in windows_hosts:
        hours = _extract_hours(q)
        return [{"tool": "splunk_failed_logins", "params": {"hours": hours}}]

    # ── Sysmon process creation ────────────────────────────────────────────────
    if any(kw in q for kw in ("sysmon", "process creat", "eventcode 1", "event code 1", "event id 1")):
        if "network" not in q:
            hours = _extract_hours(q)
            return [{"tool": "splunk_sysmon_process_create", "params": {"hours": hours}}]

    # ── Sysmon network connections ─────────────────────────────────────────────
    if any(kw in q for kw in ("sysmon network", "eventcode 3", "event code 3", "event id 3")):
        hours = _extract_hours(q)
        return [{"tool": "splunk_sysmon_network", "params": {"hours": hours}}]

    # ── Splunk health ──────────────────────────────────────────────────────────
    if any(kw in q for kw in ("splunk health", "splunk status", "is splunk", "splunk up", "splunk running")):
        return [{"tool": "splunk_health_check", "params": {}}]

    # ── Splunk recent alerts ───────────────────────────────────────────────────
    if "splunk" in q and any(kw in q for kw in ("alert", "recent", "latest", "check splunk")):
        hours = _extract_hours(q)
        return [{"tool": "splunk_recent_alerts", "params": {"hours": hours}}]

    # ── Linux audit via Splunk ─────────────────────────────────────────────────
    if "splunk" in q and any(kw in q for kw in ("linux audit", "auditd", "linux:audit")):
        hours = _extract_hours(q)
        return [{"tool": "splunk_linux_audit", "params": {"hours": hours}}]

    # ── DNS events via Splunk ──────────────────────────────────────────────────
    if "splunk" in q and any(kw in q for kw in ("dns", "domain query", "name resolution")):
        hours = _extract_hours(q)
        return [{"tool": "splunk_dns_events", "params": {"hours": hours}}]

    # ── Port / network scanning detection ─────────────────────────────────────
    # snort_alerts + zeek_notice_log catch scans from the network sensor side.
    # splunk_sysmon_network (EventCode 3) catches connection bursts on Windows VMs.
    # SiLK omitted — rwfilter/rwstats not confirmed installed on ubuntulab.
    _scan_kw = (
        "port scan", "portscan", "scanning", "network scan", "scan detect",
        "scan activity", "port sweep", "host sweep", "nmap", "masscan",
        "reconnaissance", "recon activity",
    )
    if any(kw in q for kw in _scan_kw):
        hours = _extract_hours(q)
        calls = []
        for h in available_hosts:
            caps = VM_CAPABILITIES.get(h, set())
            if "snort" in caps:
                calls.append({"tool": "snort_alerts", "host": h, "params": {"lines": 200}})
            if "zeek" in caps:
                calls.append({"tool": "zeek_notice_log", "host": h, "params": {"lines": 200}})
        # Also check Splunk for Sysmon EventCode 3 — network connections on Windows VMs
        calls.append({"tool": "splunk_sysmon_network", "params": {"hours": hours}})
        if calls:
            return calls

    # ── Snort alerts explicitly requested ─────────────────────────────────────
    if "snort" in q and any(kw in q for kw in ("alert", "alerts", "check", "review", "show", "recent")):
        calls = [
            {"tool": "snort_alerts", "host": h, "params": {"lines": 200}}
            for h in available_hosts
            if "snort" in VM_CAPABILITIES.get(h, set())
        ]
        if calls:
            return calls

    return None  # no match — fall through to LLM planner


def _plan(question: str, available_hosts: dict) -> list[dict]:
    """Ask Ollama to decide which tools to call. Returns list of call dicts."""
    manifest = tool_manifest_for_prompt(available_hosts)
    host_list = ", ".join(available_hosts.keys())

    prompt = f"""You are a lab orchestration agent that handles both system administration and security monitoring. Your job is to select the right tools to answer the user's question — whether that is a routine admin task (uptime, connectivity, service status, disk space) or a security investigation.

CRITICAL: You MUST use tool names EXACTLY as they appear in the list below — character for character. Do NOT invent, shorten, or abbreviate tool names. Do NOT use tools that are not in the list.

Available hosts: {host_list}

Available tools (use these EXACT names in "tool" field):
{manifest}

HOST TYPE GUIDE — determines which tools to use:
- Linux hosts (ubuntulab, splunksiem, parrot): use ssh_check for connectivity, interface_config for network config, process_list for processes
- Windows hosts (dc01, ws01): use win_ssh_check for connectivity, win_process_list for processes, win_network_connections for network, win_services for services

SYNONYM MAPPING — map user language to the correct tool name:
- "ifconfig", "ip addr", "network interfaces", "network config", "what is the IP", "show interfaces" → interface_config (Linux) or win_network_connections (Windows)
- "test connectivity", "connect to", "can I reach", "is X up", "connectivity check", "reachability", "ping" → ssh_check (Linux hosts) or win_ssh_check (Windows hosts: dc01, ws01)
- "what's running", "running processes", "ps", "ps aux", "top", "show processes" → process_list (Linux) or win_process_list (Windows)
- "disk space", "storage", "df", "how full" → disk_usage
- "memory", "RAM", "free", "how much memory" → memory_usage
- "uptime", "how long up", "load average" → uptime_info
- "service status", "is X running", "systemctl status" → service_status (requires service param)
- "listening ports", "open ports", "what ports" → net_listening (Linux) or win_listening_ports (Windows)
- "active connections", "established connections", "who is connected" → net_connections (Linux) or win_network_connections (Windows)

User question: {question}

Rules:
- "tool" value must be copied exactly from the tool names above (e.g. "splunk_health_check", not "splunk", not "ping_all_hosts")
- Only call tools whose listed hosts include the target host
- When checking multiple hosts, create ONE separate call per host
- Tools with a params_schema (like service_status, service_restart) REQUIRE their listed parameters — always include them
- For broad or time-range questions ("last 4 hours", "anything concerning", "check everything"), use lines: 400
- If no specific host is mentioned and the question is about a Linux admin task, default to "ubuntulab"
- Splunk tools show "hosts: n/a" — NEVER add a "host" field for them. Example: {{"tool": "splunk_health_check", "params": {{}}}}
- IMPORTANT: splunk_failed_logins covers ALL Windows hosts (ws01, dc01, etc.) — do NOT add a host param even when the user asks about a specific Windows host
- Only include tools genuinely relevant to the question — 1 to 4 tools is usually right for admin tasks, 3 to 6 for security investigations
- Respond with ONLY valid JSON, no explanation text

Example — "run ifconfig on ubuntulab":
{{"tool_calls": [{{"tool": "interface_config", "host": "ubuntulab", "params": {{}}}}]}}

Example — "test connectivity to dc01" / "connect to dc01" / "is dc01 up":
{{"tool_calls": [{{"tool": "win_ssh_check", "host": "dc01", "params": {{}}}}]}}

Example — "check all Linux machines are online" / "run a connection test":
{{"tool_calls": [{{"tool": "ssh_check", "host": "ubuntulab", "params": {{}}}}, {{"tool": "ssh_check", "host": "splunksiem", "params": {{}}}}, {{"tool": "ssh_check", "host": "parrot", "params": {{}}}}]}}

Example — "failed logins on ws01 last 7 days" / "4625 events" / "suspicious login events":
{{"tool_calls": [{{"tool": "splunk_failed_logins", "params": {{"hours": 168}}}}]}}

Example — "show sysmon process creation events from last 4 hours":
{{"tool_calls": [{{"tool": "splunk_sysmon_process_create", "params": {{"hours": 4}}}}]}}

Example — "check splunk and zeek logs for last 24 hours":
{{"tool_calls": [{{"tool": "splunk_health_check", "params": {{}}}}, {{"tool": "splunk_recent_alerts", "params": {{"hours": 24}}}}, {{"tool": "zeek_conn_log", "host": "ubuntulab", "params": {{"lines": 100}}}}]}}

Required JSON format:
{{"tool_calls": [{{"tool": "exact_tool_name_from_list", "host": "hostname", "params": {{}}}}, ...]}}
"""

    raw = ask_ollama(prompt, json_mode=True, timeout=90)

    try:
        cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()
        data = json.loads(cleaned)
        calls = data.get("tool_calls", [])
        return calls if isinstance(calls, list) else []
    except (json.JSONDecodeError, AttributeError, TypeError):
        return []


def _triage(question: str, results: list[dict], available_hosts: dict) -> list[dict]:
    """
    After the first data collection, ask the LLM if it sees anything that
    warrants a targeted follow-up query. Returns additional tool calls (may be empty).

    This is what enables the 'story' — Bernstein notices SSH brute force in auditd
    and automatically pivots to check Zeek conn.log for that source IP.
    """
    manifest = tool_manifest_for_prompt(available_hosts)
    summary = "\n\n".join(f"=== {r['label']} ===\n{r['output'][:800]}" for r in results)

    prompt = f"""You are a cybersecurity analyst reviewing initial security data from a detection lab.

User's original question: {question}

Initial data collected:
{summary}

CRITICAL RULES:
1. Only follow up if the data above contains REAL log entries showing something suspicious — do NOT invent findings.
2. If any source shows "(no results)" or "[ERROR]", treat it as empty — never fabricate what it might have contained.
3. Tool names in tool_calls MUST be copied EXACTLY from the Available tools list below — do NOT shorten, abbreviate, or invent names.
   - WRONG: "zeek", "lastb", "splunk", "failed_login"
   - RIGHT: "zeek_conn_log", "failed_logins", "splunk_failed_logins"
4. Splunk tools (splunk_*) never take a "host" field — omit it entirely.
5. If the data shows nothing suspicious, return tool_calls: [].

Examples of valid follow-up reasoning:
- "splunk_failed_logins shows 47 failures from 10.0.0.5 — follow up with zeek_conn_log to see if that IP succeeded"
- "auditd_recent shows wget EXECVE — follow up with zeek_http_log to see what URL was fetched"
- "snort_alerts fired on a host — follow up with net_connections(ubuntulab) to check for live connections"

Available tools for follow-up (use EXACT names):
{manifest}

Respond with ONLY valid JSON:
{{"reasoning": "one sentence on what you found and why you are or are not following up", "tool_calls": [{{"tool": "exact_tool_name", "host": "hostname", "params": {{"lines": 100}}}}]}}
"""

    raw = ask_ollama(prompt, json_mode=True, timeout=90)

    try:
        cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()
        data = json.loads(cleaned)
        reasoning = data.get("reasoning", "")
        calls = data.get("tool_calls", [])
        if reasoning:
            print(f"[Bernstein] Triage: {reasoning}")
        return calls if isinstance(calls, list) else []
    except (json.JSONDecodeError, AttributeError, TypeError):
        return []


def _confirm(tool_calls: list[dict]) -> list[dict]:
    """
    Filter tool_calls through user confirmation for Tier 2+ tools.
    Returns the approved subset (Tier 1 always passes; Tier 2/3 require user input).
    """
    safe_calls = []
    admin_calls = []

    for call in tool_calls:
        name = _resolve_tool_name(call.get("tool", "").strip())
        tier = TOOLS.get(name, {}).get("tier", 1)
        if tier >= 2:
            admin_calls.append((call, name, tier))
        else:
            safe_calls.append(call)

    if not admin_calls:
        return tool_calls

    has_destructive = any(t >= 3 for _, _, t in admin_calls)
    print()
    print("  [Bernstein] Admin actions planned:")
    for call, name, tier in admin_calls:
        host = call.get("host", "n/a")
        params = call.get("params") or {}
        tier_label = "!! DESTRUCTIVE !!" if tier >= 3 else "ADMIN"
        param_str = ", ".join(f"{k}={v}" for k, v in params.items()) if params else ""
        print(
            f"    [{tier_label}] {name}({host}{', ' + param_str if param_str else ''})"
        )

    if has_destructive:
        answer = input(
            "\n  Type 'yes' to approve ALL actions above (destructive included), or Enter to skip admin: "
        ).strip()
        approved = answer == "yes"
    else:
        answer = input("\n  Approve admin actions? [y/N]: ").strip().lower()
        approved = answer in ("y", "yes")

    if approved:
        print("  Admin actions approved.")
        return safe_calls + [c for c, _, _ in admin_calls]
    else:
        print("  Admin actions skipped — running read-only tools only.")
        return safe_calls


def _execute(tool_calls: list[dict]) -> list[dict]:
    """Run each planned tool call. Returns list of {label, tool, host, output}."""
    results = []

    for call in tool_calls:
        tool_name = _resolve_tool_name(call.get("tool", "").strip())
        host = call.get("host", "").strip()
        params = call.get("params") or {}

        if tool_name not in TOOLS:
            print(f"  ✗ {tool_name} — LLM hallucinated tool name, skipping")
            results.append(
                {
                    "label": tool_name,
                    "tool": tool_name,
                    "host": host,
                    "output": f"[ERROR] Unknown tool: {tool_name!r} — LLM invented this name",
                }
            )
            continue

        meta = TOOLS[tool_name]
        fn = meta["fn"]

        try:
            kwargs: dict = {}
            if meta["has_lines_param"] and "lines" in params:
                kwargs["lines"] = int(params["lines"])
            if "hours" in params:
                kwargs["hours"] = int(params["hours"])
            # Pass any extra params declared in params_schema (service, path, package, pid...)
            for param_name, param_type in meta.get("params_schema", {}).items():
                if param_name in params:
                    kwargs[param_name] = param_type(params[param_name])

            output: str = fn(host, **kwargs) if meta["has_host_param"] else fn(**kwargs)

            if len(output) > _MAX_OUTPUT_CHARS:
                output = (
                    output[:_MAX_OUTPUT_CHARS]
                    + f"\n... [truncated — {len(output)} total chars]"
                )

        except HostNotAllowedError as e:
            output = f"[BLOCKED] {e}"
        except Exception as e:
            output = f"[ERROR] {type(e).__name__}: {e}"

        label = f"{tool_name}({host})" if host else tool_name
        print(f"  ✓ {label}")
        results.append(
            {"label": label, "tool": tool_name, "host": host, "output": output}
        )

    return results


def _synthesize(question: str, results: list[dict]) -> str:
    """Feed all collected data to Ollama for correlated security narrative."""
    sections = "\n\n".join(f"=== {r['label']} ===\n{r['output']}" for r in results)

    prompt = f"""You are a lab assistant that handles both system administration and security monitoring. Answer the user's question using ONLY the actual data collected below.

CRITICAL RULES — follow these exactly:
1. ONLY discuss what appears in the collected data. Do NOT generate generic advice, templates, or placeholders like "[IP address]" or "[services list]".
2. If a tool returned [ERROR] or [BLOCKED], state that specific error clearly — do not fabricate a result.
3. If all tools errored, say so directly: "All tool calls failed — here is why: ..."
4. Never say "you can test this by running..." — YOU are the one that ran the tools, report what they returned.

User question: {question}

Collected data from {len(results)} source(s):
{sections}

Response style — choose based on what was asked:

ADMINISTRATIVE question (connectivity, service status, uptime, disk, processes, network config):
- Report the actual values from the data: IPs, status, numbers — nothing else
- No MITRE ATT&CK, no security verdict
- If a tool errored, say exactly what the error was

SECURITY question (suspicious activity, attack investigation, log analysis):
- Correlate findings across sources using the actual log entries
- Map to MITRE ATT&CK only if evidence supports it
- Verdict: CONCERNING / NORMAL / INCONCLUSIVE — based on the data, not assumption
"""
    return ask_ollama(prompt, timeout=180)


def run(question: str, available_hosts: dict) -> None:
    """Entry point: plan → confirm → execute → triage → execute → synthesize."""
    print("\n[Bernstein] Planning...")
    tool_calls = _keyword_plan(question, available_hosts)
    if tool_calls is None:
        tool_calls = _plan(question, available_hosts)

    if not tool_calls:
        print("\n[Bernstein] Could not map your question to any available tool.")
        print("  Try being explicit about the host and action. Examples:")
        print("    test connectivity to dc01")
        print("    run ifconfig on ubuntulab")
        print("    show processes on splunksiem")
        print("    check zeek logs on ubuntulab for the last hour")
        print("  Type 'help' to see more examples.\n")
        return

    # Confirm any Tier 2/3 (admin/destructive) tools before running
    approved_calls = _confirm(tool_calls)

    print(f"\n[Bernstein] Round 1 — collecting from {len(approved_calls)} source(s):")
    results = _execute(approved_calls)

    if not results:
        print("[Bernstein] No data collected.")
        return

    # Triage (adaptive follow-up) is only useful for security investigations
    # that returned real data. Skip for admin tasks and when all outputs are empty/errors.
    has_real_data = any(
        r["output"].strip() not in ("(no results)", "")
        and not r["output"].startswith("[ERROR]")
        and not r["output"].startswith("[BLOCKED]")
        for r in results
    )
    if _is_security_investigation(approved_calls) and has_real_data:
        print("\n[Bernstein] Triaging findings...")
        followup_calls = _triage(question, results, available_hosts)
    else:
        followup_calls = []

    # Deduplicate follow-up calls against what we already ran
    already_ran = {(r["tool"], r["host"]) for r in results}
    new_calls = [
        c
        for c in followup_calls
        if (c.get("tool", ""), c.get("host", "")) not in already_ran
    ]

    if new_calls:
        new_calls = _confirm(new_calls)
        print(f"[Bernstein] Round 2 — {len(new_calls)} follow-up source(s):")
        followup_results = _execute(new_calls)
        results.extend(followup_results)

    # If no result has real content, skip the LLM — it will fabricate from nothing.
    real_results = [
        r for r in results
        if r["output"].strip() not in ("(no results)", "")
        and not r["output"].startswith("[ERROR]")
        and not r["output"].startswith("[BLOCKED]")
    ]
    if not real_results:
        print("\n[Bernstein] All tool calls returned errors — nothing to analyze.")
        for r in results:
            print(f"  {r['label']}: {r['output']}")
        print()
        return

    print(f"\n[Bernstein] Analyzing {len(results)} total source(s)...\n")
    print(f"{'─' * 60}")
    print(_synthesize(question, results))
    print(f"{'─' * 60}")
