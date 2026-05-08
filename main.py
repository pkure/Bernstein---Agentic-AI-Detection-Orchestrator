from config import ALLOWED_HOSTS, SSH_USERS, VM_CAPABILITIES
import config
import agent

# ── Load local config (real IPs, usernames, tokens — gitignored) ─────────────
try:
    from config_local import ALLOWED_HOSTS as _LOCAL_HOSTS
    ALLOWED_HOSTS.update(_LOCAL_HOSTS)
    print(f"[config] Loaded hosts: {list(_LOCAL_HOSTS.keys())}")
except Exception as e:
    print(f"[config] Could not load ALLOWED_HOSTS from config_local: {e}")

try:
    from config_local import SSH_USERS as _LOCAL_USERS
    SSH_USERS.update(_LOCAL_USERS)
except Exception:
    pass  # SSH_USERS is optional — falls back to global SSH_USER

try:
    from config_local import BLOCKED_HOSTS as _LOCAL_BLOCKED
    config.BLOCKED_HOSTS = _LOCAL_BLOCKED
except Exception:
    pass

try:
    from config_local import HOST_IP as _LOCAL_HOST_IP
    config.HOST_IP = _LOCAL_HOST_IP
except Exception:
    pass


_HELP = """
Bernstein — cybersecurity detection lab agent
─────────────────────────────────────────────
Just ask in plain English. Bernstein picks the right tools,
runs them, and gives you a correlated answer.

ADMIN / OPERATIONAL
  Run ifconfig on ubuntulab
  Show me disk space on splunksiem
  What processes are running on ubuntulab?
  Is the Zeek service running?
  Check all hosts are reachable
  Show memory usage on ubuntulab
  What ports are listening on ubuntulab?

SECURITY / DETECTION
  Check the Zeek and Snort logs on ubuntulab for anything suspicious
  Show me failed logins on ubuntulab in the last hour
  Are there any port scans happening?
  Check all security logs and give me a threat summary
  Check Splunk for anything suspicious in the last 24 hours
  Show Windows Sysmon process creation events from the last 4 hours

BUILT-IN COMMANDS
  help   — this menu
  hosts  — list available hosts
  sweep  — SSH connectivity check on all hosts
  exit   — quit
"""


def _sweep():
    """Check SSH connectivity to every host in ALLOWED_HOSTS."""
    from tools.linux_common import ssh_check
    from tools.windows import win_ssh_check

    print(f"\n{'─' * 50}")
    print("Sweeping all hosts...\n")
    for name in ALLOWED_HOSTS:
        caps = VM_CAPABILITIES.get(name, set())
        try:
            if "windows" in caps:
                result = win_ssh_check(name)
            else:
                result = ssh_check(name)
            first_line = (
                result.strip().splitlines()[0] if result.strip() else "(no output)"
            )
            print(f"  ✓ {name:<14} {first_line}")
        except Exception as e:
            print(f"  ✗ {name:<14} {e}")
    print(f"{'─' * 50}\n")


def main():
    print("Bernstein is online.")
    print(f"Hosts: {list(ALLOWED_HOSTS.keys())}  |  type 'help' for examples\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBernstein out.")
            break

        if not user_input:
            continue

        low = user_input.lower()

        if low in ("exit", "quit", "q"):
            print("Bernstein out.")
            break

        if low in ("help", "?", "h"):
            print(_HELP)
            continue

        if low == "hosts":
            print(f"Available hosts: {list(ALLOWED_HOSTS.keys())}")
            continue

        if low in ("sweep", "ping", "check hosts", "check all hosts"):
            _sweep()
            continue

        width = 64
        print()
        print("*" * width)
        label = f"  YOU: {user_input}"
        print(label[:width])
        print("*" * width)
        agent.run(user_input, ALLOWED_HOSTS)


if __name__ == "__main__":
    main()
