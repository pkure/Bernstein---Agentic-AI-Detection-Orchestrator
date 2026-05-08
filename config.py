OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen:7b"

# Default SSH username — used as fallback if a host has no entry in SSH_USERS
SSH_USER = "labuser"

# Per-host SSH usernames — populated by config_local.py
# If a host isn't listed here, SSH_USER above is used as the fallback
SSH_USERS: dict[str, str] = {}

# Populated by config_local.py — never put real IPs here (this file is in git)
ALLOWED_HOSTS: dict[str, str] = {}

# Hostnames that must never be reachable regardless of ALLOWED_HOSTS
# Add your host machine's hostname here so Bernstein can never target it.
# Also set HOST_IP below to block by IP (defense-in-depth).
BLOCKED_HOSTS: list[str] = ["127.0.0.1", "localhost"]

# Set this to your host machine's IP on the lab network (e.g. the VMware host adapter IP).
# Populated by config_local.py — leave as None if not applicable.
HOST_IP: str | None = None

# Which tool categories each VM supports.
# This enforces that e.g. zeek tools can't accidentally run against the parrot attacker VM.
VM_CAPABILITIES: dict[str, set[str]] = {
    "ubuntulab":  {"zeek", "snort", "auditd", "silk", "linux_common"},
    "splunksiem": {"auditd", "linux_common", "splunk_api"},
    "dc01":       {"windows"},
    "ws01":       {"windows"},
    "parrot":     {"linux_common"},  # attacker VM — restricted, output is untrusted
}
