from config import ALLOWED_HOSTS, BLOCKED_HOSTS, SSH_USER, SSH_USERS


class HostNotAllowedError(Exception):
    pass


# These IPs are always blocked regardless of ALLOWED_HOSTS content.
# Add your host machine's VMware adapter IP to HOST_IP in config_local.py
# so Bernstein can never target the machine it runs on.
from config import HOST_IP as _HOST_IP
_BLOCKED_IPS = {"127.0.0.1", "::1"} | ({_HOST_IP} if _HOST_IP else set())

# Normalize the hostname blocklist from config (case-insensitive)
_BLOCKED_HOSTNAMES = {h.strip().lower() for h in BLOCKED_HOSTS}


def resolve_host(hostname: str) -> str:
    """Return the IP for a hostname, or raise HostNotAllowedError.

    Checks:
      1. Hostname is not on the blocked list (e.g. 'pxps', 'localhost')
      2. Hostname is in ALLOWED_HOSTS
      3. The resolved IP is not itself a blocked address (defense-in-depth
         against config_local.py aliasing a blocked IP under a new name)
    """
    hostname = hostname.strip().lower()

    if hostname in _BLOCKED_HOSTNAMES:
        raise HostNotAllowedError(f"Host '{hostname}' is explicitly blocked.")

    if hostname not in ALLOWED_HOSTS:
        raise HostNotAllowedError(
            f"Host '{hostname}' is not in ALLOWED_HOSTS. "
            f"Add it to config_local.py to enable it."
        )

    ip = ALLOWED_HOSTS[hostname]

    if ip in _BLOCKED_IPS:
        raise HostNotAllowedError(
            f"Host '{hostname}' resolves to blocked IP '{ip}'."
        )

    return ip


def resolve_ssh_user(hostname: str) -> str:
    """Return the SSH username for a hostname, falling back to the global default."""
    return SSH_USERS.get(hostname.strip().lower(), SSH_USER)


def require_capability(hostname: str, capability: str) -> None:
    """Raise HostNotAllowedError if hostname doesn't support a tool category.

    This prevents running e.g. zeek tools against the parrot attacker VM.
    VM_CAPABILITIES is imported lazily to avoid circular imports with config.
    """
    from config import VM_CAPABILITIES

    allowed = VM_CAPABILITIES.get(hostname.strip().lower(), set())
    if capability not in allowed:
        raise HostNotAllowedError(
            f"Host '{hostname}' does not support capability '{capability}'. "
            f"Allowed: {sorted(allowed) or 'none'}"
        )
