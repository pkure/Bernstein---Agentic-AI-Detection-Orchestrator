import subprocess
from config import SSH_USER

_SSH_TIMEOUT = 30


def _ssh_run(ip: str, command: str, timeout: int = _SSH_TIMEOUT, user: str = SSH_USER) -> str:
    """Execute a hardcoded command on a remote host via SSH.

    `command` must be a fully literal string — never pass user input here.
    `user` should come from resolve_ssh_user(hostname) in the calling tool.
    Integer parameters must be cast to int() in the caller before interpolation.
    String parameters must be validated against an allowlist before interpolation.

    Returns stdout on success, or an [ERROR] prefixed string on failure.
    """
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                f"{user}@{ip}",
                command,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
        if result.returncode not in (0,):
            return f"[ERROR] SSH returned {result.returncode}:\n{result.stderr.strip()}"
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"[ERROR] SSH timed out after {timeout}s"
    except Exception as e:
        return f"[ERROR] SSH failed: {e}"
