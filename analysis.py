import requests
from config import OLLAMA_URL, MODEL_NAME


def ask_ollama(prompt: str, json_mode: bool = False, timeout: int = 120) -> str:
    payload: dict = {"model": MODEL_NAME, "prompt": prompt, "stream": False}
    if json_mode:
        payload["format"] = "json"
    response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json().get("response", "")


def summarize_logs(log_text: str) -> str:
    prompt = f"""You are a cybersecurity analyst.

Analyze the following log data and summarize:
- Notable connections or events
- Suspicious patterns
- Repeated behavior
- Anything worth investigating

Keep it concise.

LOG DATA:
{log_text}
"""
    return ask_ollama(prompt)


def detect_repeated_ssh(log_text: str) -> str:
    ssh_count = sum(
        1 for line in log_text.splitlines()
        if " 22 " in line or "\t22\t" in line
    )
    if ssh_count > 3:
        return f"[ALERT] High SSH activity: {ssh_count} connections"
    elif ssh_count > 0:
        return f"[INFO] Some SSH activity: {ssh_count} connections"
    return "[OK] No SSH activity detected"
