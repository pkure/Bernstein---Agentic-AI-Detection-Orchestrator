"""Windows VM tools — PowerShell over SSH (requires OpenSSH Server on windc/win11).

To enable: open an elevated PowerShell on the Windows VM and run:
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Start-Service sshd
    Set-Service -Name sshd -StartupType Automatic

Until SSH is confirmed available, use splunk_sysmon_* tools for Windows visibility.
"""
from safety import resolve_host, require_capability, resolve_ssh_user
from tools.base import _ssh_run

_CAP = "windows"

_PS = "powershell -NonInteractive -Command"


def win_process_list(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f'{_PS} "Get-Process | Sort-Object CPU -Desc | Select-Object -First 30 | Format-Table -AutoSize"',
    )


def win_network_connections(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f'{_PS} "netstat -ano"', user=resolve_ssh_user(hostname))


def win_listening_ports(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(ip, f'{_PS} "netstat -ano | findstr LISTENING"', user=resolve_ssh_user(hostname))


def win_failed_logins(hostname: str, count: int = 20) -> str:
    count = int(count)
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f'{_PS} "Get-EventLog -LogName Security -Newest {count} -EntryType FailureAudit | Format-List"',
    )


def win_services(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f'{_PS} "Get-Service | Where-Object {{$_.Status -eq \'Running\'}} | Format-Table -AutoSize"',
    )


def win_uptime(hostname: str) -> str:
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f'{_PS} "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime"',
    )


def win_ssh_check(hostname: str) -> str:
    """Connectivity check — confirms SSH works and returns whoami + hostname."""
    ip = resolve_host(hostname)
    require_capability(hostname, _CAP)
    return _ssh_run(
        ip,
        f'{_PS} "Write-Output (\'user=\' + $env:USERNAME + \' host=\' + $env:COMPUTERNAME)"',
        user=resolve_ssh_user(hostname),
    )