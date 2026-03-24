# Qualys Cloud Agent Troubleshooting Scripts

Automated diagnostic and troubleshooting tools for the Qualys Cloud Agent. These scripts allow any team member to collect complete, organized diagnostic data from a host without requiring specific Qualys knowledge.

## Available Scripts

| Platform | Script | Language | Requirements |
|----------|--------|----------|--------------|
| Windows | [`Windows/qualys_agent_troubleshoot.ps1`](Windows/qualys_agent_troubleshoot.ps1) | PowerShell 5.1 | Administrator privileges |
| Linux | [`Linux/qualys_agent_troubleshoot.py`](Linux/qualys_agent_troubleshoot.py) | Python 3.6+ | Root access (sudo) |

## What These Scripts Do

Both scripts run the same 9-step diagnostic sequence tailored to their respective OS:

| Step | Check | What It Collects |
|------|-------|------------------|
| 1 | System Info | Hostname, OS version, uptime, domain/kernel |
| 2 | DNS | Qualys endpoint resolution, DNS config, hosts file |
| 3 | Network | Routing table, IP configuration |
| 4 | Platform Comms | TCP 443 connectivity, HTTPS status, TLS certificate validation |
| 5 | Firewall | Firewall status and Qualys-related rules |
| 6 | Agent Status | Service state, processes, config, proxy, HostID, version |
| 7 | Agent Health | Qualys Health Check Tool output (if available) |
| 8 | Environment | Disk space, time sync, certificate store |
| 9 | Agent Logs | Recent log entries and log directory listing |

**Safe by default** -- no services are started, stopped, or restarted unless you explicitly use a service control flag.

## Quick Start

### Windows

```powershell
# Copy to target host
Copy-Item .\qualys_agent_troubleshoot.ps1 \\<HOSTNAME>\C$\Temp\

# Run from elevated PowerShell on the target
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
C:\Temp\qualys_agent_troubleshoot.ps1
```

### Linux

```bash
# Push to target host
scp -i "<cert>.pem" qualys_agent_troubleshoot.py <user>@<host_ip>:/tmp/

# SSH in and run
ssh -i "<cert>.pem" <user>@<host_ip>
sudo python3 /tmp/qualys_agent_troubleshoot.py
```

## Common Options

Both scripts support the same core options (syntax differs by platform):

| Action | Windows | Linux |
|--------|---------|-------|
| Diagnostics only | `.\qualys_agent_troubleshoot.ps1` | `sudo python3 qualys_agent_troubleshoot.py` |
| Restart agent | `-Restart` | `--restart` |
| Stop agent | `-Stop` | `--stop` |
| Start agent | `-Start` | `--start` |
| Collect logs | `-CollectLogs` | `--collect-logs` |
| Support escalation | `-TraceDiag` | `--trace-diag` |
| Custom wait time | `-TraceDiag -WaitMinutes 15` | `--trace-diag --wait-minutes 15` |
| Clean up files | `-Cleanup` | `--cleanup` |

Options can be combined (e.g., `-Restart -CollectLogs` or `--restart --collect-logs`).

## Output Files

| File | Description | Location (Windows) | Location (Linux) |
|------|-------------|--------------------|-------------------|
| Diagnostic report | Full troubleshooting output | `%USERPROFILE%\Downloads\qualys_troubleshoot_<timestamp>.txt` | `/tmp/qualys_troubleshoot_<timestamp>.txt` |
| Log archive | Agent logs, configs, certs | `%USERPROFILE%\Downloads\Cloud_Agent_Logs_<timestamp>.zip` | `/tmp/Cloud_Agent_Logs_<timestamp>.zip` |

Linux output files are created with 644 permissions for non-root SCP retrieval.

## User Guides

For detailed usage instructions, see the platform-specific guides:

- [Windows User Guide](Windows/USER_GUIDE.md)
- [Linux User Guide](Linux/USER_GUIDE.md)

## Version

Current version: **1.6.0**

## Author

Brian Canaday
