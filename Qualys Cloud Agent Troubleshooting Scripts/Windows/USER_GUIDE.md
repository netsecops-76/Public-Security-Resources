# Windows User Guide -- Qualys Cloud Agent Troubleshooting Script

## Overview

`qualys_agent_troubleshoot.ps1` is an automated diagnostic script for the Qualys Cloud Agent on Windows. It collects system, network, and agent health data into a single timestamped report file, ready for review or Qualys support submission.

## Requirements

| Requirement | Details |
|-------------|---------|
| Privileges | **Run as Administrator** (elevated PowerShell) |
| PowerShell | 5.1 or later |
| .NET Framework | 4.5.2 or later |

### Supported Operating Systems

**Native PowerShell 5.1 (no additional install):**
- Windows Server 2016 and later
- Windows 10 and later

**Manual WMF 5.1 install required:**
- Windows Server 2012 R2
- Windows Server 2012
- Windows Server 2008 R2 SP1

WMF 5.1 download: https://aka.ms/wmf51download

**Not supported:**
- Windows Server 2008 (non-R2), 2003, 2000 -- cannot run PowerShell 5.1
- Any OS without .NET Framework 4.5.2+

## Getting the Script to the Target Host

```powershell
# Option 1: Admin share (from your workstation)
Copy-Item .\qualys_agent_troubleshoot.ps1 \\<HOSTNAME>\C$\Temp\

# Option 2: RDP to the host and copy to C:\Temp\
```

## Running the Script

Open an **elevated PowerShell window** on the target host:

```powershell
# Allow script execution for this session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Run diagnostics
C:\Temp\qualys_agent_troubleshoot.ps1
```

## Usage Examples

### Basic Diagnostics (No Changes)

```powershell
.\qualys_agent_troubleshoot.ps1
```

Runs all 9 diagnostic steps. No services are touched. Safe to run at any time.

### Restart the Agent After Diagnostics

```powershell
.\qualys_agent_troubleshoot.ps1 -Restart
```

Collects diagnostics first, then restarts the Qualys Cloud Agent service. Includes a 5-second post-action pause with service verification.

### Stop the Agent for Maintenance

```powershell
.\qualys_agent_troubleshoot.ps1 -Stop
```

### Start a Stopped Agent

```powershell
.\qualys_agent_troubleshoot.ps1 -Start
```

### Collect Agent Logs

```powershell
.\qualys_agent_troubleshoot.ps1 -CollectLogs
```

Creates a zip archive of agent logs, configs, and certificates at:
`%USERPROFILE%\Downloads\Cloud_Agent_Logs_<timestamp>.zip`

### Restart and Collect Logs (Combined)

```powershell
.\qualys_agent_troubleshoot.ps1 -Restart -CollectLogs
```

### Qualys Support Escalation (Trace Diagnostics)

```powershell
# Default 10-minute wait
.\qualys_agent_troubleshoot.ps1 -TraceDiag

# Custom 15-minute wait
.\qualys_agent_troubleshoot.ps1 -TraceDiag -WaitMinutes 15
```

The `-TraceDiag` workflow:
1. Verifies the agent is running (interactive start/restart if needed)
2. Sets LogLevel to 5 (Trace) with validation and retry
3. Triggers an on-demand VM scan
4. Waits with a progress bar (default 10 minutes)
5. Collects extended diagnostics (agent config, processes, local admins, recent system errors)
6. Lists recently modified agent files
7. Resets LogLevel to 1 (default)
8. Collects logs automatically (implies `-CollectLogs`)

### Clean Up After Collection

```powershell
.\qualys_agent_troubleshoot.ps1 -Cleanup
```

Removes all report and log archive files from `%USERPROFILE%\Downloads` that were left by previous runs. No diagnostics are run. Use this after you have collected the output files.

## Options Reference

| Flag | Description |
|------|-------------|
| `-Stop` | Stop the agent after diagnostics |
| `-Start` | Start the agent after diagnostics |
| `-Restart` | Restart the agent after diagnostics |
| `-CollectLogs` | Zip agent logs, configs, and certs |
| `-TraceDiag` | Full support escalation workflow |
| `-WaitMinutes N` | Wait time after on-demand scan (default: 10, used with `-TraceDiag`) |
| `-Cleanup` | Remove previous output files, then exit |

**Note:** `-Stop`, `-Start`, and `-Restart` are mutually exclusive -- use only one at a time. `-CollectLogs` can be combined with any service flag.

## Output Files

All output is written to `%USERPROFILE%\Downloads\`:

| File | When Created |
|------|--------------|
| `qualys_troubleshoot_<YYYYMMDD_HHMMSS>.txt` | Every run |
| `Cloud_Agent_Logs_<YYYYMMDD_HHMMSS>.zip` | When `-CollectLogs` or `-TraceDiag` is used |

## Diagnostic Steps Detail

| Step | Name | What It Checks |
|------|------|----------------|
| 1 | System Info | Hostname, OS version, build, uptime, domain |
| 2 | DNS | nslookup against Qualys endpoints, DNS client config, hosts file |
| 3 | Network | Route table, IP configuration, self-ping |
| 4 | Platform Comms | TCP 443 connectivity, HTTPS /status check, TLS certificate validation, CAPI log health, WinHTTP errors. Skips connectivity tests if Health Check Tool is available (covered by Step 7) |
| 5 | Firewall | Windows Firewall profile status, Qualys-specific rules |
| 6 | Agent Status | Service status, running processes, install directory, agent config, proxy config, HostID, agent version, self-protection status |
| 7 | Agent Health | Qualys Health Check Tool (`QualysAgentHealthCheck.exe`) output if available -- backend connectivity, TLS details, certificate store, module health (VM/PC/SCA/PM), patch connectivity |
| 8 | Environment | Disk space, system time sync, certificate store validation (if Health Check Tool is not available) |
| 9 | Agent Logs | Application Event Log (Qualys source), agent log directory listing |

## Troubleshooting the Script Itself

| Issue | Solution |
|-------|----------|
| "cannot be loaded because running scripts is disabled" | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first |
| "Access is denied" | Run PowerShell as Administrator |
| Script hangs on network checks | Network timeout is expected if connectivity is blocked -- let it complete |
