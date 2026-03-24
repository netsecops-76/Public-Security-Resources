# Linux User Guide -- Qualys Cloud Agent Troubleshooting Script

## Overview

`qualys_agent_troubleshoot.py` is an automated diagnostic script for the Qualys Cloud Agent on Linux. It collects system, network, and agent health data into a single timestamped report file, ready for review or Qualys support submission.

## Requirements

| Requirement | Details |
|-------------|---------|
| Privileges | **Root access** (`sudo python3`) |
| Python | 3.6 or later |

### Supported Operating Systems

- RHEL / CentOS
- Amazon Linux

## Getting the Script to the Target Host

```bash
# SCP from your workstation
scp -i "<cert>.pem" qualys_agent_troubleshoot.py <user>@<host_ip>:/tmp/
```

## Running the Script

```bash
# SSH to the target host
ssh -i "<cert>.pem" <user>@<host_ip>

# Run diagnostics
sudo python3 /tmp/qualys_agent_troubleshoot.py
```

## Usage Examples

### Basic Diagnostics (No Changes)

```bash
sudo python3 qualys_agent_troubleshoot.py
```

Runs all 9 diagnostic steps. No services are touched. Safe to run at any time.

### Restart the Agent After Diagnostics

```bash
sudo python3 qualys_agent_troubleshoot.py --restart
```

Collects diagnostics first, then restarts the Qualys Cloud Agent service. Includes a 5-second post-action pause with service verification.

### Stop the Agent for Maintenance

```bash
sudo python3 qualys_agent_troubleshoot.py --stop
```

### Start a Stopped Agent

```bash
sudo python3 qualys_agent_troubleshoot.py --start
```

### Collect Agent Logs

```bash
sudo python3 qualys_agent_troubleshoot.py --collect-logs
```

Creates a zip archive of agent logs, configs, certificates, and `/var/log/messages` at:
`/tmp/Cloud_Agent_Logs_<timestamp>.zip` (chmod 644)

### Restart and Collect Logs (Combined)

```bash
sudo python3 qualys_agent_troubleshoot.py --restart --collect-logs
```

### Qualys Support Escalation (Trace Diagnostics)

```bash
# Default 10-minute wait
sudo python3 qualys_agent_troubleshoot.py --trace-diag

# Custom 15-minute wait
sudo python3 qualys_agent_troubleshoot.py --trace-diag --wait-minutes 15
```

The `--trace-diag` workflow:
1. Verifies the agent is running (interactive start/restart if needed)
2. Sets LogLevel to 5 (Trace) with validation and retry
3. Triggers an on-demand VM scan
4. Waits with a progress bar (default 10 minutes)
5. Collects extended diagnostics (agent conf, processes, chage, dmesg, etc.)
6. Lists recently modified agent files
7. Resets LogLevel to 1 (default)
8. Collects logs automatically (implies `--collect-logs`)

### Clean Up After Collection

```bash
sudo python3 qualys_agent_troubleshoot.py --cleanup
```

Removes all `/tmp/qualys_troubleshoot_*.txt` and `/tmp/Cloud_Agent_Logs_*.zip` files from previous runs. No diagnostics are run. Use this after you have retrieved the files via SCP.

## Options Reference

| Flag | Description |
|------|-------------|
| `--stop` | Stop the agent after diagnostics |
| `--start` | Start the agent after diagnostics |
| `--restart` | Restart the agent after diagnostics |
| `--collect-logs` | Zip agent logs, configs, certs, and /var/log/messages |
| `--trace-diag` | Full support escalation workflow |
| `--wait-minutes N` | Wait time after on-demand scan (default: 10, used with `--trace-diag`) |
| `--cleanup` | Remove previous output files, then exit |

**Note:** `--stop`, `--start`, and `--restart` are mutually exclusive -- use only one at a time. `--collect-logs` can be combined with any service flag.

## Output Files

All output is written to `/tmp/` with 644 permissions for non-root SCP retrieval:

| File | When Created |
|------|--------------|
| `qualys_troubleshoot_<YYYYMMDD_HHMMSS>.txt` | Every run |
| `Cloud_Agent_Logs_<YYYYMMDD_HHMMSS>.zip` | When `--collect-logs` or `--trace-diag` is used |

### Retrieving Output Files

```bash
# From your workstation
scp -i "<cert>.pem" <user>@<host_ip>:/tmp/qualys_troubleshoot_*.txt .
scp -i "<cert>.pem" <user>@<host_ip>:/tmp/Cloud_Agent_Logs_*.zip .

# Clean up on the host after retrieval
sudo python3 /tmp/qualys_agent_troubleshoot.py --cleanup
```

## Diagnostic Steps Detail

| Step | Name | What It Checks |
|------|------|----------------|
| 1 | System Info | Hostname, kernel, uptime, /etc/os-release |
| 2 | DNS | nslookup against Qualys endpoints, resolv.conf, /etc/hosts, nsswitch.conf |
| 3 | Network | ip route, self-ping |
| 4 | Platform Comms | TCP 443 connectivity (bash /dev/tcp), curl /status, openssl s_client TLS validation, CAPI log health. Skips connectivity tests if Health Check Tool is available (covered by Step 7) |
| 5 | Firewall | firewalld status, iptables rules |
| 6 | Agent Status | systemctl status, running processes, agent config, proxy config, HostID, agent version |
| 7 | Agent Health | Qualys Health Check Tool (`qualys-healthcheck-tool`) output if available -- backend connectivity, TLS details, certificate store, module health (VM/PC/SCA/PM/UDC/SwCA), patch connectivity |
| 8 | Environment | Disk space, system time sync, certificate store validation (if Health Check Tool is not available) |
| 9 | Agent Logs | journalctl (last 50 lines), /var/log/qualys/ directory listing |

## Troubleshooting the Script Itself

| Issue | Solution |
|-------|----------|
| "Permission denied" | Run with `sudo` |
| "python3: command not found" | Install Python 3: `yum install python3` or `amazon-linux-extras install python3` |
| Script hangs on network checks | Network timeout is expected if connectivity is blocked -- let it complete |
| Cannot SCP output files | Files are created with 644 permissions -- verify your SSH key and path |
