#!/usr/bin/env python3
"""
===============================================================================
 Qualys Cloud Agent Troubleshooting Script for Linux
===============================================================================
 Version:    1.6.0
 Author:     Brian Canaday — brian.canaday@nttdata.com
 Platform:   RHEL / CentOS / Amazon Linux (Python 3.6+)

 Purpose:
   Automated troubleshooting for the Qualys Cloud Agent. Designed so any
   team member can collect complete, organized diagnostic data from a
   Linux host without requiring specific Qualys knowledge.

   All output is written to a timestamped report file in /tmp/ with 644
   permissions, ready for SCP retrieval by a non-root user.

 Prerequisites:
   - Root access (sudo python3)
   - Python 3.6+
   - Script copied to the target host (see SCP template below)

===============================================================================
 DIAGNOSTIC STEPS (default — no flags)
===============================================================================

   Step 1   System Info        hostname, kernel, uptime, /etc/os-release
   Step 2   DNS                nslookup Qualys endpoints, resolv.conf,
                               /etc/hosts, nsswitch.conf
   Step 3   Network            ip route, ping self
   Step 4   Platform Comms     If Health Check Tool is available: skips
                               4a/4b/4c (covered by Step 7). Otherwise:
                               TCP 443 check (bash /dev/tcp w/ timeout),
                               curl /status, openssl s_client TLS cert
                               validation.
                               Always: CAPI log health check (last 24
                               hours)
   Step 5   Firewall           firewalld status, iptables rules
   Step 6   Agent Status       systemctl status, process list, agent config,
                               proxy config, HostID, agent version
   Step 7   Agent Health       Qualys Health Check Tool
                               (qualys-healthcheck-tool) if available.
                               Covers: backend connectivity, TLS handshake
                               details, certificate store validation,
                               module health (VM/PC/SCA/PM/UDC/SwCA),
                               patch connectivity
   Step 8   Environment        disk space, system time sync. Certificate
                               store validation only if Health Check Tool
                               is not available (otherwise covered by
                               Step 7)
   Step 9   Agent Logs         journalctl (last 50 lines), /var/log/qualys/

   No agent services are started, stopped, or restarted.
   No log archive is created.

===============================================================================
 OPTIONS
===============================================================================

 Agent Service Control (mutually exclusive — pick one or none):

   --stop          Stop the agent after diagnostics.
                   Use for maintenance or to prevent interference.

   --start         Start the agent after diagnostics.
                   Use when the agent is not running.

   --restart       Restart the agent after diagnostics.
                   Use when the agent is stuck or misbehaving.

   All three include a 5-second post-action pause with verification
   (systemctl status + process list).

 Log Collection:

   --collect-logs  Zip all agent logs, configs, certs, and /var/log/messages
                   into /tmp/Cloud_Agent_Logs_<timestamp>.zip (chmod 644).
                   Can be combined with any service flag:
                     --restart --collect-logs

 Qualys Support Escalation:

   --trace-diag    Full support escalation workflow:
                     1. Verify agent is running (interactive start/restart)
                     2. Set LogLevel=5 (Trace) with validation + retry
                     3. Trigger on-demand VM scan
                     4. Wait with progress bar (default 10 min)
                     5. Collect extended diagnostics (agent conf, ps, chage,
                        dmesg, etc.)
                     6. List recently modified agent files
                     7. Reset LogLevel=1 (default)
                     8. Collect logs (implies --collect-logs)

   --wait-minutes N  Minutes to wait after on-demand scan (default: 10).
                     Only used with --trace-diag.
                     Example: --trace-diag --wait-minutes 15

 Cleanup:

   --cleanup       Remove all report and log archive files left behind by
                   previous runs. Deletes /tmp/qualys_troubleshoot_*.txt and
                   /tmp/Cloud_Agent_Logs_*.zip, then exits. No diagnostics
                   are run. Use after you have retrieved the files via SCP.

===============================================================================
 SCP PUSH / PULL TEMPLATE
===============================================================================

   # Push script to host:
   scp -i "<cert>.pem" qualys_agent_troubleshoot.py <user>@<host_ip>:/tmp/

   # SSH in and run:
   ssh -i "<cert>.pem" <user>@<host_ip>
   sudo python3 /tmp/qualys_agent_troubleshoot.py [OPTIONS]

   # Pull results back:
   scp -i "<cert>.pem" <user>@<host_ip>:/tmp/qualys_troubleshoot_*.txt .
   scp -i "<cert>.pem" <user>@<host_ip>:/tmp/Cloud_Agent_Logs_*.zip .

   # Clean up files on the host after retrieval:
   sudo python3 /tmp/qualys_agent_troubleshoot.py --cleanup

===============================================================================
 EXAMPLES
===============================================================================

   # Diagnostics only:
   sudo python3 qualys_agent_troubleshoot.py

   # Diagnostics + restart agent:
   sudo python3 qualys_agent_troubleshoot.py --restart

   # Diagnostics + restart + collect logs for support:
   sudo python3 qualys_agent_troubleshoot.py --restart --collect-logs

   # Stop agent for maintenance:
   sudo python3 qualys_agent_troubleshoot.py --stop

   # Qualys support escalation (10 min wait):
   sudo python3 qualys_agent_troubleshoot.py --trace-diag

   # Support escalation with 15 min wait:
   sudo python3 qualys_agent_troubleshoot.py --trace-diag --wait-minutes 15

   # Clean up files from previous runs (after SCP retrieval):
   sudo python3 qualys_agent_troubleshoot.py --cleanup

===============================================================================
 OUTPUT FILES
===============================================================================

   /tmp/qualys_troubleshoot_<YYYYMMDD_HHMMSS>.txt  — diagnostic report
   /tmp/Cloud_Agent_Logs_<YYYYMMDD_HHMMSS>.zip     — log archive (if collected)

   Both created with 644 permissions for non-root SCP retrieval.
===============================================================================
"""

import argparse
import subprocess
import sys
import os
import datetime
import textwrap
import platform
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
QUALYS_HOSTS = [
    "qagpublic.qg3.apps.qualys.com",
    "cask.qg3.apps.qualys.com",
]
QUALYS_PORT = 443
AGENT_SERVICE = "qualys-cloud-agent"

OUTPUT_DIR = "/tmp"
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_FILE = os.path.join(OUTPUT_DIR, f"qualys_troubleshoot_{TIMESTAMP}.txt")

# Paths to collect for the support zip
LOG_PATHS = [
    "/etc/init.d/qualys-cloud-agent",
    "/etc/qualys/",
    "/usr/local/qualys/",
    "/var/log/qualys/",
    "/etc/opt/qualys",
    "/etc/ssl/certs",
    "/opt/qualys",
    "/var/opt/qualys",
    "/var/spool/qualys/",
    "/etc/environment",
    "/etc/default/qualys-cloud-agent",
    "/etc/sysconfig/qualys-cloud-agent",
    "/var/log/messages",
]
LOG_ZIP = os.path.join(OUTPUT_DIR, f"Cloud_Agent_Logs_{TIMESTAMP}.zip")

# Qualys Cloud Agent paths per Qualys documentation:
#   Default install:  /usr/local/qualys/cloud-agent/
#   Alternate (6.4+): /opt/qualys/cloud-agent/
#   Config:           /etc/qualys/cloud-agent/qualys-cloud-agent.conf
#   Config (FHS/opt): /etc/opt/qualys/cloud-agent/qualys-cloud-agent.conf
#   Logs:             /var/log/qualys/
#   Logs (FHS/opt):   /var/opt/qualys/cloud-agent/log/
#   HostID:           /etc/qualys/hostid
#   Spool:            /var/spool/qualys/

# Detect install directory -- check both known locations
AGENT_INSTALL_DIR = None
INSTALL_CANDIDATES = [
    "/usr/local/qualys/cloud-agent",
    "/opt/qualys/cloud-agent",
]
for _candidate in INSTALL_CANDIDATES:
    if os.path.isdir(_candidate):
        AGENT_INSTALL_DIR = _candidate
        break
if AGENT_INSTALL_DIR is None:
    AGENT_INSTALL_DIR = "/usr/local/qualys/cloud-agent"  # default fallback

# Pre-detect Qualys Health Check Tool availability
# When available, Steps 4a/4b/4c and 8c are skipped (covered by health check)
HEALTH_CHECK_AVAILABLE = False
HEALTH_CHECK_BIN = None
_hc_candidates = [
    "/usr/local/qualys/cloud-agent/bin/qualys-healthcheck-tool",
    "/opt/qualys/cloud-agent/bin/qualys-healthcheck-tool",
]
# Also check the detected install dir
_hc_from_install = os.path.join(AGENT_INSTALL_DIR, "bin", "qualys-healthcheck-tool")
if _hc_from_install not in _hc_candidates:
    _hc_candidates.append(_hc_from_install)
for _hc_path in _hc_candidates:
    if os.path.isfile(_hc_path) and os.access(_hc_path, os.X_OK):
        HEALTH_CHECK_AVAILABLE = True
        HEALTH_CHECK_BIN = _hc_path
        break
    # Also check if present but not executable (we can chmod it)
    if os.path.isfile(_hc_path):
        HEALTH_CHECK_AVAILABLE = True
        HEALTH_CHECK_BIN = _hc_path
        break


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def banner(title):
    """Return a section banner string."""
    line = "=" * 72
    return f"\n{line}\n  {title}\n{line}"


def run_cmd(cmd, timeout=30, shell=False):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd}"
    except Exception as e:
        return -1, "", str(e)


def write(fh, text):
    """Write to both the report file and stdout."""
    print(text)
    fh.write(text + "\n")


def check_root():
    """Ensure script is running as root."""
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (sudo).")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def step_system_info(fh):
    """Step 1: Collect basic system information."""
    write(fh, banner("STEP 1 — System Information"))

    rc, out, _ = run_cmd(["hostname"])
    write(fh, f"  Hostname:  {out}")

    rc, out, _ = run_cmd(["uname", "-r"])
    write(fh, f"  Kernel:    {out}")

    rc, out, _ = run_cmd(["uptime"])
    write(fh, f"  Uptime:    {out}")

    if os.path.isfile("/etc/os-release"):
        write(fh, "\n  --- /etc/os-release ---")
        rc, out, _ = run_cmd(["cat", "/etc/os-release"])
        write(fh, textwrap.indent(out, "  "))


def step_dns(fh):
    """Step 2: DNS resolution for Qualys endpoints."""
    write(fh, banner("STEP 2 — DNS Resolution"))

    for host in QUALYS_HOSTS:
        write(fh, f"\n  --- nslookup {host} ---")
        rc, out, err = run_cmd(["nslookup", host])
        write(fh, textwrap.indent(out if rc == 0 else f"[FAIL] {err}", "  "))

    write(fh, "\n  --- /etc/resolv.conf ---")
    if os.path.isfile("/etc/resolv.conf"):
        rc, out, _ = run_cmd(["cat", "/etc/resolv.conf"])
        write(fh, textwrap.indent(out, "  "))

    write(fh, "\n  --- /etc/hosts ---")
    if os.path.isfile("/etc/hosts"):
        rc, out, _ = run_cmd(["cat", "/etc/hosts"])
        write(fh, textwrap.indent(out, "  "))

    write(fh, "\n  --- nsswitch.conf hosts line ---")
    rc, out, _ = run_cmd("grep -i '^hosts' /etc/nsswitch.conf", shell=True)
    write(fh, f"  {out}" if out else "  (not found)")


def step_network(fh):
    """Step 3: Network routing and gateway connectivity."""
    write(fh, banner("STEP 3 — Network & Routing"))

    write(fh, "\n  --- ip route ---")
    rc, out, _ = run_cmd(["ip", "route"])
    write(fh, textwrap.indent(out, "  "))

    # Ping own IP (sanity check)
    rc, out, _ = run_cmd(
        "ip route | grep default | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'",
        shell=True,
    )
    if out:
        src_ip = out.splitlines()[0]
        write(fh, f"\n  --- ping self ({src_ip}, 3 packets) ---")
        rc, out, _ = run_cmd(["ping", "-c", "3", "-W", "2", src_ip])
        write(fh, textwrap.indent(out, "  "))


def step_connectivity(fh):
    """Step 4: Qualys Cloud Platform communication tests."""
    write(fh, banner("STEP 4 — Qualys Cloud Platform Communication"))

    if HEALTH_CHECK_AVAILABLE:
        write(fh, "\n  [INFO] Qualys Health Check Tool detected — skipping 4a/4b/4c.")
        write(fh, "  TCP connectivity, HTTPS status, TLS certs, and certificate store")
        write(fh, "  validation are covered by the Health Check Tool (Step 7).")
    else:
        write(fh, "\n  [INFO] Health Check Tool not found — running manual checks.")

        # --- 4a: TCP 443 connectivity ---
        write(fh, "\n  --- 4a: TCP Port 443 Connectivity ---")
        for host in QUALYS_HOSTS:
            cmd = (
                f"timeout 5 bash -c 'echo > /dev/tcp/{host}/{QUALYS_PORT}' "
                f"2>&1 && echo CONNECTED || echo FAILED"
            )
            rc, out, _ = run_cmd(cmd, shell=True, timeout=10)
            if "CONNECTED" in out:
                write(fh, f"  [OK]   {host}:{QUALYS_PORT}")
            else:
                write(fh, f"  [FAIL] {host}:{QUALYS_PORT}  —  {out}")

        # --- 4b: curl platform status check ---
        write(fh, "\n  --- 4b: Platform Status (curl) ---")
        for host in QUALYS_HOSTS:
            url = f"https://{host}/status"
            write(fh, f"\n  curl -s -o /dev/null -w '%{{http_code}}' {url}")
            rc, out, err = run_cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 10 --max-time 15 {url}",
                shell=True, timeout=20,
            )
            http_code = out.strip()
            if http_code in ("200", "204"):
                write(fh, f"  [OK]   {host} — HTTP {http_code}")
            elif http_code:
                write(fh, f"  [WARN] {host} — HTTP {http_code}")
            else:
                write(fh, f"  [FAIL] {host} — no response: {err}")

            # Also grab verbose headers for the report
            write(fh, f"\n  curl -v {url} (headers):")
            rc2, out2, err2 = run_cmd(
                f"curl -v -s -o /dev/null --connect-timeout 10 --max-time 15 {url} 2>&1",
                shell=True, timeout=20,
            )
            # curl -v writes to stderr; with 2>&1 it all lands in stdout
            if out2:
                # Trim to just the interesting parts (connection + TLS + response)
                header_lines = [
                    l for l in out2.splitlines()
                    if l.startswith("*") or l.startswith("<") or l.startswith(">")
                ]
                write(fh, textwrap.indent("\n".join(header_lines[-30:]), "  "))

        # --- 4c: TLS/SSL certificate validation ---
        write(fh, "\n  --- 4c: TLS Certificate Validation (openssl s_client) ---")
        for host in QUALYS_HOSTS:
            write(fh, f"\n  openssl s_client -connect {host}:443")
            rc, out, err = run_cmd(
                f"echo | openssl s_client -connect {host}:443 -servername {host} 2>&1",
                shell=True, timeout=15,
            )
            combined = out if out else err
            if combined:
                # Extract the key lines: subject, issuer, dates, verify result
                important_lines = []
                for line in combined.splitlines():
                    line_lower = line.strip().lower()
                    if any(kw in line_lower for kw in [
                        "subject=", "issuer=", "verify return code",
                        "not before", "not after", "depth=",
                        "certificate chain", "server certificate",
                    ]):
                        important_lines.append(line.strip())
                if important_lines:
                    write(fh, textwrap.indent("\n".join(important_lines), "  "))
                else:
                    write(fh, textwrap.indent(combined[:1000], "  "))

                # Check for verify OK
                if "verify return code: 0" in combined.lower():
                    write(fh, f"  [OK]   {host} — TLS certificate valid")
                elif "verify return code" in combined.lower():
                    write(fh, f"  [WARN] {host} — TLS verification issue (see above)")
                else:
                    write(fh, f"  [WARN] {host} — could not determine TLS status")
            else:
                write(fh, f"  [FAIL] {host} — openssl returned no output")

    # --- 4d: CAPI health check (last 24 hours of agent logs) ---
    # Always runs regardless of health check tool availability
    write(fh, "\n  --- 4d: CAPI Health Check (last 24 hours) ---")
    write(fh, "  Scanning qualys-cloud-agent.log for CAPI events...")

    # Check both default and FHS/opt log locations
    log_dirs_to_scan = ["/var/log/qualys", "/var/opt/qualys/cloud-agent/log"]
    log_files = []
    for log_dir in log_dirs_to_scan:
        if os.path.isdir(log_dir):
            for f in sorted(os.listdir(log_dir)):
                if f.startswith("qualys-cloud-agent.log"):
                    log_files.append(os.path.join(log_dir, f))

    if not log_files:
        write(fh, "  [WARN] No qualys-cloud-agent.log files found")
        for ld in log_dirs_to_scan:
            write(fh, f"  Searched: {ld}")
    else:
        write(fh, f"  Log files to scan: {len(log_files)}")
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
        write(fh, f"  Cutoff: {cutoff_str} (last 24 hours)")

        # CAPI patterns to search for
        # Success: "CAPI event successfully completed"
        # Failure: "CAPI event failed", "CAPI request failed"
        # HTTP errors in CAPI context: "Http request failed" near CAPI entries
        capi_success = 0
        capi_errors = []
        http_errors = []

        for log_file in log_files:
            rc, out, _ = run_cmd(["cat", log_file], timeout=30)
            if rc != 0 or not out:
                continue

            lines = out.splitlines()
            prev_line = ""
            for line in lines:
                # Try to extract timestamp (format: YYYY-MM-DD HH:MM:SS.mmm)
                ts_str = line[:19] if len(line) >= 19 else ""
                try:
                    line_time = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if line_time < cutoff:
                        prev_line = line
                        continue
                except ValueError:
                    pass  # line doesn't start with timestamp, still check it

                line_upper = line.upper()

                if "CAPI EVENT SUCCESSFULLY COMPLETED" in line_upper:
                    capi_success += 1
                elif "CAPI EVENT FAILED" in line_upper or "CAPI REQUEST FAILED" in line_upper:
                    capi_errors.append(line.strip())
                elif "[ERROR]" in line_upper and "HTTP REQUEST FAILED" in line_upper:
                    http_errors.append(line.strip())

                prev_line = line

        # Report results
        write(fh, f"\n  CAPI events (last 24h):")
        write(fh, f"    Successful:  {capi_success}")
        write(fh, f"    Failed:      {len(capi_errors)}")
        write(fh, f"    HTTP errors: {len(http_errors)}")

        if capi_errors or http_errors:
            write(fh, "\n  [WARN] CAPI errors detected in the last 24 hours:")
            # Show up to 20 most recent errors
            all_errors = capi_errors + http_errors
            if len(all_errors) > 20:
                write(fh, f"  (showing last 20 of {len(all_errors)} errors)")
                all_errors = all_errors[-20:]
            for err_line in all_errors:
                write(fh, f"    {err_line}")
        else:
            write(fh, "\n  [OK] CAPI calls are healthy — no errors in the last 24 hours.")


def step_firewall(fh):
    """Step 5: Firewall status."""
    write(fh, banner("STEP 5 — Firewall Status"))

    rc, out, err = run_cmd(["systemctl", "status", "firewalld"])
    combined = out + err
    if "could not be found" in combined:
        write(fh, "  firewalld is NOT installed.")
    elif rc == 0:
        write(fh, "  firewalld is ACTIVE:")
        write(fh, textwrap.indent(out, "  "))
        rc2, out2, _ = run_cmd(["firewall-cmd", "--list-all"])
        if rc2 == 0:
            write(fh, "\n  --- firewall-cmd --list-all ---")
            write(fh, textwrap.indent(out2, "  "))
    else:
        write(fh, "  firewalld is installed but INACTIVE.")

    write(fh, "\n  --- iptables (filter) ---")
    rc, out, _ = run_cmd(["iptables", "-L", "-n", "--line-numbers"])
    write(fh, textwrap.indent(out if out else "(empty)", "  "))


def step_agent_status(fh):
    """Step 6: Qualys Cloud Agent service, process, config, and identity info."""
    write(fh, banner("STEP 6 — Qualys Cloud Agent Status"))

    write(fh, "\n  --- Service Status ---")
    rc, out, err = run_cmd(["systemctl", "status", AGENT_SERVICE])
    write(fh, textwrap.indent(out or err, "  "))

    write(fh, "\n  --- Qualys Processes ---")
    rc, out, _ = run_cmd("ps aux | grep -i qual | grep -v grep", shell=True)
    write(fh, textwrap.indent(out if out else "(none running)", "  "))

    # Agent install directory listing
    write(fh, f"\n  --- Agent Install Directory ({AGENT_INSTALL_DIR}) ---")
    if os.path.isdir(AGENT_INSTALL_DIR):
        rc, out, _ = run_cmd(["ls", "-la", AGENT_INSTALL_DIR])
        write(fh, textwrap.indent(out, "  "))
    else:
        write(fh, f"  [WARN] Agent install directory not found: {AGENT_INSTALL_DIR}")

    # Agent bin directory
    agent_bin_dir = os.path.join(AGENT_INSTALL_DIR, "bin")
    if os.path.isdir(agent_bin_dir):
        write(fh, f"\n  --- Agent Bin Directory ({agent_bin_dir}) ---")
        rc, out, _ = run_cmd(["ls", "-la", agent_bin_dir])
        write(fh, textwrap.indent(out, "  "))

    # Agent configuration files
    for cfg in ["/etc/qualys/cloud-agent/qualys-cloud-agent.conf",
                "/etc/opt/qualys/cloud-agent/qualys-cloud-agent.conf",
                "/etc/default/qualys-cloud-agent",
                "/etc/sysconfig/qualys-cloud-agent"]:
        if os.path.isfile(cfg):
            write(fh, f"\n  --- {cfg} ---")
            rc, out, _ = run_cmd(["cat", cfg])
            # Mask any password/secret values in config output
            masked = []
            for line in out.splitlines():
                line_lower = line.lower()
                if any(kw in line_lower for kw in ["pass", "secret", "cred", "token"]):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        masked.append(f"{parts[0]}=********")
                    else:
                        masked.append(line)
                else:
                    masked.append(line)
            write(fh, textwrap.indent("\n".join(masked), "  "))

    # Agent Identity — HostID
    write(fh, "\n  --- Agent Identity ---")
    hostid_paths = [
        "/etc/qualys/hostid",
        "/etc/opt/qualys/hostid",
    ]
    hostid_found = False
    for hid_path in hostid_paths:
        if os.path.isfile(hid_path):
            rc, out, _ = run_cmd(["cat", hid_path])
            write(fh, f"  HostID:  {out.strip()}  ({hid_path})")
            hostid_found = True
            break
    if not hostid_found:
        write(fh, "  HostID:  (not found)")

    # Agent version — from the binary or package
    write(fh, "\n  --- Agent Version ---")
    agent_bin = os.path.join(AGENT_INSTALL_DIR, "bin", "qualys-cloud-agent")
    if os.path.isfile(agent_bin):
        rc, out, _ = run_cmd([agent_bin, "--version"], timeout=10)
        if rc == 0 and out:
            write(fh, f"  {out.strip()}")
        else:
            # Fallback: try rpm query
            rc2, out2, _ = run_cmd(
                "rpm -qa | grep -i qualys-cloud-agent", shell=True
            )
            if out2:
                write(fh, f"  Package: {out2.strip()}")
            else:
                # Fallback: try dpkg
                rc3, out3, _ = run_cmd(
                    "dpkg -l | grep -i qualys-cloud-agent", shell=True
                )
                write(fh, f"  {out3.strip()}" if out3 else "  (could not determine version)")
    else:
        # No binary found, try package manager
        rc, out, _ = run_cmd("rpm -qa | grep -i qualys-cloud-agent", shell=True)
        if out:
            write(fh, f"  Package: {out.strip()}")
        else:
            rc, out, _ = run_cmd("dpkg -l | grep -i qualys-cloud-agent", shell=True)
            write(fh, f"  {out.strip()}" if out else "  (agent binary and package not found)")

    # Proxy configuration
    write(fh, "\n  --- Agent Proxy Configuration ---")
    proxy_found = False
    # Check agent config file for proxy settings
    for cfg in ["/etc/qualys/cloud-agent/qualys-cloud-agent.conf",
                "/etc/opt/qualys/cloud-agent/qualys-cloud-agent.conf"]:
        if os.path.isfile(cfg):
            rc, out, _ = run_cmd(
                f"grep -i proxy {cfg}", shell=True, timeout=10
            )
            if out:
                write(fh, f"  From {cfg}:")
                for line in out.splitlines():
                    line_lower = line.lower()
                    if any(kw in line_lower for kw in ["pass", "secret", "cred"]):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            write(fh, f"    {parts[0]}=********")
                        else:
                            write(fh, f"    {line.strip()}")
                    else:
                        write(fh, f"    {line.strip()}")
                proxy_found = True

    # Check environment files for proxy
    for env_file in ["/etc/default/qualys-cloud-agent",
                     "/etc/sysconfig/qualys-cloud-agent",
                     "/etc/environment"]:
        if os.path.isfile(env_file):
            rc, out, _ = run_cmd(
                f"grep -i proxy {env_file}", shell=True, timeout=10
            )
            if out:
                write(fh, f"  From {env_file}:")
                for line in out.splitlines():
                    write(fh, f"    {line.strip()}")
                proxy_found = True

    if not proxy_found:
        write(fh, "  (no Qualys proxy settings found)")

    # System-wide proxy (for reference)
    write(fh, "\n  --- System Proxy Environment ---")
    rc, out, _ = run_cmd("env | grep -i proxy", shell=True)
    write(fh, textwrap.indent(out if out else "(no system proxy environment variables set)", "  "))


def step_agent_health(fh):
    """Step 7: Qualys Agent Health Check Tool."""
    write(fh, banner("STEP 7 — Qualys Agent Health Check"))

    if not HEALTH_CHECK_AVAILABLE:
        write(fh, "  [INFO] qualys-healthcheck-tool not found.")
        write(fh, "  Health Check Tool is bundled with Cloud Agent for Linux 6.3+.")
        write(fh, "  Searched:")
        for _candidate in [
            "/usr/local/qualys/cloud-agent/bin/qualys-healthcheck-tool",
            "/opt/qualys/cloud-agent/bin/qualys-healthcheck-tool",
        ]:
            write(fh, f"    {_candidate}")
        write(fh, "  Manual connectivity checks were run in Step 4 as fallback.")
        return

    hc_bin = HEALTH_CHECK_BIN
    write(fh, f"  Tool: {hc_bin}")

    # Ensure the health check binary is executable
    if not os.access(hc_bin, os.X_OK):
        try:
            os.chmod(hc_bin, 0o755)
            write(fh, "  (set executable permission on health check tool)")
        except OSError as e:
            write(fh, f"  [WARN] Could not set executable: {e}")

    write(fh, "  Running health check (this may take a moment)...")

    # The health check tool supports an optional argument for /opt installs
    # /usr/local/qualys/cloud-agent/bin/qualys-healthcheck-tool [/opt]
    hc_cmd = [hc_bin]
    if "/opt/qualys" in AGENT_INSTALL_DIR:
        hc_cmd.append("/opt")

    rc, out, err = run_cmd(hc_cmd, timeout=120)
    if rc == 0 or out:
        write(fh, "")
        write(fh, textwrap.indent(out, "  "))
    else:
        write(fh, "  [WARN] Health check returned no output.")
        if err:
            write(fh, f"  Error: {err}")

    # Try to extract the report directory from the tool's own output
    # The tool prints: "Detailed Report Location : /var/log/qualys/.../file.json"
    hc_dir_from_output = None
    if out:
        for line in out.splitlines():
            if "Detailed Report Location" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    report_path = parts[1].strip()
                    candidate_dir = os.path.dirname(report_path)
                    if os.path.isdir(candidate_dir):
                        hc_dir_from_output = candidate_dir
                break

    # Check for HealthCheck output directory (JSON/text reports)
    # Reports are generated in the localhealthcheck directory under the
    # log directory, or a HealthCheck directory relative to the tool.
    # On Linux, the actual path is typically /var/log/qualys/localhealthcheck/
    hc_parent = os.path.dirname(os.path.dirname(hc_bin))  # up from bin/
    hc_dir_candidates = []
    if hc_dir_from_output:
        hc_dir_candidates.append(hc_dir_from_output)
    hc_dir_candidates.extend([
        "/var/log/qualys/localhealthcheck",
        "/var/opt/qualys/cloud-agent/log/localhealthcheck",
        os.path.join(hc_parent, "HealthCheck"),
        os.path.join(os.path.dirname(hc_bin), "HealthCheck"),
        os.path.join(os.getcwd(), "HealthCheck"),
    ])
    hc_dir = None
    for candidate in hc_dir_candidates:
        if os.path.isdir(candidate):
            hc_dir = candidate
            break

    if hc_dir:
        write(fh, f"\n  --- Health Check Reports ({hc_dir}) ---")
        rc, out, _ = run_cmd(["ls", "-la", hc_dir])
        write(fh, textwrap.indent(out, "  "))

        # Try to read the most recent JSON report
        json_files = []
        for f in os.listdir(hc_dir):
            if f.endswith(".json"):
                full_path = os.path.join(hc_dir, f)
                json_files.append(full_path)

        if json_files:
            # Sort by modification time, newest first
            json_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            newest_json = json_files[0]
            write(fh, f"\n  --- Latest Health Check JSON: {os.path.basename(newest_json)} ---")
            try:
                with open(newest_json, "r") as jf:
                    json_content = jf.read()
                # Limit output to avoid flooding the report
                if len(json_content) > 5000:
                    write(fh, f"  (truncated to 5000 chars — full report at {newest_json})")
                    json_content = json_content[:5000]
                write(fh, textwrap.indent(json_content, "  "))
            except (OSError, IOError) as e:
                write(fh, f"  (could not read JSON report: {e})")

        # Also show the most recent text report
        txt_files = []
        for f in os.listdir(hc_dir):
            if f.endswith(".txt"):
                full_path = os.path.join(hc_dir, f)
                txt_files.append(full_path)
        if txt_files:
            txt_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            newest_txt = txt_files[0]
            write(fh, f"\n  --- Latest Health Check Text: {os.path.basename(newest_txt)} ---")
            try:
                with open(newest_txt, "r") as tf:
                    txt_content = tf.read()
                if len(txt_content) > 3000:
                    write(fh, f"  (truncated to 3000 chars — full report at {newest_txt})")
                    txt_content = txt_content[:3000]
                write(fh, textwrap.indent(txt_content, "  "))
            except (OSError, IOError) as e:
                write(fh, f"  (could not read text report: {e})")


def step_environment(fh):
    """Step 8: Environment checks — disk space, time sync, certificate store."""
    write(fh, banner("STEP 8 — Environment Checks"))

    # --- 8a: Disk Space ---
    write(fh, "\n  --- 8a: Disk Space ---")
    rc, out, _ = run_cmd(["df", "-h"])
    if out:
        write(fh, textwrap.indent(out, "  "))
    else:
        write(fh, "  (could not query disk space)")

    # Check specific Qualys-relevant mount points
    qualys_dirs = [
        AGENT_INSTALL_DIR,
        "/var/log/qualys",
        "/var/spool/qualys",
        "/var/opt/qualys",
    ]
    for qdir in qualys_dirs:
        if os.path.isdir(qdir):
            rc, out, _ = run_cmd(["df", "-h", qdir])
            if out:
                # Extract just the data line (skip header)
                lines = out.splitlines()
                if len(lines) >= 2:
                    parts = lines[-1].split()
                    if len(parts) >= 5:
                        pct_used = parts[4].rstrip("%")
                        try:
                            pct_int = int(pct_used)
                            status = "[OK]"
                            if pct_int >= 95:
                                status = "[CRIT]"
                            elif pct_int >= 90:
                                status = "[WARN]"
                            write(fh, f"  {status}  {qdir} — {parts[3]} free ({parts[4]} used)")
                        except ValueError:
                            pass

    # --- 8b: System Time Sync ---
    write(fh, "\n  --- 8b: System Time Sync ---")
    # Try timedatectl first (systemd)
    rc, out, _ = run_cmd(["timedatectl", "status"])
    if rc == 0 and out:
        write(fh, textwrap.indent(out, "  "))
    else:
        # Fallback: try chronyc or ntpstat
        rc2, out2, _ = run_cmd(["chronyc", "tracking"])
        if rc2 == 0 and out2:
            write(fh, "  --- chronyc tracking ---")
            write(fh, textwrap.indent(out2, "  "))
        else:
            rc3, out3, _ = run_cmd(["ntpstat"])
            if rc3 == 0 and out3:
                write(fh, "  --- ntpstat ---")
                write(fh, textwrap.indent(out3, "  "))
            else:
                now = datetime.datetime.now()
                write(fh, f"  System time: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                write(fh, "  [INFO] Cannot verify NTP sync status (timedatectl/chronyc/ntpstat not available).")
                write(fh, "  Ensure system clock is accurate for TLS certificate validation and CAPI communication.")

    # --- 8c: Certificate Store Validation ---
    if HEALTH_CHECK_AVAILABLE:
        write(fh, "\n  --- 8c: Certificate Store Validation ---")
        write(fh, "  [INFO] Skipped — covered by Health Check Tool (Step 7).")
        write(fh, "  The Health Check Tool validates all Qualys and patch certificates")
        write(fh, "  against the local trust store with installed/not-installed status.")
    else:
        write(fh, "\n  --- 8c: Certificate Store Validation (Qualys endpoints) ---")
        write(fh, "  Checking if Qualys TLS certificates chain to trusted roots...")

        # Check the CA certificate bundle exists
        ca_bundle_paths = [
            "/etc/ssl/certs/ca-certificates.crt",       # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",         # RHEL/CentOS
            "/etc/ssl/ca-bundle.pem",                    # SUSE
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL 7+
        ]
        ca_bundle = None
        for cab in ca_bundle_paths:
            if os.path.isfile(cab):
                ca_bundle = cab
                break

        if ca_bundle:
            write(fh, f"  CA bundle: {ca_bundle}")
        else:
            write(fh, "  [WARN] No CA certificate bundle found at standard locations")

        for host in QUALYS_HOSTS:
            write(fh, f"\n  Validating chain for: {host}")
            # Use openssl verify with explicit CA path if available
            verify_cmd = f"echo | openssl s_client -connect {host}:443 -servername {host}"
            if ca_bundle:
                verify_cmd += f" -CAfile {ca_bundle}"
            verify_cmd += " 2>&1"

            rc, out, _ = run_cmd(verify_cmd, shell=True, timeout=15)
            if out:
                # Extract verification result and chain
                chain_lines = []
                verify_line = ""
                for line in out.splitlines():
                    stripped = line.strip()
                    stripped_lower = stripped.lower()
                    if "depth=" in stripped_lower or "verify return code" in stripped_lower:
                        chain_lines.append(stripped)
                    if "verify return code" in stripped_lower:
                        verify_line = stripped

                if chain_lines:
                    write(fh, "  Chain:")
                    for cl in chain_lines:
                        write(fh, f"    {cl}")

                if "verify return code: 0" in out.lower():
                    write(fh, f"  [OK]   {host} — certificate chain is trusted")
                elif verify_line:
                    write(fh, f"  [WARN] {host} — {verify_line}")
                else:
                    write(fh, f"  [WARN] {host} — could not determine chain status")
            else:
                write(fh, f"  [FAIL] {host} — openssl returned no output")


def step_agent_logs(fh):
    """Step 9: Recent agent journal and log directory listing."""
    write(fh, banner("STEP 9 — Agent Logs"))

    write(fh, "\n  --- journalctl -u qualys-cloud-agent (last 50 lines) ---")
    rc, out, _ = run_cmd(
        ["journalctl", "-u", AGENT_SERVICE, "--no-pager", "-n", "50"]
    )
    write(fh, textwrap.indent(out if out else "(no entries)", "  "))

    # Agent log directory listing — check both default and FHS/opt locations
    log_dirs_to_list = [
        "/var/log/qualys/",
        "/var/opt/qualys/cloud-agent/log/",
    ]
    for log_dir in log_dirs_to_list:
        if os.path.isdir(log_dir):
            write(fh, f"\n  --- {log_dir} ---")
            rc, out, _ = run_cmd(["ls", "-lah", log_dir])
            write(fh, textwrap.indent(out, "  "))


def step_collect_logs(fh):
    """Collect agent logs into a zip for Qualys support."""
    write(fh, banner("COLLECT AGENT LOGS ZIP"))

    existing = [p for p in LOG_PATHS if os.path.exists(p)]
    missing = [p for p in LOG_PATHS if not os.path.exists(p)]

    if missing:
        write(fh, "  Paths not found (skipped):")
        for m in missing:
            write(fh, f"    - {m}")

    if not existing:
        write(fh, "  [WARN] No log paths found.")
        return

    cmd = ["zip", "-qr", LOG_ZIP] + existing
    rc, out, err = run_cmd(cmd, timeout=120)
    if rc == 0:
        os.chmod(LOG_ZIP, 0o644)
        size_mb = os.path.getsize(LOG_ZIP) / (1024 * 1024)
        write(fh, f"  [OK] {LOG_ZIP}  ({size_mb:.1f} MB)  (chmod 644)")
    else:
        write(fh, f"  [FAIL] zip error: {err}")


def step_agent_action(fh, action):
    """Step 10 (optional): Stop, start, or restart the Qualys Cloud Agent."""
    label = action.upper()
    write(fh, banner(f"AGENT ACTION — {label}"))

    if action == "stop":
        write(fh, "  Stopping qualys-cloud-agent...")
        rc, out, err = run_cmd(
            ["systemctl", "stop", AGENT_SERVICE], timeout=90
        )
        if rc == 0:
            write(fh, "  [OK] Agent stopped.")
        else:
            write(fh, f"  [FAIL] Stop failed: {err}")

    elif action == "start":
        write(fh, "  Starting qualys-cloud-agent...")
        rc, out, err = run_cmd(
            ["systemctl", "start", AGENT_SERVICE], timeout=90
        )
        if rc == 0:
            write(fh, "  [OK] Agent started.")
        else:
            write(fh, f"  [FAIL] Start failed: {err}")

    elif action == "restart":
        write(fh, "  Restarting qualys-cloud-agent...")
        rc, out, err = run_cmd(
            ["systemctl", "restart", AGENT_SERVICE], timeout=90
        )
        if rc == 0:
            write(fh, "  [OK] Agent restarted.")
        else:
            write(fh, f"  [FAIL] Restart failed: {err}")

    # Post-action verification
    time.sleep(5)
    write(fh, f"\n  --- Post-{action} status ---")
    rc, out, _ = run_cmd(["systemctl", "status", AGENT_SERVICE])
    write(fh, textwrap.indent(out, "  "))

    write(fh, f"\n  --- Post-{action} processes ---")
    rc, out, _ = run_cmd("ps aux | grep -i qual | grep -v grep", shell=True)
    write(fh, textwrap.indent(out if out else "(none running)", "  "))


def step_trace_diag(fh, wait_minutes):
    """Qualys support escalation: trace logging, on-demand scan, extended diag."""
    write(fh, banner("TRACE DIAGNOSTICS — Qualys Support Escalation"))

    # --- Shared paths and helpers ---
    agent_conf = "/etc/qualys/cloud-agent/qualys-cloud-agent.conf"
    loglevel_script = "/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
    ctl_script = "/usr/local/qualys/cloud-agent/bin/cloudagentctl.sh"

    def get_current_loglevel():
        """Read LogLevel from qualys-cloud-agent.conf. Returns int or None."""
        rc, out, _ = run_cmd(
            f"grep -i 'LogLevel' {agent_conf}", shell=True, timeout=10
        )
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.strip().split("=")
                if len(parts) == 2 and "loglevel" in parts[0].lower():
                    try:
                        return int(parts[1].strip())
                    except ValueError:
                        pass
        return None

    def set_loglevel(level, fh):
        """Attempt to set LogLevel. Returns True on success."""
        rc, out, err = run_cmd(
            f"bash {loglevel_script} LogLevel={level}",
            shell=True,
            timeout=60,
        )
        if out:
            write(fh, textwrap.indent(out, "  "))
        if err and rc != 0:
            write(fh, textwrap.indent(err, "  "))
        current = get_current_loglevel()
        if current == level:
            return True
        return False

    def is_agent_running():
        """Check if qualys-cloud-agent service is active and the main process exists."""
        rc, out, _ = run_cmd(
            ["systemctl", "is-active", AGENT_SERVICE], timeout=10
        )
        if rc != 0 or out.strip() != "active":
            return False
        # Also verify the actual process is running (not just systemd thinks so)
        rc2, out2, _ = run_cmd(
            "pgrep -f 'qualys-cloud-agent/bin/qualys-cloud-agent$'",
            shell=True, timeout=10,
        )
        return rc2 == 0 and out2.strip() != ""

    def prompt_user(message, options_str):
        """Prompt user for interactive choice. Returns lowercase single char."""
        print(f"\n  {message}")
        print(f"  {options_str}")
        try:
            choice = input("  Enter choice: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "q"
        return choice

    def start_agent_and_verify(fh):
        """Start (or restart) agent and wait for it to become healthy. Returns True on success."""
        write(fh, "  Starting qualys-cloud-agent...")
        run_cmd(["systemctl", "start", AGENT_SERVICE], timeout=90)
        # Wait up to 30s for agent to come up
        for i in range(6):
            time.sleep(5)
            if is_agent_running():
                write(fh, "  [OK] Agent is running.")
                return True
            print(f"\r  Waiting for agent to start... {(i+1)*5}s", end="", flush=True)
        print()
        write(fh, "  [FAIL] Agent did not start within 30 seconds.")
        return False

    def restart_agent_and_verify(fh):
        """Restart agent and wait for it to become healthy. Returns True on success."""
        write(fh, "  Restarting qualys-cloud-agent...")
        run_cmd(["systemctl", "restart", AGENT_SERVICE], timeout=90)
        for i in range(6):
            time.sleep(5)
            if is_agent_running():
                write(fh, "  [OK] Agent is running after restart.")
                return True
            print(f"\r  Waiting for agent to restart... {(i+1)*5}s", end="", flush=True)
        print()
        write(fh, "  [FAIL] Agent did not come up within 30 seconds after restart.")
        return False

    # =========================================================================
    # STEP 1/8: Verify agent is running and responsive
    # =========================================================================
    write(fh, "\n  [1/8] Checking Qualys Cloud Agent service health...")

    rc, status_out, _ = run_cmd(["systemctl", "status", AGENT_SERVICE], timeout=10)
    agent_up = is_agent_running()

    if agent_up:
        write(fh, "  [OK] Agent service is active and process is running.")
    else:
        # Determine the state for better messaging
        rc_active, active_out, _ = run_cmd(
            ["systemctl", "is-active", AGENT_SERVICE], timeout=10
        )
        state = active_out.strip() if active_out else "unknown"
        write(fh, f"  [WARN] Agent is not healthy (state: {state}).")
        if status_out:
            write(fh, textwrap.indent(status_out, "  "))

        # Interactive: offer to start/restart or quit
        max_recovery = 2
        for attempt in range(1, max_recovery + 1):
            if state in ("inactive", "dead", "failed"):
                choice = prompt_user(
                    f"Agent is {state}. Attempt {attempt}/{max_recovery}.",
                    "[S]tart agent  |  [Q]uit"
                )
            else:
                choice = prompt_user(
                    f"Agent state is '{state}' (may be stuck). Attempt {attempt}/{max_recovery}.",
                    "[R]estart agent  |  [S]tart agent  |  [Q]uit"
                )

            if choice == "s":
                write(fh, "  User chose: start agent.")
                agent_up = start_agent_and_verify(fh)
            elif choice == "r":
                write(fh, "  User chose: restart agent.")
                agent_up = restart_agent_and_verify(fh)
            elif choice == "q":
                write(fh, "  User chose: quit.")
                write(fh, "  Exiting trace diagnostics. Report saved so far.")
                return
            else:
                write(fh, f"  Unrecognized choice '{choice}', treating as quit.")
                return

            if agent_up:
                break

            if attempt == max_recovery:
                write(fh, "  [FAIL] Could not get agent running after all attempts.")
                choice = prompt_user(
                    "Agent still not running.",
                    "[C]ontinue anyway (diagnostics only)  |  [Q]uit"
                )
                if choice == "q":
                    write(fh, "  User chose: quit.")
                    return
                else:
                    write(fh, "  User chose: continue without running agent.")

    # =========================================================================
    # STEP 2/8: Set LogLevel to 5 (Trace)
    # =========================================================================
    write(fh, "\n  [2/8] Setting LogLevel=5 (Trace)...")

    current_level = get_current_loglevel()
    if current_level is not None:
        write(fh, f"  Current LogLevel: {current_level}")

    if current_level == 5:
        write(fh, "  [OK] LogLevel is already 5 (Trace) — skipping.")
    else:
        max_attempts = 3
        success = False

        for attempt in range(1, max_attempts + 1):
            write(fh, f"  Attempt {attempt}/{max_attempts}: Setting LogLevel=5...")
            success = set_loglevel(5, fh)

            if success:
                write(fh, "  [OK] LogLevel verified at 5 (Trace).")
                break

            write(fh, f"  [WARN] LogLevel verification failed (current: {get_current_loglevel()}).")

            if attempt < max_attempts:
                write(fh, "  Restarting agent and retrying...")
                restart_agent_and_verify(fh)
            else:
                write(fh, "  [FAIL] Could not set LogLevel=5 after all attempts.")
                choice = prompt_user(
                    "LogLevel could not be set to 5.",
                    "[C]ontinue anyway  |  [R]estart agent and retry  |  [Q]uit"
                )
                if choice == "r":
                    write(fh, "  User chose: restart and retry.")
                    if restart_agent_and_verify(fh):
                        success = set_loglevel(5, fh)
                        if success:
                            write(fh, "  [OK] LogLevel verified at 5 after manual retry.")
                        else:
                            write(fh, "  [FAIL] Still could not set LogLevel=5. Continuing.")
                elif choice == "q":
                    write(fh, "  User chose: quit.")
                    write(fh, "  Exiting trace diagnostics. Report saved so far.")
                    return
                else:
                    write(fh, "  User chose: continue without trace logging.")

    # =========================================================================
    # STEP 3/8: Trigger on-demand VM scan
    # =========================================================================
    write(fh, "\n  [3/8] Triggering on-demand VM scan...")

    # Ensure the script is executable
    if os.path.isfile(ctl_script):
        os.chmod(ctl_script, 0o755)

    rc, out, err = run_cmd(
        f"bash {ctl_script} action=demand type=VM",
        shell=True,
        timeout=120,
    )

    scan_triggered = False
    combined_out = (out + " " + err).lower()

    if rc == 0 and "not running" not in combined_out:
        write(fh, "  [OK] On-demand VM scan triggered.")
        scan_triggered = True
    else:
        write(fh, f"  [WARN] On-demand scan issue (rc={rc}).")
        if out:
            write(fh, textwrap.indent(out, "  "))
        if err:
            write(fh, textwrap.indent(err, "  "))

        # Agent may have died — check and offer recovery
        if not is_agent_running():
            write(fh, "  Agent is not running — scan cannot proceed.")
            choice = prompt_user(
                "Agent is not running. Cannot trigger on-demand scan.",
                "[S]tart agent and retry scan  |  [C]ontinue (skip scan)  |  [Q]uit"
            )
            if choice == "s":
                write(fh, "  User chose: start agent and retry.")
                if start_agent_and_verify(fh):
                    time.sleep(5)
                    rc2, out2, err2 = run_cmd(
                        f"bash {ctl_script} action=demand type=VM",
                        shell=True, timeout=120,
                    )
                    if rc2 == 0:
                        write(fh, "  [OK] On-demand VM scan triggered after restart.")
                        scan_triggered = True
                    else:
                        write(fh, "  [WARN] Scan still failed after restart.")
                        if out2:
                            write(fh, textwrap.indent(out2, "  "))
            elif choice == "q":
                write(fh, "  User chose: quit.")
                return
            else:
                write(fh, "  User chose: continue without scan.")

    # =========================================================================
    # STEP 4/8: Wait for scan to complete — progress bar with countdown
    # =========================================================================
    if scan_triggered:
        total_seconds = wait_minutes * 60
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=total_seconds)
        eta_str = end_time.strftime("%H:%M:%S %Z")
        write(fh, f"\n  [4/8] Waiting {wait_minutes} minutes for on-demand scan...")
        write(fh, f"         Estimated completion: {eta_str}")
        print()

        bar_width = 30
        for elapsed in range(total_seconds + 1):
            remaining = total_seconds - elapsed
            mins, secs = divmod(remaining, 60)
            pct = elapsed / total_seconds
            filled = int(bar_width * pct)
            bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
            print(
                f"\r  {bar}  {mins:02d}:{secs:02d}  [{pct*100:.0f}%]",
                end="", flush=True,
            )
            if elapsed < total_seconds:
                time.sleep(1)

        done_bar = "\u2588" * bar_width
        print(f"\r  {done_bar}  00:00  [100%]  Done!          ")
        print()
        write(fh, f"  [OK] {wait_minutes} minute wait complete.")
    else:
        write(fh, "\n  [4/8] Skipping wait — on-demand scan was not triggered.")

    # =========================================================================
    # STEP 5/8: Extended agent diagnostics
    # =========================================================================
    write(fh, "\n  [5/8] Collecting extended agent diagnostics...")

    diag_commands = [
        ("systemctl status qualys-cloud-agent",
         ["systemctl", "status", AGENT_SERVICE]),
        ("cat qualys-cloud-agent.conf",
         ["cat", agent_conf]),
        ("id",
         ["id"]),
        ("ps -ef | grep qualys",
         "ps -ef | grep qualys | grep -v grep"),
        ("ps -ef | grep cep",
         "ps -ef | grep cep | grep -v grep"),
        ("chage -l root (password expiry)",
         ["chage", "-l", "root"]),
        ("dmesg (last 50 lines)",
         ["dmesg", "--ctime", "-T"]),
    ]

    for label, cmd in diag_commands:
        write(fh, f"\n  --- {label} ---")
        is_shell = isinstance(cmd, str)
        rc, out, err = run_cmd(cmd, shell=is_shell, timeout=30)
        if "dmesg" in label and out:
            lines = out.splitlines()
            out = "\n".join(lines[-50:])
        write(fh, textwrap.indent(out if out else err if err else "(no output)", "  "))

    # =========================================================================
    # STEP 6/8: List trace log directories
    # =========================================================================
    write(fh, "\n  [6/8] Agent log directory contents...")
    for log_dir in ["/usr/local/qualys/", "/var/log/qualys/", "/etc/qualys/"]:
        if os.path.isdir(log_dir):
            write(fh, f"\n  --- {log_dir} ---")
            rc, out, _ = run_cmd(["find", log_dir, "-type", "f",
                                  "-mmin", f"-{wait_minutes + 5}",
                                  "-ls"], timeout=30)
            write(fh, textwrap.indent(
                out if out else "(no recently modified files)", "  "
            ))

    # =========================================================================
    # STEP 7/8: Reset LogLevel back to default (1 = Error)
    # =========================================================================
    write(fh, "\n  [7/8] Resetting LogLevel=1 (default)...")
    current_level = get_current_loglevel()
    if current_level == 1:
        write(fh, "  [OK] LogLevel is already 1 — skipping.")
    else:
        success = set_loglevel(1, fh)
        if success:
            write(fh, "  [OK] LogLevel verified at 1 (default).")
        else:
            write(fh, f"  [WARN] LogLevel reset could not be verified (current: {get_current_loglevel()}).")
            write(fh, "  Manual reset: sudo bash "
                  "/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh LogLevel=1")

    # =========================================================================
    # STEP 8/8: Done — log collection follows
    # =========================================================================
    write(fh, "\n  [8/8] Trace diagnostics complete.")
    write(fh, "  Log collection will follow (--trace-diag implies --collect-logs).")


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Qualys Cloud Agent Troubleshooting Script — run with sudo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              sudo python3 qualys_agent_troubleshoot.py                         # diagnostics only
              sudo python3 qualys_agent_troubleshoot.py --restart               # diagnostics + restart agent
              sudo python3 qualys_agent_troubleshoot.py --restart --collect-logs # restart + zip logs for support
              sudo python3 qualys_agent_troubleshoot.py --trace-diag            # full Qualys support escalation
              sudo python3 qualys_agent_troubleshoot.py --trace-diag --wait-minutes 15
              sudo python3 qualys_agent_troubleshoot.py --cleanup               # remove previous output files

            By default (no flags), the script runs diagnostics only. No agent
            services are changed and no log archive is created. All output is
            saved to /tmp/ with 644 permissions for easy SCP retrieval.
        """),
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--stop",
        action="store_true",
        help="Stop the agent after diagnostics (e.g. for maintenance).",
    )
    group.add_argument(
        "--start",
        action="store_true",
        help="Start the agent after diagnostics (e.g. agent is down).",
    )
    group.add_argument(
        "--restart",
        action="store_true",
        help="Restart the agent after diagnostics (stop + start). "
             "Use when the agent is misbehaving or stuck.",
    )

    parser.add_argument(
        "--collect-logs",
        action="store_true",
        help="Zip all agent logs, configs, and certs into a single archive "
             "for Qualys support. Can be combined with any agent action flag.",
    )
    parser.add_argument(
        "--trace-diag",
        action="store_true",
        help="Qualys support escalation workflow. Sets agent LogLevel to 5 "
             "(trace), triggers an on-demand VM scan, waits for it to "
             "complete, then collects extended diagnostics (agent config, "
             "process list, root password expiry, dmesg, etc.). "
             "Automatically implies --collect-logs.",
    )
    parser.add_argument(
        "--wait-minutes",
        type=int,
        default=10,
        metavar="MIN",
        help="Minutes to wait after on-demand VM scan before collecting "
             "trace logs. Only used with --trace-diag. Default: 10. "
             "Qualys support may ask you to increase this to 15.",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove all report and log archive files from /tmp/ left by "
             "previous runs, then exit. No diagnostics are run.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()
    check_root()

    # --- Handle --cleanup: remove previous output files and exit ---
    if args.cleanup:
        import glob
        patterns = [
            os.path.join(OUTPUT_DIR, "qualys_troubleshoot_*.txt"),
            os.path.join(OUTPUT_DIR, "Cloud_Agent_Logs_*.zip"),
        ]
        total_removed = 0
        print("\n  Cleaning up previous troubleshooting files in /tmp/...\n")
        for pattern in patterns:
            matches = glob.glob(pattern)
            for f in matches:
                try:
                    os.remove(f)
                    print(f"  Removed: {f}")
                    total_removed += 1
                except OSError as e:
                    print(f"  [WARN] Could not remove {f}: {e}")
        if total_removed == 0:
            print("  No files found to clean up.")
        else:
            print(f"\n  [OK] Removed {total_removed} file(s).")
        print()
        sys.exit(0)

    os.system("clear")

    # --trace-diag implies --collect-logs
    if args.trace_diag:
        args.collect_logs = True

    # Determine agent action
    agent_action = None
    if args.stop:
        agent_action = "stop"
    elif args.start:
        agent_action = "start"
    elif args.restart:
        agent_action = "restart"

    # Build mode string
    flags = []
    if args.trace_diag:
        flags.append(f"trace-diag (wait {args.wait_minutes}min)")
    if agent_action:
        flags.append(agent_action)
    if args.collect_logs and not args.trace_diag:
        flags.append("collect-logs")
    mode = "diagnostics + " + ", ".join(flags) if flags else "diagnostics only"

    start = datetime.datetime.now()

    print(f"\n{'=' * 72}")
    print(f"  Qualys Cloud Agent Troubleshooting Script  v1.6.0")
    print(f"  Host:    {platform.node()}")
    print(f"  Date:    {start.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"  Mode:    {mode}")
    print(f"  Report:  {REPORT_FILE}")
    print(f"{'=' * 72}\n")

    with open(REPORT_FILE, "w") as fh:
        write(fh, f"Qualys Cloud Agent Troubleshooting Report")
        write(fh, f"Generated: {start.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        write(fh, f"Host:      {platform.node()}")
        write(fh, f"Mode:      {mode}")

        step_system_info(fh)       # 1
        step_dns(fh)               # 2
        step_network(fh)           # 3
        step_connectivity(fh)      # 4 (Platform Comms)
        step_firewall(fh)          # 5
        step_agent_status(fh)      # 6
        step_agent_health(fh)      # 7
        step_environment(fh)       # 8
        step_agent_logs(fh)        # 9

        if args.trace_diag:
            step_trace_diag(fh, args.wait_minutes)

        if args.collect_logs:
            step_collect_logs(fh)  # 9

        if agent_action:
            step_agent_action(fh, agent_action)  # 10

        # --- Summary ---
        elapsed = (datetime.datetime.now() - start).total_seconds()
        write(fh, banner("SUMMARY"))
        write(fh, f"  Report:       {REPORT_FILE}")
        if args.collect_logs and os.path.isfile(LOG_ZIP):
            size_mb = os.path.getsize(LOG_ZIP) / (1024 * 1024)
            write(fh, f"  Log archive:  {LOG_ZIP}  ({size_mb:.1f} MB)")
        if agent_action:
            write(fh, f"  Action:       {agent_action}")
        write(fh, f"  Duration:     {elapsed:.1f}s")
        write(fh, "")
        write(fh, "  --- SCP Pull Commands (from Windows Downloads) ---")
        write(fh, f'  scp -i "<Certificate Name>.pem" "<User Name>"@<HOST_IP>:{REPORT_FILE} .')
        if args.collect_logs and os.path.isfile(LOG_ZIP):
            write(fh, f'  scp -i "<Certificate Name>.pem" "<User Name>"@<HOST_IP>:{LOG_ZIP} .')
        write(fh, "")
        write(fh, "  --- Cleanup (after retrieving files) ---")
        write(fh, "  sudo python3 /tmp/qualys_agent_troubleshoot.py --cleanup")

    # Set permissions so non-root users can SCP retrieve
    os.chmod(REPORT_FILE, 0o644)

    # Append report into the zip if it exists
    if args.collect_logs and os.path.isfile(LOG_ZIP):
        run_cmd(["zip", "-qj", LOG_ZIP, REPORT_FILE])
        os.chmod(LOG_ZIP, 0o644)

    print(f"\n  Done. Report: {REPORT_FILE}\n")


if __name__ == "__main__":
    main()
