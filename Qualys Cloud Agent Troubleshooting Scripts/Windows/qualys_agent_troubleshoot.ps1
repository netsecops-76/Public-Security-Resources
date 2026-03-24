<#
===============================================================================
 Qualys Cloud Agent Troubleshooting Script for Windows
===============================================================================
 Version:    1.6.0
 Author:     Brian Canaday -- netsecops@gmail.com
 Platform:   PowerShell 5.1 required

 Supported Operating Systems (native PowerShell 5.1):
   - Windows Server 2016 and later
   - Windows 10 and later

 Supported Operating Systems (manual WMF 5.1 install required):
   - Windows Server 2012 R2
   - Windows Server 2012
   - Windows Server 2008 R2 SP1

 Not Supported:
   - Windows Server 2008 (non-R2), 2003, 2000 -- cannot run PS 5.1
   - Any OS without .NET Framework 4.5.2+

 WMF 5.1 Manual Download (for older OS):
   https://aka.ms/wmf51download

 Purpose:
   Automated troubleshooting for the Qualys Cloud Agent. Designed so any
   team member can collect complete, organized diagnostic data from a
   Windows host without requiring specific Qualys knowledge.

   All output is written to a timestamped report file in the user's
   Downloads folder, ready for collection.

 Prerequisites:
   - Run as Administrator (elevated PowerShell)
   - PowerShell 5.1+ (see supported OS list above)
   - .NET Framework 4.5.2+
   - Script copied to the target host

===============================================================================
 DIAGNOSTIC STEPS (default -- no flags)
===============================================================================

   Step 1   System Info        hostname, OS version, build, uptime, domain
   Step 2   DNS                nslookup Qualys endpoints, DNS client config,
                               hosts file
   Step 3   Network            route print, IP configuration, ping self
   Step 4   Platform Comms     If Health Check Tool is available: skips
                               4a/4b/4c (covered by Step 7). Otherwise:
                               TCP 443 check (async w/ timeout),
                               Invoke-WebRequest /status, TLS cert
                               validation (SslStream w/ timeout).
                               Always: CAPI log health check (last 24
                               hours), WinHTTP error code extraction
   Step 5   Firewall           Windows Firewall profiles, Qualys-specific
                               rules
   Step 6   Agent Status       service status, process list, install dir,
                               agent config, proxy config, HostID, agent
                               version, self-protection status
   Step 7   Agent Health       Qualys Health Check Tool
                               (QualysAgentHealthCheck.exe) if available.
                               Covers: backend connectivity, TLS handshake
                               details (cipher/protocol/cert chain),
                               certificate store validation, module health
                               (VM/PC/SCA/PM), patch connectivity
   Step 8   Environment        disk space, system time sync. Certificate
                               store validation only if Health Check Tool
                               is not available (otherwise covered by
                               Step 7)
   Step 9   Agent Logs         Application Event Log (Qualys source),
                               agent log directory listing

   No agent services are started, stopped, or restarted.
   No log archive is created.

===============================================================================
 OPTIONS
===============================================================================

 Agent Service Control (mutually exclusive -- pick one or none):

   -Stop           Stop the agent after diagnostics.
                   Use for maintenance or to prevent interference.

   -Start          Start the agent after diagnostics.
                   Use when the agent is not running.

   -Restart        Restart the agent after diagnostics.
                   Use when the agent is stuck or misbehaving.

   All three include a 5-second post-action pause with verification
   (service status + process list).

 Log Collection:

   -CollectLogs    Zip all agent logs, configs, and certs into
                   %USERPROFILE%\Downloads\Cloud_Agent_Logs_<timestamp>.zip
                   Can be combined with any service flag:
                     -Restart -CollectLogs

 Qualys Support Escalation:

   -TraceDiag      Full support escalation workflow:
                     1. Verify agent is running (interactive start/restart)
                     2. Set LogLevel=5 (Trace) with validation and retry
                     3. Trigger on-demand VM scan
                     4. Wait with progress bar (default 10 min)
                     5. Collect extended diagnostics (agent config, processes,
                        local admins, recent system errors, etc.)
                     6. List recently modified agent files
                     7. Reset LogLevel=1 (default)
                     8. Collect logs (implies -CollectLogs)

   -WaitMinutes N  Minutes to wait after on-demand scan (default: 10).
                   Only used with -TraceDiag.
                   Example: -TraceDiag -WaitMinutes 15

 Cleanup:

   -Cleanup        Remove all report and log archive files left behind by
                   previous runs in %USERPROFILE%\Downloads, then exit.
                   No diagnostics are run. Use after you have collected
                   the output files.

===============================================================================
 COPY TEMPLATE
===============================================================================

   # Copy script to target host (from admin workstation):
   Copy-Item .\qualys_agent_troubleshoot.ps1 \\<HOSTNAME>\C$\Temp\

   # Or via RDP, copy to C:\Temp\ on the target host

   # Run on the target host (elevated PowerShell):
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   C:\Temp\qualys_agent_troubleshoot.ps1 [OPTIONS]

   # Collect results from:
   %USERPROFILE%\Downloads\qualys_troubleshoot_*.txt
   %USERPROFILE%\Downloads\Cloud_Agent_Logs_*.zip

   # Clean up files on the host after collection:
   C:\Temp\qualys_agent_troubleshoot.ps1 -Cleanup

===============================================================================
 EXAMPLES
===============================================================================

   # Diagnostics only:
   .\qualys_agent_troubleshoot.ps1

   # Diagnostics + restart agent:
   .\qualys_agent_troubleshoot.ps1 -Restart

   # Diagnostics + restart + collect logs for support:
   .\qualys_agent_troubleshoot.ps1 -Restart -CollectLogs

   # Stop agent for maintenance:
   .\qualys_agent_troubleshoot.ps1 -Stop

   # Qualys support escalation (10 min wait):
   .\qualys_agent_troubleshoot.ps1 -TraceDiag

   # Support escalation with 15 min wait:
   .\qualys_agent_troubleshoot.ps1 -TraceDiag -WaitMinutes 15

   # Clean up files from previous runs (after collection):
   .\qualys_agent_troubleshoot.ps1 -Cleanup

===============================================================================
 OUTPUT FILES
===============================================================================

   %USERPROFILE%\Downloads\qualys_troubleshoot_<YYYYMMDD_HHMMSS>.txt
       -- diagnostic report

   %USERPROFILE%\Downloads\Cloud_Agent_Logs_<YYYYMMDD_HHMMSS>.zip
       -- log archive (if -CollectLogs or -TraceDiag)

===============================================================================
 ROADMAP (future enhancements)
===============================================================================

   - netsh trace integration: Add -NetTrace flag to start a network
     capture (netsh trace start persistent=yes capture=yes), restart
     the agent, wait for error reproduction, then stop capture and
     collect the .etl file for Qualys support analysis.

   - On-demand scan via registry: As a fallback when QualysAgentCtl.exe
     is not found, trigger scans by creating registry subkeys under
     HKLM\SOFTWARE\Qualys\QualysAgent (Inventory, Vulnerability,
     PolicyCompliance, UDC, SCA) and setting ScanOnDemand=1 (DWORD).

   - Get-EventLog migration: Get-EventLog is deprecated in PS 7+.
     When PS 7+ becomes a target, replace with Get-WinEvent and
     FilterHashtable queries.

   - TLS SecurityProtocol restore: Currently the script sets
     [System.Net.ServicePointManager]::SecurityProtocol to TLS 1.2
     without restoring the original value. This is safe because the
     script runs in its own process, but if the script is ever
     dot-sourced or used in a larger session, a save/restore pattern
     should be added.

===============================================================================
#>
[CmdletBinding()]
param(
    [switch]$Stop,
    [switch]$Start,
    [switch]$Restart,
    [switch]$CollectLogs,
    [switch]$TraceDiag,
    [switch]$Cleanup,
    [int]$WaitMinutes = 10
)

# ============================================================================
# Strict PS5.1 compliance -- no ?. no ?? no ternary no [PSCustomObject]@{}
# no Where-Object pipelines -- use foreach. Pure ASCII only. Never use $PID.
# ============================================================================

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$QualysHosts = @(
    "qagpublic.qg3.apps.qualys.com",
    "cask.qg3.apps.qualys.com"
)
$QualysPort = 443
$AgentServiceName = "QualysAgent"

# Qualys Cloud Agent paths per Qualys documentation:
#   Install:  C:\Program Files (x86)\QualysAgent\Qualys\  (some installs use Program Files)
#   Data:     C:\ProgramData\Qualys\QualysAgent\
#   Logs:     C:\ProgramData\Qualys\QualysAgent\  (Log.txt, Archive.*.txt)
#   Log dir:  C:\ProgramData\Qualys\QualysAgent\Log\  (per-app logs)
#   Fallback: C:\Windows\Logs\QualysAgent (if ProgramData not accessible)
#   Registry: HKLM\SOFTWARE\Qualys\QualysAgent\Logs\TraceLevel (DWORD, 6=debug)

# Detect install directory -- check both known locations
$AgentInstallDir = $null
$installCandidates = @(
    "C:\Program Files\Qualys\QualysAgent",
    "C:\Program Files (x86)\QualysAgent\Qualys",
    "C:\Program Files (x86)\QualysAgent"
)
foreach ($candidate in $installCandidates) {
    if (Test-Path $candidate) {
        $AgentInstallDir = $candidate
        break
    }
}
if (-not $AgentInstallDir) {
    $AgentInstallDir = "C:\Program Files\Qualys\QualysAgent"
}

$AgentDataDir = "C:\ProgramData\Qualys\QualysAgent"
$AgentLogDir = Join-Path $AgentDataDir "Log"
$AgentLogFallback = "C:\Windows\Logs\QualysAgent"
$AgentRegPath = "HKLM:\SOFTWARE\Qualys\QualysAgent\Logs"

# Pre-detect Qualys Health Check Tool availability
# When available, Steps 4a/4b/4c and 8c are skipped (covered by health check)
$HealthCheckAvailable = $false
$HealthCheckExe = $null
$hcCandidates = @(
    "C:\Program Files\Qualys\QualysAgent\QualysAgentHealthCheck.exe",
    "C:\Program Files (x86)\QualysAgent\Qualys\QualysAgentHealthCheck.exe",
    "C:\Program Files (x86)\QualysAgent\QualysAgentHealthCheck.exe"
)
# Also check the detected install dir
foreach ($candidate in $installCandidates) {
    $hcCandidates += (Join-Path $candidate "QualysAgentHealthCheck.exe")
}
foreach ($hcPath in $hcCandidates) {
    if (Test-Path $hcPath) {
        $HealthCheckAvailable = $true
        $HealthCheckExe = $hcPath
        break
    }
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path $env:USERPROFILE "Downloads"
$ReportFile = Join-Path $OutputDir ("qualys_troubleshoot_" + $Timestamp + ".txt")

# Paths to collect for the support zip (per Qualys support requirements)
$LogPaths = @(
    $AgentDataDir,
    $AgentInstallDir,
    $AgentLogFallback
)
$LogZip = Join-Path $OutputDir ("Cloud_Agent_Logs_" + $Timestamp + ".zip")

# Stopwatch for duration tracking
$ScriptTimer = New-Object System.Diagnostics.Stopwatch
$ScriptTimer.Start()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Banner {
    param([string]$Title)
    $line = "=" * 72
    $text = "`n$line`n  $Title`n$line"
    return $text
}

function Write-Both {
    param([string]$Text)
    Write-Host $Text
    # Use shared StreamWriter for performance (opened once, closed at script end)
    if ($script:ReportWriter) {
        $script:ReportWriter.WriteLine($Text)
        $script:ReportWriter.Flush()
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeCommand {
    param(
        [string]$Command,
        [int]$TimeoutSeconds = 30
    )
    $result = New-Object PSObject
    $result | Add-Member -MemberType NoteProperty -Name "ExitCode" -Value -1
    $result | Add-Member -MemberType NoteProperty -Name "Output" -Value ""
    $result | Add-Member -MemberType NoteProperty -Name "Error" -Value ""

    try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "cmd.exe"
        $pinfo.Arguments = "/c $Command"
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $pinfo
        $null = $proc.Start()

        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()

        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            try { $proc.Kill() } catch {}
            $result.Error = "Command timed out after ${TimeoutSeconds}s"
            return $result
        }

        $result.ExitCode = $proc.ExitCode
        $result.Output = $stdout.Trim()
        $result.Error = $stderr.Trim()
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ---------------------------------------------------------------------------
# Step 1: System Information
# ---------------------------------------------------------------------------
function Step-SystemInfo {
    Write-Both (Write-Banner "STEP 1 -- System Information")

    $hostname = $env:COMPUTERNAME
    Write-Both "  Hostname:     $hostname"

    $os = Get-WmiObject -Class Win32_OperatingSystem
    Write-Both "  OS:           $($os.Caption) $($os.Version)"
    Write-Both "  Build:        $($os.BuildNumber)"

    $bootTime = $os.ConvertToDateTime($os.LastBootUpTime)
    $uptime = (Get-Date) - $bootTime
    $uptimeStr = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    Write-Both "  Uptime:       $uptimeStr (boot: $($bootTime.ToString('yyyy-MM-dd HH:mm:ss')))"

    $cs = Get-WmiObject -Class Win32_ComputerSystem
    Write-Both "  Domain:       $($cs.Domain)"
    Write-Both "  Model:        $($cs.Manufacturer) $($cs.Model)"

    $mem = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    Write-Both "  Memory:       ${mem} GB"

    Write-Both "  PowerShell:   $($PSVersionTable.PSVersion)"
}

# ---------------------------------------------------------------------------
# Step 2: DNS Resolution
# ---------------------------------------------------------------------------
function Step-DNS {
    Write-Both (Write-Banner "STEP 2 -- DNS Resolution")

    foreach ($hostName in $QualysHosts) {
        Write-Both "`n  --- nslookup $hostName ---"
        $r = Get-SafeCommand -Command "nslookup $hostName" -TimeoutSeconds 10
        if ($r.ExitCode -eq 0) {
            foreach ($line in $r.Output.Split("`n")) {
                Write-Both "  $line"
            }
        }
        else {
            Write-Both "  [FAIL] $($r.Error)"
        }
    }

    Write-Both "`n  --- DNS Client Server Addresses ---"
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
        foreach ($adapter in $dnsServers) {
            $ifAlias = $adapter.InterfaceAlias
            $addrs = $adapter.ServerAddresses -join ", "
            if ($addrs) {
                Write-Both "  $ifAlias : $addrs"
            }
        }
    }
    catch {
        Write-Both "  (Get-DnsClientServerAddress not available -- falling back to WMI)"
        try {
            $wmiAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction Stop
            foreach ($wmiNic in $wmiAdapters) {
                if ($wmiNic.IPEnabled -and $wmiNic.DNSServerSearchOrder) {
                    $dnsAddrs = $wmiNic.DNSServerSearchOrder -join ", "
                    Write-Both "  $($wmiNic.Description) : $dnsAddrs"
                }
            }
        }
        catch {
            Write-Both "  (WMI DNS fallback also failed: $($_.Exception.Message))"
        }
    }

    Write-Both "`n  --- hosts file ---"
    $hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        $hostsContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
        foreach ($line in $hostsContent) {
            Write-Both "  $line"
        }
    }
    else {
        Write-Both "  (hosts file not found)"
    }
}

# ---------------------------------------------------------------------------
# Step 3: Network & Routing
# ---------------------------------------------------------------------------
function Step-Network {
    Write-Both (Write-Banner "STEP 3 -- Network & Routing")

    Write-Both "`n  --- route print (IPv4) ---"
    $r = Get-SafeCommand -Command "route print -4" -TimeoutSeconds 10
    if ($r.Output) {
        foreach ($line in $r.Output.Split("`n")) {
            Write-Both "  $line"
        }
    }

    Write-Both "`n  --- IP Configuration ---"
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
    foreach ($adapter in $adapters) {
        if ($adapter.IPEnabled) {
            Write-Both "  Adapter:  $($adapter.Description)"
            $ipList = $adapter.IPAddress
            if ($ipList) {
                foreach ($ip in $ipList) {
                    Write-Both "  IP:       $ip"
                }
            }
            $gwList = $adapter.DefaultIPGateway
            if ($gwList) {
                foreach ($gw in $gwList) {
                    Write-Both "  Gateway:  $gw"
                }
            }
            Write-Both ""
        }
    }

    # Ping self
    $localIPs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
    foreach ($nic in $localIPs) {
        if ($nic.IPEnabled -and $nic.IPAddress) {
            $selfIP = $nic.IPAddress[0]
            Write-Both "  --- ping self ($selfIP, 3 packets) ---"
            $r = Get-SafeCommand -Command "ping -n 3 -w 2000 $selfIP" -TimeoutSeconds 15
            foreach ($line in $r.Output.Split("`n")) {
                Write-Both "  $line"
            }
            break
        }
    }
}

# ---------------------------------------------------------------------------
# Step 4: Qualys Cloud Platform Communication
# ---------------------------------------------------------------------------
function Step-Connectivity {
    Write-Both (Write-Banner "STEP 4 -- Qualys Cloud Platform Communication")

    if ($script:HealthCheckAvailable) {
        Write-Both "`n  [INFO] Qualys Health Check Tool detected -- skipping 4a/4b/4c."
        Write-Both "  TCP connectivity, HTTPS status, TLS certs, and certificate store"
        Write-Both "  validation are covered by the Health Check Tool (Step 7)."
    }
    else {
        Write-Both "`n  [INFO] Health Check Tool not found -- running manual checks."

    # --- 4a: TCP 443 connectivity ---
    Write-Both "`n  --- 4a: TCP Port 443 Connectivity ---"
    foreach ($qHost in $QualysHosts) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectResult = $tcp.BeginConnect($qHost, $QualysPort, $null, $null)
            $waited = $connectResult.AsyncWaitHandle.WaitOne(5000, $false)
            if ($waited -and $tcp.Connected) {
                Write-Both "  [OK]   ${qHost}:${QualysPort}"
            }
            else {
                Write-Both "  [FAIL] ${qHost}:${QualysPort} -- connection timed out"
            }
            $tcp.Close()
        }
        catch {
            Write-Both "  [FAIL] ${qHost}:${QualysPort} -- $($_.Exception.Message)"
        }
    }

    # --- 4b: Platform Status (Invoke-WebRequest) ---
    Write-Both "`n  --- 4b: Platform Status (HTTPS) ---"
    foreach ($qHost in $QualysHosts) {
        $url = "https://${qHost}/status"
        Write-Both "`n  Testing: $url"
        try {
            # Force TLS 1.2
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            $statusCode = $response.StatusCode
            if ($statusCode -eq 200 -or $statusCode -eq 204) {
                Write-Both "  [OK]   $qHost -- HTTP $statusCode"
            }
            else {
                Write-Both "  [WARN] $qHost -- HTTP $statusCode"
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            # Try to extract HTTP status from the exception
            if ($_.Exception.Response) {
                $respStatus = [int]$_.Exception.Response.StatusCode
                Write-Both "  [WARN] $qHost -- HTTP $respStatus"
            }
            else {
                Write-Both "  [FAIL] $qHost -- $errMsg"
            }
        }
    }

    # --- 4c: TLS Certificate Validation ---
    Write-Both "`n  --- 4c: TLS Certificate Validation ---"
    foreach ($qHost in $QualysHosts) {
        Write-Both "`n  Checking certificate: ${qHost}:443"
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectResult = $tcp.BeginConnect($qHost, 443, $null, $null)
            $waited = $connectResult.AsyncWaitHandle.WaitOne(10000, $false)
            if (-not $waited -or -not $tcp.Connected) {
                Write-Both "  [FAIL] ${qHost}:443 -- connection timed out (10s)"
                try { $tcp.Close() } catch {}
                continue
            }
            $tcp.EndConnect($connectResult)
            $sslStream = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
            $sslStream.AuthenticateAsClient($qHost)

            $cert = $sslStream.RemoteCertificate
            $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)

            Write-Both "  Subject:    $($cert2.Subject)"
            Write-Both "  Issuer:     $($cert2.Issuer)"
            Write-Both "  Not Before: $($cert2.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Both "  Not After:  $($cert2.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Both "  Thumbprint: $($cert2.Thumbprint)"
            Write-Both "  Protocol:   $($sslStream.SslProtocol)"

            $now = Get-Date
            if ($now -lt $cert2.NotBefore -or $now -gt $cert2.NotAfter) {
                Write-Both "  [WARN] $qHost -- certificate is EXPIRED or not yet valid"
            }
            else {
                Write-Both "  [OK]   $qHost -- TLS certificate valid"
            }

            $sslStream.Close()
            $tcp.Close()
        }
        catch {
            Write-Both "  [FAIL] $qHost -- $($_.Exception.Message)"
        }
    }

    } # end if (-not $HealthCheckAvailable)

    # --- 4d: CAPI Health Check (last 24 hours of agent logs) ---
    Write-Both "`n  --- 4d: CAPI Health Check (last 24 hours) ---"
    Write-Both "  Scanning agent log files for CAPI events..."

    $logFiles = @()

    # Primary log location: C:\ProgramData\Qualys\QualysAgent\  (Log.txt, Archive.*.txt)
    # Per-app logs:         C:\ProgramData\Qualys\QualysAgent\Log\
    # Fallback location:    C:\Windows\Logs\QualysAgent
    $logSearchDirs = @(
        $AgentDataDir,
        $AgentLogDir,
        $AgentLogFallback
    )

    foreach ($searchDir in $logSearchDirs) {
        if (Test-Path $searchDir) {
            # Scan for Log.txt, Archive*.txt, and any .log files
            $txtFiles = Get-ChildItem -Path $searchDir -Filter "*.txt" -ErrorAction SilentlyContinue
            foreach ($f in $txtFiles) {
                $logFiles += $f.FullName
            }
            $logFileMatches = Get-ChildItem -Path $searchDir -Filter "*.log" -ErrorAction SilentlyContinue
            foreach ($f in $logFileMatches) {
                $logFiles += $f.FullName
            }
        }
    }

    if ($logFiles.Count -eq 0) {
        Write-Both "  [WARN] No agent log files found"
        foreach ($sd in $logSearchDirs) {
            Write-Both "  Searched: $sd"
        }
    }
    else {
        Write-Both "  Log files to scan: $($logFiles.Count)"
        $cutoff = (Get-Date).AddHours(-24)
        Write-Both "  Cutoff: $($cutoff.ToString('yyyy-MM-dd HH:mm:ss')) (last 24 hours)"

        $capiSuccess = 0
        $capiErrors = New-Object System.Collections.ArrayList
        $httpErrors = New-Object System.Collections.ArrayList
        $winHttpCodes = @{}

        foreach ($logFile in $logFiles) {
            $content = $null
            try {
                $content = Get-Content -Path $logFile -ErrorAction Stop
            }
            catch {
                continue
            }
            if (-not $content) { continue }

            foreach ($line in $content) {
                # Try to parse timestamp (format: YYYY-MM-DD HH:MM:SS.mmm or YYYY/MM/DD HH:MM:SS)
                $skipLine = $false
                if ($line.Length -ge 19) {
                    $tsStr = $line.Substring(0, 19)
                    [datetime]$lineTime = [datetime]::MinValue
                    $parsed = [datetime]::TryParseExact(
                        $tsStr,
                        "yyyy-MM-dd HH:mm:ss",
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [System.Globalization.DateTimeStyles]::None,
                        [ref]$lineTime
                    )
                    if (-not $parsed) {
                        [datetime]$lineTime = [datetime]::MinValue
                        $parsed = [datetime]::TryParseExact(
                            $tsStr,
                            "yyyy/MM/dd HH:mm:ss",
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::None,
                            [ref]$lineTime
                        )
                    }
                    if ($parsed -and $lineTime -lt $cutoff) {
                        $skipLine = $true
                    }
                }
                if ($skipLine) { continue }

                $upper = $line.ToUpper()

                if ($upper.Contains("CAPI EVENT SUCCESSFULLY COMPLETED")) {
                    $capiSuccess++
                }
                elseif ($upper.Contains("CAPI EVENT FAILED") -or $upper.Contains("CAPI REQUEST FAILED")) {
                    $null = $capiErrors.Add($line.Trim())
                }
                elseif ($upper.Contains("[ERROR]") -and $upper.Contains("HTTP REQUEST FAILED")) {
                    $null = $httpErrors.Add($line.Trim())
                }

                # Extract WinHTTP error codes (12xxx pattern)
                $codeMatch = [regex]::Match($line, '(?:error\s*(?:code)?[:=\s]*|WinHTTP\s*[:=\s]*)(\d{5})', 'IgnoreCase')
                if ($codeMatch.Success) {
                    $errCode = $codeMatch.Groups[1].Value
                    if ($errCode.StartsWith("12")) {
                        if ($winHttpCodes.ContainsKey($errCode)) {
                            $winHttpCodes[$errCode] = $winHttpCodes[$errCode] + 1
                        }
                        else {
                            $winHttpCodes[$errCode] = 1
                        }
                    }
                }
            }
        }

        Write-Both "`n  CAPI events (last 24h):"
        Write-Both "    Successful:  $capiSuccess"
        Write-Both "    Failed:      $($capiErrors.Count)"
        Write-Both "    HTTP errors: $($httpErrors.Count)"

        # WinHTTP error code summary with human-readable descriptions
        if ($winHttpCodes.Count -gt 0) {
            Write-Both "`n  WinHTTP error codes detected (last 24h):"
            $winHttpDescriptions = @{
                "12001" = "Out of handles"
                "12002" = "Timeout (server not responding)"
                "12005" = "Invalid URL"
                "12007" = "Name not resolved (DNS failure)"
                "12009" = "Invalid option"
                "12029" = "Cannot connect (server unreachable)"
                "12030" = "Connection aborted"
                "12031" = "Connection reset"
                "12038" = "Cert CN name mismatch"
                "12044" = "Client auth cert needed"
                "12045" = "Invalid CA"
                "12057" = "Proxy auth required"
                "12152" = "Invalid server response"
                "12175" = "SSL/TLS certificate error"
                "12178" = "Auto-proxy service error"
                "12180" = "Auto-detection failed (proxy)"
            }
            foreach ($codeKey in $winHttpCodes.Keys) {
                $desc = "Unknown"
                if ($winHttpDescriptions.ContainsKey($codeKey)) {
                    $desc = $winHttpDescriptions[$codeKey]
                }
                Write-Both "    $codeKey x$($winHttpCodes[$codeKey]): $desc"
            }
        }

        if ($capiErrors.Count -gt 0 -or $httpErrors.Count -gt 0) {
            Write-Both "`n  [WARN] CAPI errors detected in the last 24 hours:"
            $allErrors = New-Object System.Collections.ArrayList
            foreach ($e in $capiErrors) { $null = $allErrors.Add($e) }
            foreach ($e in $httpErrors) { $null = $allErrors.Add($e) }

            $showCount = $allErrors.Count
            if ($showCount -gt 20) {
                Write-Both "  (showing last 20 of $showCount errors)"
                $startIdx = $showCount - 20
                for ($i = $startIdx; $i -lt $showCount; $i++) {
                    Write-Both "    $($allErrors[$i])"
                }
            }
            else {
                foreach ($e in $allErrors) {
                    Write-Both "    $e"
                }
            }
        }
        else {
            Write-Both "`n  [OK] CAPI calls are healthy -- no errors in the last 24 hours."
        }
    }
}

# ---------------------------------------------------------------------------
# Step 5: Firewall Status
# ---------------------------------------------------------------------------
function Step-Firewall {
    Write-Both (Write-Banner "STEP 5 -- Firewall Status")

    Write-Both "`n  --- Windows Firewall Profiles ---"
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($prof in $profiles) {
            $state = "DISABLED"
            if ($prof.Enabled) { $state = "ENABLED" }
            Write-Both "  $($prof.Name): $state (DefaultInboundAction: $($prof.DefaultInboundAction))"
        }
    }
    catch {
        Write-Both "  (Get-NetFirewallProfile not available -- falling back to netsh)"
        $r = Get-SafeCommand -Command "netsh advfirewall show allprofiles state" -TimeoutSeconds 10
        if ($r.ExitCode -eq 0 -and $r.Output) {
            foreach ($line in $r.Output.Split("`n")) {
                Write-Both "  $line"
            }
        }
        else {
            Write-Both "  (netsh advfirewall also failed: $($r.Error))"
        }
    }

    # Check for Qualys-specific firewall rules
    Write-Both "`n  --- Qualys-related Firewall Rules ---"
    try {
        $fwRules = Get-NetFirewallRule -ErrorAction Stop
        $qualysRuleFound = $false
        foreach ($rule in $fwRules) {
            $dn = $rule.DisplayName
            if ($dn -and $dn.ToUpper().Contains("QUALYS")) {
                Write-Both "  $dn  Enabled=$($rule.Enabled)  Direction=$($rule.Direction)  Action=$($rule.Action)"
                $qualysRuleFound = $true
            }
        }
        if (-not $qualysRuleFound) {
            Write-Both "  (no Qualys-specific firewall rules found)"
        }
    }
    catch {
        Write-Both "  (Get-NetFirewallRule not available -- falling back to netsh)"
        $r = Get-SafeCommand -Command "netsh advfirewall firewall show rule name=all" -TimeoutSeconds 30
        if ($r.ExitCode -eq 0 -and $r.Output) {
            $qualysRuleFound = $false
            $ruleBlock = ""
            foreach ($line in $r.Output.Split("`n")) {
                $trimmed = $line.Trim()
                if ($trimmed -eq "" -or $trimmed.StartsWith("---")) {
                    if ($ruleBlock.ToUpper().Contains("QUALYS")) {
                        Write-Both $ruleBlock
                        $qualysRuleFound = $true
                    }
                    $ruleBlock = ""
                }
                else {
                    $ruleBlock = $ruleBlock + "`n  " + $trimmed
                }
            }
            # Check last block
            if ($ruleBlock.ToUpper().Contains("QUALYS")) {
                Write-Both $ruleBlock
                $qualysRuleFound = $true
            }
            if (-not $qualysRuleFound) {
                Write-Both "  (no Qualys-specific firewall rules found via netsh)"
            }
        }
        else {
            Write-Both "  (netsh firewall rule query also failed: $($r.Error))"
        }
    }
}

# ---------------------------------------------------------------------------
# Step 6: Agent Status
# ---------------------------------------------------------------------------
function Step-AgentStatus {
    Write-Both (Write-Banner "STEP 6 -- Qualys Cloud Agent Status")

    Write-Both "`n  --- Service Status ---"
    $svc = $null
    try {
        $svc = Get-Service -Name $AgentServiceName -ErrorAction Stop
        Write-Both "  Service Name:   $($svc.Name)"
        Write-Both "  Display Name:   $($svc.DisplayName)"
        Write-Both "  Status:         $($svc.Status)"
        Write-Both "  StartType:      $($svc.StartType)"
    }
    catch {
        Write-Both "  [WARN] Service '$AgentServiceName' not found."
        Write-Both "  Checking alternate names..."
        $altNames = @("QualysAgent", "qualys-cloud-agent", "QualysFIM")
        foreach ($altName in $altNames) {
            try {
                $altSvc = Get-Service -Name $altName -ErrorAction Stop
                Write-Both "  Found: $($altSvc.Name) -- Status: $($altSvc.Status)"
            }
            catch {
                # not found, skip
            }
        }
    }

    Write-Both "`n  --- Qualys Processes ---"
    $qualysProcs = Get-Process -ErrorAction SilentlyContinue
    $found = $false
    foreach ($proc in $qualysProcs) {
        $pname = $proc.ProcessName.ToUpper()
        if ($pname.Contains("QUALYS")) {
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            Write-Both "  PID=$($proc.Id)  Name=$($proc.ProcessName)  Mem=${memMB}MB  CPU=$($proc.CPU)s"
            $found = $true
        }
    }
    if (-not $found) {
        Write-Both "  (no Qualys processes running)"
    }

    Write-Both "`n  --- Agent Install Directory ---"
    if (Test-Path $AgentInstallDir) {
        $items = Get-ChildItem -Path $AgentInstallDir -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Write-Both "  $($item.Mode)  $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $($item.Name)"
        }
    }
    else {
        Write-Both "  [WARN] Agent install directory not found: $AgentInstallDir"
    }

    Write-Both "`n  --- Agent Data Directory ---"
    if (Test-Path $AgentDataDir) {
        $items = Get-ChildItem -Path $AgentDataDir -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Write-Both "  $($item.Mode)  $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $($item.Name)"
        }
    }
    else {
        Write-Both "  [WARN] Agent data directory not found: $AgentDataDir"
    }

    # Agent registry configuration
    Write-Both "`n  --- Agent Registry Configuration ---"
    $regKeys = @(
        "HKLM:\SOFTWARE\Qualys\QualysAgent",
        "HKLM:\SOFTWARE\Qualys\QualysAgent\Logs"
    )
    foreach ($regKey in $regKeys) {
        if (Test-Path $regKey) {
            Write-Both "  $regKey"
            try {
                $props = Get-ItemProperty -Path $regKey -ErrorAction Stop
                $propNames = $props.PSObject.Properties
                foreach ($prop in $propNames) {
                    $pn = $prop.Name
                    # Skip PS-internal properties
                    if ($pn -eq "PSPath" -or $pn -eq "PSParentPath" -or $pn -eq "PSChildName" -or $pn -eq "PSDrive" -or $pn -eq "PSProvider") {
                        continue
                    }
                    Write-Both "    $pn = $($prop.Value)"
                }
            }
            catch {
                Write-Both "    (could not read: $($_.Exception.Message))"
            }
        }
        else {
            Write-Both "  (not found: $regKey)"
        }
    }

    # Agent HostID and version
    Write-Both "`n  --- Agent Identity ---"
    $qualysRegRoot = "HKLM:\SOFTWARE\Qualys"
    if (Test-Path $qualysRegRoot) {
        try {
            $qProps = Get-ItemProperty -Path $qualysRegRoot -ErrorAction Stop
            if ($qProps.PSObject.Properties.Match("HostID").Count -gt 0) {
                Write-Both "  HostID:  $($qProps.HostID)"
            }
            else {
                Write-Both "  HostID:  (not set)"
            }
        }
        catch {
            Write-Both "  HostID:  (could not read: $($_.Exception.Message))"
        }
    }
    else {
        Write-Both "  HostID:  (registry key not found: $qualysRegRoot)"
    }

    # Agent executable version
    $agentExePaths = @(
        (Join-Path $AgentInstallDir "QualysCloudAgent.exe"),
        (Join-Path $AgentInstallDir "QualysAgent.exe")
    )
    $versionFound = $false
    foreach ($exePath in $agentExePaths) {
        if (Test-Path $exePath) {
            try {
                $fileInfo = Get-Item $exePath -ErrorAction Stop
                $ver = $fileInfo.VersionInfo.FileVersion
                Write-Both "  Agent Version:  $ver  ($exePath)"
                $versionFound = $true
                break
            }
            catch {
                Write-Both "  Agent Version:  (could not read version from $exePath)"
            }
        }
    }
    if (-not $versionFound) {
        Write-Both "  Agent Version:  (executable not found)"
    }

    # Proxy configuration
    Write-Both "`n  --- Agent Proxy Configuration ---"
    $proxyRegPath = "HKLM:\SOFTWARE\Qualys\QualysAgent"
    if (Test-Path $proxyRegPath) {
        try {
            $proxyProps = Get-ItemProperty -Path $proxyRegPath -ErrorAction Stop
            $proxyKeys = @("ProxyHost", "ProxyPort", "ProxyUser", "ProxyPAC", "ProxyWPAD", "ProxySetting")
            $proxyFound = $false
            foreach ($pk in $proxyKeys) {
                if ($proxyProps.PSObject.Properties.Match($pk).Count -gt 0) {
                    $val = $proxyProps.$pk
                    # Mask password values
                    if ($pk -eq "ProxyPass" -or $pk -eq "ProxyPassword") {
                        $val = "********"
                    }
                    Write-Both "  $pk = $val"
                    $proxyFound = $true
                }
            }
            if (-not $proxyFound) {
                Write-Both "  (no Qualys proxy settings configured in registry)"
            }
        }
        catch {
            Write-Both "  (could not read proxy config: $($_.Exception.Message))"
        }
    }
    else {
        Write-Both "  (agent registry key not found)"
    }

    # System WinHTTP proxy
    Write-Both "`n  --- System WinHTTP Proxy ---"
    $r = Get-SafeCommand -Command "netsh winhttp show proxy" -TimeoutSeconds 10
    if ($r.Output) {
        foreach ($line in $r.Output.Split("`n")) {
            Write-Both "  $line"
        }
    }
    else {
        Write-Both "  (could not query WinHTTP proxy: $($r.Error))"
    }

    # QualysProxy.exe registry-stored proxy configuration (read-only)
    # NOTE: QualysProxy.exe /d is DELETE (destructive) -- never call it.
    # Proxy settings are stored under HKLM:\SOFTWARE\Qualys\QualysAgent\Proxy
    Write-Both "`n  --- Qualys Agent Proxy Registry (detailed) ---"
    $proxySubPath = "HKLM:\SOFTWARE\Qualys\QualysAgent\Proxy"
    if (Test-Path $proxySubPath) {
        try {
            $pxProps = Get-ItemProperty -Path $proxySubPath -ErrorAction Stop
            $pxNames = $pxProps.PSObject.Properties
            foreach ($pxProp in $pxNames) {
                $pxn = $pxProp.Name
                if ($pxn -eq "PSPath" -or $pxn -eq "PSParentPath" -or $pxn -eq "PSChildName" -or $pxn -eq "PSDrive" -or $pxn -eq "PSProvider") {
                    continue
                }
                $pxVal = $pxProp.Value
                # Mask any password-like values
                $pxnUpper = $pxn.ToUpper()
                if ($pxnUpper.Contains("PASS") -or $pxnUpper.Contains("SECRET") -or $pxnUpper.Contains("CRED")) {
                    $pxVal = "********"
                }
                Write-Both "    $pxn = $pxVal"
            }
        }
        catch {
            Write-Both "  (could not read proxy subkey: $($_.Exception.Message))"
        }
    }
    else {
        Write-Both "  (no Proxy subkey found at $proxySubPath)"
    }

    # Also note QualysProxy.exe location for manual use
    $proxyExePaths = @(
        (Join-Path $AgentInstallDir "QualysProxy.exe"),
        "C:\Program Files\Qualys\QualysAgent\QualysProxy.exe",
        "C:\Program Files (x86)\QualysAgent\Qualys\QualysProxy.exe"
    )
    foreach ($pxPath in $proxyExePaths) {
        if (Test-Path $pxPath) {
            Write-Both "  QualysProxy.exe found at: $pxPath"
            Write-Both "  Manual: Run `"$pxPath`" (no args) to view current proxy config"
            break
        }
    }

    # Self-protection status
    Write-Both "`n  --- Agent Self-Protection Status ---"
    $spRegPath = "HKLM:\SOFTWARE\Qualys\QualysAgent"
    if (Test-Path $spRegPath) {
        try {
            $spProps = Get-ItemProperty -Path $spRegPath -ErrorAction Stop
            $spKeys = @("SelfProtection", "SelfProtectionEnabled", "SPEnabled")
            $spFound = $false
            foreach ($spk in $spKeys) {
                if ($spProps.PSObject.Properties.Match($spk).Count -gt 0) {
                    Write-Both "  $spk = $($spProps.$spk)"
                    $spFound = $true
                }
            }
            if (-not $spFound) {
                Write-Both "  (no self-protection keys found in registry -- may be managed by platform)"
            }
        }
        catch {
            Write-Both "  (could not read: $($_.Exception.Message))"
        }
    }

    # Check for QualysSPConfig.exe
    $spConfigPaths = @(
        (Join-Path $AgentInstallDir "QualysSPConfig.exe"),
        "C:\Program Files\Qualys\QualysAgent\QualysSPConfig.exe"
    )
    foreach ($spCfg in $spConfigPaths) {
        if (Test-Path $spCfg) {
            Write-Both "  Self-Protection config utility found: $spCfg"
            break
        }
    }
}

# ---------------------------------------------------------------------------
# Step 7: Agent Health Check Tool
# ---------------------------------------------------------------------------
function Step-AgentHealth {
    Write-Both (Write-Banner "STEP 7 -- Qualys Agent Health Check")

    if (-not $script:HealthCheckAvailable) {
        Write-Both "  [INFO] QualysAgentHealthCheck.exe not found."
        Write-Both "  Health Check Tool is bundled with Cloud Agent v5.5+."
        Write-Both "  Manual connectivity checks were run in Step 4 as fallback."
        return
    }

    $hcExe = $script:HealthCheckExe
    Write-Both "  Running health check (this may take a moment)..."

    $r = Get-SafeCommand -Command "`"$hcExe`"" -TimeoutSeconds 120
    if ($r.ExitCode -eq 0 -or $r.Output) {
        Write-Both ""
        foreach ($line in $r.Output.Split("`n")) {
            Write-Both "  $line"
        }
    }
    else {
        Write-Both "  [WARN] Health check returned no output."
        if ($r.Error) {
            Write-Both "  Error: $($r.Error)"
        }
    }

    # Check for HealthCheck output directory (JSON/text reports)
    $hcDir = Join-Path (Split-Path $hcExe -Parent) "HealthCheck"
    if (Test-Path $hcDir) {
        Write-Both "`n  --- Health Check Reports ---"
        $hcFiles = Get-ChildItem -Path $hcDir -ErrorAction SilentlyContinue
        foreach ($hcFile in $hcFiles) {
            Write-Both "  $($hcFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $($hcFile.Name)"
        }

        # Try to read the most recent JSON report
        $jsonFiles = New-Object System.Collections.ArrayList
        foreach ($hcFile in $hcFiles) {
            if ($hcFile.Extension -eq ".json") {
                $null = $jsonFiles.Add($hcFile)
            }
        }
        if ($jsonFiles.Count -gt 0) {
            # Sort by LastWriteTime descending, take newest
            $newestJson = $null
            foreach ($jf in $jsonFiles) {
                if ($null -eq $newestJson -or $jf.LastWriteTime -gt $newestJson.LastWriteTime) {
                    $newestJson = $jf
                }
            }
            if ($newestJson) {
                Write-Both "`n  --- Latest Health Check JSON: $($newestJson.Name) ---"
                try {
                    $jsonContent = Get-Content -Path $newestJson.FullName -Raw -ErrorAction Stop
                    # Limit output to avoid flooding the report
                    if ($jsonContent.Length -gt 5000) {
                        Write-Both "  (truncated to 5000 chars -- full report at $($newestJson.FullName))"
                        $jsonContent = $jsonContent.Substring(0, 5000)
                    }
                    foreach ($line in $jsonContent.Split("`n")) {
                        Write-Both "  $line"
                    }
                }
                catch {
                    Write-Both "  (could not read JSON report: $($_.Exception.Message))"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Step 8: Environment Checks (disk, time, certs)
# ---------------------------------------------------------------------------
function Step-Environment {
    Write-Both (Write-Banner "STEP 8 -- Environment Checks")

    # --- 8a: Disk Space ---
    Write-Both "`n  --- 8a: Disk Space ---"
    try {
        $disks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction Stop
        foreach ($disk in $disks) {
            # DriveType 3 = local disk
            if ($disk.DriveType -eq 3) {
                $totalGB = [math]::Round($disk.Size / 1GB, 1)
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
                $pctFree = 0
                if ($disk.Size -gt 0) {
                    $pctFree = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
                }
                $status = "[OK]"
                if ($pctFree -lt 5) { $status = "[CRIT]" }
                elseif ($pctFree -lt 10) { $status = "[WARN]" }
                Write-Both "  $status  $($disk.DeviceID)  ${freeGB}GB free / ${totalGB}GB total  (${pctFree}% free)"
            }
        }
    }
    catch {
        Write-Both "  (could not query disk space: $($_.Exception.Message))"
    }

    # Check ProgramData volume specifically if different from C:
    $pdDrive = $AgentDataDir.Substring(0, 2)
    if ($pdDrive -ne "C:") {
        Write-Both "  Note: Agent data is on $pdDrive (not C:) -- verify space above."
    }

    # --- 8b: System Time Sync ---
    Write-Both "`n  --- 8b: System Time Sync ---"
    $r = Get-SafeCommand -Command "w32tm /query /status" -TimeoutSeconds 10
    if ($r.ExitCode -eq 0 -and $r.Output) {
        foreach ($line in $r.Output.Split("`n")) {
            $trimmed = $line.Trim()
            if ($trimmed) {
                Write-Both "  $trimmed"
            }
        }
    }
    else {
        Write-Both "  (w32tm query failed -- checking system time manually)"
        $systemTime = Get-Date
        Write-Both "  System time: $($systemTime.ToString('yyyy-MM-dd HH:mm:ss')) (UTC offset: $($systemTime.ToString('zzz')))"
        Write-Both "  [INFO] Cannot verify NTP sync status. Ensure system clock is accurate"
        Write-Both "  for TLS certificate validation and CAPI communication."
    }

    # --- 8c: Certificate Store Validation ---
    if ($script:HealthCheckAvailable) {
        Write-Both "`n  --- 8c: Certificate Store Validation ---"
        Write-Both "  [INFO] Skipped -- covered by Health Check Tool (Step 7)."
        Write-Both "  The Health Check Tool validates all Qualys and patch certificates"
        Write-Both "  against the local trust store with installed/not-installed status."
    }
    else {
    Write-Both "`n  --- 8c: Certificate Store Validation (Qualys endpoints) ---"
    Write-Both "  Checking if Qualys TLS certificates chain to trusted roots..."
    Write-Both "  (Validates the SYSTEM account's trust store, not the current user's)"

    foreach ($qHost in $QualysHosts) {
        Write-Both "`n  Validating chain for: $qHost"
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectResult = $tcp.BeginConnect($qHost, 443, $null, $null)
            $waited = $connectResult.AsyncWaitHandle.WaitOne(10000, $false)
            if (-not $waited -or -not $tcp.Connected) {
                Write-Both "  [SKIP] Could not connect to ${qHost}:443 (timeout)"
                try { $tcp.Close() } catch {}
                continue
            }
            $tcp.EndConnect($connectResult)

            # Use a callback to capture chain validation details
            $chainErrors = New-Object System.Collections.ArrayList
            $callback = [System.Net.Security.RemoteCertificateValidationCallback]{
                param($sender, $certificate, $chain, $sslPolicyErrors)
                if ($sslPolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None) {
                    foreach ($status in $chain.ChainStatus) {
                        $null = $chainErrors.Add($status.StatusInformation.Trim())
                    }
                }
                return $true  # Accept anyway so we can inspect the chain
            }

            $sslStream = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
            $sslStream.AuthenticateAsClient($qHost)

            $cert = $sslStream.RemoteCertificate
            $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)

            # Build and validate the chain
            $chainObj = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chainObj.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $chainBuilt = $chainObj.Build($cert2)

            if ($chainBuilt -and $chainObj.ChainStatus.Length -eq 0) {
                Write-Both "  [OK]   $qHost -- certificate chain is trusted"
            }
            else {
                Write-Both "  [WARN] $qHost -- certificate chain issues:"
                foreach ($cs in $chainObj.ChainStatus) {
                    Write-Both "    Status: $($cs.Status) -- $($cs.StatusInformation.Trim())"
                }
            }

            # Show chain elements
            Write-Both "  Chain:"
            for ($i = 0; $i -lt $chainObj.ChainElements.Count; $i++) {
                $elem = $chainObj.ChainElements[$i]
                Write-Both "    [$i] $($elem.Certificate.Subject)"
            }

            $sslStream.Close()
            $tcp.Close()
        }
        catch {
            Write-Both "  [FAIL] $qHost -- $($_.Exception.Message)"
        }
    }

    } # end else (no health check -- manual cert validation)
}

# ---------------------------------------------------------------------------
# Step 9: Agent Logs
# ---------------------------------------------------------------------------
function Step-AgentLogs {
    Write-Both (Write-Banner "STEP 9 -- Agent Logs")

    # Windows Event Log entries for Qualys
    Write-Both "`n  --- Application Event Log (Qualys, last 50) ---"
    try {
        $events = Get-EventLog -LogName Application -Newest 200 -ErrorAction Stop
        $qualysEvents = New-Object System.Collections.ArrayList
        foreach ($evt in $events) {
            if ($evt.Source -and $evt.Source.ToUpper().Contains("QUALYS")) {
                $null = $qualysEvents.Add($evt)
            }
        }
        if ($qualysEvents.Count -gt 0) {
            $showCount = $qualysEvents.Count
            if ($showCount -gt 50) { $showCount = 50 }
            for ($i = 0; $i -lt $showCount; $i++) {
                $evt = $qualysEvents[$i]
                $ts = $evt.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Both "  $ts [$($evt.EntryType)] $($evt.Source): $($evt.Message)"
            }
        }
        else {
            Write-Both "  (no Qualys entries in Application log)"
        }
    }
    catch {
        Write-Both "  (could not read Application event log: $($_.Exception.Message))"
    }

    # Agent log directory listing
    Write-Both "`n  --- Agent Log Directories ---"
    $logDirsToCheck = @($AgentDataDir, $AgentLogDir, $AgentLogFallback)
    foreach ($ld in $logDirsToCheck) {
        if (Test-Path $ld) {
            Write-Both "  Directory: $ld"
            $logItems = Get-ChildItem -Path $ld -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $logItems) {
                if (-not $item.PSIsContainer) {
                    $sizeMB = [math]::Round($item.Length / 1MB, 2)
                    Write-Both "  $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  ${sizeMB}MB  $($item.FullName)"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Optional: Collect Logs
# ---------------------------------------------------------------------------
function Step-CollectLogs {
    Write-Both (Write-Banner "COLLECT AGENT LOGS ZIP")

    $existingPaths = New-Object System.Collections.ArrayList
    $missingPaths = New-Object System.Collections.ArrayList

    foreach ($p in $LogPaths) {
        if (Test-Path $p) {
            $null = $existingPaths.Add($p)
        }
        else {
            $null = $missingPaths.Add($p)
        }
    }

    if ($missingPaths.Count -gt 0) {
        Write-Both "  Paths not found (skipped):"
        foreach ($m in $missingPaths) {
            Write-Both "    - $m"
        }
    }

    if ($existingPaths.Count -eq 0) {
        Write-Both "  [WARN] No log paths found."
        return
    }

    # Stage files to a temp directory then compress
    $stageDir = Join-Path $env:TEMP ("qualys_logs_" + $Timestamp)
    $null = New-Item -ItemType Directory -Path $stageDir -Force

    foreach ($srcPath in $existingPaths) {
        $destName = $srcPath.Replace(":", "").Replace("\", "_")
        $destPath = Join-Path $stageDir $destName
        try {
            if (Test-Path $srcPath -PathType Container) {
                Copy-Item -Path $srcPath -Destination $destPath -Recurse -Force -ErrorAction Stop
            }
            else {
                $null = New-Item -ItemType Directory -Path $destPath -Force
                Copy-Item -Path $srcPath -Destination $destPath -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Both "  [WARN] Could not copy: $srcPath -- $($_.Exception.Message)"
        }
    }

    try {
        Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $LogZip -Force
        $zipSize = [math]::Round((Get-Item $LogZip).Length / 1MB, 1)
        Write-Both "  [OK] $LogZip  (${zipSize} MB)"
    }
    catch {
        Write-Both "  [FAIL] Compress-Archive error: $($_.Exception.Message)"
    }

    # Cleanup staging
    Remove-Item -Path $stageDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Optional: Agent Service Action
# ---------------------------------------------------------------------------
function Step-AgentAction {
    param([string]$Action)

    Write-Both (Write-Banner "AGENT ACTION -- $($Action.ToUpper())")

    $svcName = $AgentServiceName
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
    }
    catch {
        Write-Both "  [FAIL] Service '$svcName' not found."
        return
    }

    if ($Action -eq "stop") {
        Write-Both "  Stopping $svcName..."
        try {
            Stop-Service -Name $svcName -Force -ErrorAction Stop
            Write-Both "  [OK] Agent stopped."
        }
        catch {
            Write-Both "  [FAIL] Stop failed: $($_.Exception.Message)"
        }
    }
    elseif ($Action -eq "start") {
        Write-Both "  Starting $svcName..."
        try {
            Start-Service -Name $svcName -ErrorAction Stop
            Write-Both "  [OK] Agent started."
        }
        catch {
            Write-Both "  [FAIL] Start failed: $($_.Exception.Message)"
        }
    }
    elseif ($Action -eq "restart") {
        Write-Both "  Restarting $svcName..."
        try {
            Restart-Service -Name $svcName -Force -ErrorAction Stop
            Write-Both "  [OK] Agent restarted."
        }
        catch {
            Write-Both "  [FAIL] Restart failed: $($_.Exception.Message)"
        }
    }

    # Post-action verification
    Start-Sleep -Seconds 5
    Write-Both "`n  --- Post-$Action status ---"
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        Write-Both "  Status: $($svc.Status)"
    }
    catch {
        Write-Both "  (could not query service status)"
    }

    Write-Both "`n  --- Post-$Action processes ---"
    $qualysProcs = Get-Process -ErrorAction SilentlyContinue
    $found = $false
    foreach ($proc in $qualysProcs) {
        if ($proc.ProcessName.ToUpper().Contains("QUALYS")) {
            Write-Both "  PID=$($proc.Id)  Name=$($proc.ProcessName)"
            $found = $true
        }
    }
    if (-not $found) {
        Write-Both "  (no Qualys processes running)"
    }
}

# ---------------------------------------------------------------------------
# Trace Diagnostics (optional)
# ---------------------------------------------------------------------------
function Step-TraceDiag {
    param([int]$WaitMin)

    Write-Both (Write-Banner "TRACE DIAGNOSTICS -- Qualys Support Escalation")

    # --- Helper: read current TraceLevel from registry ---
    # Per Qualys docs: HKLM\SOFTWARE\Qualys\QualysAgent\Logs\TraceLevel (DWORD)
    # Values: 0=off, 1=error, 6=debug/trace
    function Get-CurrentLogLevel {
        if (-not (Test-Path $AgentRegPath)) { return $null }
        try {
            $props = Get-ItemProperty -Path $AgentRegPath -ErrorAction Stop
            if ($props.PSObject.Properties.Match("TraceLevel").Count -gt 0) {
                return [int]$props.TraceLevel
            }
        }
        catch {}
        return $null
    }

    # --- Helper: set TraceLevel in registry ---
    function Set-LogLevel {
        param([int]$Level)
        try {
            if (-not (Test-Path $AgentRegPath)) {
                $null = New-Item -Path $AgentRegPath -Force
            }
            Set-ItemProperty -Path $AgentRegPath -Name "TraceLevel" -Value $Level -Type DWord -Force
            return $true
        }
        catch {
            Write-Both "  [WARN] Registry write failed: $($_.Exception.Message)"
            return $false
        }
    }

    # --- Helper: check if agent service is running ---
    function Test-AgentRunning {
        try {
            $svc = Get-Service -Name $AgentServiceName -ErrorAction Stop
            if ($svc.Status -eq "Running") { return $true }
        }
        catch {}
        return $false
    }

    # =========================================================================
    # 1/8: Verify agent is running
    # =========================================================================
    Write-Both "`n  [1/8] Checking Qualys Cloud Agent service health..."

    if (Test-AgentRunning) {
        Write-Both "  [OK] Agent service is running."
    }
    else {
        Write-Both "  [WARN] Agent is not running."

        for ($attempt = 1; $attempt -le 2; $attempt++) {
            Write-Host "`n  Agent is not running. Attempt $attempt/2."
            Write-Host "  [S]tart agent  |  [Q]uit"
            $choice = Read-Host "  Enter choice"
            $choice = $choice.Trim().ToLower()

            if ($choice -eq "s") {
                Write-Both "  User chose: start agent."
                try {
                    Start-Service -Name $AgentServiceName -ErrorAction Stop
                    Start-Sleep -Seconds 10
                }
                catch {
                    Write-Both "  [WARN] Start failed: $($_.Exception.Message)"
                }

                if (Test-AgentRunning) {
                    Write-Both "  [OK] Agent is running."
                    break
                }
                else {
                    Write-Both "  [FAIL] Agent still not running."
                }
            }
            elseif ($choice -eq "q") {
                Write-Both "  User chose: quit."
                Write-Both "  Exiting trace diagnostics."
                return
            }
            else {
                Write-Both "  Unrecognized choice. Exiting."
                return
            }

            if ($attempt -eq 2) {
                Write-Host "`n  Agent still not running."
                Write-Host "  [C]ontinue anyway  |  [Q]uit"
                $choice2 = Read-Host "  Enter choice"
                if ($choice2.Trim().ToLower() -eq "q") {
                    Write-Both "  User chose: quit."
                    return
                }
                Write-Both "  User chose: continue without running agent."
            }
        }
    }

    # =========================================================================
    # 2/8: Set LogLevel=5 (Trace)
    # =========================================================================
    Write-Both "`n  [2/8] Setting LogLevel=5 (Trace)..."

    $currentLevel = Get-CurrentLogLevel
    if ($null -ne $currentLevel) {
        Write-Both "  Current LogLevel: $currentLevel"
    }

    if ($currentLevel -eq 5) {
        Write-Both "  [OK] LogLevel is already 5 (Trace) -- skipping."
    }
    elseif ($currentLevel -eq 6) {
        Write-Both "  [OK] TraceLevel is already 6 (Debug) -- sufficient for trace."
    }
    else {
        # Per Qualys docs: set TraceLevel=6 in registry, then restart agent
        $setSuccess = $false

        for ($attempt = 1; $attempt -le 3; $attempt++) {
            Write-Both "  Attempt ${attempt}/3: Setting TraceLevel=6 via registry..."

            $writeOk = Set-LogLevel -Level 6
            if (-not $writeOk) {
                Write-Both "  [WARN] Could not write registry."
            }

            # Restart agent so new TraceLevel takes effect
            Write-Both "  Restarting agent to apply TraceLevel..."
            try {
                Restart-Service -Name $AgentServiceName -Force -ErrorAction Stop
                Start-Sleep -Seconds 10
            }
            catch {
                Write-Both "  [WARN] Restart failed: $($_.Exception.Message)"
            }

            $verifyLevel = Get-CurrentLogLevel
            if ($verifyLevel -eq 6) {
                Write-Both "  [OK] TraceLevel verified at 6 (Debug/Trace)."
                $setSuccess = $true
                break
            }

            Write-Both "  [WARN] Verification failed (current: $verifyLevel)."
        }

        if (-not $setSuccess) {
            Write-Both "  [FAIL] Could not set TraceLevel after all attempts."
            Write-Both "  Manual: Set HKLM\SOFTWARE\Qualys\QualysAgent\Logs\TraceLevel = 6 (DWORD)"
            Write-Host "`n  [C]ontinue anyway  |  [Q]uit"
            $choice = Read-Host "  Enter choice"
            if ($choice.Trim().ToLower() -eq "q") {
                Write-Both "  User chose: quit."
                return
            }
            Write-Both "  User chose: continue."
        }
    }

    # =========================================================================
    # 3/8: Trigger on-demand VM scan
    # =========================================================================
    Write-Both "`n  [3/8] Triggering on-demand VM scan..."

    $scanTriggered = $false

    # Search for agent control utilities in known locations
    $ctlSearchPaths = @(
        (Join-Path $AgentInstallDir "QualysAgentCtl.exe"),
        (Join-Path $AgentInstallDir "cloudagentctl.bat"),
        (Join-Path $AgentDataDir "QualysAgentCtl.exe"),
        "C:\Program Files\Qualys\QualysAgent\QualysAgentCtl.exe",
        "C:\Program Files (x86)\QualysAgent\Qualys\QualysAgentCtl.exe",
        "C:\Program Files (x86)\QualysAgent\QualysAgentCtl.exe"
    )

    $ctlFound = $null
    foreach ($ctlPath in $ctlSearchPaths) {
        if (Test-Path $ctlPath) {
            $ctlFound = $ctlPath
            break
        }
    }

    if ($ctlFound) {
        Write-Both "  Using: $ctlFound"
        $r = Get-SafeCommand -Command "`"$ctlFound`" action=demand type=VM" -TimeoutSeconds 120
        if ($r.ExitCode -eq 0 -and -not $r.Output.ToUpper().Contains("NOT RUNNING")) {
            Write-Both "  [OK] On-demand VM scan triggered."
            $scanTriggered = $true
        }
        else {
            Write-Both "  [WARN] Scan issue: $($r.Output) $($r.Error)"
        }
    }
    else {
        Write-Both "  [WARN] No agent control utility found in any known location."
        foreach ($sp in $ctlSearchPaths) {
            Write-Both "    Checked: $sp"
        }
        Write-Both "  Skipping on-demand scan trigger."
    }

    # =========================================================================
    # 4/8: Wait with progress bar
    # =========================================================================
    if ($scanTriggered) {
        $totalSeconds = $WaitMin * 60
        $endTime = (Get-Date).AddSeconds($totalSeconds)
        $etaStr = $endTime.ToString("HH:mm:ss")
        Write-Both "`n  [4/8] Waiting $WaitMin minutes for on-demand scan..."
        Write-Both "         Estimated completion: $etaStr"

        for ($elapsed = 0; $elapsed -le $totalSeconds; $elapsed++) {
            $remaining = $totalSeconds - $elapsed
            $mins = [math]::Floor($remaining / 60)
            $secs = $remaining % 60
            $pct = 0
            if ($totalSeconds -gt 0) { $pct = [math]::Round(($elapsed / $totalSeconds) * 100) }
            $barWidth = 30
            $filled = [math]::Floor($barWidth * $elapsed / $totalSeconds)
            $empty = $barWidth - $filled
            $barFull = "#" * $filled
            $barEmpty = "-" * $empty
            $minsStr = $mins.ToString("D2")
            $secsStr = $secs.ToString("D2")

            Write-Host -NoNewline ("`r  [{0}{1}]  {2}:{3}  [{4}%]" -f $barFull, $barEmpty, $minsStr, $secsStr, $pct)

            if ($elapsed -lt $totalSeconds) {
                Start-Sleep -Seconds 1
            }
        }
        Write-Host ("`r  [{0}]  00:00  [100%]  Done!          " -f ("#" * 30))
        Write-Both "  [OK] $WaitMin minute wait complete."
    }
    else {
        Write-Both "`n  [4/8] Skipping wait -- on-demand scan was not triggered."
    }

    # =========================================================================
    # 5/8: Extended diagnostics
    # =========================================================================
    Write-Both "`n  [5/8] Collecting extended agent diagnostics..."

    Write-Both "`n  --- Service Status ---"
    try {
        $svc = Get-Service -Name $AgentServiceName -ErrorAction Stop
        Write-Both "  $($svc.Name): $($svc.Status)"
    }
    catch {
        Write-Both "  (service not found)"
    }

    Write-Both "`n  --- Agent Registry Config ---"
    $traceDiagRegKeys = @(
        "HKLM:\SOFTWARE\Qualys\QualysAgent",
        "HKLM:\SOFTWARE\Qualys\QualysAgent\Logs"
    )
    foreach ($rk in $traceDiagRegKeys) {
        if (Test-Path $rk) {
            Write-Both "  $rk"
            try {
                $rProps = Get-ItemProperty -Path $rk -ErrorAction Stop
                $rNames = $rProps.PSObject.Properties
                foreach ($rp in $rNames) {
                    $rpn = $rp.Name
                    if ($rpn -eq "PSPath" -or $rpn -eq "PSParentPath" -or $rpn -eq "PSChildName" -or $rpn -eq "PSDrive" -or $rpn -eq "PSProvider") {
                        continue
                    }
                    Write-Both "    $rpn = $($rp.Value)"
                }
            }
            catch {
                Write-Both "    (could not read)"
            }
        }
    }

    Write-Both "`n  --- whoami ---"
    Write-Both "  $(whoami)"

    Write-Both "`n  --- Qualys Processes ---"
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($proc in $procs) {
        if ($proc.ProcessName.ToUpper().Contains("QUALYS")) {
            Write-Both "  PID=$($proc.Id)  Name=$($proc.ProcessName)  CPU=$($proc.CPU)s"
        }
    }

    Write-Both "`n  --- Local Admin Check ---"
    $r = Get-SafeCommand -Command "net localgroup Administrators" -TimeoutSeconds 10
    foreach ($line in $r.Output.Split("`n")) {
        Write-Both "  $line"
    }

    Write-Both "`n  --- System Events (last 20 errors) ---"
    try {
        $sysEvents = Get-EventLog -LogName System -EntryType Error -Newest 20 -ErrorAction Stop
        foreach ($evt in $sysEvents) {
            $ts = $evt.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Both "  $ts $($evt.Source): $($evt.Message)"
        }
    }
    catch {
        Write-Both "  (could not read System event log)"
    }

    # =========================================================================
    # 6/8: Recently modified files
    # =========================================================================
    Write-Both "`n  [6/8] Recently modified agent files..."
    $searchDirs = @($AgentInstallDir, $AgentDataDir, $AgentLogFallback)
    $recentCutoff = (Get-Date).AddMinutes(-($WaitMin + 5))
    foreach ($sd in $searchDirs) {
        if (Test-Path $sd) {
            Write-Both "`n  --- $sd ---"
            $recentFiles = Get-ChildItem -Path $sd -Recurse -File -ErrorAction SilentlyContinue
            foreach ($rf in $recentFiles) {
                if ($rf.LastWriteTime -gt $recentCutoff) {
                    $sizeMB = [math]::Round($rf.Length / 1MB, 2)
                    Write-Both "  $($rf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))  ${sizeMB}MB  $($rf.FullName)"
                }
            }
        }
    }

    # =========================================================================
    # 7/8: Reset LogLevel=1
    # =========================================================================
    Write-Both "`n  [7/8] Resetting TraceLevel to default..."
    $currentLevel = Get-CurrentLogLevel
    if ($null -eq $currentLevel) {
        Write-Both "  [OK] TraceLevel registry key not set -- already at default."
    }
    elseif ($currentLevel -le 1) {
        Write-Both "  [OK] TraceLevel is already at default ($currentLevel) -- skipping."
    }
    else {
        # Remove the TraceLevel value to revert to default behavior
        try {
            Remove-ItemProperty -Path $AgentRegPath -Name "TraceLevel" -Force -ErrorAction Stop
            Write-Both "  Removed TraceLevel registry value."
        }
        catch {
            # Fall back to setting it to 0
            $null = Set-LogLevel -Level 0
        }

        # Restart agent to pick up the change
        Write-Both "  Restarting agent to apply default TraceLevel..."
        try {
            Restart-Service -Name $AgentServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 5
            Write-Both "  [OK] Agent restarted with default TraceLevel."
        }
        catch {
            Write-Both "  [WARN] Restart failed: $($_.Exception.Message)"
            Write-Both "  Manual: Remove HKLM\SOFTWARE\Qualys\QualysAgent\Logs\TraceLevel and restart service"
        }
    }

    # =========================================================================
    # 8/8: Done
    # =========================================================================
    Write-Both "`n  [8/8] Trace diagnostics complete."
    Write-Both "  Log collection will follow (-TraceDiag implies -CollectLogs)."
}


# ============================================================================
# MAIN
# ============================================================================

# Validate administrator
if (-not (Test-Administrator)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'."
    exit 1
}

# --- Handle -Cleanup: remove previous output files and exit ---
if ($Cleanup) {
    Write-Host ""
    Write-Host "  Cleaning up previous troubleshooting files in $OutputDir..."
    Write-Host ""

    $patterns = @(
        (Join-Path $OutputDir "qualys_troubleshoot_*.txt"),
        (Join-Path $OutputDir "Cloud_Agent_Logs_*.zip")
    )
    $totalRemoved = 0

    foreach ($pattern in $patterns) {
        $cleanupFiles = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
        foreach ($f in $cleanupFiles) {
            try {
                Remove-Item -Path $f.FullName -Force -ErrorAction Stop
                Write-Host "  Removed: $($f.FullName)"
                $totalRemoved++
            }
            catch {
                Write-Host "  [WARN] Could not remove $($f.FullName): $($_.Exception.Message)"
            }
        }
    }

    if ($totalRemoved -eq 0) {
        Write-Host "  No files found to clean up."
    }
    else {
        Write-Host ""
        Write-Host "  [OK] Removed $totalRemoved file(s)." -ForegroundColor Green
    }
    Write-Host ""
    exit 0
}

# Validate mutually exclusive service flags
$actionCount = 0
if ($Stop)    { $actionCount++ }
if ($Start)   { $actionCount++ }
if ($Restart) { $actionCount++ }
if ($actionCount -gt 1) {
    Write-Host "[ERROR] Only one of -Stop, -Start, -Restart may be specified." -ForegroundColor Red
    exit 1
}

# TraceDiag implies CollectLogs
if ($TraceDiag) { $CollectLogs = $true }

# Determine agent action
$agentAction = $null
if ($Stop)    { $agentAction = "stop" }
if ($Start)   { $agentAction = "start" }
if ($Restart) { $agentAction = "restart" }

# Build mode string
$flagList = New-Object System.Collections.ArrayList
if ($TraceDiag) { $null = $flagList.Add("trace-diag (wait ${WaitMinutes}min)") }
if ($agentAction) { $null = $flagList.Add($agentAction) }
if ($CollectLogs -and -not $TraceDiag) { $null = $flagList.Add("collect-logs") }

$mode = "diagnostics only"
if ($flagList.Count -gt 0) {
    $mode = "diagnostics + " + ($flagList -join ", ")
}

Clear-Host

$startTime = Get-Date

Write-Host ""
Write-Host ("=" * 72)
Write-Host "  Qualys Cloud Agent Troubleshooting Script  v1.6.0"
Write-Host "  Host:    $env:COMPUTERNAME"
Write-Host "  Date:    $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "  Mode:    $mode"
Write-Host "  Report:  $ReportFile"
Write-Host ("=" * 72)
Write-Host ""

# Initialize report file with shared StreamWriter for clean ASCII
# This writer stays open for the entire script run (closed in finally block)
$script:ReportWriter = New-Object System.IO.StreamWriter($ReportFile, $false, [System.Text.Encoding]::ASCII)
$script:ReportWriter.WriteLine("Qualys Cloud Agent Troubleshooting Report")
$script:ReportWriter.WriteLine("Generated: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))")
$script:ReportWriter.WriteLine("Host:      $env:COMPUTERNAME")
$script:ReportWriter.WriteLine("Mode:      $mode")
$script:ReportWriter.Flush()

# Run diagnostic steps inside try/finally to ensure writer is closed
try {

Step-SystemInfo        # 1
Step-DNS               # 2
Step-Network           # 3
Step-Connectivity      # 4 (Platform Comms)
Step-Firewall          # 5
Step-AgentStatus       # 6
Step-AgentHealth       # 7
Step-Environment       # 8
Step-AgentLogs         # 9

if ($TraceDiag) {
    Step-TraceDiag -WaitMin $WaitMinutes
}

if ($CollectLogs) {
    Step-CollectLogs
}

if ($agentAction) {
    Step-AgentAction -Action $agentAction
}

# --- Summary ---
$ScriptTimer.Stop()
$elapsed = $ScriptTimer.Elapsed.TotalSeconds

Write-Both (Write-Banner "SUMMARY")
Write-Both "  Report:       $ReportFile"
if ($CollectLogs -and (Test-Path $LogZip)) {
    $zipSize = [math]::Round((Get-Item $LogZip).Length / 1MB, 1)
    Write-Both "  Log archive:  $LogZip  (${zipSize} MB)"
}
if ($agentAction) {
    Write-Both "  Action:       $agentAction"
}
$elapsedStr = [math]::Round($elapsed, 1)
Write-Both "  Duration:     ${elapsedStr}s"
Write-Both ""
Write-Both "  Report saved to: $ReportFile"
if ($CollectLogs -and (Test-Path $LogZip)) {
    Write-Both "  Log archive:     $LogZip"
}
Write-Both ""
Write-Both "  --- Cleanup (after retrieving files) ---"
Write-Both "  .\qualys_agent_troubleshoot.ps1 -Cleanup"

Write-Host ""
Write-Host "  Done. Report: $ReportFile" -ForegroundColor Green
Write-Host ""

} # end try
finally {
    # Close the shared report writer
    if ($script:ReportWriter) {
        $script:ReportWriter.Close()
        $script:ReportWriter = $null
    }
}