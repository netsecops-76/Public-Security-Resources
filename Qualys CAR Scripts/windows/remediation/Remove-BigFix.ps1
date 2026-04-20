<#
.SYNOPSIS
    Audits or removes IBM/HCL BigFix client software and all associated
    artifacts from a Windows host. Deployed via Qualys CAR using UI-defined
    POSITIONAL parameters.

.DESCRIPTION
    By default this script runs in AUDIT MODE only. It discovers BigFix
    services, processes, installed products, filesystem directories,
    registry keys, scheduled tasks, and firewall rules, then reports what
    was found and what would be uninstalled. No changes are made in audit
    mode.

    Run with RunMode=Enforce to invoke the full removal workflow: stop
    services, kill processes, uninstall products, remove filesystem
    artifacts, registry keys, scheduled tasks, and firewall rules.

# ==============================================================================
# CAR UI PARAMETERS (define on Script Details page in this EXACT order):
# ==============================================================================
#
#   Position 1:  RunMode
#     Type:      String
#     Required:  No
#     Default:   Audit
#     Allowed:   Audit | Enforce
#     Purpose:   Audit-first. "Enforce" performs the destructive uninstall
#                + cleanup workflow. Anything except "Enforce" is treated
#                as audit.
#
#   Position 2:  CleanupOnly
#     Type:      String
#     Required:  No
#     Default:   No
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off (case-insensitive)
#     Purpose:   (applies only with RunMode=Enforce) Skip the MSI/EXE
#                uninstaller phase; only remove filesystem, registry,
#                task, and firewall artifacts.
#
#   Position 3:  UseBESRemoveIfFound
#     Type:      String
#     Required:  No
#     Default:   No
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off (case-insensitive)
#     Purpose:   (applies only with RunMode=Enforce) After MSI/EXE
#                uninstall, also run BESRemove.exe if present in standard
#                locations.
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Go to: Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details tab:
#        Name:        Remove BigFix (Windows)
#        Description: Audit or uninstall the BigFix client.
#        Platform:    Windows
#        Interpreter: PowerShell
#        Upload:      Remove-BigFix.ps1 from this repo
#   4. Parameters tab (ORDER MATTERS - positional):
#        Add parameter: RunMode              (String, Optional, default "Audit")
#        Add parameter: CleanupOnly          (String, Optional, default "No")
#        Add parameter: UseBESRemoveIfFound  (String, Optional, default "No")
#   5. Save. Run the job first with RunMode=Audit against a pilot asset to
#      review what would be removed before escalating to Enforce.
#   6. Runtime log and output are captured by the Qualys Cloud Agent.
#
# CLI INVOCATION (local testing):
#   .\Remove-BigFix.ps1                                   # pure audit
#   .\Remove-BigFix.ps1 Enforce No No                     # full removal
#   .\Remove-BigFix.ps1 Enforce Yes No                    # only cleanup artifacts
#   .\Remove-BigFix.ps1 Enforce No Yes                    # removal + BESRemove.exe
#
# CAR INVOKES EQUIVALENT TO:
#   powershell.exe -ExecutionPolicy Bypass -File Remove-BigFix.ps1 `
#                  "<RunMode>" "<CleanupOnly>" "<UseBESRemoveIfFound>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional params win. If empty, script checks $env:RunMode,
#   $env:CleanupOnly, $env:UseBESRemoveIfFound. Defaults last.
#   The legacy -U switch is still accepted for backward compatibility
#   with scripts that invoke this tool by the old name.
#
# ==============================================================================

.NOTES
    Author:      Brian Canaday
    Team:        netsecops-76
    Version:     3.0.0
    Created:     2026-04-03
    Script:      Remove-BigFix.ps1

    Changelog:
        3.0.0 - 2026-04-20 - CAR parameterization refactor. Switches to
                              positional string params (RunMode,
                              CleanupOnly, UseBESRemoveIfFound) consumable
                              by Qualys CAR UI. Dual-invocation support:
                              positional first, $env fallback, defaults
                              last. Legacy -U switch preserved for
                              backward compatibility. ASCII-only log
                              output. No $var = if() assignments.
        2.0.0 - 2026-04-03 - Added audit-only default mode. Full workflow
                              now requires -U switch. Audit report details
                              services, processes, products, dirs, reg
                              keys, tasks, and firewall rules with full
                              paths. No system impact without -U.
        1.0.0 - 2026-04-03 - Initial release. PS5.1 compliant, CAR-ready.

    Requirements:
        Windows PowerShell 5.1, Local Administrator or SYSTEM privileges.
        No interactive prompts; safe for CAR/remote deployment.

    Exit Codes:
        0  = Success (audit: nothing found -or- removal: no components remain)
        1  = Completed with warnings or residual components detected
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$RunMode = '',

    [Parameter(Position=1)]
    [string]$CleanupOnly = '',

    [Parameter(Position=2)]
    [string]$UseBESRemoveIfFound = '',

    # Legacy switch retained for backward compatibility with older CAR jobs
    # or local test scripts that invoke `Remove-BigFix.ps1 -U`. When set,
    # it forces RunMode=Enforce if the positional param is empty.
    [switch]$U
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# TRUTHY CONVERSION HELPER
# ---------------------------------------------------------------------------
function ConvertTo-CarBool {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().ToLowerInvariant()
    switch ($v) {
        'yes'   { return $true }
        'y'     { return $true }
        'true'  { return $true }
        't'     { return $true }
        '1'     { return $true }
        'on'    { return $true }
        'no'    { return $false }
        'n'     { return $false }
        'false' { return $false }
        'f'     { return $false }
        '0'     { return $false }
        'off'   { return $false }
        default {
            Write-Host ("    [WARN]  Unrecognized truthy value '{0}'; treating as false." -f $Value) -ForegroundColor Yellow
            return $false
        }
    }
}

# ---------------------------------------------------------------------------
# PARAMETER RESOLUTION: positional first, env fallback, legacy switch, defaults.
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($RunMode))             { $RunMode             = $env:RunMode }
if ([string]::IsNullOrWhiteSpace($CleanupOnly))         { $CleanupOnly         = $env:CleanupOnly }
if ([string]::IsNullOrWhiteSpace($UseBESRemoveIfFound)) { $UseBESRemoveIfFound = $env:UseBESRemoveIfFound }

# Legacy -U switch -> RunMode=Enforce (only if RunMode still empty)
if ($U -and [string]::IsNullOrWhiteSpace($RunMode)) { $RunMode = 'Enforce' }

# Defaults
if ([string]::IsNullOrWhiteSpace($RunMode)) { $RunMode = 'Audit' }

$IsEnforce        = ($RunMode.Trim().ToLowerInvariant() -eq 'enforce')
$CleanupOnlyBool  = ConvertTo-CarBool $CleanupOnly
$UseBESRemoveBool = ConvertTo-CarBool $UseBESRemoveIfFound

# ---------------------------------------------------------------------------
# RUNTIME BANNER
# ---------------------------------------------------------------------------
Clear-Host
$ScriptVersion  = '3.0.0'
$Stopwatch      = [System.Diagnostics.Stopwatch]::StartNew()
$StartTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$ScriptHost     = $env:COMPUTERNAME
$Mode           = 'AUDIT (read-only)'
if ($IsEnforce) { $Mode = 'ENFORCE (uninstall + cleanup)' }
$LogPath        = Join-Path $env:TEMP ('Remove-BigFix_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

Write-Host ('=' * 66) -ForegroundColor Cyan
Write-Host '  Remove-BigFix.ps1' -ForegroundColor Cyan
Write-Host ('  Version              : {0}' -f $ScriptVersion) -ForegroundColor Cyan
Write-Host ('  Host                 : {0}' -f $ScriptHost)    -ForegroundColor Cyan
Write-Host ('  Started              : {0}' -f $StartTimestamp)-ForegroundColor Cyan
Write-Host ('  Log                  : {0}' -f $LogPath)       -ForegroundColor Cyan
Write-Host '  ----- parameters -----'                         -ForegroundColor Cyan
Write-Host ('  RunMode              : {0}' -f $RunMode)             -ForegroundColor Cyan
Write-Host ('  CleanupOnly          : {0}' -f $CleanupOnlyBool)     -ForegroundColor Cyan
Write-Host ('  UseBESRemoveIfFound  : {0}' -f $UseBESRemoveBool)    -ForegroundColor Cyan
Write-Host ('  Mode                 : {0}' -f $Mode)                -ForegroundColor Cyan
Write-Host ('=' * 66) -ForegroundColor Cyan

if (-not $IsEnforce) {
    Write-Host ''
    Write-Host '  AUDIT MODE: script reports what it finds but makes NO changes.'       -ForegroundColor Yellow
    Write-Host '  Re-run with RunMode=Enforce to perform the actual uninstall/cleanup.' -ForegroundColor Yellow
}
Write-Host ''

# ---------------------------------------------------------------------------
# COUNTERS
# ---------------------------------------------------------------------------
$CountServicesFound   = 0
$CountProcessesFound  = 0
$CountProductsFound   = 0
$CountDirsFound       = 0
$CountKeysFound       = 0
$CountTasksFound      = 0
$CountRulesFound      = 0

$CountServicesStopped = 0
$CountProcessesKilled = 0
$CountProductsRemoved = 0
$CountDirsRemoved     = 0
$CountKeysRemoved     = 0
$CountTasksRemoved    = 0
$CountRulesRemoved    = 0
$CountWarnings        = 0

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
$LogLines = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param([string]$Message, [string]$Level)
    if ([string]::IsNullOrEmpty($Level)) { $Level = 'INFO' }
    $line = '{0}  [{1}]  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.PadRight(4), $Message
    $LogLines.Add($line)
    if ($Level -eq 'WARN')   { Write-Host ('    [WARN]  {0}' -f $Message) -ForegroundColor Yellow }
    elseif ($Level -eq 'ERROR') { Write-Host ('    [ERROR] {0}' -f $Message) -ForegroundColor Red }
    elseif ($Level -eq 'OK')    { Write-Host ('    [OK]    {0}' -f $Message) -ForegroundColor Green }
    elseif ($Level -eq 'SKIP')  { Write-Host ('    [-]     {0}' -f $Message) -ForegroundColor DarkGray }
    elseif ($Level -eq 'FIND')  { Write-Host ('    [FOUND] {0}' -f $Message) -ForegroundColor Magenta }
    elseif ($Level -eq 'ACT')   { Write-Host ('    [ACT]   {0}' -f $Message) -ForegroundColor Cyan }
    else                        { Write-Host $Message }
}

function Save-Log {
    try { $LogLines | Out-File -FilePath $LogPath -Encoding ASCII -Force } catch {}
}

# ---------------------------------------------------------------------------
# PATTERN MATCHING
# ---------------------------------------------------------------------------
$BigFixNamePatterns = @(
    'BigFix',
    'BES Client',
    'BES Relay',
    'BES Server',
    'BES Root',
    'BES FillDB',
    'BES GatherDB',
    'BESWebReports',
    'BES Web Reports',
    'BESRemove',
    'BESAdmin',
    'Client Deploy Tool',
    'BigFix Enterprise',
    'IBM Endpoint Manager',
    'Tivoli Endpoint Manager',
    'HCL BigFix'
)

function Test-IsBigFix {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $matched = $false
    foreach ($pattern in $BigFixNamePatterns) {
        if ($Text -match [regex]::Escape($pattern)) { $matched = $true; break }
    }
    return $matched
}

$UninstallRegPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

# ---------------------------------------------------------------------------
# STEP 1 - SERVICES
# ---------------------------------------------------------------------------
$verb = 'Scanning for'
if ($IsEnforce) { $verb = 'Stopping' }
Write-Host ('[Step 1/8] {0} BigFix services...' -f $verb) -ForegroundColor Green
Write-Log ('[Step 1/8] Services - Mode: {0}' -f $Mode)

$ServiceNamePatterns = @('^BES', '^BigFix', '^HCLBigFix', '^TivoliEndpoint')

function Get-ServiceSortKey {
    param([string]$Name)
    $lower = $Name.ToLower()
    if ($lower -match 'helper')     { return 0 }
    if ($lower -match 'webreport')  { return 1 }
    if ($lower -match 'webui')      { return 2 }
    if ($lower -match 'relay')      { return 3 }
    if ($lower -match 'gather')     { return 4 }
    if ($lower -match 'filldb')     { return 5 }
    if ($lower -match 'root')       { return 6 }
    if ($lower -match 'client')     { return 7 }
    return 99
}

$allSvcs   = Get-Service -ErrorAction SilentlyContinue
$bfSvcList = New-Object System.Collections.Generic.List[object]

foreach ($svc in $allSvcs) {
    $nameMatch = $false
    foreach ($pat in $ServiceNamePatterns) {
        if ($svc.Name -match $pat) { $nameMatch = $true; break }
    }
    if (-not $nameMatch) { $nameMatch = Test-IsBigFix $svc.DisplayName }
    if ($nameMatch) { [void]$bfSvcList.Add($svc) }
}

$sortedSvcs = $bfSvcList | Sort-Object { Get-ServiceSortKey $_.Name }

foreach ($svc in $sortedSvcs) {
    $CountServicesFound++
    if ($IsEnforce) {
        Write-Log ('Service: {0} [{1}] - {2}' -f $svc.Name, $svc.Status, $svc.DisplayName)
        try { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
        if ($svc.Status -ne 'Stopped') {
            try {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Write-Log ('Stopped: {0}' -f $svc.Name) -Level 'OK'
                $CountServicesStopped++
            } catch {
                Write-Log ('Could not stop {0}: {1}' -f $svc.Name, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        } else {
            Write-Log ('Already stopped: {0}' -f $svc.Name) -Level 'SKIP'
            $CountServicesStopped++
        }
    } else {
        Write-Log ('FOUND service: {0} (Status={1}, DisplayName={2})' -f $svc.Name, $svc.Status, $svc.DisplayName) -Level 'FIND'
    }
}

if ($bfSvcList.Count -eq 0) { Write-Log 'No BigFix services found.' -Level 'SKIP' }
if ($IsEnforce) { Start-Sleep -Seconds 2 }

# ---------------------------------------------------------------------------
# STEP 2 - PROCESSES
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Scanning for'
if ($IsEnforce) { $verb = 'Killing residual' }
Write-Host ('[Step 2/8] {0} BigFix processes...' -f $verb) -ForegroundColor Green
Write-Log ('[Step 2/8] Processes - Mode: {0}' -f $Mode)

$ProcessPatterns = @(
    '^BESClient$', '^BESRelay$', '^BESRootServer$', '^BESFillDB$',
    '^BESGatherDB?$', '^BESWebReports', '^BESAdmin$', '^BESPluginPortal$',
    '^qna$', '^xqna$', '^XBESClientUI$', '^XOpenUI$'
)

function Stop-BigFixProcesses {
    param([switch]$AuditOnly)
    $found = 0
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($proc in $procs) {
        $hit = $false
        foreach ($pat in $ProcessPatterns) {
            if ($proc.Name -match $pat) { $hit = $true; break }
        }
        if ($hit) {
            $script:CountProcessesFound++
            if ($AuditOnly) {
                Write-Log ('FOUND process: {0} (PID {1}, Path={2})' -f $proc.Name, $proc.Id, $proc.Path) -Level 'FIND'
            } else {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-Log ('Killed: {0} (PID {1})' -f $proc.Name, $proc.Id) -Level 'OK'
                    $script:CountProcessesKilled++
                } catch {
                    Write-Log ('Could not kill {0}: {1}' -f $proc.Name, $_.Exception.Message) -Level 'WARN'
                    $script:CountWarnings++
                }
            }
            $found++
        }
    }
    return $found
}

if ($IsEnforce) {
    $killed = Stop-BigFixProcesses
} else {
    $killed = Stop-BigFixProcesses -AuditOnly
}
if ($killed -eq 0) { Write-Log 'No BigFix processes found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 3 - INSTALLED PRODUCTS
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[Step 3/8] Discovering installed BigFix products...' -ForegroundColor Green
Write-Log ('[Step 3/8] Installed products - Mode: {0}' -f $Mode)

$ProductsFound = New-Object System.Collections.Generic.List[object]
$SeenCodes     = New-Object System.Collections.Generic.HashSet[string]

foreach ($regBase in $UninstallRegPaths) {
    if (-not (Test-Path $regBase)) { continue }
    $subKeys = Get-ChildItem -Path $regBase -ErrorAction SilentlyContinue
    foreach ($key in $subKeys) {
        $dispName    = $key.GetValue('DisplayName')
        $publisher   = $key.GetValue('Publisher')
        $uninstStr   = $key.GetValue('UninstallString')
        $quietStr    = $key.GetValue('QuietUninstallString')
        $installLoc  = $key.GetValue('InstallLocation')
        $productCode = $key.PSChildName
        $displayVer  = $key.GetValue('DisplayVersion')

        $isMatch = (Test-IsBigFix $dispName) -or (Test-IsBigFix $publisher) -or
                   (Test-IsBigFix $uninstStr) -or (Test-IsBigFix $installLoc)

        if ($isMatch -and (-not $SeenCodes.Contains($productCode))) {
            [void]$SeenCodes.Add($productCode)
            $entry = New-Object PSObject
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'DisplayName'         -Value $dispName
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'DisplayVersion'       -Value $displayVer
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'Publisher'            -Value $publisher
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'ProductCode'          -Value $productCode
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'UninstallString'      -Value $uninstStr
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'QuietUninstallString' -Value $quietStr
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'InstallLocation'      -Value $installLoc
            [void]$ProductsFound.Add($entry)
            $CountProductsFound++

            if ($IsEnforce) {
                Write-Log ('Product: {0} v{1} [{2}]' -f $dispName, $displayVer, $publisher)
            } else {
                Write-Log ('FOUND product : {0} v{1}' -f $dispName, $displayVer) -Level 'FIND'
                Write-Log ('  Publisher   : {0}' -f $publisher)
                Write-Log ('  ProductCode : {0}' -f $productCode)
                Write-Log ('  InstallDir  : {0}' -f $installLoc)
                $uninstDisplay = $uninstStr
                if (-not [string]::IsNullOrWhiteSpace($quietStr)) { $uninstDisplay = $quietStr }
                Write-Log ('  Uninstaller : {0}' -f $uninstDisplay)
            }
        }
    }
}

if ($ProductsFound.Count -eq 0) { Write-Log 'No registered BigFix products found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 4 - UNINSTALL (active only with -U)
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Products that WOULD be uninstalled (audit)...'
if ($IsEnforce) { $verb = 'Uninstalling BigFix products...' }
Write-Host ('[Step 4/8] {0}' -f $verb) -ForegroundColor Green
Write-Log ('[Step 4/8] Uninstall - Mode: {0}' -f $Mode)

function Normalize-UninstallCommand {
    param([string]$CommandLine, [string]$ProductCode)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        if ($ProductCode -match '^\{[A-Fa-f0-9\-]+\}$') {
            return ('msiexec.exe /X {0} /qn /norestart' -f $ProductCode)
        }
        return $null
    }
    $cmd = $CommandLine.Trim()
    if ($cmd -match '(?i)msiexec') {
        $cmd = $cmd -replace '(?i)\s/I\s', ' /X '
        $cmd = $cmd -replace '(?i)/I\s*\{', '/X {'
        if ($cmd -notmatch '(?i)/[Xx]\s') {
            if ($ProductCode -match '^\{[A-Fa-f0-9\-]+\}$') {
                $cmd = ('msiexec.exe /X {0}' -f $ProductCode)
            }
        }
        if ($cmd -notmatch '(?i)/q[nrbf]')  { $cmd = $cmd + ' /qn' }
        if ($cmd -notmatch '(?i)/norestart') { $cmd = $cmd + ' /norestart' }
    }
    return $cmd
}

if (-not $IsEnforce) {
    # Audit - report what would be done
    if ($ProductsFound.Count -eq 0) {
        Write-Log 'No products to uninstall.' -Level 'SKIP'
    } else {
        foreach ($product in $ProductsFound) {
            $cmdToRun = $null
            if (-not [string]::IsNullOrWhiteSpace($product.QuietUninstallString)) {
                $cmdToRun = $product.QuietUninstallString
            } elseif (-not [string]::IsNullOrWhiteSpace($product.UninstallString)) {
                $cmdToRun = Normalize-UninstallCommand -CommandLine $product.UninstallString -ProductCode $product.ProductCode
            } else {
                $cmdToRun = Normalize-UninstallCommand -CommandLine $null -ProductCode $product.ProductCode
            }
            Write-Log ('WOULD uninstall: {0} v{1}' -f $product.DisplayName, $product.DisplayVersion) -Level 'ACT'
            Write-Log ('  Command      : {0}' -f $cmdToRun)
        }
    }
} elseif ($CleanupOnlyBool) {
    Write-Log '-CleanupOnly specified; skipping uninstall phase.' -Level 'SKIP'
} else {
    foreach ($product in $ProductsFound) {
        $cmdToRun = $null
        if (-not [string]::IsNullOrWhiteSpace($product.QuietUninstallString)) {
            $cmdToRun = $product.QuietUninstallString
        } elseif (-not [string]::IsNullOrWhiteSpace($product.UninstallString)) {
            $cmdToRun = Normalize-UninstallCommand -CommandLine $product.UninstallString -ProductCode $product.ProductCode
        } else {
            $cmdToRun = Normalize-UninstallCommand -CommandLine $null -ProductCode $product.ProductCode
        }

        if ([string]::IsNullOrWhiteSpace($cmdToRun)) {
            Write-Log ('No uninstall command for: {0}' -f $product.DisplayName) -Level 'WARN'
            $CountWarnings++
            continue
        }

        Write-Log ('Uninstalling: {0}' -f $product.DisplayName)
        Write-Log ('  Command: {0}' -f $cmdToRun)

        try {
            $proc     = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c ' + $cmdToRun) -Wait -PassThru -NoNewWindow -ErrorAction Stop
            $exitCode = $proc.ExitCode
            if ($exitCode -eq 0 -or $exitCode -eq 3010 -or $exitCode -eq 1605) {
                Write-Log ('Uninstalled (exit {0}): {1}' -f $exitCode, $product.DisplayName) -Level 'OK'
                $CountProductsRemoved++
            } else {
                Write-Log ('Exit {0} for: {1}' -f $exitCode, $product.DisplayName) -Level 'WARN'
                $CountWarnings++
            }
        } catch {
            Write-Log ('Uninstall failed for {0}: {1}' -f $product.DisplayName, $_.Exception.Message) -Level 'WARN'
            $CountWarnings++
        }
    }

    if ($UseBESRemoveBool) {
        $besRemoveCandidates = @(
            ('{0}\BigFix Enterprise\BESRemove.exe' -f $env:ProgramFiles),
            ('{0}\BigFix Enterprise\BESRemove.exe' -f ${env:ProgramFiles(x86)}),
            'C:\Temp\BESRemove.exe',
            ('{0}\BESRemove.exe' -f $env:TEMP)
        )
        $besRemoveExe = $null
        foreach ($candidate in $besRemoveCandidates) {
            if (Test-Path $candidate) { $besRemoveExe = $candidate; break }
        }
        if ($besRemoveExe) {
            Write-Log ('Running BESRemove.exe: {0}' -f $besRemoveExe)
            try {
                $proc = Start-Process -FilePath $besRemoveExe -ArgumentList '/silent' -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
                Write-Log ('BESRemove.exe exited: {0}' -f $proc.ExitCode) -Level 'OK'
            } catch {
                Write-Log ('BESRemove.exe failed: {0}' -f $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
            Start-Sleep -Seconds 3
            [void](Stop-BigFixProcesses)
        } else {
            Write-Log 'BESRemove.exe not found in standard locations.' -Level 'SKIP'
        }
    }
}

# ---------------------------------------------------------------------------
# STEP 5 - FILESYSTEM ARTIFACTS
# ---------------------------------------------------------------------------
$PF86 = ${env:ProgramFiles(x86)}

$DirsToCheck = @(
    ('{0}\BigFix Enterprise'  -f $env:ProgramFiles),
    ('{0}\BigFix Enterprise'  -f $PF86),
    ('{0}\IBM\BigFix'         -f $env:ProgramFiles),
    ('{0}\IBM\BigFix'         -f $PF86),
    ('{0}\HCL\BigFix'         -f $env:ProgramFiles),
    ('{0}\HCL\BigFix'         -f $PF86),
    ('{0}\BigFix'             -f $env:ProgramData),
    ('{0}\IBM\BigFix'         -f $env:ProgramData),
    ('{0}\HCL\BigFix'         -f $env:ProgramData),
    ('{0}\BES'                -f $env:TEMP),
    'C:\Windows\Temp\BES'
)

Write-Host ''
$verb = 'Scanning for'
if ($IsEnforce) { $verb = 'Removing' }
Write-Host ('[Step 5/8] {0} filesystem artifacts...' -f $verb) -ForegroundColor Green
Write-Log ('[Step 5/8] Filesystem - Mode: {0}' -f $Mode)

foreach ($dir in $DirsToCheck) {
    if ([string]::IsNullOrWhiteSpace($dir)) { continue }
    if (Test-Path $dir) {
        $CountDirsFound++
        if ($IsEnforce) {
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-Log ('Removed: {0}' -f $dir) -Level 'OK'
                $CountDirsRemoved++
            } catch {
                Write-Log ('Could not remove {0}: {1}' -f $dir, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        } else {
            Write-Log ('FOUND directory  : {0}' -f $dir) -Level 'FIND'
            Write-Log ('  WOULD delete   : {0} (recursive)' -f $dir)
        }
    } else {
        Write-Log ('Not present: {0}' -f $dir) -Level 'SKIP'
    }
}

if ($CountDirsFound -eq 0) { Write-Log 'No BigFix filesystem artifacts found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 6 - REGISTRY KEYS
# ---------------------------------------------------------------------------
$RegKeysToCheck = @(
    'HKLM:\SOFTWARE\BigFix',
    'HKLM:\SOFTWARE\WOW6432Node\BigFix',
    'HKLM:\SOFTWARE\BigFix Enterprise',
    'HKLM:\SOFTWARE\WOW6432Node\BigFix Enterprise',
    'HKLM:\SOFTWARE\IBM\BigFix',
    'HKLM:\SOFTWARE\WOW6432Node\IBM\BigFix',
    'HKLM:\SOFTWARE\HCL\BigFix',
    'HKLM:\SOFTWARE\WOW6432Node\HCL\BigFix',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESClient',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESRelay',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESRootServer',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESFillDB',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESGatherDB',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESWebReportsServer',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESWebUI',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BESPluginPortal',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\BESClient',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\BigFix'
)

Write-Host ''
$verb = 'Scanning for'
if ($IsEnforce) { $verb = 'Removing' }
Write-Host ('[Step 6/8] {0} registry keys...' -f $verb) -ForegroundColor Green
Write-Log ('[Step 6/8] Registry - Mode: {0}' -f $Mode)

foreach ($regKey in $RegKeysToCheck) {
    if (Test-Path $regKey) {
        $CountKeysFound++
        if ($IsEnforce) {
            try {
                Remove-Item -Path $regKey -Recurse -Force -ErrorAction Stop
                Write-Log ('Removed key: {0}' -f $regKey) -Level 'OK'
                $CountKeysRemoved++
            } catch {
                Write-Log ('Could not remove {0}: {1}' -f $regKey, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        } else {
            Write-Log ('FOUND reg key    : {0}' -f $regKey) -Level 'FIND'
            Write-Log ('  WOULD delete   : {0} (recursive)' -f $regKey)
        }
    } else {
        Write-Log ('Not present: {0}' -f $regKey) -Level 'SKIP'
    }
}

if ($CountKeysFound -eq 0) { Write-Log 'No BigFix registry keys found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 7 - SCHEDULED TASKS
# ---------------------------------------------------------------------------
$TaskPatterns = @('BigFix', 'BESClient', 'BESRelay', 'IBM Endpoint', 'Tivoli Endpoint', 'HCL BigFix')

Write-Host ''
$verb = 'Scanning for'
if ($IsEnforce) { $verb = 'Removing' }
Write-Host ('[Step 7/8] {0} scheduled tasks...' -f $verb) -ForegroundColor Green
Write-Log ('[Step 7/8] Scheduled tasks - Mode: {0}' -f $Mode)

$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $allTasks) {
    $isMatch = $false
    foreach ($pat in $TaskPatterns) {
        if ($task.TaskName -match [regex]::Escape($pat)) { $isMatch = $true; break }
    }
    if ($isMatch) {
        $CountTasksFound++
        $taskFullPath = ('{0}{1}' -f $task.TaskPath, $task.TaskName)
        if ($IsEnforce) {
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                Write-Log ('Removed task: {0}' -f $taskFullPath) -Level 'OK'
                $CountTasksRemoved++
            } catch {
                Write-Log ('Could not remove task {0}: {1}' -f $task.TaskName, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        } else {
            Write-Log ('FOUND task       : {0}' -f $taskFullPath) -Level 'FIND'
            Write-Log ('  WOULD delete   : {0}' -f $taskFullPath)
        }
    }
}

if ($CountTasksFound -eq 0) { Write-Log 'No BigFix scheduled tasks found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 8 - FIREWALL RULES
# ---------------------------------------------------------------------------
$FwPatterns = @('BigFix', 'BESClient', 'BESRelay', 'BES Client', 'BES Relay', 'IBM Endpoint', 'HCL BigFix')

Write-Host ''
$verb = 'Scanning for'
if ($IsEnforce) { $verb = 'Removing' }
Write-Host ('[Step 8/8] {0} firewall rules...' -f $verb) -ForegroundColor Green
Write-Log ('[Step 8/8] Firewall rules - Mode: {0}' -f $Mode)

try {
    $allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue
    foreach ($rule in $allRules) {
        $isMatch = $false
        foreach ($pat in $FwPatterns) {
            if ($rule.DisplayName -match [regex]::Escape($pat)) { $isMatch = $true; break }
        }
        if ($isMatch) {
            $CountRulesFound++
            if ($IsEnforce) {
                try {
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                    Write-Log ('Removed rule: {0}' -f $rule.DisplayName) -Level 'OK'
                    $CountRulesRemoved++
                } catch {
                    Write-Log ('Could not remove rule {0}: {1}' -f $rule.DisplayName, $_.Exception.Message) -Level 'WARN'
                    $CountWarnings++
                }
            } else {
                Write-Log ('FOUND fw rule    : {0} (Direction={1}, Enabled={2})' -f $rule.DisplayName, $rule.Direction, $rule.Enabled) -Level 'FIND'
                Write-Log ('  WOULD delete   : rule "{0}"' -f $rule.DisplayName)
            }
        }
    }
} catch {
    Write-Log ('Firewall enumeration failed: {0}' -f $_.Exception.Message) -Level 'WARN'
    $CountWarnings++
}

if ($CountRulesFound -eq 0) { Write-Log 'No BigFix firewall rules found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# VERIFICATION SCAN (only when -U was used)
# ---------------------------------------------------------------------------
$RemainingProducts = New-Object System.Collections.Generic.List[string]

if ($IsEnforce) {
    Write-Host ''
    Write-Log 'Running post-removal verification scan...'
    $SeenCheck = New-Object System.Collections.Generic.HashSet[string]

    foreach ($regBase in $UninstallRegPaths) {
        if (-not (Test-Path $regBase)) { continue }
        $subKeys = Get-ChildItem -Path $regBase -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            $dispName    = $key.GetValue('DisplayName')
            $productCode = $key.PSChildName
            if ((Test-IsBigFix $dispName) -and (-not $SeenCheck.Contains($productCode))) {
                [void]$SeenCheck.Add($productCode)
                [void]$RemainingProducts.Add($dispName)
                Write-Log ('REMAINING: {0}' -f $dispName) -Level 'WARN'
                $CountWarnings++
            }
        }
    }
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
$Stopwatch.Stop()
$Elapsed = $Stopwatch.Elapsed

Write-Host ''
Write-Host ('=' * 66) -ForegroundColor Cyan

if ($IsEnforce) {
    Write-Host '  REMOVAL SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 66) -ForegroundColor Cyan
    Write-Host ('  Services found       : {0}  (stopped: {1})' -f $CountServicesFound,  $CountServicesStopped)
    Write-Host ('  Processes found      : {0}  (killed: {1})'  -f $CountProcessesFound, $CountProcessesKilled)
    Write-Host ('  Products found       : {0}  (removed: {1})' -f $CountProductsFound,  $CountProductsRemoved)
    Write-Host ('  Directories found    : {0}  (removed: {1})' -f $CountDirsFound,      $CountDirsRemoved)
    Write-Host ('  Registry keys found  : {0}  (removed: {1})' -f $CountKeysFound,      $CountKeysRemoved)
    Write-Host ('  Sched. tasks found   : {0}  (removed: {1})' -f $CountTasksFound,     $CountTasksRemoved)
    Write-Host ('  Firewall rules found : {0}  (removed: {1})' -f $CountRulesFound,     $CountRulesRemoved)
    Write-Host ('  Warnings             : {0}' -f $CountWarnings)
    Write-Host ('  Remaining products   : {0}' -f $RemainingProducts.Count)
} else {
    Write-Host '  AUDIT SUMMARY (no changes made)' -ForegroundColor Yellow
    Write-Host ('=' * 66) -ForegroundColor Cyan
    Write-Host ('  Services found       : {0}' -f $CountServicesFound)
    Write-Host ('  Processes found      : {0}' -f $CountProcessesFound)
    Write-Host ('  Products found       : {0}  (would be uninstalled)' -f $CountProductsFound)
    Write-Host ('  Directories found    : {0}  (would be deleted)'     -f $CountDirsFound)
    Write-Host ('  Registry keys found  : {0}  (would be deleted)'     -f $CountKeysFound)
    Write-Host ('  Sched. tasks found   : {0}  (would be removed)'     -f $CountTasksFound)
    Write-Host ('  Firewall rules found : {0}  (would be removed)'     -f $CountRulesFound)
    Write-Host ''
    Write-Host '  To perform actual removal, re-run with: -U' -ForegroundColor Yellow
}

Write-Host ('  Elapsed              : {0:mm\:ss\.fff}' -f $Elapsed)
Write-Host ('  Log                  : {0}' -f $LogPath)
Write-Host ('=' * 66) -ForegroundColor Cyan

Write-Log ('SUMMARY: mode={0} svc_found={1} proc_found={2} prod_found={3} dir_found={4} reg_found={5} task_found={6} fw_found={7} warnings={8} elapsed={9:mm\:ss\.fff}' -f
    $Mode, $CountServicesFound, $CountProcessesFound, $CountProductsFound,
    $CountDirsFound, $CountKeysFound, $CountTasksFound, $CountRulesFound,
    $CountWarnings, $Elapsed)

Save-Log

if ($IsEnforce) {
    if ($RemainingProducts.Count -gt 0) {
        Write-Host ''
        Write-Host ('  [WARN] {0} BigFix product(s) still registered. Manual review required.' -f $RemainingProducts.Count) -ForegroundColor Yellow
        Write-Host ''
        exit 1
    }
    Write-Host ''
    Write-Host '  [OK] BigFix removal complete. No registered products remain.' -ForegroundColor Green
    Write-Host ''
    exit 0
} else {
    $totalFound = $CountServicesFound + $CountProcessesFound + $CountProductsFound +
                  $CountDirsFound + $CountKeysFound + $CountTasksFound + $CountRulesFound
    Write-Host ''
    if ($totalFound -gt 0) {
        Write-Host ('  [AUDIT] {0} BigFix component(s) detected. Run with -U to remove.' -f $totalFound) -ForegroundColor Yellow
    } else {
        Write-Host '  [AUDIT] No BigFix components detected on this host.' -ForegroundColor Green
    }
    Write-Host ''
    exit 0
}
