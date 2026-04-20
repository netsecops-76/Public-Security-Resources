<#
.SYNOPSIS
    Audits or removes Okta, ScaleFT, and Advanced Server Access (ASA/sftd)
    software and all associated artifacts from a Windows host. Deployed via
    Qualys CAR using UI-defined POSITIONAL parameters.

.DESCRIPTION
    Audit-first. By default, the script discovers and reports all Okta/
    ScaleFT services, processes, installed products, filesystem artifacts,
    registry keys, scheduled tasks, and firewall rules - with no changes
    made to the system.

    RunMode=Enforce performs the full uninstall workflow: stops services,
    kills processes, uninstalls registered products, removes leftover
    directories, registry keys, scheduled tasks, and firewall rules.

# ==============================================================================
# CAR UI PARAMETERS (define on Script Details page in this EXACT order):
# ==============================================================================
#
#   Position 1:  RunMode
#     Type:      String
#     Required:  No
#     Default:   Audit
#     Allowed:   Audit | Enforce
#
#   Position 2:  CleanupOnly
#     Type:      String
#     Required:  No
#     Default:   No
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off (case-insensitive)
#     Purpose:   (Enforce only) Skip the uninstaller phase; only remove
#                filesystem, registry, task, and firewall artifacts.
#
#   Position 3:  IncludeCurrentUser
#     Type:      String
#     Required:  No
#     Default:   No
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Also scan HKCU uninstall keys. Requires user context;
#                less useful in SYSTEM/CAR runs, which is why the default
#                is No.
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details:
#        Name:        Remove Okta (Windows)
#        Platform:    Windows
#        Interpreter: PowerShell
#        Upload:      Remove-Okta.ps1
#   4. Parameters (ORDER MATTERS - positional):
#        RunMode             (String, Optional, default "Audit")
#        CleanupOnly         (String, Optional, default "No")
#        IncludeCurrentUser  (String, Optional, default "No")
#   5. Save. Audit first against a pilot asset before Enforce.
#   6. Note: Okta Verify accounts should ideally be unenrolled BEFORE this
#      script runs with Enforce. The script proceeds regardless and removes
#      everything it can reach.
#
# CLI INVOCATION (local testing):
#   .\Remove-Okta.ps1                         # audit
#   .\Remove-Okta.ps1 Enforce                 # full removal
#   .\Remove-Okta.ps1 Enforce Yes No          # cleanup-only removal
#
# CAR INVOKES EQUIVALENT TO:
#   powershell.exe -ExecutionPolicy Bypass -File Remove-Okta.ps1 `
#                  "<RunMode>" "<CleanupOnly>" "<IncludeCurrentUser>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional params win. If empty, script checks $env:RunMode,
#   $env:CleanupOnly, $env:IncludeCurrentUser. Defaults last. Legacy -U
#   switch preserved for backward compatibility.
#
# ==============================================================================

.NOTES
    Author:      Brian Canaday
    Team:        netsecops-76
    Version:     3.0.0
    Created:     2026-04-03
    Script:      Remove-Okta.ps1

    Changelog:
        3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces -U /
                              -CleanupOnly / -IncludeCurrentUser switches
                              with positional string parameters consumable
                              by Qualys CAR UI. Dual-invocation support:
                              positional first, env fallback, defaults
                              last. Legacy -U switch preserved. ASCII-only
                              log output. No $var = if() assignments.
        2.0.0 - 2026-04-03 - Audit-first redesign. Default run is
                              discovery/report only. -U switch required to
                              invoke destructive removal workflow.
        1.0.0 - 2026-04-03 - Initial release. PS5.1 compliant, CAR-ready.

    Requirements:
        Windows PowerShell 5.1, Local Administrator or SYSTEM privileges.
        No interactive prompts; safe for CAR/remote deployment.

    Note:
        Okta Verify accounts should ideally be unenrolled before uninstalling
        Okta Verify. This script proceeds regardless and removes all
        artifacts it can reach.

    Exit Codes:
        0  = Success (audit: nothing found | removal: clean)
        1  = Audit found components / removal completed with warnings
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$RunMode = '',

    [Parameter(Position=1)]
    [string]$CleanupOnly = '',

    [Parameter(Position=2)]
    [string]$IncludeCurrentUser = '',

    # Legacy switch retained for backward compatibility with older invocations
    # (Remove-Okta.ps1 -U). When set, forces RunMode=Enforce if positional is empty.
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
# PARAMETER RESOLUTION: positional first, env fallback, legacy switch, default.
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($RunMode))            { $RunMode            = $env:RunMode }
if ([string]::IsNullOrWhiteSpace($CleanupOnly))        { $CleanupOnly        = $env:CleanupOnly }
if ([string]::IsNullOrWhiteSpace($IncludeCurrentUser)) { $IncludeCurrentUser = $env:IncludeCurrentUser }

if ($U -and [string]::IsNullOrWhiteSpace($RunMode)) { $RunMode = 'Enforce' }
if ([string]::IsNullOrWhiteSpace($RunMode))         { $RunMode = 'Audit' }

$IsEnforce                = ($RunMode.Trim().ToLowerInvariant() -eq 'enforce')
$AuditOnly                = (-not $IsEnforce)
$CleanupOnlyBool          = ConvertTo-CarBool $CleanupOnly
$IncludeCurrentUserBool   = ConvertTo-CarBool $IncludeCurrentUser

# ---------------------------------------------------------------------------
# RUNTIME BANNER
# ---------------------------------------------------------------------------
Clear-Host
$ScriptVersion  = '3.0.0'
$Stopwatch      = [System.Diagnostics.Stopwatch]::StartNew()
$StartTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$ScriptHost     = $env:COMPUTERNAME
$ModeLabel      = 'AUDIT'
if ($IsEnforce) { $ModeLabel = 'ENFORCE' }

$LogDir  = Join-Path $env:ProgramData 'OktaRemoval'
$LogFile = Join-Path $LogDir ('Remove-Okta_{0}_{1}.log' -f $ModeLabel, (Get-Date -Format 'yyyyMMdd_HHmmss'))

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Host ('=' * 66) -ForegroundColor Cyan
Write-Host '  Remove-Okta.ps1' -ForegroundColor Cyan
Write-Host ('  Version             : {0}' -f $ScriptVersion)          -ForegroundColor Cyan
Write-Host ('  Host                : {0}' -f $ScriptHost)             -ForegroundColor Cyan
Write-Host ('  Started             : {0}' -f $StartTimestamp)         -ForegroundColor Cyan
Write-Host ('  Log                 : {0}' -f $LogFile)                -ForegroundColor Cyan
Write-Host '  ----- parameters -----'                                 -ForegroundColor Cyan
Write-Host ('  RunMode             : {0}' -f $RunMode)                -ForegroundColor Cyan
Write-Host ('  CleanupOnly         : {0}' -f $CleanupOnlyBool)        -ForegroundColor Cyan
Write-Host ('  IncludeCurrentUser  : {0}' -f $IncludeCurrentUserBool) -ForegroundColor Cyan
Write-Host ('  Mode                : {0}' -f $ModeLabel)              -ForegroundColor Cyan
Write-Host ('=' * 66) -ForegroundColor Cyan

if ($AuditOnly) {
    Write-Host ''
    Write-Host '  [AUDIT MODE] No changes will be made to this system.'       -ForegroundColor Yellow
    Write-Host '  Re-run with RunMode=Enforce to perform removal.'            -ForegroundColor Yellow
}
Write-Host ''

# ---------------------------------------------------------------------------
# COUNTERS
# ---------------------------------------------------------------------------
# Audit counters (findings)
$AuditServices  = 0
$AuditProcesses = 0
$AuditProducts  = 0
$AuditDirs      = 0
$AuditRegKeys   = 0
$AuditTasks     = 0
$AuditRules     = 0

# Action counters (only incremented when -U is active)
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
    if     ($Level -eq 'WARN')  { Write-Host ('    [WARN] {0}' -f $Message) -ForegroundColor Yellow }
    elseif ($Level -eq 'OK')    { Write-Host ('    [OK]   {0}' -f $Message) -ForegroundColor Green }
    elseif ($Level -eq 'SKIP')  { Write-Host ('    [--]   {0}' -f $Message) -ForegroundColor DarkGray }
    elseif ($Level -eq 'FIND')  { Write-Host ('    [FIND] {0}' -f $Message) -ForegroundColor Magenta }
    elseif ($Level -eq 'ACT')   { Write-Host ('    [ACT]  {0}' -f $Message) -ForegroundColor White }
    else                        { Write-Host $Message }
}

function Save-Log {
    try { $LogLines | Out-File -FilePath $LogFile -Encoding UTF8 -Force } catch {}
}

# ---------------------------------------------------------------------------
# VENDOR PATTERN MATCHING
# ---------------------------------------------------------------------------
$VendorNamePatterns = @(
    'Okta',
    'ScaleFT',
    'scaleleft',
    'sftd',
    'Advanced Server Access',
    'Okta Verify',
    'Okta LDAP',
    'Okta AD Agent',
    'Okta RADIUS',
    'Okta Provisioning',
    'Okta On-Prem',
    'Okta RSA',
    'Okta Device Trust',
    'Okta Browser Plugin',
    'Okta SAML Toolkit',
    'Okta IWA',
    'Okta Workflows',
    'ASA Agent',
    'Advanced Server Access Agent'
)

$VendorPathRegex = '(?i)(okta|scaleft|scaleleft|sftd|\\sft\\|advanced.server.access)'

function Test-IsVendorMatch {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $matched = $false
    foreach ($pattern in $VendorNamePatterns) {
        if ($Text -match [regex]::Escape($pattern)) { $matched = $true; break }
    }
    return $matched
}

$UninstallRegPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
if ($IncludeCurrentUserBool) {
    $UninstallRegPaths += 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
}

# ---------------------------------------------------------------------------
# STEP 1 - DISCOVER / STOP SERVICES
# ---------------------------------------------------------------------------
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Stopping and removing' }
Write-Host ('[Step 1/8] {0} Okta/ScaleFT services...' -f $verb) -ForegroundColor Green
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Stopping and removing' }
Write-Log ('[Step 1/8] {0} Okta/ScaleFT services' -f $verb)

$ExplicitServiceNames = @(
    'OktaLDAPAgent',
    'OktaADAgent',
    'OktaRADIUSAgent',
    'OktaProvisioningAgent',
    'OktaIWAServer',
    'OktaVerify',
    'OktaDeviceTrust',
    'sftd',
    'scaleft-server-tools',
    'scaleft-client-tools',
    'ScaleFTServer',
    'ScaleFTClient',
    'OktaASA',
    'OktaBrowserPlugin'
)

function Stop-And-DeleteService {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }

    $script:AuditServices++
    Write-Log ('FOUND service: {0} | Status: {1} | StartType: {2}' -f $svc.Name, $svc.Status, $svc.StartType) -Level 'FIND'

    if ($script:AuditOnly) { return }

    Write-Log ('ACTION: Stopping and deleting service: {0}' -f $ServiceName) -Level 'ACT'
    try { Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
    if ($svc.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Log ('Stopped: {0}' -f $ServiceName) -Level 'OK'
        } catch {
            Write-Log ('Could not stop {0}: {1}' -f $ServiceName, $_.Exception.Message) -Level 'WARN'
            $script:CountWarnings++
        }
    }
    $scResult = & sc.exe delete $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log ('Deleted service: {0}' -f $ServiceName) -Level 'OK'
    } else {
        Write-Log ('sc.exe delete {0}: {1}' -f $ServiceName, ($scResult -join ' ')) -Level 'WARN'
    }
    $script:CountServicesStopped++
}

foreach ($svcName in $ExplicitServiceNames) {
    Stop-And-DeleteService -ServiceName $svcName
}

$cimServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
foreach ($cimSvc in $cimServices) {
    $nameMatch    = Test-IsVendorMatch $cimSvc.Name
    $displayMatch = Test-IsVendorMatch $cimSvc.DisplayName
    $pathMatch    = ($cimSvc.PathName -match $VendorPathRegex)
    if ($nameMatch -or $displayMatch -or $pathMatch) {
        Stop-And-DeleteService -ServiceName $cimSvc.Name
    }
}

if ($AuditServices -eq 0) { Write-Log 'No Okta/ScaleFT services found.' -Level 'SKIP' }
if (-not $AuditOnly) { Start-Sleep -Seconds 2 }

# ---------------------------------------------------------------------------
# STEP 2 - DISCOVER / KILL PROCESSES
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Killing' }
Write-Host ('[Step 2/8] {0} Okta/ScaleFT processes...' -f $verb) -ForegroundColor Green
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Killing' }
Write-Log ('[Step 2/8] {0} Okta/ScaleFT processes' -f $verb)

$ProcessPatterns = @(
    '(?i)^okta',
    '(?i)^sftd$',
    '(?i)^scaleft',
    '(?i)^sft-',
    '(?i)^OktaVerify',
    '(?i)^OktaBrowserPlugin',
    '(?i)^OktaIWA'
)

function Find-VendorProcesses {
    $found = New-Object System.Collections.Generic.List[object]
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($proc in $procs) {
        $hit = $false
        foreach ($pat in $ProcessPatterns) {
            if ($proc.Name -match $pat) { $hit = $true; break }
        }
        if (-not $hit) {
            try {
                $procPath = $proc.MainModule.FileName
                if ($procPath -match $VendorPathRegex) { $hit = $true }
            } catch {}
        }
        if ($hit) { [void]$found.Add($proc) }
    }
    return $found
}

$vendorProcs = Find-VendorProcesses
foreach ($proc in $vendorProcs) {
    $procPath = ''
    try { $procPath = $proc.MainModule.FileName } catch {}
    Write-Log ('FOUND process: {0} | PID: {1} | Path: {2}' -f $proc.Name, $proc.Id, $procPath) -Level 'FIND'
    $AuditProcesses++

    if (-not $AuditOnly) {
        Write-Log ('ACTION: Killing process {0} (PID {1})' -f $proc.Name, $proc.Id) -Level 'ACT'
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Log ('Killed: {0} (PID {1})' -f $proc.Name, $proc.Id) -Level 'OK'
            $CountProcessesKilled++
        } catch {
            Write-Log ('Could not kill {0}: {1}' -f $proc.Name, $_.Exception.Message) -Level 'WARN'
            $CountWarnings++
        }
    }
}

if ($AuditProcesses -eq 0) { Write-Log 'No Okta/ScaleFT processes found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 3 - DISCOVER INSTALLED PRODUCTS
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[Step 3/8] Discovering installed Okta/ScaleFT products...' -ForegroundColor Green
Write-Log '[Step 3/8] Discovering installed Okta/ScaleFT products'

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
        $installSrc  = $key.GetValue('InstallSource')
        $helpLink    = $key.GetValue('HelpLink')
        $productCode = $key.PSChildName
        $displayVer  = $key.GetValue('DisplayVersion')

        $isMatch = (Test-IsVendorMatch $dispName) -or
                   (Test-IsVendorMatch $publisher) -or
                   (Test-IsVendorMatch $uninstStr) -or
                   (Test-IsVendorMatch $installLoc) -or
                   (Test-IsVendorMatch $installSrc) -or
                   (Test-IsVendorMatch $helpLink)

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
            Add-Member -InputObject $entry -MemberType NoteProperty -Name 'RegistryBase'         -Value $regBase
            [void]$ProductsFound.Add($entry)
            $AuditProducts++

            Write-Log ('FOUND product: {0} v{1} | Publisher: {2} | Code: {3}' -f $dispName, $displayVer, $publisher, $productCode) -Level 'FIND'
            if (-not [string]::IsNullOrWhiteSpace($installLoc)) {
                Write-Log ('  Install location: {0}' -f $installLoc) -Level 'FIND'
            }
            if (-not [string]::IsNullOrWhiteSpace($quietStr)) {
                $uninstDisplay = $quietStr
            } else {
                $uninstDisplay = $uninstStr
            }
            if (-not [string]::IsNullOrWhiteSpace($uninstDisplay)) {
                Write-Log ('  Uninstall command: {0}' -f $uninstDisplay) -Level 'FIND'
            }
            Write-Log ('  Registry key: {0}\{1}' -f $regBase, $productCode) -Level 'FIND'
        }
    }
}

if ($AuditProducts -eq 0) { Write-Log 'No registered Okta/ScaleFT products found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 4 - UNINSTALL PRODUCTS (active only with -U)
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Uninstall phase skipped (audit mode)'
if (-not $AuditOnly) { $verb = 'Uninstalling Okta/ScaleFT products' }
Write-Host ('[Step 4/8] {0}...' -f $verb) -ForegroundColor Green
$verb = 'Uninstall phase skipped (audit mode)'
if (-not $AuditOnly) { $verb = 'Uninstalling Okta/ScaleFT products' }
Write-Log ('[Step 4/8] {0}' -f $verb)

function Build-UninstallCommand {
    param([string]$DisplayName, [string]$UninstallString, [string]$QuietUninstallString, [string]$ProductCode)

    $cmdLine = $QuietUninstallString
    if ([string]::IsNullOrWhiteSpace($cmdLine)) { $cmdLine = $UninstallString }
    if ([string]::IsNullOrWhiteSpace($cmdLine)) {
        if ($ProductCode -match '^\{[A-Fa-f0-9\-]+\}$') {
            return 'msiexec.exe /X {0} /qn /norestart' -f $ProductCode
        }
        return $null
    }

    $cmdLine = $cmdLine.Trim()

    if ($cmdLine -match '(?i)msiexec') {
        $cmdLine = $cmdLine -replace '(?i)\s/I\s', ' /X '
        $cmdLine = $cmdLine -replace '(?i)/I\s*\{', '/X {'
        if ($cmdLine -notmatch '(?i)/q[nrbf]') { $cmdLine = $cmdLine + ' /qn' }
        if ($cmdLine -notmatch '(?i)/norestart') { $cmdLine = $cmdLine + ' /norestart' }
        return $cmdLine
    }

    if ($DisplayName -match '(?i)okta verify') {
        if ($cmdLine -notmatch '(?i)/uninstall') { $cmdLine = $cmdLine + ' /uninstall /q' }
        return $cmdLine
    }

    if ($cmdLine -notmatch '(?i)/quiet|/qn|/s\b|/silent|/verysilent|/q\b') {
        $cmdLine = $cmdLine + ' /quiet /norestart'
    }
    return $cmdLine
}

if ($AuditOnly) {
    if ($ProductsFound.Count -gt 0) {
        Write-Log 'Products that WOULD be uninstalled with -U:' -Level 'FIND'
        foreach ($product in $ProductsFound) {
            $dispName = $product.DisplayName
            if ([string]::IsNullOrWhiteSpace($dispName)) { $dispName = $product.ProductCode }
            $cmdToRun = Build-UninstallCommand `
                -DisplayName          $product.DisplayName `
                -UninstallString      $product.UninstallString `
                -QuietUninstallString $product.QuietUninstallString `
                -ProductCode          $product.ProductCode
            if ([string]::IsNullOrWhiteSpace($cmdToRun)) {
                $cmdDisplay = '(no uninstall command found)'
            } else {
                $cmdDisplay = $cmdToRun
            }
            Write-Log ('  WOULD UNINSTALL: {0}' -f $dispName) -Level 'FIND'
            Write-Log ('    Command: {0}' -f $cmdDisplay) -Level 'FIND'
        }
    }
} elseif ($CleanupOnlyBool) {
    Write-Log '-CleanupOnly specified; skipping uninstall phase.' -Level 'SKIP'
} else {
    foreach ($product in $ProductsFound) {
        $dispName = $product.DisplayName
        if ([string]::IsNullOrWhiteSpace($dispName)) { $dispName = $product.ProductCode }

        $cmdToRun = Build-UninstallCommand `
            -DisplayName          $product.DisplayName `
            -UninstallString      $product.UninstallString `
            -QuietUninstallString $product.QuietUninstallString `
            -ProductCode          $product.ProductCode

        if ([string]::IsNullOrWhiteSpace($cmdToRun)) {
            Write-Log ('No uninstall command for: {0}' -f $dispName) -Level 'WARN'
            $CountWarnings++
            continue
        }

        Write-Log ('ACTION: Uninstalling: {0}' -f $dispName) -Level 'ACT'
        Write-Log ('  Command: {0}' -f $cmdToRun) -Level 'ACT'

        try {
            $proc     = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c ' + $cmdToRun) -Wait -PassThru -NoNewWindow -ErrorAction Stop
            $exitCode = $proc.ExitCode
            if ($exitCode -eq 0 -or $exitCode -eq 3010 -or $exitCode -eq 1605) {
                Write-Log ('Uninstalled (exit {0}): {1}' -f $exitCode, $dispName) -Level 'OK'
                $CountProductsRemoved++
            } else {
                Write-Log ('Exit {0} for: {1}' -f $exitCode, $dispName) -Level 'WARN'
                $CountWarnings++
            }
        } catch {
            Write-Log ('Uninstall failed for {0}: {1}' -f $dispName, $_.Exception.Message) -Level 'WARN'
            $CountWarnings++
        }
    }

    Start-Sleep -Seconds 3
    $postProcs = Find-VendorProcesses
    foreach ($proc in $postProcs) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}

# ---------------------------------------------------------------------------
# STEP 5 - FILESYSTEM ARTIFACTS
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Host ('[Step 5/8] {0} filesystem artifacts...' -f $verb) -ForegroundColor Green
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Log ('[Step 5/8] {0} filesystem artifacts' -f $verb)

$PF86 = ${env:ProgramFiles(x86)}

$DirsToRemove = @(
    ('{0}\Okta'                                   -f $env:ProgramFiles),
    ('{0}\Okta'                                   -f $PF86),
    ('{0}\Okta'                                   -f $env:ProgramData),
    ('{0}\Okta\Okta LDAP Agent'                   -f $PF86),
    ('{0}\Okta\Okta AD Agent'                     -f $PF86),
    ('{0}\Okta\Okta RADIUS Agent'                 -f $PF86),
    ('{0}\Okta\On-Premises Provisioning Agent'    -f $PF86),
    ('{0}\Okta\On-Prem MFA'                       -f $PF86),
    ('{0}\Okta\Okta RSA SecurID Agent'            -f $PF86),
    ('{0}\ScaleFT'                                -f $env:ProgramFiles),
    ('{0}\ScaleFT'                                -f $PF86),
    ('{0}\ScaleFT'                                -f $env:ProgramData),
    ('{0}\Okta\ASA'                               -f $env:ProgramFiles),
    ('{0}\Okta\ASA'                               -f $PF86),
    'C:\Windows\System32\config\systemprofile\AppData\Local\scaleft',
    'C:\Windows\SysWOW64\config\systemprofile\AppData\Local\scaleft',
    ('{0}\Okta'    -f $env:LocalAppData),
    ('{0}\Okta'    -f $env:AppData),
    ('{0}\ScaleFT' -f $env:LocalAppData),
    ('{0}\ScaleFT' -f $env:AppData),
    ('{0}\okta'    -f $env:TEMP),
    ('{0}\scaleft' -f $env:TEMP)
)

foreach ($dir in $DirsToRemove) {
    if ([string]::IsNullOrWhiteSpace($dir)) { continue }
    if (Test-Path $dir) {
        $AuditDirs++
        if ($AuditOnly) {
            Write-Log ('WOULD DELETE dir: {0}' -f $dir) -Level 'FIND'
        } else {
            Write-Log ('ACTION: Removing: {0}' -f $dir) -Level 'ACT'
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-Log ('Removed: {0}' -f $dir) -Level 'OK'
                $CountDirsRemoved++
            } catch {
                Write-Log ('Could not remove {0}: {1}' -f $dir, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        }
    } else {
        Write-Log ('Not found: {0}' -f $dir) -Level 'SKIP'
    }
}

if ($AuditDirs -eq 0 -and $AuditOnly) { Write-Log 'No Okta/ScaleFT filesystem artifacts found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 6 - REGISTRY KEYS
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Host ('[Step 6/8] {0} registry keys...' -f $verb) -ForegroundColor Green
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Log ('[Step 6/8] {0} registry keys' -f $verb)

$RegKeysToRemove = @(
    'HKLM:\SOFTWARE\Okta',
    'HKLM:\SOFTWARE\WOW6432Node\Okta',
    'HKCU:\SOFTWARE\Okta',
    'HKLM:\SOFTWARE\ScaleFT',
    'HKLM:\SOFTWARE\WOW6432Node\ScaleFT',
    'HKCU:\SOFTWARE\ScaleFT',
    'HKLM:\SYSTEM\CurrentControlSet\Services\OktaLDAPAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\OktaADAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\OktaRADIUSAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\OktaProvisioningAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\OktaIWAServer',
    'HKLM:\SYSTEM\CurrentControlSet\Services\OktaVerify',
    'HKLM:\SYSTEM\CurrentControlSet\Services\sftd',
    'HKLM:\SYSTEM\CurrentControlSet\Services\scaleft-server-tools',
    'HKLM:\SYSTEM\CurrentControlSet\Services\scaleft-client-tools',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\OktaLDAPAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\OktaADAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\sftd',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OktaVerify',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OktaVerify'
)

foreach ($regKey in $RegKeysToRemove) {
    if (Test-Path $regKey) {
        $AuditRegKeys++
        if ($AuditOnly) {
            Write-Log ('WOULD DELETE key: {0}' -f $regKey) -Level 'FIND'
        } else {
            Write-Log ('ACTION: Removing key: {0}' -f $regKey) -Level 'ACT'
            try {
                Remove-Item -Path $regKey -Recurse -Force -ErrorAction Stop
                Write-Log ('Removed key: {0}' -f $regKey) -Level 'OK'
                $CountKeysRemoved++
            } catch {
                Write-Log ('Could not remove {0}: {1}' -f $regKey, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        }
    } else {
        Write-Log ('Not found: {0}' -f $regKey) -Level 'SKIP'
    }
}

# Dynamic Run/RunOnce scan
$RunKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($runKey in $RunKeys) {
    if (-not (Test-Path $runKey)) { continue }
    $keyObj = Get-Item -Path $runKey -ErrorAction SilentlyContinue
    if (-not $keyObj) { continue }
    $valueNames = $keyObj.GetValueNames()
    foreach ($valName in $valueNames) {
        $valData = $keyObj.GetValue($valName)
        if ($valData -match $VendorPathRegex) {
            $AuditRegKeys++
            if ($AuditOnly) {
                Write-Log ('WOULD DELETE Run value: {0}\{1} = {2}' -f $runKey, $valName, $valData) -Level 'FIND'
            } else {
                Write-Log ('ACTION: Removing Run value: {0}\{1}' -f $runKey, $valName) -Level 'ACT'
                try {
                    Remove-ItemProperty -Path $runKey -Name $valName -Force -ErrorAction Stop
                    Write-Log ('Removed Run value: {0}\{1}' -f $runKey, $valName) -Level 'OK'
                    $CountKeysRemoved++
                } catch {
                    Write-Log ('Could not remove Run value {0}: {1}' -f $valName, $_.Exception.Message) -Level 'WARN'
                    $CountWarnings++
                }
            }
        }
    }
}

if ($AuditRegKeys -eq 0 -and $AuditOnly) { Write-Log 'No Okta/ScaleFT registry keys found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 7 - SCHEDULED TASKS
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Host ('[Step 7/8] {0} scheduled tasks...' -f $verb) -ForegroundColor Green
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Log ('[Step 7/8] {0} scheduled tasks' -f $verb)

$TaskPatterns = @('Okta', 'ScaleFT', 'scaleleft', 'sftd', 'OktaVerify', 'OktaLDAP', 'Advanced Server Access')
$allTasks     = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $allTasks) {
    $nameMatch = $false
    $pathMatch = $false
    foreach ($pat in $TaskPatterns) {
        if ($task.TaskName -match [regex]::Escape($pat)) { $nameMatch = $true; break }
    }
    foreach ($pat in $TaskPatterns) {
        if ($task.TaskPath -match [regex]::Escape($pat)) { $pathMatch = $true; break }
    }
    if ($nameMatch -or $pathMatch) {
        $AuditTasks++
        if ($AuditOnly) {
            Write-Log ('WOULD DELETE task: {0}{1}' -f $task.TaskPath, $task.TaskName) -Level 'FIND'
        } else {
            Write-Log ('ACTION: Removing task: {0}{1}' -f $task.TaskPath, $task.TaskName) -Level 'ACT'
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                Write-Log ('Removed task: {0}{1}' -f $task.TaskPath, $task.TaskName) -Level 'OK'
                $CountTasksRemoved++
            } catch {
                Write-Log ('Could not remove task {0}: {1}' -f $task.TaskName, $_.Exception.Message) -Level 'WARN'
                $CountWarnings++
            }
        }
    }
}

if ($AuditTasks -eq 0) { Write-Log 'No Okta/ScaleFT scheduled tasks found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# STEP 8 - FIREWALL RULES
# ---------------------------------------------------------------------------
Write-Host ''
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Host ('[Step 8/8] {0} firewall rules...' -f $verb) -ForegroundColor Green
$verb = 'Discovering'
if (-not $AuditOnly) { $verb = 'Removing' }
Write-Log ('[Step 8/8] {0} firewall rules' -f $verb)

$FwPatterns = @('Okta', 'ScaleFT', 'sftd', 'ASA Agent', 'OktaVerify', 'Advanced Server Access')

try {
    $allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue
    foreach ($rule in $allRules) {
        $isMatch = $false
        foreach ($pat in $FwPatterns) {
            if ($rule.DisplayName -match [regex]::Escape($pat)) { $isMatch = $true; break }
        }
        if ($isMatch) {
            $AuditRules++
            if ($AuditOnly) {
                Write-Log ('WOULD DELETE firewall rule: {0} | Direction: {1} | Action: {2}' -f $rule.DisplayName, $rule.Direction, $rule.Action) -Level 'FIND'
            } else {
                Write-Log ('ACTION: Removing rule: {0}' -f $rule.DisplayName) -Level 'ACT'
                try {
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                    Write-Log ('Removed rule: {0}' -f $rule.DisplayName) -Level 'OK'
                    $CountRulesRemoved++
                } catch {
                    Write-Log ('Could not remove rule {0}: {1}' -f $rule.DisplayName, $_.Exception.Message) -Level 'WARN'
                    $CountWarnings++
                }
            }
        }
    }
} catch {
    Write-Log ('Firewall enumeration failed: {0}' -f $_.Exception.Message) -Level 'WARN'
    $CountWarnings++
}

if ($AuditRules -eq 0) { Write-Log 'No Okta/ScaleFT firewall rules found.' -Level 'SKIP' }

# ---------------------------------------------------------------------------
# POST-REMOVAL VERIFICATION SCAN (uninstall mode only)
# ---------------------------------------------------------------------------
$RemainingProducts = New-Object System.Collections.Generic.List[string]

if (-not $AuditOnly) {
    Write-Host ''
    Write-Log 'Running post-removal verification scan...'

    $SeenCheck = New-Object System.Collections.Generic.HashSet[string]
    foreach ($regBase in $UninstallRegPaths) {
        if (-not (Test-Path $regBase)) { continue }
        $subKeys = Get-ChildItem -Path $regBase -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            $dispName    = $key.GetValue('DisplayName')
            $productCode = $key.PSChildName
            if ((Test-IsVendorMatch $dispName) -and (-not $SeenCheck.Contains($productCode))) {
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
Write-Host ('=' * 62) -ForegroundColor Cyan

if ($AuditOnly) {
    $TotalFindings = $AuditServices + $AuditProcesses + $AuditProducts + $AuditDirs + $AuditRegKeys + $AuditTasks + $AuditRules

    Write-Host '  AUDIT SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 62) -ForegroundColor Cyan
    Write-Host ('  Services found       : {0}' -f $AuditServices)
    Write-Host ('  Processes found      : {0}' -f $AuditProcesses)
    Write-Host ('  Products found       : {0}' -f $AuditProducts)
    Write-Host ('  Filesystem artifacts : {0}' -f $AuditDirs)
    Write-Host ('  Registry keys found  : {0}' -f $AuditRegKeys)
    Write-Host ('  Scheduled tasks found: {0}' -f $AuditTasks)
    Write-Host ('  Firewall rules found : {0}' -f $AuditRules)
    Write-Host ('  Total findings       : {0}' -f $TotalFindings)
    Write-Host ('  Elapsed              : {0:mm\:ss\.fff}' -f $Elapsed)
    Write-Host ('  Log                  : {0}' -f $LogFile)
    Write-Host ('=' * 62) -ForegroundColor Cyan

    Write-Log ('AUDIT SUMMARY: svc={0} proc={1} prod={2} dir={3} reg={4} task={5} fw={6} total={7} elapsed={8:mm\:ss\.fff}' -f
        $AuditServices, $AuditProcesses, $AuditProducts,
        $AuditDirs, $AuditRegKeys, $AuditTasks,
        $AuditRules, $TotalFindings, $Elapsed)

    Save-Log

    Write-Host ''
    if ($TotalFindings -gt 0) {
        Write-Host ('  [FIND] {0} Okta/ScaleFT component(s) detected on this host.' -f $TotalFindings) -ForegroundColor Magenta
        Write-Host '  Re-run with -U to perform removal.' -ForegroundColor Yellow
        Write-Host ''
        exit 1
    } else {
        Write-Host '  [OK] No Okta/ScaleFT components detected on this host.' -ForegroundColor Green
        Write-Host ''
        exit 0
    }
} else {
    Write-Host '  REMOVAL SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 62) -ForegroundColor Cyan
    Write-Host ('  Services stopped     : {0}' -f $CountServicesStopped)
    Write-Host ('  Processes killed     : {0}' -f $CountProcessesKilled)
    Write-Host ('  Products uninstalled : {0}' -f $CountProductsRemoved)
    Write-Host ('  Directories removed  : {0}' -f $CountDirsRemoved)
    Write-Host ('  Registry keys removed: {0}' -f $CountKeysRemoved)
    Write-Host ('  Scheduled tasks rm   : {0}' -f $CountTasksRemoved)
    Write-Host ('  Firewall rules rm    : {0}' -f $CountRulesRemoved)
    Write-Host ('  Warnings             : {0}' -f $CountWarnings)
    Write-Host ('  Remaining products   : {0}' -f $RemainingProducts.Count)
    Write-Host ('  Elapsed              : {0:mm\:ss\.fff}' -f $Elapsed)
    Write-Host ('  Log                  : {0}' -f $LogFile)
    Write-Host ('=' * 62) -ForegroundColor Cyan

    Write-Log ('REMOVAL SUMMARY: svc={0} proc={1} prod={2} dir={3} reg={4} task={5} fw={6} warn={7} remain={8} elapsed={9:mm\:ss\.fff}' -f
        $CountServicesStopped, $CountProcessesKilled, $CountProductsRemoved,
        $CountDirsRemoved, $CountKeysRemoved, $CountTasksRemoved,
        $CountRulesRemoved, $CountWarnings, $RemainingProducts.Count, $Elapsed)

    Save-Log

    Write-Host ''
    Write-Host '  NOTE: A reboot is strongly recommended after removing Okta RADIUS/AD/IWA agents.' -ForegroundColor Yellow

    if ($RemainingProducts.Count -gt 0) {
        Write-Host ('  [WARN] {0} product(s) still registered. Manual review required.' -f $RemainingProducts.Count) -ForegroundColor Yellow
        Write-Host ''
        exit 1
    }

    Write-Host '  [OK] Okta/ScaleFT removal complete. No registered products remain.' -ForegroundColor Green
    Write-Host ''
    exit 0
}
