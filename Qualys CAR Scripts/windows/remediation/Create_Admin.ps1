<#
.SYNOPSIS
    Create, repair, or remove a local administrator user on a Windows host.
    Deployed via Qualys Cloud Agent / CAR using UI-defined POSITIONAL
    parameters.

.DESCRIPTION
    Two modes selected via the RunMode parameter:

        RunMode = 1   Create-or-Repair
                        If the user is absent, create it, add to
                        Administrators, set the password, and mark
                        PasswordNeverExpires = true (break-glass pattern).
                        If the user is already present, ensure it is
                        enabled, still in Administrators, and reset the
                        password per the Password parameter.

        RunMode = 2   Remove
                        Terminate all processes owned by the user,
                        remove from Administrators, and delete the local
                        user account. The profile directory under
                        C:\Users\<username>\ is intentionally LEFT IN
                        PLACE (data-preserving).

    Password sourcing:

        "CHANGE_ME"   Sentinel placeholder. Script REFUSES to run while
                      this value is present. Forces the operator to set
                      a real value in the CAR UI before deployment.
        "<literal>"   Use the supplied string as the password.
        ""            Invalid on Windows (account needs a password to be
                      usable). Script errors out with a clear message.

    SECURITY NOTE: the password is supplied via a CAR UI parameter.
    Anyone with script-edit rights on the CAR policy sees this value.
    Rotate the password after first run and whenever policy editors
    change.

# ==============================================================================
# CAR UI PARAMETERS (define on Script Details page in this EXACT order):
# ==============================================================================
#
#   Position 1:  Username
#     Type:      String
#     Required:  Yes
#     Default:   (none)
#     Example:   TEMPADMIN
#     Purpose:   Local account to create, repair, or remove. Must be a
#                valid POSIX-ish name (letters, digits, underscore, dash).
#
#   Position 2:  Password
#     Type:      String   (mark as sensitive / masked if CAR version supports)
#     Required:  Yes
#     Default:   (none)
#     Example:   <strong-literal>
#     Purpose:   Initial password for the account. Masked as *** in the
#                runtime banner and log file. NEVER leave as CHANGE_ME.
#
#   Position 3:  RunMode
#     Type:      String
#     Required:  No
#     Default:   1
#     Allowed:   1 = create or repair (non-destructive if account exists)
#                2 = remove (terminates user processes, deletes account)
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Go to: Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details tab:
#        Name:        Create Admin User (Windows)
#        Description: Create, repair, or remove a local Administrator user.
#        Platform:    Windows
#        Interpreter: PowerShell
#        Upload:      Create_Admin.ps1 from this repo
#   4. Parameters tab (ORDER MATTERS, positional):
#        Add parameter: Username   (String, Required, no default)
#        Add parameter: Password   (String, Required, mark sensitive/masked)
#        Add parameter: RunMode    (String, Optional, default "1")
#   5. Save. Attach the script to a CAR Job that targets the intended assets.
#   6. Runtime output is captured by the Qualys Cloud Agent. Review via
#        CAR -> Jobs -> <job> -> Results -> Script Output.
#
# CLI INVOCATION (local testing):
#   .\Create_Admin.ps1 <Username> <Password> <RunMode>
#   .\Create_Admin.ps1 TEMPADMIN 'MyP@ss!' 1
#
# CAR INVOKES EQUIVALENT TO:
#   powershell.exe -ExecutionPolicy Bypass -File Create_Admin.ps1 `
#                  "<Username>" "<Password>" "<RunMode>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional params win. If any param is omitted or empty, the script
#   checks the same-named environment variable next ($env:Username,
#   $env:Password, $env:RunMode). Only after BOTH are empty does the
#   script error. This lets local developers set env vars once and rerun
#   without retyping positional args every time.
#
# ==============================================================================

.NOTES
    Author:      Brian Canaday
    Team:        netsecops-76
    Version:     3.0.1
    Created:     2026-04-20
    Script:      Create_Admin.ps1

    Changelog:
        3.0.1 - 2026-04-21 - Mode 2 process-kill: catch the specific
                              ProcessCommandException thrown when a PID
                              has already exited between the Win32_Process
                              enumeration and the Stop-Process call, and
                              log it at [--] (skip) level without bumping
                              the warning counter. A clean Mode 2 run now
                              exits 0 instead of 1 when processes
                              self-terminate during session teardown.
                              Adds a summary line when any "already gone"
                              PIDs are observed.
        3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces the
                              hard-coded ENVIRONMENT block with a POSITIONAL
                              param() block consumable by Qualys CAR UI
                              parameters. Dual-invocation support: param
                              first, fallback to $env:<Name>. ASCII-only
                              log output. Password masked in banner.
        2.0.0 - 2026-04-20 - Rewrite. Replaces the v1.x diagnostic-only
                              script with a real create/repair/remove
                              worker. Introduces the env block at the
                              top and explicit RunMode selector.
        1.x.x - 2026-03-30 - Diagnostic script (superseded).

    Requirements:
        Windows PowerShell 5.1, local Administrator or SYSTEM privileges.
        No interactive prompts; safe for CAR / remote deployment.

    Exit Codes:
        0 = Success
        1 = Completed with warnings (e.g. partial cleanup in Mode 2)
        2 = Fatal error / insufficient privileges / bad parameters

    Security:
        - Password travels through the CAR UI parameter. Anyone with
          policy-edit rights sees it. Rotate after first run.
        - Script log output is captured by the Qualys Cloud Agent log
          channel. Treat that channel as credential-sensitive.
        - PasswordNeverExpires is intentional for a break-glass account.
        - Profile dir (%USERPROFILE%) is NOT deleted in Mode 2 - data
          preservation policy. Clean manually if required.
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Position=0)]
    [string]$Username = '',

    [Parameter(Position=1)]
    [string]$Password = '',

    [Parameter(Position=2)]
    [string]$RunMode = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# PARAMETER RESOLUTION: positional first, env fallback, defaults last.
# ============================================================
if ([string]::IsNullOrWhiteSpace($Username)) { $Username = $env:Username }
if ([string]::IsNullOrWhiteSpace($Password)) { $Password = $env:Password }
if ([string]::IsNullOrWhiteSpace($RunMode))  { $RunMode  = $env:RunMode  }
if ([string]::IsNullOrWhiteSpace($RunMode))  { $RunMode  = '1' }

# Validate RunMode -> numeric for switch compatibility.
if ($RunMode -ne '1' -and $RunMode -ne '2') {
    Write-Host ("ERROR: RunMode must be '1' or '2'; received '{0}'." -f $RunMode) -ForegroundColor Red
    exit 2
}
$RunModeNum = [int]$RunMode


# -------- globals / state --------
$ScriptName    = 'Create_Admin.ps1'
$ScriptVersion = '3.0.1'
$StartedAt     = Get-Date
$HostName      = $env:COMPUTERNAME

$CountWarnings = 0
$CountErrors   = 0
$LogLines      = New-Object System.Collections.Generic.List[object]

# ============================================================
# LOGGING HELPERS
# ============================================================
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level
    )
    if ([string]::IsNullOrEmpty($Level)) { $Level = 'INFO' }
    $line = '{0}  [{1}]  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.PadRight(5), $Message
    $null = $LogLines.Add($line)
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow  ; break }
        'OK'    { Write-Host $line -ForegroundColor Green   ; break }
        'FIND'  { Write-Host $line -ForegroundColor Magenta ; break }
        'ERROR' { Write-Host $line -ForegroundColor Red     ; break }
        '--'    { Write-Host $line -ForegroundColor DarkGray; break }
        default { Write-Host $line }
    }
}

function Add-Warning { param([string]$Message); $script:CountWarnings++; Write-Log $Message -Level 'WARN' }
function Add-Err     { param([string]$Message); $script:CountErrors++;   Write-Log $Message -Level 'ERROR' }

# ============================================================
# HELPERS
# ============================================================

function Resolve-EffectivePassword {
    # Returns the plaintext password to use, or $null if invalid.
    if ([string]::IsNullOrEmpty($Password)) {
        Add-Err 'Password is empty. Windows accounts require a password. Supply via CAR parameter 2 or $env:Password.'
        return $null
    }
    if ($Password -eq 'CHANGE_ME') {
        Add-Err 'Password is still the "CHANGE_ME" placeholder - refusing to run. Set a real value in the CAR UI parameter before deployment.'
        return $null
    }
    Write-Log 'Literal password supplied via CAR parameter - rotate after first run and whenever policy editors change.' -Level 'WARN'
    return $Password
}

function Test-UserExists {
    param([string]$Name)
    try { $null = Get-LocalUser -Name $Name -ErrorAction Stop; return $true }
    catch { return $false }
}

function Test-InAdministrators {
    param([string]$Name)
    try {
        $m = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
             Where-Object { $_.Name -like "*\$Name" }
        return [bool]$m
    } catch { return $false }
}

# ============================================================
# MODE 1 - CREATE OR REPAIR
# ============================================================
function Invoke-CreateOrRepair {
    param([string]$EffectivePassword)

    $securePw = ConvertTo-SecureString $EffectivePassword -AsPlainText -Force

    if (Test-UserExists -Name $Username) {
        Write-Log ("User '{0}' exists - entering repair mode." -f $Username) -Level 'INFO'

        # Ensure enabled
        try {
            $u = Get-LocalUser -Name $Username -ErrorAction Stop
            if (-not $u.Enabled) {
                Enable-LocalUser -Name $Username -ErrorAction Stop
                Write-Log "Enabled disabled account '$Username'." -Level 'OK'
            } else {
                Write-Log "Account '$Username' already enabled." -Level '--'
            }
        } catch {
            Add-Err ('Failed to ensure account enabled: {0}' -f $_.Exception.Message)
        }

        # Reset password
        try {
            Set-LocalUser -Name $Username -Password $securePw -PasswordNeverExpires $true -ErrorAction Stop
            Write-Log "Reset password and set PasswordNeverExpires=true." -Level 'OK'
        } catch {
            Add-Err ('Failed to reset password: {0}' -f $_.Exception.Message)
        }
    } else {
        Write-Log ("User '{0}' does not exist - creating." -f $Username) -Level 'INFO'
        try {
            New-LocalUser -Name $Username `
                          -Password $securePw `
                          -FullName $Username `
                          -Description 'Emergency recovery - Qualys provisioned' `
                          -PasswordNeverExpires `
                          -UserMayNotChangePassword:$false `
                          -AccountNeverExpires `
                          -ErrorAction Stop | Out-Null
            Write-Log "Created user '$Username'." -Level 'OK'
        } catch {
            Add-Err ('Failed to create user: {0}' -f $_.Exception.Message)
            return
        }
    }

    # Ensure Administrators membership
    if (Test-InAdministrators -Name $Username) {
        Write-Log "'$Username' is already a member of Administrators." -Level '--'
    } else {
        try {
            Add-LocalGroupMember -Group 'Administrators' -Member $Username -ErrorAction Stop
            Write-Log "Added '$Username' to Administrators." -Level 'OK'
        } catch {
            Add-Err ('Failed to add to Administrators: {0}' -f $_.Exception.Message)
        }
    }
}

# ============================================================
# MODE 2 - REMOVE
# ============================================================
function Invoke-Remove {
    if (-not (Test-UserExists -Name $Username)) {
        Write-Log ("User '{0}' does not exist - nothing to remove." -f $Username) -Level '--'
        return
    }

    Write-Log "WARNING: Mode 2 will remove user '$Username' and kill its active processes." -Level 'WARN'
    Write-Log "Profile directory under C:\Users\ will be LEFT IN PLACE." -Level 'INFO'

    # 1. Kill all processes owned by the user
    try {
        $ownedPids = @()
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
        foreach ($p in $procs) {
            try {
                $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($owner.User -eq $Username) { $ownedPids += [int]$p.ProcessId }
            } catch {}
        }
        if ($ownedPids.Count -gt 0) {
            Write-Log ("Killing {0} process(es) owned by '{1}'." -f $ownedPids.Count, $Username) -Level 'INFO'
            $killedCount = 0
            $goneCount   = 0
            foreach ($pid_ in $ownedPids) {
                try {
                    Stop-Process -Id $pid_ -Force -ErrorAction Stop
                    $killedCount++
                }
                catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
                    # Race: the process exited between Win32_Process enumeration
                    # and Stop-Process. Session teardown often cascades and kills
                    # child processes before our loop reaches them. This is
                    # success, not failure - log at SKIP level without bumping
                    # the warning counter.
                    Write-Log ('Process {0} already gone (exited on its own).' -f $pid_) -Level '--'
                    $goneCount++
                }
                catch {
                    Add-Warning ('Failed to kill pid {0}: {1}' -f $pid_, $_.Exception.Message)
                }
            }
            if ($goneCount -gt 0) {
                Write-Log ("Summary: {0} killed, {1} exited on their own during teardown." -f $killedCount, $goneCount) -Level '--'
            }
        } else {
            Write-Log "No active processes owned by '$Username'." -Level '--'
        }
    } catch {
        Add-Warning ('Process enumeration failed: {0}' -f $_.Exception.Message)
    }

    # 2. Remove from Administrators (best-effort - user may not be a member)
    try {
        if (Test-InAdministrators -Name $Username) {
            Remove-LocalGroupMember -Group 'Administrators' -Member $Username -ErrorAction Stop
            Write-Log "Removed '$Username' from Administrators." -Level 'OK'
        }
    } catch {
        Add-Warning ('Failed to remove from Administrators: {0}' -f $_.Exception.Message)
    }

    # 3. Delete local user account
    try {
        Remove-LocalUser -Name $Username -ErrorAction Stop
        Write-Log "Deleted local user '$Username'." -Level 'OK'
    } catch {
        Add-Err ('Failed to delete user: {0}' -f $_.Exception.Message)
    }
}

# ============================================================
# VERIFY
# ============================================================
function Invoke-Verify {
    param([int]$ExpectedMode)
    $userPresent   = Test-UserExists -Name $Username
    $inAdmins = $false
    if ($userPresent) { $inAdmins = Test-InAdministrators -Name $Username }

    Write-Log '----------------------------------------------------------------' -Level 'INFO'
    Write-Log ('User present       : {0}' -f $userPresent) -Level 'FIND'
    Write-Log ('In Administrators  : {0}' -f $inAdmins)    -Level 'FIND'

    if ($ExpectedMode -eq 1) {
        if ($userPresent -and $inAdmins) {
            Write-Log 'Mode 1 outcome: PASS' -Level 'OK'
        } else {
            Add-Warning 'Mode 1 outcome: FAIL - user missing or not in Administrators.'
        }
    } else {
        if (-not $userPresent) {
            Write-Log 'Mode 2 outcome: PASS (user absent).' -Level 'OK'
        } else {
            Add-Warning 'Mode 2 outcome: FAIL - user still present.'
        }
    }
}

# ============================================================
# MAIN
# ============================================================
Write-Log '================================================================' -Level 'INFO'
Write-Log ('{0} v{1} on {2}' -f $ScriptName, $ScriptVersion, $HostName)     -Level 'INFO'
Write-Log ('Started at         : {0}' -f $StartedAt.ToString('o'))          -Level 'INFO'
Write-Log ('Target username    : {0}' -f $Username)                         -Level 'INFO'
$modeLabel = 'unknown'
if ($RunModeNum -eq 1) { $modeLabel = 'create-or-repair' }
if ($RunModeNum -eq 2) { $modeLabel = 'remove' }
Write-Log ('Run mode           : {0} ({1})' -f $RunMode, $modeLabel) -Level 'INFO'
Write-Log ('Password (masked)  : ***') -Level 'INFO'
Write-Log '================================================================' -Level 'INFO'

if ([string]::IsNullOrWhiteSpace($Username)) {
    Add-Err 'Username is empty. Supply via CAR parameter 1 or $env:Username.'
    exit 2
}

switch ($RunModeNum) {
    1 {
        $pw = Resolve-EffectivePassword
        if ($null -eq $pw) { exit 2 }
        Invoke-CreateOrRepair -EffectivePassword $pw
        Invoke-Verify -ExpectedMode 1
    }
    2 {
        Invoke-Remove
        Invoke-Verify -ExpectedMode 2
    }
    default {
        Add-Err ('Invalid RunMode={0}. Must be 1 (create-or-repair) or 2 (remove).' -f $RunMode)
        exit 2
    }
}

$elapsed = ((Get-Date) - $StartedAt).TotalSeconds
Write-Log ('Warnings: {0}   Errors: {1}   Elapsed: {2:N1}s' -f $CountWarnings, $CountErrors, $elapsed) -Level 'INFO'

if ($CountErrors -gt 0)   { exit 2 }
if ($CountWarnings -gt 0) { exit 1 }
exit 0
