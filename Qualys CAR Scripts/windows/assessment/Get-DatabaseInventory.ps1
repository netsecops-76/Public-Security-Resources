<#
.SYNOPSIS
    Inventories database management systems (DBMS) installed and running on a
    Windows host. Reports host identity, instance details, listening endpoints,
    database catalogs, and authentication configuration.

.DESCRIPTION
    Read-only discovery script designed for unattended execution via Qualys CAR
    or equivalent endpoint-management tooling. Makes NO changes to the system,
    opens NO outbound network connections (except the opt-in probes below),
    and modifies NO database state.

    Coverage (current):
        Microsoft SQL Server (full, Express, LocalDB)
        SQL Server Analysis / Reporting / Integration Services (SSAS/SSRS/SSIS)
        Oracle Database
        MySQL / MariaDB / Percona Server
        PostgreSQL (incl. Greenplum)
        MongoDB
        Redis
        IBM Db2
        SAP ASE (Sybase) / SAP MaxDB
        Informix
        Firebird
        Teradata
        InfluxDB
        ClickHouse
        Couchbase
        Neo4j
        Elasticsearch / OpenSearch
        RavenDB
        etcd                                            (new in v2.0)
        HashiCorp Consul                                (new in v2.0)
        Memcached (cache, reported as DBMS-adjacent)    (new in v2.0)
        Prometheus                                      (new in v2.0)
        H2 / HSQLDB / Apache Derby (server mode only)   (new in v2.0)
        SQLite (filesystem scan, opt-in)                (new in v2.0)
        Microsoft Access (.mdb/.accdb scan, opt-in)     (new in v2.0)

    Per-instance output:
        Host identity (hostname, FQDN, domain, IPv4/IPv6, OS version)
        Product / edition / version / patch level
        Instance name + instance ID
        Installation + data paths
        Service name, state, start mode, service account
        PIDs and process owner(s)
        Listening IPs + ports + protocol
        Database/catalog names (config/filesystem first; deep-probe optional)
        Authentication mode and source (registry key or config file + line)
        SPN registrations (with -IncludeAdLookup)
        TLS / encryption posture

# ==============================================================================
# CAR UI PARAMETERS (define on Script Details page in this EXACT order):
# ==============================================================================
#
#   Position 1:  DeepProbe                 (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off (case-insensitive)
#     Purpose:   Opt-in. Open local trust-based queries against detected
#                instances to enumerate catalog names. DISRUPTION NOTE:
#                queries will appear in DBA audit logs. Coordinate with DBAs
#                before fleet rollout.
#
#   Position 2:  IncludeAdLookup           (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Opt-in. Enrich domain service accounts + SPNs with AD
#                lookups via Get-ADUser (RSAT) or ADSI. DISRUPTION NOTE:
#                fleet-wide LDAP fan-out can spike DC load. Pair with
#                scheduled jitter across the CAR population.
#
#   Position 3:  IncludeEmbeddedEngines    (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Opt-in. Walk the filesystem for SQLite and MS Access
#                files. Scoped to EmbeddedPaths with a 256 KB size floor,
#                magic-byte validation, 500-hit cap per engine, and
#                always-excluded directories (user profile, WinSxS, etc).
#
#   Position 4:  EmbeddedPaths             (String, Default "")
#     Example:   C:\inetpub,C:\ProgramData,C:\Program Files
#     Purpose:   Comma-separated directories to scan when
#                IncludeEmbeddedEngines is Yes. Empty means use built-in
#                defaults (see below).
#
#   Position 5:  SkipNetwork               (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Skip Get-NetTCPConnection socket enumeration. Use on
#                hosts with very large connection tables.
#
#   Position 6:  DryRun                    (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   With DeepProbe=Yes, list which instances WOULD be probed
#                WITHOUT opening any connection. Recommended for first-
#                time DeepProbe fleet rollout.
#
#   Position 7:  Retain                    (String, Default "1")
#     Purpose:   Integer count (as string). Number of run outputs kept on
#                disk including the current run; older inventory_*.log /
#                .json files in OutputPath are deleted at run start.
#
#   Position 8:  JsonOnly                  (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Suppress human-readable console output; only the JSON
#                document is emitted on stdout. The .log and .json side-
#                car files are still written to disk.
#
#   Position 9:  OutputPath                (String, Default "")
#     Example:   C:\CAR\dbinv
#     Purpose:   Override default output dir (C:\ProgramData\DatabaseInventory).
#                Empty uses the default.
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details tab:
#        Name:        Database Inventory (Windows)
#        Platform:    Windows
#        Interpreter: PowerShell
#        Upload:      Get-DatabaseInventory.ps1
#   4. Parameters tab (ORDER MATTERS - positional). Add 9 parameters in
#      the order listed above, each as type String with the documented
#      default.
#   5. Save. Output is captured by the Qualys Cloud Agent plus written to
#      files under C:\ProgramData\DatabaseInventory\.
#   6. FIRST FLEET RUN: keep DeepProbe=No and IncludeAdLookup=No. Run
#      audit-shape discovery only to confirm baseline output across
#      representative hosts before enabling opt-in probes.
#
# CLI INVOCATION (local testing):
#   .\Get-DatabaseInventory.ps1                                     # full defaults
#   .\Get-DatabaseInventory.ps1 Yes No No "" No No 1 No ""          # just DeepProbe
#   .\Get-DatabaseInventory.ps1 Yes Yes Yes "C:\data" No No 3 Yes "C:\CAR\dbinv"
#
# CAR INVOKES EQUIVALENT TO:
#   powershell.exe -ExecutionPolicy Bypass -File Get-DatabaseInventory.ps1 `
#                  "<DeepProbe>" "<IncludeAdLookup>" "<IncludeEmbeddedEngines>" `
#                  "<EmbeddedPaths>" "<SkipNetwork>" "<DryRun>" "<Retain>" `
#                  "<JsonOnly>" "<OutputPath>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional params win. If empty, script checks the same-named env var
#   ($env:DeepProbe, $env:IncludeAdLookup, etc.). Defaults applied last.
#   Legacy switch parameters (-DeepProbe, -IncludeAdLookup, etc.) are
#   still accepted when invoked with the old PowerShell switch syntax;
#   this keeps older test harnesses working.
#
# ==============================================================================

.NOTES
    Author:      Brian Canaday
    Team:        netsecops-76
    Version:     3.0.0
    Created:     2026-04-14
    Script:      Get-DatabaseInventory.ps1

    Changelog:
        3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces
                              switch parameters with 9 POSITIONAL string
                              parameters consumable by Qualys CAR UI.
                              Dual-invocation support: positional first,
                              $env fallback, defaults last. Legacy switch
                              aliases still accepted. ASCII-only log
                              output. No $var = if() assignments.
        2.0.0 - 2026-04-14 - Backlog-engine expansion:
                             + Tier 1 services: etcd, Consul, Memcached,
                               Prometheus, H2/HSQLDB/Derby (server mode).
                             + Tier 2 filesystem-scan (opt-in, gated behind
                               -IncludeEmbeddedEngines): SQLite, MS Access.
                             Tier 3 engines (LevelDB/RocksDB) intentionally
                             skipped - see backlog note below.
        1.0.0 - 2026-04-14 - Initial release. PS 5.1 compliant, CAR-ready.

    Requirements:
        Windows PowerShell 5.1, Local Administrator or SYSTEM privileges.
        No interactive prompts; safe for CAR/remote deployment.

    Exit Codes:
        0 = Scan completed cleanly
        1 = Scan completed with collection warnings
        2 = Insufficient privileges (enforced by #Requires)

    Output:
        <OutputPath>\inventory_<yyyyMMdd_HHmmss>.log   (human-readable)
        <OutputPath>\inventory_<yyyyMMdd_HHmmss>.json  (machine-readable)

    Backlog (databases to consider adding in future versions):
        - LevelDB / RocksDB - intentionally skipped. These are *embedded
          library* KV engines (not servers), have no network port and no
          authentication, and ship inside many databases this script already
          detects (Cassandra, InfluxDB, Elasticsearch, CockroachDB, Qdrant,
          TiKV, ...). To get useful signal, detect the parent application
          instead and annotate its storage engine in that record. Folding
          this work back into the backlog as "detect specific application-
          layer databases that embed LevelDB/RocksDB".
        - Application-tier NoSQL (Qdrant, TiKV, CockroachDB, Pilosa, etc.).
        - Oracle Autonomous / managed-service endpoints (via connection
          strings found on the host).

    Safety:
        - Read-only throughout. No writes to registry, files, services, or DBs.
        - No outbound network connections except opt-in probes.
        - Win32_Product NOT used (avoids installer reconfigure pass).
        - Config files parsed read-only; password/secret values redacted.
#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName='Positional')]
param(
    # ---- CAR positional params (strings) ----
    [Parameter(ParameterSetName='Positional', Position=0)]
    [string]$DeepProbeParam = '',

    [Parameter(ParameterSetName='Positional', Position=1)]
    [string]$IncludeAdLookupParam = '',

    [Parameter(ParameterSetName='Positional', Position=2)]
    [string]$IncludeEmbeddedEnginesParam = '',

    [Parameter(ParameterSetName='Positional', Position=3)]
    [string]$EmbeddedPathsParam = '',

    [Parameter(ParameterSetName='Positional', Position=4)]
    [string]$SkipNetworkParam = '',

    [Parameter(ParameterSetName='Positional', Position=5)]
    [string]$DryRunParam = '',

    [Parameter(ParameterSetName='Positional', Position=6)]
    [string]$RetainParam = '',

    [Parameter(ParameterSetName='Positional', Position=7)]
    [string]$JsonOnlyParam = '',

    [Parameter(ParameterSetName='Positional', Position=8)]
    [string]$OutputPathParam = '',

    # ---- Legacy switch aliases (for backward compatibility with older calls) ----
    [Parameter(ParameterSetName='LegacySwitches')]
    [switch]$DeepProbe,
    [Parameter(ParameterSetName='LegacySwitches')]
    [switch]$IncludeAdLookup,
    [Parameter(ParameterSetName='LegacySwitches')]
    [switch]$IncludeEmbeddedEngines,
    [Parameter(ParameterSetName='LegacySwitches')]
    [string]$EmbeddedPaths = '',
    [Parameter(ParameterSetName='LegacySwitches')]
    [switch]$SkipNetwork,
    [Parameter(ParameterSetName='LegacySwitches')]
    [switch]$DryRun,
    [Parameter(ParameterSetName='LegacySwitches')]
    [int]$Retain = 0,
    [Parameter(ParameterSetName='LegacySwitches')]
    [switch]$JsonOnly,
    [Parameter(ParameterSetName='LegacySwitches')]
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================================
# TRUTHY + PARAMETER RESOLUTION
# ============================================================================
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

# Resolve each logical parameter: positional string -> env var -> legacy switch -> default.
# The Positional parameter set binds when at least one positional is provided;
# otherwise the legacy switches bind. Either way, the *Bool values here are
# the single source of truth for the rest of the script.

function Resolve-CarString {
    param(
        [string]$PositionalValue,
        [string]$EnvName,
        [string]$Default = ''
    )
    if (-not [string]::IsNullOrWhiteSpace($PositionalValue)) { return $PositionalValue }
    $envVal = [Environment]::GetEnvironmentVariable($EnvName)
    if (-not [string]::IsNullOrWhiteSpace($envVal)) { return $envVal }
    return $Default
}

# Resolve strings with env fallback
$DeepProbeStr              = Resolve-CarString $DeepProbeParam              'DeepProbe'              ''
$IncludeAdLookupStr        = Resolve-CarString $IncludeAdLookupParam        'IncludeAdLookup'        ''
$IncludeEmbeddedEnginesStr = Resolve-CarString $IncludeEmbeddedEnginesParam 'IncludeEmbeddedEngines' ''
$EmbeddedPathsStr          = Resolve-CarString $EmbeddedPathsParam          'EmbeddedPaths'          ''
$SkipNetworkStr            = Resolve-CarString $SkipNetworkParam            'SkipNetwork'            ''
$DryRunStr                 = Resolve-CarString $DryRunParam                 'DryRun'                 ''
$RetainStr                 = Resolve-CarString $RetainParam                 'Retain'                 ''
$JsonOnlyStr               = Resolve-CarString $JsonOnlyParam               'JsonOnly'               ''
$OutputPathStr             = Resolve-CarString $OutputPathParam             'OutputPath'             ''

# Convert strings to typed values
$DeepProbeBool              = ConvertTo-CarBool $DeepProbeStr
$IncludeAdLookupBool        = ConvertTo-CarBool $IncludeAdLookupStr
$IncludeEmbeddedEnginesBool = ConvertTo-CarBool $IncludeEmbeddedEnginesStr
$SkipNetworkBool            = ConvertTo-CarBool $SkipNetworkStr
$DryRunBool                 = ConvertTo-CarBool $DryRunStr
$JsonOnlyBool               = ConvertTo-CarBool $JsonOnlyStr

# Apply legacy switches (they only bind when invoked with -DeepProbe etc.;
# they override the resolved strings when set true).
if ($DeepProbe)              { $DeepProbeBool              = $true }
if ($IncludeAdLookup)        { $IncludeAdLookupBool        = $true }
if ($IncludeEmbeddedEngines) { $IncludeEmbeddedEnginesBool = $true }
if ($SkipNetwork)            { $SkipNetworkBool            = $true }
if ($DryRun)                 { $DryRunBool                 = $true }
if ($JsonOnly)               { $JsonOnlyBool               = $true }
if (-not [string]::IsNullOrWhiteSpace($EmbeddedPaths)) { $EmbeddedPathsStr = $EmbeddedPaths }
if (-not [string]::IsNullOrWhiteSpace($OutputPath))    { $OutputPathStr   = $OutputPath }
if ($Retain -gt 0)                                     { $RetainStr       = [string]$Retain }

# Retain -> int
$RetainInt = 1
if (-not [string]::IsNullOrWhiteSpace($RetainStr)) {
    $parsed = 0
    if ([int]::TryParse($RetainStr, [ref]$parsed) -and $parsed -gt 0) {
        $RetainInt = $parsed
    }
}

# EmbeddedPaths: comma-separated string -> array
$EmbeddedPathsArr = @()
if (-not [string]::IsNullOrWhiteSpace($EmbeddedPathsStr)) {
    $EmbeddedPathsArr = @(
        $EmbeddedPathsStr.Split(',') |
          ForEach-Object { $_.Trim() } |
          Where-Object { $_ -ne '' }
    )
}

# Bind into the names the body of the script already uses. Keeping these as
# the single source of truth means the rest of the script needed no changes.
Set-Variable -Name 'DeepProbe'              -Value $DeepProbeBool              -Scope Script -Force
Set-Variable -Name 'IncludeAdLookup'        -Value $IncludeAdLookupBool        -Scope Script -Force
Set-Variable -Name 'IncludeEmbeddedEngines' -Value $IncludeEmbeddedEnginesBool -Scope Script -Force
Set-Variable -Name 'EmbeddedPaths'          -Value $EmbeddedPathsArr           -Scope Script -Force
Set-Variable -Name 'SkipNetwork'            -Value $SkipNetworkBool            -Scope Script -Force
Set-Variable -Name 'DryRun'                 -Value $DryRunBool                 -Scope Script -Force
Set-Variable -Name 'JsonOnly'               -Value $JsonOnlyBool               -Scope Script -Force
Set-Variable -Name 'Retain'                 -Value $RetainInt                  -Scope Script -Force
Set-Variable -Name 'OutputPath'             -Value $OutputPathStr              -Scope Script -Force

# ============================================================================
# GLOBALS / STATE
# ============================================================================

$ScriptName    = 'Get-DatabaseInventory.ps1'
$ScriptVersion = '3.0.0'
$StartedAt     = Get-Date
$Stamp         = $StartedAt.ToString('yyyyMMdd_HHmmss')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $env:ProgramData 'DatabaseInventory'
}
if ($Retain -lt 1) { $Retain = 1 }

$LogPath  = Join-Path $OutputPath ("inventory_{0}.log"  -f $Stamp)
$JsonPath = Join-Path $OutputPath ("inventory_{0}.json" -f $Stamp)

$LogLines    = New-Object System.Collections.Generic.List[object]
$Instances   = New-Object System.Collections.Generic.List[object]
$WarningList = New-Object System.Collections.Generic.List[object]
$ErrorList   = New-Object System.Collections.Generic.List[object]

$CountWarnings = 0
$CountErrors   = 0

# Regex used to redact secrets from config-file content before logging
$SecretsRegex = '(?im)^(\s*[#;]?\s*(password|passwd|pwd|secret|token|apikey|api[_-]?key|requirepass|connection[-_]?string|authentication_string)\s*[:=]\s*).+$'

# ============================================================================
# LOGGING HELPERS
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level
    )
    if ([string]::IsNullOrEmpty($Level)) { $Level = 'INFO' }
    $line = '{0}  [{1}]  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.PadRight(5), $Message
    $null = $LogLines.Add($line)

    if (-not $JsonOnly) {
        switch ($Level) {
            'WARN'  { Write-Host $line -ForegroundColor Yellow  ; break }
            'OK'    { Write-Host $line -ForegroundColor Green   ; break }
            'FIND'  { Write-Host $line -ForegroundColor Magenta ; break }
            'ERROR' { Write-Host $line -ForegroundColor Red     ; break }
            '--'    { Write-Host $line -ForegroundColor DarkGray; break }
            default { Write-Host $line }
        }
    }
}

function Save-Log {
    try {
        $null = New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop
        $LogLines | Out-File -FilePath $LogPath -Encoding ASCII -Force
    } catch {
        Write-Host ('Failed to write log: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
}

function Save-Json {
    param([Parameter(Mandatory=$true)][object]$Document)
    try {
        $null = New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop
        $json = $Document | ConvertTo-Json -Depth 12
        $json | Out-File -FilePath $JsonPath -Encoding UTF8 -Force
        if ($JsonOnly) { Write-Output $json }
    } catch {
        Write-Host ('Failed to write JSON: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
}

function Add-Warning {
    param([string]$Message)
    $null = $WarningList.Add($Message)
    $script:CountWarnings++
}

function Add-ScanError {
    param([string]$Message)
    $null = $ErrorList.Add($Message)
    $script:CountErrors++
}

# ============================================================================
# RETENTION / CLEANUP
# ============================================================================

function Invoke-OutputCleanup {
    try {
        if (-not (Test-Path -Path $OutputPath)) { return }
        $patterns = @('inventory_*.log','inventory_*.json')
        $files = @()
        foreach ($p in $patterns) {
            $files += Get-ChildItem -Path $OutputPath -Filter $p -File -ErrorAction SilentlyContinue
        }
        if (-not $files -or $files.Count -eq 0) { return }
        $sorted = $files | Sort-Object -Property Name -Descending
        $toKeep = [math]::Max(0, $Retain - 1)
        $toDelete = $sorted | Select-Object -Skip $toKeep
        foreach ($f in $toDelete) {
            try {
                Remove-Item -Path $f.FullName -Force -ErrorAction Stop
                Write-Log ('Cleaned old output: {0}' -f $f.Name) -Level '--'
            } catch {
                Write-Log ('Failed to delete old file {0}: {1}' -f $f.Name, $_.Exception.Message) -Level 'WARN'
                $script:CountWarnings++
            }
        }
    } catch {
        Write-Log ('Output cleanup error: {0}' -f $_.Exception.Message) -Level 'WARN'
        $script:CountWarnings++
    }
}

# ============================================================================
# LOW-LEVEL HELPERS
# ============================================================================

function Protect-Secrets {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return ($Text -replace $SecretsRegex, '$1<REDACTED>')
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-SafeRegValue {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        if ($item.PSObject.Properties.Name -contains $Name) { return $item.$Name }
        return $null
    } catch { return $null }
}

function Get-SafeRegSubkeys {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        return @(Get-ChildItem -LiteralPath $Path -ErrorAction Stop)
    } catch { return @() }
}

function ConvertTo-SafeArray {
    param($Value)
    if ($null -eq $Value) { return ,@() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return ,@($Value)
    }
    return ,@($Value)
}

function Read-SafeFile {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        return (Get-Content -LiteralPath $Path -ErrorAction Stop -Raw)
    } catch {
        Add-Warning ('Could not read file {0}: {1}' -f $Path, $_.Exception.Message)
        return $null
    }
}

function Resolve-ServiceAccountType {
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return 'unknown' }
    $a = $Account.Trim()
    if ($a -match '^(LocalSystem|\.\\LocalSystem|NT AUTHORITY\\SYSTEM)$')   { return 'local_system' }
    if ($a -match '^NT AUTHORITY\\(LocalService|NetworkService)$')          { return 'local_service' }
    if ($a -match '^NT SERVICE\\')                                          { return 'virtual_service_account' }
    if ($a -match '^\.\\')                                                  { return 'local_user' }
    if ($a -match '\\' -and $a -notmatch '^\.\\')                           { return 'domain_user' }
    if ($a -match '\$$')                                                    { return 'managed_service_account' }
    return 'unknown'
}

function Add-InstanceFinding {
    param([Parameter(Mandatory=$true)][object]$Instance)
    $null = $Instances.Add($Instance)
    $prod = '<unknown>'
    if ($Instance.PSObject.Properties.Name -contains 'product') { $prod = $Instance.product }
    $name = '(default)'
    if ($Instance.PSObject.Properties.Name -contains 'instance_name' -and $Instance.instance_name) {
        $name = $Instance.instance_name
    }
    Write-Log ('Instance recorded: {0} / {1}' -f $prod, $name) -Level 'FIND'
}

function New-InstanceRecord {
    param(
        [Parameter(Mandatory=$true)][string]$Product,
        [string]$Vendor
    )
    return [ordered]@{
        product                       = $Product
        vendor                        = $Vendor
        edition                       = $null
        version                       = $null
        patch_level                   = $null
        instance_name                 = $null
        instance_id                   = $null
        install_path                  = $null
        data_path                     = $null
        config_paths                  = New-Object System.Collections.Generic.List[object]
        service                       = $null
        processes                     = New-Object System.Collections.Generic.List[object]
        listen                        = New-Object System.Collections.Generic.List[object]
        databases                     = New-Object System.Collections.Generic.List[object]
        database_enumeration_method   = 'none'
        authentication                = [ordered]@{
            mode            = $null
            source          = $null
            details         = New-Object System.Collections.Generic.List[object]
            integrated_auth = $false
            ad_integrated   = $false
        }
        spns                          = New-Object System.Collections.Generic.List[object]
        tls                           = [ordered]@{
            enabled            = $null
            force_encryption   = $null
            cert_thumbprint    = $null
        }
        ad_lookup                     = $null
        notes                         = New-Object System.Collections.Generic.List[object]
        collection_warnings           = New-Object System.Collections.Generic.List[object]
    }
}

# ============================================================================
# HOST IDENTITY
# ============================================================================

function Get-HostIdentity {
    $h = [ordered]@{
        hostname       = $env:COMPUTERNAME
        fqdn           = $null
        domain         = $null
        domain_joined  = $false
        os             = $null
        os_version     = $null
        ip_addresses   = New-Object System.Collections.Generic.List[object]
    }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $h.domain_joined = [bool]$cs.PartOfDomain
        $h.domain        = $cs.Domain
        if ($cs.DNSHostName -and $cs.Domain) {
            $h.fqdn = '{0}.{1}' -f $cs.DNSHostName, $cs.Domain
        } else {
            $h.fqdn = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName
        }
    } catch {
        Add-Warning ('Host identity lookup failed: {0}' -f $_.Exception.Message)
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $h.os         = $os.Caption
        $h.os_version = $os.Version
    } catch {
        Add-Warning ('OS lookup failed: {0}' -f $_.Exception.Message)
    }
    try {
        $addrs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' -ErrorAction Stop
        foreach ($a in $addrs) {
            if ($null -ne $a.IPAddress) {
                foreach ($ip in (ConvertTo-SafeArray $a.IPAddress)) {
                    if ([string]::IsNullOrWhiteSpace($ip)) { continue }
                    $fam = 'v4'
                    if ($ip -match ':') { $fam = 'v6' }
                    $null = $h.ip_addresses.Add([ordered]@{
                        interface = $a.Description
                        address   = $ip
                        family    = $fam
                    })
                }
            }
        }
    } catch {
        Add-Warning ('IP address lookup failed: {0}' -f $_.Exception.Message)
    }
    return $h
}

# ============================================================================
# PRODUCT PATTERN TABLE
# ============================================================================
# Used by the broad service/process sweep for high-level "what products are
# present" counts. Per-product Invoke-*Discovery functions do their own, more
# precise matching against registry keys, config files, and service metadata.

$script:DbProductPatterns = @(
    [pscustomobject]@{ Product='Microsoft SQL Server';          Vendor='Microsoft';   ServiceRegex='^(MSSQLSERVER|MSSQL\$.+|SQLAgent\$.+|SQLServerAgent|SQLTELEMETRY.*|SQLBrowser|SQLWriter)$'; ProcessRegex='^(sqlservr|sqlagent|sqlbrowser|sqlwriter)$' }
    [pscustomobject]@{ Product='SSAS (Analysis Services)';       Vendor='Microsoft';   ServiceRegex='^(MSSQLServerOLAPService|MSOLAP\$.+)$';                                                      ProcessRegex='^msmdsrv$' }
    [pscustomobject]@{ Product='SSRS (Reporting Services)';      Vendor='Microsoft';   ServiceRegex='^(ReportServer|SQLServerReportingServices|ReportServer\$.+|PowerBIReportServer|PBIRS)$';    ProcessRegex='^(ReportingServicesService|reportingservice)$' }
    [pscustomobject]@{ Product='SSIS (Integration Services)';    Vendor='Microsoft';   ServiceRegex='^(MsDtsServer.*|SSISSCALEOUT.*)$';                                                           ProcessRegex='^MsDtsSrvr$' }
    [pscustomobject]@{ Product='Oracle Database';                Vendor='Oracle';      ServiceRegex='^(OracleService.+|OracleOraDb.+TNSListener.*|OracleVssWriter.*|OracleJobScheduler.+|OracleMTSRecoveryService)$'; ProcessRegex='^(oracle|tnslsnr)$' }
    [pscustomobject]@{ Product='MySQL';                          Vendor='Oracle';      ServiceRegex='^(MySQL.*|MYSQL.*)$';                                                                        ProcessRegex='^mysqld$' }
    [pscustomobject]@{ Product='MariaDB';                        Vendor='MariaDB';     ServiceRegex='^(MariaDB.*)$';                                                                              ProcessRegex='^(mysqld|mariadbd)$' }
    [pscustomobject]@{ Product='Percona Server';                 Vendor='Percona';     ServiceRegex='^(Percona.*)$';                                                                              ProcessRegex='^(mysqld|percona)$' }
    [pscustomobject]@{ Product='PostgreSQL';                     Vendor='PostgreSQL';  ServiceRegex='^(postgresql.*|postgres.*)$';                                                                ProcessRegex='^postgres$' }
    [pscustomobject]@{ Product='MongoDB';                        Vendor='MongoDB';     ServiceRegex='^(MongoDB.*|mongod.*)$';                                                                     ProcessRegex='^mongod$' }
    [pscustomobject]@{ Product='Redis';                          Vendor='Redis';       ServiceRegex='^(Redis|redis-server.*)$';                                                                   ProcessRegex='^redis-server$' }
    [pscustomobject]@{ Product='IBM Db2';                        Vendor='IBM';         ServiceRegex='^(DB2.+|DB2GOVERNOR|DB2MGMTSVC.*|DB2DAS.+)$';                                                ProcessRegex='^(db2syscs|db2fmp|db2star2)$' }
    [pscustomobject]@{ Product='SAP ASE (Sybase)';               Vendor='SAP';         ServiceRegex='^(SYBSQL_.+|SAP_ASE_.+|Sybase.+|SAP ASE.+)$';                                                ProcessRegex='^(sqlsrvr|dataserver)$' }
    [pscustomobject]@{ Product='SAP MaxDB';                      Vendor='SAP';         ServiceRegex='^(SAP DB.*|MaxDB.*|SAPDB.*)$';                                                               ProcessRegex='^(kernel|maxdb)$' }
    [pscustomobject]@{ Product='Informix';                       Vendor='IBM';         ServiceRegex='^(IBM Informix.*|INFORMIX.*)$';                                                              ProcessRegex='^oninit$' }
    [pscustomobject]@{ Product='Firebird';                       Vendor='Firebird';    ServiceRegex='^(Firebird.*|FirebirdServer.*|FirebirdGuardian.*)$';                                          ProcessRegex='^(firebird|fbserver|fbguard)$' }
    [pscustomobject]@{ Product='Teradata';                       Vendor='Teradata';    ServiceRegex='^(Teradata.*)$';                                                                             ProcessRegex='^(tdatcmd|tdat_.*)$' }
    [pscustomobject]@{ Product='InfluxDB';                       Vendor='InfluxData';  ServiceRegex='^(InfluxDB.*|influxd.*)$';                                                                   ProcessRegex='^influxd$' }
    [pscustomobject]@{ Product='ClickHouse';                     Vendor='ClickHouse';  ServiceRegex='^(clickhouse.*|ClickHouse.*)$';                                                              ProcessRegex='^(clickhouse-server|clickhouse)$' }
    [pscustomobject]@{ Product='Couchbase';                      Vendor='Couchbase';   ServiceRegex='^(CouchbaseServer.*|Couchbase.*)$';                                                          ProcessRegex='^(beam\.smp|memcached)$' }
    [pscustomobject]@{ Product='Neo4j';                          Vendor='Neo4j';       ServiceRegex='^(neo4j.*|Neo4j.*)$';                                                                        ProcessRegex='^neo4j$' }
    [pscustomobject]@{ Product='Elasticsearch';                  Vendor='Elastic';     ServiceRegex='^(elasticsearch.*|Elasticsearch.*)$';                                                       ProcessRegex='^elasticsearch$' }
    [pscustomobject]@{ Product='OpenSearch';                     Vendor='OpenSearch';  ServiceRegex='^(opensearch.*|OpenSearch.*)$';                                                              ProcessRegex='^opensearch$' }
    [pscustomobject]@{ Product='RavenDB';                        Vendor='RavenDB';     ServiceRegex='^(RavenDB.*)$';                                                                              ProcessRegex='^Raven\.Server$' }
    # v2.0 additions
    [pscustomobject]@{ Product='etcd';                           Vendor='CNCF';        ServiceRegex='^(etcd.*)$';                                                                                 ProcessRegex='^etcd$' }
    [pscustomobject]@{ Product='HashiCorp Consul';               Vendor='HashiCorp';   ServiceRegex='^(consul.*)$';                                                                               ProcessRegex='^consul$' }
    [pscustomobject]@{ Product='Memcached';                      Vendor='Memcached';   ServiceRegex='^(memcached.*)$';                                                                            ProcessRegex='^memcached$' }
    [pscustomobject]@{ Product='Prometheus';                     Vendor='Prometheus';  ServiceRegex='^(prometheus.*)$';                                                                           ProcessRegex='^prometheus$' }
    [pscustomobject]@{ Product='H2 / HSQLDB / Derby (server)';   Vendor='Various';     ServiceRegex='^(h2|hsqldb|derby).*$';                                                                      ProcessRegex='^(h2|hsqldb|java)$' }
)

# ============================================================================
# SERVICE / PROCESS / SOCKET ENUMERATION
# ============================================================================

function Get-AllDatabaseServices {
    $results = New-Object System.Collections.Generic.List[object]
    try {
        $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    } catch {
        Add-Warning ('Service enumeration failed: {0}' -f $_.Exception.Message)
        return $results
    }
    foreach ($s in $svcs) {
        foreach ($pat in $script:DbProductPatterns) {
            if ($s.Name -match $pat.ServiceRegex) {
                $null = $results.Add([ordered]@{
                    product      = $pat.Product
                    vendor       = $pat.Vendor
                    name         = $s.Name
                    display_name = $s.DisplayName
                    state        = $s.State
                    start_mode   = $s.StartMode
                    image_path   = $s.PathName
                    account      = $s.StartName
                    process_id   = [int]$s.ProcessId
                })
                break
            }
        }
    }
    return $results
}

function Get-AllDatabaseProcesses {
    $results = New-Object System.Collections.Generic.List[object]
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    } catch {
        Add-Warning ('Process enumeration failed: {0}' -f $_.Exception.Message)
        return $results
    }
    foreach ($p in $procs) {
        $baseName = $p.Name
        if ($baseName -match '\.exe$') { $baseName = $baseName -replace '\.exe$','' }
        foreach ($pat in $script:DbProductPatterns) {
            if ($baseName -match $pat.ProcessRegex) {
                $owner = $null
                try {
                    $ownInfo = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                    if ($ownInfo -and $ownInfo.User) {
                        $owner = $ownInfo.User
                        if ($ownInfo.Domain) { $owner = '{0}\{1}' -f $ownInfo.Domain, $ownInfo.User }
                    }
                } catch {}
                $null = $results.Add([ordered]@{
                    product      = $pat.Product
                    vendor       = $pat.Vendor
                    name         = $p.Name
                    pid          = [int]$p.ProcessId
                    parent_pid   = [int]$p.ParentProcessId
                    command_line = $p.CommandLine
                    executable   = $p.ExecutablePath
                    owner        = $owner
                })
                break
            }
        }
    }
    return $results
}

function Get-ListeningSockets {
    $results = New-Object System.Collections.Generic.List[object]
    if ($SkipNetwork) { return $results }
    try {
        $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop
    } catch {
        Add-Warning ('Get-NetTCPConnection failed; skipping listening-socket map: {0}' -f $_.Exception.Message)
        return $results
    }
    foreach ($c in $conns) {
        $null = $results.Add([ordered]@{
            protocol    = 'tcp'
            local_ip    = $c.LocalAddress
            local_port  = [int]$c.LocalPort
            pid         = [int]$c.OwningProcess
        })
    }
    return $results
}

function Get-ListenForPid {
    param(
        [Parameter(Mandatory=$true)]$Sockets,
        [Parameter(Mandatory=$true)][int]$ProcessId
    )
    $matches = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Sockets) {
        if ($s.pid -eq $ProcessId) { $null = $matches.Add($s) }
    }
    return $matches
}

# ============================================================================
# MICROSOFT SQL SERVER (engine) + LOCALDB
# ============================================================================

function Invoke-SqlServerDiscovery {
    param($Services, $Processes, $Sockets)

    $mapKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\InstanceNames\SQL'
    if (-not (Test-Path -LiteralPath $mapKey)) {
        Write-Log 'No Microsoft SQL Server (engine) instances found.' -Level '--'
        return
    }

    $map = Get-ItemProperty -LiteralPath $mapKey -ErrorAction SilentlyContinue
    if (-not $map) { return }

    $props = $map.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
    foreach ($p in $props) {
        $instName = $p.Name
        $instId   = [string]$p.Value
        $rec = New-InstanceRecord -Product 'Microsoft SQL Server' -Vendor 'Microsoft'
        $rec.instance_name = $instName
        $rec.instance_id   = $instId

        $setupKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\Setup' -f $instId
        $rec.edition      = Get-SafeRegValue $setupKey 'Edition'
        $rec.version      = Get-SafeRegValue $setupKey 'Version'
        $rec.patch_level  = Get-SafeRegValue $setupKey 'PatchLevel'
        $rec.install_path = Get-SafeRegValue $setupKey 'SQLBinRoot'
        $rec.data_path    = Get-SafeRegValue $setupKey 'SQLDataRoot'

        $svrKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\MSSQLServer' -f $instId
        $loginMode = Get-SafeRegValue $svrKey 'LoginMode'
        $defaultData = Get-SafeRegValue $svrKey 'DefaultData'
        if ($defaultData) { $null = $rec.config_paths.Add($defaultData) }

        $modeLabel = switch ($loginMode) {
            1 { 'Windows Authentication Only' }
            2 { 'Mixed Mode (SQL + Windows)' }
            default { 'Unknown (LoginMode=' + ([string]$loginMode) + ')' }
        }
        $rec.authentication.mode            = $modeLabel
        $rec.authentication.source          = '{0}\LoginMode={1}' -f $svrKey, [string]$loginMode
        $rec.authentication.integrated_auth = $true
        $rec.authentication.ad_integrated   = $null   # confirmed only via SPN lookup

        # TLS / encryption
        $netKey = '{0}\SuperSocketNetLib' -f $svrKey
        $rec.tls.force_encryption = [bool](Get-SafeRegValue $netKey 'ForceEncryption')
        $rec.tls.cert_thumbprint  = Get-SafeRegValue $netKey 'Certificate'
        if ($rec.tls.force_encryption -or $rec.tls.cert_thumbprint) { $rec.tls.enabled = $true } else { $rec.tls.enabled = $false }

        # TCP configuration (IPAll)
        $tcpAll = '{0}\Tcp\IPAll' -f $netKey
        $staticPort = Get-SafeRegValue $tcpAll 'TcpPort'
        $dynPort    = Get-SafeRegValue $tcpAll 'TcpDynamicPorts'
        foreach ($portVal in @($staticPort, $dynPort)) {
            if ([string]::IsNullOrWhiteSpace($portVal)) { continue }
            foreach ($one in ($portVal -split ',')) {
                $one = $one.Trim()
                if ($one -match '^\d+$') {
                    $null = $rec.listen.Add([ordered]@{
                        protocol    = 'tcp'
                        local_ip    = '(IPAll)'
                        local_port  = [int]$one
                        source      = 'registry:SuperSocketNetLib\Tcp\IPAll'
                    })
                }
            }
        }

        # Matching service from Win32_Service sweep
        $svcName = 'MSSQL$' + $instName
        if ($instName -eq 'MSSQLSERVER') { $svcName = 'MSSQLSERVER' }
        $svc = $Services | Where-Object { $_.name -eq $svcName } | Select-Object -First 1
        if ($svc) {
            $rec.service = [ordered]@{
                name          = $svc.name
                display_name  = $svc.display_name
                state         = $svc.state
                start_mode    = $svc.start_mode
                image_path    = $svc.image_path
                account       = $svc.account
                account_type  = Resolve-ServiceAccountType $svc.account
            }
            if ($svc.process_id -gt 0) {
                foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                    $null = $rec.listen.Add([ordered]@{
                        protocol    = $ls.protocol
                        local_ip    = $ls.local_ip
                        local_port  = $ls.local_port
                        source      = 'live_socket'
                    })
                }
                foreach ($pr in ($Processes | Where-Object { $_.pid -eq $svc.process_id })) {
                    $null = $rec.processes.Add([ordered]@{
                        pid          = $pr.pid
                        name         = $pr.name
                        executable   = $pr.executable
                        owner        = $pr.owner
                        command_line = $pr.command_line
                    })
                }
            }
        }

        # Database enumeration from data dir (config/FS method)
        if ($rec.data_path -and (Test-Path -LiteralPath $rec.data_path)) {
            try {
                $mdfs = Get-ChildItem -LiteralPath $rec.data_path -Filter '*.mdf' -File -ErrorAction Stop
                foreach ($m in $mdfs) {
                    $dbName = [System.IO.Path]::GetFileNameWithoutExtension($m.Name)
                    if (-not $rec.databases.Contains($dbName)) { $null = $rec.databases.Add($dbName) }
                }
                if ($rec.databases.Count -gt 0) { $rec.database_enumeration_method = 'config_filesystem' }
            } catch {
                $null = $rec.collection_warnings.Add('Data dir listing failed: ' + $_.Exception.Message)
            }
        }

        Add-InstanceFinding $rec
    }
}

function Invoke-SqlServerLocalDbDiscovery {
    $root = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server Local DB\Installed Versions'
    if (-not (Test-Path -LiteralPath $root)) { return }
    $vers = Get-SafeRegSubkeys $root
    foreach ($v in $vers) {
        $rec = New-InstanceRecord -Product 'Microsoft SQL Server LocalDB' -Vendor 'Microsoft'
        $rec.version      = Split-Path -Leaf $v.PSPath
        $rec.instance_id  = $rec.version
        $rec.install_path = Get-SafeRegValue $v.PSPath 'InstanceAPIPath'
        $rec.authentication.mode            = 'Windows Authentication Only'
        $rec.authentication.source          = 'LocalDB process model (per-user, Windows auth only)'
        $rec.authentication.integrated_auth = $true
        $rec.authentication.ad_integrated   = $false
        $null = $rec.notes.Add('LocalDB runs per-user on demand; catalog enumeration requires a live user session.')
        Add-InstanceFinding $rec
    }
}

# ============================================================================
# SSAS / SSRS / SSIS
# ============================================================================

function Invoke-SsasDiscovery {
    param($Services, $Processes, $Sockets)
    $mapKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\InstanceNames\OLAP'
    if (-not (Test-Path -LiteralPath $mapKey)) { return }
    $map = Get-ItemProperty -LiteralPath $mapKey -ErrorAction SilentlyContinue
    if (-not $map) { return }
    $props = $map.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
    foreach ($p in $props) {
        $rec = New-InstanceRecord -Product 'SQL Server Analysis Services (SSAS)' -Vendor 'Microsoft'
        $rec.instance_name = $p.Name
        $rec.instance_id   = [string]$p.Value
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\Setup' -f $rec.instance_id
        $rec.edition     = Get-SafeRegValue $setupKey 'Edition'
        $rec.version     = Get-SafeRegValue $setupKey 'Version'
        $rec.patch_level = Get-SafeRegValue $setupKey 'PatchLevel'

        # SSAS stores its data dir in OLAPServer config (msmdsrv.ini) - path is under install dir
        $instFolder = Get-SafeRegValue $setupKey 'SQLPath'
        if ($instFolder) { $rec.install_path = $instFolder }

        $rec.authentication.mode            = 'Windows Authentication Only'
        $rec.authentication.source          = 'SSAS supports Windows authentication only (Kerberos/NTLM)'
        $rec.authentication.integrated_auth = $true

        $svcName = 'MSOLAP$' + $p.Name
        if ($p.Name -eq 'MSSQLSERVER') { $svcName = 'MSSQLServerOLAPService' }
        $svc = $Services | Where-Object { $_.name -eq $svcName } | Select-Object -First 1
        if ($svc) {
            $rec.service = [ordered]@{
                name          = $svc.name
                display_name  = $svc.display_name
                state         = $svc.state
                start_mode    = $svc.start_mode
                image_path    = $svc.image_path
                account       = $svc.account
                account_type  = Resolve-ServiceAccountType $svc.account
            }
            if ($svc.process_id -gt 0) {
                foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                    $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
                }
            }
        }
        Add-InstanceFinding $rec
    }
}

function Invoke-SsrsDiscovery {
    param($Services, $Processes, $Sockets)
    $mapKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\InstanceNames\RS'
    $instanceMap = @()
    if (Test-Path -LiteralPath $mapKey) {
        $m = Get-ItemProperty -LiteralPath $mapKey -ErrorAction SilentlyContinue
        if ($m) {
            $instanceMap = $m.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        }
    }
    # Also check for standalone SSRS / Power BI Report Server
    $standalone = @()
    $pbirsKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft Power BI Report Server'
    $ssrsKey  = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server Reporting Services'
    foreach ($k in @($pbirsKey, $ssrsKey)) {
        if (Test-Path -LiteralPath $k) { $standalone += $k }
    }

    if (-not $instanceMap -and -not $standalone) { return }

    foreach ($p in $instanceMap) {
        $rec = New-InstanceRecord -Product 'SQL Server Reporting Services (SSRS)' -Vendor 'Microsoft'
        $rec.instance_name = $p.Name
        $rec.instance_id   = [string]$p.Value
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\Setup' -f $rec.instance_id
        $rec.edition     = Get-SafeRegValue $setupKey 'Edition'
        $rec.version     = Get-SafeRegValue $setupKey 'Version'
        $rec.patch_level = Get-SafeRegValue $setupKey 'PatchLevel'
        $rec.authentication.mode   = 'Windows Authentication (NTLM / Kerberos / Forms if configured)'
        $rec.authentication.source = 'rsreportserver.config (AuthenticationTypes element) - not parsed'
        $rec.authentication.integrated_auth = $true

        $svcName = 'ReportServer$' + $p.Name
        if ($p.Name -eq 'MSSQLSERVER') { $svcName = 'ReportServer' }
        $svc = $Services | Where-Object { $_.name -eq $svcName } | Select-Object -First 1
        if ($svc) {
            $rec.service = [ordered]@{
                name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
                image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
            }
            if ($svc.process_id -gt 0) {
                foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                    $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
                }
            }
        }
        Add-InstanceFinding $rec
    }
    foreach ($k in $standalone) {
        $rec = New-InstanceRecord -Product 'SQL Server Reporting Services (SSRS)' -Vendor 'Microsoft'
        $rec.install_path = Get-SafeRegValue $k 'InstallRootDirectory'
        $rec.version      = Get-SafeRegValue $k 'Version'
        $rec.instance_name = 'PBIRS'
        if ($k -match 'Reporting Services$') { $rec.instance_name = 'SSRS' }
        $rec.authentication.mode            = 'Windows Authentication (standalone SSRS/PBIRS)'
        $rec.authentication.source          = 'rsreportserver.config - not parsed'
        $rec.authentication.integrated_auth = $true
        $svc = $Services | Where-Object { $_.name -match '^(SQLServerReportingServices|PowerBIReportServer|PBIRS)$' } | Select-Object -First 1
        if ($svc) {
            $rec.service = [ordered]@{
                name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
                image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
            }
        }
        Add-InstanceFinding $rec
    }
}

function Invoke-SsisDiscovery {
    param($Services, $Processes, $Sockets)
    $svcs = $Services | Where-Object { $_.name -match '^(MsDtsServer.*|SSISSCALEOUT.*)$' }
    foreach ($svc in $svcs) {
        $rec = New-InstanceRecord -Product 'SQL Server Integration Services (SSIS)' -Vendor 'Microsoft'
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path
        # SSIS version tracks the SQL Server major version (MsDtsServer150 = SQL 2019)
        if ($svc.name -match 'MsDtsServer(\d+)') { $rec.version = $Matches[1] }
        $rec.authentication.mode            = 'Windows Authentication (DCOM)'
        $rec.authentication.source          = 'SSIS server uses DCOM; access governed by MsDtsSrvr.ini.xml ACL'
        $rec.authentication.integrated_auth = $true
        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        Add-InstanceFinding $rec
    }
}

# ============================================================================
# MONGODB
# ============================================================================

function Invoke-MongoDbDiscovery {
    param($Services, $Processes, $Sockets)

    $svcs = $Services | Where-Object { $_.name -match '^MongoDB' -or $_.display_name -match 'MongoDB' }
    if (-not $svcs) { return }
    foreach ($svc in $svcs) {
        $rec = New-InstanceRecord -Product 'MongoDB' -Vendor 'MongoDB'
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path

        $cfgPath = $null
        if ($svc.image_path -and ($svc.image_path -match '--config\s+"?([^"]+?\.cfg)"?')) { $cfgPath = $Matches[1] }
        if (-not $cfgPath) {
            $candidates = @()
            foreach ($ver in 8,7,6,5,4) {
                $candidates += ('C:\Program Files\MongoDB\Server\{0}.0\bin\mongod.cfg' -f $ver)
            }
            foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { $cfgPath = $c; break } }
        }

        if ($cfgPath) {
            $null = $rec.config_paths.Add($cfgPath)
            $cfg = Read-SafeFile $cfgPath
            if ($cfg) {
                if ($cfg -match '(?im)^\s*port\s*:\s*(\d+)') {
                    $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(mongod.cfg)'; local_port=[int]$Matches[1]; source='mongod.cfg:net.port' })
                }
                if ($cfg -match '(?im)^\s*bindIp\s*:\s*(.+)$') {
                    $null = $rec.notes.Add('net.bindIp=' + $Matches[1].Trim())
                }
                if ($cfg -match '(?im)^\s*dbPath\s*:\s*(.+)$') {
                    $rec.data_path = $Matches[1].Trim().Trim('"')
                }
                if ($cfg -match '(?im)^\s*authorization\s*:\s*(\w+)') {
                    $rec.authentication.mode   = 'security.authorization=' + $Matches[1]
                    $rec.authentication.source = $cfgPath + ':security.authorization'
                }
                if ($cfg -match '(?i)ldap\s*:') {
                    $rec.authentication.ad_integrated = $true
                    if (-not $rec.authentication.mode) { $rec.authentication.mode = 'LDAP (Enterprise)' }
                    $null = $rec.authentication.details.Add('security.ldap block present')
                }
                if ($cfg -match '(?im)^\s*clusterAuthMode\s*:\s*(\w+)') {
                    $null = $rec.authentication.details.Add('clusterAuthMode=' + $Matches[1])
                }
                if ($cfg -match '(?im)^\s*mode\s*:\s*(requireTLS|preferTLS|allowTLS|disabled)') {
                    $rec.tls.enabled = ($Matches[1] -notmatch 'disabled')
                    $null = $rec.authentication.details.Add('net.tls.mode=' + $Matches[1])
                }
            }
        }

        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
        }

        # Database enumeration: each subdirectory of dbPath (except diagnostic.data / journal) is a database in WiredTiger.
        # With WiredTiger's collection-level files, DB-name inference from filesystem is lossy; note and defer to deep-probe.
        if ($rec.data_path -and (Test-Path -LiteralPath $rec.data_path)) {
            $null = $rec.notes.Add('WiredTiger storage: DB names require deep-probe (listDatabases) - not inferred from filesystem.')
        }

        Add-InstanceFinding $rec
    }
}

# ============================================================================
# REDIS
# ============================================================================

function Invoke-RedisDiscovery {
    param($Services, $Processes, $Sockets)
    $svcs = $Services | Where-Object { $_.name -match '^(Redis|redis-server)' -or $_.display_name -match 'Redis' }
    if (-not $svcs) { return }
    foreach ($svc in $svcs) {
        $rec = New-InstanceRecord -Product 'Redis' -Vendor 'Redis'
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path

        $cfgPath = $null
        if ($svc.image_path -and ($svc.image_path -match '"?([^"]+\.conf)"?')) { $cfgPath = $Matches[1] }

        if ($cfgPath -and (Test-Path -LiteralPath $cfgPath)) {
            $null = $rec.config_paths.Add($cfgPath)
            $cfg = Read-SafeFile $cfgPath
            if ($cfg) {
                if ($cfg -match '(?im)^\s*port\s+(\d+)') {
                    $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(redis.conf)'; local_port=[int]$Matches[1]; source='redis.conf:port' })
                }
                if ($cfg -match '(?im)^\s*bind\s+(.+)$')        { $null = $rec.notes.Add('bind=' + $Matches[1].Trim()) }
                if ($cfg -match '(?im)^\s*tls-port\s+(\d+)')   {
                    $rec.tls.enabled = $true
                    $null = $rec.listen.Add([ordered]@{ protocol='tcp-tls'; local_ip='(redis.conf)'; local_port=[int]$Matches[1]; source='redis.conf:tls-port' })
                }
                if ($cfg -match '(?im)^\s*aclfile\s+(.+)$')    { $null = $rec.authentication.details.Add('aclfile=' + $Matches[1].Trim()) }
                if ($cfg -match '(?im)^\s*requirepass\s+')     {
                    $rec.authentication.mode = 'Password (requirepass)'
                    $rec.authentication.source = $cfgPath + ':requirepass'
                } else {
                    $rec.authentication.mode = 'No auth required (unless ACL file set)'
                    $rec.authentication.source = $cfgPath
                }
                $userLines = [regex]::Matches($cfg, '(?im)^\s*user\s+(\S+)\s+.*$')
                foreach ($m in $userLines) { $null = $rec.authentication.details.Add('ACL user: ' + $m.Groups[1].Value) }
            }
        } else {
            $null = $rec.collection_warnings.Add('redis.conf not located; auth details incomplete')
        }

        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
        }
        $null = $rec.notes.Add('Redis exposes 16 numbered logical DBs (0-15) by default; not named.')
        Add-InstanceFinding $rec
    }
}

# ============================================================================
# GENERIC (light) DISCOVERY - used by the remaining DB products for which
# detailed auth/catalog parsing is out of scope for v1.0.
# ============================================================================

function Invoke-GenericDbDiscovery {
    param(
        [Parameter(Mandatory=$true)][string]$Product,
        [Parameter(Mandatory=$true)][string]$Vendor,
        [Parameter(Mandatory=$true)][string]$ServiceRegex,
        [string]$AuthNote = 'Auth details not parsed in v1.0 (surface-level discovery only).',
        [Parameter(Mandatory=$true)]$Services,
        [Parameter(Mandatory=$true)]$Processes,
        [Parameter(Mandatory=$true)]$Sockets
    )
    $svcs = $Services | Where-Object { $_.name -match $ServiceRegex -or $_.display_name -match $ServiceRegex }
    if (-not $svcs) { return }
    foreach ($svc in $svcs) {
        $rec = New-InstanceRecord -Product $Product -Vendor $Vendor
        $rec.instance_name             = $svc.name
        $rec.install_path              = $svc.image_path
        $rec.authentication.mode       = $AuthNote
        $rec.authentication.source     = 'service metadata only'
        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
            foreach ($pr in ($Processes | Where-Object { $_.pid -eq $svc.process_id })) {
                $null = $rec.processes.Add([ordered]@{
                    pid=$pr.pid; name=$pr.name; executable=$pr.executable; owner=$pr.owner; command_line=$pr.command_line
                })
            }
        }
        Add-InstanceFinding $rec
    }
}

# ============================================================================
# REMAINING DATABASES (generic detection + product-specific hints)
# ============================================================================

function Invoke-Db2Discovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'IBM Db2' -Vendor 'IBM' `
        -ServiceRegex '^(DB2.+|DB2GOVERNOR|DB2MGMTSVC.*|DB2DAS.+)$' `
        -AuthNote 'Db2 default: OS-based authentication (SERVER). Check db2 "get dbm cfg" AUTHENTICATION setting for full auth config.'
}

function Invoke-SybaseAseDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'SAP ASE (Sybase)' -Vendor 'SAP' `
        -ServiceRegex '^(SYBSQL_.+|SAP_ASE_.+|Sybase.+|SAP ASE.+)$' `
        -AuthNote 'ASE default: internal logins. LDAP/Kerberos supported via sp_configure "enable ldap user auth" / KRB settings.'
}

function Invoke-MaxDbDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'SAP MaxDB' -Vendor 'SAP' `
        -ServiceRegex '^(SAP DB.*|MaxDB.*|SAPDB.*)$' `
        -AuthNote 'MaxDB default: internal user DB. Integrated OS/AD auth requires Connect Feature configuration.'
}

function Invoke-InformixDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'IBM Informix' -Vendor 'IBM' `
        -ServiceRegex '^(IBM Informix.*|INFORMIX.*|oninit.*)$' `
        -AuthNote 'Informix default: OS authentication via pam_informix or OS pluggable auth.'
}

function Invoke-FirebirdDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'Firebird' -Vendor 'Firebird' `
        -ServiceRegex '^(Firebird.*|FirebirdServer.*|FirebirdGuardian.*)$' `
        -AuthNote 'Firebird default: Srp / Legacy_Auth in firebird.conf (AuthServer setting).'
}

function Invoke-TeradataDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'Teradata' -Vendor 'Teradata' `
        -ServiceRegex '^(Teradata.*)$' `
        -AuthNote 'Teradata default: TD2 (internal). LDAP/KRB5 configured via tdgssconfigfile.'
}

function Invoke-InfluxDbDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'InfluxDB' -Vendor 'InfluxData' `
        -ServiceRegex '^(InfluxDB.*|influxd.*)$' `
        -AuthNote 'InfluxDB 2.x: token-based. 1.x: [http] auth-enabled = true/false in influxdb.conf.'
}

function Invoke-ClickHouseDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'ClickHouse' -Vendor 'ClickHouse' `
        -ServiceRegex '^(clickhouse.*|ClickHouse.*)$' `
        -AuthNote 'ClickHouse: users defined in users.xml or via SQL. LDAP/Kerberos configured under <ldap_servers> / <kerberos>.'
}

function Invoke-CouchbaseDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'Couchbase' -Vendor 'Couchbase' `
        -ServiceRegex '^(CouchbaseServer.*|Couchbase.*)$' `
        -AuthNote 'Couchbase: local RBAC users + optional LDAP/SAML via cluster settings.'
}

function Invoke-Neo4jDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'Neo4j' -Vendor 'Neo4j' `
        -ServiceRegex '^(neo4j.*|Neo4j.*)$' `
        -AuthNote 'Neo4j: native / LDAP / SSO configured in neo4j.conf (dbms.security.auth_providers).'
}

function Invoke-ElasticsearchDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'Elasticsearch' -Vendor 'Elastic' `
        -ServiceRegex '^(elasticsearch.*|Elasticsearch.*)$' `
        -AuthNote 'Elasticsearch: xpack.security.authc.* realms in elasticsearch.yml (native / ldap / ad / saml / oidc / kerberos).'
}

function Invoke-OpenSearchDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'OpenSearch' -Vendor 'OpenSearch' `
        -ServiceRegex '^(opensearch.*|OpenSearch.*)$' `
        -AuthNote 'OpenSearch: security plugin config in opensearch-security/config.yml (internal / ldap / saml / openid).'
}

function Invoke-RavenDbDiscovery {
    param($Services, $Processes, $Sockets)
    Invoke-GenericDbDiscovery -Services $Services -Processes $Processes -Sockets $Sockets `
        -Product 'RavenDB' -Vendor 'RavenDB' `
        -ServiceRegex '^(RavenDB.*)$' `
        -AuthNote 'RavenDB: X.509 client certificate authentication by default.'
}

# ============================================================================
# ETCD  (v2.0)
# ============================================================================
#
# etcd on Windows is rare but exists (k8s for Windows containers, CNCF demos).
# Config file is etcd.conf.yml; runtime flags are more common. Auth is
# certificate-based (--client-cert-auth) or v3 RBAC with token.

function Invoke-EtcdDiscovery {
    param($Services, $Processes, $Sockets)
    $svcs = $Services | Where-Object { $_.name -match '^etcd' -or $_.display_name -match 'etcd' }
    $procs = $Processes | Where-Object { $_.name -match '^etcd(\.exe)?$' }
    if (-not $svcs -and -not $procs) { return }

    $rec = New-InstanceRecord -Product 'etcd' -Vendor 'CNCF'
    $svc = $svcs | Select-Object -First 1
    if ($svc) {
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path
        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
        }
    }

    # Parse command-line flags (--listen-client-urls, --listen-peer-urls, --client-cert-auth)
    $cmdline = $null
    if ($svc -and $svc.image_path) { $cmdline = $svc.image_path }
    elseif ($procs) { $cmdline = ($procs | Select-Object -First 1).command_line }

    if ($cmdline) {
        $certAuth = ($cmdline -match '--client-cert-auth(=true|\s|$)')
        $peerAuth = ($cmdline -match '--peer-client-cert-auth(=true|\s|$)')
        $authToken = ($cmdline -match '--auth-token=(\S+)')
        $parts = @()
        if ($certAuth)  { $parts += 'client mTLS (--client-cert-auth=true)' }
        if ($peerAuth)  { $parts += 'peer mTLS (--peer-client-cert-auth=true)' }
        if ($authToken) { $parts += ('RBAC token type: ' + $Matches[1]) }
        if ($parts.Count -gt 0) {
            $rec.authentication.mode   = ($parts -join ' + ')
            $rec.authentication.source = 'command-line flags'
        } else {
            $rec.authentication.mode   = 'No auth configured (client-cert-auth not enabled, no RBAC token)'
            $rec.authentication.source = 'command-line flags (defaults)'
        }

        # Ports from --listen-client-urls / --listen-peer-urls
        $urlRegex = '(?i)--listen-(client|peer)-urls(?:=|\s+)(\S+)'
        $urlMatches = [regex]::Matches($cmdline, $urlRegex)
        foreach ($m in $urlMatches) {
            $role = $m.Groups[1].Value
            foreach ($u in ($m.Groups[2].Value -split ',')) {
                if ($u -match ':(\d+)(?:$|\/)') {
                    $null = $rec.listen.Add([ordered]@{
                        protocol='tcp'; local_ip='(--listen-' + $role + '-urls)'
                        local_port=[int]$Matches[1]; source=('etcd --listen-' + $role + '-urls')
                    })
                }
            }
        }
    } else {
        # Defaults
        $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(default)'; local_port=2379; source='etcd default client port' })
        $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(default)'; local_port=2380; source='etcd default peer port' })
    }

    # Config file (rarely present on Windows, but try)
    $cfgCandidates = @('C:\ProgramData\etcd\etcd.conf.yml','C:\etcd\etcd.conf.yml')
    foreach ($c in $cfgCandidates) {
        if (Test-Path -LiteralPath $c) {
            $null = $rec.config_paths.Add($c)
            break
        }
    }

    $null = $rec.notes.Add('Stores cluster-coordination state (k8s, service discovery). Hold for RBAC/TLS review.')
    Add-InstanceFinding $rec
}

# ============================================================================
# HASHICORP CONSUL  (v2.0)
# ============================================================================

function Invoke-ConsulDiscovery {
    param($Services, $Processes, $Sockets)
    $svcs = $Services | Where-Object { $_.name -match '^consul' -or $_.display_name -match 'Consul' }
    $procs = $Processes | Where-Object { $_.name -match '^consul(\.exe)?$' }
    if (-not $svcs -and -not $procs) { return }

    $rec = New-InstanceRecord -Product 'HashiCorp Consul' -Vendor 'HashiCorp'
    $svc = $svcs | Select-Object -First 1
    if ($svc) {
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path
        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
        }
    }

    # Find config dir from command line (-config-dir) or default location
    $cmdline = $null
    if ($svc -and $svc.image_path) { $cmdline = $svc.image_path }
    elseif ($procs) { $cmdline = ($procs | Select-Object -First 1).command_line }

    $cfgDir = $null
    if ($cmdline -and ($cmdline -match '-config-dir(?:=|\s+)"?([^\s"]+)"?')) {
        $cfgDir = $Matches[1]
    } else {
        foreach ($d in @('C:\ProgramData\consul\config','C:\consul\config')) {
            if (Test-Path -LiteralPath $d) { $cfgDir = $d; break }
        }
    }
    if ($cfgDir -and (Test-Path -LiteralPath $cfgDir)) {
        foreach ($f in (Get-ChildItem -LiteralPath $cfgDir -Filter '*.hcl' -File -ErrorAction SilentlyContinue)) {
            $null = $rec.config_paths.Add($f.FullName)
        }
        foreach ($f in (Get-ChildItem -LiteralPath $cfgDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            $null = $rec.config_paths.Add($f.FullName)
        }
        $combined = ''
        foreach ($p in $rec.config_paths) { $combined += "`n" + (Read-SafeFile $p) }
        if ($combined -match '(?im)"?acl"?\s*[:=]\s*\{[^}]*"?enabled"?\s*[:=]\s*true') {
            $rec.authentication.mode = 'ACLs enabled (token-based)'
        } elseif ($combined -match 'acl\s*\{' -or $combined -match '"?acl"?\s*[:=]') {
            $rec.authentication.mode = 'ACL block present (check tokens.default)'
        } else {
            $rec.authentication.mode = 'No ACLs configured (anonymous access allowed by default)'
        }
        $rec.authentication.source = ($rec.config_paths -join ';')
    } else {
        $rec.authentication.mode = 'Config dir not located; ACL state unknown'
    }

    # Canonical ports if not already added from live sockets
    $portMap = @{8500='HTTP API';8501='HTTPS API';8300='server RPC';8301='LAN gossip';8302='WAN gossip';8600='DNS'}
    foreach ($p in $portMap.Keys) {
        $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(default)'; local_port=$p; source=('Consul ' + $portMap[$p] + ' default') })
    }

    $null = $rec.notes.Add('Service discovery / distributed config store. Often integrated with Vault for secrets.')
    Add-InstanceFinding $rec
}

# ============================================================================
# MEMCACHED  (v2.0)
# ============================================================================

function Invoke-MemcachedDiscovery {
    param($Services, $Processes, $Sockets)
    $svcs = $Services | Where-Object { $_.name -match '^memcached' -or $_.display_name -match 'Memcached' }
    $procs = $Processes | Where-Object { $_.name -match '^memcached(\.exe)?$' }
    if (-not $svcs -and -not $procs) { return }

    $rec = New-InstanceRecord -Product 'Memcached' -Vendor 'Memcached'
    $svc = $svcs | Select-Object -First 1
    if ($svc) {
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path
        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
        }
    }

    # Parse SASL flag / custom port from command line
    $cmdline = $null
    if ($svc -and $svc.image_path) { $cmdline = $svc.image_path }
    elseif ($procs) { $cmdline = ($procs | Select-Object -First 1).command_line }

    $sasl = $false
    if ($cmdline -and ($cmdline -match '(-S(\s|$)|--enable-sasl)')) { $sasl = $true }
    if ($sasl) {
        $rec.authentication.mode = 'SASL enabled (-S)'
    } else {
        $rec.authentication.mode = 'No authentication (default)'
    }
    $rec.authentication.source = 'service command-line'

    if ($cmdline -and ($cmdline -match '-p\s+(\d+)')) {
        $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(-p)'; local_port=[int]$Matches[1]; source='memcached -p' })
    } else {
        $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(default)'; local_port=11211; source='memcached default' })
    }

    $null = $rec.notes.Add('Cache, not a persistent DBMS. Primary security concern: exposure beyond trusted network when auth is off.')
    Add-InstanceFinding $rec
}

# ============================================================================
# PROMETHEUS  (v2.0)
# ============================================================================

function Invoke-PrometheusDiscovery {
    param($Services, $Processes, $Sockets)
    $svcs = $Services | Where-Object { $_.name -match '^prometheus' -or $_.display_name -match 'Prometheus' }
    $procs = $Processes | Where-Object { $_.name -match '^prometheus(\.exe)?$' }
    if (-not $svcs -and -not $procs) { return }

    $rec = New-InstanceRecord -Product 'Prometheus' -Vendor 'Prometheus'
    $svc = $svcs | Select-Object -First 1
    if ($svc) {
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path
        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
        }
    }

    $cmdline = $null
    if ($svc -and $svc.image_path) { $cmdline = $svc.image_path }
    elseif ($procs) { $cmdline = ($procs | Select-Object -First 1).command_line }

    $webConfig = $null
    $mainConfig = $null
    if ($cmdline) {
        if ($cmdline -match '--web\.config\.file(?:=|\s+)"?([^\s"]+)"?')    { $webConfig = $Matches[1] }
        if ($cmdline -match '--config\.file(?:=|\s+)"?([^\s"]+)"?')         { $mainConfig = $Matches[1] }
        if ($cmdline -match '--web\.listen-address(?:=|\s+)"?([^\s"]+)"?') {
            if ($Matches[1] -match ':(\d+)$') {
                $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(--web.listen-address)'; local_port=[int]$Matches[1]; source='prometheus --web.listen-address' })
            }
        }
    }
    if (-not $mainConfig) {
        foreach ($c in @('C:\ProgramData\Prometheus\prometheus.yml','C:\Prometheus\prometheus.yml')) {
            if (Test-Path -LiteralPath $c) { $mainConfig = $c; break }
        }
    }
    if ($mainConfig) { $null = $rec.config_paths.Add($mainConfig) }
    if ($webConfig)  { $null = $rec.config_paths.Add($webConfig) }

    if ($webConfig -and (Test-Path -LiteralPath $webConfig)) {
        $wc = Read-SafeFile $webConfig
        $authBits = @()
        if ($wc -match '(?im)^\s*tls_server_config\s*:') { $authBits += 'tls_server_config'; $rec.tls.enabled = $true }
        if ($wc -match '(?im)^\s*basic_auth_users\s*:')  { $authBits += 'basic_auth_users' }
        if ($authBits.Count -gt 0) {
            $rec.authentication.mode   = ($authBits -join ' + ')
            $rec.authentication.source = $webConfig
        } else {
            $rec.authentication.mode   = 'web.config.file present but no tls_server_config / basic_auth_users'
            $rec.authentication.source = $webConfig
        }
    } else {
        $rec.authentication.mode   = 'No native auth (typically fronted by reverse proxy for basic/TLS)'
        $rec.authentication.source = 'no --web.config.file'
    }

    if (-not ($rec.listen | Where-Object { $_.local_port -eq 9090 })) {
        $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(default)'; local_port=9090; source='Prometheus default' })
    }
    $null = $rec.notes.Add('Time-series DB. Targets/scrape config in --config.file; write access usually off by default.')
    Add-InstanceFinding $rec
}

# ============================================================================
# H2 / HSQLDB / APACHE DERBY (server mode)  (v2.0)
# ============================================================================
#
# These are Java-embedded engines. Server-mode detection is primarily by
# inspecting java.exe process command lines for the engine JAR or main class.
# Embedded-in-app usage (the engine running in-process inside another JVM
# without a network listener) is NOT reported.

function Invoke-JavaEmbeddedServerDiscovery {
    param($Services, $Processes, $Sockets)

    $javaProcs = $Processes | Where-Object { $_.name -match '^java(w)?(\.exe)?$' }
    if (-not $javaProcs) { return }

    $patterns = @(
        [pscustomobject]@{
            Product       = 'H2 Database (server mode)'
            Vendor        = 'H2 Group'
            Match         = '(?i)(h2-[\d\.]+\.jar|org\.h2\.tools\.Server|org\.h2\.server)'
            DefaultPort   = 9092
            AuthNote      = 'H2 server: user / password stored in the database file; TLS via -tcpSSL. Check command-line for -tcpAllowOthers (enables remote clients) and -tcpPassword (mgmt password).'
        }
        [pscustomobject]@{
            Product       = 'HSQLDB (server mode)'
            Vendor        = 'HSQL Development Group'
            Match         = '(?i)(hsqldb[-_][\d\.]+\.jar|org\.hsqldb\.Server|org\.hsqldb\.server\.Server)'
            DefaultPort   = 9001
            AuthNote      = 'HSQLDB: user table in server database. Authentication is internal; TLS via server.tls=true in server.properties.'
        }
        [pscustomobject]@{
            Product       = 'Apache Derby (Network Server)'
            Vendor        = 'Apache'
            Match         = '(?i)(derbynet\.jar|derbyrun\.jar|org\.apache\.derby\.drda\.NetworkServerControl)'
            DefaultPort   = 1527
            AuthNote      = 'Derby Network Server: authentication requires derby.connection.requireAuthentication=true in derby.properties; otherwise anonymous connections are allowed.'
        }
    )

    foreach ($proc in $javaProcs) {
        $cl = $proc.command_line
        if (-not $cl) { continue }
        foreach ($pat in $patterns) {
            if ($cl -match $pat.Match) {
                $rec = New-InstanceRecord -Product $pat.Product -Vendor $pat.Vendor
                $rec.instance_name             = ('pid-' + [string]$proc.pid)
                $rec.install_path              = $proc.executable
                $rec.authentication.mode       = $pat.AuthNote
                $rec.authentication.source     = 'java command-line inspection'

                $null = $rec.processes.Add([ordered]@{
                    pid=$proc.pid; name=$proc.name; executable=$proc.executable; owner=$proc.owner
                    command_line=$cl
                })

                foreach ($ls in (Get-ListenForPid $Sockets $proc.pid)) {
                    $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
                }

                # Add default-port hint if nothing else matched
                if ($rec.listen.Count -eq 0) {
                    $null = $rec.listen.Add([ordered]@{
                        protocol='tcp'; local_ip='(default)'; local_port=$pat.DefaultPort; source=($pat.Product + ' default')
                    })
                }

                $null = $rec.notes.Add('Detected via java command-line inspection. If running in true embedded (in-process) mode without a listener, this record will NOT be emitted.')
                Add-InstanceFinding $rec
                break   # don't match multiple engine signatures against the same process
            }
        }
    }
}

# ============================================================================
# EMBEDDED ENGINE FILESYSTEM SCAN (SQLite, MS Access) - opt-in only  (v2.0)
# ============================================================================
#
# Guardrails:
#   - Directory allowlist (caller-overridable via -EmbeddedPaths).
#   - Always-excluded: Windows, Program Files\Microsoft Office (Outlook PSTs
#     and Office embedded DBs create huge false-positive volume), user
#     AppData (browsers, chat apps, Electron).
#   - Size floor: 256 KB minimum.
#   - Magic-byte validation (SQLite "SQLite format 3\0", Access Jet/ACE sig).
#   - Per-engine hit cap: 500 files; when hit, a WARN log line is emitted.
#   - Files are reported individually as one instance each so the operator
#     can prioritize by path + size.

$script:EmbeddedHitCap = 500
$script:EmbeddedMinSize = 256KB

# Dirs ALWAYS excluded, even if the caller names them explicitly.
$script:EmbeddedAlwaysExcluded = @(
    'C:\Windows'
    'C:\Windows\WinSxS'
    'C:\Windows\Installer'
    'C:\Windows\assembly'
    "$env:USERPROFILE"
    'C:\Users'
    'C:\ProgramData\Microsoft\Windows Defender'
    'C:\Program Files\Microsoft Office'
    'C:\Program Files (x86)\Microsoft Office'
    'C:\Program Files\Common Files\microsoft shared'
)

function Test-PathUnderExcluded {
    param([string]$Path)
    $p = $Path.ToLowerInvariant().TrimEnd('\')
    foreach ($e in $script:EmbeddedAlwaysExcluded) {
        $en = $e.ToLowerInvariant().TrimEnd('\')
        if ($p -eq $en -or $p.StartsWith($en + '\')) { return $true }
    }
    return $false
}

function Get-DefaultEmbeddedPaths {
    $defaults = @('C:\inetpub','C:\ProgramData','C:\Program Files','C:\Program Files (x86)')
    foreach ($letter in 'D','E','F','G') {
        $p = '{0}:\' -f $letter
        if (Test-Path -LiteralPath $p) { $defaults += $p }
    }
    return $defaults
}

function Test-SqliteMagic {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] 16
            $read = $fs.Read($buf, 0, 16)
            if ($read -lt 16) { return $false }
            $sig = [System.Text.Encoding]::ASCII.GetString($buf, 0, 15)
            return ($sig -eq 'SQLite format 3')
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Test-AccessMagic {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] 20
            $read = $fs.Read($buf, 0, 20)
            if ($read -lt 20) { return $false }
            # Access/Jet DBs begin with a 4-byte ID followed by "Standard Jet DB" or "Standard ACE DB"
            $tail = [System.Text.Encoding]::ASCII.GetString($buf, 4, 15)
            return ($tail -eq 'Standard Jet DB' -or $tail -eq 'Standard ACE DB')
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Invoke-EmbeddedFilesystemScan {
    if (-not $IncludeEmbeddedEngines) {
        Write-Log 'Embedded-engine filesystem scan: skipped (flag not set).' -Level '--'
        return
    }

    Write-Log 'Embedded-engine filesystem scan: ENABLED (-IncludeEmbeddedEngines).' -Level 'WARN'
    Write-Log 'This walks selected directories, validates magic bytes, and reports each matching file.' -Level 'INFO'

    $searchPaths = @()
    if ($EmbeddedPaths -and $EmbeddedPaths.Count -gt 0) {
        $searchPaths = $EmbeddedPaths
    } else {
        $searchPaths = Get-DefaultEmbeddedPaths
    }
    Write-Log ('Embedded scan directories: {0}' -f ($searchPaths -join '; ')) -Level 'INFO'
    Write-Log ('Size floor: {0} bytes   Per-engine hit cap: {1}' -f $script:EmbeddedMinSize, $script:EmbeddedHitCap) -Level 'INFO'

    $sqliteExts = '.sqlite','.sqlite3','.db','.db3'
    $accessExts = '.mdb','.accdb'
    $sqliteHits = 0
    $accessHits = 0

    foreach ($root in $searchPaths) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        if (Test-PathUnderExcluded $root) {
            Write-Log ('Skipping excluded root: {0}' -f $root) -Level '--'
            continue
        }
        Write-Log ('Walking: {0}' -f $root) -Level 'INFO'

        try {
            $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue
        } catch {
            Add-Warning ('Embedded-scan enumeration failed under {0}: {1}' -f $root, $_.Exception.Message)
            continue
        }

        foreach ($f in $files) {
            if ($null -eq $f) { continue }
            if (Test-PathUnderExcluded $f.FullName) { continue }
            if ($f.Length -lt $script:EmbeddedMinSize) { continue }

            $ext = $f.Extension.ToLowerInvariant()
            $engine = $null
            $magicOk = $false
            if ($sqliteExts -contains $ext) {
                if ($sqliteHits -ge $script:EmbeddedHitCap) { continue }
                if (Test-SqliteMagic $f.FullName) { $engine = 'SQLite'; $magicOk = $true }
            } elseif ($accessExts -contains $ext) {
                if ($accessHits -ge $script:EmbeddedHitCap) { continue }
                if (Test-AccessMagic $f.FullName) { $engine = 'Microsoft Access'; $magicOk = $true }
            }
            if (-not $magicOk) { continue }

            $rec = New-InstanceRecord -Product $engine -Vendor 'Embedded'
            $rec.instance_name             = $f.Name
            $rec.install_path              = $f.FullName
            $rec.data_path                 = $f.FullName
            $rec.authentication.mode       = if ($engine -eq 'SQLite') {
                'No built-in authentication (SQLite relies on filesystem ACLs); optional SQLCipher extension provides full-database encryption.'
            } else {
                'Access / Jet: workgroup file or database password. Anonymous by default when workgroup info is absent.'
            }
            $rec.authentication.source     = 'file magic bytes'
            $rec.database_enumeration_method = 'filesystem_scan'
            $null = $rec.databases.Add($f.BaseName)
            $null = $rec.notes.Add(('Size: {0} bytes   Last-modified: {1}' -f $f.Length, $f.LastWriteTimeUtc.ToString('o')))
            Add-InstanceFinding $rec

            if ($engine -eq 'SQLite') { $sqliteHits++ } else { $accessHits++ }
            if ($sqliteHits -ge $script:EmbeddedHitCap -and $accessHits -ge $script:EmbeddedHitCap) {
                Write-Log 'Both per-engine hit caps reached; stopping embedded-scan traversal.' -Level 'WARN'
                $script:CountWarnings++
                return
            }
        }
    }

    if ($sqliteHits -ge $script:EmbeddedHitCap) {
        Write-Log ('SQLite hit cap ({0}) reached; consider narrowing -EmbeddedPaths.' -f $script:EmbeddedHitCap) -Level 'WARN'
        $script:CountWarnings++
    }
    if ($accessHits -ge $script:EmbeddedHitCap) {
        Write-Log ('Access hit cap ({0}) reached; consider narrowing -EmbeddedPaths.' -f $script:EmbeddedHitCap) -Level 'WARN'
        $script:CountWarnings++
    }
    Write-Log ('Embedded scan complete. SQLite: {0}  Access: {1}' -f $sqliteHits, $accessHits) -Level 'OK'
}

# ============================================================================
# DEEP PROBE (opt-in; local trust-based catalog enumeration)
# ============================================================================

function Invoke-DeepProbe {
    Write-Log 'Deep-probe enabled: will open LOCAL, trust-based connections to discovered instances.' -Level 'WARN'
    Write-Log 'Any DB audit trail will record these queries. Coordinate with DBAs.' -Level 'WARN'

    foreach ($rec in $Instances) {
        switch -Regex ($rec.product) {
            'Microsoft SQL Server$' {
                $port = $null
                foreach ($l in $rec.listen) { if ($l.source -eq 'live_socket' -or $l.source -like 'registry*') { $port = $l.local_port; break } }
                $serverSpec = '.'
                if ($rec.instance_name -and $rec.instance_name -ne 'MSSQLSERVER') { $serverSpec = '.\' + $rec.instance_name }
                if ($DryRun) {
                    Write-Log ('[dry-run] Would probe MSSQL instance {0} (port {1})' -f $serverSpec, $port) -Level '--'
                    continue
                }
                try {
                    $connStr = 'Server={0};Database=master;Integrated Security=SSPI;Connect Timeout=3;Encrypt=false' -f $serverSpec
                    $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
                    $conn.Open()
                    $cmd = $conn.CreateCommand()
                    $cmd.CommandText = 'SELECT name FROM sys.databases ORDER BY name'
                    $cmd.CommandTimeout = 3
                    $rdr = $cmd.ExecuteReader()
                    $names = New-Object System.Collections.Generic.List[object]
                    while ($rdr.Read()) { $null = $names.Add($rdr.GetString(0)) }
                    $rdr.Close(); $conn.Close()
                    foreach ($n in $names) { if (-not $rec.databases.Contains($n)) { $null = $rec.databases.Add($n) } }
                    $rec.database_enumeration_method = 'deep_probe'
                    Write-Log ('Deep-probed MSSQL {0}: {1} databases' -f $serverSpec, $names.Count) -Level 'OK'
                } catch {
                    $null = $rec.collection_warnings.Add('MSSQL deep-probe failed: ' + $_.Exception.Message)
                    Add-Warning ('MSSQL deep-probe failed on {0}: {1}' -f $serverSpec, $_.Exception.Message)
                }
            }
            '^PostgreSQL$' {
                if (-not (Test-CommandExists 'psql')) {
                    $null = $rec.collection_warnings.Add('psql not in PATH; Postgres deep-probe skipped')
                    continue
                }
                $port = $null
                foreach ($l in $rec.listen) { if ($l.source -eq 'live_socket') { $port = $l.local_port; break } }
                if (-not $port) { foreach ($l in $rec.listen) { $port = $l.local_port; break } }
                if ($DryRun) {
                    Write-Log ('[dry-run] Would probe PostgreSQL on port {0}' -f $port) -Level '--'
                    continue
                }
                try {
                    $env:PGCONNECT_TIMEOUT = '3'
                    $out = & psql -h 127.0.0.1 -p $port -U postgres -d postgres -A -t -c 'SELECT datname FROM pg_database ORDER BY datname' 2>$null
                    if ($LASTEXITCODE -eq 0 -and $out) {
                        foreach ($line in ($out -split "`r?`n")) {
                            $n = $line.Trim()
                            if ($n -and -not $rec.databases.Contains($n)) { $null = $rec.databases.Add($n) }
                        }
                        $rec.database_enumeration_method = 'deep_probe'
                        Write-Log ('Deep-probed Postgres (port {0}): {1} databases' -f $port, $rec.databases.Count) -Level 'OK'
                    } else {
                        $null = $rec.collection_warnings.Add('psql returned non-zero or empty (peer-auth may not be permitted for current principal)')
                    }
                } catch {
                    $null = $rec.collection_warnings.Add('Postgres deep-probe failed: ' + $_.Exception.Message)
                }
            }
            default {
                # Deep-probe not implemented for this product in v1.0
            }
        }
    }
}

# ============================================================================
# ACTIVE DIRECTORY ENRICHMENT (opt-in)
# ============================================================================

function Get-AdAccountDetails {
    param([string]$SamAccount)
    if ([string]::IsNullOrWhiteSpace($SamAccount)) { return $null }

    # Prefer Get-ADUser if available
    if (Test-CommandExists 'Get-ADUser') {
        try {
            $u = Get-ADUser -Identity $SamAccount -Properties DisplayName,Enabled,PasswordLastSet,LastLogonDate,MemberOf,Mail -ErrorAction Stop
            return [ordered]@{
                source           = 'Get-ADUser'
                display_name     = $u.DisplayName
                enabled          = [bool]$u.Enabled
                password_last_set= if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('o') } else { $null }
                last_logon       = if ($u.LastLogonDate)   { $u.LastLogonDate.ToString('o') }   else { $null }
                mail             = $u.Mail
                distinguished_name = $u.DistinguishedName
                member_of        = @($u.MemberOf)
            }
        } catch {
            # fall through to ADSI
        }
    }

    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=user)(sAMAccountName=$SamAccount))"
        foreach ($p in @('displayName','userAccountControl','pwdLastSet','lastLogonTimestamp','memberOf','distinguishedName','mail')) {
            [void]$searcher.PropertiesToLoad.Add($p)
        }
        $searcher.ClientTimeout      = [TimeSpan]::FromSeconds(3)
        $searcher.ServerTimeLimit    = [TimeSpan]::FromSeconds(3)
        $result = $searcher.FindOne()
        if (-not $result) { return $null }
        $props = $result.Properties
        $enabled = $null
        if ($props['userAccountControl'] -and $props['userAccountControl'].Count -gt 0) {
            $uac = [int]$props['userAccountControl'][0]
            $enabled = -not ([bool]($uac -band 0x2))   # ACCOUNTDISABLE flag
        }
        $pwdLast = $null
        if ($props['pwdLastSet'] -and $props['pwdLastSet'].Count -gt 0) {
            $ft = [int64]$props['pwdLastSet'][0]
            if ($ft -gt 0) { $pwdLast = [DateTime]::FromFileTimeUtc($ft).ToString('o') }
        }
        $last = $null
        if ($props['lastLogonTimestamp'] -and $props['lastLogonTimestamp'].Count -gt 0) {
            $ft = [int64]$props['lastLogonTimestamp'][0]
            if ($ft -gt 0) { $last = [DateTime]::FromFileTimeUtc($ft).ToString('o') }
        }
        return [ordered]@{
            source            = 'ADSI'
            display_name      = [string]($props['displayName'] -join '')
            enabled           = $enabled
            password_last_set = $pwdLast
            last_logon        = $last
            mail              = [string]($props['mail'] -join '')
            distinguished_name= [string]($props['distinguishedName'] -join '')
            member_of         = @($props['memberOf'])
        }
    } catch {
        Add-Warning ('ADSI lookup failed for {0}: {1}' -f $SamAccount, $_.Exception.Message)
        return $null
    }
}

function Invoke-AdEnrichment {
    Write-Log 'AD enrichment enabled: resolving domain service accounts against Active Directory.' -Level 'INFO'
    $cache = @{}
    foreach ($rec in $Instances) {
        if (-not $rec.service) { continue }
        $acct = $rec.service.account
        if ([string]::IsNullOrWhiteSpace($acct)) { continue }
        $acctType = Resolve-ServiceAccountType $acct
        if ($acctType -ne 'domain_user' -and $acctType -ne 'managed_service_account') { continue }
        $sam = $acct
        if ($sam -match '\\(.+)$') { $sam = $Matches[1] }
        if ($sam -match '\$$') { }   # keep $ for gMSA/MSA
        if ($cache.ContainsKey($sam)) {
            $rec.ad_lookup = $cache[$sam]
            continue
        }
        $info = Get-AdAccountDetails -SamAccount $sam
        if ($info) {
            $cache[$sam] = $info
            $rec.ad_lookup = $info
            Write-Log ('AD resolved: {0} ({1})' -f $acct, $info.source) -Level 'OK'
        } else {
            $null = $rec.collection_warnings.Add('AD lookup returned no result for ' + $acct)
        }
    }
}

# ============================================================================
# MAIN
# ============================================================================

$TotalSteps = 9
Write-Log ('{0} v{1} started at {2}' -f $ScriptName, $ScriptVersion, $StartedAt.ToString('o')) -Level 'INFO'
Write-Log '----- parameters -----' -Level 'INFO'
Write-Log ('DeepProbe              : {0}' -f $DeepProbe)              -Level 'INFO'
Write-Log ('IncludeAdLookup        : {0}' -f $IncludeAdLookup)        -Level 'INFO'
Write-Log ('IncludeEmbeddedEngines : {0}' -f $IncludeEmbeddedEngines) -Level 'INFO'
$EmbPathsShown = '(defaults)'
if ($EmbeddedPaths.Count -gt 0) { $EmbPathsShown = ($EmbeddedPaths -join ', ') }
Write-Log ('EmbeddedPaths          : {0}' -f $EmbPathsShown)          -Level 'INFO'
Write-Log ('SkipNetwork            : {0}' -f $SkipNetwork)            -Level 'INFO'
Write-Log ('DryRun                 : {0}' -f $DryRun)                 -Level 'INFO'
Write-Log ('Retain                 : {0}' -f $Retain)                 -Level 'INFO'
Write-Log ('JsonOnly               : {0}' -f $JsonOnly)               -Level 'INFO'
Write-Log ('OutputPath             : {0}' -f $OutputPath)             -Level 'INFO'
Write-Log '----------------------' -Level 'INFO'
Write-Log ('Log: {0}' -f $LogPath)  -Level 'INFO'
Write-Log ('JSON: {0}' -f $JsonPath) -Level 'INFO'
if ($DeepProbe)       { Write-Log 'DeepProbe: ENABLED (local trust queries will occur).' -Level 'WARN' }
if ($IncludeAdLookup) { Write-Log 'IncludeAdLookup: ENABLED (LDAP queries to DC will occur).' -Level 'WARN' }
if ($DryRun)          { Write-Log 'DryRun: ENABLED (deep-probe will log intent only).' -Level 'INFO' }
if ($SkipNetwork)     { Write-Log 'SkipNetwork: ENABLED (listening sockets not enumerated).' -Level 'INFO' }

Invoke-OutputCleanup

Write-Log ('[Step 1/{0}] Host identity' -f $TotalSteps) -Level 'INFO'
$hostInfo = Get-HostIdentity
Write-Log ('Host: {0}  FQDN: {1}  Domain: {2} (joined={3})  OS: {4}' -f $hostInfo.hostname, $hostInfo.fqdn, $hostInfo.domain, $hostInfo.domain_joined, $hostInfo.os) -Level 'OK'
foreach ($ip in $hostInfo.ip_addresses) {
    Write-Log ('  IP: {0} ({1}) on {2}' -f $ip.address, $ip.family, $ip.interface) -Level '--'
}

Write-Log ('[Step 2/{0}] Enumerating DB-like services...' -f $TotalSteps) -Level 'INFO'
$services = Get-AllDatabaseServices
Write-Log ('Found {0} matching service(s).' -f $services.Count) -Level 'OK'

Write-Log ('[Step 3/{0}] Enumerating DB-like processes...' -f $TotalSteps) -Level 'INFO'
$processes = Get-AllDatabaseProcesses
Write-Log ('Found {0} matching process(es).' -f $processes.Count) -Level 'OK'

Write-Log ('[Step 4/{0}] Enumerating listening sockets...' -f $TotalSteps) -Level 'INFO'
$sockets = Get-ListeningSockets
Write-Log ('Collected {0} listening socket(s).' -f $sockets.Count) -Level 'OK'

Write-Log ('[Step 5/{0}] Per-product discovery...' -f $TotalSteps) -Level 'INFO'
Invoke-SqlServerDiscovery         -Services $services -Processes $processes -Sockets $sockets
Invoke-SqlServerLocalDbDiscovery
Invoke-SsasDiscovery              -Services $services -Processes $processes -Sockets $sockets
Invoke-SsrsDiscovery              -Services $services -Processes $processes -Sockets $sockets
Invoke-SsisDiscovery              -Services $services -Processes $processes -Sockets $sockets
Invoke-OracleDiscovery            -Services $services -Processes $processes -Sockets $sockets
Invoke-MySqlDiscovery             -Services $services -Processes $processes -Sockets $sockets
Invoke-PostgresDiscovery          -Services $services -Processes $processes -Sockets $sockets
Invoke-MongoDbDiscovery           -Services $services -Processes $processes -Sockets $sockets
Invoke-RedisDiscovery             -Services $services -Processes $processes -Sockets $sockets
Invoke-Db2Discovery               -Services $services -Processes $processes -Sockets $sockets
Invoke-SybaseAseDiscovery         -Services $services -Processes $processes -Sockets $sockets
Invoke-MaxDbDiscovery             -Services $services -Processes $processes -Sockets $sockets
Invoke-InformixDiscovery          -Services $services -Processes $processes -Sockets $sockets
Invoke-FirebirdDiscovery          -Services $services -Processes $processes -Sockets $sockets
Invoke-TeradataDiscovery          -Services $services -Processes $processes -Sockets $sockets
Invoke-InfluxDbDiscovery          -Services $services -Processes $processes -Sockets $sockets
Invoke-ClickHouseDiscovery        -Services $services -Processes $processes -Sockets $sockets
Invoke-CouchbaseDiscovery         -Services $services -Processes $processes -Sockets $sockets
Invoke-Neo4jDiscovery             -Services $services -Processes $processes -Sockets $sockets
Invoke-ElasticsearchDiscovery     -Services $services -Processes $processes -Sockets $sockets
Invoke-OpenSearchDiscovery        -Services $services -Processes $processes -Sockets $sockets
Invoke-RavenDbDiscovery           -Services $services -Processes $processes -Sockets $sockets
# v2.0 additions
Invoke-EtcdDiscovery              -Services $services -Processes $processes -Sockets $sockets
Invoke-ConsulDiscovery            -Services $services -Processes $processes -Sockets $sockets
Invoke-MemcachedDiscovery         -Services $services -Processes $processes -Sockets $sockets
Invoke-PrometheusDiscovery        -Services $services -Processes $processes -Sockets $sockets
Invoke-JavaEmbeddedServerDiscovery -Services $services -Processes $processes -Sockets $sockets
Write-Log ('Per-product pass complete: {0} instance(s) recorded.' -f $Instances.Count) -Level 'OK'

Write-Log ('[Step 6/{0}] Embedded-engine filesystem scan...' -f $TotalSteps) -Level 'INFO'
Invoke-EmbeddedFilesystemScan

Write-Log ('[Step 7/{0}] Deep probe...' -f $TotalSteps) -Level 'INFO'
if ($DeepProbe) {
    Invoke-DeepProbe
} else {
    Write-Log 'Deep probe: skipped (flag not set).' -Level '--'
}

Write-Log ('[Step 8/{0}] AD enrichment...' -f $TotalSteps) -Level 'INFO'
if ($IncludeAdLookup) {
    Invoke-AdEnrichment
} else {
    Write-Log 'AD enrichment: skipped (flag not set).' -Level '--'
}

Write-Log ('[Step 9/{0}] Summary + JSON export...' -f $TotalSteps) -Level 'INFO'
$FinishedAt = Get-Date
$elapsed = $FinishedAt - $StartedAt

$productCounts = @{}
foreach ($i in $Instances) {
    if (-not $productCounts.ContainsKey($i.product)) { $productCounts[$i.product] = 0 }
    $productCounts[$i.product]++
}

Write-Log '----------------------------------------------------------------' -Level 'INFO'
Write-Log ('SUMMARY: {0} instance(s) across {1} product(s).' -f $Instances.Count, $productCounts.Keys.Count) -Level 'OK'
foreach ($k in ($productCounts.Keys | Sort-Object)) {
    Write-Log ('  {0}: {1}' -f $k, $productCounts[$k]) -Level 'FIND'
}
Write-Log ('Warnings: {0}   Errors: {1}   Elapsed: {2:N1}s' -f $CountWarnings, $CountErrors, $elapsed.TotalSeconds) -Level 'INFO'

$doc = [ordered]@{
    scan = [ordered]@{
        script        = $ScriptName
        version       = $ScriptVersion
        started_at    = $StartedAt.ToString('o')
        finished_at   = $FinishedAt.ToString('o')
        elapsed_seconds = [math]::Round($elapsed.TotalSeconds, 2)
        options       = [ordered]@{
            deep_probe               = [bool]$DeepProbe
            include_ad_lookup        = [bool]$IncludeAdLookup
            include_embedded_engines = [bool]$IncludeEmbeddedEngines
            embedded_paths           = @($EmbeddedPaths)
            json_only                = [bool]$JsonOnly
            skip_network             = [bool]$SkipNetwork
            dry_run                  = [bool]$DryRun
            retain                   = $Retain
        }
    }
    host        = $hostInfo
    instances   = @($Instances)
    product_counts = $productCounts
    warnings    = @($WarningList)
    errors      = @($ErrorList)
    counts      = [ordered]@{
        instances = $Instances.Count
        warnings  = $CountWarnings
        errors    = $CountErrors
    }
}

Save-Log
Save-Json $doc

$exit = 0
if ($CountErrors -gt 0) { $exit = 1 }
elseif ($CountWarnings -gt 0) { $exit = 1 }
exit $exit

# ============================================================================
# POSTGRESQL (incl. Greenplum / EDB Postgres)
# ============================================================================

function Invoke-PostgresDiscovery {
    param($Services, $Processes, $Sockets)

    $installsKey = 'HKLM:\SOFTWARE\PostgreSQL\Installations'
    $installs = Get-SafeRegSubkeys $installsKey
    $edbKey   = 'HKLM:\SOFTWARE\EnterpriseDB'
    if (Test-Path -LiteralPath $edbKey) {
        $installs += (Get-SafeRegSubkeys $edbKey)
    }
    if ((-not $installs -or $installs.Count -eq 0) -and
        -not ($Services | Where-Object { $_.name -match '^postgres' })) {
        Write-Log 'No PostgreSQL instances found.' -Level '--'
        return
    }

    foreach ($k in $installs) {
        $rec = New-InstanceRecord -Product 'PostgreSQL' -Vendor 'PostgreSQL'
        $rec.version      = Get-SafeRegValue $k.PSPath 'Version'
        $rec.instance_id  = Get-SafeRegValue $k.PSPath 'ServiceID'
        $rec.instance_name = $rec.instance_id
        $rec.install_path = Get-SafeRegValue $k.PSPath 'Base Directory'
        $rec.data_path    = Get-SafeRegValue $k.PSPath 'Data Directory'
        $regPort          = Get-SafeRegValue $k.PSPath 'Port'
        if ($regPort) {
            $null = $rec.listen.Add([ordered]@{
                protocol='tcp'; local_ip='(registry)'; local_port=[int]$regPort; source='HKLM\SOFTWARE\PostgreSQL\Installations'
            })
        }

        # Parse postgresql.conf
        if ($rec.data_path) {
            $pgConf = Join-Path $rec.data_path 'postgresql.conf'
            if (Test-Path -LiteralPath $pgConf) {
                $null = $rec.config_paths.Add($pgConf)
                $content = Read-SafeFile $pgConf
                if ($content) {
                    if ($content -match '(?im)^\s*port\s*=\s*(\d+)') {
                        $null = $rec.listen.Add([ordered]@{
                            protocol='tcp'; local_ip='(postgresql.conf)'; local_port=[int]$Matches[1]; source='postgresql.conf:port'
                        })
                    }
                    if ($content -match "(?im)^\s*listen_addresses\s*=\s*'([^']*)'") {
                        $null = $rec.notes.Add('listen_addresses=' + $Matches[1])
                    }
                    if ($content -match '(?im)^\s*ssl\s*=\s*(on|off|true|false)') {
                        $rec.tls.enabled = ($Matches[1] -match '(?i)on|true')
                    }
                }
            }

            # pg_hba.conf -> auth methods
            $pgHba = Join-Path $rec.data_path 'pg_hba.conf'
            if (Test-Path -LiteralPath $pgHba) {
                $null = $rec.config_paths.Add($pgHba)
                $hba = Read-SafeFile $pgHba
                if ($hba) {
                    $methods = @{}
                    foreach ($line in ($hba -split "`n")) {
                        $line = $line.Trim()
                        if ($line -eq '' -or $line.StartsWith('#')) { continue }
                        $parts = ($line -split '\s+') | Where-Object { $_ -ne '' }
                        if ($parts.Count -lt 4) { continue }
                        # TYPE DATABASE USER [ADDRESS] METHOD [OPTIONS]
                        $type = $parts[0]
                        $method = $parts[4]
                        if ($type -eq 'local') { $method = $parts[3] }
                        if ($method) {
                            if (-not $methods.ContainsKey($method)) { $methods[$method] = 0 }
                            $methods[$method]++
                            $null = $rec.authentication.details.Add(
                                ('type={0} db={1} user={2} method={3}' -f $type, $parts[1], $parts[2], $method)
                            )
                        }
                    }
                    if ($methods.Count -gt 0) {
                        $rec.authentication.mode   = 'pg_hba.conf: ' + (($methods.Keys | Sort-Object) -join ',')
                        $rec.authentication.source = $pgHba
                        if ($methods.ContainsKey('ldap'))                  { $rec.authentication.ad_integrated = $true }
                        if ($methods.ContainsKey('gss') -or $methods.ContainsKey('sspi')) {
                            $rec.authentication.ad_integrated   = $true
                            $rec.authentication.integrated_auth = $true
                        }
                    }
                }
            }

            # Database directory enumeration: base/ contains numeric OIDs; names live in pg_database (binary).
            # For config/filesystem mode, count OIDs; deep-probe will resolve names.
            $baseDir = Join-Path $rec.data_path 'base'
            if (Test-Path -LiteralPath $baseDir) {
                try {
                    $oidDirs = Get-ChildItem -LiteralPath $baseDir -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^\d+$' }
                    if ($oidDirs.Count -gt 0) {
                        $null = $rec.notes.Add(('base/ contains {0} database OIDs (names require deep-probe)' -f $oidDirs.Count))
                    }
                } catch {}
            }
        }

        # Matching service
        $svcMatch = "^postgresql.*$rec.version" -replace '\.', '\.'
        $svc = $Services | Where-Object { $_.name -match '^postgresql' -and ($null -eq $rec.version -or $_.name -like ('*' + $rec.version + '*')) } | Select-Object -First 1
        if (-not $svc) { $svc = $Services | Where-Object { $_.name -match '^postgresql' } | Select-Object -First 1 }
        if ($svc) {
            $rec.service = [ordered]@{
                name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
                image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
            }
            if ($svc.process_id -gt 0) {
                foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                    $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
                }
            }
        }

        Add-InstanceFinding $rec
    }
}

# ============================================================================
# MYSQL / MARIADB / PERCONA SERVER
# ============================================================================

function Invoke-MySqlDiscovery {
    param($Services, $Processes, $Sockets)

    $candidateServices = $Services | Where-Object {
        $_.name -match '^(MySQL.*|MariaDB.*|Percona.*)$' -or $_.display_name -match '(MySQL|MariaDB|Percona)'
    }
    if (-not $candidateServices) { return }

    foreach ($svc in $candidateServices) {
        # Determine product label by inspecting service name/display
        $product = 'MySQL'
        $vendor  = 'Oracle'
        if ($svc.name -match 'MariaDB' -or $svc.display_name -match 'MariaDB') { $product = 'MariaDB'; $vendor = 'MariaDB' }
        elseif ($svc.name -match 'Percona' -or $svc.display_name -match 'Percona') { $product = 'Percona Server'; $vendor = 'Percona' }

        $rec = New-InstanceRecord -Product $product -Vendor $vendor
        $rec.instance_name = $svc.name
        $rec.install_path  = $svc.image_path

        # Extract --defaults-file from the service image path if present
        $cfgPath = $null
        if ($svc.image_path -and ($svc.image_path -match '--defaults-file=(?<q>"?)([^"]+?)\k<q>(?=\s|$)')) {
            $cfgPath = $Matches[2]
        }
        if (-not $cfgPath) {
            # Try common defaults
            $candidates = @(
                'C:\ProgramData\MySQL\MySQL Server 8.0\my.ini'
                'C:\ProgramData\MySQL\MySQL Server 5.7\my.ini'
                'C:\Program Files\MariaDB 11.3\data\my.ini'
                'C:\Program Files\MariaDB 10.11\data\my.ini'
                'C:\Program Files\MariaDB 10.6\data\my.ini'
            )
            foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { $cfgPath = $c; break } }
        }

        if ($cfgPath) { $null = $rec.config_paths.Add($cfgPath) }
        $cfg = Read-SafeFile $cfgPath
        if ($cfg) {
            if ($cfg -match '(?im)^\s*port\s*=\s*(\d+)')     {
                $null = $rec.listen.Add([ordered]@{ protocol='tcp'; local_ip='(my.ini)'; local_port=[int]$Matches[1]; source='my.ini:port' })
            }
            if ($cfg -match '(?im)^\s*datadir\s*=\s*(.+)$')  { $rec.data_path = ($Matches[1].Trim().Trim('"')) }

            # Authentication plugin / LDAP / PAM hints
            $authBits = New-Object System.Collections.Generic.List[object]
            if ($cfg -match '(?im)^\s*default[_-]authentication[_-]plugin\s*=\s*(\S+)') {
                $null = $authBits.Add('default_authentication_plugin=' + $Matches[1])
            }
            $plugins = [regex]::Matches($cfg, '(?im)^\s*plugin[_-]load(?:[_-]add)?\s*=\s*(.+)$')
            foreach ($m in $plugins) { $null = $authBits.Add('plugin_load=' + $m.Groups[1].Value.Trim()) }

            if ($cfg -match '(?i)authentication_ldap') {
                $rec.authentication.mode = 'LDAP (authentication_ldap_* plugin)'
                $rec.authentication.ad_integrated = $true
            } elseif ($cfg -match '(?i)auth[_-]pam|authentication_pam') {
                $rec.authentication.mode = 'PAM'
            } elseif ($cfg -match '(?im)^\s*default[_-]authentication[_-]plugin\s*=\s*(\S+)') {
                $rec.authentication.mode = 'Native ({0})' -f $Matches[1]
            } else {
                $rec.authentication.mode = 'Native (default plugin not explicitly set)'
            }
            $rec.authentication.source = $cfgPath
            foreach ($b in $authBits) { $null = $rec.authentication.details.Add($b) }

            # Data directory -> db enumeration (each subdir is a database name)
            if ($rec.data_path -and (Test-Path -LiteralPath $rec.data_path)) {
                try {
                    $dirs = Get-ChildItem -LiteralPath $rec.data_path -Directory -ErrorAction Stop
                    foreach ($d in $dirs) {
                        if ($d.Name -match '^(mysql|performance_schema|sys|information_schema|#.+)$') { continue }
                        if (-not $rec.databases.Contains($d.Name)) { $null = $rec.databases.Add($d.Name) }
                    }
                    if ($rec.databases.Count -gt 0) { $rec.database_enumeration_method = 'config_filesystem' }
                } catch {
                    $null = $rec.collection_warnings.Add('datadir listing failed: ' + $_.Exception.Message)
                }
            }
        } else {
            $null = $rec.collection_warnings.Add('my.ini not locatable; auth/port details incomplete')
        }

        $rec.service = [ordered]@{
            name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
            image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
        }
        if ($svc.process_id -gt 0) {
            foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
            }
            foreach ($pr in ($Processes | Where-Object { $_.pid -eq $svc.process_id })) {
                $null = $rec.processes.Add([ordered]@{
                    pid=$pr.pid; name=$pr.name; executable=$pr.executable; owner=$pr.owner; command_line=$pr.command_line
                })
            }
        }

        Add-InstanceFinding $rec
    }
}

# ============================================================================
# ORACLE DATABASE
# ============================================================================

function Invoke-OracleDiscovery {
    param($Services, $Processes, $Sockets)

    $rootKey = 'HKLM:\SOFTWARE\ORACLE'
    $homes = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $rootKey) {
        foreach ($sub in (Get-SafeRegSubkeys $rootKey)) {
            $name = Split-Path -Leaf $sub.PSPath
            if ($name -match '^KEY_|^ALL_HOMES$|^HOME\d+$') {
                $oh   = Get-SafeRegValue $sub.PSPath 'ORACLE_HOME'
                $ohn  = Get-SafeRegValue $sub.PSPath 'ORACLE_HOME_NAME'
                $sid  = Get-SafeRegValue $sub.PSPath 'ORACLE_SID'
                if ($oh) { $null = $homes.Add([pscustomobject]@{ OracleHome=$oh; HomeName=$ohn; Sid=$sid; RegKey=$sub.PSPath }) }
            }
        }
    }

    # Oracle services may exist without registry homes (XE bundles, etc.); also collect SIDs from services.
    $oraServices = $Services | Where-Object { $_.name -match '^OracleService(.+)$' }
    $sidsFromServices = @()
    foreach ($s in $oraServices) {
        if ($s.name -match '^OracleService(.+)$') { $sidsFromServices += $Matches[1] }
    }

    if ($homes.Count -eq 0 -and $oraServices.Count -eq 0) {
        Write-Log 'No Oracle Database instances found.' -Level '--'
        return
    }

    # One record per SID (most useful unit for Oracle); otherwise per ORACLE_HOME.
    $sidsSeen = @{}
    foreach ($sid in $sidsFromServices) {
        if ($sidsSeen.ContainsKey($sid)) { continue }
        $sidsSeen[$sid] = $true

        $rec = New-InstanceRecord -Product 'Oracle Database' -Vendor 'Oracle'
        $rec.instance_name = $sid
        $rec.instance_id   = $sid

        # Pick an ORACLE_HOME (first match on SID, else first home)
        $home = $homes | Where-Object { $_.Sid -eq $sid } | Select-Object -First 1
        if (-not $home) { $home = $homes | Select-Object -First 1 }
        if ($home) {
            $rec.install_path = $home.OracleHome
            $rec.notes.Add('ORACLE_HOME_NAME=' + [string]$home.HomeName) | Out-Null
            $networkAdmin = Join-Path $home.OracleHome 'network\admin'

            $sqlnet = Join-Path $networkAdmin 'sqlnet.ora'
            if (Test-Path -LiteralPath $sqlnet) {
                $null = $rec.config_paths.Add($sqlnet)
                $content = Read-SafeFile $sqlnet
                if ($content) {
                    if ($content -match '(?im)^\s*SQLNET\.AUTHENTICATION_SERVICES\s*=\s*\((.+?)\)') {
                        $svcs = $Matches[1]
                        $rec.authentication.mode   = 'SQLNET.AUTHENTICATION_SERVICES=(' + $svcs + ')'
                        $rec.authentication.source = '{0}:SQLNET.AUTHENTICATION_SERVICES' -f $sqlnet
                        if ($svcs -match '(?i)NTS')       { $rec.authentication.integrated_auth = $true; $rec.authentication.ad_integrated = $true }
                        if ($svcs -match '(?i)KERBEROS5') { $rec.authentication.ad_integrated = $true }
                    } else {
                        $rec.authentication.mode   = 'Default (local OS authentication, password file)'
                        $rec.authentication.source = $sqlnet + ' (no SQLNET.AUTHENTICATION_SERVICES line)'
                    }
                }
            }

            $listener = Join-Path $networkAdmin 'listener.ora'
            if (Test-Path -LiteralPath $listener) {
                $null = $rec.config_paths.Add($listener)
                $content = Read-SafeFile $listener
                if ($content) {
                    $portMatches = [regex]::Matches($content, '(?im)\(PORT\s*=\s*(\d+)\)')
                    foreach ($m in $portMatches) {
                        $null = $rec.listen.Add([ordered]@{
                            protocol    = 'tcp'
                            local_ip    = '(listener.ora)'
                            local_port  = [int]$m.Groups[1].Value
                            source      = 'listener.ora'
                        })
                    }
                }
            }

            $tns = Join-Path $networkAdmin 'tnsnames.ora'
            if (Test-Path -LiteralPath $tns) {
                $null = $rec.config_paths.Add($tns)
                $content = Read-SafeFile $tns
                if ($content) {
                    $svcMatches = [regex]::Matches($content, '(?im)\(SERVICE_NAME\s*=\s*([^\s\)]+)\)')
                    foreach ($m in $svcMatches) {
                        $db = $m.Groups[1].Value
                        if (-not $rec.databases.Contains($db)) { $null = $rec.databases.Add($db) }
                    }
                    if ($rec.databases.Count -gt 0) { $rec.database_enumeration_method = 'config_filesystem' }
                }
            }
        }

        # Matching service
        $svcName = 'OracleService' + $sid
        $svc = $Services | Where-Object { $_.name -eq $svcName } | Select-Object -First 1
        if ($svc) {
            $rec.service = [ordered]@{
                name=$svc.name; display_name=$svc.display_name; state=$svc.state; start_mode=$svc.start_mode
                image_path=$svc.image_path; account=$svc.account; account_type=Resolve-ServiceAccountType $svc.account
            }
            if ($svc.process_id -gt 0) {
                foreach ($ls in (Get-ListenForPid $Sockets $svc.process_id)) {
                    $null = $rec.listen.Add([ordered]@{ protocol=$ls.protocol; local_ip=$ls.local_ip; local_port=$ls.local_port; source='live_socket' })
                }
            }
        }

        Add-InstanceFinding $rec
    }
}
