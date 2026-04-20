# Qualys CAR Parameter Reference

Every script in this repo is parameterized for **Qualys Custom Assessment and
Remediation (CAR)** via **UI-defined POSITIONAL parameters**. CAR passes the
parameters you define on the Script Details page as positional command-line
arguments in the order they appear. It does not set environment variables and
does not pass named flags.

This document is the single reference for what parameters to define, in what
order, with what types and defaults, for each script.

**Reference:** https://docs.qualys.com/en/car/latest/scripts/parameterized_script_examples.htm

---

## Universal Conventions

- **All parameters are type `String` in CAR.** CAR passes everything as a
  string. The scripts coerce strings to bools (`Yes/No/True/False/1/0/On/Off`,
  case-insensitive) and ints where needed.
- **Audit-first.** `RunMode` defaults to `Audit` on every remediation script.
  Destructive action requires explicit `Enforce`.
- **Dual invocation.** Positional args win. If a positional is empty, the
  script checks the same-named environment variable next
  (`$env:RunMode` / `$RUN_MODE`). Defaults apply last. Legacy switch / flag
  forms are still accepted for local testing; don't rely on them in CAR.
- **Password masking.** Scripts mask credential-shaped values (`Password`)
  as `***` in the runtime banner and log file.
- **Exit codes.** `0` = clean, `1` = warnings, `2` = fatal (privilege or
  parameter error). CAR Job Results use the exit code.

### Setup Flow for Every Script

1. Qualys Cloud Platform -> **Custom Assessment and Remediation** -> **Scripts** -> **New Script**.
2. **Script Details** tab:
   - **Name**: copy from the per-script section below.
   - **Platform**: Windows or Linux.
   - **Interpreter**: PowerShell or Bash.
   - **Upload**: the `.ps1` or `.sh` file from this repo.
3. **Parameters** tab: add each parameter in the exact order shown, using the
   listed type and default.
4. Save. Attach to a CAR Job that targets the intended asset tag.
5. For destructive scripts, always run with `RunMode=Audit` on a pilot asset
   before setting `RunMode=Enforce` fleet-wide.

---

## `windows/remediation/Create_Admin.ps1`

**Script name:** Create Admin User (Windows)
**Platform:** Windows | **Interpreter:** PowerShell | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `Username` | String | Yes | (none) | Local account to create/repair/remove. |
| 2 | `Password` | String (mark sensitive) | Yes | (none) | Initial password. **Masked as `***` in output.** |
| 3 | `RunMode` | String | No | `1` | `1` = create-or-repair, `2` = remove. |

**Example values:**
- `TEMPADMIN`, `<strong-literal>`, `1` -> create or repair
- `TEMPADMIN`, `<strong-literal>`, `2` -> remove (terminates user processes, deletes account)

**Operator notes:**
- **Password is visible to any user with script-edit rights on the CAR
  policy.** Rotate after first run and whenever policy editors change.
- `RunMode=2` is destructive. Mode 2 on a host with the target user logged in
  will terminate that session.
- The Windows profile directory under `C:\Users\<user>\` is **not** deleted in
  Mode 2 (data-preservation policy). Clean manually if required.

---

## `linux/remediation/Create_Admin.sh`

**Script name:** Create Admin User (Linux)
**Platform:** Linux | **Interpreter:** Bash | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `Username` | String | Yes | (none) | Local account to create/repair/remove (POSIX rules). |
| 2 | `AuthMethod` | String | No | `rsa` | `rsa` \| `password`. |
| 3 | `Password` | String (mark sensitive) | Conditional | `""` | Empty allowed only with `AuthMethod=rsa` (locks pw). Required for `AuthMethod=password`. **Masked as `***` in output.** |
| 4 | `RunMode` | String | No | `1` | `1` = create-or-repair, `2` = remove. |

**Example values:**
- `TEMPADMIN`, `rsa`, `""`, `1` -> create with 4096-bit RSA keypair, password locked
- `TEMPADMIN`, `password`, `<strong-literal>`, `1` -> create with a login password
- `TEMPADMIN`, `rsa`, `""`, `2` -> remove (kills user sessions, `userdel -r`, cleanup)

**Operator notes:**
- **Password (when used) is visible to any user with script-edit rights.**
  Rotate after first run.
- **RSA private key is emitted to stdout** so the Qualys log channel captures
  it. Treat the log channel as a credential store.
- `RunMode=2` terminates user sessions via `pkill -TERM` then `pkill -KILL`
  before `userdel -r`. Do not deploy Mode 2 fleet-wide without first confirming
  the target username in the CAR UI.
- Script rejects `Password="CHANGE_ME"` as a guard against unintentional runs.

---

## `windows/remediation/Remove-BigFix.ps1`

**Script name:** Remove BigFix (Windows)
**Platform:** Windows | **Interpreter:** PowerShell | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `RunMode` | String | No | `Audit` | `Audit` \| `Enforce`. |
| 2 | `CleanupOnly` | String (bool) | No | `No` | Enforce only. Skip MSI/EXE uninstall, remove artifacts only. |
| 3 | `UseBESRemoveIfFound` | String (bool) | No | `No` | Enforce only. Also run BESRemove.exe after uninstallers. |

**Truthy values (for string booleans):** `Yes`, `No`, `True`, `False`, `1`,
`0`, `On`, `Off` (case-insensitive). Anything else logs a WARN and is treated
as `false`.

**Example values:**
- `Audit`, `No`, `No` -> default audit-only scan
- `Enforce`, `No`, `No` -> full removal (services, processes, products, artifacts)
- `Enforce`, `Yes`, `No` -> artifact cleanup only (skip uninstallers)
- `Enforce`, `No`, `Yes` -> full removal + BESRemove.exe sweep

**Operator notes:**
- Always audit first against a pilot asset before running Enforce at scale.
- Legacy `-U` switch is still accepted for local testing but not used by CAR.

---

## `linux/remediation/remove-bigfix.sh`

**Script name:** Remove BigFix (Linux)
**Platform:** Linux | **Interpreter:** Bash | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `RunMode` | String | No | `Audit` | `Audit` \| `Enforce`. |
| 2 | `CleanupOnly` | String (bool) | No | `No` | Enforce only. Skip package removal; remove filesystem artifacts only. |
| 3 | `FullCleanup` | String (bool) | No | `No` | Enforce only. Also remove `/var/opt/BESCommon`. |
| 4 | `PackagesOnly` | String (bool) | No | `No` | Enforce only. Skip pre/post process kills and filesystem cleanup. |

**Example values:**
- `Audit` -> audit-only scan
- `Enforce` -> full removal
- `Enforce`, `Yes`, `No`, `No` -> artifact cleanup only
- `Enforce`, `No`, `Yes`, `No` -> full removal + `BESCommon`

**Operator notes:**
- Audit first. Then Enforce on a pilot host. Then scale.
- Covers RHEL / CentOS / Rocky / Alma (RPM) and Debian / Ubuntu (DEB).

---

## `windows/remediation/Remove-Okta.ps1`

**Script name:** Remove Okta (Windows)
**Platform:** Windows | **Interpreter:** PowerShell | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `RunMode` | String | No | `Audit` | `Audit` \| `Enforce`. |
| 2 | `CleanupOnly` | String (bool) | No | `No` | Enforce only. Skip uninstallers, remove filesystem/registry/task/firewall artifacts only. |
| 3 | `IncludeCurrentUser` | String (bool) | No | `No` | Also scan HKCU uninstall keys. Requires user context; less useful under SYSTEM/CAR. |

**Example values:**
- `Audit`, `No`, `No` -> audit-only scan
- `Enforce`, `No`, `No` -> full removal
- `Enforce`, `Yes`, `No` -> cleanup-only removal (skip registered uninstallers)

**Operator notes:**
- **Unenroll Okta Verify accounts BEFORE running Enforce.** The script
  proceeds regardless and removes everything it can reach.
- `IncludeCurrentUser=Yes` only meaningfully scans HKCU for the interactive
  user session. Under CAR's SYSTEM context it typically returns no results.

---

## `linux/remediation/remove-okta.sh`

**Script name:** Remove Okta (Linux)
**Platform:** Linux | **Interpreter:** Bash | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `RunMode` | String | No | `Audit` | `Audit` \| `Enforce`. |
| 2 | `CleanupOnly` | String (bool) | No | `No` | Enforce only. Filesystem cleanup only. |
| 3 | `PackagesOnly` | String (bool) | No | `No` | Enforce only. Skip pre/post process kills and filesystem cleanup. |

**Example values:**
- `Audit` -> audit-only
- `Enforce` -> full removal
- `Enforce`, `Yes`, `No` -> filesystem cleanup only
- `Enforce`, `No`, `Yes` -> packages only

---

## `windows/assessment/Get-DatabaseInventory.ps1`

**Script name:** Database Inventory (Windows)
**Platform:** Windows | **Interpreter:** PowerShell | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `DeepProbe` | String (bool) | No | `No` | Opt-in local trust-based catalog queries. **Visible in DBA audit logs.** |
| 2 | `IncludeAdLookup` | String (bool) | No | `No` | Opt-in AD lookup via `Get-ADUser` or ADSI. **Generates LDAP load.** |
| 3 | `IncludeEmbeddedEngines` | String (bool) | No | `No` | Opt-in SQLite + Access filesystem scan. Size-floored + magic-byte validated. |
| 4 | `EmbeddedPaths` | String | No | `""` | Comma-separated dirs for embedded-scan. Empty uses built-in defaults. |
| 5 | `SkipNetwork` | String (bool) | No | `No` | Skip `Get-NetTCPConnection` socket enumeration. |
| 6 | `DryRun` | String (bool) | No | `No` | With `DeepProbe=Yes`, log intent without opening connections. |
| 7 | `Retain` | String (int) | No | `1` | Number of run outputs kept on disk (older pruned at run start). |
| 8 | `JsonOnly` | String (bool) | No | `No` | Suppress human stdout; emit JSON on stdout. Files still written. |
| 9 | `OutputPath` | String | No | `""` | Override default `C:\ProgramData\DatabaseInventory`. |

**Example values:**
- All empty / defaults -> basic audit-shape discovery, no opt-in probes.
- `Yes`, `No`, `No`, `""`, `No`, `Yes`, `1`, `No`, `""` -> DeepProbe dry run.
- `Yes`, `Yes`, `Yes`, `"C:\inetpub,C:\apps"`, `No`, `No`, `3`, `Yes`, `"C:\CAR\dbinv"` -> everything on, custom embedded paths, retain 3 runs, JSON-only stdout.

**Operator notes:**
- **First fleet run:** keep every toggle at the default `No`. Confirm output
  across representative hosts before enabling any opt-in probe.
- `DeepProbe=Yes` + `DryRun=Yes` is the intended on-ramp for DeepProbe
  rollouts: it logs which instances would be probed without making any
  outbound connections.
- `IncludeEmbeddedEngines=Yes` triggers a disk walk over `EmbeddedPaths`.
  Always-excluded paths (Windows / WinSxS / Office / user-profile) cannot be
  overridden. Size floor 256 KB, magic-byte check required for a match, cap
  500 hits per engine.

---

## `linux/assessment/get-database-inventory.sh`

**Script name:** Database Inventory (Linux)
**Platform:** Linux | **Interpreter:** Bash | **Version:** 3.0.0

| Pos | Name | Type | Required | Default | Notes |
|----:|------|------|:--------:|---------|-------|
| 1 | `DeepProbe` | String (bool) | No | `No` | Opt-in local trust-based catalog queries. |
| 2 | `IncludeAdLookup` | String (bool) | No | `No` | Opt-in AD lookup via `ldapsearch` or `getent`. |
| 3 | `IncludeEmbeddedEngines` | String (bool) | No | `No` | Opt-in SQLite filesystem scan. |
| 4 | `EmbeddedPaths` | String | No | `""` | Comma-separated dirs. Empty uses `/srv,/opt,/var/lib,/data`. |
| 5 | `SkipNetwork` | String (bool) | No | `No` | Skip `ss -lntp` socket enumeration. |
| 6 | `DryRun` | String (bool) | No | `No` | With `DeepProbe=Yes`, log intent only. |
| 7 | `Retain` | String (int) | No | `1` | Run-output retention count. |
| 8 | `JsonOnly` | String (bool) | No | `No` | Suppress human stdout; emit JSON on stdout. |
| 9 | `OutputPath` | String | No | `""` | Override default `/var/log/database-inventory`. |

**Example values:**
- All empty / defaults -> basic audit-shape discovery.
- `Yes`, `No`, `No`, `""`, `No`, `Yes`, `1`, `No`, `""` -> DeepProbe dry run.

**Operator notes:**
- Always-excluded paths for embedded scan: `/proc`, `/sys`, `/dev`, `/tmp`,
  `/run`, `/var/cache`, `/var/lib/dpkg`, `/var/lib/rpm`, `/home`.
- Size floor 256 KiB, magic-byte validation (`SQLite format 3`), 500-hit cap.

---

## Quick Reference Matrix

| Script | Pos1 | Pos2 | Pos3 | Pos4 | Pos5 | Pos6 | Pos7 | Pos8 | Pos9 |
|---|---|---|---|---|---|---|---|---|---|
| `Create_Admin.ps1` | Username | Password | RunMode | - | - | - | - | - | - |
| `Create_Admin.sh` | Username | AuthMethod | Password | RunMode | - | - | - | - | - |
| `Remove-BigFix.ps1` | RunMode | CleanupOnly | UseBESRemoveIfFound | - | - | - | - | - | - |
| `remove-bigfix.sh` | RunMode | CleanupOnly | FullCleanup | PackagesOnly | - | - | - | - | - |
| `Remove-Okta.ps1` | RunMode | CleanupOnly | IncludeCurrentUser | - | - | - | - | - | - |
| `remove-okta.sh` | RunMode | CleanupOnly | PackagesOnly | - | - | - | - | - | - |
| `Get-DatabaseInventory.ps1` | DeepProbe | IncludeAdLookup | IncludeEmbeddedEngines | EmbeddedPaths | SkipNetwork | DryRun | Retain | JsonOnly | OutputPath |
| `get-database-inventory.sh` | DeepProbe | IncludeAdLookup | IncludeEmbeddedEngines | EmbeddedPaths | SkipNetwork | DryRun | Retain | JsonOnly | OutputPath |
