# Qualys CAR Scripts

A library of parameterized scripts for **Qualys Custom Assessment and Remediation (CAR)**.
Every script is designed for unattended execution by the Qualys Cloud Agent using
UI-defined **positional parameters** you configure on the Script Details page.

- **Platforms:** Windows (PowerShell 5.1) and Linux (Bash). macOS placeholders exist but no macOS scripts yet.
- **Language & version:** all shipping scripts are at **v3.0.0**.
- **Parameter reference:** [`docs/CAR_PARAMETERS.md`](docs/CAR_PARAMETERS.md) - single source of truth for what to define on the CAR UI for each script.

---

## Script Inventory

| Script | Platform | Purpose | Ver. | Params | Mode |
|---|---|---|---|---|---|
| [`windows/assessment/Get-DatabaseInventory.ps1`](windows/assessment/Get-DatabaseInventory.ps1) | Windows | Inventory installed databases, ports, auth config, catalogs | 3.0.0 | 9 | Read-only assessment |
| [`linux/assessment/get-database-inventory.sh`](linux/assessment/get-database-inventory.sh) | Linux | Inventory installed databases, ports, auth config, catalogs | 3.0.0 | 9 | Read-only assessment |
| [`windows/remediation/Create_Admin.ps1`](windows/remediation/Create_Admin.ps1) | Windows | Create / repair / remove a local Administrator account | 3.1.0 | 3 | Create or Remove |
| [`linux/remediation/Create_Admin.sh`](linux/remediation/Create_Admin.sh) | Linux | Create / repair / remove a local admin with RSA or password auth | 3.1.0 | 4 | Create or Remove |
| [`windows/remediation/Remove-BigFix.ps1`](windows/remediation/Remove-BigFix.ps1) | Windows | Audit / uninstall the BigFix / BESClient agent | 3.1.0 | 3 | Audit or Enforce |
| [`linux/remediation/remove-bigfix.sh`](linux/remediation/remove-bigfix.sh) | Linux | Audit / uninstall the BigFix / BESClient agent on RPM + DEB | 3.1.0 | 4 | Audit or Enforce |
| [`windows/remediation/Remove-Okta.ps1`](windows/remediation/Remove-Okta.ps1) | Windows | Audit / uninstall ScaleFT / sftd and artifacts | 3.1.0 | 3 | Audit or Enforce |
| [`linux/remediation/remove-okta.sh`](linux/remediation/remove-okta.sh) | Linux | Audit / uninstall ScaleFT / sftd on RPM + DEB | 3.1.0 | 3 | Audit or Enforce |

### At-a-glance: what each script's positional parameters are

| Script | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 |
|---|---|---|---|---|---|---|---|---|---|
| `Create_Admin.ps1` | RunMode | Username | Password | | | | | | |
| `Create_Admin.sh` | RunMode | AuthMethod | Username | Password | | | | | |
| `Remove-BigFix.ps1` | RunMode | CleanupOnly | UseBESRemoveIfFound | | | | | | |
| `remove-bigfix.sh` | RunMode | CleanupOnly | FullCleanup | PackagesOnly | | | | | |
| `Remove-Okta.ps1` | RunMode | CleanupOnly | IncludeCurrentUser | | | | | | |
| `remove-okta.sh` | RunMode | CleanupOnly | PackagesOnly | | | | | | |
| `Get-DatabaseInventory.ps1` | DeepProbe | IncludeAdLookup | IncludeEmbeddedEngines | EmbeddedPaths | SkipNetwork | DryRun | Retain | JsonOnly | OutputPath |
| `get-database-inventory.sh` | DeepProbe | IncludeAdLookup | IncludeEmbeddedEngines | EmbeddedPaths | SkipNetwork | DryRun | Retain | JsonOnly | OutputPath |

Full type / default / allowed-values / example tables live in [`docs/CAR_PARAMETERS.md`](docs/CAR_PARAMETERS.md).

---

## Repository Layout

```
LICENSE
README.md                                (this file)
docs/
  CAR_PARAMETERS.md                      parameter reference for every script
linux/
  assessment/
    get-database-inventory.sh
  remediation/
    Create_Admin.sh
    remove-bigfix.sh
    remove-okta.sh
windows/
  assessment/
    Get-DatabaseInventory.ps1
  remediation/
    Create_Admin.ps1
    Remove-BigFix.ps1
    Remove-Okta.ps1
macos/
  assessment/                            (empty placeholder)
  remediation/                           (empty placeholder)
```

Directory hierarchy is platform-first, purpose-second: `<platform>/<assessment|remediation>/`.

- **Assessment** scripts are read-only discovery / inventory / check scripts.
- **Remediation** scripts can make changes to system state. Every remediation script is **audit-first**: it reports what it would do and makes no changes unless you explicitly set its destructive mode parameter.

---

## How CAR Passes Parameters

Qualys CAR does **not** set environment variables and does **not** pass named flags (no `-Username value` style). It passes UI-defined parameters as **positional command-line arguments** in the order they were defined on the Script Details page.

Concretely, CAR invokes scripts like this:

```
# Windows
powershell.exe -ExecutionPolicy Bypass -File <script>.ps1 "<P1>" "<P2>" "<P3>" ...

# Linux
/bin/bash <script>.sh "<P1>" "<P2>" "<P3>" ...
```

Every script in this repo is built around that model:

1. **Positional args win** - the first positional arg is parameter 1, etc.
2. **Empty positional -> environment-variable fallback** - if a positional arg is empty, the script checks the same-named environment variable (e.g. `$env:RunMode` / `$RUN_MODE`). This is for local testing, not for CAR use.
3. **Defaults last** - if both positional and env var are empty, the script falls back to the documented default.

CAR passes every value as a string; the scripts coerce strings to booleans and integers where needed using a shared truthy convention (see below).

### Legacy flag syntax (local testing only)

For local-testing convenience, each script still accepts its pre-v3.0 named flag or switch form:

```powershell
.\Remove-BigFix.ps1 -U                               # same as: .\Remove-BigFix.ps1 Enforce
```

```bash
./remove-bigfix.sh --uninstall --cleanup-only        # same as: ./remove-bigfix.sh Enforce Yes
```

CAR never uses the legacy forms. They exist to keep older test harnesses working.

---

## Conventions (v3.0.0 era)

These apply to every script currently in the repo. New scripts are expected to follow them.

### Parameters

- All parameters are **strings** at the CAR boundary. Scripts do their own type coercion.
- **Truthy values** (for boolean-shaped parameters), case-insensitive: `Yes`, `No`, `True`, `False`, `1`, `0`, `On`, `Off`. Anything else logs a `[WARN]` and is treated as false.
- **Sensitive values** (currently `Password` on `Create_Admin.{ps1,sh}`) are masked as `***` in the runtime banner and log file.
- **Placeholder guard:** scripts that expect a required secret reject `"CHANGE_ME"` at runtime and exit 2 without making changes.

### Audit-first remediation

Every remediation script defaults to a non-destructive mode:

| Script pattern | Default mode | Destructive trigger |
|---|---|---|
| `Create_Admin.*` | `RunMode=1` (create-or-repair) | `RunMode=2` (remove) |
| `Remove-*` | `RunMode=Audit` | `RunMode=Enforce` |

Always run a pilot asset with the default mode before promoting to the destructive mode at fleet scale.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success / audit clean |
| `1` | Completed with warnings (e.g. collection issue, residuals after removal, audit findings present) |
| `2` | Fatal - insufficient privileges, invalid parameter, `CHANGE_ME` sentinel still present |

CAR Job Results use the exit code.

### Logging

- Each script writes a timestamped human-readable `.log` to a platform-appropriate persistent directory (Windows: `C:\ProgramData\<Tool>\`; Linux: `/var/log/<tool>/`).
- `Get-DatabaseInventory.*` additionally emits a `.json` sidecar with the same stem.
- Runtime banner echoes every received parameter (with sensitive values masked).
- Log labels are `[OK]`, `[INFO]`, `[WARN]`, `[FIND]`, `[--]`. Pure ASCII only.

### PowerShell 5.1 compliance (for `.ps1` files)

All Windows scripts are PS 5.1 compliant:

- `#Requires -RunAsAdministrator`, `Set-StrictMode -Version Latest`, `$ErrorActionPreference = 'Continue'`
- No PS7+ syntax: no null-coalescing `??`, no null-prop `?.`, no ternary `?:`
- No `$var = if (...) { ... } else { ... }` assignments - explicit two-line form instead
- No inline `if/else` inside `-f` format operator args
- No `Win32_Product` (avoids installer reconfigure pass)
- `Get-CimInstance` only (no `Get-WmiObject`)
- No `$PID` assignment (it's an auto-variable)
- ASCII-only log output (no em-dashes, smart quotes, unicode)

### Bash hardening (for `.sh` files)

- `#!/usr/bin/env bash`, `set -u`, `set -o pipefail`
- Root enforcement via `[ "$(id -u)" -ne 0 ] && exit 2`
- ASCII-only output

---

## Deploying a Script via CAR

Summary walkthrough. The detailed setup block is repeated verbatim inside each script's header comment and in `docs/CAR_PARAMETERS.md`.

1. **Qualys Cloud Platform** -> **Custom Assessment and Remediation** -> **Scripts** -> **New Script**.
2. **Script Details** tab: give it a name, choose Windows or Linux, pick the matching interpreter (PowerShell or Bash), and upload the file from this repo.
3. **Parameters** tab: add each parameter **in the exact order documented** for that script. See the at-a-glance table above, or the per-script table in `docs/CAR_PARAMETERS.md`.
4. Save. Attach the script to a CAR Job targeting the intended asset tag.
5. For any destructive script, run first with `RunMode=Audit` (or `RunMode=1` for Create_Admin) against a pilot asset.
6. Review output in the Qualys Cloud Agent log channel and in the on-disk log file the script writes.

---

## Local Testing

Every script can be run outside CAR for development or debugging. Pass parameters positionally:

```powershell
# Windows examples
.\windows\remediation\Create_Admin.ps1 TEMPADMIN 'MyP@ss' 1
.\windows\remediation\Remove-BigFix.ps1 Audit
.\windows\assessment\Get-DatabaseInventory.ps1 No No No "" No No 1 No ""
```

```bash
# Linux examples
sudo ./linux/remediation/Create_Admin.sh TEMPADMIN rsa "" 1
sudo ./linux/remediation/remove-bigfix.sh Audit
sudo ./linux/assessment/get-database-inventory.sh No No No "" No No 1 No ""
```

Or via environment variables (fallback path; positional args take priority):

```bash
RUN_MODE=Enforce CLEANUP_ONLY=Yes ./linux/remediation/remove-bigfix.sh
```

```powershell
$env:RunMode='Enforce'; .\windows\remediation\Remove-BigFix.ps1
```

---

## Versioning + Changelog

- Every script carries its own version number and its own changelog block in the header comment.
- All currently-shipped scripts are at **v3.0.0** (CAR parameterization refactor, April 2026).
- There is **no repo-level changelog** - per-script changelogs are authoritative.

---

## Contributing

1. Put the script in the correct `<platform>/<assessment|remediation>/` directory.
2. Follow the v3.0.0 conventions above. Borrow liberally from an existing script of the same shape.
3. Add a CAR UI PARAMETERS + CAR SETUP GUIDE section to the script header, following the pattern used by the existing scripts.
4. Add the script's parameter table to `docs/CAR_PARAMETERS.md` (matrix at the bottom + per-script section above).
5. Add the script's row to the inventory table in this README.
6. Test locally first, then as an audit-mode CAR job against a pilot asset, **before** scaling.

---

## License

MIT - see [LICENSE](LICENSE).
