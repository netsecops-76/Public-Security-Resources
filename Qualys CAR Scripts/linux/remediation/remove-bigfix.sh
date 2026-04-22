#!/usr/bin/env bash
# ==============================================================================
# remove-bigfix.sh
# ==============================================================================
# Author:    Brian Canaday
# Team:      netsecops-76
# Version:   3.1.0
# Created:   2026-04-03
#
# Description:
#   Audits or uninstalls the BigFix / BESClient agent and associated
#   artifacts on RHEL/CentOS/Rocky/Alma (RPM) and Debian/Ubuntu (DEB)
#   Linux. Designed for unattended execution via Qualys Cloud Agent / CAR
#   using UI-defined POSITIONAL parameters.
#
#   Target software (exclusively):
#       BES (BigFix), besclient, BESClient
#
#   NOTE: This script targets ONLY the BESClient agent. Server-side
#   components (BESRelay, BESServer, BESRootServer, BESFillDB, BESGatherDB,
#   BESWebReports, BESWebUI, BESPluginPortal) and legacy vendor branding
#   (IBM Endpoint Manager, Tivoli Endpoint Manager) are intentionally
#   excluded.
#
#   Audit-first: by default, nothing is changed. Operator must explicitly
#   set RunMode=Enforce to perform the destructive uninstall workflow.
#
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
#     Purpose:   (Enforce only) Skip package removal; remove filesystem artifacts only.
#
#   Position 3:  FullCleanup
#     Type:      String
#     Required:  No
#     Default:   No
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   (Enforce only) Also remove /var/opt/BESCommon.
#
#   Position 4:  PackagesOnly
#     Type:      String
#     Required:  No
#     Default:   No
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   (Enforce only) Skip pre/post process kills and filesystem
#                cleanup; remove packages only.
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details:
#        Name:        Remove BigFix (Linux)
#        Platform:    Linux
#        Interpreter: Bash
#        Upload:      remove-bigfix.sh
#   4. Parameters (ORDER MATTERS - positional):
#        RunMode       (String, Optional, default "Audit")
#        CleanupOnly   (String, Optional, default "No")
#        FullCleanup   (String, Optional, default "No")
#        PackagesOnly  (String, Optional, default "No")
#   5. Save. Always run RunMode=Audit first against a pilot asset before
#      promoting to Enforce.
#
# CLI INVOCATION (local testing):
#   sudo ./remove-bigfix.sh                               # audit
#   sudo ./remove-bigfix.sh Enforce                       # full removal
#   sudo ./remove-bigfix.sh Enforce Yes No No             # artifact cleanup only
#   sudo ./remove-bigfix.sh Enforce No  Yes No            # full + BESCommon
#
# CAR INVOKES EQUIVALENT TO:
#   /bin/bash remove-bigfix.sh "<RunMode>" "<CleanupOnly>" "<FullCleanup>" "<PackagesOnly>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional args win. If a positional is empty, the same-named env var
#   is used ($RUN_MODE, $CLEANUP_ONLY, $FULL_CLEANUP, $PACKAGES_ONLY).
#   Defaults applied last. Legacy named flags (-U / --uninstall /
#   --cleanup-only / --full-cleanup / --packages-only) are still
#   recognized anywhere in the arg list for backward compatibility.
#
# Exit Codes:
#   0  = Success (audit: scan complete | enforce: no packages remain)
#   1  = Completed with warnings or residual packages detected
#   2  = Must be run as root
#
# Changelog:
#   3.1.0 - 2026-04-22 - Narrow target scope to BES (BigFix) / besclient /
#                        BESClient agent ONLY. Removed server-side
#                        components (BESRelay, BESServer, BESRootServer,
#                        BESFillDB, BESGatherDB, BESWebReports, BESWebUI,
#                        BESPluginPortal), legacy vendor branding (IBM
#                        Endpoint Manager, Tivoli Endpoint Manager), and
#                        utility processes (qna, xqna) from all discovery
#                        arrays and patterns.
#   3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces named
#                        flags with POSITIONAL string parameters (RunMode,
#                        CleanupOnly, FullCleanup, PackagesOnly) consumable
#                        by Qualys CAR UI. Dual-invocation support:
#                        positional first, env fallback, defaults last.
#                        Legacy flag tokens still recognized for local
#                        testing. ASCII-only log output.
#   2.0.0 - 2026-04-03 - Added audit-only default mode. Full workflow now
#                        requires -U/--uninstall.
#   1.0.0 - 2026-04-03 - Initial release. CAR-ready, hardened bash.
# ==============================================================================

set -u
set -o pipefail

# ------------------------------------------------------------------------------
# TRUTHY HELPER (accept Yes/No, True/False, 1/0, On/Off case-insensitive)
# ------------------------------------------------------------------------------
car_truthy() {
    local v="${1:-}"
    v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"
    case "$v" in
        yes|y|true|t|1|on)      return 0 ;;
        ""|no|n|false|f|0|off)  return 1 ;;
        *)
            echo "[WARN] Unrecognized truthy value '$1'; treating as false." >&2
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# PARAMETER RESOLUTION
# ------------------------------------------------------------------------------
# Scan the whole argv for legacy flag tokens (backward compat). Each token
# sets the same-named raw variable as if the matching positional had been
# provided.
_RAW_RUNMODE=""
_RAW_CLEANUP=""
_RAW_FULL=""
_RAW_PACKAGES=""
for arg in "$@"; do
    case "$arg" in
        -U|--uninstall)   _RAW_RUNMODE="Enforce" ;;
        --cleanup-only)   _RAW_CLEANUP="Yes" ;;
        --full-cleanup)   _RAW_FULL="Yes" ;;
        --packages-only)  _RAW_PACKAGES="Yes" ;;
    esac
done

# Helper: treat known legacy flag tokens as NOT-positional values.
_pos_is_flag() {
    case "${1:-}" in
        -U|--uninstall|--cleanup-only|--full-cleanup|--packages-only) return 0 ;;
        *) return 1 ;;
    esac
}

if [ $# -ge 1 ] && ! _pos_is_flag "${1:-}"; then _RAW_RUNMODE="${1}"; fi
if [ $# -ge 2 ] && ! _pos_is_flag "${2:-}"; then _RAW_CLEANUP="${2}"; fi
if [ $# -ge 3 ] && ! _pos_is_flag "${3:-}"; then _RAW_FULL="${3}"; fi
if [ $# -ge 4 ] && ! _pos_is_flag "${4:-}"; then _RAW_PACKAGES="${4}"; fi

# Positional -> env -> default
RUN_MODE="${_RAW_RUNMODE:-${RUN_MODE:-Audit}}"
CLEANUP_ONLY_STR="${_RAW_CLEANUP:-${CLEANUP_ONLY:-No}}"
FULL_CLEANUP_STR="${_RAW_FULL:-${FULL_CLEANUP:-No}}"
PACKAGES_ONLY_STR="${_RAW_PACKAGES:-${PACKAGES_ONLY:-No}}"

# Normalize into 0/1 counters used throughout the rest of the script.
UNINSTALL=0
CLEANUP_ONLY=0
FULL_CLEANUP=0
PACKAGES_ONLY=0
if [ "$(printf '%s' "${RUN_MODE}" | tr '[:upper:]' '[:lower:]')" = "enforce" ]; then
    UNINSTALL=1
fi
if car_truthy "${CLEANUP_ONLY_STR}";  then CLEANUP_ONLY=1;  fi
if car_truthy "${FULL_CLEANUP_STR}";  then FULL_CLEANUP=1;  fi
if car_truthy "${PACKAGES_ONLY_STR}"; then PACKAGES_ONLY=1; fi

MODE="AUDIT (read-only)"
if [ "${UNINSTALL}" -eq 1 ]; then
    MODE="ENFORCE (uninstall + cleanup)"
fi

# ------------------------------------------------------------------------------
# ROOT CHECK
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root." >&2
    exit 2
fi

# ------------------------------------------------------------------------------
# LOG + TIMING
# ------------------------------------------------------------------------------
LOG_FILE="/tmp/remove-bigfix_$(date '+%Y%m%d_%H%M%S').log"
START_EPOCH=$(date +%s)

# Discovery counters
SERVICES_FOUND=0
PROCESSES_FOUND=0
PACKAGES_FOUND=0
FILES_FOUND=0

# Action counters (only increment when -U is active)
SERVICES_STOPPED=0
PROCESSES_KILLED=0
PACKAGES_REMOVED=0
FILES_REMOVED=0
WARNINGS=0

log() {
    local msg
    msg="$(date '+%Y-%m-%d %H:%M:%S')  $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

log_ok() {
    log "[OK]    $*"
}

log_warn() {
    log "[WARN]  $*"
    WARNINGS=$(( WARNINGS + 1 ))
}

log_skip() {
    log "[-]     $*"
}

log_find() {
    log "[FOUND] $*"
}

log_act() {
    log "[WOULD] $*"
}

run_silent() {
    "$@" >>"$LOG_FILE" 2>&1 || true
}

# ------------------------------------------------------------------------------
# BANNER
# ------------------------------------------------------------------------------
clear || true
echo "================================================================"
echo "  remove-bigfix.sh  v3.1.0"
echo "  Host         : $(hostname -f 2>/dev/null || hostname)"
echo "  Started      : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log          : ${LOG_FILE}"
echo "  ----- parameters -----"
echo "  RunMode      : ${RUN_MODE}"
echo "  CleanupOnly  : ${CLEANUP_ONLY_STR}"
echo "  FullCleanup  : ${FULL_CLEANUP_STR}"
echo "  PackagesOnly : ${PACKAGES_ONLY_STR}"
echo "  Mode         : ${MODE}"
echo "================================================================"
if [ "${UNINSTALL}" -eq 0 ]; then
    echo ""
    echo "  AUDIT MODE: script reports what it finds but makes NO changes."
    echo "  Re-run with RunMode=Enforce to perform the actual uninstall."
fi
echo ""

log "remove-bigfix.sh v3.1.0 started - Mode: ${MODE}"
log "Params: RunMode=${RUN_MODE} CleanupOnly=${CLEANUP_ONLY_STR} FullCleanup=${FULL_CLEANUP_STR} PackagesOnly=${PACKAGES_ONLY_STR}"
log "Flags:  UNINSTALL=${UNINSTALL} CLEANUP_ONLY=${CLEANUP_ONLY} FULL_CLEANUP=${FULL_CLEANUP} PACKAGES_ONLY=${PACKAGES_ONLY}"

# ------------------------------------------------------------------------------
# HELPERS: Package manager detection
# ------------------------------------------------------------------------------
HAS_RPM=0
HAS_DEB=0
HAS_SYSTEMD=0

if command -v rpm >/dev/null 2>&1 && rpm -q --quiet bash >/dev/null 2>&1; then
    HAS_RPM=1
fi
if command -v dpkg-query >/dev/null 2>&1; then
    HAS_DEB=1
fi
if command -v systemctl >/dev/null 2>&1; then
    HAS_SYSTEMD=1
fi

# ------------------------------------------------------------------------------
# HELPERS: Service control
# ------------------------------------------------------------------------------
service_unit_exists() {
    local svc="$1"
    if [ "${HAS_SYSTEMD}" -eq 1 ]; then
        systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service" && return 0
        systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${svc}"         && return 0
    fi
    [ -x "/etc/init.d/${svc}" ] && return 0
    return 1
}

check_service() {
    local svc="$1"
    if service_unit_exists "$svc"; then
        SERVICES_FOUND=$(( SERVICES_FOUND + 1 ))
        if [ "${UNINSTALL}" -eq 1 ]; then
            log "Stopping service: ${svc}"
            if [ "${HAS_SYSTEMD}" -eq 1 ]; then
                run_silent systemctl stop "$svc"
                run_silent systemctl disable "$svc"
                run_silent systemctl daemon-reload
            fi
            run_silent service "$svc" stop 2>/dev/null || true
            log_ok "Service stopped/disabled: ${svc}"
            SERVICES_STOPPED=$(( SERVICES_STOPPED + 1 ))
        else
            log_find "Service present: ${svc} - WOULD stop and disable"
        fi
    else
        log_skip "Service not found: ${svc}"
    fi
}

# ------------------------------------------------------------------------------
# STEP 1 - SERVICES
# ------------------------------------------------------------------------------
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 1/6] Stopping BigFix services..."
else
    echo "[Step 1/6] Scanning for BigFix services..."
fi
log "[Step 1/6] Services - Mode: ${MODE}"

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    check_service besclient
    check_service besagent
    check_service BESClient

    if [ "${SERVICES_FOUND}" -eq 0 ]; then
        log_skip "No BigFix services found."
    fi

    if [ "${UNINSTALL}" -eq 1 ]; then
        sleep 2
    fi
fi

# ------------------------------------------------------------------------------
# STEP 2 - PROCESSES
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 2/6] Killing residual BigFix processes..."
else
    echo "[Step 2/6] Scanning for BigFix processes..."
fi
log "[Step 2/6] Processes - Mode: ${MODE}"

BES_PROC_PATTERNS=(
    "BESClient"
    "BESAgentService"
)

scan_bigfix_processes() {
    local action="${1:-audit}"
    local found=0
    for pattern in "${BES_PROC_PATTERNS[@]}"; do
        local pids
        pids=$(pgrep -f "${pattern}" 2>/dev/null || true)
        if [ -n "${pids}" ]; then
            found=$(( found + 1 ))
            PROCESSES_FOUND=$(( PROCESSES_FOUND + 1 ))
            if [ "${action}" = "kill" ]; then
                log "Killing process(es) matching '${pattern}': ${pids}"
                run_silent pkill -9 -f "${pattern}"
                log_ok "Killed: ${pattern} (PIDs: ${pids})"
                PROCESSES_KILLED=$(( PROCESSES_KILLED + 1 ))
            else
                log_find "Process running: ${pattern} (PIDs: ${pids}) - WOULD kill"
            fi
        fi
    done
    return ${found}
}

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    if [ "${UNINSTALL}" -eq 1 ]; then
        scan_bigfix_processes "kill" || true
    else
        scan_bigfix_processes "audit" || true
    fi
    if [ "${PROCESSES_FOUND}" -eq 0 ]; then
        log_skip "No residual BigFix processes found."
    fi
fi

# ------------------------------------------------------------------------------
# STEP 3 - PACKAGES
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 3/6] Discovering and removing BigFix packages..."
else
    echo "[Step 3/6] Scanning for installed BigFix packages..."
fi
log "[Step 3/6] Packages - Mode: ${MODE}"

# --- RPM ---
discover_rpm_packages() {
    if [ "${HAS_RPM}" -eq 0 ]; then echo ""; return; fi
    rpm -qa 2>/dev/null | grep -Ei '^(BESClient|besclient|bigfix)' | sort -u
}

remove_rpm_package() {
    local pkg="$1"
    log "Removing RPM: ${pkg}"
    if rpm -e --nodeps "${pkg}" >>"${LOG_FILE}" 2>&1; then
        log_ok "Removed RPM: ${pkg}"
        PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 ))
    else
        log_warn "Failed to remove RPM: ${pkg}"
    fi
}

# --- DEB ---
discover_deb_packages() {
    if [ "${HAS_DEB}" -eq 0 ]; then echo ""; return; fi
    dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -Ei '^(besclient|bigfix)' | sort -u
}

remove_deb_package() {
    local pkg="$1"
    log "Removing DEB: ${pkg}"
    if command -v apt-get >/dev/null 2>&1; then
        if DEBIAN_FRONTEND=noninteractive apt-get -y purge "${pkg}" >>"${LOG_FILE}" 2>&1; then
            log_ok "Removed DEB: ${pkg}"
            PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 ))
        else
            log_warn "Failed to remove DEB: ${pkg}"
        fi
    else
        if dpkg --purge "${pkg}" >>"${LOG_FILE}" 2>&1; then
            log_ok "Removed DEB: ${pkg}"
            PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 ))
        else
            log_warn "Failed to remove DEB: ${pkg}"
        fi
    fi
}

FOUND_RPM_PKGS=$(discover_rpm_packages)
FOUND_DEB_PKGS=$(discover_deb_packages)

# Count packages found
if [ -n "${FOUND_RPM_PKGS}" ]; then
    while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        PACKAGES_FOUND=$(( PACKAGES_FOUND + 1 ))
    done <<< "${FOUND_RPM_PKGS}"
fi
if [ -n "${FOUND_DEB_PKGS}" ]; then
    while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        PACKAGES_FOUND=$(( PACKAGES_FOUND + 1 ))
    done <<< "${FOUND_DEB_PKGS}"
fi

if [ "${CLEANUP_ONLY}" -eq 1 ] && [ "${UNINSTALL}" -eq 1 ]; then
    log_skip "--cleanup-only specified; skipping package removal."
elif [ "${UNINSTALL}" -eq 0 ]; then
    # Audit - report what was found
    if [ "${PACKAGES_FOUND}" -eq 0 ]; then
        log_skip "No BigFix packages found."
    else
        if [ -n "${FOUND_RPM_PKGS}" ]; then
            log_find "RPM packages found - WOULD uninstall (rpm -e --nodeps):"
            while IFS= read -r pkg; do
                [ -z "$pkg" ] && continue
                log_act "  ${pkg}"
            done <<< "${FOUND_RPM_PKGS}"
        fi
        if [ -n "${FOUND_DEB_PKGS}" ]; then
            log_find "DEB packages found - WOULD purge (apt-get purge / dpkg --purge):"
            while IFS= read -r pkg; do
                [ -z "$pkg" ] && continue
                log_act "  ${pkg}"
            done <<< "${FOUND_DEB_PKGS}"
        fi
    fi
else
    # Active removal - RPM ordered
    RPM_ORDERED_PATTERNS=(
        "BESAgent"
        "BESClient"
        "besclient"
        "bigfix"
    )

    if [ -n "${FOUND_RPM_PKGS}" ]; then
        log "Found BigFix RPM packages:"
        echo "${FOUND_RPM_PKGS}" | tee -a "${LOG_FILE}"
        local_removed=""
        for pattern in "${RPM_ORDERED_PATTERNS[@]}"; do
            while IFS= read -r pkg; do
                [ -z "$pkg" ] && continue
                echo "${pkg}" | grep -Eiq "^${pattern}" || continue
                echo "${local_removed}" | grep -qx "${pkg}" && continue
                remove_rpm_package "${pkg}"
                local_removed="${local_removed}
${pkg}"
            done <<< "${FOUND_RPM_PKGS}"
        done
        # Catch-all
        while IFS= read -r pkg; do
            [ -z "$pkg" ] && continue
            echo "${local_removed}" | grep -qx "${pkg}" && continue
            remove_rpm_package "${pkg}"
        done <<< "${FOUND_RPM_PKGS}"
    else
        log_skip "No BigFix RPM packages found."
    fi

    # Active removal - DEB ordered
    DEB_ORDERED_PATTERNS=(
        "besagent"
        "besclient"
        "bigfix"
    )

    if [ -n "${FOUND_DEB_PKGS}" ]; then
        log "Found BigFix DEB packages:"
        echo "${FOUND_DEB_PKGS}" | tee -a "${LOG_FILE}"
        local_removed=""
        for pattern in "${DEB_ORDERED_PATTERNS[@]}"; do
            while IFS= read -r pkg; do
                [ -z "$pkg" ] && continue
                echo "${pkg}" | grep -Eiq "${pattern}" || continue
                echo "${local_removed}" | grep -qx "${pkg}" && continue
                remove_deb_package "${pkg}"
                local_removed="${local_removed}
${pkg}"
            done <<< "${FOUND_DEB_PKGS}"
        done
        # Catch-all
        while IFS= read -r pkg; do
            [ -z "$pkg" ] && continue
            echo "${local_removed}" | grep -qx "${pkg}" && continue
            remove_deb_package "${pkg}"
        done <<< "${FOUND_DEB_PKGS}"

        if command -v apt-get >/dev/null 2>&1; then
            run_silent apt-get -y autoremove
        fi
    else
        log_skip "No BigFix DEB packages found."
    fi

    # Second process sweep
    if [ "${PACKAGES_ONLY}" -eq 0 ]; then
        sleep 2
        scan_bigfix_processes "kill" || true
    fi
fi

# ------------------------------------------------------------------------------
# STEP 4 - FILESYSTEM
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 4/6] Removing filesystem artifacts..."
else
    echo "[Step 4/6] Scanning for filesystem artifacts..."
fi
log "[Step 4/6] Filesystem - Mode: ${MODE}"

BES_DIRS=(
    /etc/opt/BESClient
    /opt/BESClient
    /opt/HCL/BigFix
    /var/opt/BESClient
    /tmp/BES
    /tmp/besclient
)

BES_LOGS=(
    /var/log/BESClient.log
    /var/log/BESInstall.log
)

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    for dir in "${BES_DIRS[@]}"; do
        if [ -e "${dir}" ]; then
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log "Removing: ${dir}"
                if rm -rf "${dir}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed: ${dir}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove: ${dir}"
                fi
            else
                log_find "Directory present: ${dir} - WOULD delete (recursive)"
            fi
        else
            log_skip "Not present: ${dir}"
        fi
    done

    for logfile in "${BES_LOGS[@]}"; do
        if [ -e "${logfile}" ]; then
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log "Removing log: ${logfile}"
                if rm -rf "${logfile}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed log: ${logfile}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove log: ${logfile}"
                fi
            else
                log_find "Log file present: ${logfile} - WOULD delete"
            fi
        fi
    done

    # BESCommon
    if [ -e /var/opt/BESCommon ]; then
        if [ "${FULL_CLEANUP}" -eq 1 ] && [ "${UNINSTALL}" -eq 1 ]; then
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            log "Full cleanup: removing /var/opt/BESCommon"
            if rm -rf /var/opt/BESCommon >>"${LOG_FILE}" 2>&1; then
                log_ok "Removed: /var/opt/BESCommon"
                FILES_REMOVED=$(( FILES_REMOVED + 1 ))
            else
                log_warn "Could not remove: /var/opt/BESCommon"
            fi
        elif [ "${UNINSTALL}" -eq 0 ]; then
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            log_find "Directory present: /var/opt/BESCommon - WOULD delete only if run with --full-cleanup -U"
        else
            log_skip "/var/opt/BESCommon retained (use --full-cleanup with -U to remove)"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# STEP 5 - SERVICE FILES + LD.SO CONFIG
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 5/6] Removing service files and ld.so config..."
else
    echo "[Step 5/6] Scanning for service files and ld.so config..."
fi
log "[Step 5/6] Service files / ld.so - Mode: ${MODE}"

BES_SERVICE_FILES=(
    /etc/init.d/besclient
    /etc/init.d/BESClient
    /usr/lib/systemd/system/besclient.service
    /usr/lib/systemd/system/BESClient.service
    /etc/systemd/system/besclient.service
    /etc/systemd/system/BESClient.service
)

BES_LD_CONF_FILES=(
    /etc/ld.so.conf.d/BESClient.conf
    /etc/ld.so.conf.d/bes.conf
    /etc/ld.so.conf.d/bigfix.conf
)

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    LD_CONF_FOUND=0
    for f in "${BES_SERVICE_FILES[@]}"; do
        if [ -e "${f}" ]; then
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                if rm -f "${f}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed service file: ${f}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove service file: ${f}"
                fi
            else
                log_find "Service file present: ${f} - WOULD delete"
            fi
        fi
    done

    for f in "${BES_LD_CONF_FILES[@]}"; do
        if [ -e "${f}" ]; then
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            LD_CONF_FOUND=$(( LD_CONF_FOUND + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                if rm -f "${f}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed ld.so conf: ${f}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove ld.so conf: ${f}"
                fi
            else
                log_find "ld.so conf present: ${f} - WOULD delete"
            fi
        fi
    done

    if [ "${UNINSTALL}" -eq 1 ]; then
        if command -v ldconfig >/dev/null 2>&1; then
            run_silent ldconfig
        fi
        if [ "${HAS_SYSTEMD}" -eq 1 ]; then
            run_silent systemctl daemon-reload
            run_silent systemctl reset-failed 2>/dev/null || true
        fi
    fi
fi

# ------------------------------------------------------------------------------
# STEP 6 - CRON JOBS
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 6/6] Removing BigFix cron jobs..."
else
    echo "[Step 6/6] Scanning for BigFix cron jobs..."
fi
log "[Step 6/6] Cron - Mode: ${MODE}"

BES_CRON_PATHS=(
    /etc/cron.d/besclient
    /etc/cron.d/BESClient
    /etc/cron.d/bigfix
)

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    CRON_FOUND=0
    for cron_file in "${BES_CRON_PATHS[@]}"; do
        if [ -e "${cron_file}" ]; then
            CRON_FOUND=$(( CRON_FOUND + 1 ))
            FILES_FOUND=$(( FILES_FOUND + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                if rm -f "${cron_file}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed cron: ${cron_file}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove cron: ${cron_file}"
                fi
            else
                log_find "Cron file present: ${cron_file} - WOULD delete"
            fi
        fi
    done
    if [ "${CRON_FOUND}" -eq 0 ]; then
        log_skip "No BigFix cron jobs found."
    fi
fi

# ------------------------------------------------------------------------------
# VERIFICATION SCAN (only when -U was used)
# ------------------------------------------------------------------------------
REMAINING_RPM=""
REMAINING_DEB=""

if [ "${UNINSTALL}" -eq 1 ]; then
    echo ""
    log "Running post-removal verification scan..."

    if [ "${HAS_RPM}" -eq 1 ]; then
        REMAINING_RPM=$(discover_rpm_packages)
        if [ -n "${REMAINING_RPM}" ]; then
            log "[WARN] Remaining RPM packages:"
            echo "${REMAINING_RPM}" | tee -a "${LOG_FILE}"
            WARNINGS=$(( WARNINGS + 1 ))
        fi
    fi

    if [ "${HAS_DEB}" -eq 1 ]; then
        REMAINING_DEB=$(discover_deb_packages)
        if [ -n "${REMAINING_DEB}" ]; then
            log "[WARN] Remaining DEB packages:"
            echo "${REMAINING_DEB}" | tee -a "${LOG_FILE}"
            WARNINGS=$(( WARNINGS + 1 ))
        fi
    fi
fi

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
END_EPOCH=$(date +%s)
ELAPSED=$(( END_EPOCH - START_EPOCH ))
ELAPSED_FMT="$(printf '%02d:%02d' $(( ELAPSED / 60 )) $(( ELAPSED % 60 )))"

TOTAL_FOUND=$(( SERVICES_FOUND + PROCESSES_FOUND + PACKAGES_FOUND + FILES_FOUND ))

echo ""
echo "================================================================"
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "  REMOVAL SUMMARY"
    echo "================================================================"
    echo "  Services found       : ${SERVICES_FOUND}  (stopped: ${SERVICES_STOPPED})"
    echo "  Processes found      : ${PROCESSES_FOUND}  (killed: ${PROCESSES_KILLED})"
    echo "  Packages found       : ${PACKAGES_FOUND}  (removed: ${PACKAGES_REMOVED})"
    echo "  Files/dirs found     : ${FILES_FOUND}  (removed: ${FILES_REMOVED})"
    echo "  Warnings             : ${WARNINGS}"
else
    echo "  AUDIT SUMMARY (no changes made)"
    echo "================================================================"
    echo "  Services found       : ${SERVICES_FOUND}  (would be stopped)"
    echo "  Processes found      : ${PROCESSES_FOUND}  (would be killed)"
    echo "  Packages found       : ${PACKAGES_FOUND}  (would be uninstalled)"
    echo "  Files/dirs found     : ${FILES_FOUND}  (would be deleted)"
    echo ""
    echo "  To perform actual removal, re-run with: -U or --uninstall"
fi
echo "  Elapsed              : ${ELAPSED_FMT}"
echo "  Log                  : ${LOG_FILE}"
echo "================================================================"

log "SUMMARY: mode=${MODE} svc_found=${SERVICES_FOUND} proc_found=${PROCESSES_FOUND} pkg_found=${PACKAGES_FOUND} files_found=${FILES_FOUND} svc_stopped=${SERVICES_STOPPED} proc_killed=${PROCESSES_KILLED} pkg_removed=${PACKAGES_REMOVED} files_removed=${FILES_REMOVED} warnings=${WARNINGS} elapsed=${ELAPSED_FMT}"

if [ "${UNINSTALL}" -eq 1 ]; then
    if [ -n "${REMAINING_RPM}" ] || [ -n "${REMAINING_DEB}" ]; then
        echo ""
        echo "  [WARN] Some BigFix packages still remain. Manual review required."
        echo ""
        log "Finished with residual BigFix packages present. Exit 1."
        exit 1
    fi
    echo ""
    echo "  [OK] BigFix removal complete. No packages remain."
    echo ""
    log "BigFix removal complete. Exit 0."
    exit 0
else
    echo ""
    if [ "${TOTAL_FOUND}" -gt 0 ]; then
        echo "  [AUDIT] ${TOTAL_FOUND} BigFix component(s) detected. Run with -U to remove."
    else
        echo "  [AUDIT] No BigFix components detected on this host."
    fi
    echo ""
    log "Audit complete. Total components found: ${TOTAL_FOUND}. Exit 0."
    exit 0
fi
