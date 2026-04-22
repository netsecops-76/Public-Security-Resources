#!/usr/bin/env bash
# ==============================================================================
# remove-okta.sh
# ==============================================================================
# Author:    Brian Canaday
# Team:      netsecops-76
# Version:   3.1.0
# Created:   2026-04-03
#
# Description:
#   Audits or uninstalls ScaleFT / sftd software on RHEL/CentOS/Rocky/Alma
#   (RPM) and Debian/Ubuntu (DEB) Linux. Designed for unattended execution
#   via Qualys Cloud Agent / CAR using UI-defined POSITIONAL parameters.
#
#   Target software (exclusively):
#       ScaleFT, scaleft-server-tools, scaleft-client-tools, sftd
#
#   NOTE: This script targets ONLY the four products listed above. Other
#   Okta products (Okta LDAP Agent, Okta AD Agent, Okta RADIUS Agent,
#   OktaASA, Advanced Server Access, etc.) are intentionally excluded.
#
#   Audit-first: nothing changes unless RunMode=Enforce.
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
#     Purpose:   (Enforce only) Skip package removal; filesystem cleanup only.
#
#   Position 3:  PackagesOnly
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
#        Name:        Remove Okta (Linux)
#        Platform:    Linux
#        Interpreter: Bash
#        Upload:      remove-okta.sh
#   4. Parameters (ORDER MATTERS - positional):
#        RunMode       (String, Optional, default "Audit")
#        CleanupOnly   (String, Optional, default "No")
#        PackagesOnly  (String, Optional, default "No")
#   5. Save. Always audit first before promoting to Enforce.
#
# CLI INVOCATION (local testing):
#   sudo ./remove-okta.sh                     # audit
#   sudo ./remove-okta.sh Enforce             # full removal
#   sudo ./remove-okta.sh Enforce Yes No      # filesystem cleanup only
#   sudo ./remove-okta.sh Enforce No  Yes     # packages only
#
# CAR INVOKES EQUIVALENT TO:
#   /bin/bash remove-okta.sh "<RunMode>" "<CleanupOnly>" "<PackagesOnly>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional args win. Empty positional falls back to env vars
#   (RUN_MODE, CLEANUP_ONLY, PACKAGES_ONLY), then defaults. Legacy named
#   flags (-U / --uninstall / --cleanup-only / --packages-only) still
#   recognized anywhere in the arg list for backward compatibility.
#
# Exit Codes:
#   0  = Audit: no findings | Enforce: clean
#   1  = Findings present | warnings during removal
#   2  = Must be run as root
#
# Changelog:
#   3.1.0 - 2026-04-22 - Narrow target scope to ScaleFT /
#                        scaleft-server-tools / scaleft-client-tools /
#                        sftd ONLY. Removed all Okta*, OktaLDAPAgent,
#                        okta-ldap-agent, okta-ad-agent, okta-radius-agent,
#                        okta-asa, Advanced Server Access, and scaleleft
#                        patterns from every discovery array, regex,
#                        filesystem path, service file list, ld.so conf
#                        list, and cron file list.
#   3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces named
#                        flags with POSITIONAL string parameters (RunMode,
#                        CleanupOnly, PackagesOnly) consumable by Qualys
#                        CAR UI. Dual-invocation support: positional
#                        first, env fallback, defaults last. Legacy flag
#                        tokens still recognized. ASCII-only log output.
#   2.0.0 - 2026-04-03 - Audit-first redesign. Default is discovery/report
#                        only; -U required for destructive workflow.
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
_RAW_RUNMODE=""
_RAW_CLEANUP=""
_RAW_PACKAGES=""
for arg in "$@"; do
    case "$arg" in
        -U|--uninstall)  _RAW_RUNMODE="Enforce" ;;
        --cleanup-only)  _RAW_CLEANUP="Yes" ;;
        --packages-only) _RAW_PACKAGES="Yes" ;;
    esac
done

_pos_is_flag() {
    case "${1:-}" in
        -U|--uninstall|--cleanup-only|--packages-only) return 0 ;;
        *) return 1 ;;
    esac
}

if [ $# -ge 1 ] && ! _pos_is_flag "${1:-}"; then _RAW_RUNMODE="${1}"; fi
if [ $# -ge 2 ] && ! _pos_is_flag "${2:-}"; then _RAW_CLEANUP="${2}"; fi
if [ $# -ge 3 ] && ! _pos_is_flag "${3:-}"; then _RAW_PACKAGES="${3}"; fi

RUN_MODE="${_RAW_RUNMODE:-${RUN_MODE:-Audit}}"
CLEANUP_ONLY_STR="${_RAW_CLEANUP:-${CLEANUP_ONLY:-No}}"
PACKAGES_ONLY_STR="${_RAW_PACKAGES:-${PACKAGES_ONLY:-No}}"

UNINSTALL=0
CLEANUP_ONLY=0
PACKAGES_ONLY=0
if [ "$(printf '%s' "${RUN_MODE}" | tr '[:upper:]' '[:lower:]')" = "enforce" ]; then
    UNINSTALL=1
fi
if car_truthy "${CLEANUP_ONLY_STR}";  then CLEANUP_ONLY=1;  fi
if car_truthy "${PACKAGES_ONLY_STR}"; then PACKAGES_ONLY=1; fi

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
LOG_DIR="/var/log/okta-removal"
mkdir -p "${LOG_DIR}"
MODE_LABEL="AUDIT"
if [ "${UNINSTALL}" -eq 1 ]; then MODE_LABEL="ENFORCE"; fi
LOG_FILE="${LOG_DIR}/remove-okta_${MODE_LABEL}_$(date '+%Y%m%d_%H%M%S').log"
START_EPOCH=$(date +%s)

# Audit counters (findings)
AUDIT_SERVICES=0
AUDIT_PROCESSES=0
AUDIT_PACKAGES=0
AUDIT_FILES=0

# Action counters (only incremented when -U is active)
SERVICES_STOPPED=0
PROCESSES_KILLED=0
PACKAGES_REMOVED=0
FILES_REMOVED=0
WARNINGS=0

log() {
    local msg
    msg="$(date '+%Y-%m-%d %H:%M:%S')  $*"
    echo "$msg" | tee -a "${LOG_FILE}"
}

log_ok()   { log "[OK]   $*"; }
log_warn() { log "[WARN] $*"; WARNINGS=$(( WARNINGS + 1 )); }
log_skip() { log "[--]   $*"; }
log_find() { log "[FIND] $*"; }
log_act()  { log "[ACT]  $*"; }

run_silent() {
    "$@" >>"${LOG_FILE}" 2>&1 || true
}

# ------------------------------------------------------------------------------
# BANNER
# ------------------------------------------------------------------------------
clear || true
echo "================================================================"
echo "  remove-okta.sh  v3.1.0"
echo "  Host         : $(hostname -f 2>/dev/null || hostname)"
echo "  Started      : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log          : ${LOG_FILE}"
echo "  ----- parameters -----"
echo "  RunMode      : ${RUN_MODE}"
echo "  CleanupOnly  : ${CLEANUP_ONLY_STR}"
echo "  PackagesOnly : ${PACKAGES_ONLY_STR}"
echo "  Mode         : ${MODE_LABEL}"
echo "================================================================"
if [ "${UNINSTALL}" -eq 0 ]; then
    echo ""
    echo "  [AUDIT MODE] No changes will be made to this system."
    echo "  Re-run with RunMode=Enforce to perform removal."
fi
echo ""

log "remove-okta.sh v3.1.0 started | RunMode=${RUN_MODE} | Mode=${MODE_LABEL} | CleanupOnly=${CLEANUP_ONLY_STR} | PackagesOnly=${PACKAGES_ONLY_STR}"

# ------------------------------------------------------------------------------
# ENVIRONMENT DETECTION
# ------------------------------------------------------------------------------
HAS_RPM=0
HAS_DEB=0
HAS_DNF=0
HAS_YUM=0
HAS_ZYPPER=0
HAS_SYSTEMD=0

command -v rpm        >/dev/null 2>&1 && HAS_RPM=1
command -v dpkg-query >/dev/null 2>&1 && HAS_DEB=1
command -v dnf        >/dev/null 2>&1 && HAS_DNF=1
command -v yum        >/dev/null 2>&1 && HAS_YUM=1
command -v zypper     >/dev/null 2>&1 && HAS_ZYPPER=1
command -v systemctl  >/dev/null 2>&1 && HAS_SYSTEMD=1

log "Environment: RPM=${HAS_RPM} DEB=${HAS_DEB} DNF=${HAS_DNF} YUM=${HAS_YUM} ZYPPER=${HAS_ZYPPER} SYSTEMD=${HAS_SYSTEMD}"

# ------------------------------------------------------------------------------
# MATCH PATTERN
# ------------------------------------------------------------------------------
MATCH_REGEX='(scaleft|sftd|(^|[-_.])sft([-_.]|$))'

# ------------------------------------------------------------------------------
# SERVICE HELPERS
# ------------------------------------------------------------------------------
service_unit_exists() {
    local svc="$1"
    if [ "${HAS_SYSTEMD}" -eq 1 ]; then
        systemctl list-unit-files 2>/dev/null | awk '{print $1}' | \
            grep -qx "${svc}.service" 2>/dev/null && return 0
        systemctl list-unit-files 2>/dev/null | awk '{print $1}' | \
            grep -qx "${svc}" 2>/dev/null && return 0
    fi
    [ -x "/etc/init.d/${svc}" ] && return 0
    return 1
}

get_service_state() {
    local svc="$1"
    if [ "${HAS_SYSTEMD}" -eq 1 ]; then
        systemctl is-active "${svc}" 2>/dev/null || echo "inactive"
    else
        echo "unknown"
    fi
}

audit_or_stop_service() {
    local svc="$1"
    if service_unit_exists "${svc}"; then
        AUDIT_SERVICES=$(( AUDIT_SERVICES + 1 ))
        local state
        state=$(get_service_state "${svc}")
        log_find "FOUND service: ${svc} | State: ${state}"

        if [ "${UNINSTALL}" -eq 1 ]; then
            log_act "Stopping/disabling service: ${svc}"
            if [ "${HAS_SYSTEMD}" -eq 1 ]; then
                run_silent systemctl stop "${svc}"
                run_silent systemctl disable "${svc}"
            fi
            run_silent service "${svc}" stop 2>/dev/null || true
            log_ok "Stopped/disabled: ${svc}"
            SERVICES_STOPPED=$(( SERVICES_STOPPED + 1 ))
        fi
    else
        log_skip "Service not found: ${svc}"
    fi
}

# ------------------------------------------------------------------------------
# STEP 1 - SERVICES
# ------------------------------------------------------------------------------
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 1/6] Stopping Okta/ScaleFT services..."
    log "[Step 1/6] Stopping Okta/ScaleFT services"
else
    echo "[Step 1/6] Discovering Okta/ScaleFT services..."
    log "[Step 1/6] Discovering Okta/ScaleFT services"
fi

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    EXPLICIT_SERVICES=(
        sftd
        scaleft-server-tools
        scaleft-client-tools
    )

    for svc in "${EXPLICIT_SERVICES[@]}"; do
        audit_or_stop_service "${svc}"
    done

    # Dynamic systemctl scan
    if [ "${HAS_SYSTEMD}" -eq 1 ]; then
        TMPSVCS=$(mktemp)
        systemctl list-unit-files --type=service --no-legend 2>/dev/null \
            | awk '{print $1}' \
            | sed 's/\.service$//' \
            | grep -Ei "${MATCH_REGEX}" \
            > "${TMPSVCS}" 2>/dev/null || true

        while IFS= read -r svc; do
            [ -z "${svc}" ] && continue
            audit_or_stop_service "${svc}"
        done < "${TMPSVCS}"
        rm -f "${TMPSVCS}"
    fi

    # SysV init.d scan
    if [ -d /etc/init.d ]; then
        for initscript in /etc/init.d/*; do
            basename_svc=$(basename "${initscript}")
            if echo "${basename_svc}" | grep -Eiq "${MATCH_REGEX}"; then
                audit_or_stop_service "${basename_svc}"
            fi
        done
    fi

    if [ "${AUDIT_SERVICES}" -eq 0 ]; then
        log_skip "No Okta/ScaleFT services found."
    fi

    if [ "${UNINSTALL}" -eq 1 ]; then sleep 2; fi
fi

# ------------------------------------------------------------------------------
# STEP 2 - PROCESSES
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 2/6] Killing residual Okta/ScaleFT processes..."
    log "[Step 2/6] Killing residual Okta/ScaleFT processes"
else
    echo "[Step 2/6] Discovering Okta/ScaleFT processes..."
    log "[Step 2/6] Discovering Okta/ScaleFT processes"
fi

audit_or_kill_processes() {
    TMPPIDS=$(mktemp)
    ps -eo pid=,comm=,args= 2>/dev/null \
        | grep -Ei "${MATCH_REGEX}" \
        | grep -v grep \
        | grep -v "remove-okta" \
        > "${TMPPIDS}" 2>/dev/null || true

    while IFS= read -r psline; do
        [ -z "${psline}" ] && continue
        local pid comm fullpath
        pid=$(echo "${psline}"      | awk '{print $1}')
        comm=$(echo "${psline}"     | awk '{print $2}')
        fullpath=$(echo "${psline}" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | awk '{print $1}')

        if [ -n "${pid}" ] && [ "${pid}" -gt 0 ] 2>/dev/null; then
            AUDIT_PROCESSES=$(( AUDIT_PROCESSES + 1 ))
            log_find "FOUND process: ${comm} | PID: ${pid} | Path: ${fullpath}"

            if [ "${UNINSTALL}" -eq 1 ]; then
                log_act "Killing PID ${pid} (${comm})"
                kill -9 "${pid}" 2>/dev/null || true
                log_ok "Killed: ${comm} (PID ${pid})"
                PROCESSES_KILLED=$(( PROCESSES_KILLED + 1 ))
            fi
        fi
    done < "${TMPPIDS}"
    rm -f "${TMPPIDS}"
}

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    audit_or_kill_processes
    if [ "${AUDIT_PROCESSES}" -eq 0 ]; then
        log_skip "No residual Okta/ScaleFT processes found."
    fi
fi

# ------------------------------------------------------------------------------
# STEP 3 - PACKAGES
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 3/6] Discovering and removing Okta/ScaleFT packages..."
    log "[Step 3/6] Discovering and removing Okta/ScaleFT packages"
else
    echo "[Step 3/6] Discovering Okta/ScaleFT packages..."
    log "[Step 3/6] Discovering Okta/ScaleFT packages"
fi

# --- RPM helpers ---
discover_rpm_packages() {
    if [ "${HAS_RPM}" -eq 0 ]; then echo ""; return; fi
    rpm -qa 2>/dev/null | grep -Ei "${MATCH_REGEX}" | sort -u
    for pkg in scaleft-server-tools scaleft-client-tools sftd; do
        if rpm -q "${pkg}" >/dev/null 2>&1; then
            echo "${pkg}"
        fi
    done
}

remove_rpm_package() {
    local pkg="$1"
    log_act "Removing RPM: ${pkg}"
    if rpm -e --nodeps "${pkg}" >>"${LOG_FILE}" 2>&1; then
        log_ok "Removed RPM: ${pkg}"
        PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 ))
    else
        log_warn "Failed to remove RPM: ${pkg} (trying package manager fallback)"
        if [ "${HAS_DNF}" -eq 1 ]; then
            dnf -y remove "${pkg}" >>"${LOG_FILE}" 2>&1 && \
                { log_ok "Removed via dnf: ${pkg}"; PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 )); } || true
        elif [ "${HAS_YUM}" -eq 1 ]; then
            yum -y remove "${pkg}" >>"${LOG_FILE}" 2>&1 && \
                { log_ok "Removed via yum: ${pkg}"; PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 )); } || true
        elif [ "${HAS_ZYPPER}" -eq 1 ]; then
            zypper -n remove "${pkg}" >>"${LOG_FILE}" 2>&1 && \
                { log_ok "Removed via zypper: ${pkg}"; PACKAGES_REMOVED=$(( PACKAGES_REMOVED + 1 )); } || true
        fi
    fi
}

process_rpm_packages() {
    TMPRPMS=$(mktemp)
    discover_rpm_packages | sort -u > "${TMPRPMS}"

    if [ ! -s "${TMPRPMS}" ]; then
        log_skip "No Okta/ScaleFT RPM packages found."
        rm -f "${TMPRPMS}"
        return
    fi

    log_find "Found Okta/ScaleFT RPM packages:"
    while IFS= read -r pkg; do
        [ -z "${pkg}" ] && continue
        AUDIT_PACKAGES=$(( AUDIT_PACKAGES + 1 ))
        local installed_version
        installed_version=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "${pkg}" 2>/dev/null || echo "unknown")
        log_find "  PACKAGE: ${pkg} | Version: ${installed_version} | Manager: RPM"
    done < "${TMPRPMS}"

    if [ "${UNINSTALL}" -eq 1 ] && [ "${CLEANUP_ONLY}" -eq 0 ]; then
        local ordered_patterns=(
            "scaleft-server"
            "scaleft-client"
            "sftd"
            "scaleft"
        )

        local removed_list=""

        for pattern in "${ordered_patterns[@]}"; do
            while IFS= read -r pkg; do
                [ -z "${pkg}" ] && continue
                if echo "${removed_list}" | grep -qx "${pkg}"; then continue; fi
                if echo "${pkg}" | grep -Eiq "${pattern}"; then
                    remove_rpm_package "${pkg}"
                    removed_list="${removed_list}
${pkg}"
                fi
            done < "${TMPRPMS}"
        done

        # Catch-all remainder
        while IFS= read -r pkg; do
            [ -z "${pkg}" ] && continue
            if echo "${removed_list}" | grep -qx "${pkg}"; then continue; fi
            remove_rpm_package "${pkg}"
        done < "${TMPRPMS}"
    fi

    rm -f "${TMPRPMS}"
}

# --- DEB helpers ---
discover_deb_packages() {
    if [ "${HAS_DEB}" -eq 0 ]; then echo ""; return; fi
    dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei "${MATCH_REGEX}" | sort -u
    for pkg in scaleft-server-tools scaleft-client-tools sftd; do
        if dpkg-query -l "${pkg}" >/dev/null 2>&1; then
            echo "${pkg}"
        fi
    done
}

remove_deb_package() {
    local pkg="$1"
    log_act "Removing DEB: ${pkg}"
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

process_deb_packages() {
    TMPDEBS=$(mktemp)
    discover_deb_packages | sort -u > "${TMPDEBS}"

    if [ ! -s "${TMPDEBS}" ]; then
        log_skip "No Okta/ScaleFT DEB packages found."
        rm -f "${TMPDEBS}"
        return
    fi

    log_find "Found Okta/ScaleFT DEB packages:"
    while IFS= read -r pkg; do
        [ -z "${pkg}" ] && continue
        AUDIT_PACKAGES=$(( AUDIT_PACKAGES + 1 ))
        local installed_version
        installed_version=$(dpkg-query -W -f='${Version}' "${pkg}" 2>/dev/null || echo "unknown")
        log_find "  PACKAGE: ${pkg} | Version: ${installed_version} | Manager: DEB"
    done < "${TMPDEBS}"

    if [ "${UNINSTALL}" -eq 1 ] && [ "${CLEANUP_ONLY}" -eq 0 ]; then
        local ordered_patterns=(
            "scaleft-server"
            "scaleft-client"
            "sftd"
            "scaleft"
        )

        local removed_list=""

        for pattern in "${ordered_patterns[@]}"; do
            while IFS= read -r pkg; do
                [ -z "${pkg}" ] && continue
                if echo "${removed_list}" | grep -qx "${pkg}"; then continue; fi
                if echo "${pkg}" | grep -Eiq "${pattern}"; then
                    remove_deb_package "${pkg}"
                    removed_list="${removed_list}
${pkg}"
                fi
            done < "${TMPDEBS}"
        done

        while IFS= read -r pkg; do
            [ -z "${pkg}" ] && continue
            if echo "${removed_list}" | grep -qx "${pkg}"; then continue; fi
            remove_deb_package "${pkg}"
        done < "${TMPDEBS}"

        if command -v apt-get >/dev/null 2>&1; then
            run_silent apt-get -y autoremove
        fi
    fi

    rm -f "${TMPDEBS}"
}

process_rpm_packages
process_deb_packages

# Second process sweep post-uninstall
if [ "${UNINSTALL}" -eq 1 ] && [ "${PACKAGES_ONLY}" -eq 0 ] && [ "${CLEANUP_ONLY}" -eq 0 ]; then
    sleep 2
    audit_or_kill_processes
fi

# ------------------------------------------------------------------------------
# STEP 4 - FILESYSTEM ARTIFACTS
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 4/6] Removing filesystem artifacts..."
    log "[Step 4/6] Removing filesystem artifacts"
else
    echo "[Step 4/6] Discovering filesystem artifacts..."
    log "[Step 4/6] Discovering filesystem artifacts"
fi

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    OKTA_DIRS=(
        /opt/scaleft
        /opt/ScaleFT
        /etc/scaleft
        /etc/ScaleFT
        /etc/sft
        /etc/sftd
        /var/lib/scaleft
        /var/lib/ScaleFT
        /var/lib/sft
        /var/lib/sftd
        /var/log/scaleft
        /var/log/ScaleFT
        /var/log/sft
        /var/log/sftd
        /var/cache/scaleft
        /usr/sbin/sftd
        /usr/local/sbin/sftd
        /usr/bin/sft
        /usr/local/bin/sft
        /root/.sft
        /root/.scaleft
        /tmp/scaleft
        /tmp/sftd
    )

    OKTA_LOG_FILES=(
        /var/log/sftd.log
        /var/log/scaleft.log
    )

    for dir in "${OKTA_DIRS[@]}"; do
        if [ -e "${dir}" ]; then
            AUDIT_FILES=$(( AUDIT_FILES + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log_act "Removing: ${dir}"
                if rm -rf "${dir}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed: ${dir}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove: ${dir}"
                fi
            else
                log_find "WOULD DELETE dir: ${dir}"
            fi
        else
            log_skip "Not found: ${dir}"
        fi
    done

    for logfile in "${OKTA_LOG_FILES[@]}"; do
        if [ -e "${logfile}" ]; then
            AUDIT_FILES=$(( AUDIT_FILES + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log_act "Removing log: ${logfile}"
                if rm -f "${logfile}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed log: ${logfile}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove log: ${logfile}"
                fi
            else
                log_find "WOULD DELETE file: ${logfile}"
            fi
        fi
    done

    if [ "${AUDIT_FILES}" -eq 0 ] && [ "${UNINSTALL}" -eq 0 ]; then
        log_skip "No Okta/ScaleFT filesystem artifacts found."
    fi
fi

# ------------------------------------------------------------------------------
# STEP 5 - SERVICE FILES AND LD.SO CLEANUP
# ------------------------------------------------------------------------------
echo ""
if [ "${UNINSTALL}" -eq 1 ]; then
    echo "[Step 5/6] Removing service files and ld.so config..."
    log "[Step 5/6] Removing service files and ld.so config"
else
    echo "[Step 5/6] Discovering service files and ld.so config..."
    log "[Step 5/6] Discovering service files and ld.so config"
fi

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    OKTA_SERVICE_FILES=(
        /etc/init.d/sftd
        /etc/init.d/scaleft-server-tools
        /etc/init.d/scaleft-client-tools
        /usr/lib/systemd/system/sftd.service
        /usr/lib/systemd/system/scaleft-server-tools.service
        /usr/lib/systemd/system/scaleft-client-tools.service
        /etc/systemd/system/sftd.service
        /etc/systemd/system/scaleft-server-tools.service
        /etc/systemd/system/scaleft-client-tools.service
    )

    OKTA_LD_CONF_FILES=(
        /etc/ld.so.conf.d/scaleft.conf
        /etc/ld.so.conf.d/sftd.conf
    )

    LD_CHANGED=0

    for f in "${OKTA_SERVICE_FILES[@]}"; do
        if [ -e "${f}" ]; then
            AUDIT_FILES=$(( AUDIT_FILES + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log_act "Removing service file: ${f}"
                if rm -f "${f}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed service file: ${f}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove service file: ${f}"
                fi
            else
                log_find "WOULD DELETE service file: ${f}"
            fi
        fi
    done

    for f in "${OKTA_LD_CONF_FILES[@]}"; do
        if [ -e "${f}" ]; then
            AUDIT_FILES=$(( AUDIT_FILES + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log_act "Removing ld.so conf: ${f}"
                if rm -f "${f}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed ld.so conf: ${f}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                    LD_CHANGED=1
                else
                    log_warn "Could not remove ld.so conf: ${f}"
                fi
            else
                log_find "WOULD DELETE ld.so conf: ${f}"
            fi
        fi
    done

    if [ "${UNINSTALL}" -eq 1 ]; then
        if [ "${LD_CHANGED}" -eq 1 ] && command -v ldconfig >/dev/null 2>&1; then
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
    echo "[Step 6/6] Removing Okta/ScaleFT cron jobs..."
    log "[Step 6/6] Removing Okta/ScaleFT cron jobs"
else
    echo "[Step 6/6] Discovering Okta/ScaleFT cron jobs..."
    log "[Step 6/6] Discovering Okta/ScaleFT cron jobs"
fi

if [ "${PACKAGES_ONLY}" -eq 0 ] || [ "${UNINSTALL}" -eq 0 ]; then
    OKTA_CRON_FILES=(
        /etc/cron.d/sftd
        /etc/cron.d/scaleft
    )

    CRON_FOUND=0
    for cron_file in "${OKTA_CRON_FILES[@]}"; do
        if [ -e "${cron_file}" ]; then
            CRON_FOUND=$(( CRON_FOUND + 1 ))
            AUDIT_FILES=$(( AUDIT_FILES + 1 ))
            if [ "${UNINSTALL}" -eq 1 ]; then
                log_act "Removing cron: ${cron_file}"
                if rm -f "${cron_file}" >>"${LOG_FILE}" 2>&1; then
                    log_ok "Removed cron: ${cron_file}"
                    FILES_REMOVED=$(( FILES_REMOVED + 1 ))
                else
                    log_warn "Could not remove cron: ${cron_file}"
                fi
            else
                log_find "WOULD DELETE cron: ${cron_file}"
            fi
        fi
    done

    if [ "${CRON_FOUND}" -eq 0 ]; then
        log_skip "No Okta/ScaleFT cron jobs found."
    fi
fi

# ------------------------------------------------------------------------------
# VERIFICATION SCAN (uninstall mode only)
# ------------------------------------------------------------------------------
REMAINING_RPM=""
REMAINING_DEB=""

if [ "${UNINSTALL}" -eq 1 ]; then
    echo ""
    log "Running post-removal verification scan..."

    if [ "${HAS_RPM}" -eq 1 ]; then
        REMAINING_RPM=$(discover_rpm_packages 2>/dev/null | sort -u || true)
        if [ -n "${REMAINING_RPM}" ]; then
            log "[WARN] Remaining RPM packages:"
            echo "${REMAINING_RPM}" | tee -a "${LOG_FILE}"
            WARNINGS=$(( WARNINGS + 1 ))
        fi
    fi

    if [ "${HAS_DEB}" -eq 1 ]; then
        REMAINING_DEB=$(discover_deb_packages 2>/dev/null | sort -u || true)
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

echo ""
echo "============================================================"

if [ "${UNINSTALL}" -eq 0 ]; then
    TOTAL_FINDINGS=$(( AUDIT_SERVICES + AUDIT_PROCESSES + AUDIT_PACKAGES + AUDIT_FILES ))

    echo "  AUDIT SUMMARY"
    echo "============================================================"
    echo "  Services found       : ${AUDIT_SERVICES}"
    echo "  Processes found      : ${AUDIT_PROCESSES}"
    echo "  Packages found       : ${AUDIT_PACKAGES}"
    echo "  Files/dirs found     : ${AUDIT_FILES}"
    echo "  Total findings       : ${TOTAL_FINDINGS}"
    echo "  Elapsed              : ${ELAPSED_FMT}"
    echo "  Log                  : ${LOG_FILE}"
    echo "============================================================"

    log "AUDIT SUMMARY: svc=${AUDIT_SERVICES} proc=${AUDIT_PROCESSES} pkg=${AUDIT_PACKAGES} files=${AUDIT_FILES} total=${TOTAL_FINDINGS} elapsed=${ELAPSED_FMT}"

    echo ""
    if [ "${TOTAL_FINDINGS}" -gt 0 ]; then
        echo "  [FIND] ${TOTAL_FINDINGS} Okta/ScaleFT component(s) detected on this host."
        echo "  Re-run with -U to perform removal."
        echo ""
        log "Audit complete. ${TOTAL_FINDINGS} findings. Exit 1."
        exit 1
    else
        echo "  [OK] No Okta/ScaleFT components detected on this host."
        echo ""
        log "Audit complete. No findings. Exit 0."
        exit 0
    fi
else
    echo "  REMOVAL SUMMARY"
    echo "============================================================"
    echo "  Services stopped     : ${SERVICES_STOPPED}"
    echo "  Processes killed     : ${PROCESSES_KILLED}"
    echo "  Packages removed     : ${PACKAGES_REMOVED}"
    echo "  Files/dirs removed   : ${FILES_REMOVED}"
    echo "  Warnings             : ${WARNINGS}"
    echo "  Elapsed              : ${ELAPSED_FMT}"
    echo "  Log                  : ${LOG_FILE}"
    echo "============================================================"

    log "REMOVAL SUMMARY: svc=${SERVICES_STOPPED} proc=${PROCESSES_KILLED} pkg=${PACKAGES_REMOVED} files=${FILES_REMOVED} warn=${WARNINGS} elapsed=${ELAPSED_FMT}"
    log "NOTE: A reboot is strongly recommended after removing sftd/scaleft components."

    if [ -n "${REMAINING_RPM}" ] || [ -n "${REMAINING_DEB}" ]; then
        echo ""
        echo "  [WARN] Some Okta/ScaleFT packages still remain. Manual review required."
        echo ""
        log "Finished with residual packages present. Exit 1."
        exit 1
    fi

    echo ""
    echo "  [OK] Okta/ScaleFT removal complete. No packages remain."
    echo ""
    log "Okta/ScaleFT removal complete. Exit 0."
    exit 0
fi
