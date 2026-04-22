#!/usr/bin/env bash
# ==============================================================================
# Create_Admin.sh
# ==============================================================================
# Author:    Brian Canaday
# Team:      netsecops-76
# Version:   3.1.0
# Created:   2026-04-20
#
# Description:
#   Create, repair, or remove a local administrator user on Linux. Designed
#   for unattended execution via Qualys Cloud Agent / CAR using UI-defined
#   POSITIONAL parameters.
#
#   Two modes, selected by the RunMode parameter:
#
#     RUN_MODE=1   Create-or-Repair
#                    If the user is absent: create with a locked password,
#                    passwordless sudo via /etc/sudoers.d/<user>, and either
#                    an RSA key or a password per AuthMethod.
#                    If the user is present: diagnose and fix SSH key-auth
#                    failure points (file perms, ownership, SELinux context,
#                    sudoers drop-in, password-lock state, authorized_keys
#                    content). Regenerates the keypair if missing or corrupt.
#
#     RUN_MODE=2   Remove
#                    Terminate all processes owned by the user (SIGKILL),
#                    run userdel -r (home dir removed), delete
#                    /etc/sudoers.d/<user>, delete /root/.ssh/<user>_rsa*.
#                    Idempotent: exits 0 with [SKIP] if the user is absent.
#
#   Authentication method (AuthMethod parameter):
#
#     "rsa"       Generate a 4096-bit PEM-format RSA keypair at
#                 /root/.ssh/<user>_rsa and install its public key into
#                 the user's ~/.ssh/authorized_keys. Private key is
#                 emitted to stdout so Qualys log retrieval captures it.
#                 Password behaviour (below) still applies - typically
#                 left empty so the password stays locked and only key
#                 auth works.
#     "password"  No key is generated. A password MUST be supplied.
#                 SSH password auth must be enabled in sshd_config for
#                 the account to be usable remotely.
#
#   Password sourcing (Password parameter):
#
#     ""          Leave the password locked. Only meaningful with
#                 AuthMethod=rsa; rejected with AuthMethod=password.
#     "CHANGE_ME" Sentinel placeholder. Script REFUSES to run while
#                 this value is present. Forces an intentional edit
#                 in the CAR UI before deployment.
#     "<literal>" Use the given string as the password.
#
# ==============================================================================
# CAR UI PARAMETERS (define on Script Details page in this EXACT order):
# ==============================================================================
#
#   Position 1:  RunMode
#     Type:      String
#     Required:  No
#     Default:   1
#     Allowed:   1 = create-or-repair (non-destructive if account exists)
#                2 = remove (terminates user processes, deletes account)
#
#   Position 2:  AuthMethod
#     Type:      String
#     Required:  No
#     Default:   rsa
#     Allowed:   rsa | password
#     Purpose:   Whether to provision SSH-key auth or a login password.
#                "rsa" generates a 4096-bit PEM keypair for the user.
#
#   Position 3:  Username
#     Type:      String
#     Required:  Yes
#     Default:   (none)
#     Example:   TEMPADMIN
#     Purpose:   Local account to create, repair, or remove. Must match
#                POSIX rules: lowercase letters, digits, underscore, dash;
#                1-32 chars; cannot start with a digit.
#
#   Position 4:  Password
#     Type:      String   (mark sensitive / masked if CAR supports it)
#     Required:  Conditional
#                - Empty / omitted when AuthMethod=rsa (account stays locked)
#                - Required (non-empty) when AuthMethod=password
#     Default:   (empty)
#     Purpose:   Initial password for the account. Masked as *** in banner
#                and log output. NEVER leave as "CHANGE_ME".
#                Intentionally LAST so omitting it does not shift the
#                preceding arguments.
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Go to: Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details tab:
#        Name:        Create Admin User (Linux)
#        Description: Create, repair, or remove a local admin user.
#        Platform:    Linux
#        Interpreter: Bash (shebang /usr/bin/env bash in the script)
#        Upload:      Create_Admin.sh from this repo
#   4. Parameters tab (ORDER MATTERS - positional):
#        Add parameter: RunMode     (String, Optional, default "1")
#        Add parameter: AuthMethod  (String, Optional, default "rsa")
#        Add parameter: Username    (String, Required, no default)
#        Add parameter: Password    (String, Optional, mark sensitive)
#        NOTE: Password is LAST so leaving it blank does not shift the
#              preceding arguments.
#   5. Save. Attach the script to a CAR Job that targets the intended assets.
#   6. Runtime output is captured by the Qualys Cloud Agent. Review via
#        CAR -> Jobs -> <job> -> Results -> Script Output.
#
# CLI INVOCATION (local testing):
#   sudo ./Create_Admin.sh <RunMode> <AuthMethod> <Username> [<Password>]
#   sudo ./Create_Admin.sh 1 rsa TEMPADMIN
#   sudo ./Create_Admin.sh 2 rsa TEMPADMIN
#   sudo ./Create_Admin.sh 1 password TEMPADMIN 'MyP@ss'
#
# CAR INVOKES EQUIVALENT TO:
#   /bin/bash Create_Admin.sh "<RunMode>" "<AuthMethod>" "<Username>" "<Password>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional args win. If any positional is empty, the script checks the
#   same-named environment variable ($RUN_MODE, $AUTH_METHOD, $USERNAME,
#   $PASSWORD) before applying defaults. Lets local developers export vars
#   once and rerun without retyping positional args.
#
# Exit Codes:
#   0  = Success
#   1  = Completed with warnings
#   2  = Fatal error / must be run as root / invalid parameters
#
# Changelog:
#   3.1.0 - 2026-04-22 - Fix CAR positional-arg shift bug. When Password
#                        is left blank in the CAR UI, some CAR versions
#                        omit the empty parameter entirely instead of
#                        passing "". This shifted RunMode into the
#                        Password position, causing Mode 2 runs to
#                        execute as Mode 1. Fix: reorder positional
#                        params so RunMode is first and Password is
#                        last. New order: RunMode, AuthMethod,
#                        Username, Password.
#   3.0.1 - 2026-04-21 - Mode 2 session-termination: SIGTERM -> SIGKILL
#                        escalation is the routine fallback by design, not
#                        a failure. Downgrade that log line from [WARN]
#                        to [INFO] so a successful cleanup doesn't bump
#                        the warning counter (which otherwise trips exit
#                        code 1 on an otherwise clean run). Final summary
#                        now reports whether SIGTERM was sufficient or
#                        SIGKILL escalation was required. The genuine
#                        error path (SIGKILL itself fails, processes
#                        survive) remains [ERROR] and still exits 2.
#                        Matches the equivalent fix in Create_Admin.ps1
#                        v3.0.1.
#   3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces the
#                        hard-coded ENVIRONMENT block with POSITIONAL
#                        args consumable by Qualys CAR UI parameters.
#                        Dual-invocation support: positional first,
#                        fallback to env vars, defaults last. ASCII-only
#                        log output. Password masked in banner.
#   2.0.0 - 2026-04-20 - Rewrite. Replaces Create_Admin.py (965 lines of
#                        Python) with bash. Introduces the ENVIRONMENT
#                        block, explicit RUN_MODE selector, AUTH_METHOD
#                        switch, and explicit Mode 2 (remove).
#   1.0.0 - 2026-03-30 - Initial Python version (superseded).
#
# Safety:
#   - Password travels through the CAR UI parameter. Anyone with policy-
#     edit rights on the CAR job sees it. Rotate after first run.
#   - The RSA private key (AuthMethod=rsa) is emitted to stdout so the
#     Qualys agent retrieves it via its log channel. Treat that channel
#     as credential-sensitive.
#   - Mode 2 terminates sessions owned by the user (pkill -KILL -u)
#     before userdel. Running Mode 2 fleet-wide is destructive; review
#     CAR job parameters carefully before deployment.
# ==============================================================================

set -u
set -o pipefail

# ============================================================
# PARAMETER RESOLUTION: positional first, env fallback, defaults last.
#
# IMPORTANT: Password is intentionally LAST so that when CAR omits
# empty parameters (rather than passing ""), the other three fields
# don't shift. Common case: AuthMethod=rsa with no password means
# CAR sends only 3 args and position 4 is simply absent.
# ============================================================
RUN_MODE="${1:-${RUN_MODE:-1}}"
AUTH_METHOD="${2:-${AUTH_METHOD:-rsa}}"
USERNAME="${3:-${USERNAME:-}}"
PASSWORD="${4:-${PASSWORD:-}}"
# ============================================================

# -------- globals / state --------
SCRIPT_NAME="Create_Admin.sh"
SCRIPT_VERSION="3.1.0"
STAMP="$(date '+%Y%m%d_%H%M%S')"
HOSTNAME_LOCAL="$(hostname 2>/dev/null || echo unknown)"
STARTED_AT="$(date '+%Y-%m-%dT%H:%M:%S%z')"
START_EPOCH="$(date +%s)"

LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/admin_user_provision_${STAMP}.log"

SSH_KEY_COMMENT="recovery-access"
SUDOERS_FILE=""   # populated after USERNAME validation
PRIV_KEY_PATH=""
PUB_KEY_PATH=""

COUNT_WARNINGS=0
COUNT_ERRORS=0
ISSUES_FOUND_FILE="$(mktemp /tmp/create-admin-issues.XXXXXX)"
ISSUES_FIXED_FILE="$(mktemp /tmp/create-admin-fixed.XXXXXX)"

trap 'rm -f "${ISSUES_FOUND_FILE}" "${ISSUES_FIXED_FILE}"' EXIT

# ============================================================
# LOGGING HELPERS
# ============================================================
_log_line() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local line="${ts}  [${level}]  $*"
    mkdir -p "${LOG_DIR}" 2>/dev/null
    printf '%s\n' "${line}" >>"${LOG_FILE}" 2>/dev/null
    printf '%s\n' "${line}"
}
log()      { _log_line "INFO " "$@"; }
log_ok()   { _log_line "OK   " "$@"; }
log_warn() { _log_line "WARN " "$@"; COUNT_WARNINGS=$((COUNT_WARNINGS + 1)); }
log_err()  { _log_line "ERROR" "$@"; COUNT_ERRORS=$((COUNT_ERRORS + 1)); }
log_find() { _log_line "FIND " "$@"; }
log_skip() { _log_line "--   " "$@"; }

issue_found() { printf '%s\n' "$*" >>"${ISSUES_FOUND_FILE}"; log_warn "ISSUE: $*"; }
issue_fixed() { printf '%s\n' "$*" >>"${ISSUES_FIXED_FILE}"; log_ok   "FIXED: $*"; }

# ============================================================
# LOW-LEVEL HELPERS
# ============================================================
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_err "This script must be run as root."
        exit 2
    fi
}

user_exists() {
    id -u "$1" >/dev/null 2>&1
}

detect_distro() {
    if [ -r /etc/redhat-release ]; then echo "rhel"
    elif [ -r /etc/debian_version ]; then echo "debian"
    else echo "generic"
    fi
}

selinux_enforcing() {
    command -v getenforce >/dev/null 2>&1 || return 1
    [ "$(getenforce 2>/dev/null)" = "Enforcing" ]
}

# Validate environment settings. Emits errors and exits on invalid combinations.
validate_env() {
    # USERNAME
    if [ -z "${USERNAME}" ]; then
        log_err "USERNAME is empty. Supply via CAR parameter 1 or \$USERNAME env var."
        exit 2
    fi
    if ! printf '%s' "${USERNAME}" | grep -qE '^[a-z_][a-z0-9_-]{0,31}$'; then
        log_err "USERNAME '${USERNAME}' is not a valid POSIX-ish username (lowercase + digits + _ -, 1-32 chars)."
        exit 2
    fi

    # RUN_MODE
    case "${RUN_MODE}" in
        1|2) : ;;
        *)
            log_err "RUN_MODE='${RUN_MODE}' is invalid. Must be 1 (create-or-repair) or 2 (remove)."
            exit 2
            ;;
    esac

    # AUTH_METHOD (only matters for Mode 1; Mode 2 ignores it)
    if [ "${RUN_MODE}" -eq 1 ]; then
        case "${AUTH_METHOD}" in
            rsa|password) : ;;
            *)
                log_err "AUTH_METHOD='${AUTH_METHOD}' is invalid. Must be 'rsa' or 'password'."
                exit 2
                ;;
        esac
        if [ "${AUTH_METHOD}" = "password" ] && [ -z "${PASSWORD}" ]; then
            log_err "AuthMethod='password' requires Password parameter to be non-empty (CAR parameter 3 or \$PASSWORD env)."
            exit 2
        fi
        if [ "${PASSWORD}" = "CHANGE_ME" ]; then
            log_err "Password is still the 'CHANGE_ME' placeholder - refusing to run. Set a real value in the CAR UI parameter before deployment."
            exit 2
        fi
    fi

    # Populate derived paths
    SUDOERS_FILE="/etc/sudoers.d/${USERNAME}"
    PRIV_KEY_PATH="/root/.ssh/${USERNAME}_rsa"
    PUB_KEY_PATH="${PRIV_KEY_PATH}.pub"
}

# Resolve the plaintext password to use for Mode 1. May be empty (keep locked).
resolve_password() {
    if [ -z "${PASSWORD}" ]; then
        # Only valid with AUTH_METHOD=rsa - already enforced in validate_env
        log "Password: empty - account will be left locked (key-only auth)."
        printf ''
        return
    fi
    log_warn "Literal password supplied via CAR parameter - rotate after first run and whenever policy editors change."
    printf '%s' "${PASSWORD}"
}

# ============================================================
# CREATE PATH - user does not exist
# ============================================================

create_user() {
    local distro
    distro="$(detect_distro)"
    log "Detected distro family: ${distro}"

    # useradd with home dir, /bin/bash shell, and a sensible description
    if ! useradd --create-home --shell /bin/bash \
                 --comment "Emergency recovery - Qualys provisioned" \
                 "${USERNAME}"; then
        log_err "useradd failed for '${USERNAME}'."
        exit 2
    fi
    log_ok "User '${USERNAME}' created."
}

configure_sudo() {
    local line="${USERNAME} ALL=(ALL) NOPASSWD: ALL"
    local tmp
    tmp="$(mktemp /tmp/sudoers.XXXXXX)"
    printf '%s\n' "${line}" >"${tmp}"
    chmod 0440 "${tmp}"
    if ! visudo -cf "${tmp}" >/dev/null; then
        rm -f "${tmp}"
        log_err "Sudoers syntax check failed; refusing to install drop-in."
        return 1
    fi
    install -m 0440 -o root -g root "${tmp}" "${SUDOERS_FILE}"
    rm -f "${tmp}"
    log_ok "Sudoers drop-in installed: ${SUDOERS_FILE}"
}

generate_rsa_keypair() {
    local home_dir ssh_dir authorized_keys
    home_dir="$(getent passwd "${USERNAME}" | cut -d: -f6)"
    ssh_dir="${home_dir}/.ssh"
    authorized_keys="${ssh_dir}/authorized_keys"

    # Ensure .ssh dir exists under the user's home
    install -d -m 0700 -o "${USERNAME}" -g "${USERNAME}" "${ssh_dir}"

    # Ensure /root/.ssh exists for the retrieval copy
    install -d -m 0700 -o root -g root /root/.ssh

    # Remove any stale key files - regenerating fresh
    rm -f "${PRIV_KEY_PATH}" "${PUB_KEY_PATH}"

    # RSA 4096, PEM format (BEGIN RSA PRIVATE KEY), no passphrase
    if ! ssh-keygen -t rsa -b 4096 -m PEM \
                    -f "${PRIV_KEY_PATH}" -N "" \
                    -C "${SSH_KEY_COMMENT}@${HOSTNAME_LOCAL}" >/dev/null; then
        log_err "ssh-keygen failed."
        return 1
    fi
    chmod 0600 "${PRIV_KEY_PATH}"
    log_ok "RSA 4096 keypair generated at ${PRIV_KEY_PATH}"

    # Install public key into authorized_keys (fresh - single entry)
    install -m 0600 -o "${USERNAME}" -g "${USERNAME}" \
            "${PUB_KEY_PATH}" "${authorized_keys}"
    log_ok "authorized_keys installed for '${USERNAME}'"

    # Restore SELinux context if enforcing
    if selinux_enforcing; then
        restorecon -R -v "${ssh_dir}" >/dev/null 2>&1 || true
        log_ok "SELinux context restored on ${ssh_dir}"
    fi
}

set_user_password() {
    local pw="$1"
    if [ -z "${pw}" ]; then
        # Explicit lock via passwd -l
        if passwd -l "${USERNAME}" >/dev/null 2>&1; then
            log_ok "Password locked for '${USERNAME}' (key-only auth)."
        else
            log_warn "Failed to lock password for '${USERNAME}'."
        fi
        return
    fi
    # chpasswd reads "user:pw" from stdin - avoids argv exposure
    if printf '%s:%s' "${USERNAME}" "${pw}" | chpasswd; then
        log_ok "Password set for '${USERNAME}'."
    else
        log_err "chpasswd failed for '${USERNAME}'."
    fi
}

# ============================================================
# REPAIR PATH - user exists
# ============================================================

# Check a path's mode and fix it if wrong. Emits issue_found / issue_fixed.
ensure_mode() {
    local path="$1" want="$2" label="$3"
    if [ ! -e "${path}" ]; then
        issue_found "${label} missing: ${path}"
        return 1
    fi
    local actual
    actual="$(stat -c '%a' "${path}" 2>/dev/null)"
    if [ "${actual}" != "${want}" ]; then
        issue_found "${label} perms wrong: ${path} is ${actual}, want ${want}"
        if chmod "${want}" "${path}"; then
            issue_fixed "${label} perms -> ${want}"
        else
            log_err "chmod ${want} ${path} failed"
        fi
    fi
}

# Check ownership and fix if wrong. Emits issue_found / issue_fixed.
ensure_owner() {
    local path="$1" want_uid="$2" want_gid="$3" label="$4"
    if [ ! -e "${path}" ]; then return; fi
    local uid gid
    uid="$(stat -c '%u' "${path}" 2>/dev/null)"
    gid="$(stat -c '%g' "${path}" 2>/dev/null)"
    if [ "${uid}" != "${want_uid}" ] || [ "${gid}" != "${want_gid}" ]; then
        issue_found "${label} ownership wrong: ${path} is ${uid}:${gid}, want ${want_uid}:${want_gid}"
        if chown "${want_uid}:${want_gid}" "${path}"; then
            issue_fixed "${label} ownership -> ${want_uid}:${want_gid}"
        else
            log_err "chown ${want_uid}:${want_gid} ${path} failed"
        fi
    fi
}

# Ensure the password is locked when AUTH_METHOD=rsa with empty PASSWORD.
ensure_password_locked() {
    local status
    status="$(passwd -S "${USERNAME}" 2>/dev/null | awk '{print $2}')"
    case "${status}" in
        LK|L|NP) log_skip "Password status for '${USERNAME}' is ${status} - already locked." ;;
        PS|P)
            issue_found "Password is unlocked (status=${status}) - sshd may prompt for password on key-auth failure."
            if passwd -l "${USERNAME}" >/dev/null 2>&1; then
                issue_fixed "Password locked for '${USERNAME}'."
            fi
            ;;
        *) log_warn "Password status for '${USERNAME}' is '${status:-unknown}'."
           ;;
    esac
}

# Verify authorized_keys contains the public key that matches /root/.ssh/<user>_rsa.pub.
ensure_authorized_keys_match() {
    local authorized_keys="$1"
    if [ ! -r "${PUB_KEY_PATH}" ]; then
        issue_found "Retrieval public key missing: ${PUB_KEY_PATH} - will regenerate."
        return 1
    fi
    if [ ! -r "${authorized_keys}" ]; then
        issue_found "authorized_keys missing: ${authorized_keys} - will regenerate."
        return 1
    fi
    local pub
    pub="$(cat "${PUB_KEY_PATH}")"
    if grep -qF -- "${pub}" "${authorized_keys}"; then
        log_skip "Public key already present in authorized_keys."
        return 0
    fi
    issue_found "Public key in ${PUB_KEY_PATH} not found in ${authorized_keys} - will overwrite."
    return 1
}

# Verify private key is PEM/RSA (not OpenSSH format - broader client compat).
ensure_private_key_format() {
    if [ ! -r "${PRIV_KEY_PATH}" ]; then
        issue_found "Private key missing: ${PRIV_KEY_PATH}"
        return 1
    fi
    if grep -q 'BEGIN RSA PRIVATE KEY' "${PRIV_KEY_PATH}" 2>/dev/null; then
        log_skip "Private key is PEM RSA format - good."
        return 0
    fi
    if grep -q 'BEGIN OPENSSH PRIVATE KEY' "${PRIV_KEY_PATH}" 2>/dev/null; then
        issue_found "Private key is OpenSSH format (not PEM); regenerating for broader client compat."
        return 1
    fi
    issue_found "Private key format unrecognized at ${PRIV_KEY_PATH}; regenerating."
    return 1
}

ensure_sudoers_dropin() {
    if [ -r "${SUDOERS_FILE}" ]; then
        if visudo -cf "${SUDOERS_FILE}" >/dev/null 2>&1; then
            log_skip "Sudoers drop-in present and valid: ${SUDOERS_FILE}"
            return 0
        fi
        issue_found "Sudoers drop-in ${SUDOERS_FILE} fails visudo syntax check - rewriting."
    else
        issue_found "Sudoers drop-in missing: ${SUDOERS_FILE}"
    fi
    if configure_sudo; then
        issue_fixed "Sudoers drop-in installed: ${SUDOERS_FILE}"
    fi
}

ensure_sshd_pubkey_auth() {
    # Light sshd_config check - flag only PubkeyAuthentication no and
    # PasswordAuthentication no (the latter is informational only, not a
    # failure, but we log it). We deliberately do NOT modify sshd_config.
    local conf=/etc/ssh/sshd_config
    [ -r "${conf}" ] || return
    local pubkey
    pubkey="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*PubkeyAuthentication/ {print $2}' "${conf}" | tail -n1)"
    pubkey="${pubkey:-yes}"
    if [ "$(printf '%s' "${pubkey}" | tr '[:upper:]' '[:lower:]')" = "no" ]; then
        log_warn "sshd_config: PubkeyAuthentication is 'no' - key auth will fail even with correct files."
    else
        log_skip "sshd_config: PubkeyAuthentication=${pubkey}"
    fi
}

remediate_user() {
    local home_dir uid gid ssh_dir authorized_keys
    home_dir="$(getent passwd "${USERNAME}" | cut -d: -f6)"
    uid="$(id -u "${USERNAME}")"
    gid="$(id -g "${USERNAME}")"
    ssh_dir="${home_dir}/.ssh"
    authorized_keys="${ssh_dir}/authorized_keys"

    log "Repair target: user=${USERNAME} home=${home_dir} uid=${uid} gid=${gid}"

    # --- Shell ---
    local shell_cur
    shell_cur="$(getent passwd "${USERNAME}" | cut -d: -f7)"
    case "${shell_cur}" in
        /sbin/nologin|/usr/sbin/nologin|/bin/false)
            issue_found "User shell is ${shell_cur} - SSH login blocked."
            if usermod -s /bin/bash "${USERNAME}"; then
                issue_fixed "Shell set to /bin/bash."
            fi
            ;;
        *)
            log_skip "Shell: ${shell_cur}"
            ;;
    esac

    # --- Sudoers drop-in ---
    ensure_sudoers_dropin

    # --- RSA-specific checks (skip entirely under AUTH_METHOD=password) ---
    if [ "${AUTH_METHOD}" = "rsa" ]; then
        # Ensure dirs exist with correct modes
        if [ ! -d "${ssh_dir}" ]; then
            issue_found ".ssh dir missing; creating ${ssh_dir}"
            install -d -m 0700 -o "${uid}" -g "${gid}" "${ssh_dir}"
            issue_fixed ".ssh dir created."
        fi

        ensure_mode  "${home_dir}" 700 "Home directory"
        ensure_owner "${home_dir}" "${uid}" "${gid}" "Home directory"
        ensure_mode  "${ssh_dir}"  700 ".ssh directory"
        ensure_owner "${ssh_dir}"  "${uid}" "${gid}" ".ssh directory"

        # Key material - regenerate if any check flags a problem
        local regen=0
        ensure_private_key_format      || regen=1
        ensure_authorized_keys_match "${authorized_keys}" || regen=1

        if [ "${regen}" -eq 1 ]; then
            log "Regenerating keypair and rewriting authorized_keys."
            if generate_rsa_keypair; then
                issue_fixed "Keypair regenerated and authorized_keys rewritten."
            fi
        fi

        # Re-assert modes on the key files after any changes
        ensure_mode  "${authorized_keys}" 600 "authorized_keys"
        ensure_owner "${authorized_keys}" "${uid}" "${gid}" "authorized_keys"
        [ -r "${PRIV_KEY_PATH}" ] && chmod 0600 "${PRIV_KEY_PATH}"

        # SELinux context
        if selinux_enforcing; then
            local ctx
            ctx="$(ls -dZ "${ssh_dir}" 2>/dev/null | awk '{print $1}')"
            if ! printf '%s' "${ctx}" | grep -q 'ssh_home_t'; then
                issue_found "SELinux context wrong on ${ssh_dir}: ${ctx} (expected ssh_home_t)"
                if restorecon -R -v "${ssh_dir}" >/dev/null 2>&1; then
                    issue_fixed "SELinux context restored."
                fi
            else
                log_skip "SELinux context on ${ssh_dir} looks right."
            fi
        fi

        # sshd_config sanity (informational)
        ensure_sshd_pubkey_auth
    fi

    # --- Password handling (both auth methods) ---
    if [ "${AUTH_METHOD}" = "rsa" ] && [ -z "${PASSWORD}" ]; then
        ensure_password_locked
    else
        local pw
        pw="$(resolve_password)"
        set_user_password "${pw}"
    fi
}

# ============================================================
# REMOVE PATH
# ============================================================

# Kill all processes owned by the user (SIGTERM then SIGKILL).
terminate_user_sessions() {
    local pids
    pids="$(pgrep -u "${USERNAME}" 2>/dev/null || true)"
    if [ -z "${pids}" ]; then
        log_skip "No active processes owned by '${USERNAME}'."
        return 0
    fi
    local initial_count
    initial_count="$(printf '%s\n' "${pids}" | awk 'NF' | wc -l | tr -d ' ')"
    log "Terminating processes owned by '${USERNAME}': $(printf '%s' "${pids}" | tr '\n' ' ')"

    # Polite first: SIGTERM
    pkill -TERM -u "${USERNAME}" 2>/dev/null || true
    # Short grace window
    local i
    for i in 1 2 3; do
        sleep 1
        pgrep -u "${USERNAME}" >/dev/null 2>&1 || break
    done

    # Forceful escalation if any remain. This is the routine fallback - not a
    # failure condition. Log at INFO so a successful cleanup doesn't bump the
    # warning counter (which would trip exit code 1 on an otherwise clean run).
    local escalated=0
    if pgrep -u "${USERNAME}" >/dev/null 2>&1; then
        local stuck
        stuck="$(pgrep -u "${USERNAME}" 2>/dev/null | wc -l | tr -d ' ')"
        log "Processes for '${USERNAME}' still present after SIGTERM (${stuck} remaining) - escalating to SIGKILL."
        pkill -KILL -u "${USERNAME}" 2>/dev/null || true
        sleep 1
        escalated=1
    fi

    # If SIGKILL also failed, this is a real error (uninterruptible or defunct).
    if pgrep -u "${USERNAME}" >/dev/null 2>&1; then
        log_err "Could not terminate all processes owned by '${USERNAME}'; userdel will likely fail."
        return 1
    fi

    if [ "${escalated}" -eq 1 ]; then
        log_ok "All processes for '${USERNAME}' terminated (${initial_count} signalled; SIGKILL escalation was required)."
    else
        log_ok "All processes for '${USERNAME}' terminated (${initial_count} signalled; SIGTERM was sufficient)."
    fi
}

remove_user() {
    if ! user_exists "${USERNAME}"; then
        log_skip "User '${USERNAME}' does not exist - nothing to remove."
        return 0
    fi

    log_warn "Mode 2: removing user '${USERNAME}' from ${HOSTNAME_LOCAL}. This kills active sessions and deletes the home directory."

    terminate_user_sessions || true

    # userdel -r removes the home directory and mail spool
    if userdel -r "${USERNAME}" 2>/dev/null; then
        log_ok "userdel -r '${USERNAME}' succeeded."
    else
        # userdel without -r if home removal fails (keeps account gone even if home cleanup balks)
        if userdel "${USERNAME}" 2>/dev/null; then
            log_warn "userdel -r failed; ran userdel without -r (home dir may remain)."
        else
            log_err "userdel '${USERNAME}' failed - manual intervention required."
            return 1
        fi
    fi

    # Sudoers drop-in
    if [ -e "${SUDOERS_FILE}" ]; then
        if rm -f "${SUDOERS_FILE}"; then
            log_ok "Removed sudoers drop-in: ${SUDOERS_FILE}"
        else
            log_warn "Failed to remove ${SUDOERS_FILE}"
        fi
    fi

    # Retrieval key pair in /root/.ssh/
    local removed=0
    for p in "${PRIV_KEY_PATH}" "${PUB_KEY_PATH}"; do
        if [ -e "${p}" ]; then
            rm -f "${p}" && removed=$((removed + 1))
        fi
    done
    if [ "${removed}" -gt 0 ]; then
        log_ok "Removed ${removed} retrieval key file(s) from /root/.ssh/"
    fi
}

# ============================================================
# VERIFY + OUTPUT
# ============================================================

verify_mode_1() {
    local home_dir uid sudoers_ok key_ok authkeys_ok shell_ok pw_ok
    local ssh_dir authorized_keys
    home_dir="$(getent passwd "${USERNAME}" 2>/dev/null | cut -d: -f6)"
    uid="$(id -u "${USERNAME}" 2>/dev/null)"
    ssh_dir="${home_dir:-/nonexistent}/.ssh"
    authorized_keys="${ssh_dir}/authorized_keys"

    local all_pass=1
    _check() {
        local label="$1" pass="$2"
        if [ "${pass}" -eq 1 ]; then
            log_find "[PASS] ${label}"
        else
            log_find "[FAIL] ${label}"
            all_pass=0
        fi
    }

    _check "User exists"                      "$(user_exists "${USERNAME}" && echo 1 || echo 0)"
    _check "Sudoers drop-in present"          "$([ -r "${SUDOERS_FILE}" ] && echo 1 || echo 0)"

    if [ "${AUTH_METHOD}" = "rsa" ]; then
        _check ".ssh dir exists"              "$([ -d "${ssh_dir}" ] && echo 1 || echo 0)"
        _check "authorized_keys present"      "$([ -r "${authorized_keys}" ] && echo 1 || echo 0)"
        _check "Private key present"          "$([ -r "${PRIV_KEY_PATH}" ] && echo 1 || echo 0)"
        _check "Private key is PEM RSA"       "$(grep -q 'BEGIN RSA PRIVATE KEY' "${PRIV_KEY_PATH}" 2>/dev/null && echo 1 || echo 0)"
    fi

    local shell_cur
    shell_cur="$(getent passwd "${USERNAME}" 2>/dev/null | cut -d: -f7)"
    case "${shell_cur}" in
        /sbin/nologin|/usr/sbin/nologin|/bin/false) _check "Shell is a login shell" 0 ;;
        *)                                           _check "Shell is a login shell" 1 ;;
    esac

    local pw_status
    pw_status="$(passwd -S "${USERNAME}" 2>/dev/null | awk '{print $2}')"
    if [ "${AUTH_METHOD}" = "rsa" ] && [ -z "${PASSWORD}" ]; then
        case "${pw_status}" in
            LK|L|NP) _check "Password locked (expected for rsa / empty PASSWORD)" 1 ;;
            *)       _check "Password locked (expected for rsa / empty PASSWORD)" 0 ;;
        esac
    else
        case "${pw_status}" in
            PS|P) _check "Password usable"      1 ;;
            *)    _check "Password usable"      0 ;;
        esac
    fi

    if [ "${all_pass}" -eq 1 ]; then
        log_ok "Mode 1 verify: PASS"
    else
        log_warn "Mode 1 verify: some checks FAILED (see above)."
    fi
}

verify_mode_2() {
    if user_exists "${USERNAME}"; then
        log_warn "Mode 2 verify: FAIL - user '${USERNAME}' still exists."
    else
        log_ok "Mode 2 verify: PASS - user '${USERNAME}' is absent."
    fi
    [ -e "${SUDOERS_FILE}" ]       && log_warn "Residual sudoers file: ${SUDOERS_FILE}"
    [ -e "${PRIV_KEY_PATH}" ]      && log_warn "Residual private key: ${PRIV_KEY_PATH}"
}

output_retrieval_material() {
    # Emits the private key and/or the generated password to stdout, wrapped
    # in markers the Qualys log channel will preserve verbatim.
    if [ "${AUTH_METHOD}" = "rsa" ] && [ -r "${PRIV_KEY_PATH}" ]; then
        printf '\n'
        printf -- '--- BEGIN PRIVATE KEY: %s / %s ---\n' "${HOSTNAME_LOCAL}" "${USERNAME}"
        cat "${PRIV_KEY_PATH}"
        printf -- '--- END PRIVATE KEY: %s / %s ---\n' "${HOSTNAME_LOCAL}" "${USERNAME}"
        if [ -r "${PUB_KEY_PATH}" ]; then
            printf '\n'
            printf -- '--- PUBLIC KEY: %s / %s ---\n' "${HOSTNAME_LOCAL}" "${USERNAME}"
            cat "${PUB_KEY_PATH}"
            printf -- '--- END PUBLIC KEY: %s / %s ---\n' "${HOSTNAME_LOCAL}" "${USERNAME}"
        fi
    fi
}

# ============================================================
# MAIN
# ============================================================
log "================================================================"
log "${SCRIPT_NAME} v${SCRIPT_VERSION} on ${HOSTNAME_LOCAL}"
log "Started at         : ${STARTED_AT}"
log "Target username    : ${USERNAME}"
case "${RUN_MODE}" in
    1) log "Run mode           : 1 (create-or-repair)" ;;
    2) log "Run mode           : 2 (remove)" ;;
    *) log "Run mode           : ${RUN_MODE} (invalid - will error in validation)" ;;
esac
if [ "${RUN_MODE}" -eq 1 ]; then
    log "Auth method        : ${AUTH_METHOD}"
    if [ -z "${PASSWORD}" ]; then
        log "Password source    : (empty - leave locked)"
    else
        log "Password source    : literal (supplied via CAR parameter, masked ***)"
    fi
fi
log "Log file           : ${LOG_FILE}"
log "================================================================"

require_root
validate_env

case "${RUN_MODE}" in
    1)
        if user_exists "${USERNAME}"; then
            log "User '${USERNAME}' EXISTS - entering repair path."
            remediate_user

            # Count and report the diagnosis / fix tallies
            local_found="$(wc -l <"${ISSUES_FOUND_FILE}" 2>/dev/null | tr -d ' ')"
            local_fixed="$(wc -l <"${ISSUES_FIXED_FILE}" 2>/dev/null | tr -d ' ')"
            log "Repair summary: ${local_found} issue(s) found, ${local_fixed} fix(es) applied."
        else
            log "User '${USERNAME}' does NOT exist - entering create path."
            create_user
            configure_sudo || true
            if [ "${AUTH_METHOD}" = "rsa" ]; then
                generate_rsa_keypair || true
            fi
            pw="$(resolve_password)"
            set_user_password "${pw}"
        fi
        verify_mode_1
        output_retrieval_material
        ;;
    2)
        remove_user
        verify_mode_2
        ;;
esac

elapsed=$(( $(date +%s) - START_EPOCH ))
log "Warnings: ${COUNT_WARNINGS}   Errors: ${COUNT_ERRORS}   Elapsed: ${elapsed}s"

if [ "${COUNT_ERRORS}"   -gt 0 ]; then exit 2; fi
if [ "${COUNT_WARNINGS}" -gt 0 ]; then exit 1; fi
exit 0
