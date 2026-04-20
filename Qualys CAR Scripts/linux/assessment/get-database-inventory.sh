#!/usr/bin/env bash
# ==============================================================================
# get-database-inventory.sh
# ==============================================================================
# Author:    Brian Canaday
# Team:      netsecops-76
# Version:   3.0.0
# Created:   2026-04-14
#
# Description:
#   Read-only database-inventory discovery script for Linux hosts, designed
#   for unattended execution via Qualys CAR using UI-defined POSITIONAL
#   parameters. Makes NO changes to the system, opens NO outbound network
#   connections (except the opt-in probes below), and modifies NO database
#   state.
#
#   Coverage (current):
#     MySQL / MariaDB / Percona Server    PostgreSQL (incl. Greenplum/EDB)
#     MongoDB                              Redis
#     Oracle Database                      IBM Db2
#     SAP HANA                             SAP ASE (Sybase) / MaxDB
#     Microsoft SQL Server on Linux        Informix / Firebird / Teradata
#     Apache Cassandra / ScyllaDB          InfluxDB / ClickHouse
#     Elasticsearch / OpenSearch           CouchDB / Couchbase / Neo4j
#     etcd                                 HashiCorp Consul            (v2.0)
#     Memcached (cache, DBMS-adjacent)     Prometheus                  (v2.0)
#     H2 / HSQLDB / Derby (server mode)                                (v2.0)
#     SQLite filesystem scan (opt-in)                                  (v2.0)
#
#   Per-instance output captures: host identity (hostname, FQDN, domain,
#   IPv4/v6, OS), product / edition / version, instance name + id, install
#   and data paths, service name/state/account, PIDs and process owners,
#   listening IPs + ports, database/catalog names (config/FS first, deep
#   probe optional), authentication mode and source (registry or config file
#   + line), SPNs (with --include-ad-lookup), TLS/encryption posture.
#
# ==============================================================================
# CAR UI PARAMETERS (define on Script Details page in this EXACT order):
# ==============================================================================
#
#   Position 1:  DeepProbe                 (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off (case-insensitive)
#     Purpose:   Opt-in. Open local trust-based queries to discovered
#                instances to enumerate catalog names. DISRUPTION NOTE:
#                queries will appear in DB audit logs. Coordinate with DBAs
#                before fleet rollout.
#
#   Position 2:  IncludeAdLookup           (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Opt-in. Resolve domain service accounts via ldapsearch or
#                getent. DISRUPTION NOTE: fleet-wide LDAP fan-out can spike
#                DC load. Pair with scheduled jitter.
#
#   Position 3:  IncludeEmbeddedEngines    (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Opt-in. Walk the filesystem for SQLite database files
#                (with size floor + magic-byte validation + hit cap).
#
#   Position 4:  EmbeddedPaths             (String, Default "")
#     Example:   /srv,/opt,/var/lib,/data
#     Purpose:   Comma-separated directories to scan when
#                IncludeEmbeddedEngines=Yes. Empty uses built-in defaults.
#                Always excluded regardless: /proc, /sys, /dev, /tmp.
#
#   Position 5:  SkipNetwork               (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   Skip listening-socket enumeration (ss -lntp).
#
#   Position 6:  DryRun                    (String, Default "No")
#     Allowed:   Yes | No | True | False | 1 | 0 | On | Off
#     Purpose:   With DeepProbe=Yes, list which instances WOULD be probed
#                WITHOUT opening any connection.
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
#     Example:   /var/log/database-inventory
#     Purpose:   Override default output dir. Empty uses the default
#                (/var/log/database-inventory).
#
# ==============================================================================
# QUALYS CAR SETUP GUIDE (first-time deployment):
# ==============================================================================
#
#   1. Sign in to Qualys Cloud Platform.
#   2. Custom Assessment and Remediation -> Scripts -> New Script.
#   3. Script Details tab:
#        Name:        Database Inventory (Linux)
#        Platform:    Linux
#        Interpreter: Bash (shebang /usr/bin/env bash in the script)
#        Upload:      get-database-inventory.sh
#   4. Parameters tab (ORDER MATTERS - positional). Add 9 parameters in
#      the order listed above, each as type String with the documented
#      default.
#   5. Save. Output is captured by the Qualys Cloud Agent plus written to
#      /var/log/database-inventory/ (override via OutputPath).
#   6. FIRST FLEET RUN: keep DeepProbe=No and IncludeAdLookup=No to
#      confirm baseline discovery across representative hosts before
#      enabling opt-in probes.
#
# CLI INVOCATION (local testing):
#   sudo ./get-database-inventory.sh                                        # defaults
#   sudo ./get-database-inventory.sh Yes No No "" No No 1 No ""             # DeepProbe only
#   sudo ./get-database-inventory.sh Yes Yes Yes "/opt" No No 3 Yes "/tmp/dbinv"
#
# CAR INVOKES EQUIVALENT TO:
#   /bin/bash get-database-inventory.sh "<DeepProbe>" "<IncludeAdLookup>" \
#       "<IncludeEmbeddedEngines>" "<EmbeddedPaths>" "<SkipNetwork>" \
#       "<DryRun>" "<Retain>" "<JsonOnly>" "<OutputPath>"
#
# DUAL-INVOCATION FALLBACK:
#   Positional args win. Empty positional falls back to same-named env
#   vars (DEEP_PROBE, INCLUDE_AD_LOOKUP, INCLUDE_EMBEDDED, EMBEDDED_PATHS,
#   SKIP_NETWORK, DRY_RUN, RETAIN, JSON_ONLY, OUTPUT_PATH). Defaults last.
#   Legacy named flags (--deep-probe, --include-ad-lookup, etc.) are
#   still recognized anywhere in the arg list for local testing.
#
# Exit Codes:
#   0  = Scan completed cleanly
#   1  = Scan completed with collection warnings
#   2  = Must be run as root
#
# Backlog (databases to consider adding in future versions):
#   - LevelDB / RocksDB - intentionally skipped. These are *embedded library*
#     KV engines (not servers), have no network port and no authentication,
#     and ship inside databases this script already detects (Cassandra,
#     InfluxDB, Elasticsearch, CockroachDB, Qdrant, TiKV, ...). To get useful
#     signal, detect the parent application instead and annotate its storage
#     engine in that record.
#   - Application-tier NoSQL (Qdrant, TiKV, CockroachDB, Pilosa, etc.).
#   - Oracle Autonomous / managed-service endpoints (via connection strings
#     found on the host).
#
# Changelog:
#   3.0.0 - 2026-04-20 - CAR parameterization refactor. Replaces named
#                        flag parsing with 9 POSITIONAL string parameters
#                        consumable by Qualys CAR UI. Dual-invocation
#                        support: positional first, env fallback, defaults
#                        last. Legacy named flags still recognized.
#                        ASCII-only log output.
#   2.0.0 - 2026-04-14 - Backlog-engine expansion:
#                        + Tier 1 services: etcd, Consul, Memcached,
#                          Prometheus, H2/HSQLDB/Derby (server mode).
#                        + Tier 2 filesystem-scan (opt-in, gated behind
#                          --include-embedded): SQLite.
#                        Tier 3 engines (LevelDB/RocksDB) intentionally
#                        skipped - see backlog note above.
#   1.0.0 - 2026-04-14 - Initial release. CAR-ready, hardened bash.
#
# Dependencies:
#   Required:  bash 4+, coreutils, awk, sed, ps, find (all universal).
#   Preferred: jq  (cleanest JSON manipulation; default on some distros).
#   Fallback:  python3 or python (shipped by default on RHEL 8+, Ubuntu
#              18.04+, SLES 15+, Amazon Linux 2+, Rocky/Alma 8+).
#   Detection order for JSON manipulation: jq -> python3 -> python -> manual.
#   Optional:  ss, netstat (socket enumeration - one is usually present)
#              systemctl    (service enumeration on systemd hosts)
#              rpm / dpkg   (package version where we query it)
#              ldapsearch   (AD enrichment via GSSAPI; otherwise getent used)
#              mysql / psql / mongosh  (deep-probe only; optional).
#   The script degrades gracefully when optional tools are missing.
#
# Safety:
#   - Read-only throughout. No writes to files, services, or databases.
#   - No outbound network connections except opt-in probes.
#   - Config files parsed read-only; password/secret values redacted.
# ==============================================================================

set -u
set -o pipefail

# ------------------------------------------------------------------------------
# TRUTHY HELPER (accepts Yes/No, True/False, 1/0, On/Off case-insensitive)
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
#
# Positional args (as supplied by CAR) win. Legacy named flags are still
# honored anywhere in the arg list for local testing. Empty positionals
# fall back to same-named env vars, then to built-in defaults.
# ------------------------------------------------------------------------------

# Pre-scan argv for legacy flag tokens (backward compat).
_RAW_DEEP=""
_RAW_AD=""
_RAW_EMBED=""
_RAW_EMBED_PATHS=""
_RAW_SKIPNET=""
_RAW_DRYRUN=""
_RAW_RETAIN=""
_RAW_JSONONLY=""
_RAW_OUTPUT=""

_i=0
_argv=("$@")
_argc=$#
while [ "${_i}" -lt "${_argc}" ]; do
    _arg="${_argv[${_i}]}"
    case "${_arg}" in
        --deep-probe)         _RAW_DEEP="Yes" ;;
        --include-ad-lookup)  _RAW_AD="Yes" ;;
        --include-embedded)   _RAW_EMBED="Yes" ;;
        --json-only)          _RAW_JSONONLY="Yes" ;;
        --skip-network)       _RAW_SKIPNET="Yes" ;;
        --dry-run)            _RAW_DRYRUN="Yes" ;;
        --output-path)        _i=$((_i + 1)); _RAW_OUTPUT="${_argv[${_i}]:-}" ;;
        --retain)             _i=$((_i + 1)); _RAW_RETAIN="${_argv[${_i}]:-}" ;;
        --embedded-paths)     _i=$((_i + 1)); _RAW_EMBED_PATHS="${_argv[${_i}]:-}" ;;
        -h|--help)
            sed -n '2,160p' "$0"
            exit 0
            ;;
    esac
    _i=$((_i + 1))
done

_pos_is_flag() {
    case "${1:-}" in
        --deep-probe|--include-ad-lookup|--include-embedded|--json-only| \
        --skip-network|--dry-run|--output-path|--retain|--embedded-paths|-h|--help)
            return 0 ;;
        *) return 1 ;;
    esac
}

# Apply positional args IF they aren't legacy flags. Order matches CAR UI:
# 1 DeepProbe  2 IncludeAdLookup  3 IncludeEmbeddedEngines  4 EmbeddedPaths
# 5 SkipNetwork 6 DryRun           7 Retain                  8 JsonOnly    9 OutputPath
if [ $# -ge 1 ] && ! _pos_is_flag "${1:-}"; then _RAW_DEEP="${1}"; fi
if [ $# -ge 2 ] && ! _pos_is_flag "${2:-}"; then _RAW_AD="${2}"; fi
if [ $# -ge 3 ] && ! _pos_is_flag "${3:-}"; then _RAW_EMBED="${3}"; fi
if [ $# -ge 4 ] && ! _pos_is_flag "${4:-}"; then _RAW_EMBED_PATHS="${4}"; fi
if [ $# -ge 5 ] && ! _pos_is_flag "${5:-}"; then _RAW_SKIPNET="${5}"; fi
if [ $# -ge 6 ] && ! _pos_is_flag "${6:-}"; then _RAW_DRYRUN="${6}"; fi
if [ $# -ge 7 ] && ! _pos_is_flag "${7:-}"; then _RAW_RETAIN="${7}"; fi
if [ $# -ge 8 ] && ! _pos_is_flag "${8:-}"; then _RAW_JSONONLY="${8}"; fi
if [ $# -ge 9 ] && ! _pos_is_flag "${9:-}"; then _RAW_OUTPUT="${9}"; fi

# Positional -> env -> default. Booleans go through car_truthy.
_DEEPSTR="${_RAW_DEEP:-${DEEP_PROBE:-No}}"
_ADSTR="${_RAW_AD:-${INCLUDE_AD_LOOKUP:-No}}"
_EMBEDSTR="${_RAW_EMBED:-${INCLUDE_EMBEDDED:-No}}"
_SKIPSTR="${_RAW_SKIPNET:-${SKIP_NETWORK:-No}}"
_DRYSTR="${_RAW_DRYRUN:-${DRY_RUN:-No}}"
_JSONSTR="${_RAW_JSONONLY:-${JSON_ONLY:-No}}"
EMBEDDED_PATHS="${_RAW_EMBED_PATHS:-${EMBEDDED_PATHS:-}}"
OUTPUT_PATH="${_RAW_OUTPUT:-${OUTPUT_PATH:-}}"
RETAIN="${_RAW_RETAIN:-${RETAIN:-1}}"

# Normalize into the 0/1 counters the rest of the script already uses.
DEEP_PROBE=0
INCLUDE_AD_LOOKUP=0
INCLUDE_EMBEDDED=0
SKIP_NETWORK=0
DRY_RUN=0
JSON_ONLY=0
if car_truthy "${_DEEPSTR}";   then DEEP_PROBE=1;        fi
if car_truthy "${_ADSTR}";     then INCLUDE_AD_LOOKUP=1; fi
if car_truthy "${_EMBEDSTR}";  then INCLUDE_EMBEDDED=1;  fi
if car_truthy "${_SKIPSTR}";   then SKIP_NETWORK=1;      fi
if car_truthy "${_DRYSTR}";    then DRY_RUN=1;           fi
if car_truthy "${_JSONSTR}";   then JSON_ONLY=1;         fi

# ------------------------------------------------------------------------------
# ROOT ENFORCEMENT
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root." >&2
    exit 2
fi

# ------------------------------------------------------------------------------
# GLOBALS / STATE
# ------------------------------------------------------------------------------
SCRIPT_NAME="get-database-inventory.sh"
SCRIPT_VERSION="3.0.0"
STAMP="$(date '+%Y%m%d_%H%M%S')"
STARTED_AT="$(date '+%Y-%m-%dT%H:%M:%S%z')"
START_EPOCH="$(date +%s)"

if [ -z "${OUTPUT_PATH}" ]; then
    OUTPUT_PATH="/var/log/database-inventory"
fi
if ! [[ "${RETAIN}" =~ ^[0-9]+$ ]] || [ "${RETAIN}" -lt 1 ]; then
    RETAIN=1
fi

LOG_FILE="${OUTPUT_PATH}/inventory_${STAMP}.log"
JSON_FILE="${OUTPUT_PATH}/inventory_${STAMP}.json"

mkdir -p "${OUTPUT_PATH}"

COUNT_WARNINGS=0
COUNT_ERRORS=0

# Instance records are accumulated as a newline-delimited pseudo-array of
# JSON objects stored in a tempfile. Final JSON assembly happens at exit.
INSTANCES_FILE="$(mktemp /tmp/dbinv-instances.XXXXXX.ndjson)"
WARNINGS_FILE="$(mktemp /tmp/dbinv-warnings.XXXXXX.txt)"
ERRORS_FILE="$(mktemp /tmp/dbinv-errors.XXXXXX.txt)"
trap 'rm -f "${INSTANCES_FILE}" "${WARNINGS_FILE}" "${ERRORS_FILE}"' EXIT

# Capability detection
HAS_SS=0;       command -v ss >/dev/null 2>&1           && HAS_SS=1
HAS_NETSTAT=0;  command -v netstat >/dev/null 2>&1      && HAS_NETSTAT=1
HAS_SYSTEMCTL=0;command -v systemctl >/dev/null 2>&1    && HAS_SYSTEMCTL=1
HAS_JQ=0;       command -v jq >/dev/null 2>&1           && HAS_JQ=1
HAS_RPM=0;      command -v rpm >/dev/null 2>&1          && HAS_RPM=1
HAS_DPKG=0;     command -v dpkg-query >/dev/null 2>&1   && HAS_DPKG=1
HAS_LDAPSEARCH=0;command -v ldapsearch >/dev/null 2>&1  && HAS_LDAPSEARCH=1
HAS_MYSQL=0;    command -v mysql >/dev/null 2>&1        && HAS_MYSQL=1
HAS_PSQL=0;     command -v psql >/dev/null 2>&1         && HAS_PSQL=1
HAS_REDIS_CLI=0;command -v redis-cli >/dev/null 2>&1    && HAS_REDIS_CLI=1
HAS_MONGOSH=0;  command -v mongosh >/dev/null 2>&1      && HAS_MONGOSH=1

# Python fallback for JSON manipulation when jq is absent.
# Python 3 is installed by default on all modern enterprise Linux distros
# (RHEL 8+, Ubuntu 18.04+, SLES 15+, Amazon Linux 2+), with json in stdlib.
PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
fi
HAS_PY=0
[ -n "${PY_BIN}" ] && HAS_PY=1

# ------------------------------------------------------------------------------
# LOGGING HELPERS
# ------------------------------------------------------------------------------
_log_line() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local line
    line="${ts}  [${level}]  $*"
    # Write to log file always; honor --json-only for stdout suppression
    printf '%s\n' "${line}" >>"${LOG_FILE}"
    if [ "${JSON_ONLY}" -eq 0 ]; then
        printf '%s\n' "${line}"
    fi
}
log()      { _log_line "INFO " "$@"; }
log_ok()   { _log_line "OK   " "$@"; }
log_warn() { _log_line "WARN " "$@"; COUNT_WARNINGS=$((COUNT_WARNINGS + 1)); echo "$*" >>"${WARNINGS_FILE}"; }
log_err()  { _log_line "ERROR" "$@"; COUNT_ERRORS=$((COUNT_ERRORS + 1));     echo "$*" >>"${ERRORS_FILE}"; }
log_find() { _log_line "FIND " "$@"; }
log_skip() { _log_line "--   " "$@"; }

# ------------------------------------------------------------------------------
# CLEANUP (retention of prior run output)
# ------------------------------------------------------------------------------
cleanup_prior_runs() {
    local keep=$((RETAIN - 1))
    if [ "${keep}" -lt 0 ]; then keep=0; fi
    local f
    # Sort descending (newest first); skip the top $keep; delete the rest.
    local files=()
    while IFS= read -r f; do
        [ -n "${f}" ] && files+=("${f}")
    done < <(find "${OUTPUT_PATH}" -maxdepth 1 -type f \( -name 'inventory_*.log' -o -name 'inventory_*.json' \) -printf '%f\n' 2>/dev/null | sort -r)
    local i=0
    for f in "${files[@]}"; do
        if [ "${i}" -lt "${keep}" ]; then
            i=$((i + 1))
            continue
        fi
        if rm -f "${OUTPUT_PATH}/${f}" 2>/dev/null; then
            log_skip "Cleaned old output: ${f}"
        else
            log_warn "Failed to remove old output: ${f}"
        fi
    done
}

# ------------------------------------------------------------------------------
# JSON HELPERS
# ------------------------------------------------------------------------------
# Escape a single string for inclusion inside JSON double-quotes.
# Handles: backslash, double quote, backspace, form-feed, newline, carriage
# return, tab, and control characters U+0000-U+001F.
json_escape() {
    local s="${1-}"
    # Replace backslash first
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    # Use printf %q? Too aggressive. Do manual control-char replacement.
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "${s}"
}

# Emit a JSON string literal (quoted, escaped) or "null" if empty and $2 != keep
json_str() {
    local v="${1-}"
    if [ -z "${v}" ]; then
        printf 'null'
    else
        printf '"%s"' "$(json_escape "${v}")"
    fi
}

# Emit a raw value suitable for JSON numbers/booleans/null; fall back to null
json_raw_or_null() {
    local v="${1-}"
    if [ -z "${v}" ]; then
        printf 'null'
    else
        printf '%s' "${v}"
    fi
}

# Emit a JSON array of strings from a newline-delimited input (stdin)
json_str_array_from_stdin() {
    local first=1
    printf '['
    local line
    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        if [ "${first}" -eq 1 ]; then
            first=0
        else
            printf ','
        fi
        printf '"%s"' "$(json_escape "${line}")"
    done
    printf ']'
}

# Append one JSON object (passed via stdin) as a single line to INSTANCES_FILE.
append_instance() {
    tr -d '\n' >>"${INSTANCES_FILE}"
    printf '\n' >>"${INSTANCES_FILE}"
}

# Merge a value into a single-line JSON document at a top-level key.
# Usage: json_merge_line <input_json> <top_level_key> <value_json>
# Returns the modified JSON line on stdout.
# Prefers jq; falls back to python3/python; if neither is available, returns
# input unchanged and logs a warning once per session.
_JSON_MERGE_WARNED=0

# Python helper script as a here-doc-free string (so we can pipe stdin).
_PY_MERGE='
import json, sys
key = sys.argv[1]
val = json.loads(sys.argv[2])
doc = json.loads(sys.stdin.read())
doc[key] = val
print(json.dumps(doc))
'
_PY_EXTRACT='
import json, sys
k = sys.argv[1]
try:
    doc = json.loads(sys.stdin.read())
    v = doc
    for part in k.split("."):
        v = v.get(part, "") if isinstance(v, dict) else ""
    print(v if v is not None else "")
except Exception:
    print("")
'
_PY_PRETTY='
import json, sys
doc = json.loads(sys.stdin.read())
print(json.dumps(doc, indent=2))
'
_PY_COUNT_BY_PRODUCT='
import json, sys
counts = {}
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        obj = json.loads(line)
        p = obj.get("product", "")
        counts[p] = counts.get(p, 0) + 1
    except Exception:
        pass
print(json.dumps(counts))
'
_PY_WRAP_NDJSON='
import json, sys
out = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        out.append(json.loads(line))
    except Exception:
        pass
print(json.dumps(out))
'

json_merge_line() {
    local input="$1" key="$2" value="$3"
    if [ "${HAS_JQ}" -eq 1 ]; then
        printf '%s' "${input}" | jq --argjson v "${value}" ".${key} = \$v"
        return
    fi
    if [ "${HAS_PY}" -eq 1 ]; then
        printf '%s' "${input}" | "${PY_BIN}" -c "${_PY_MERGE}" "${key}" "${value}"
        return
    fi
    if [ "${_JSON_MERGE_WARNED}" -eq 0 ]; then
        log_warn "Neither jq nor python available; deep-probe/AD results cannot be merged into JSON."
        _JSON_MERGE_WARNED=1
    fi
    printf '%s' "${input}"
}

# Extract a top-level (or dotted) string field from a single-line JSON document.
json_extract() {
    local input="$1" key="$2" default="${3-}"
    local out=""
    if [ "${HAS_JQ}" -eq 1 ]; then
        out="$(printf '%s' "${input}" | jq -r ".${key} // \"\"")"
    elif [ "${HAS_PY}" -eq 1 ]; then
        out="$(printf '%s' "${input}" | "${PY_BIN}" -c "${_PY_EXTRACT}" "${key}")"
    else
        # Last-ditch regex - only works for simple top-level flat keys.
        out="$(printf '%s' "${input}" | sed -n "s/.*\"${key##*.}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n1)"
    fi
    if [ -z "${out}" ]; then out="${default}"; fi
    printf '%s' "${out}"
}

# Build an ldap/AD lookup JSON object from name=value pairs on stdin (one per line).
# Input format: key=value (string values only; missing = empty string)
# Output: one JSON object on stdout.
json_object_from_kv_stdin() {
    if [ "${HAS_JQ}" -eq 1 ]; then
        jq -Rn '[inputs | select(length>0) | split("=") | {(.[0]): (.[1:] | join("="))}] | add // {}'
        return
    fi
    if [ "${HAS_PY}" -eq 1 ]; then
        "${PY_BIN}" -c '
import json, sys
obj = {}
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line or "=" not in line: continue
    k, _, v = line.partition("=")
    obj[k] = v
print(json.dumps(obj))
'
        return
    fi
    # Manual fallback: build JSON via printf + json_escape.
    local first=1 line k v
    printf '{'
    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        k="${line%%=*}"
        v="${line#*=}"
        if [ "${first}" -eq 1 ]; then first=0; else printf ','; fi
        printf '"%s":%s' "$(json_escape "${k}")" "$(json_str "${v}")"
    done
    printf '}'
}

# ------------------------------------------------------------------------------
# LOW-LEVEL HELPERS
# ------------------------------------------------------------------------------
# Read a file if it exists AND we can read it; echo to stdout. On failure the
# function emits nothing and increments the warning count.
read_safe() {
    local path="$1"
    if [ -r "${path}" ]; then
        cat -- "${path}" 2>/dev/null || true
    else
        if [ -e "${path}" ]; then
            log_warn "Config file not readable: ${path}"
        fi
    fi
}

# Redact lines containing secrets before logging.
redact_secrets() {
    sed -E 's/((^|[[:space:]])(password|passwd|pwd|secret|token|apikey|api[_-]?key|requirepass|connection[-_]?string|authentication_string)[[:space:]]*[:=][[:space:]]*).*/\1<REDACTED>/Ig'
}

# Classify a service account string as local_system / local_service /
# virtual_service / local_user / domain_user / unknown.
classify_linux_user() {
    local u="${1-}"
    if [ -z "${u}" ]; then
        printf 'unknown'
        return
    fi
    # Common DB service users
    case "${u}" in
        root)                                    printf 'root' ;;
        mysql|postgres|mongod|mongodb|redis|oracle|db2inst1|cassandra|elasticsearch|opensearch|couchdb|couchbase|neo4j|influxdb|clickhouse|_ase|sybase|informix|mssql)
            printf 'local_db_service'
            ;;
        *)
            if id -u "${u}" >/dev/null 2>&1; then
                # Domain-mapped accounts (sssd/winbind) usually contain @ or \
                if printf '%s' "${u}" | grep -qE '[@\\]'; then
                    printf 'domain_user'
                else
                    printf 'local_user'
                fi
            else
                printf 'unknown'
            fi
            ;;
    esac
}

# ------------------------------------------------------------------------------
# HOST IDENTITY
# ------------------------------------------------------------------------------
HOST_HOSTNAME=""
HOST_FQDN=""
HOST_DOMAIN=""
HOST_DOMAIN_JOINED="false"
HOST_OS=""
HOST_OS_VERSION=""
HOST_IPS_FILE=""

collect_host_identity() {
    HOST_HOSTNAME="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
    HOST_FQDN="$(hostname -f 2>/dev/null || echo "${HOST_HOSTNAME}")"
    HOST_DOMAIN="$(hostname -d 2>/dev/null || true)"
    [ -z "${HOST_DOMAIN}" ] && HOST_DOMAIN="$(awk '/^domain|^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"

    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        HOST_OS="${PRETTY_NAME:-${NAME:-Linux}}"
        HOST_OS_VERSION="${VERSION_ID:-}"
    else
        HOST_OS="$(uname -sr)"
    fi

    # Domain-joined hint: realm list (sssd), or Kerberos keytab, or winbind
    if command -v realm >/dev/null 2>&1 && realm list 2>/dev/null | grep -q '.'; then
        HOST_DOMAIN_JOINED="true"
    elif [ -s /etc/krb5.keytab ] 2>/dev/null; then
        HOST_DOMAIN_JOINED="true"
    elif pgrep -x winbindd >/dev/null 2>&1 || pgrep -x sssd >/dev/null 2>&1; then
        HOST_DOMAIN_JOINED="true"
    fi

    HOST_IPS_FILE="$(mktemp /tmp/dbinv-ips.XXXXXX.txt)"
    # Prefer `ip -o addr` (always present on modern systemd Linux). Fall back to ifconfig.
    if command -v ip >/dev/null 2>&1; then
        # Format: <iface>|<address>|<family>
        ip -o addr show 2>/dev/null | awk '{
            iface=$2; fam=$3; ip=$4;
            sub(/\/.*/, "", ip);
            f="v4"; if (fam ~ /inet6/) f="v6";
            printf "%s|%s|%s\n", iface, ip, f;
        }' >>"${HOST_IPS_FILE}"
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig 2>/dev/null | awk '
            /^[a-zA-Z0-9]/ { iface=$1; sub(/:$/, "", iface) }
            /inet / { printf "%s|%s|v4\n", iface, $2 }
            /inet6 / { printf "%s|%s|v6\n", iface, $2 }
        ' >>"${HOST_IPS_FILE}"
    fi
}

# ------------------------------------------------------------------------------
# SERVICE / PROCESS / SOCKET ENUMERATION
# ------------------------------------------------------------------------------
# These are populated once at startup; each product discovery function greps
# the file for its pattern.
SERVICES_FILE=""
PROCESSES_FILE=""
LISTEN_FILE=""

collect_services() {
    SERVICES_FILE="$(mktemp /tmp/dbinv-svcs.XXXXXX.txt)"
    # Format: <unit>|<state>|<description>
    if [ "${HAS_SYSTEMCTL}" -eq 1 ]; then
        systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null \
            | awk '{
                unit=$1; sub(/\.service$/, "", unit);
                state=$3;
                desc=""; for (i=5;i<=NF;i++) { desc=desc $i " " }
                sub(/ +$/, "", desc);
                printf "%s|%s|%s\n", unit, state, desc;
            }' >>"${SERVICES_FILE}"
    fi
    # Also try to detect non-systemd init (sysvinit on older distros)
    if [ "${HAS_SYSTEMCTL}" -eq 0 ] && [ -d /etc/init.d ]; then
        find /etc/init.d -maxdepth 1 -type f -executable -printf '%f\n' 2>/dev/null \
            | awk '{ printf "%s|unknown|sysvinit\n", $1 }' >>"${SERVICES_FILE}"
    fi
}

collect_processes() {
    PROCESSES_FILE="$(mktemp /tmp/dbinv-procs.XXXXXX.txt)"
    # Format: <user>|<pid>|<ppid>|<comm>|<args>
    ps -eo user=,pid=,ppid=,comm=,args= 2>/dev/null \
        | awk '{
            user=$1; pid=$2; ppid=$3; comm=$4;
            args=""; for (i=5;i<=NF;i++) { args=args $i " " }
            sub(/ +$/, "", args);
            gsub(/\|/, "_", comm);   # guard the delimiter
            gsub(/\|/, "_", args);
            printf "%s|%s|%s|%s|%s\n", user, pid, ppid, comm, args;
        }' >>"${PROCESSES_FILE}"
}

collect_listen() {
    LISTEN_FILE="$(mktemp /tmp/dbinv-listen.XXXXXX.txt)"
    if [ "${SKIP_NETWORK}" -eq 1 ]; then
        return
    fi
    # Format: <proto>|<local_ip>|<local_port>|<pid>
    if [ "${HAS_SS}" -eq 1 ]; then
        # ss -H -tlnp -> "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=1234,fd=3))"
        ss -H -tlnp 2>/dev/null | awk '{
            laddr=$4;
            proto="tcp";
            pid="";
            for (i=1;i<=NF;i++) {
                if ($i ~ /users:/) {
                    match($i, /pid=[0-9]+/);
                    if (RSTART>0) { pid=substr($i, RSTART+4, RLENGTH-4) }
                }
            }
            n=split(laddr, parts, ":");
            port=parts[n];
            ip=laddr; sub(":" port "$", "", ip);
            gsub(/^\[|\]$/, "", ip);
            printf "%s|%s|%s|%s\n", proto, ip, port, pid;
        }' >>"${LISTEN_FILE}"
    elif [ "${HAS_NETSTAT}" -eq 1 ]; then
        netstat -lntp 2>/dev/null | awk 'NR>2 {
            proto="tcp"; laddr=$4; proginfo=$7;
            n=split(laddr, parts, ":");
            port=parts[n];
            ip=laddr; sub(":" port "$", "", ip);
            pid=""; split(proginfo, p, "/");
            if (p[1] ~ /^[0-9]+$/) { pid=p[1] }
            printf "%s|%s|%s|%s\n", proto, ip, port, pid;
        }' >>"${LISTEN_FILE}"
    else
        log_warn "Neither ss nor netstat available; listening-socket map will be empty."
    fi
}

# Look up listening sockets for a given PID in LISTEN_FILE.
# Usage: listen_for_pid <pid> -> lines of "<proto>|<ip>|<port>|<pid>"
listen_for_pid() {
    local want="$1"
    [ -z "${want}" ] && return 0
    awk -F'|' -v want="${want}" '$4==want' "${LISTEN_FILE}" 2>/dev/null
}

# Look up a service by regex in SERVICES_FILE. Usage: match_services <regex>
match_services() {
    local re="$1"
    awk -F'|' -v re="${re}" '$1 ~ re' "${SERVICES_FILE}" 2>/dev/null
}

# Look up processes by regex against comm OR args.
match_processes() {
    local re="$1"
    awk -F'|' -v re="${re}" '$4 ~ re || $5 ~ re' "${PROCESSES_FILE}" 2>/dev/null
}

# ------------------------------------------------------------------------------
# INSTANCE RECORD BUILDER
# ------------------------------------------------------------------------------
INST_PRODUCT=""; INST_VENDOR=""; INST_EDITION=""; INST_VERSION=""; INST_PATCH=""
INST_NAME=""; INST_ID=""; INST_INSTALL=""; INST_DATA=""
INST_DB_METHOD="none"
INST_AUTH_MODE=""; INST_AUTH_SOURCE=""
INST_AUTH_INT="false"; INST_AUTH_AD="false"
INST_TLS_ENABLED="null"; INST_TLS_FORCE="null"; INST_TLS_CERT=""
INST_SVC_NAME=""; INST_SVC_DISPLAY=""; INST_SVC_STATE=""; INST_SVC_EXEC=""
INST_SVC_ACCT=""; INST_SVC_ACCT_TYPE=""
INST_DBS_FILE=""; INST_LISTEN_FILE=""; INST_CFG_FILE=""
INST_AUTH_DETAIL_FILE=""; INST_NOTES_FILE=""; INST_WARN_FILE=""
INST_PROC_FILE=""; INST_SPN_FILE=""

init_instance() {
    INST_PRODUCT="${1-}"
    INST_VENDOR="${2-}"
    INST_EDITION=""; INST_VERSION=""; INST_PATCH=""
    INST_NAME=""; INST_ID=""; INST_INSTALL=""; INST_DATA=""
    INST_DB_METHOD="none"
    INST_AUTH_MODE=""; INST_AUTH_SOURCE=""
    INST_AUTH_INT="false"; INST_AUTH_AD="false"
    INST_TLS_ENABLED="null"; INST_TLS_FORCE="null"; INST_TLS_CERT=""
    INST_SVC_NAME=""; INST_SVC_DISPLAY=""; INST_SVC_STATE=""; INST_SVC_EXEC=""
    INST_SVC_ACCT=""; INST_SVC_ACCT_TYPE=""
    INST_DBS_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_LISTEN_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_CFG_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_AUTH_DETAIL_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_NOTES_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_WARN_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_PROC_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
    INST_SPN_FILE="$(mktemp /tmp/dbinv-i.XXXXXX)"
}

add_database()     { printf '%s\n' "$1" >>"${INST_DBS_FILE}"; }
add_listen()       {
    # args: proto ip port source
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"${INST_LISTEN_FILE}"
}
add_config_path()  { printf '%s\n' "$1" >>"${INST_CFG_FILE}"; }
add_auth_detail()  { printf '%s\n' "$1" >>"${INST_AUTH_DETAIL_FILE}"; }
add_inst_note()    { printf '%s\n' "$1" >>"${INST_NOTES_FILE}"; }
add_inst_warn()    { printf '%s\n' "$1" >>"${INST_WARN_FILE}"; }
add_inst_proc()    {
    # args: pid comm args user
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"${INST_PROC_FILE}"
}

# Attach process + listen information for a given PID to the current instance.
attach_pid() {
    local pid="$1"
    [ -z "${pid}" ] && return 0
    local row comm args user
    row="$(awk -F'|' -v pid="${pid}" '$2==pid {print}' "${PROCESSES_FILE}" 2>/dev/null | head -n1)"
    if [ -n "${row}" ]; then
        user="$(printf '%s' "${row}" | cut -d'|' -f1)"
        comm="$(printf '%s' "${row}" | cut -d'|' -f4)"
        args="$(printf '%s' "${row}" | cut -d'|' -f5)"
        add_inst_proc "${pid}" "${comm}" "${args}" "${user}"
        # If no service account yet and proc owner is known, use that
        [ -z "${INST_SVC_ACCT}" ] && INST_SVC_ACCT="${user}"
        [ -z "${INST_SVC_ACCT_TYPE}" ] && INST_SVC_ACCT_TYPE="$(classify_linux_user "${user}")"
    fi
    listen_for_pid "${pid}" | while IFS='|' read -r proto ip port _pid; do
        [ -n "${port}" ] && printf '%s|%s|%s|%s\n' "${proto}" "${ip}" "${port}" "live_socket" >>"${INST_LISTEN_FILE}"
    done
}

# Serialize the current instance as one JSON line into INSTANCES_FILE.
emit_instance() {
    local tmp
    tmp="$(mktemp /tmp/dbinv-emit.XXXXXX)"
    {
        printf '{'
        printf '"product":%s,'               "$(json_str "${INST_PRODUCT}")"
        printf '"vendor":%s,'                "$(json_str "${INST_VENDOR}")"
        printf '"edition":%s,'               "$(json_str "${INST_EDITION}")"
        printf '"version":%s,'               "$(json_str "${INST_VERSION}")"
        printf '"patch_level":%s,'           "$(json_str "${INST_PATCH}")"
        printf '"instance_name":%s,'         "$(json_str "${INST_NAME}")"
        printf '"instance_id":%s,'           "$(json_str "${INST_ID}")"
        printf '"install_path":%s,'          "$(json_str "${INST_INSTALL}")"
        printf '"data_path":%s,'             "$(json_str "${INST_DATA}")"

        printf '"config_paths":'
        json_str_array_from_stdin <"${INST_CFG_FILE}"
        printf ','

        # service object
        printf '"service":'
        if [ -n "${INST_SVC_NAME}${INST_SVC_ACCT}" ]; then
            printf '{"name":%s,"display_name":%s,"state":%s,"executable":%s,"account":%s,"account_type":%s}' \
                "$(json_str "${INST_SVC_NAME}")" \
                "$(json_str "${INST_SVC_DISPLAY}")" \
                "$(json_str "${INST_SVC_STATE}")" \
                "$(json_str "${INST_SVC_EXEC}")" \
                "$(json_str "${INST_SVC_ACCT}")" \
                "$(json_str "${INST_SVC_ACCT_TYPE}")"
        else
            printf 'null'
        fi
        printf ','

        # processes array
        printf '"processes":['
        local first=1 prow
        while IFS='|' read -r p_pid p_comm p_args p_user; do
            [ -z "${p_pid}" ] && continue
            if [ "${first}" -eq 1 ]; then first=0; else printf ','; fi
            printf '{"pid":%s,"name":%s,"args":%s,"owner":%s}' \
                "${p_pid}" \
                "$(json_str "${p_comm}")" \
                "$(json_str "${p_args}")" \
                "$(json_str "${p_user}")"
        done <"${INST_PROC_FILE}"
        printf '],'

        # listen array
        printf '"listen":['
        first=1
        while IFS='|' read -r l_proto l_ip l_port l_src; do
            [ -z "${l_port}" ] && continue
            if [ "${first}" -eq 1 ]; then first=0; else printf ','; fi
            printf '{"protocol":%s,"local_ip":%s,"local_port":%s,"source":%s}' \
                "$(json_str "${l_proto}")" \
                "$(json_str "${l_ip}")" \
                "${l_port}" \
                "$(json_str "${l_src}")"
        done <"${INST_LISTEN_FILE}"
        printf '],'

        # databases array
        printf '"databases":'
        json_str_array_from_stdin <"${INST_DBS_FILE}"
        printf ','
        printf '"database_enumeration_method":%s,' "$(json_str "${INST_DB_METHOD}")"

        # authentication
        printf '"authentication":{'
        printf '"mode":%s,"source":%s,"integrated_auth":%s,"ad_integrated":%s,"details":' \
            "$(json_str "${INST_AUTH_MODE}")" \
            "$(json_str "${INST_AUTH_SOURCE}")" \
            "${INST_AUTH_INT}" \
            "${INST_AUTH_AD}"
        json_str_array_from_stdin <"${INST_AUTH_DETAIL_FILE}"
        printf '},'

        # spns
        printf '"spns":'
        json_str_array_from_stdin <"${INST_SPN_FILE}"
        printf ','

        # tls
        printf '"tls":{"enabled":%s,"force_encryption":%s,"cert_thumbprint":%s},' \
            "${INST_TLS_ENABLED}" \
            "${INST_TLS_FORCE}" \
            "$(json_str "${INST_TLS_CERT}")"

        # notes + warnings
        printf '"notes":'
        json_str_array_from_stdin <"${INST_NOTES_FILE}"
        printf ','
        printf '"collection_warnings":'
        json_str_array_from_stdin <"${INST_WARN_FILE}"

        printf '}'
    } >"${tmp}"
    cat "${tmp}" | append_instance
    rm -f "${tmp}" \
        "${INST_DBS_FILE}" "${INST_LISTEN_FILE}" "${INST_CFG_FILE}" \
        "${INST_AUTH_DETAIL_FILE}" "${INST_NOTES_FILE}" "${INST_WARN_FILE}" \
        "${INST_PROC_FILE}" "${INST_SPN_FILE}"
    log_find "Instance recorded: ${INST_PRODUCT} / ${INST_NAME:-(default)}"
}

# ==============================================================================
# PER-PRODUCT DISCOVERY FUNCTIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# MYSQL / MARIADB / PERCONA
# ------------------------------------------------------------------------------
discover_mysql_family() {
    # Match service units
    local svc_row svc_name svc_state
    local found=0
    # Unique service names matching mysql-ish
    local svc_names
    svc_names="$(match_services '^(mysql|mysqld|mariadb|mariadbd|percona-server)$' | cut -d'|' -f1 | sort -u)"
    # Also consider a bare process match if no service unit exists
    local procs
    procs="$(match_processes '(^mysqld$|/mysqld( |$))')"

    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        log_skip "No MySQL / MariaDB / Percona instance detected."
        return
    fi

    # Determine product label from service name or binary path
    local label="MySQL" vendor="Oracle"
    if printf '%s' "${svc_names}${procs}" | grep -qiE 'mariadb'; then
        label="MariaDB"; vendor="MariaDB"
    elif printf '%s' "${svc_names}${procs}" | grep -qiE 'percona'; then
        label="Percona Server"; vendor="Percona"
    fi

    init_instance "${label}" "${vendor}"

    # Pick the first matching service unit (there is typically only one)
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi

    # Locate the running mysqld process (if any) to get owner and listen ports
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    # Find the active defaults-file. Prefer what's on the process command line;
    # fall back to standard Linux locations.
    local cfgpath=""
    if [ -n "${procs}" ]; then
        cfgpath="$(printf '%s\n' "${procs}" | head -n1 | awk -F'|' '{print $5}' \
                  | grep -oE -- '--defaults-file=[^ ]+' | head -n1 | sed 's/^--defaults-file=//')"
    fi
    if [ -z "${cfgpath}" ]; then
        for c in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mysql.conf.d/mysqld.cnf; do
            if [ -r "${c}" ]; then cfgpath="${c}"; break; fi
        done
    fi

    if [ -n "${cfgpath}" ] && [ -r "${cfgpath}" ]; then
        add_config_path "${cfgpath}"
        local cfg
        cfg="$(read_safe "${cfgpath}")"

        # Collect effective port and datadir across the [mysqld] section of main file plus included fragments.
        # For simplicity we scan the main file only (most distros put everything there or include via !includedir).
        local port datadir
        port="$(printf '%s\n' "${cfg}"    | awk -F'[= ]+' '/^[[:space:]]*port[[:space:]]*=/ {print $2; exit}')"
        datadir="$(printf '%s\n' "${cfg}" | awk -F'[= ]+' '/^[[:space:]]*datadir[[:space:]]*=/ {print $2; exit}' | tr -d '"')"

        if [ -n "${port}" ]; then add_listen "tcp" "(my.cnf)" "${port}" "my.cnf:port"; fi
        [ -n "${datadir}" ] && INST_DATA="${datadir}"

        # Authentication plugins
        local def_plugin plugin_load
        def_plugin="$(printf '%s\n' "${cfg}" | awk -F'[= ]+' '/^[[:space:]]*default[_-]authentication[_-]plugin[[:space:]]*=/ {print $2; exit}')"
        plugin_load="$(printf '%s\n' "${cfg}" | grep -iE '^[[:space:]]*plugin[_-]load(_add)?[[:space:]]*=')"

        [ -n "${def_plugin}" ] && add_auth_detail "default_authentication_plugin=${def_plugin}"
        while IFS= read -r line; do
            [ -z "${line}" ] && continue
            add_auth_detail "$(printf '%s' "${line}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        done <<<"${plugin_load}"

        if printf '%s' "${cfg}" | grep -qi 'authentication_ldap'; then
            INST_AUTH_MODE="LDAP (authentication_ldap_* plugin)"
            INST_AUTH_AD="true"
        elif printf '%s' "${cfg}" | grep -qiE 'auth[_-]pam|authentication_pam'; then
            INST_AUTH_MODE="PAM"
        elif [ -n "${def_plugin}" ]; then
            INST_AUTH_MODE="Native (${def_plugin})"
        else
            INST_AUTH_MODE="Native (default plugin not explicitly set)"
        fi
        INST_AUTH_SOURCE="${cfgpath}"
    else
        add_inst_warn "my.cnf not locatable; auth/port details incomplete"
    fi

    # Enumerate databases from datadir (each subdir is a database name)
    if [ -n "${INST_DATA}" ] && [ -d "${INST_DATA}" ]; then
        while IFS= read -r d; do
            [ -z "${d}" ] && continue
            case "${d}" in
                mysql|performance_schema|sys|information_schema) continue ;;
                \#*) continue ;;
            esac
            add_database "${d}"
        done < <(find "${INST_DATA}" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort)
        if [ -s "${INST_DBS_FILE}" ]; then INST_DB_METHOD="config_filesystem"; fi
    fi

    # Version
    if [ -x /usr/sbin/mysqld ] || [ -x /usr/bin/mysqld ]; then
        local bin
        bin="$(command -v mysqld || echo /usr/sbin/mysqld)"
        INST_VERSION="$("${bin}" --version 2>/dev/null | head -n1 | sed 's/.*Ver //; s/ for .*//')"
    fi

    emit_instance
    found=1
}

# ------------------------------------------------------------------------------
# POSTGRESQL (incl. Greenplum / EDB Postgres)
# ------------------------------------------------------------------------------
discover_postgres() {
    # Find postgres-related services and processes
    local svc_names
    svc_names="$(match_services '^(postgresql(-[0-9.]+)?|postgres(ql)?-primary|edb-as.*)$' | cut -d'|' -f1 | sort -u)"
    local procs
    procs="$(match_processes '(^postgres$|/postgres( |$)|postgres:)')"

    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        log_skip "No PostgreSQL instance detected."
        return
    fi

    # There can be multiple Postgres clusters on one host (postgresql@13-main etc.).
    # On Debian family, pg_lsclusters enumerates them; on RHEL family, /var/lib/pgsql/ contains data dirs.
    local clusters_file
    clusters_file="$(mktemp /tmp/dbinv-pg-clusters.XXXXXX)"

    if command -v pg_lsclusters >/dev/null 2>&1; then
        # Format: <version> <cluster> <port> <status> <owner> <data dir> <log>
        pg_lsclusters --no-header 2>/dev/null | awk '{ printf "%s|%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5, $6 }' >>"${clusters_file}"
    else
        # RHEL family / source installs - scan likely data-dir parents.
        for base in /var/lib/pgsql /var/lib/postgresql; do
            [ -d "${base}" ] || continue
            # Look for directories containing PG_VERSION
            while IFS= read -r pgv; do
                [ -z "${pgv}" ] && continue
                local datadir ver
                datadir="$(dirname "${pgv}")"
                ver="$(tr -d '\n' <"${pgv}" 2>/dev/null || echo '')"
                printf '%s|main|0|unknown|postgres|%s\n' "${ver}" "${datadir}" >>"${clusters_file}"
            done < <(find "${base}" -maxdepth 4 -name PG_VERSION -type f 2>/dev/null)
        done
    fi

    if ! [ -s "${clusters_file}" ]; then
        # No discoverable data dirs, but service/process exists - emit a minimal record.
        init_instance "PostgreSQL" "PostgreSQL"
        local svc_name svc_row
        svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
        if [ -n "${svc_name}" ]; then
            svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
            INST_SVC_NAME="${svc_name}"
            INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
            INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
        fi
        local pid
        pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
        [ -n "${pid}" ] && attach_pid "${pid}"
        INST_AUTH_MODE="unknown (no data dir located for pg_hba.conf parse)"
        add_inst_warn "Could not locate any Postgres data directory"
        emit_instance
        rm -f "${clusters_file}"
        return
    fi

    while IFS='|' read -r ver cluster port state owner datadir _rest; do
        [ -z "${datadir}" ] && continue
        init_instance "PostgreSQL" "PostgreSQL"
        INST_VERSION="${ver}"
        INST_NAME="${cluster}"
        INST_ID="${ver}/${cluster}"
        INST_DATA="${datadir}"

        local cfg_dir
        cfg_dir="${datadir}"
        if [ -d "/etc/postgresql/${ver}/${cluster}" ]; then cfg_dir="/etc/postgresql/${ver}/${cluster}"; fi

        local pgconf="${cfg_dir}/postgresql.conf"
        local pghba="${cfg_dir}/pg_hba.conf"

        if [ -r "${pgconf}" ]; then
            add_config_path "${pgconf}"
            local content listen_addrs
            content="$(read_safe "${pgconf}")"
            local cfgport
            cfgport="$(printf '%s\n' "${content}" | awk -F'[= ]+' '/^[[:space:]]*port[[:space:]]*=/ {gsub(/[^0-9]/,"",$2); if ($2!="") {print $2; exit}}')"
            [ -n "${cfgport}" ] && add_listen "tcp" "(postgresql.conf)" "${cfgport}" "postgresql.conf:port"
            listen_addrs="$(printf '%s\n' "${content}" | awk -F"'" '/^[[:space:]]*listen_addresses[[:space:]]*=/ {print $2; exit}')"
            [ -n "${listen_addrs}" ] && add_inst_note "listen_addresses=${listen_addrs}"
            if printf '%s' "${content}" | grep -qiE '^[[:space:]]*ssl[[:space:]]*=[[:space:]]*(on|true)'; then
                INST_TLS_ENABLED="true"
            fi
        fi

        if [ -r "${pghba}" ]; then
            add_config_path "${pghba}"
            local methods
            methods="$(awk '
                /^[[:space:]]*#/ {next}
                /^[[:space:]]*$/ {next}
                {
                    type=$1; db=$2; user=$3;
                    if (type=="local") { method=$4 } else { method=$5 }
                    if (method!="") { print type "|" db "|" user "|" method }
                }' "${pghba}" 2>/dev/null)"
            local unique_methods
            unique_methods="$(printf '%s\n' "${methods}" | awk -F'|' '{print $4}' | sort -u | paste -sd ',' -)"
            if [ -n "${unique_methods}" ]; then
                INST_AUTH_MODE="pg_hba.conf: ${unique_methods}"
                INST_AUTH_SOURCE="${pghba}"
                if printf '%s' "${unique_methods}" | grep -q 'ldap'; then INST_AUTH_AD="true"; fi
                if printf '%s' "${unique_methods}" | grep -qE 'gss|sspi'; then INST_AUTH_AD="true"; INST_AUTH_INT="true"; fi
            fi
            while IFS= read -r line; do
                [ -z "${line}" ] && continue
                local t d u m
                t="$(printf '%s' "${line}" | cut -d'|' -f1)"
                d="$(printf '%s' "${line}" | cut -d'|' -f2)"
                u="$(printf '%s' "${line}" | cut -d'|' -f3)"
                m="$(printf '%s' "${line}" | cut -d'|' -f4)"
                add_auth_detail "type=${t} db=${d} user=${u} method=${m}"
            done <<<"${methods}"
        fi

        # Try to locate an actual running PID for this cluster and enrich
        # via attach_pid.
        local pg_pid
        pg_pid="$(pgrep -af "postgres.*${datadir}" 2>/dev/null | awk 'NR==1 {print $1}')"
        [ -n "${pg_pid}" ] && attach_pid "${pg_pid}"

        # Count OIDs in base/ as proxy for DB count (names require deep-probe)
        if [ -d "${datadir}/base" ]; then
            local oid_count
            oid_count="$(find "${datadir}/base" -maxdepth 1 -mindepth 1 -type d -printf '.' 2>/dev/null | wc -c)"
            add_inst_note "base/ contains ${oid_count} database OIDs (names require deep-probe)"
        fi

        emit_instance
    done <"${clusters_file}"

    rm -f "${clusters_file}"
}

# ------------------------------------------------------------------------------
# MONGODB
# ------------------------------------------------------------------------------
discover_mongodb() {
    local svc_names
    svc_names="$(match_services '^(mongod|mongodb)$' | cut -d'|' -f1 | sort -u)"
    local procs
    procs="$(match_processes '(^mongod$|/mongod( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        log_skip "No MongoDB instance detected."
        return
    fi

    init_instance "MongoDB" "MongoDB"

    local svc_name="" svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi

    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    # Locate config file. Prefer --config from cmdline, else /etc/mongod.conf
    local cfg=""
    if [ -n "${procs}" ]; then
        cfg="$(printf '%s\n' "${procs}" | head -n1 | awk -F'|' '{print $5}' \
               | grep -oE -- '(--config|-f)[= ]+[^ ]+' | head -n1 | awk '{print $NF}')"
    fi
    [ -z "${cfg}" ] && [ -r /etc/mongod.conf ] && cfg="/etc/mongod.conf"

    if [ -n "${cfg}" ] && [ -r "${cfg}" ]; then
        add_config_path "${cfg}"
        local content
        content="$(read_safe "${cfg}")"
        local port bindip dbpath authz
        port="$(printf '%s\n' "${content}" | awk '/^[[:space:]]*port[[:space:]]*:/ {gsub(/[^0-9]/,""); if ($0!="") {print; exit}}')"
        bindip="$(printf '%s\n' "${content}" | awk -F': *' '/^[[:space:]]*bindIp[[:space:]]*:/ {print $2; exit}')"
        dbpath="$(printf '%s\n' "${content}" | awk -F': *' '/^[[:space:]]*dbPath[[:space:]]*:/ {print $2; exit}' | tr -d '"')"
        authz="$(printf '%s\n' "${content}"  | awk -F': *' '/^[[:space:]]*authorization[[:space:]]*:/ {print $2; exit}')"

        [ -n "${port}" ]   && add_listen "tcp" "(mongod.conf)" "${port}" "mongod.conf:net.port"
        [ -n "${bindip}" ] && add_inst_note "net.bindIp=${bindip}"
        [ -n "${dbpath}" ] && INST_DATA="${dbpath}"

        if [ -n "${authz}" ]; then
            INST_AUTH_MODE="security.authorization=${authz}"
            INST_AUTH_SOURCE="${cfg}:security.authorization"
        fi
        if printf '%s' "${content}" | grep -qE '^[[:space:]]*ldap[[:space:]]*:'; then
            INST_AUTH_AD="true"
            [ -z "${INST_AUTH_MODE}" ] && INST_AUTH_MODE="LDAP (Enterprise)"
            add_auth_detail "security.ldap block present"
        fi
        local tlsmode
        tlsmode="$(printf '%s\n' "${content}" | awk -F': *' '/^[[:space:]]*mode[[:space:]]*:[[:space:]]*(requireTLS|preferTLS|allowTLS|disabled)/ {print $2; exit}')"
        if [ -n "${tlsmode}" ]; then
            if [ "${tlsmode}" = "disabled" ]; then INST_TLS_ENABLED="false"; else INST_TLS_ENABLED="true"; fi
            add_auth_detail "net.tls.mode=${tlsmode}"
        fi
    else
        add_inst_warn "/etc/mongod.conf not located; auth details incomplete"
    fi

    # Version
    if command -v mongod >/dev/null 2>&1; then
        INST_VERSION="$(mongod --version 2>/dev/null | awk '/db version/ {print $3; exit}')"
    fi

    add_inst_note "WiredTiger storage: DB names require deep-probe (listDatabases) - not inferred from filesystem."
    emit_instance
}

# ------------------------------------------------------------------------------
# REDIS
# ------------------------------------------------------------------------------
discover_redis() {
    local svc_names
    svc_names="$(match_services '^(redis(-server)?(@.+)?|valkey(-server)?)$' | cut -d'|' -f1 | sort -u)"
    local procs
    procs="$(match_processes '(^redis-server$|/redis-server( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        log_skip "No Redis / Valkey instance detected."
        return
    fi

    # Iterate over distinct services (redis@ instances can be many)
    local names
    if [ -n "${svc_names}" ]; then
        names="${svc_names}"
    else
        # derive from cmdline config paths
        names="default"
    fi

    local svc_name
    while IFS= read -r svc_name; do
        [ -z "${svc_name}" ] && continue
        init_instance "Redis" "Redis"
        INST_NAME="${svc_name}"
        INST_SVC_NAME="${svc_name}"
        local svc_row
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"

        # Attach matching process by matching the service name in args (best-effort)
        local pid
        pid="$(printf '%s\n' "${procs}" | head -n1 | awk -F'|' '{print $2}')"
        [ -n "${pid}" ] && attach_pid "${pid}"

        # Locate config
        local cfg=""
        if [ -n "${procs}" ]; then
            cfg="$(printf '%s\n' "${procs}" | head -n1 | awk -F'|' '{print $5}' | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.conf$/) {print $i; exit}}')"
        fi
        if [ -z "${cfg}" ]; then
            for c in "/etc/redis/${svc_name}.conf" /etc/redis/redis.conf /etc/redis.conf; do
                [ -r "${c}" ] && { cfg="${c}"; break; }
            done
        fi

        if [ -n "${cfg}" ] && [ -r "${cfg}" ]; then
            add_config_path "${cfg}"
            local content
            content="$(read_safe "${cfg}")"
            local port tlsport bind
            port="$(printf '%s\n' "${content}"    | awk '/^[[:space:]]*port[[:space:]]+/ {print $2; exit}')"
            tlsport="$(printf '%s\n' "${content}" | awk '/^[[:space:]]*tls-port[[:space:]]+/ {print $2; exit}')"
            bind="$(printf '%s\n' "${content}"    | awk -F'[[:space:]]+' '/^[[:space:]]*bind[[:space:]]+/ {sub(/^[[:space:]]*bind[[:space:]]+/, ""); print; exit}' "${cfg}" 2>/dev/null)"

            [ -n "${port}" ]    && add_listen "tcp"     "(redis.conf)" "${port}"    "redis.conf:port"
            [ -n "${tlsport}" ] && { INST_TLS_ENABLED="true"; add_listen "tcp-tls" "(redis.conf)" "${tlsport}" "redis.conf:tls-port"; }
            [ -n "${bind}" ]    && add_inst_note "bind=${bind}"

            if printf '%s\n' "${content}" | grep -qE '^[[:space:]]*requirepass[[:space:]]+'; then
                INST_AUTH_MODE="Password (requirepass)"
                INST_AUTH_SOURCE="${cfg}:requirepass"
            else
                INST_AUTH_MODE="No auth required (unless ACL file set)"
                INST_AUTH_SOURCE="${cfg}"
            fi
            local aclfile
            aclfile="$(printf '%s\n' "${content}" | awk '/^[[:space:]]*aclfile[[:space:]]+/ {print $2; exit}')"
            [ -n "${aclfile}" ] && add_auth_detail "aclfile=${aclfile}"
            while IFS= read -r uline; do
                [ -z "${uline}" ] && continue
                local uname
                uname="$(printf '%s' "${uline}" | awk '{print $2}')"
                [ -n "${uname}" ] && add_auth_detail "ACL user: ${uname}"
            done < <(printf '%s\n' "${content}" | awk '/^[[:space:]]*user[[:space:]]+/ {print}')
        else
            add_inst_warn "redis.conf not located; auth details incomplete"
        fi

        if command -v redis-server >/dev/null 2>&1; then
            INST_VERSION="$(redis-server --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^v=/) {sub(/^v=/,"",$i); print $i; exit}}')"
        fi
        add_inst_note "Redis exposes 16 numbered logical DBs (0-15) by default; not named."
        emit_instance
    done <<<"${names}"
}

# ------------------------------------------------------------------------------
# ORACLE DATABASE
# ------------------------------------------------------------------------------
discover_oracle() {
    local procs
    procs="$(match_processes '(^oracle[A-Z0-9]+$|^ora_|^tnslsnr$|/tnslsnr( |$))')"
    local oratab="/etc/oratab"
    if [ ! -r "${oratab}" ] && [ -z "${procs}" ]; then
        log_skip "No Oracle Database instance detected."
        return
    fi

    # Parse /etc/oratab: <SID>:<ORACLE_HOME>:<autostart>
    local sid oh
    if [ -r "${oratab}" ]; then
        while IFS=: read -r sid oh _rest; do
            case "${sid}" in ''|\#*) continue ;; esac
            [ -z "${sid}" ] && continue
            [ "${sid}" = "*" ] && continue

            init_instance "Oracle Database" "Oracle"
            INST_NAME="${sid}"
            INST_ID="${sid}"
            INST_INSTALL="${oh}"

            if [ -n "${oh}" ] && [ -d "${oh}/network/admin" ]; then
                local sqlnet="${oh}/network/admin/sqlnet.ora"
                local listener="${oh}/network/admin/listener.ora"
                local tns="${oh}/network/admin/tnsnames.ora"

                if [ -r "${sqlnet}" ]; then
                    add_config_path "${sqlnet}"
                    local auth_svc
                    auth_svc="$(grep -iE '^[[:space:]]*SQLNET\.AUTHENTICATION_SERVICES' "${sqlnet}" 2>/dev/null | sed -E 's/.*=[[:space:]]*\(([^)]*)\).*/\1/' | head -n1)"
                    if [ -n "${auth_svc}" ]; then
                        INST_AUTH_MODE="SQLNET.AUTHENTICATION_SERVICES=(${auth_svc})"
                        INST_AUTH_SOURCE="${sqlnet}"
                        if printf '%s' "${auth_svc}" | grep -qiE 'NTS|KERBEROS5'; then INST_AUTH_AD="true"; fi
                        if printf '%s' "${auth_svc}" | grep -qi 'NTS'; then INST_AUTH_INT="true"; fi
                    else
                        INST_AUTH_MODE="Default (OS authentication, password file)"
                        INST_AUTH_SOURCE="${sqlnet} (no SQLNET.AUTHENTICATION_SERVICES line)"
                    fi
                fi

                if [ -r "${listener}" ]; then
                    add_config_path "${listener}"
                    while IFS= read -r port_match; do
                        [ -n "${port_match}" ] && add_listen "tcp" "(listener.ora)" "${port_match}" "listener.ora"
                    done < <(grep -oE 'PORT[[:space:]]*=[[:space:]]*[0-9]+' "${listener}" 2>/dev/null | grep -oE '[0-9]+' | sort -u)
                fi

                if [ -r "${tns}" ]; then
                    add_config_path "${tns}"
                    while IFS= read -r svc_name; do
                        [ -n "${svc_name}" ] && add_database "${svc_name}"
                    done < <(grep -oE 'SERVICE_NAME[[:space:]]*=[[:space:]]*[^[:space:])]+' "${tns}" 2>/dev/null | sed -E 's/.*=[[:space:]]*//' | sort -u)
                    [ -s "${INST_DBS_FILE}" ] && INST_DB_METHOD="config_filesystem"
                fi
            fi

            # Match process for this SID
            local pid
            pid="$(pgrep -f "ora_pmon_${sid}$" 2>/dev/null | head -n1)"
            [ -z "${pid}" ] && pid="$(pgrep -x "oracle${sid}" 2>/dev/null | head -n1)"
            [ -n "${pid}" ] && attach_pid "${pid}"

            emit_instance
        done <"${oratab}"
    fi

    # Also detect tnslsnr as a standalone record if there's no oratab entry
    if [ ! -r "${oratab}" ] && [ -n "${procs}" ]; then
        init_instance "Oracle Database (listener)" "Oracle"
        local pid
        pid="$(pgrep -x tnslsnr 2>/dev/null | head -n1)"
        [ -n "${pid}" ] && attach_pid "${pid}"
        INST_AUTH_MODE="unknown (oratab absent)"
        add_inst_warn "/etc/oratab not present; only listener process detected"
        emit_instance
    fi
}

# ------------------------------------------------------------------------------
# IBM DB2
# ------------------------------------------------------------------------------
discover_db2() {
    local procs
    procs="$(match_processes '(^db2(sysc|fmp|star2|vend)$|/db2(sysc|fmp|star2|vend)( |$))')"
    if [ -z "${procs}" ] && ! id db2inst1 >/dev/null 2>&1; then
        log_skip "No IBM Db2 instance detected."
        return
    fi

    init_instance "IBM Db2" "IBM"
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    # Default instance user is db2inst1 in single-instance installs
    if id db2inst1 >/dev/null 2>&1; then
        INST_NAME="db2inst1"
        INST_INSTALL="$(eval echo "~db2inst1")"
    fi

    # Port from /etc/services
    if [ -r /etc/services ]; then
        local dbport
        dbport="$(awk '/^db2c_/ {split($2, p, "/"); print p[1]; exit}' /etc/services 2>/dev/null)"
        [ -n "${dbport}" ] && add_listen "tcp" "(/etc/services)" "${dbport}" "/etc/services:db2c_*"
    fi

    INST_AUTH_MODE="Db2 default: OS-based authentication (SERVER). Check \"db2 get dbm cfg\" AUTHENTICATION setting."
    INST_AUTH_SOURCE="db2 get dbm cfg (not parsed in v1.0)"
    add_inst_note "Deep-probe not implemented for Db2; run manually: su - db2inst1 -c 'db2 list db directory' and 'db2 get dbm cfg'"
    emit_instance
}

# ------------------------------------------------------------------------------
# SAP HANA
# ------------------------------------------------------------------------------
discover_hana() {
    local procs
    procs="$(match_processes '^hdb(nameserver|indexserver|xsengine|daemon|compileserver|preprocessor|webdispatcher)$')"
    if [ -z "${procs}" ] && [ ! -d /hana/shared ] && [ ! -d /usr/sap ]; then
        log_skip "No SAP HANA instance detected."
        return
    fi

    # Each <SID> under /usr/sap/ with an HDB<nn> subdirectory is an instance
    local sid_dirs
    sid_dirs="$(find /usr/sap -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | grep -vE '^(hostctrl|trans|SYS|saptools)$')"
    local sid
    while IFS= read -r sid; do
        [ -z "${sid}" ] && continue
        [ ! -d "/usr/sap/${sid}" ] && continue
        # Find the HDB<NN> subdir
        local inst_dir nr
        inst_dir="$(find "/usr/sap/${sid}" -maxdepth 1 -mindepth 1 -type d -name 'HDB[0-9]*' -printf '%f\n' 2>/dev/null | head -n1)"
        [ -z "${inst_dir}" ] && continue
        nr="${inst_dir#HDB}"

        init_instance "SAP HANA" "SAP"
        INST_NAME="${sid}"
        INST_ID="${sid}/${inst_dir}"
        INST_INSTALL="/usr/sap/${sid}/${inst_dir}"

        # HANA default SQL port: 3<NR>15 (indexserver) and 3<NR>13 (tenant for MDC)
        add_listen "tcp" "(default)" "3${nr}13" "HANA default sys port"
        add_listen "tcp" "(default)" "3${nr}15" "HANA default sql port"

        local gi="/usr/sap/${sid}/SYS/global/hdb/custom/config/global.ini"
        [ -r "${gi}" ] && add_config_path "${gi}"

        INST_AUTH_MODE="Internal user store + optional Kerberos/SAML/LDAP via global.ini [authentication] section"
        INST_AUTH_SOURCE="${gi:-unknown}"
        add_inst_note "Deep-probe not implemented for HANA; tenant DB enumeration requires hdbsql with privileged credentials."

        local pid
        pid="$(pgrep -x hdbnameserver 2>/dev/null | head -n1)"
        [ -n "${pid}" ] && attach_pid "${pid}"

        emit_instance
    done <<<"${sid_dirs}"
}

# ------------------------------------------------------------------------------
# MICROSOFT SQL SERVER ON LINUX
# ------------------------------------------------------------------------------
discover_mssql_linux() {
    local svc_names
    svc_names="$(match_services '^(mssql-server|mssql)$' | cut -d'|' -f1 | sort -u)"
    local procs
    procs="$(match_processes '(^sqlservr$|/sqlservr( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ] && [ ! -r /var/opt/mssql/mssql.conf ]; then
        log_skip "No MSSQL-on-Linux instance detected."
        return
    fi

    init_instance "Microsoft SQL Server (Linux)" "Microsoft"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi

    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    local cfg="/var/opt/mssql/mssql.conf"
    if [ -r "${cfg}" ]; then
        add_config_path "${cfg}"
        local content
        content="$(read_safe "${cfg}")"
        local port edition
        port="$(printf '%s\n' "${content}" | awk -F'[= ]+' '/^[[:space:]]*tcpport[[:space:]]*=/ {print $2; exit}')"
        edition="$(printf '%s\n' "${content}" | awk -F'[= ]+' '/^[[:space:]]*edition[[:space:]]*=/ {print $2; exit}')"
        [ -n "${port}" ]    && add_listen "tcp" "(mssql.conf)" "${port}" "mssql.conf:tcpport"
        [ -n "${edition}" ] && INST_EDITION="${edition}"
    else
        add_listen "tcp" "(default)" "1433" "default port"
    fi

    if [ -x /opt/mssql/bin/sqlservr ]; then
        INST_VERSION="$(/opt/mssql/bin/sqlservr --version 2>/dev/null | head -n2 | tr '\n' ' ')"
    fi

    INST_AUTH_MODE="Windows auth via Kerberos + SQL logins (mixed). Use mssql-conf to set login mode; SPNs required for AD integration."
    INST_AUTH_SOURCE="${cfg}"

    # Enumerate user databases by listing *.mdf files in the data directory.
    # MSSQL on Linux stores each database as <name>.mdf (primary file), the
    # same convention as Windows. Running as root we can list filenames
    # regardless of the engine's runtime state - no credentials required.
    local mssql_datadir="/var/opt/mssql/data"
    if [ -d "${mssql_datadir}" ] && [ -r "${mssql_datadir}" ]; then
        local mdf dbname
        while IFS= read -r mdf; do
            [ -z "${mdf}" ] && continue
            dbname="$(basename "${mdf}" .mdf)"
            # Skip SQL Server internal resource DB; master/model/msdb/tempdb are
            # visible system DBs so include them (matches the Windows script).
            case "${dbname}" in
                mssqlsystemresource) continue ;;
            esac
            add_database "${dbname}"
        done < <(find "${mssql_datadir}" -maxdepth 1 -name '*.mdf' -type f 2>/dev/null | sort)
        if [ -s "${INST_DBS_FILE}" ]; then
            INST_DB_METHOD="config_filesystem"
        fi
    else
        add_inst_note "Database catalog enumeration requires deep-probe (sqlcmd 'SELECT name FROM sys.databases'); no credentials available in unattended mode."
    fi

    emit_instance
}

# ------------------------------------------------------------------------------
# GENERIC LIGHT DISCOVERY (presence, service, process, port) for products for
# which detailed auth parsing is out of scope for v1.0.
# ------------------------------------------------------------------------------
# Usage: discover_generic <product> <vendor> <service-regex> <process-regex> <auth-note>
discover_generic() {
    local product="$1" vendor="$2" svc_re="$3" proc_re="$4" auth_note="$5"
    local svc_names procs
    svc_names="$(match_services "${svc_re}" | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes "${proc_re}")"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        return
    fi

    init_instance "${product}" "${vendor}"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    INST_AUTH_MODE="${auth_note}"
    INST_AUTH_SOURCE="service metadata only (v1.0 surface-level discovery)"
    emit_instance
}

# ------------------------------------------------------------------------------
# APACHE CASSANDRA / SCYLLADB
# ------------------------------------------------------------------------------
discover_cassandra() {
    local svc_names procs
    svc_names="$(match_services '^(cassandra|scylla|scylla-server)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(cassandra|scylla)')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        log_skip "No Cassandra / ScyllaDB instance detected."
        return
    fi
    local is_scylla=0
    if printf '%s' "${svc_names}${procs}" | grep -qiE 'scylla'; then is_scylla=1; fi

    if [ "${is_scylla}" -eq 1 ]; then
        init_instance "ScyllaDB" "ScyllaDB"
    else
        init_instance "Apache Cassandra" "Apache"
    fi
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    local cfg=""
    for c in /etc/cassandra/cassandra.yaml /etc/cassandra/default.conf/cassandra.yaml /etc/scylla/scylla.yaml; do
        [ -r "${c}" ] && { cfg="${c}"; break; }
    done
    if [ -n "${cfg}" ]; then
        add_config_path "${cfg}"
        local authenticator authorizer
        authenticator="$(awk -F': *' '/^authenticator[[:space:]]*:/ {print $2; exit}' "${cfg}" 2>/dev/null | tr -d ' ')"
        authorizer="$(awk -F': *' '/^authorizer[[:space:]]*:/ {print $2; exit}' "${cfg}" 2>/dev/null | tr -d ' ')"
        [ -n "${authenticator}" ] && add_auth_detail "authenticator=${authenticator}"
        [ -n "${authorizer}" ]    && add_auth_detail "authorizer=${authorizer}"
        INST_AUTH_MODE="authenticator=${authenticator:-AllowAllAuthenticator}"
        INST_AUTH_SOURCE="${cfg}"
    fi
    emit_instance
}

# ------------------------------------------------------------------------------
# ELASTICSEARCH / OPENSEARCH
# ------------------------------------------------------------------------------
discover_elastic_family() {
    local svc_names procs
    svc_names="$(match_services '^(elasticsearch|opensearch)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(elasticsearch|opensearch)')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then
        log_skip "No Elasticsearch / OpenSearch instance detected."
        return
    fi

    local variant="Elasticsearch" vendor="Elastic" cfg=""
    if printf '%s' "${svc_names}${procs}" | grep -qiE 'opensearch'; then
        variant="OpenSearch"; vendor="OpenSearch"
    fi
    if [ "${variant}" = "OpenSearch" ]; then
        for c in /etc/opensearch/opensearch.yml /usr/share/opensearch/config/opensearch.yml; do
            [ -r "${c}" ] && { cfg="${c}"; break; }
        done
    else
        for c in /etc/elasticsearch/elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml; do
            [ -r "${c}" ] && { cfg="${c}"; break; }
        done
    fi

    init_instance "${variant}" "${vendor}"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"

    if [ -n "${cfg}" ]; then
        add_config_path "${cfg}"
        local http_port
        http_port="$(awk -F': *' '/^http\.port/ {print $2; exit}' "${cfg}" 2>/dev/null | tr -d '"')"
        [ -n "${http_port}" ] && add_listen "tcp" "(config)" "${http_port}" "${variant}:http.port"

        if grep -qE '^xpack\.security\.enabled:[[:space:]]*true' "${cfg}" 2>/dev/null; then
            INST_AUTH_MODE="x-pack security (native/ldap/ad/saml/oidc/kerberos per elasticsearch.yml)"
            INST_AUTH_SOURCE="${cfg}"
        elif [ "${variant}" = "OpenSearch" ]; then
            INST_AUTH_MODE="OpenSearch Security plugin (config.yml)"
            INST_AUTH_SOURCE="${cfg}"
        else
            INST_AUTH_MODE="security not explicitly enabled"
            INST_AUTH_SOURCE="${cfg}"
        fi
    fi
    emit_instance
}

# ------------------------------------------------------------------------------
# COUCHDB / COUCHBASE
# ------------------------------------------------------------------------------
discover_couchdb() {
    local svc_names procs
    svc_names="$(match_services '^(couchdb)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes 'couchdb')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ] && [ ! -d /opt/couchdb ]; then
        return
    fi
    init_instance "Apache CouchDB" "Apache"
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"
    for c in /opt/couchdb/etc/local.ini /etc/couchdb/local.ini; do
        [ -r "${c}" ] && { add_config_path "${c}"; break; }
    done
    INST_AUTH_MODE="_users DB (native) + optional JWT/Proxy auth (chttpd_auth settings in local.ini)"
    emit_instance
}

discover_couchbase() {
    discover_generic "Couchbase" "Couchbase" \
        '^(couchbase-server)$' \
        '(beam\.smp|/opt/couchbase|memcached)' \
        "Couchbase: local RBAC users + optional LDAP/SAML via cluster settings."
}

# ------------------------------------------------------------------------------
# NEO4J
# ------------------------------------------------------------------------------
discover_neo4j() {
    local svc_names procs
    svc_names="$(match_services '^(neo4j)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(^neo4j$|/neo4j( |$)|org\.neo4j)')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then return; fi

    init_instance "Neo4j" "Neo4j"
    local pid
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"
    for c in /etc/neo4j/neo4j.conf /var/lib/neo4j/conf/neo4j.conf; do
        if [ -r "${c}" ]; then
            add_config_path "${c}"
            local providers
            providers="$(awk -F= '/^dbms\.security\.auth_providers/ {print $2; exit}' "${c}" 2>/dev/null)"
            [ -n "${providers}" ] && INST_AUTH_MODE="dbms.security.auth_providers=${providers}"
            break
        fi
    done
    [ -z "${INST_AUTH_MODE}" ] && INST_AUTH_MODE="Native / LDAP / SSO via neo4j.conf (dbms.security.auth_providers)"
    emit_instance
}

# ------------------------------------------------------------------------------
# INFLUXDB, CLICKHOUSE, FIREBIRD, SAP ASE, SAP MAXDB, INFORMIX, TERADATA, RAVEN
# ------------------------------------------------------------------------------
discover_influxdb()  { discover_generic "InfluxDB"   "InfluxData"  '^(influxdb|influxd)$' '(^influxd$|/influxd( |$))'       "InfluxDB 2.x: token-based. 1.x: [http] auth-enabled in influxdb.conf."; }
discover_clickhouse(){ discover_generic "ClickHouse" "ClickHouse"  '^(clickhouse-server)$' '(clickhouse-server|/clickhouse)' "ClickHouse: users.xml or SQL users + optional LDAP/Kerberos."; }
discover_firebird()  { discover_generic "Firebird"   "Firebird"    '^(firebird|firebird-superserver)$' '(^fbguard$|^fbserver$|^firebird$)' "Firebird: AuthServer in firebird.conf (Srp / Legacy_Auth)."; }
discover_sybase()    { discover_generic "SAP ASE (Sybase)" "SAP"   '^(sybase|sap-ase.*)$' '(dataserver|ASE)'                  "ASE: internal logins. LDAP/Kerberos via sp_configure / KRB."; }
discover_maxdb()     { discover_generic "SAP MaxDB" "SAP"          '^(sapdb|maxdb)$'     '(kernel|maxdb)'                    "MaxDB: internal user DB + optional Connect Feature OS/AD."; }
discover_informix()  { discover_generic "IBM Informix" "IBM"       '^(informix.*)$'      '(^oninit$|/oninit( |$))'           "Informix: OS authentication via pam_informix or pluggable auth."; }
discover_teradata()  { discover_generic "Teradata" "Teradata"      '^(tdatcmd.*|tdat.*)$' '(^tdatcmd$|/tdatcmd)'              "Teradata: TD2 (internal), LDAP/KRB5 via tdgssconfigfile."; }
discover_ravendb()   { discover_generic "RavenDB" "RavenDB"        '^(ravendb.*)$'        '(Raven\.Server|ravendb)'           "RavenDB: X.509 client certificate authentication by default."; }

# ==============================================================================
# v2.0 ADDITIONS: etcd / Consul / Memcached / Prometheus / H2/HSQLDB/Derby
# ==============================================================================

# ------------------------------------------------------------------------------
# ETCD
# ------------------------------------------------------------------------------
discover_etcd() {
    local svc_names procs
    svc_names="$(match_services '^(etcd|etcd-member)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(^etcd$|/etcd( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then return; fi

    init_instance "etcd" "CNCF"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid pid_row cmdline
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"
    if [ -n "${pid}" ]; then
        pid_row="$(awk -F'|' -v p="${pid}" '$2==p {print; exit}' "${PROCESSES_FILE}")"
        cmdline="$(printf '%s' "${pid_row}" | cut -d'|' -f5)"
    fi

    # Config file (less common on Linux - most etcd deployments use flags via unit files)
    for c in /etc/etcd/etcd.conf.yml /etc/etcd/etcd.conf /etc/default/etcd; do
        [ -r "${c}" ] && { add_config_path "${c}"; break; }
    done

    local cert_auth=0 peer_cert_auth=0 auth_token=""
    if [ -n "${cmdline}" ]; then
        printf '%s' "${cmdline}" | grep -qE -- '--client-cert-auth(=true|[[:space:]]|$)' && cert_auth=1
        printf '%s' "${cmdline}" | grep -qE -- '--peer-client-cert-auth(=true|[[:space:]]|$)' && peer_cert_auth=1
        auth_token="$(printf '%s' "${cmdline}" | grep -oE -- '--auth-token=[^[:space:]]+' | head -n1 | sed 's/^--auth-token=//')"
        # Ports from --listen-client-urls / --listen-peer-urls
        while IFS= read -r url; do
            [ -z "${url}" ] && continue
            local port="${url##*:}"; port="${port%%/*}"
            if printf '%s' "${port}" | grep -qE '^[0-9]+$'; then
                add_listen "tcp" "(--listen-client-urls)" "${port}" "etcd --listen-client-urls"
            fi
        done < <(printf '%s' "${cmdline}" | grep -oE -- '--listen-client-urls[= ]+[^[:space:]]+' | head -n1 | sed 's/^--listen-client-urls[= ]//' | tr ',' '\n')
        while IFS= read -r url; do
            [ -z "${url}" ] && continue
            local port="${url##*:}"; port="${port%%/*}"
            if printf '%s' "${port}" | grep -qE '^[0-9]+$'; then
                add_listen "tcp" "(--listen-peer-urls)" "${port}" "etcd --listen-peer-urls"
            fi
        done < <(printf '%s' "${cmdline}" | grep -oE -- '--listen-peer-urls[= ]+[^[:space:]]+' | head -n1 | sed 's/^--listen-peer-urls[= ]//' | tr ',' '\n')
    fi

    local parts=""
    [ "${cert_auth}" -eq 1 ]      && parts="${parts}client mTLS (--client-cert-auth=true); "
    [ "${peer_cert_auth}" -eq 1 ] && parts="${parts}peer mTLS (--peer-client-cert-auth=true); "
    [ -n "${auth_token}" ]        && parts="${parts}RBAC token type: ${auth_token}; "
    if [ -n "${parts}" ]; then
        INST_AUTH_MODE="${parts%; }"
        INST_AUTH_SOURCE="command-line flags"
    else
        INST_AUTH_MODE="No auth configured (client-cert-auth not enabled, no RBAC token)"
        INST_AUTH_SOURCE="command-line flags (defaults)"
    fi

    # Fall back to default ports if none extracted
    if ! [ -s "${INST_LISTEN_FILE}" ]; then
        add_listen "tcp" "(default)" "2379" "etcd default client port"
        add_listen "tcp" "(default)" "2380" "etcd default peer port"
    fi

    add_inst_note "Stores cluster-coordination state (k8s, service discovery). Hold for RBAC/TLS review."
    emit_instance
}

# ------------------------------------------------------------------------------
# HASHICORP CONSUL
# ------------------------------------------------------------------------------
discover_consul() {
    local svc_names procs
    svc_names="$(match_services '^(consul|consul-.+)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(^consul$|/consul( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then return; fi

    init_instance "HashiCorp Consul" "HashiCorp"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid pid_row cmdline
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"
    if [ -n "${pid}" ]; then
        pid_row="$(awk -F'|' -v p="${pid}" '$2==p {print; exit}' "${PROCESSES_FILE}")"
        cmdline="$(printf '%s' "${pid_row}" | cut -d'|' -f5)"
    fi

    # Locate config dir from cmdline or default
    local cfg_dir=""
    if [ -n "${cmdline}" ]; then
        cfg_dir="$(printf '%s' "${cmdline}" | grep -oE -- '-config-dir[= ]+[^[:space:]]+' | head -n1 | sed 's/^-config-dir[= ]//')"
    fi
    [ -z "${cfg_dir}" ] && for d in /etc/consul.d /etc/consul /opt/consul/config; do
        [ -d "${d}" ] && { cfg_dir="${d}"; break; }
    done

    local combined=""
    if [ -n "${cfg_dir}" ] && [ -d "${cfg_dir}" ]; then
        while IFS= read -r f; do
            [ -r "${f}" ] || continue
            add_config_path "${f}"
            combined="${combined}
$(read_safe "${f}")"
        done < <(find "${cfg_dir}" -maxdepth 2 -type f \( -name '*.hcl' -o -name '*.json' \) 2>/dev/null)
    fi

    if printf '%s' "${combined}" | grep -qE 'acl[[:space:]]*\{[^}]*enabled[[:space:]]*=[[:space:]]*true' 2>/dev/null \
       || printf '%s' "${combined}" | grep -qE '"acl"[[:space:]]*:[[:space:]]*\{[^}]*"enabled"[[:space:]]*:[[:space:]]*true' 2>/dev/null; then
        INST_AUTH_MODE="ACLs enabled (token-based)"
    elif printf '%s' "${combined}" | grep -qE 'acl[[:space:]]*\{' 2>/dev/null; then
        INST_AUTH_MODE="ACL block present (check tokens.default)"
    elif [ -n "${combined}" ]; then
        INST_AUTH_MODE="No ACLs configured (anonymous access allowed by default)"
    else
        INST_AUTH_MODE="Config dir not located; ACL state unknown"
    fi
    INST_AUTH_SOURCE="${cfg_dir:-unknown}"

    # Canonical Consul ports
    add_listen "tcp" "(default)" "8500" "Consul HTTP API default"
    add_listen "tcp" "(default)" "8501" "Consul HTTPS API default"
    add_listen "tcp" "(default)" "8300" "Consul server RPC default"
    add_listen "tcp" "(default)" "8301" "Consul LAN gossip default"
    add_listen "tcp" "(default)" "8302" "Consul WAN gossip default"
    add_listen "tcp" "(default)" "8600" "Consul DNS default"

    add_inst_note "Service discovery / distributed config store. Often integrated with Vault for secrets."
    emit_instance
}

# ------------------------------------------------------------------------------
# MEMCACHED
# ------------------------------------------------------------------------------
discover_memcached() {
    local svc_names procs
    svc_names="$(match_services '^(memcached)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(^memcached$|/memcached( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then return; fi

    init_instance "Memcached" "Memcached"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid pid_row cmdline
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"
    if [ -n "${pid}" ]; then
        pid_row="$(awk -F'|' -v p="${pid}" '$2==p {print; exit}' "${PROCESSES_FILE}")"
        cmdline="$(printf '%s' "${pid_row}" | cut -d'|' -f5)"
    fi

    # Config files
    local cfg=""
    for c in /etc/sysconfig/memcached /etc/default/memcached /etc/memcached.conf; do
        [ -r "${c}" ] && { cfg="${c}"; add_config_path "${c}"; break; }
    done

    # SASL detection: -S in command line or in OPTIONS env in config file
    local sasl=0
    if [ -n "${cmdline}" ] && printf '%s' "${cmdline}" | grep -qE -- '(^| )-S( |$)|--enable-sasl'; then
        sasl=1
    elif [ -n "${cfg}" ] && grep -qE -- '(^| )-S( |$)|--enable-sasl' "${cfg}" 2>/dev/null; then
        sasl=1
    fi
    if [ "${sasl}" -eq 1 ]; then
        INST_AUTH_MODE="SASL enabled (-S)"
    else
        INST_AUTH_MODE="No authentication (default)"
    fi
    INST_AUTH_SOURCE="${cfg:-command-line flags}"

    # Port
    local port=""
    if [ -n "${cmdline}" ]; then
        port="$(printf '%s' "${cmdline}" | grep -oE -- '-p[[:space:]]+[0-9]+' | head -n1 | awk '{print $2}')"
    fi
    if [ -z "${port}" ] && [ -n "${cfg}" ]; then
        port="$(grep -oE -- '(-p|PORT=)[[:space:]]*[0-9]+' "${cfg}" 2>/dev/null | head -n1 | grep -oE '[0-9]+')"
    fi
    if [ -n "${port}" ]; then
        add_listen "tcp" "(-p)" "${port}" "memcached -p"
    else
        add_listen "tcp" "(default)" "11211" "memcached default"
    fi

    add_inst_note "Cache, not a persistent DBMS. Primary security concern: exposure beyond trusted network when auth is off."
    emit_instance
}

# ------------------------------------------------------------------------------
# PROMETHEUS
# ------------------------------------------------------------------------------
discover_prometheus() {
    local svc_names procs
    svc_names="$(match_services '^(prometheus|prometheus-server)$' | cut -d'|' -f1 | sort -u)"
    procs="$(match_processes '(^prometheus$|/prometheus( |$))')"
    if [ -z "${svc_names}" ] && [ -z "${procs}" ]; then return; fi

    init_instance "Prometheus" "Prometheus"
    local svc_name svc_row
    svc_name="$(printf '%s\n' "${svc_names}" | head -n1)"
    if [ -n "${svc_name}" ]; then
        svc_row="$(awk -F'|' -v n="${svc_name}" '$1==n {print; exit}' "${SERVICES_FILE}")"
        INST_SVC_NAME="${svc_name}"
        INST_SVC_STATE="$(printf '%s' "${svc_row}" | cut -d'|' -f2)"
        INST_SVC_DISPLAY="$(printf '%s' "${svc_row}" | cut -d'|' -f3)"
    fi
    local pid pid_row cmdline
    pid="$(printf '%s\n' "${procs}" | awk -F'|' 'NR==1 {print $2}')"
    [ -n "${pid}" ] && attach_pid "${pid}"
    if [ -n "${pid}" ]; then
        pid_row="$(awk -F'|' -v p="${pid}" '$2==p {print; exit}' "${PROCESSES_FILE}")"
        cmdline="$(printf '%s' "${pid_row}" | cut -d'|' -f5)"
    fi

    local web_config="" main_config="" listen_addr=""
    if [ -n "${cmdline}" ]; then
        web_config="$(printf '%s' "${cmdline}" | grep -oE -- '--web\.config\.file[= ]+[^[:space:]]+' | head -n1 | sed 's/^--web\.config\.file[= ]//')"
        main_config="$(printf '%s' "${cmdline}" | grep -oE -- '--config\.file[= ]+[^[:space:]]+' | head -n1 | sed 's/^--config\.file[= ]//')"
        listen_addr="$(printf '%s' "${cmdline}" | grep -oE -- '--web\.listen-address[= ]+[^[:space:]]+' | head -n1 | sed 's/^--web\.listen-address[= ]//')"
    fi
    if [ -z "${main_config}" ]; then
        for c in /etc/prometheus/prometheus.yml /opt/prometheus/prometheus.yml; do
            [ -r "${c}" ] && { main_config="${c}"; break; }
        done
    fi
    [ -n "${main_config}" ] && add_config_path "${main_config}"
    [ -n "${web_config}" ]  && add_config_path "${web_config}"

    if [ -n "${listen_addr}" ] && printf '%s' "${listen_addr}" | grep -qE ':[0-9]+$'; then
        local port="${listen_addr##*:}"
        add_listen "tcp" "(--web.listen-address)" "${port}" "prometheus --web.listen-address"
    fi

    if [ -n "${web_config}" ] && [ -r "${web_config}" ]; then
        local auth_bits=""
        if grep -qE '^[[:space:]]*tls_server_config[[:space:]]*:' "${web_config}" 2>/dev/null; then
            auth_bits="${auth_bits}tls_server_config "
            INST_TLS_ENABLED="true"
        fi
        if grep -qE '^[[:space:]]*basic_auth_users[[:space:]]*:' "${web_config}" 2>/dev/null; then
            auth_bits="${auth_bits}basic_auth_users "
        fi
        if [ -n "${auth_bits}" ]; then
            INST_AUTH_MODE="$(printf '%s' "${auth_bits}" | sed 's/ $//' | tr ' ' '+')"
            INST_AUTH_SOURCE="${web_config}"
        else
            INST_AUTH_MODE="web.config.file present but no tls_server_config / basic_auth_users"
            INST_AUTH_SOURCE="${web_config}"
        fi
    else
        INST_AUTH_MODE="No native auth (typically fronted by reverse proxy for basic/TLS)"
        INST_AUTH_SOURCE="no --web.config.file"
    fi

    # Default port fallback
    if ! grep -qE '\|9090\|' "${INST_LISTEN_FILE}" 2>/dev/null; then
        add_listen "tcp" "(default)" "9090" "Prometheus default"
    fi

    add_inst_note "Time-series DB. Targets/scrape config in --config.file; write access usually off by default."
    emit_instance
}

# ------------------------------------------------------------------------------
# H2 / HSQLDB / APACHE DERBY (server mode only)
# ------------------------------------------------------------------------------
#
# These engines are Java-embedded libraries. Only server-mode deployments are
# reported (detected via java command-line inspection). True in-process
# embedded usage is out of scope - those engines have no network listener and
# no independent authentication to inventory.
#
discover_java_embedded_servers() {
    # Iterate java processes once; for each, test against every engine pattern.
    local java_rows
    java_rows="$(awk -F'|' '$4=="java" || $4=="javaw" {print}' "${PROCESSES_FILE}" 2>/dev/null)"
    [ -z "${java_rows}" ] && return

    # Regex | product | vendor | default port | auth note
    local patterns_file
    patterns_file="$(mktemp /tmp/dbinv-javapats.XXXXXX)"
    cat >"${patterns_file}" <<'EOF'
(h2-[0-9.]+\.jar|org\.h2\.tools\.Server|org\.h2\.server)|H2 Database (server mode)|H2 Group|9092|H2 server: user/password stored in DB file; TLS via -tcpSSL. Check -tcpAllowOthers (remote clients) and -tcpPassword (mgmt).
(hsqldb[-_][0-9.]+\.jar|org\.hsqldb\.Server|org\.hsqldb\.server\.Server)|HSQLDB (server mode)|HSQL Development Group|9001|HSQLDB: user table in server DB. Auth internal; TLS via server.tls=true in server.properties.
(derbynet\.jar|derbyrun\.jar|org\.apache\.derby\.drda\.NetworkServerControl)|Apache Derby (Network Server)|Apache|1527|Derby Network Server: authentication requires derby.connection.requireAuthentication=true in derby.properties; anonymous by default.
EOF

    while IFS= read -r proc_row; do
        [ -z "${proc_row}" ] && continue
        local pid user cmdline
        user="$(printf '%s' "${proc_row}" | cut -d'|' -f1)"
        pid="$(printf '%s'  "${proc_row}" | cut -d'|' -f2)"
        cmdline="$(printf '%s' "${proc_row}" | cut -d'|' -f5)"

        while IFS='|' read -r regex product vendor default_port auth_note; do
            [ -z "${regex}" ] && continue
            if printf '%s' "${cmdline}" | grep -qE "${regex}"; then
                init_instance "${product}" "${vendor}"
                INST_NAME="pid-${pid}"
                INST_AUTH_MODE="${auth_note}"
                INST_AUTH_SOURCE="java command-line inspection"
                INST_SVC_ACCT="${user}"
                INST_SVC_ACCT_TYPE="$(classify_linux_user "${user}")"
                add_inst_proc "${pid}" "java" "${cmdline}" "${user}"
                listen_for_pid "${pid}" | while IFS='|' read -r proto ip port _pid; do
                    [ -n "${port}" ] && printf '%s|%s|%s|%s\n' "${proto}" "${ip}" "${port}" "live_socket" >>"${INST_LISTEN_FILE}"
                done
                if ! [ -s "${INST_LISTEN_FILE}" ]; then
                    add_listen "tcp" "(default)" "${default_port}" "${product} default"
                fi
                add_inst_note "Detected via java command-line inspection. In-process embedded usage (no network listener) is NOT reported."
                emit_instance
                break   # don't match multiple engines against the same java process
            fi
        done <"${patterns_file}"
    done <<<"${java_rows}"

    rm -f "${patterns_file}"
}

# ------------------------------------------------------------------------------
# SQLITE FILESYSTEM SCAN (opt-in, --include-embedded)
# ------------------------------------------------------------------------------
#
# Guardrails (matching the Windows script):
#   - Directory allowlist (default /srv /opt /var/lib /data; caller-overridable
#     via --embedded-paths).
#   - Always-excluded: /proc /sys /dev /tmp /run /var/cache /var/lib/dpkg
#     /var/lib/rpm /home (browser/app sqlite noise).
#   - Size floor: 256 KiB minimum.
#   - Magic-byte validation: file must start with "SQLite format 3\0".
#   - Stays on local filesystems only (find -xdev).
#   - Per-run hit cap: 500; warns when reached.
#
# Access (.mdb/.accdb) files on Linux are rare (would only appear on Samba
# mounts that we won't cross due to -xdev, or in backup dirs). We DO still
# check for them with the same magic-byte validation, but expect ~zero hits
# in typical Linux deployments.
#
EMBEDDED_HIT_CAP=500
EMBEDDED_MIN_SIZE=262144   # 256 KiB
EMBEDDED_ALWAYS_EXCLUDED="/proc /sys /dev /tmp /run /var/cache /var/lib/dpkg /var/lib/rpm /home"

_is_under_excluded() {
    local path="$1"
    for ex in ${EMBEDDED_ALWAYS_EXCLUDED}; do
        case "${path}" in
            "${ex}"|"${ex}"/*) return 0 ;;
        esac
    done
    return 1
}

_check_sqlite_magic() {
    # Read first 16 bytes, compare ASCII of bytes 0..14 to "SQLite format 3".
    local path="$1"
    local header
    header="$(dd if="${path}" bs=1 count=16 2>/dev/null | tr -d '\0')"
    case "${header}" in
        "SQLite format 3"*) return 0 ;;
    esac
    return 1
}

_check_access_magic() {
    # Bytes 4..18 are "Standard Jet DB" or "Standard ACE DB".
    local path="$1"
    local header
    header="$(dd if="${path}" bs=1 count=20 skip=4 2>/dev/null | tr -d '\0')"
    case "${header}" in
        "Standard Jet DB"*|"Standard ACE DB"*) return 0 ;;
    esac
    return 1
}

run_embedded_scan() {
    [ "${INCLUDE_EMBEDDED}" -eq 0 ] && { log_skip "Embedded-engine filesystem scan: skipped (flag not set)."; return; }

    log_warn "Embedded-engine filesystem scan: ENABLED (--include-embedded)."
    log "This walks selected directories, stays on local filesystems, validates magic bytes, and reports each matching file."

    local search_paths
    if [ -n "${EMBEDDED_PATHS}" ]; then
        search_paths="$(printf '%s' "${EMBEDDED_PATHS}" | tr ',' ' ')"
    else
        search_paths=""
        for d in /srv /opt /var/lib /data; do
            [ -d "${d}" ] && search_paths="${search_paths} ${d}"
        done
    fi
    log "Embedded scan directories:${search_paths}"
    log "Size floor: ${EMBEDDED_MIN_SIZE} bytes   Per-engine hit cap: ${EMBEDDED_HIT_CAP}"

    local sqlite_hits=0 access_hits=0 file path ext
    for root in ${search_paths}; do
        [ -z "${root}" ] && continue
        [ -d "${root}" ] || continue
        if _is_under_excluded "${root}"; then
            log_skip "Skipping excluded root: ${root}"
            continue
        fi
        log "Walking: ${root}"

        while IFS= read -r path; do
            [ -z "${path}" ] && continue
            _is_under_excluded "${path}" && continue

            ext="${path##*.}"
            ext="$(printf '%s' "${ext}" | tr '[:upper:]' '[:lower:]')"

            case "${ext}" in
                sqlite|sqlite3|db|db3)
                    [ "${sqlite_hits}" -ge "${EMBEDDED_HIT_CAP}" ] && continue
                    _check_sqlite_magic "${path}" || continue
                    _emit_embedded_record "SQLite" "Embedded" "${path}" \
                        "No built-in authentication (relies on filesystem ACLs); optional SQLCipher extension provides encryption."
                    sqlite_hits=$((sqlite_hits + 1))
                    ;;
                mdb|accdb)
                    [ "${access_hits}" -ge "${EMBEDDED_HIT_CAP}" ] && continue
                    _check_access_magic "${path}" || continue
                    _emit_embedded_record "Microsoft Access" "Embedded" "${path}" \
                        "Access/Jet: workgroup file or database password. Anonymous by default when workgroup info is absent."
                    access_hits=$((access_hits + 1))
                    ;;
            esac

            if [ "${sqlite_hits}" -ge "${EMBEDDED_HIT_CAP}" ] && [ "${access_hits}" -ge "${EMBEDDED_HIT_CAP}" ]; then
                log_warn "Both per-engine hit caps reached; stopping embedded-scan traversal."
                break 2
            fi
        done < <(find "${root}" -xdev -type f \
                    \( -iname '*.sqlite' -o -iname '*.sqlite3' -o -iname '*.db' -o -iname '*.db3' -o -iname '*.mdb' -o -iname '*.accdb' \) \
                    -size +${EMBEDDED_MIN_SIZE}c \
                    2>/dev/null)
    done

    [ "${sqlite_hits}" -ge "${EMBEDDED_HIT_CAP}" ] && log_warn "SQLite hit cap (${EMBEDDED_HIT_CAP}) reached; consider narrowing --embedded-paths."
    [ "${access_hits}" -ge "${EMBEDDED_HIT_CAP}" ] && log_warn "Access hit cap (${EMBEDDED_HIT_CAP}) reached; consider narrowing --embedded-paths."
    log_ok "Embedded scan complete. SQLite: ${sqlite_hits}  Access: ${access_hits}"
}

_emit_embedded_record() {
    local product="$1" vendor="$2" path="$3" auth_note="$4"
    init_instance "${product}" "${vendor}"
    INST_NAME="$(basename "${path}")"
    INST_INSTALL="${path}"
    INST_DATA="${path}"
    INST_AUTH_MODE="${auth_note}"
    INST_AUTH_SOURCE="file magic bytes"
    INST_DB_METHOD="filesystem_scan"
    add_database "$(basename "${path}" | sed 's/\.[^.]*$//')"
    local sz mt
    sz="$(stat -c%s "${path}" 2>/dev/null || echo 0)"
    mt="$(stat -c%Y "${path}" 2>/dev/null || echo 0)"
    add_inst_note "Size: ${sz} bytes   Mtime-epoch: ${mt}"
    emit_instance
}

# ==============================================================================
# DEEP PROBE (opt-in, local trust-based catalog enumeration)
# ==============================================================================
#
# For each already-emitted instance, try a local trust-based query to list
# catalog names. Uses jq if installed, otherwise falls back to python3/python
# (present by default on all modern enterprise Linux distros). If neither is
# available the probe still runs and logs results to the text log, but the
# JSON is not updated - a single warning is emitted once per run.
#
run_deep_probe() {
    [ "${DEEP_PROBE}" -eq 0 ] && { log_skip "Deep probe: skipped (flag not set)."; return; }
    log_warn "Deep-probe enabled: will open LOCAL, trust-based connections to discovered instances."
    log_warn "Any DB audit trail will record these queries. Coordinate with DBAs before fleet rollout."
    if [ "${HAS_JQ}" -eq 0 ] && [ "${HAS_PY}" -eq 0 ]; then
        log_warn "Neither jq nor python available - probe results will be logged but NOT merged into JSON."
    fi

    local tmp_out
    tmp_out="$(mktemp /tmp/dbinv-probe.XXXXXX.ndjson)"

    local line product inst_name port dbs_json_array
    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        product="$(json_extract   "${line}" 'product')"
        inst_name="$(json_extract "${line}" 'instance_name')"
        port="$(json_extract      "${line}" 'listen.0.local_port')"

        local names=""
        case "${product}" in
            MySQL|MariaDB|"Percona Server")
                if [ "${DRY_RUN}" -eq 1 ]; then
                    log_skip "[dry-run] Would probe ${product} (port ${port:-3306})"
                elif [ "${HAS_MYSQL}" -eq 1 ]; then
                    # Try common no-credential auth paths in order:
                    #   1. unix socket + auth_socket (MariaDB / MySQL 8 default for root)
                    #   2. Debian maintenance user
                    #   3. Percona/RHEL /root/.my.cnf if present (root's creds)
                    names="$(mysql --connect-timeout=3 --protocol=SOCKET -BN -e 'SHOW DATABASES;' 2>/dev/null || true)"
                    if [ -z "${names}" ] && [ -r /etc/mysql/debian.cnf ]; then
                        names="$(mysql --defaults-file=/etc/mysql/debian.cnf --connect-timeout=3 -BN -e 'SHOW DATABASES;' 2>/dev/null || true)"
                    fi
                    if [ -z "${names}" ]; then
                        names="$(mysql --connect-timeout=3 -u root -BN -e 'SHOW DATABASES;' 2>/dev/null || true)"
                    fi
                fi
                ;;
            PostgreSQL)
                if [ "${DRY_RUN}" -eq 1 ]; then
                    log_skip "[dry-run] Would probe PostgreSQL (port ${port:-5432}) via sudo -u postgres psql"
                elif [ "${HAS_PSQL}" -eq 1 ] && id postgres >/dev/null 2>&1; then
                    # Root can sudo to postgres without a password; peer auth on the UNIX socket
                    # then gives us read access to pg_database metadata.
                    names="$(sudo -n -u postgres PGCONNECT_TIMEOUT=3 psql -AtXqc 'SELECT datname FROM pg_database ORDER BY datname' 2>/dev/null || true)"
                fi
                ;;
            MongoDB)
                if [ "${DRY_RUN}" -eq 1 ]; then
                    log_skip "[dry-run] Would probe MongoDB (port ${port:-27017})"
                elif [ "${HAS_MONGOSH}" -eq 1 ]; then
                    # Unauthenticated localhost exception lets listDatabases succeed
                    # when no users exist yet; will fail silently once auth is enforced.
                    names="$(mongosh --quiet --eval 'db.adminCommand({listDatabases:1}).databases.map(d=>d.name).join("\n")' 2>/dev/null || true)"
                fi
                ;;
            "Microsoft SQL Server (Linux)")
                # MSSQL on Linux requires explicit credentials - no local-trust login path
                # exists. However, running as root we can enumerate databases directly from
                # the *.mdf files in /var/opt/mssql/data/ (done during discover_mssql_linux).
                log_skip "MSSQL-on-Linux: catalog enumeration handled by filesystem scan during discovery (no credentials available for sqlcmd deep-probe)."
                ;;
        esac

        if [ -n "${names}" ]; then
            local db_count
            db_count="$(printf '%s\n' "${names}" | awk 'NF' | wc -l | tr -d ' ')"
            log_ok "Deep-probed ${product} / ${inst_name:-default}: ${db_count} databases"

            if [ "${HAS_JQ}" -eq 1 ]; then
                dbs_json_array="$(printf '%s\n' "${names}" | awk 'NF' | jq -R . | jq -s .)"
            elif [ "${HAS_PY}" -eq 1 ]; then
                dbs_json_array="$(printf '%s\n' "${names}" | "${PY_BIN}" -c '
import json, sys
print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))
')"
            else
                dbs_json_array=""
            fi
            if [ -n "${dbs_json_array}" ]; then
                line="$(json_merge_line "${line}" 'databases' "${dbs_json_array}")"
                line="$(json_merge_line "${line}" 'database_enumeration_method' '"deep_probe"')"
            fi
        fi

        printf '%s\n' "${line}" >>"${tmp_out}"
    done <"${INSTANCES_FILE}"

    mv -f "${tmp_out}" "${INSTANCES_FILE}"
}

# ==============================================================================
# AD ENRICHMENT (opt-in)
# ==============================================================================
#
# Looks up each domain service account (format user@REALM or DOMAIN\user) via
# ldapsearch (if installed and GSSAPI bind works), or falls back to getent for
# sssd/winbind-mapped accounts. Writes results back into each instance JSON
# via jq (or python fallback) under an `ad_lookup` object. Results are also
# logged to the text log regardless of whether the JSON merge is possible.
#
run_ad_enrichment() {
    [ "${INCLUDE_AD_LOOKUP}" -eq 0 ] && { log_skip "AD enrichment: skipped (flag not set)."; return; }
    log "AD enrichment enabled: resolving domain service accounts."

    if [ "${HAS_JQ}" -eq 0 ] && [ "${HAS_PY}" -eq 0 ]; then
        log_warn "Neither jq nor python available - AD lookup results will be logged but NOT merged into JSON."
    fi

    local tmp_out
    tmp_out="$(mktemp /tmp/dbinv-ad.XXXXXX.ndjson)"
    local -A cache
    local line acct acct_type ad_json

    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        acct="$(json_extract      "${line}" 'service.account')"
        acct_type="$(json_extract "${line}" 'service.account_type')"
        if [ "${acct_type}" != "domain_user" ] || [ -z "${acct}" ]; then
            printf '%s\n' "${line}" >>"${tmp_out}"
            continue
        fi
        if [ -n "${cache[${acct}]:-}" ]; then
            ad_json="${cache[${acct}]}"
        else
            ad_json="$(lookup_ad_account "${acct}")"
            cache[${acct}]="${ad_json}"
        fi
        if [ -n "${ad_json}" ] && [ "${ad_json}" != "null" ]; then
            line="$(json_merge_line "${line}" 'ad_lookup' "${ad_json}")"
        fi
        printf '%s\n' "${line}" >>"${tmp_out}"
    done <"${INSTANCES_FILE}"
    mv -f "${tmp_out}" "${INSTANCES_FILE}"
}

# Look up an account via ldapsearch (GSSAPI) or getent. Emit a JSON object on
# stdout, or `null` if not resolvable. Uses jq/python/manual fallback for JSON.
lookup_ad_account() {
    local acct="$1"
    local sam="${acct}"
    # Strip domain prefix/suffix: DOMAIN\user, user@REALM -> user
    case "${sam}" in
        *\\*) sam="${sam##*\\}" ;;
        *@*)  sam="${sam%%@*}"  ;;
    esac

    local kv_file
    kv_file="$(mktemp /tmp/dbinv-ad.XXXXXX)"

    # Try ldapsearch with GSSAPI bind (requires krb5 ticket / keytab)
    if [ "${HAS_LDAPSEARCH}" -eq 1 ]; then
        local out
        out="$(ldapsearch -Q -LLL -Y GSSAPI "(sAMAccountName=${sam})" \
                    displayName userAccountControl pwdLastSet lastLogonTimestamp memberOf distinguishedName mail 2>/dev/null || true)"
        if [ -n "${out}" ]; then
            local dn display_name uac pwd_last last_logon mail enabled
            dn="$(printf '%s\n' "${out}"           | awk -F': ' '/^dn:/ {print $2; exit}')"
            display_name="$(printf '%s\n' "${out}" | awk -F': ' '/^displayName:/ {print $2; exit}')"
            uac="$(printf '%s\n' "${out}"          | awk -F': ' '/^userAccountControl:/ {print $2; exit}')"
            pwd_last="$(printf '%s\n' "${out}"     | awk -F': ' '/^pwdLastSet:/ {print $2; exit}')"
            last_logon="$(printf '%s\n' "${out}"   | awk -F': ' '/^lastLogonTimestamp:/ {print $2; exit}')"
            mail="$(printf '%s\n' "${out}"         | awk -F': ' '/^mail:/ {print $2; exit}')"
            enabled=""
            if [ -n "${uac}" ]; then
                if (( (uac & 0x2) == 0 )); then enabled="true"; else enabled="false"; fi
            fi
            log_ok "AD resolved (ldapsearch): ${acct}"
            {
                printf 'source=ldapsearch\n'
                printf 'display_name=%s\n' "${display_name}"
                printf 'enabled=%s\n'      "${enabled}"
                printf 'password_last_set_ft=%s\n' "${pwd_last}"
                printf 'last_logon_ft=%s\n'       "${last_logon}"
                printf 'mail=%s\n'               "${mail}"
                printf 'distinguished_name=%s\n' "${dn}"
            } >"${kv_file}"
            json_object_from_kv_stdin <"${kv_file}"
            rm -f "${kv_file}"
            return
        fi
    fi

    # getent passwd fallback (sssd/winbind)
    local ent
    ent="$(getent passwd "${sam}" 2>/dev/null || true)"
    if [ -n "${ent}" ]; then
        local uid gid home
        uid="$(printf '%s' "${ent}"  | cut -d: -f3)"
        gid="$(printf '%s' "${ent}"  | cut -d: -f4)"
        home="$(printf '%s' "${ent}" | cut -d: -f6)"
        log_ok "AD resolved (getent): ${acct}"
        {
            printf 'source=getent\n'
            printf 'uid=%s\n'  "${uid}"
            printf 'gid=%s\n'  "${gid}"
            printf 'home=%s\n' "${home}"
        } >"${kv_file}"
        json_object_from_kv_stdin <"${kv_file}"
        rm -f "${kv_file}"
        return
    fi

    rm -f "${kv_file}"
    log_warn "AD lookup returned no result for ${acct}"
    printf 'null'
}

# ==============================================================================
# SUMMARY + JSON EXPORT
# ==============================================================================
emit_summary_json() {
    local finished_at finished_epoch elapsed
    finished_at="$(date '+%Y-%m-%dT%H:%M:%S%z')"
    finished_epoch="$(date +%s)"
    elapsed=$((finished_epoch - START_EPOCH))

    # Per-product counts
    local counts_json="{}"
    if [ -s "${INSTANCES_FILE}" ]; then
        if [ "${HAS_JQ}" -eq 1 ]; then
            counts_json="$(jq -s 'reduce .[] as $i ({}; .[$i.product] += 1)' "${INSTANCES_FILE}")"
        elif [ "${HAS_PY}" -eq 1 ]; then
            counts_json="$("${PY_BIN}" -c "${_PY_COUNT_BY_PRODUCT}" <"${INSTANCES_FILE}")"
        fi
    fi

    # Instances array
    local instances_array="[]"
    if [ -s "${INSTANCES_FILE}" ]; then
        if [ "${HAS_JQ}" -eq 1 ]; then
            instances_array="$(jq -s '.' "${INSTANCES_FILE}")"
        elif [ "${HAS_PY}" -eq 1 ]; then
            instances_array="$("${PY_BIN}" -c "${_PY_WRAP_NDJSON}" <"${INSTANCES_FILE}")"
        else
            # Manually wrap ndjson in [] (simple concatenation with commas).
            instances_array="$(awk 'BEGIN{print "["} NR>1{print ","} {print} END{print "]"}' "${INSTANCES_FILE}" | tr -d '\n')"
        fi
    fi

    # Host IPs array
    local ips_array="[]"
    if [ -s "${HOST_IPS_FILE}" ]; then
        ips_array="$(awk -F'|' '
            BEGIN { printf "[" }
            NR>1  { printf "," }
            { printf "{\"interface\":\"%s\",\"address\":\"%s\",\"family\":\"%s\"}", $1, $2, $3 }
            END   { printf "]" }
        ' "${HOST_IPS_FILE}")"
    fi

    # Warnings / errors arrays
    local warnings_arr errors_arr
    warnings_arr="$(json_str_array_from_stdin <"${WARNINGS_FILE}")"
    errors_arr="$(json_str_array_from_stdin   <"${ERRORS_FILE}")"

    local host_obj
    host_obj="$(printf '{"hostname":%s,"fqdn":%s,"domain":%s,"domain_joined":%s,"os":%s,"os_version":%s,"ip_addresses":%s}' \
        "$(json_str "${HOST_HOSTNAME}")" \
        "$(json_str "${HOST_FQDN}")" \
        "$(json_str "${HOST_DOMAIN}")" \
        "${HOST_DOMAIN_JOINED}" \
        "$(json_str "${HOST_OS}")" \
        "$(json_str "${HOST_OS_VERSION}")" \
        "${ips_array}")"

    local scan_obj
    scan_obj="$(printf '{"script":%s,"version":%s,"started_at":%s,"finished_at":%s,"elapsed_seconds":%s,"options":{"deep_probe":%s,"include_ad_lookup":%s,"include_embedded_engines":%s,"embedded_paths":%s,"json_only":%s,"skip_network":%s,"dry_run":%s,"retain":%s}}' \
        "$(json_str "${SCRIPT_NAME}")" \
        "$(json_str "${SCRIPT_VERSION}")" \
        "$(json_str "${STARTED_AT}")" \
        "$(json_str "${finished_at}")" \
        "${elapsed}" \
        "$([ "${DEEP_PROBE}"        -eq 1 ] && echo true || echo false)" \
        "$([ "${INCLUDE_AD_LOOKUP}" -eq 1 ] && echo true || echo false)" \
        "$([ "${INCLUDE_EMBEDDED}"  -eq 1 ] && echo true || echo false)" \
        "$(json_str "${EMBEDDED_PATHS}")" \
        "$([ "${JSON_ONLY}"         -eq 1 ] && echo true || echo false)" \
        "$([ "${SKIP_NETWORK}"      -eq 1 ] && echo true || echo false)" \
        "$([ "${DRY_RUN}"           -eq 1 ] && echo true || echo false)" \
        "${RETAIN}")"

    local instance_count
    instance_count=$(wc -l <"${INSTANCES_FILE}" 2>/dev/null || echo 0)
    instance_count="$(printf '%s' "${instance_count}" | tr -d ' ')"

    local counts_obj
    counts_obj="$(printf '{"instances":%s,"warnings":%s,"errors":%s}' \
        "${instance_count}" "${COUNT_WARNINGS}" "${COUNT_ERRORS}")"

    local full_doc
    full_doc="$(printf '{"scan":%s,"host":%s,"instances":%s,"product_counts":%s,"warnings":%s,"errors":%s,"counts":%s}' \
        "${scan_obj}" "${host_obj}" "${instances_array}" "${counts_json}" "${warnings_arr}" "${errors_arr}" "${counts_obj}")"

    # Pretty-print if we have a tool for it; otherwise dump compact.
    if [ "${HAS_JQ}" -eq 1 ]; then
        printf '%s' "${full_doc}" | jq '.' >"${JSON_FILE}"
    elif [ "${HAS_PY}" -eq 1 ]; then
        printf '%s' "${full_doc}" | "${PY_BIN}" -c "${_PY_PRETTY}" >"${JSON_FILE}"
    else
        printf '%s\n' "${full_doc}" >"${JSON_FILE}"
    fi
    if [ "${JSON_ONLY}" -eq 1 ]; then cat "${JSON_FILE}"; fi
}

# ==============================================================================
# MAIN
# ==============================================================================
TOTAL_STEPS=9
log "${SCRIPT_NAME} v${SCRIPT_VERSION} started at ${STARTED_AT}"
log "----- parameters -----"
log "DeepProbe              : ${_DEEPSTR} (resolved=${DEEP_PROBE})"
log "IncludeAdLookup        : ${_ADSTR} (resolved=${INCLUDE_AD_LOOKUP})"
log "IncludeEmbeddedEngines : ${_EMBEDSTR} (resolved=${INCLUDE_EMBEDDED})"
if [ -n "${EMBEDDED_PATHS}" ]; then
    log "EmbeddedPaths          : ${EMBEDDED_PATHS}"
else
    log "EmbeddedPaths          : (defaults)"
fi
log "SkipNetwork            : ${_SKIPSTR} (resolved=${SKIP_NETWORK})"
log "DryRun                 : ${_DRYSTR} (resolved=${DRY_RUN})"
log "Retain                 : ${RETAIN}"
log "JsonOnly               : ${_JSONSTR} (resolved=${JSON_ONLY})"
log "OutputPath             : ${OUTPUT_PATH:-(default)}"
log "----------------------"
log "Log:  ${LOG_FILE}"
log "JSON: ${JSON_FILE}"
[ "${DEEP_PROBE}"        -eq 1 ] && log_warn "DeepProbe: ENABLED (local trust queries will occur)."
[ "${INCLUDE_AD_LOOKUP}" -eq 1 ] && log_warn "IncludeAdLookup: ENABLED (LDAP queries to DC will occur)."
[ "${DRY_RUN}"           -eq 1 ] && log "DryRun: ENABLED (deep-probe will log intent only)."
[ "${SKIP_NETWORK}"      -eq 1 ] && log "SkipNetwork: ENABLED (listening sockets not enumerated)."
log "Retain: ${RETAIN} run(s) of output on disk."

cleanup_prior_runs

log "[Step 1/${TOTAL_STEPS}] Host identity"
collect_host_identity
log_ok "Host: ${HOST_HOSTNAME}  FQDN: ${HOST_FQDN}  Domain: ${HOST_DOMAIN} (joined=${HOST_DOMAIN_JOINED})  OS: ${HOST_OS}"
if [ -s "${HOST_IPS_FILE}" ]; then
    while IFS='|' read -r iface ip fam; do
        log_skip "  IP: ${ip} (${fam}) on ${iface}"
    done <"${HOST_IPS_FILE}"
fi

log "[Step 2/${TOTAL_STEPS}] Enumerating services..."
collect_services
log_ok "Collected $(wc -l <"${SERVICES_FILE}" 2>/dev/null | tr -d ' ') service unit(s)."

log "[Step 3/${TOTAL_STEPS}] Enumerating processes..."
collect_processes
log_ok "Collected $(wc -l <"${PROCESSES_FILE}" 2>/dev/null | tr -d ' ') process(es)."

log "[Step 4/${TOTAL_STEPS}] Enumerating listening sockets..."
collect_listen
log_ok "Collected $(wc -l <"${LISTEN_FILE}" 2>/dev/null | tr -d ' ') listening socket(s)."

log "[Step 5/${TOTAL_STEPS}] Per-product discovery..."
discover_mysql_family
discover_postgres
discover_mongodb
discover_redis
discover_oracle
discover_db2
discover_hana
discover_mssql_linux
discover_cassandra
discover_elastic_family
discover_couchdb
discover_couchbase
discover_neo4j
discover_influxdb
discover_clickhouse
discover_firebird
discover_sybase
discover_maxdb
discover_informix
discover_teradata
discover_ravendb
# v2.0 additions
discover_etcd
discover_consul
discover_memcached
discover_prometheus
discover_java_embedded_servers
log_ok "Per-product pass complete: $(wc -l <"${INSTANCES_FILE}" 2>/dev/null | tr -d ' ') instance(s) recorded."

log "[Step 6/${TOTAL_STEPS}] Embedded-engine filesystem scan..."
run_embedded_scan

log "[Step 7/${TOTAL_STEPS}] Deep probe..."
run_deep_probe

log "[Step 8/${TOTAL_STEPS}] AD enrichment..."
run_ad_enrichment

log "[Step 9/${TOTAL_STEPS}] Summary + JSON export..."

INSTANCE_COUNT="$(wc -l <"${INSTANCES_FILE}" 2>/dev/null | tr -d ' ')"
log "----------------------------------------------------------------"
log_ok "SUMMARY: ${INSTANCE_COUNT} instance(s) recorded."
if [ -s "${INSTANCES_FILE}" ]; then
    _product_lines=""
    if [ "${HAS_JQ}" -eq 1 ]; then
        _product_lines="$(jq -r '.product' "${INSTANCES_FILE}" 2>/dev/null)"
    elif [ "${HAS_PY}" -eq 1 ]; then
        _product_lines="$("${PY_BIN}" -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        print(json.loads(line).get("product", ""))
    except Exception:
        pass
' <"${INSTANCES_FILE}")"
    else
        # Regex fallback - assumes "product" never appears as another key's string value.
        _product_lines="$(sed -n 's/.*"product"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${INSTANCES_FILE}")"
    fi
    if [ -n "${_product_lines}" ]; then
        while IFS='|' read -r prod cnt; do
            [ -z "${prod}" ] && continue
            log_find "  ${prod}: ${cnt}"
        done < <(printf '%s\n' "${_product_lines}" | sort | uniq -c | awk '{cnt=$1; $1=""; sub(/^[[:space:]]+/,""); print $0 "|" cnt}')
    fi
fi
log "Warnings: ${COUNT_WARNINGS}   Errors: ${COUNT_ERRORS}   Elapsed: $((($(date +%s) - START_EPOCH)))s"

emit_summary_json

# Exit code
if [ "${COUNT_ERRORS}" -gt 0 ] || [ "${COUNT_WARNINGS}" -gt 0 ]; then
    exit 1
fi
exit 0
