# Qualys Cloud Agent Log Viewer

A single-file HTML tool for parsing and analyzing Qualys Cloud Agent log files and CAR (Custom Assessment & Remediation) job report CSVs. Drop files into your browser and get an organized, searchable, color-coded view instantly.

No server, no install, no build step. Just open `qualys-log-viewer.html` in any modern browser.

**Current Version:** 1.0.8

## Quick Start

1. Open `qualys-log-viewer.html` in Chrome, Edge, Firefox, or Safari
2. Drag and drop your log files or CAR report CSVs onto the upload zone — or click **Browse Files**
3. The viewer auto-detects the log type and displays parsed, grouped, color-coded entries

## Supported Input Formats

| Format | Description |
|---|---|
| `.log` | Raw Qualys agent log files |
| `.csv` | CAR (Custom Assessment & Remediation) report exports |
| `.zip` | ZIP archives containing log files or nested archives |
| `.tar.gz` / `.tgz` | Gzip or LZMA-compressed tar archives |
| `.gz` | Single gzip-compressed files |
| `.7z` | 7-Zip archives (loaded via CDN on first use) |
| **Folders** | Upload an entire folder of log files |

### REMOTELOG Bundles

The viewer handles Qualys REMOTELOG bundles from both Linux and Windows agents automatically:

- **Linux REMOTELOG** — LZMA-compressed tar archives (`.tar.gz` with LZMA compression, sometimes double-wrapped as LZMA > gzip > tar)
- **Windows REMOTELOG** — ZIP files containing nested 7z archives with agent logs, health checks, MSI logs, and patch management logs

### CAR Job Reports

CAR (Custom Assessment & Remediation) job report CSV exports are fully supported. Each asset in the report gets its own tab with execution status, script output parsing, and the same filtering/search capabilities as raw log files. The asset banner displays host details, technology, agent UUID, execution status, and duration.

## Supported Log Types

| Log Type | Files | Description |
|---|---|---|
| **Cloud Agent** | `qualys-cloud-agent.log` | Main agent lifecycle — CAPI events, scan scheduling, HTTP comms, module status |
| **Scan** | `qualys-cloud-agent-scan.log` | Scan execution — manifest processing, OS matching, command execution with stdout/stderr |
| **CEP** | `qualys-cep.log` | Custom Event Processing — manifest execution, polling, AHS status uploads |
| **Health Check** | `qualys-health-check.log` | Agent diagnostics — system checks, connectivity, proxy config, resource usage |
| **Multiplexer** | `qualys-mux.log` | Multiplexer module activity |
| **Agent ID** | `agentid.log` | Agent identification service (Go logrus format) |
| **CAR Reports** | `.csv` | Custom Assessment & Remediation report exports with per-asset tabs |
| **Windows Logs** | `Log.txt`, `communicationlog.txt`, etc. | Windows agent log files from REMOTELOG bundles |

## Features

### Host Details Banner

When viewing `qualys-cloud-agent.log` files, the viewer automatically extracts host metadata from the CAPI JSON payload and displays a rich details banner:

- **Host** — Computer name
- **OS** — Full OS name and architecture
- **Agent UUID** — Agent identifier
- **Agent Version** — Installed agent version
- **Platform** — Linux or Windows
- **Provider** — Cloud provider (Azure, AWS, GCP) if applicable
- **IPv4** — Primary IP address
- **FQDN** — Fully qualified domain name

When multiple log files are loaded from the same archive, all tabs inherit the host details from the cloud-agent log.

### Toolbar Controls

- **Search** — Real-time partial-match search across all log messages. Multiple words are matched independently (AND logic) — typing `scan manifest` finds lines containing both words anywhere, in any order. Each matching term is highlighted
- **Level Filters** — Filter by All, Trace, Debug, Info, Warning, or Error
- **Redact** — Toggle sensitive data redaction (on by default). Masks CustomerIDs, AgentIDs, IPs, MAC addresses, HMAC tokens, UUIDs in URLs, and FQDN values. Redaction applies to both the log view and the host details banner. Search still works on original values
- **Sort Order** — Toggle between Newest First (default) and Oldest First. Qualys logs are written oldest-to-newest, but troubleshooting usually starts from the latest entries
- **Select** — Enter line selection mode. Checkboxes appear next to each log line for picking individual entries. Use Select All / Deselect All for bulk operations. Export selected lines as a plain-text file with host header info and divider-separated entries. Files are named `hostname_logname_YYYYMMDDHHMMSS.txt`
- **New File** — Reset and load different files (header bar)

### Smart Grouping

Log entries are semantically grouped based on the detected log type:

- **Cloud Agent** — CAPI cycles, scan events, module lifecycle, agent startup/shutdown
- **CEP** — Component lifecycle, manifest execution cycles, polling with retries
- **Health Check** — Individual check sections (CPU, RAM, disk, connectivity, proxy, certificates)
- **Scan** — Manifest processing blocks, command executions, OS mismatch batches (collapsed)
- **Generic** — Time-gap-based grouping (2-second gaps) for unrecognized formats

### JSON Payload Rendering

CAPI request and response payloads are detected automatically. Click the **{JSON}** button to expand a collapsible, syntax-highlighted view with:
- Keys in blue, strings in green, numbers in orange, booleans in purple
- Sensitive fields redacted when redaction is enabled

### Multi-File Tabs

When loading multiple files (via multi-select, folder upload, or archive extraction):
- Each file gets its own tab with the viewer defaulting to `qualys-cloud-agent.log` (Linux) or `Log.txt` (Windows) when available
- Arrow buttons appear at the tab bar edges when tabs overflow the visible area
- Tabs show badge indicators: error count (red), warning count (yellow), or OK (green)
- Files with errors are sorted first

### Performance

- Chunked rendering for files over 5,000 lines with a "Load More" button
- Large log files (50K+ lines) are handled without browser lock-up

## Compression Support

The viewer handles multiple compression formats transparently:

| Format | Method | Notes |
|---|---|---|
| **Gzip** | Inline [fflate](https://github.com/101arrowz/fflate) decoder (MIT) — truncation-tolerant | Standard `.tar.gz` files |
| **LZMA** | Inline JS decoder ([js-lzma](https://github.com/jcmellado/js-lzma), MIT) | Linux REMOTELOG bundles |
| **LZMA > Gzip** | Auto-detected double decompression | Some Linux REMOTELOG formats |
| **Deflate** | Browser-native `DecompressionStream` | ZIP entry extraction |
| **7z / LZMA2** | [7z-wasm](https://github.com/use-strict/7z-wasm) via CDN | Windows REMOTELOG bundles |

The LZMA decoder is embedded inline (no external dependencies). The 7z decoder is loaded from jsDelivr CDN on first use and requires internet access. If CDN is unavailable, the viewer shows manual extraction instructions.

## Auto-Detection

The viewer identifies log types using two methods:

1. **Filename matching** — `qualys-cloud-agent.log` → Cloud Agent, `qualys-cep.log` → CEP, etc.
2. **Content analysis** — Scans the first 200 lines for process names in the log format brackets (e.g., `[qualys-cloud-agent]`, `[cep]`, `[qualys-health-check-tool]`)

Two log line formats are supported:
- **Standard Qualys format**: `YYYY-MM-DD HH:MM:SS.mmm +0000 [process][PID]:[Level]:[ThreadID]:Message`
- **Go logrus format** (agentid.log): `time="..." level=info msg="..."`

## Version Check

On page load, the viewer checks for updates by fetching `version.txt` from the GitHub repository. The header badge shows the result:

| Status | Badge |
|---|---|
| Up to date | ✓ v1.0.3 — Latest (green) |
| Update available | ⚠ vX.X.X Available — Update (yellow, with link) |
| Check blocked | v1.0.3 — Update check unavailable (gray, with help link) |

**Note:** SSL-inspecting proxies (Zscaler, Netskope, corporate firewalls) may block outbound requests to `raw.githubusercontent.com`, preventing the version check. This does not affect any viewer functionality — all log parsing works fully offline. Click the "Update check unavailable" link for details, or check the repository directly for updates.

## Browser Requirements

- Chrome 105+, Edge 105+, Firefox 113+, or Safari 16.4+
- Required APIs: `DecompressionStream`, `File`, `FileReader`, `DataView`
- 7z extraction additionally requires network access to jsDelivr CDN

## License

Apache 2.0

## Credits

- LZMA decoder: [js-lzma](https://github.com/jcmellado/js-lzma) by Juan Mellado (MIT)
- Gzip decoder: [fflate](https://github.com/101arrowz/fflate) by 101arrowz (MIT)
- 7z WASM decoder: [7z-wasm](https://github.com/use-strict/7z-wasm) (LGPL, loaded from CDN)
