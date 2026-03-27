# Changelog

All notable changes to the Qualys Cloud Agent Log Viewer are documented here.

## [1.0.9] - 2026-03-27

### Added
- Date/time range slider filter — dual-handle slider below the summary banner for narrowing log views by time range
- Windows cloud agent log parser (`Log.txt`) — structured timestamp, level, PID, thread, component columns
- CloudAgentInstaller.log parser — bracket-delimited timestamp with Info/Verbose/Warning/Error levels
- Sync.log parser — ISO 8601 nanosecond timestamps with single-char level codes (I/W/E/D/V/S)
- MSI verbose log parser — extracts date from header, timestamps from `[HH:MM:SS:fff]` brackets
- Health check JSON pretty-printer with syntax highlighting and green/red status indicators
- Health check TXT structured renderer with section headers, numbered checks, and Pass/Fail color coding
- Directory listing table renderer for datadir.txt/installdir.txt with file icons, human-readable sizes, and truncated hashes
- Cached `tsMs` (millisecond timestamp) on every parsed line for faster filtering and grouping

### Fixed
- BOM replacement characters (`\uFFFD`) stripped from line starts — fixes first-line parsing failures on Windows UTF-16 encoded logs
- Tab bar scroll arrows and time slider arrows now use matching warm gold color
- Help modal link color improved for readability on dark background

## [1.0.8] - 2026-03-26

### Added
- Auto-update download — click "Update" to open a dropdown with "Download Now" or "Go to GitHub"
- Hosting context detection — shows current file path or server URL to guide update placement
- Versioned download filenames (e.g., `qualys-log-viewer-1.0.8.html`) to avoid file locking and cache issues
- Post-download badge shows the filename and prompts user to open the new file

## [1.0.7] - 2026-03-26

### Added
- Tab bar scroll arrows — left/right navigation arrows appear when log tabs overflow the visible area
- Default tab selection — automatically opens `qualys-cloud-agent.log` (Linux) or `log.txt` (Windows) on load
- Line selection mode — toggle checkboxes on individual log lines to select specific entries
- Plain-text export — export selected lines with host header info, each separated by divider lines
- Select button toggles to "Cancel" label when in selection mode

### Removed
- Duplicate "New File" button from toolbar mid-screen (header button remains)

## [1.0.6] - 2026-03-26

### Added
- Smarter version check with N-behind indicator (N-1, N-2, etc.) showing how many versions behind
- Semantic version comparison replacing simple string equality check
- Multi-line `version.txt` format tracking full version history
- This changelog

## [1.0.5] - 2026-03-26

### Fixed
- Truncated Linux REMOTELOG gzip decompression now uses embedded fflate v0.8.2
- DecompressionStream discarded buffered output on truncation errors (~327KB recovered); fflate streaming Gunzip recovers all data up to truncation point (~20MB)
- Help section updated to reflect fflate decompression details

## [1.0.4] - 2026-03-25

### Fixed
- Windows agent log CAPI extraction and UTF-16 handling
- CAR (Custom Assessment & Remediation) job report CSV support documented

## [1.0.3] - 2026-03-25

### Added
- Host details extraction from CAPI payload displayed in log banner
- Automatic version check against GitHub repository with update badge
- Offline notice when version check is blocked by SSL-inspecting proxy (Zscaler, Netskope)

### Improved
- Search now supports multi-term partial matching

## [1.0.2] - 2026-03-25

### Added
- Multi-format file handling for .log, .zip, .tar.gz, .gz, and .csv
- New File button in header for loading additional files
- Expanded log format support

## [1.0.1] - 2026-03-25

### Fixed
- New File button repositioned next to title
- Button visibility fix on file load

## [1.0.0] - 2026-03-25

### Added
- Initial release of Qualys Cloud Agent Log Viewer
- Single-file HTML tool for parsing Qualys Cloud Agent log files
- Drag-and-drop file upload with folder support
- Smart log grouping by source file and log level
- Color-coded log levels (ERROR, WARN, INFO, DEBUG, VERBOSE)
- Full-text search with highlighting
- Automatic redaction of sensitive fields (CustomerIDs, AgentIDs, IPs, MACs, HMAC tokens)
- REMOTELOG bundle support for Linux (LZMA + gzip + tar) and Windows (7z via CDN)
- ZIP and tar.gz archive extraction
- Responsive dark theme UI
