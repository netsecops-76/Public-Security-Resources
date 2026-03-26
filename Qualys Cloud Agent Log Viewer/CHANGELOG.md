# Changelog

All notable changes to the Qualys Cloud Agent Log Viewer are documented here.

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
