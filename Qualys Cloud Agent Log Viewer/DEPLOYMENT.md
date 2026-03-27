# Deployment Guide

The Qualys Cloud Agent Log Viewer is a single HTML file with no build step, no server requirements, and no dependencies (except an optional CDN-loaded 7z decoder for Windows REMOTELOG bundles). It supports raw agent log files, REMOTELOG bundles, and CAR (Custom Assessment & Remediation) job report CSV exports. This makes deployment straightforward across a variety of environments.

## Quick Deploy Options

### Option 1: Local File (Simplest)

Download `qualys-log-viewer.html` and open it directly in a browser.

```
# Download from GitHub
curl -LO https://github.com/netsecops-76/Public-Security-Resources/raw/Qualys-Cloud-Agent-Log-Viewer/Qualys%20Cloud%20Agent%20Log%20Viewer/qualys-log-viewer.html

# Open in default browser
open qualys-log-viewer.html        # macOS
xdg-open qualys-log-viewer.html    # Linux
start qualys-log-viewer.html       # Windows
```

All features work from `file://` except 7z extraction (which requires CDN access). Linux REMOTELOG bundles (LZMA/gzip) work fully offline.

### Option 2: Internal Web Server

Host on any static file server for team access.

**Python (quick test)**
```bash
cd /path/to/qualys-log-viewer
python3 -m http.server 8080
# Visit http://localhost:8080/qualys-log-viewer.html
```

**Nginx**
```nginx
server {
    listen 8080;
    server_name qualys-logs.internal;
    root /opt/qualys-log-viewer;
    index qualys-log-viewer.html;

    # Cache the HTML but allow updates
    location / {
        expires 1h;
        add_header Cache-Control "public, must-revalidate";
    }
}
```

**Apache**
```apache
<VirtualHost *:8080>
    DocumentRoot /opt/qualys-log-viewer
    DirectoryIndex qualys-log-viewer.html
</VirtualHost>
```

**IIS** — Drop `qualys-log-viewer.html` into any IIS site directory. No configuration needed.

### Option 3: GitHub Pages

1. Fork or clone the repository
2. Go to **Settings > Pages**
3. Set source to **Deploy from a branch** > `Qualys-Cloud-Agent-Log-Viewer` > `/ (root)`
4. Access at `https://<username>.github.io/Public-Security-Resources/Qualys%20Cloud%20Agent%20Log%20Viewer/qualys-log-viewer.html`

### Option 4: SharePoint / OneDrive

1. Upload `qualys-log-viewer.html` to a SharePoint document library or OneDrive folder
2. Share the link with your team
3. Users download and open locally — or embed via an iframe if your tenant allows HTML rendering

### Option 5: S3 / Azure Blob / GCS Static Hosting

**AWS S3**
```bash
aws s3 cp qualys-log-viewer.html s3://your-bucket/ --content-type "text/html"
aws s3 website s3://your-bucket/ --index-document qualys-log-viewer.html
```

**Azure Blob Storage**
```bash
az storage blob upload --container-name '$web' \
  --file qualys-log-viewer.html \
  --name qualys-log-viewer.html \
  --content-type "text/html" \
  --account-name yourstorageaccount
```

## Network Requirements

| Feature | Network Access | Notes |
|---|---|---|
| Core viewer | None | All parsing, filtering, grouping works offline |
| Linux REMOTELOG (LZMA) | None | LZMA decoder is embedded inline |
| ZIP / tar.gz / gzip | None | Browser-native decompression |
| Windows REMOTELOG (7z) | jsDelivr CDN | Loads ~80KB JS + ~1.6MB WASM on first 7z file |
| Version check | `raw.githubusercontent.com` | Fetches `version.txt` on page load to check for updates |

### Air-Gapped / Offline Environments

For environments without internet access, Windows REMOTELOG 7z bundles will show a fallback message with manual extraction instructions. Users can pre-extract 7z archives using 7-Zip before uploading the raw log files.

To make 7z work offline, you could self-host the WASM decoder:

1. Download the 7z-wasm files:
   ```bash
   curl -LO https://cdn.jsdelivr.net/npm/7z-wasm@1.2.0/7zz.umd.js
   curl -LO https://cdn.jsdelivr.net/npm/7z-wasm@1.2.0/7zz.wasm
   ```

2. Host them alongside `qualys-log-viewer.html`

3. Update the CDN URLs in the HTML file:
   ```
   Find:    https://cdn.jsdelivr.net/npm/7z-wasm@1.2.0/
   Replace: ./
   ```

## Security Considerations

### Data Privacy

- **All processing is client-side.** Log data never leaves the user's browser. No data is sent to any server.
- **Redaction is on by default.** Sensitive fields (CustomerIDs, AgentIDs, IPs, MAC addresses, HMAC tokens) are masked in the display. This protects against accidental exposure in screenshots or screen shares.
- **The 7z WASM decoder is loaded from jsDelivr CDN.** Only the decoder code is fetched — no log data is transmitted. If this is a concern, self-host the WASM files (see above).

### Content Security Policy

If deploying behind a CSP, you need to allow:

```
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
connect-src 'self' https://cdn.jsdelivr.net https://raw.githubusercontent.com;
```

- Remove `cdn.jsdelivr.net` if you self-host the 7z-wasm files
- Remove `raw.githubusercontent.com` if you don't need the automatic version check

### File Size

The HTML file is approximately 166KB (includes embedded LZMA and fflate gzip decoders, plus parsers for all Windows log formats) — small enough to email, embed in wikis, or distribute via any file sharing method.

## Version Check & Updating

The viewer includes an automatic version check. On page load, it fetches `version.txt` from the GitHub repository and compares it to the embedded `APP_VERSION`. If a newer version is available, a yellow badge appears in the header with a link to the repository.

**SSL-inspecting proxies** (Zscaler, Netskope, corporate firewalls) may block the request to `raw.githubusercontent.com`. When this happens, the badge shows "Update check unavailable" with a link to the Help panel explaining the issue. No viewer functionality is affected.

Since it's a single file, updating is just replacing `qualys-log-viewer.html` and `version.txt`:

```bash
# Pull latest from GitHub
cd /path/to/qualys-log-viewer
git pull origin Qualys-Cloud-Agent-Log-Viewer

# Or download directly
curl -LO https://github.com/netsecops-76/Public-Security-Resources/raw/Qualys-Cloud-Agent-Log-Viewer/Qualys%20Cloud%20Agent%20Log%20Viewer/qualys-log-viewer.html
```

When releasing a new version:
1. Update the `APP_VERSION` constant in `qualys-log-viewer.html`
2. Update `version.txt` to match
3. Commit and push both files

## Embedding in Other Tools

The viewer can be embedded in internal portals or documentation sites via iframe:

```html
<iframe src="qualys-log-viewer.html"
        style="width:100%; height:800px; border:1px solid #333; border-radius:8px;"
        allow="clipboard-read; clipboard-write">
</iframe>
```

Note: File drag-and-drop into iframes may require the `allow` attribute and same-origin hosting.

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Blank page | Old browser | Use Chrome 105+, Edge 105+, Firefox 113+, Safari 16.4+ |
| "No supported files found" | Wrong file type | Use `.log`, `.csv`, `.zip`, `.tar.gz`, or `.gz` files |
| 7z extraction fails | No internet / CDN blocked | Pre-extract 7z files with 7-Zip, or self-host the WASM decoder |
| Large file is slow | File > 50K lines | Use level filters to reduce visible lines. Groups auto-collapse after 500 lines |
| CORS error in iframe | Cross-origin hosting | Host the HTML on the same origin as the parent page |
| "Update check unavailable" | Proxy blocking GitHub | Zscaler/Netskope/corporate proxy blocking `raw.githubusercontent.com`. No impact on functionality. Check the repo directly for updates |
| Host details not showing | Not a cloud-agent log | CAPI host details are only available in `qualys-cloud-agent.log`. Other log types show the summary banner only |
