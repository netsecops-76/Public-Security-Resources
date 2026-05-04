# Updating Q KB Explorer

## Important Notice

We apologize for the inconvenience — the previous in-app update mechanism had issues that could leave the application in a partially broken state after updating. **Your data was never at risk.** All synced QIDs, CIDs, policies, tags, PM patches, credentials, and schedules are stored on a Docker volume that is completely separate from the application code. No update — successful or failed — touches your data.

If you ran the in-app updater and experienced issues (missing pages, 404 errors, "permission denied" on restart, or partially loaded features), follow the recovery steps below to restore full operation.

---

## Recovery: If You Ran the Old Updater and Things Broke

Your data is safe. Run these two commands to rebuild the app with the latest code:

```bash
docker compose build --no-cache
docker compose up -d
```

That's it. The container rebuilds from scratch with the current version, your data volume reconnects, and everything works.

---

## How Updates Work Now (v2.1.0+)

We've completely rebuilt the update mechanism to prevent these issues going forward. The new system is **manifest-driven** — each release ships with an `update-manifest.json` that tells the updater exactly what to do.

### What Changed

| Before (old updater) | After (manifest-driven) |
|---------------------|------------------------|
| Hardcoded logic that couldn't adapt to new requirements | Manifest from the NEW version controls the update |
| Dependencies installed AFTER code was replaced (caused import errors) | Dependencies installed BEFORE code is replaced |
| SIGHUP reload kept cached failed imports | Workers killed and respawned fresh |
| entrypoint.sh copied without execute permission | Explicit `chmod +x` step in manifest |
| No verification — update assumed success | App import verified, self-heal if broken |

### The Manifest

Each release includes `update-manifest.json` that defines the exact update steps:

```json
{
  "version": "2.1.0",
  "steps": [
    {"action": "copy_file", "src": "requirements.txt", "dst": "requirements.txt"},
    {"action": "pip_install", "args": "-r requirements.txt"},
    {"action": "copy_dir", "src": "app", "dst": "app"},
    {"action": "copy_file", "src": "entrypoint.sh", "dst": "entrypoint.sh"},
    {"action": "run_command", "cmd": "chmod +x /app/entrypoint.sh"},
    {"action": "copy_file", "src": "update-manifest.json", "dst": "update-manifest.json"},
    {"action": "restart"}
  ]
}
```

This means:
- **New dependencies are always installed first** — the app never loads without its requirements
- **Docker-only files (Dockerfile, docker-compose.yml) are never touched** — your container config stays stable
- **The entrypoint gets updated with self-heal logic** — if anything goes wrong on the next restart, it auto-installs missing packages
- **Future releases can add custom steps** — database migrations, config changes, cleanup tasks — without changing the updater code

### Self-Healing Startup

The entrypoint now includes a pre-flight check:

```bash
python3 -c "from app.main import app" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[QKBE] App import failed — installing dependencies..."
    pip install --no-cache-dir -r /app/requirements.txt
fi
```

If the app fails to load (missing packages, broken imports), it automatically installs dependencies before starting Gunicorn. This catches edge cases that the update itself might miss.

---

## One-Time Setup (First Time on v2.1.0)

If you're coming from an older version (pre-v2.1.0), you need ONE container rebuild to get the new update infrastructure:

```bash
# Pull the latest code and rebuild
cd "Q KB Explorer"
git pull origin Q-KB-Explorer
docker compose build --no-cache
docker compose up -d
```

After this single rebuild, all future updates work through the Settings → Update UI without ever needing to rebuild again.

---

## Using the In-App Updater

1. Open **Settings** tab
2. Scroll to **Application Updates**
3. Click **Check for Updates**
4. If an update is available, click **Apply Update**
5. The app restarts automatically — refresh your browser

The update typically completes in 2–5 seconds.

---

## When to Rebuild vs. When to Use In-App Update

| Scenario | Action |
|----------|--------|
| Regular updates (new features, bug fixes) | **In-app updater** — Settings → Apply Update |
| First time setting up Q KB Explorer | `docker compose build && docker compose up -d` |
| Coming from a version before v2.1.0 | **One-time rebuild** (see above), then in-app updates work |
| Something went wrong after an update | `docker compose build --no-cache && docker compose up -d` |
| Changing Docker configuration (ports, volumes, TLS) | Edit `docker-compose.yml` then rebuild |

---

## Your Data is Always Safe

The application code (`/app/`) and your data (`/data/`) live in completely separate locations:

- **Code**: Baked into the Docker image at build time, replaced during in-app updates
- **Data**: On a named Docker volume (`qkbe-data`) that persists across builds, updates, and container restarts

No update process — whether successful, failed, or interrupted — can corrupt or delete your:
- Synced QIDs, CIDs, policies, mandates, tags, PM patches
- Saved credentials and vault encryption key
- Sync schedules and history
- Tag exports, migration reports, audit results
- Intelligence saved searches

Even if you completely delete and rebuild the container, your data reconnects automatically on the next start.
