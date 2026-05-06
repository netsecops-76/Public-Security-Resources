# Updating Q KB Explorer

## If your in-app update didn't actually take effect

**Symptoms:** you clicked **Apply Update**, the UI returned a success message, but the app still behaves like the previous version — bugs that were supposedly fixed are still happening, or new features aren't visible. The version string in Settings may have advanced, but the running behavior didn't.

This was a real bug in the updater shipped with v2.1.0, and it's fixed in v2.2.0. Short version: gunicorn was started with `--preload`, which makes the master process import the app once and fork workers from that imported copy. The updater killed and respawned workers — but the master still held the old code in memory, so respawned workers re-inherited it. Files on disk got replaced; the running app didn't.

**Your data was never at risk.** All synced QIDs, CIDs, policies, tags, PM patches, credentials, schedules, and saved searches live on Docker volumes completely separate from the application code. Nothing about this bug touches the data volumes — successful or not.

### Recovery (one-time)

The bug is in the *running* code, so the in-app updater cannot fix itself. Run this once on the host where the container lives:

```bash
cd "Q KB Explorer"             # the directory containing docker-compose.yml
git pull origin Q-KB-Explorer
docker compose down
docker compose build --no-cache
docker compose up -d
```

After this rebuild you'll be on v2.2.0 or later. From that point forward, every in-app update lands cleanly and you do not need to rebuild again.

If `git pull` is unavailable on the host (you don't have a local checkout), download the latest tarball directly from the public branch and unpack it over your existing directory before the `docker compose` commands.

---

## How updates work in v2.2.0+

When you click **Apply Update**:

1. The app checks GitHub (`netsecops-76/Public-Security-Resources`, branch `Q-KB-Explorer`) for a newer commit SHA than the one currently deployed.
2. If newer, it downloads the source tarball and reads `update-manifest.json` from it. The manifest controls what the updater does — install dependencies, copy code, fix permissions, and restart.
3. Files are copied into `/app` inside the container.
4. The new commit SHA is recorded.
5. The gunicorn master process exits cleanly (after a 2-second delay so the apply response can flush to your browser).
6. Docker's `restart: unless-stopped` policy brings the container back up. The new entrypoint runs and the new code is imported fresh on the way up.

Total downtime is roughly 5–10 seconds. Refresh your browser once the version string in Settings advances.

The manifest version (currently `2.2.0`) is a human-readable label shown in release notes and the updater response. The "is an update available" check is based on the GitHub commit SHA, not the manifest version — so any commit pushed to the public branch produces an update offer.

---

## Why pre-2.2.0 updates silently failed

In case you want to know what was actually wrong:

- gunicorn was started with `--preload app.main:app`, which is normally a memory-saving optimization. Under `--preload`, the master imports the app once and then forks workers; workers share the imported pages via copy-on-write.
- The updater's restart logic killed every worker process but explicitly spared PID 1 (the master). When the worker pool dropped, the master respawned new workers — by forking itself again. The new workers inherited the master's already-imported (old) app, regardless of what was now on disk.
- Result: file copy succeeded, version SHA advanced, "success" returned to the UI, and the running code was unchanged.

v2.2.0 fixes this in two layers:

- The updater now signals the gunicorn master (PID 1) directly with SIGTERM. Docker's restart policy brings the container back up, the entrypoint runs fresh, and the new code is imported cleanly. If signalling the master fails for any reason, the updater falls back to the previous worker-only kill so the update is still attempted.
- The entrypoint drops `--preload`. Even if a future code path forgets to restart the master, per-worker respawns now re-read disk on their own.

---

## When to use which path

| Situation | What to do |
|-----------|------------|
| You're on v2.2.0+ and there's a new release | **Settings → Apply Update** |
| You're on pre-v2.2.0 (in-app updates aren't taking effect) | **One-time rebuild** — see Recovery above |
| First-time install | `docker compose build && docker compose up -d` |
| You changed `docker-compose.yml` (ports, volumes, TLS) | `docker compose up -d --build` |
| Something looks wrong after any update | `docker compose down && docker compose build --no-cache && docker compose up -d` |

---

## Your data is on separate volumes

Application code lives inside the image and the container's writable layer:

- `/app/` — replaced on rebuild; modified by in-app updates.

User data lives on named Docker volumes:

- `/keys` (volume `qkbe-keys`) — AES-256 vault encryption key.
- `/data` (volume `qkbe-data`) — encrypted credential vault, SQLite database, sync schedules and history.

No update path — successful, failed, or interrupted — touches the volumes. You can run `docker compose down`, `docker compose build --no-cache`, and `docker compose up -d` as many times as you want; the next start reconnects to the same data automatically.

If you ever want to wipe and start over (this *will* delete your data), use `docker compose down -v` to remove the volumes as well.
