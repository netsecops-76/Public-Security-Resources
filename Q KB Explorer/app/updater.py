"""
Q KB Explorer — Manifest-Driven Application Updater

Checks the public GitHub repository for new versions and applies updates
using an update-manifest.json that ships WITH each release. The manifest
tells the updater exactly what to copy, what to skip, and what commands
to run — so the update logic is always controlled by the NEW version,
not the old one running the update.

Source: https://github.com/netsecops-76/Public-Security-Resources
Branch: Q-KB-Explorer
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time

import requests

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────
REPO_OWNER = "netsecops-76"
REPO_NAME = "Public-Security-Resources"
BRANCH = "Q-KB-Explorer"
API_BASE = "https://api.github.com"

# File to track current version (commit SHA)
VERSION_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".current_version")
APP_DIR = os.path.dirname(os.path.dirname(__file__))  # /app

# Updater protocol version — if the manifest requires a higher version,
# the update is rejected with a message to rebuild the container.
UPDATER_VERSION = 2


def get_current_version() -> str | None:
    """Read the currently deployed commit SHA."""
    if os.path.exists(VERSION_FILE):
        return open(VERSION_FILE).read().strip()
    return None


def _save_version(sha: str):
    """Write the deployed commit SHA to disk."""
    with open(VERSION_FILE, "w") as f:
        f.write(sha)


def check_for_updates() -> dict:
    """Check GitHub for new commits on the Q-KB-Explorer branch."""
    try:
        url = f"{API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/branches/{BRANCH}"
        resp = requests.get(url, timeout=15, headers={"Accept": "application/vnd.github.v3+json"})
        resp.raise_for_status()
        data = resp.json()

        latest_sha = data["commit"]["sha"]
        latest_msg = data["commit"]["commit"]["message"].split("\n")[0]
        latest_date = data["commit"]["commit"]["committer"]["date"]

        current = get_current_version()
        update_available = current is None or current != latest_sha

        result = {
            "update_available": update_available,
            "current": current,
            "latest": latest_sha,
            "latest_short": latest_sha[:8],
            "latest_message": latest_msg,
            "latest_date": latest_date,
        }

        if current and update_available:
            try:
                compare_url = f"{API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/compare/{current}...{latest_sha}"
                compare_resp = requests.get(compare_url, timeout=15,
                                            headers={"Accept": "application/vnd.github.v3+json"})
                if compare_resp.status_code == 200:
                    result["commits_behind"] = compare_resp.json().get("total_commits", 0)
            except Exception:
                result["commits_behind"] = None
        else:
            result["commits_behind"] = 0

        return result

    except requests.RequestException as e:
        logger.error("[Updater] GitHub API check failed: %s", e)
        return {"update_available": False, "error": str(e)}


def apply_update() -> dict:
    """
    Download and apply update using the manifest from the NEW version.

    The manifest (update-manifest.json) ships with each release and
    tells this updater exactly what to do. This means:
    - New dependencies are always installed (manifest says so)
    - Docker-only files are never copied (manifest excludes them)
    - Custom pre/post steps can be added per-release
    - The old updater doesn't need to know anything about the new version
    """
    t0 = time.time()
    steps_completed = []

    try:
        # Step 1: Check for update
        logger.info("[Updater] Checking latest version...")
        info = check_for_updates()
        if info.get("error"):
            return {"status": "error", "error": info["error"]}
        if not info.get("update_available"):
            return {"status": "ok", "message": "Already up to date", "version": info.get("current")}

        latest_sha = info["latest"]
        logger.info("[Updater] Downloading version %s...", latest_sha[:8])

        # Step 2: Download and extract tarball
        tarball_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/archive/{BRANCH}.tar.gz"
        resp = requests.get(tarball_url, timeout=120, stream=True)
        resp.raise_for_status()

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            for chunk in resp.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name

        extract_dir = tempfile.mkdtemp()
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(extract_dir)

        entries = os.listdir(extract_dir)
        if len(entries) != 1:
            raise RuntimeError(f"Unexpected tarball structure: {entries}")
        repo_root = os.path.join(extract_dir, entries[0])
        steps_completed.append("download")

        # Step 3: Find the project directory and load manifest
        # Try both root and nested "Q KB Explorer/" path
        project_dir = repo_root
        manifest_path = os.path.join(project_dir, "update-manifest.json")
        if not os.path.exists(manifest_path):
            project_dir = os.path.join(repo_root, "Q KB Explorer")
            manifest_path = os.path.join(project_dir, "update-manifest.json")

        if not os.path.exists(manifest_path):
            # Fallback: no manifest — use legacy behavior
            logger.warning("[Updater] No update-manifest.json found. Using legacy update.")
            return _legacy_apply(project_dir, latest_sha, info, t0)

        with open(manifest_path) as f:
            manifest = json.load(f)

        logger.info("[Updater] Manifest loaded: version=%s, %d steps",
                    manifest.get("version", "?"), len(manifest.get("steps", [])))

        # Step 4: Check updater version compatibility
        min_version = manifest.get("min_updater_version", 1)
        if min_version > UPDATER_VERSION:
            return {
                "status": "error",
                "error": (
                    f"This update requires updater version {min_version} but you have "
                    f"version {UPDATER_VERSION}. Please rebuild the Docker container "
                    f"manually: docker compose build --no-cache && docker compose up -d"
                ),
            }

        # Step 5: Execute manifest steps
        for i, step in enumerate(manifest.get("steps", [])):
            action = step.get("action")
            logger.info("[Updater] Step %d/%d: %s", i + 1, len(manifest["steps"]), action)

            if action == "copy_dir":
                src = os.path.join(project_dir, step["src"])
                dst = os.path.join(APP_DIR, step["dst"])
                if not os.path.isdir(src):
                    raise RuntimeError(f"copy_dir: source not found: {src}")
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                steps_completed.append(f"copy_dir:{step['dst']}")

            elif action == "copy_file":
                src = os.path.join(project_dir, step["src"])
                dst = os.path.join(APP_DIR, step["dst"])
                if os.path.exists(src):
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
                    steps_completed.append(f"copy_file:{step['dst']}")
                elif step.get("required", False):
                    raise RuntimeError(f"copy_file: required file not found: {src}")

            elif action == "pip_install":
                args = step.get("args", "-r requirements.txt")
                cmd = f"pip install --no-cache-dir {args}"
                logger.info("[Updater] Running: %s", cmd)
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True, text=True, timeout=180,
                    cwd=APP_DIR,
                )
                if result.returncode != 0:
                    logger.warning("[Updater] pip install returned %d: %s",
                                   result.returncode, result.stderr[:500])
                steps_completed.append("pip_install")

            elif action == "run_command":
                cmd = step["cmd"]
                logger.info("[Updater] Running command: %s", cmd)
                subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=step.get("timeout", 60), cwd=APP_DIR,
                )
                steps_completed.append(f"run_command:{cmd[:30]}")

            elif action == "restart":
                # Save version before restart
                _save_version(latest_sha)
                steps_completed.append("save_version")
                # Cleanup temp files
                os.remove(tmp_path)
                shutil.rmtree(extract_dir)
                # Restart
                logger.info("[Updater] Restarting Gunicorn...")
                _restart_gunicorn()
                steps_completed.append("restart")

            else:
                logger.warning("[Updater] Unknown action '%s' — skipping", action)

        # If no restart step in manifest, save version and cleanup anyway
        if "restart" not in [s.get("action") for s in manifest.get("steps", [])]:
            _save_version(latest_sha)
            os.remove(tmp_path)
            shutil.rmtree(extract_dir)

        duration = round(time.time() - t0, 1)
        logger.info("[Updater] Update complete in %.1fs — %s", duration, latest_sha[:8])

        return {
            "status": "ok",
            "version": latest_sha,
            "version_short": latest_sha[:8],
            "message": info.get("latest_message", ""),
            "manifest_version": manifest.get("version"),
            "steps_completed": steps_completed,
            "duration_s": duration,
        }

    except Exception as e:
        duration = round(time.time() - t0, 1)
        logger.error("[Updater] Update failed after %.1fs at step '%s': %s",
                     duration, steps_completed[-1] if steps_completed else "init", e)
        return {
            "status": "error",
            "error": str(e),
            "steps_completed": steps_completed,
            "duration_s": duration,
        }


def _legacy_apply(project_dir: str, latest_sha: str, info: dict, t0: float) -> dict:
    """Fallback for repos without update-manifest.json."""
    src_app = os.path.join(project_dir, "app")
    dst_app = os.path.join(APP_DIR, "app")
    if not os.path.isdir(src_app):
        return {"status": "error", "error": f"No app/ found in {os.listdir(project_dir)}"}

    shutil.rmtree(dst_app)
    shutil.copytree(src_app, dst_app)

    src_reqs = os.path.join(project_dir, "requirements.txt")
    dst_reqs = os.path.join(APP_DIR, "requirements.txt")
    if os.path.exists(src_reqs):
        shutil.copy2(src_reqs, dst_reqs)
        try:
            subprocess.run(["pip", "install", "--no-cache-dir", "-r", dst_reqs],
                           capture_output=True, text=True, timeout=120)
        except Exception as e:
            logger.warning("[Updater] Legacy pip install: %s", e)

    _save_version(latest_sha)
    _restart_gunicorn()

    return {
        "status": "ok",
        "version": latest_sha,
        "version_short": latest_sha[:8],
        "message": info.get("latest_message", ""),
        "duration_s": round(time.time() - t0, 1),
        "legacy": True,
    }


def _restart_gunicorn():
    """Restart Gunicorn workers to load new code.

    SIGHUP alone doesn't work reliably when the initial import failed
    (cached import error in worker). Instead:
    1. Send SIGUSR2 to spawn a new master process
    2. Then SIGTERM old workers so fresh ones load the new code

    If that fails, fall back to SIGHUP which at least tries a graceful reload.
    """
    try:
        # Kill all worker processes (not PID 1 master) — forces fresh spawn
        import subprocess
        result = subprocess.run(
            ["python3", "-c",
             "import os,signal; "
             "[os.kill(int(p), signal.SIGTERM) "
             "for p in os.listdir('/proc') "
             "if p.isdigit() and int(p) != 1 and int(p) != os.getpid()]"],
            capture_output=True, text=True, timeout=5,
        )
        logger.info("[Updater] Worker processes terminated — master will respawn them")
    except Exception as e:
        # Fallback: SIGHUP
        logger.warning("[Updater] Worker kill failed (%s), trying SIGHUP", e)
        try:
            os.kill(1, signal.SIGHUP)
        except Exception:
            pass
