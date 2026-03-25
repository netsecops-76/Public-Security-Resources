"""
Q KB Explorer — Application Updater

Checks the public GitHub repository for new versions and applies updates
by downloading the source tarball, extracting, and restarting Gunicorn.

Source: https://github.com/netsecops-76/Public-Security-Resources
Branch: Q-KB-Explorer
"""
from __future__ import annotations

import hashlib
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
    """
    Check GitHub for new commits on the Q-KB-Explorer branch.

    Returns:
        {"update_available": bool, "current": str|None, "latest": str,
         "latest_message": str, "latest_date": str, "commits_behind": int}
    """
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

        # Count commits behind (if we have a current version)
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
    Download and apply the latest version from GitHub.

    Steps:
    1. Download tarball of the Q-KB-Explorer branch
    2. Extract to temp directory
    3. Copy app/ files over current installation
    4. Install any new pip requirements
    5. Save new version SHA
    6. Restart Gunicorn worker via SIGHUP

    Returns: {"status": "ok"|"error", "version": str, ...}
    """
    t0 = time.time()

    try:
        # Step 1: Get latest SHA
        logger.info("[Updater] Checking latest version...")
        info = check_for_updates()
        if info.get("error"):
            return {"status": "error", "error": info["error"]}
        if not info.get("update_available"):
            return {"status": "ok", "message": "Already up to date", "version": info.get("current")}

        latest_sha = info["latest"]
        logger.info("[Updater] Downloading version %s...", latest_sha[:8])

        # Step 2: Download tarball
        tarball_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/archive/{BRANCH}.tar.gz"
        resp = requests.get(tarball_url, timeout=60, stream=True)
        resp.raise_for_status()

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            for chunk in resp.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name

        # Step 3: Extract
        logger.info("[Updater] Extracting update...")
        extract_dir = tempfile.mkdtemp()
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(extract_dir)

        # Find the extracted directory (GitHub tarballs have a top-level dir)
        entries = os.listdir(extract_dir)
        if len(entries) != 1:
            raise RuntimeError(f"Unexpected tarball structure: {entries}")
        source_dir = os.path.join(extract_dir, entries[0])

        # Step 4: Navigate into the project subdirectory
        # The tarball extracts as: Public-Security-Resources-Q-KB-Explorer/Q KB Explorer/app/
        # We need to find the subdirectory containing app/
        src_app = os.path.join(source_dir, "app")
        project_dir = source_dir
        if not os.path.isdir(src_app):
            # Look for app/ inside a subdirectory (e.g. "Q KB Explorer/app/")
            for entry in os.listdir(source_dir):
                candidate = os.path.join(source_dir, entry, "app")
                if os.path.isdir(candidate):
                    project_dir = os.path.join(source_dir, entry)
                    src_app = candidate
                    logger.info("[Updater] Found app/ in subdirectory: %s", entry)
                    break
            else:
                raise RuntimeError(
                    f"No app/ directory found in update. "
                    f"Top-level contents: {os.listdir(source_dir)}"
                )

        dst_app = os.path.join(APP_DIR, "app")
        logger.info("[Updater] Applying update: %s → %s", src_app, dst_app)
        # Remove old app dir and replace with new
        shutil.rmtree(dst_app)
        shutil.copytree(src_app, dst_app)

        # Also copy root-level files if present (requirements.txt, Dockerfile, etc.)
        for root_file in ("requirements.txt", "Dockerfile", "docker-compose.yml", "entrypoint.sh"):
            src_file = os.path.join(project_dir, root_file)
            dst_file = os.path.join(APP_DIR, root_file)
            if os.path.exists(src_file):
                shutil.copy2(src_file, dst_file)

        # Step 5: Install new requirements (if any changed)
        logger.info("[Updater] Installing dependencies...")
        try:
            subprocess.run(
                ["pip", "install", "--no-cache-dir", "-r", dst_reqs],
                capture_output=True, text=True, timeout=120,
            )
        except Exception as e:
            logger.warning("[Updater] pip install warning: %s", e)

        # Step 6: Save version
        _save_version(latest_sha)

        # Cleanup
        os.remove(tmp_path)
        shutil.rmtree(extract_dir)

        duration = round(time.time() - t0, 1)
        logger.info("[Updater] Update applied in %.1fs — version %s", duration, latest_sha[:8])

        # Step 7: Restart Gunicorn
        logger.info("[Updater] Restarting Gunicorn workers...")
        _restart_gunicorn()

        return {
            "status": "ok",
            "version": latest_sha,
            "version_short": latest_sha[:8],
            "message": info.get("latest_message", ""),
            "duration_s": duration,
        }

    except Exception as e:
        duration = round(time.time() - t0, 1)
        logger.error("[Updater] Update failed after %.1fs: %s", duration, e)
        return {"status": "error", "error": str(e), "duration_s": duration}


def _restart_gunicorn():
    """Send SIGHUP to the Gunicorn master process to gracefully reload workers."""
    try:
        # Gunicorn master is PID 1 in Docker
        os.kill(1, signal.SIGHUP)
        logger.info("[Updater] SIGHUP sent to Gunicorn master (PID 1)")
    except Exception as e:
        logger.warning("[Updater] Failed to send SIGHUP: %s — container restart may be needed", e)
