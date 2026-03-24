from __future__ import annotations

"""
Server-Side Credential Vault
Built by netsecops-76

Encrypted credential storage using AES-256-GCM.
Key and vault are stored on separate Docker volumes for defense in depth:
  - /keys/.vault_key.bin  (hidden file, 0600 permissions, 32-byte random key)
  - /data/vault.json      (encrypted credential entries)

An attacker needs access to BOTH volumes to decrypt stored passwords.

The encryption key is auto-generated on first container startup and reused
on subsequent starts. Deleting the key volume makes all stored passwords
permanently unrecoverable.
"""

import os
import json
import secrets
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Volume Paths ────────────────────────────────────────────────────────────
# Key and vault on separate volumes for defense in depth.
# Override via environment variables if needed.
KEY_DIR = os.environ.get("QAE_KEY_DIR", "/keys")
DATA_DIR = os.environ.get("QAE_DATA_DIR", "/data")

KEY_FILE = os.path.join(KEY_DIR, ".vault_key.bin")   # Hidden file
VAULT_FILE = os.path.join(DATA_DIR, "vault.json")

# ─── AES-256-GCM Key Management ─────────────────────────────────────────────

_cached_key = None  # In-memory cache — avoids repeated disk reads


def _ensure_dirs():
    """Create key and data directories if they don't exist."""
    os.makedirs(KEY_DIR, mode=0o700, exist_ok=True)
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)


def _load_or_generate_key():
    """Load existing key from disk or generate a new random 256-bit key."""
    global _cached_key
    if _cached_key is not None:
        return _cached_key

    _ensure_dirs()

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) == 32:
            _cached_key = key
            return key
        # Invalid key file — regenerate
        os.remove(KEY_FILE)

    # Generate new random 256-bit (32-byte) key
    key = secrets.token_bytes(32)

    # Write with restrictive permissions: owner-read-only (0400)
    # Use os.open + os.fdopen for atomic permission setting
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)

    # Lock down to read-only after write
    os.chmod(KEY_FILE, 0o400)

    _cached_key = key
    return key


def _encrypt(plaintext: str) -> dict:
    """Encrypt a string with AES-256-GCM. Returns dict with iv + ciphertext (hex)."""
    key = _load_or_generate_key()
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)  # 96-bit IV for GCM
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return {
        "iv": iv.hex(),
        "ct": ciphertext.hex()
    }


def _decrypt(enc: dict) -> str:
    """Decrypt an AES-256-GCM encrypted dict back to plaintext string."""
    key = _load_or_generate_key()
    aesgcm = AESGCM(key)
    iv = bytes.fromhex(enc["iv"])
    ciphertext = bytes.fromhex(enc["ct"])
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


# ─── Vault CRUD ─────────────────────────────────────────────────────────────

def _load_vault() -> list:
    """Load vault entries from disk. Returns empty list if file doesn't exist."""
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def _save_vault(vault: list):
    """Write vault entries to disk."""
    _ensure_dirs()
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=2)
    os.chmod(VAULT_FILE, 0o600)


def list_credentials() -> list:
    """List all credentials (without passwords). Safe for API response."""
    vault = _load_vault()
    return [{
        "id": c["id"],
        "username": c["username"],
        "platform": c.get("platform", ""),
        "display_name": c.get("display_name", ""),
        "api_version": c.get("api_version", "v5"),
        "created": c.get("created", ""),
        "updated": c.get("updated", "")
    } for c in vault]


def save_credential(username: str, password: str, platform: str = "",
                     api_version: str = "v5",
                     display_name: str = "") -> dict:
    """Save or update a credential. Password is encrypted before storage."""
    vault = _load_vault()
    enc_pw = _encrypt(password)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Check for existing username+platform combo — update if found
    existing = next(
        (i for i, c in enumerate(vault)
         if c["username"] == username and c.get("platform", "") == platform),
        None
    )

    if existing is not None:
        vault[existing]["encrypted_password"] = enc_pw
        vault[existing]["api_version"] = api_version
        vault[existing]["display_name"] = display_name
        vault[existing]["updated"] = now
        cred_id = vault[existing]["id"]
    else:
        cred_id = secrets.token_hex(8)
        vault.append({
            "id": cred_id,
            "username": username,
            "encrypted_password": enc_pw,
            "platform": platform,
            "display_name": display_name,
            "api_version": api_version,
            "created": now,
            "updated": now
        })

    _save_vault(vault)
    return {"id": cred_id, "username": username, "platform": platform,
            "display_name": display_name, "api_version": api_version}


def update_credential(cred_id: str, **fields) -> dict | None:
    """Update metadata on an existing credential (without re-encrypting password).

    Accepted fields: platform, api_version, display_name.
    Returns the updated credential summary or None if not found.
    """
    vault = _load_vault()
    cred = next((c for c in vault if c["id"] == cred_id), None)
    if cred is None:
        return None

    allowed = {"platform", "api_version", "display_name"}
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    changed = False
    for key, val in fields.items():
        if key in allowed and val is not None:
            cred[key] = val
            changed = True
    if changed:
        cred["updated"] = now
        _save_vault(vault)

    return {
        "id": cred["id"],
        "username": cred["username"],
        "platform": cred.get("platform", ""),
        "display_name": cred.get("display_name", ""),
        "api_version": cred.get("api_version", "v5"),
    }


def delete_credential(cred_id: str) -> bool:
    """Delete a credential by ID. Returns True if found and deleted."""
    vault = _load_vault()
    original_len = len(vault)
    vault = [c for c in vault if c["id"] != cred_id]
    if len(vault) == original_len:
        return False
    _save_vault(vault)
    return True


def get_decrypted_password(cred_id: str) -> str | None:
    """Decrypt and return a password by credential ID. Internal use only."""
    vault = _load_vault()
    cred = next((c for c in vault if c["id"] == cred_id), None)
    if not cred or "encrypted_password" not in cred:
        return None
    try:
        return _decrypt(cred["encrypted_password"])
    except Exception:
        return None


def get_credential_for_api(cred_id: str) -> dict | None:
    """Decrypt and return full credential for API use.

    Returns {"username": str, "password": str, "platform": str} or None.
    Used by API endpoints when the frontend sends credential_id instead
    of a raw password — the password never leaves the server after save.
    """
    vault = _load_vault()
    cred = next((c for c in vault if c["id"] == cred_id), None)
    if not cred or "encrypted_password" not in cred:
        return None
    try:
        password = _decrypt(cred["encrypted_password"])
        return {
            "username": cred["username"],
            "password": password,
            "platform": cred.get("platform", ""),
        }
    except Exception:
        return None


def verify_password(cred_id: str, password: str) -> bool:
    """Verify a password against a stored credential. For vault auth gate."""
    stored = get_decrypted_password(cred_id)
    if stored is None:
        return False
    return secrets.compare_digest(stored.encode(), password.encode())
