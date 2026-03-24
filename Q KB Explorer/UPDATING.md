# Updating Q KB Explorer

This guide covers how to pull the latest version and update your running instance.

## Quick Update

```bash
# Navigate to your local copy
cd "Public-Security-Resources/Q KB Explorer"

# Pull the latest changes
git pull origin Q-KB-Explorer

# Rebuild and restart the container
docker compose down
docker compose build
docker compose up -d
```

Your data is preserved across updates — the SQLite database, credential vault, and encryption key live on Docker volumes that persist independently of the container.

## Step-by-Step

### 1. Check Your Current Version

Open Q KB Explorer in your browser and check the CHANGELOG or the Settings tab for the current version.

You can also check locally:

```bash
git log --oneline -1
```

### 2. Pull the Latest Code

```bash
cd "Public-Security-Resources/Q KB Explorer"
git pull origin Q-KB-Explorer
```

If you see "Already up to date", you're on the latest version.

### 3. Rebuild the Docker Image

A rebuild is required whenever application code or dependencies change:

```bash
docker compose build
```

### 4. Restart the Container

```bash
docker compose down
docker compose up -d
```

### 5. Verify the Update

Open **http://localhost:5051** in your browser and confirm the application loads correctly.

## Data Persistence

The following data is stored on Docker volumes and survives updates:

| Volume | Contents | What It Stores |
|--------|----------|----------------|
| `qkbe-keys` | Encryption key | `.vault_key.bin` — AES-256 key for credential vault |
| `qkbe-data` | Application data | `vault.json` (encrypted credentials) + `qkbe.db` (SQLite database with all synced QIDs, CIDs, Policies, Mandates) |

**You do not need to re-sync your data after updating.** All previously synced data, saved credentials, and sync history are retained.

## If Something Goes Wrong

### Roll Back to a Previous Version

```bash
# View available commits
git log --oneline -10

# Check out a specific version
git checkout <commit-hash>

# Rebuild and restart
docker compose down
docker compose build
docker compose up -d
```

### Reset to a Clean State

If you need to start fresh (this removes all synced data and credentials):

```bash
docker compose down -v
docker compose build
docker compose up -d
```

The `-v` flag removes Docker volumes. You will need to re-enter credentials and re-sync all data.

## Staying Notified

Watch the repository on GitHub to receive notifications when updates are published:

1. Go to [Public-Security-Resources](https://github.com/netsecops-76/Public-Security-Resources)
2. Click **Watch** and select **Custom** > **Releases** or **All Activity**
