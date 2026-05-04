# Development_Foundation.md — Q KB Explorer Development Configuration

> **Version:** 4.0.0
> **Purpose:** Project-specific configuration for Q KB Explorer.
> **Setup:** Customized from Development Foundation universal template.

---

## 🔧 PROJECT IDENTITY

```yaml
PROJECT_NAME: "Q KB Explorer"
DESCRIPTION: "Qualys Knowledge Base & Policy Compliance Explorer — local caching, full-text search, and cross-environment policy migration for Qualys QIDs, CIDs, Policies, and Mandates"
INDUSTRY: "cybersecurity, vulnerability management, compliance"
MULTI_TENANT: false
MAINTAINER: "netsecops-76"

PROJECT_SCALE: "STANDARD"
# 🟡 STANDARD — Medium app with ~55 API endpoints, 20 DB tables, Docker deployment,
#                single-page frontend with 7 tabs. Solo developer project.
#                Core 6 docs required. Feature branches OK, direct merge OK.

TECH_STACK:
  backend: "Python 3.12, Flask 3.1.3"
  frontend: "Vanilla JavaScript, Chart.js (no framework)"
  database: "SQLite with WAL mode and FTS5 full-text search"
  orm: "Raw SQL via sqlite3 (no ORM)"
  migrations: "Schema in database.py _SCHEMA_SQL with idempotent CREATE IF NOT EXISTS + ALTER TABLE migrations"
  auth: "Vault-based identity gate (AES-256-GCM encrypted credential vault, session cookies)"
  realtime: "Server-sent progress events during sync operations"
  http_client: "requests 2.32.4 (Qualys API), xmltodict for XML parsing"
  deployment: "Docker (python:3.12-slim), Gunicorn, optional TLS"
  ci_cd: "GitHub Actions (pytest on push/PR) — .github/workflows/ci.yml"

GIT:
  enabled: true
  remote: "github"
  repo_url: "https://github.com/netsecops-76/Q_KB_Explorer"
  default_branch: "main"
  branching_strategy: "trunk"
  auto_commit: false
  commit_convention: "simple"

LANGUAGE_RULES:
  - "Python 3.12+ — use type hints on function signatures"
  - "SQL queries use parameterized placeholders (?) — never f-strings for user input"
  - "JSON responses on all API endpoints — always return {error: msg} on failure"
  - "Frontend: vanilla JS only — no build step, no npm, no bundler"

NAMING_CONVENTIONS:
  backend_files: "snake_case"
  frontend_files: "snake_case"
  database_tables: "snake_case_plural"
  api_paths: "kebab-case"
  env_vars: "SCREAMING_SNAKE_CASE"
```
