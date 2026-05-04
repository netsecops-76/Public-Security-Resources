"""
Q KB Explorer — OpenAPI / Swagger documentation
Built by netsecops-76

Spec generation and Swagger UI / ReDoc mounts via SpecTree (pydantic-
based, code-driven). Existing ``@app.route(...)`` handlers stay as-is;
this module adds an additional decorator (``@api.validate(...)``) per
route to declare its query / body / response shapes. SpecTree reads
those declarations to:

  1. Generate the OpenAPI 3 spec at runtime (no checked-in YAML to
     fall out of sync).
  2. Serve Swagger UI at ``/api/docs`` and ReDoc at ``/api/redoc``.
  3. Validate incoming requests against the declared schemas (free
     input validation as a side effect).

Shared response shapes (``Error``, ``Pagination``) live here so every
documented route reuses them rather than redefining the envelope.
Endpoint-specific models live next to their handlers in main.py to
keep the route + its contract in one place.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field
from spectree import SpecTree, SecurityScheme


# ── SpecTree instance ────────────────────────────────────────────────────
# `mode="strict"` would 422 any request that doesn't match the declared
# schema. We deliberately use the default (`normalize`) so partially
# documented routes degrade gracefully — undecorated routes pass through
# unchanged, decorated routes get validation. Keeps incremental rollout
# safe.
api = SpecTree(
    "flask",
    title="Q KB Explorer API",
    version="dev",
    description=(
        "Local Qualys Knowledge Base, Compliance, Policy, Tag, and PM "
        "Patch caching API. All endpoints return JSON; errors follow the "
        "shared `Error` envelope. Most routes are guarded by the vault "
        "identity gate (cookie-based session — unlock the vault in the "
        "UI before calling them)."
    ),
    path="api/docs",   # Swagger UI mount → /api/docs
    security_schemes=[
        SecurityScheme(
            name="vault_session",
            data={
                "type": "apiKey",
                "in": "cookie",
                "name": "session",
                "description": (
                    "Vault session cookie set by /api/credentials/verify. "
                    "Most data routes 401 without it."
                ),
            },
        )
    ],
)


# ── Shared response models ───────────────────────────────────────────────

class Error(BaseModel):
    """Standard error envelope returned by every documented route."""

    error: str = Field(..., description="Human-readable failure message")


class Unauthorized(BaseModel):
    """Returned when the vault identity gate rejects the request."""

    error: str = Field(..., description='Always `"Unauthorized"` for this status')


T = TypeVar("T")


class Pagination(BaseModel, Generic[T]):
    """Paginated list envelope shared by search endpoints.

    Subclass with a concrete item type to get a fully typed response:

        class QidSearchResponse(Pagination[QidSummary]): pass
    """

    results: list[T] = Field(..., description="Page of items")
    total: int = Field(..., description="Total matches across all pages", ge=0)
    page: int = Field(..., description="Current page number (1-indexed)", ge=1)
    per_page: int = Field(..., description="Items per page", ge=1)
    pages: int = Field(..., description="Total page count", ge=0)


# ── Tag groupings used by Swagger UI sidebar ─────────────────────────────
# Used as the `tags` arg on @api.validate decorators. Keeping them as
# constants here avoids typos drifting between routes.
TAG_QIDS = "QIDs"
TAG_CIDS = "CIDs"
TAG_POLICIES = "Policies"
TAG_MANDATES = "Mandates"
TAG_TAGS = "Tags"
TAG_PM = "PM Patches"
TAG_INTEL = "Intelligence"
TAG_SYNC = "Sync"
TAG_LIBRARY = "Tag Library"
TAG_AUDIT = "Tag Audit"
TAG_CREDS = "Credentials & Auth"
TAG_HEALTH = "Health & Meta"
TAG_SCHED = "Schedules"


# ── Common response shapes ──────────────────────────────────────────────

class OkMessage(BaseModel):
    """Generic 200 envelope for write endpoints that don't need to
    return a record body — `{"deleted": True}`, `{"updated": True,
    "tag_id": 12345}`, etc. Extra fields ride along."""

    model_config = {"extra": "allow"}
