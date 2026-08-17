"""Multi-operator user accounts + per-run annotations (D4).

Adds user accounts (stdlib ``hashlib.pbkdf2_hmac`` + ``secrets`` for password
hashing — no new dep) and per-run annotations (operator comments on findings)
for pair-testing collaboration. **Auth is loopback-only by design** — this
module does NOT weaken the loopback bind (``assert_api_loopback`` in
``tools/api/auth.py``). No roles/permissions system (AGENTS.md §E rejects that
as out of scope).

Routes:
- ``POST /api/v1/users`` — create a user account (username + password).
- ``POST /api/v1/users/login`` — verify credentials, return the user id.
- ``GET /api/v1/users`` — list users (no password hashes).
- ``POST /api/v1/runs/{run_id}/annotations`` — attach an operator comment.
- ``GET /api/v1/runs/{run_id}/annotations`` — list annotations for a run.
- ``DELETE /api/v1/annotations/{annotation_id}`` — delete an annotation.

All routes require the bearer token (same as every other v1 route). The user
account is an attribution layer on top of the loopback bearer gate, not a
replacement for it.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from tools.api.auth import BearerAuth, hash_password, verify_password
from tools.api.persistence import ApiPersistence

router = APIRouter(prefix="/api/v1", tags=["users"])

# Module-level wiring set by ``configure()``. Keeps the route handlers thin
# and testable without reaching into app state.
_AUTH: BearerAuth | None = None
_PERSISTENCE: ApiPersistence | None = None


def configure(auth: BearerAuth, persistence: ApiPersistence) -> None:
    global _AUTH, _PERSISTENCE
    _AUTH = auth
    _PERSISTENCE = persistence


async def _require_auth(request: Request) -> str:
    """FastAPI dependency: validate bearer token via BearerAuth.__call__."""
    if _AUTH is None:
        raise RuntimeError("API auth not configured.")
    return await _AUTH(request)


def _persistence() -> ApiPersistence:
    if _PERSISTENCE is None:
        raise HTTPException(status_code=500, detail="users routes not configured.")
    return _PERSISTENCE


# ── Request/response models ─────────────────────────────────────────────────


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    created_at: str
    last_login: str = ""


class AnnotationRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=4096)
    finding_ref: str = Field("", max_length=256)
    user_id: str = Field(..., min_length=1)
    username: str = Field("", max_length=64)


class AnnotationResponse(BaseModel):
    id: str
    run_id: str
    user_id: str
    username: str
    body: str
    finding_ref: str
    created_at: str


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("/users", response_model=UserResponse, status_code=201)
def create_user(req: CreateUserRequest, auth: str = Depends(_require_auth)) -> UserResponse:
    """Create a user account. Duplicate username → 409."""
    persistence = _persistence()
    existing = persistence.get_user_by_username(req.username)
    if existing is not None:
        raise HTTPException(status_code=409, detail="username already exists")
    password_hash, password_salt = hash_password(req.password)
    uid = persistence.create_user(req.username, password_hash, password_salt)
    user = persistence.get_user(uid)
    return UserResponse(
        id=user["id"], username=user["username"],
        created_at=user["created_at"], last_login=user.get("last_login", ""),
    )


@router.post("/users/login", response_model=UserResponse)
def login(req: LoginRequest, auth: str = Depends(_require_auth)) -> UserResponse:
    """Verify credentials. Returns the user record on success, 401 on mismatch."""
    persistence = _persistence()
    user = persistence.get_user_by_username(req.username)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid username or password")
    if not verify_password(req.password, user["password_hash"], user["password_salt"]):
        raise HTTPException(status_code=401, detail="invalid username or password")
    persistence.touch_user_login(user["id"])
    return UserResponse(
        id=user["id"], username=user["username"],
        created_at=user["created_at"], last_login=user.get("last_login", ""),
    )


@router.get("/users", response_model=list[UserResponse])
def list_users(auth: str = Depends(_require_auth)) -> list[UserResponse]:
    """List users (no password hashes ever returned)."""
    persistence = _persistence()
    return [
        UserResponse(
            id=u["id"], username=u["username"],
            created_at=u["created_at"], last_login=u.get("last_login", ""),
        )
        for u in persistence.list_users()
    ]


@router.post("/runs/{run_id}/annotations", response_model=AnnotationResponse, status_code=201)
def add_annotation(
    run_id: str, req: AnnotationRequest, auth: str = Depends(_require_auth),
) -> AnnotationResponse:
    """Attach an operator comment to a run's finding."""
    persistence = _persistence()
    if persistence.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="run not found")
    user = persistence.get_user(req.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    aid = persistence.add_annotation(
        run_id=run_id, user_id=req.user_id,
        username=req.username or user["username"],
        body=req.body, finding_ref=req.finding_ref,
    )
    anns = persistence.list_annotations(run_id)
    ann = next((a for a in anns if a["id"] == aid), None)
    if ann is None:
        raise HTTPException(status_code=500, detail="annotation persistence failed")
    return AnnotationResponse(**ann)


@router.get("/runs/{run_id}/annotations", response_model=list[AnnotationResponse])
def list_annotations(run_id: str, auth: str = Depends(_require_auth)) -> list[AnnotationResponse]:
    persistence = _persistence()
    if persistence.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="run not found")
    return [AnnotationResponse(**a) for a in persistence.list_annotations(run_id)]


@router.delete("/annotations/{annotation_id}", status_code=204)
def delete_annotation(annotation_id: str, auth: str = Depends(_require_auth)):
    persistence = _persistence()
    if not persistence.delete_annotation(annotation_id):
        raise HTTPException(status_code=404, detail="annotation not found")
