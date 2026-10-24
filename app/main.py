import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import OrganizationDB, RefreshTokenDB, UserDB, UserInvitationDB
from app.schemas import (
    AcceptInvitationRequest,
    AdminInviteRequest,
    AdminInviteResponse,
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    UserActivationRequest,
    UserActivationResponse,
    UserResponse,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_refresh_token,
    get_public_key,
    jwks_document,
    verify_password,
)

settings = get_settings()
app = FastAPI(title="MyImpact API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in settings.allowed_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

bearer_scheme = HTTPBearer(auto_error=False)


def require_platform_admin(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(
            credentials.credentials,
            get_public_key(),
            algorithms=["RS256"],
            audience=settings.auth_audience,
            issuer=settings.auth_issuer,
            options={"require": ["sub", "exp", "iss", "aud"]},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The access token is invalid or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    scopes = claims.get("scope", "")
    subject = claims.get("sub")
    if (
        claims.get("is_platform_admin") is not True
        or not isinstance(scopes, str)
        or "myimpact-api" not in scopes.split()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform administrator access is required.",
        )
    if not isinstance(subject, str) or not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The access token is missing user identity claims.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.get(UserDB, subject)
    if user is None or not user.is_active or not user.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active platform administrator access is required.",
        )
    return user.id


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="myimpact_refresh",
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/auth",
        max_age=settings.refresh_token_days * 24 * 60 * 60,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key="myimpact_refresh",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/auth",
    )


def _validate_browser_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    allowed_origins = {
        value.strip()
        for value in settings.allowed_origins.split(",")
        if value.strip()
    }
    if origin is not None and origin not in allowed_origins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The request origin is not allowed.",
        )


def _is_expired(expires_at: datetime, now: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= now


def _auth_response(user: UserDB, db: Session, response: Response) -> AuthResponse:
    access_token, expires_in = create_access_token(user)
    refresh_token, _ = create_refresh_token(db, user.id)
    db.commit()
    _set_refresh_cookie(response, refresh_token)
    return AuthResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse.model_validate(user, from_attributes=True),
    )


def _get_or_create_organization(db: Session, company: str) -> OrganizationDB:
    name = " ".join(company.split())
    normalized_name = name.casefold()
    organization = db.scalar(
        select(OrganizationDB).where(
            OrganizationDB.normalized_name == normalized_name
        )
    )
    if organization is not None:
        return organization

    organization = OrganizationDB(
        id=str(uuid4()),
        name=name,
        normalized_name=normalized_name,
        created_at=datetime.now(UTC),
    )
    db.add(organization)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        organization = db.scalar(
            select(OrganizationDB).where(
                OrganizationDB.normalized_name == normalized_name
            )
        )
        if organization is None:
            raise
    return organization


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "service": "myimpact-api"}


@app.get("/.well-known/jwks.json")
def get_jwks() -> dict[str, list[dict[str, str]]]:
    return jwks_document()


@app.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    request: RegisterRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AuthResponse:
    normalized_email = str(request.email).lower()
    existing_user = db.scalar(
        select(UserDB.id).where(func.lower(UserDB.email) == normalized_email)
    )
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    now = datetime.now(UTC)
    organization = _get_or_create_organization(db, request.company)
    user = UserDB(
        id=str(uuid4()),
        name=request.name,
        email=normalized_email,
        role=None,
        organization_id=organization.id,
        password_hash=hash_password(request.password),
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    try:
        db.flush()
        result = _auth_response(user, db, response)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from exc
    return result


@app.post("/auth/login", response_model=AuthResponse)
def login(
    request: LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AuthResponse:
    user = db.scalar(
        select(UserDB).where(
            func.lower(UserDB.email) == str(request.email).lower()
        )
    )
    if (
        user is None
        or not user.is_active
        or not verify_password(request.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email or password is incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _auth_response(user, db, response)


@app.post("/auth/refresh", response_model=AuthResponse)
def refresh(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AuthResponse:
    _validate_browser_origin(request)
    raw_token = request.cookies.get("myimpact_refresh")
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session is missing.")

    now = datetime.now(UTC)
    token_hash = hash_refresh_token(raw_token)
    token_row = db.scalar(
        select(RefreshTokenDB)
        .where(RefreshTokenDB.token_hash == token_hash)
        .with_for_update()
    )
    if token_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session is invalid.")
    if token_row.revoked_at is not None:
        db.execute(
            update(RefreshTokenDB)
            .where(
                RefreshTokenDB.family_id == token_row.family_id,
                RefreshTokenDB.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session has already been used.")
    if _is_expired(token_row.expires_at, now) or _is_expired(
        token_row.family_expires_at, now
    ):
        token_row.revoked_at = now
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session has expired.")

    user = db.get(UserDB, token_row.user_id)
    if user is None or not user.is_active:
        db.execute(
            update(RefreshTokenDB)
            .where(
                RefreshTokenDB.family_id == token_row.family_id,
                RefreshTokenDB.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        token_row.revoked_at = now
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session is invalid.")

    token_row.revoked_at = now
    token_row.last_used_at = now
    next_token, next_row = create_refresh_token(
        db,
        user.id,
        family_id=token_row.family_id,
        family_expires_at=token_row.family_expires_at,
        now=now,
    )
    token_row.replaced_by = next_row.id
    access_token, expires_in = create_access_token(user, now=now)
    db.commit()
    _set_refresh_cookie(response, next_token)
    return AuthResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse.model_validate(user, from_attributes=True),
    )


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    _validate_browser_origin(request)
    raw_token = request.cookies.get("myimpact_refresh")
    if raw_token:
        token_row = db.scalar(
            select(RefreshTokenDB).where(
                RefreshTokenDB.token_hash == hash_refresh_token(raw_token)
            )
        )
        if token_row is not None:
            now = datetime.now(UTC)
            db.execute(
                update(RefreshTokenDB)
                .where(
                    RefreshTokenDB.family_id == token_row.family_id,
                    RefreshTokenDB.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            db.commit()
    _clear_refresh_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.post("/auth/accept-invitation", response_model=AuthResponse)
def accept_invitation(
    request: AcceptInvitationRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AuthResponse:
    now = datetime.now(UTC)
    invitation = db.scalar(
        select(UserInvitationDB)
        .where(UserInvitationDB.token_hash == hash_refresh_token(request.token))
        .with_for_update()
    )
    if (
        invitation is None
        or invitation.consumed_at is not None
        or _is_expired(invitation.expires_at, now)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The invitation is invalid or has expired.",
        )

    user = db.get(UserDB, invitation.user_id)
    if user is None or user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The invitation is invalid or has expired.",
        )

    user.password_hash = hash_password(request.password)
    user.is_active = True
    user.updated_at = now
    invitation.consumed_at = now
    db.flush()
    return _auth_response(user, db, response)


@app.post(
    "/admin/users/invitations",
    response_model=AdminInviteResponse,
    status_code=status.HTTP_201_CREATED,
)
def invite_user(
    request: AdminInviteRequest,
    admin_id: Annotated[str, Depends(require_platform_admin)],
    db: Annotated[Session, Depends(get_db)],
) -> AdminInviteResponse:
    normalized_email = str(request.email).lower()
    user = db.scalar(
        select(UserDB).where(func.lower(UserDB.email) == normalized_email)
    )
    if user is not None and (user.is_active or user.password_hash is not None):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    organization = _get_or_create_organization(db, request.company)

    now = datetime.now(UTC)
    if user is None:
        user = UserDB(
            id=str(uuid4()),
            name=request.name,
            email=normalized_email,
            role=request.role,
            organization_id=organization.id,
            password_hash=None,
            is_active=False,
            created_at=now,
            updated_at=now,
        )
    else:
        user.name = request.name
        user.role = request.role
        user.organization_id = organization.id
        user.updated_at = now
        db.execute(
            update(UserInvitationDB)
            .where(
                UserInvitationDB.user_id == user.id,
                UserInvitationDB.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )
    raw_token = secrets.token_urlsafe(48)
    expires_at = now + timedelta(hours=72)
    invitation = UserInvitationDB(
        id=str(uuid4()),
        user_id=user.id,
        token_hash=hash_refresh_token(raw_token),
        created_at=now,
        expires_at=expires_at,
    )
    db.add_all([user, invitation])
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from exc

    return AdminInviteResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        company=organization.name,
        role=user.role,
        invite_token=raw_token,
        expires_at=expires_at,
    )


@app.patch(
    "/admin/users/{user_id}/status",
    response_model=UserActivationResponse,
)
def set_user_active_status(
    user_id: str,
    request: UserActivationRequest,
    admin_id: Annotated[str, Depends(require_platform_admin)],
    db: Annotated[Session, Depends(get_db)],
) -> UserActivationResponse:
    user = db.get(UserDB, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    if not request.is_active and user.id == admin_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot disable your own platform-admin account.",
        )
    if request.is_active and user.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The user must accept their invitation before being activated.",
        )
    if (
        not request.is_active
        and user.is_platform_admin
        and db.scalar(
            select(func.count())
            .select_from(UserDB)
            .where(UserDB.is_platform_admin.is_(True), UserDB.is_active.is_(True))
        )
        <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="At least one active platform administrator must remain.",
        )

    user.is_active = request.is_active
    user.updated_at = datetime.now(UTC)
    if not request.is_active:
        db.execute(
            update(RefreshTokenDB)
            .where(
                RefreshTokenDB.user_id == user.id,
                RefreshTokenDB.revoked_at.is_(None),
            )
            .values(revoked_at=user.updated_at)
        )
    db.commit()
    return UserActivationResponse(id=user.id, is_active=user.is_active)
