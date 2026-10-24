import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import RefreshTokenDB, UserDB

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if password_hash is None:
        return False
    try:
        return password_hasher.verify(password_hash, password)
    except VerificationError:
        return False


def _read_key(path: Path) -> bytes:
    return path.expanduser().read_bytes()


def get_private_key() -> RSAPrivateKey:
    key = serialization.load_pem_private_key(
        _read_key(get_settings().auth_private_key_file),
        password=None,
    )
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("AUTH_PRIVATE_KEY_FILE must contain an RSA private key.")
    return key


def get_public_key() -> RSAPublicKey:
    key = serialization.load_pem_public_key(
        _read_key(get_settings().auth_public_key_file)
    )
    if not isinstance(key, RSAPublicKey):
        raise TypeError("AUTH_PUBLIC_KEY_FILE must contain an RSA public key.")
    return key


def create_access_token(user: UserDB, now: datetime | None = None) -> tuple[str, int]:
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + timedelta(minutes=settings.access_token_minutes)
    token = jwt.encode(
        {
            "sub": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "is_platform_admin": user.is_platform_admin,
            "scope": "myimpact-api myimpact-ai",
            "iss": settings.auth_issuer,
            "aud": settings.auth_audience,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "jti": str(uuid4()),
        },
        get_private_key(),
        algorithm="RS256",
        headers={"kid": settings.auth_key_id, "typ": "JWT"},
    )
    return token, settings.access_token_minutes * 60


def create_refresh_token(
    db: Session,
    user_id: str,
    family_id: str | None = None,
    family_expires_at: datetime | None = None,
    now: datetime | None = None,
) -> tuple[str, RefreshTokenDB]:
    settings = get_settings()
    created_at = now or datetime.now(UTC)
    if family_expires_at is None:
        absolute_expiry = created_at + timedelta(days=settings.refresh_token_max_days)
    else:
        absolute_expiry = family_expires_at
        if absolute_expiry.tzinfo is None:
            absolute_expiry = absolute_expiry.replace(tzinfo=UTC)
    expires_at = min(
        created_at + timedelta(days=settings.refresh_token_days),
        absolute_expiry,
    )
    raw_token = secrets.token_urlsafe(48)
    row = RefreshTokenDB(
        id=str(uuid4()),
        family_id=family_id or str(uuid4()),
        user_id=user_id,
        token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        created_at=created_at,
        expires_at=expires_at,
        family_expires_at=absolute_expiry,
    )
    db.execute(
        delete(RefreshTokenDB).where(
            RefreshTokenDB.expires_at < created_at - timedelta(days=7)
        ).execution_options(synchronize_session=False)
    )
    db.add(row)
    return raw_token, row


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def jwks_document() -> dict[str, list[dict[str, str]]]:
    settings = get_settings()
    public_numbers = get_public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": settings.auth_key_id,
                "n": _base64url_uint(public_numbers.n),
                "e": _base64url_uint(public_numbers.e),
            }
        ]
    }


def _base64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    encoded = base64.urlsafe_b64encode(value.to_bytes(byte_length, "big"))
    return encoded.rstrip(b"=").decode("ascii")


def user_claims(user: UserDB) -> dict[str, Any]:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
    }
