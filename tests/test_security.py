import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
from app import security
from app.database import Base
from app.models import RefreshTokenDB, UserDB
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


def test_password_hashes_are_verified_without_storing_plaintext():
    password = "correct horse battery staple"
    hashed = security.hash_password(password)

    assert hashed != password
    assert security.verify_password(password, hashed)
    assert not security.verify_password("wrong password", hashed)
    assert not security.verify_password(password, None)


def test_access_token_is_signed_for_platform_and_expires(monkeypatch):
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime(2026, 10, 23, tzinfo=UTC)
    settings = SimpleNamespace(
        auth_issuer="https://auth.example.test",
        auth_audience="myimpact-platform",
        auth_key_id="test-key",
        access_token_minutes=15,
    )
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_private_key", lambda: private_key)
    user = SimpleNamespace(
        id="user-1",
        name="Alex Example",
        email="alex@example.test",
        role="Engineer",
        is_platform_admin=True,
    )

    token, expires_in = security.create_access_token(user, now=now)
    claims = jwt.decode(
        token,
        private_key.public_key(),
        algorithms=["RS256"],
        audience="myimpact-platform",
        issuer="https://auth.example.test",
        options={"verify_exp": False},
    )

    assert expires_in == 900
    assert claims["sub"] == "user-1"
    assert claims["is_platform_admin"] is True
    assert claims["scope"] == "myimpact-api myimpact-ai"
    assert datetime.fromtimestamp(claims["exp"], UTC) == now + timedelta(minutes=15)


def test_refresh_token_persists_only_a_hash_and_expiry(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    settings = SimpleNamespace(refresh_token_days=30, refresh_token_max_days=90)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    now = datetime(2026, 10, 23, tzinfo=UTC)

    with Session(engine) as db:
        user = UserDB(
            id="user-1",
            name="Alex",
            email="alex@example.test",
            role=None,
            password_hash=PasswordHasher().hash("correct horse battery staple"),
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        db.flush()
        raw_token, row = security.create_refresh_token(db, user.id, now=now)
        db.commit()

        persisted = db.scalar(
            select(RefreshTokenDB).where(RefreshTokenDB.id == row.id)
        )

    assert persisted is not None
    assert raw_token != persisted.token_hash
    assert persisted.token_hash == security.hash_refresh_token(raw_token)
    assert persisted.expires_at.replace(tzinfo=UTC) == now + timedelta(days=30)
    assert persisted.family_expires_at.replace(tzinfo=UTC) == now + timedelta(days=90)


def test_jwks_document_contains_the_configured_public_signing_key(monkeypatch):
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    settings = SimpleNamespace(auth_key_id="test-key")
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_public_key", lambda: private_key.public_key())

    jwks = security.jwks_document()
    jwk = jwks["keys"][0]
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

    assert jwk["kid"] == "test-key"
    assert jwk["alg"] == "RS256"
    assert public_key.public_numbers() == private_key.public_key().public_numbers()
