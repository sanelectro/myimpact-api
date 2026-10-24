from datetime import UTC, datetime

import pytest
from app import main, security
from app.database import Base, get_db
from app.models import RefreshTokenDB
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def auth_client(monkeypatch):
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(security, "get_private_key", lambda: private_key)
    monkeypatch.setattr(main, "get_public_key", lambda: private_key.public_key())
    monkeypatch.setattr(main.settings, "cookie_secure", False)
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_get_db
    client = TestClient(main.app)
    yield client, test_session
    client.close()
    main.app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_registration_refresh_rotation_and_logout(auth_client):
    client, test_session = auth_client
    registered = client.post(
        "/auth/register",
        json={
            "name": "Alex Example",
            "email": "Alex@example.com",
            "company": "Example Engineering",
            "password": "a-long-test-password",
            "role": "administrator",
        },
    )
    assert registered.status_code == 201, registered.text
    assert registered.json()["user"]["role"] is None
    assert registered.json()["user"]["is_platform_admin"] is False
    assert "myimpact_refresh" in registered.cookies

    initial_cookie = registered.cookies.get("myimpact_refresh")
    with test_session() as db:
        initial_rows = db.scalars(select(RefreshTokenDB)).all()
        assert len(initial_rows) == 1
        assert initial_rows[0].token_hash != initial_cookie
        user = db.get(main.UserDB, registered.json()["user"]["id"])
        assert user is not None
        organization = db.get(main.OrganizationDB, user.organization_id)
        assert organization is not None
        assert organization.name == "Example Engineering"
    csrf_response = client.post(
        "/auth/refresh",
        headers={"Origin": "https://attacker.example"},
    )
    assert csrf_response.status_code == 403

    refreshed = client.post("/auth/refresh")
    assert refreshed.status_code == 200
    rotated_cookie = refreshed.cookies.get("myimpact_refresh")
    assert rotated_cookie
    assert rotated_cookie != initial_cookie

    with test_session() as db:
        rows = db.scalars(select(RefreshTokenDB)).all()
        assert len(rows) == 2
        assert all(row.token_hash not in {initial_cookie, rotated_cookie} for row in rows)
        assert sum(row.revoked_at is None for row in rows) == 1

    logged_out = client.post("/auth/logout")
    assert logged_out.status_code == 204
    with test_session() as db:
        rows = db.scalars(select(RefreshTokenDB)).all()
        assert all(row.revoked_at is not None for row in rows)


def test_login_and_case_insensitive_duplicate_email(auth_client):
    client, _ = auth_client
    registered = client.post(
        "/auth/register",
        json={
            "name": "Alex Example",
            "email": "alex@example.com",
            "company": "Acme",
            "password": "a-long-test-password",
        },
    )
    assert registered.status_code == 201

    logged_in = client.post(
        "/auth/login",
        json={"email": "ALEX@example.com", "password": "a-long-test-password"},
    )
    assert logged_in.status_code == 200
    assert logged_in.json()["user"]["id"] == registered.json()["user"]["id"]
    assert logged_in.json()["access_token"]

    invalid_login = client.post(
        "/auth/login",
        json={"email": "alex@example.com", "password": "incorrect-password"},
    )
    duplicate_registration = client.post(
        "/auth/register",
        json={
            "name": "Duplicate",
            "email": "ALEX@EXAMPLE.COM",
            "company": "Acme",
            "password": "another-long-password",
        },
    )
    assert invalid_login.status_code == 401
    assert duplicate_registration.status_code == 409


def test_admin_invitation_activation_and_single_use(auth_client):
    client, test_session = auth_client
    now = datetime.now(UTC)
    admin = main.UserDB(
        id="platform-admin",
        name="Platform Admin",
        email="platform-admin@example.com",
        role=None,
        is_platform_admin=True,
        password_hash=None,
        created_at=now,
        updated_at=now,
    )
    with test_session() as db:
        db.add(admin)
        db.commit()
        admin_token, _ = security.create_access_token(admin)

    invitation = client.post(
        "/admin/users/invitations",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Taylor Example",
            "email": "taylor@example.com",
            "company": "Acme",
            "role": "Software Engineer",
        },
    )

    assert invitation.status_code == 201, invitation.text
    details = invitation.json()
    assert details["company"] == "Acme"
    assert details["role"] == "Software Engineer"
    with test_session() as db:
        user = db.get(main.UserDB, details["id"])
        assert user is not None
        assert user.is_active is False
        assert user.password_hash is None
        stored_invitation = db.query(main.UserInvitationDB).one()
        assert stored_invitation.token_hash != details["invite_token"]

    resent = client.post(
        "/admin/users/invitations",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Taylor Example",
            "email": "TAYLOR@example.com",
            "company": "Acme",
            "role": "Software Engineer",
        },
    )
    assert resent.status_code == 201, resent.text
    assert resent.json()["invite_token"] != details["invite_token"]

    stale_invitation = client.post(
        "/auth/accept-invitation",
        json={
            "token": details["invite_token"],
            "password": "a-new-secure-password",
        },
    )
    accepted = client.post(
        "/auth/accept-invitation",
        json={
            "token": resent.json()["invite_token"],
            "password": "a-new-secure-password",
        },
    )
    repeated = client.post(
        "/auth/accept-invitation",
        json={
            "token": resent.json()["invite_token"],
            "password": "a-new-secure-password",
        },
    )

    assert stale_invitation.status_code == 400
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["user"]["email"] == "taylor@example.com"
    assert accepted.json()["user"]["is_platform_admin"] is False
    assert repeated.status_code == 400


def test_registration_reuses_case_insensitive_organization(auth_client):
    client, test_session = auth_client
    missing_organization = client.post(
        "/auth/register",
        json={
            "name": "No Organization",
            "email": "missing-organization@example.com",
            "password": "a-long-test-password",
        },
    )
    first = client.post(
        "/auth/register",
        json={
            "name": "First User",
            "email": "first@example.com",
            "company": "Acme  Engineering",
            "password": "a-long-test-password",
        },
    )
    second = client.post(
        "/auth/register",
        json={
            "name": "Second User",
            "email": "second@example.com",
            "company": "  ACME Engineering  ",
            "password": "another-long-password",
        },
    )

    assert missing_organization.status_code == 422
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    with test_session() as db:
        first_user = db.get(main.UserDB, first.json()["user"]["id"])
        second_user = db.get(main.UserDB, second.json()["user"]["id"])
        organizations = db.scalars(select(main.OrganizationDB)).all()
        assert first_user is not None
        assert second_user is not None
        assert first_user.organization_id == second_user.organization_id
        assert len(organizations) == 1


def test_admin_can_disable_user_and_disabled_user_cannot_sign_in(auth_client):
    client, test_session = auth_client
    registered = client.post(
        "/auth/register",
        json={
            "name": "Taylor Example",
            "email": "taylor@example.com",
            "company": "Acme",
            "password": "a-long-test-password",
        },
    )
    user_id = registered.json()["user"]["id"]
    now = datetime.now(UTC)
    admin = main.UserDB(
        id="platform-admin",
        name="Platform Admin",
        email="platform-admin@example.com",
        role=None,
        is_platform_admin=True,
        password_hash=None,
        created_at=now,
        updated_at=now,
    )
    with test_session() as db:
        db.add(admin)
        db.commit()
        admin_token, _ = security.create_access_token(admin)

    disabled = client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False},
    )

    login = client.post(
        "/auth/login",
        json={"email": "taylor@example.com", "password": "a-long-test-password"},
    )

    assert disabled.status_code == 200
    assert disabled.json() == {"id": user_id, "is_active": False}
    assert login.status_code == 401
    assert client.post("/auth/refresh").status_code == 401


def test_non_admin_cannot_invite_customer_users(auth_client):
    client, _ = auth_client
    registered = client.post(
        "/auth/register",
        json={
            "name": "Taylor Example",
            "email": "taylor@example.com",
            "company": "Acme",
            "password": "a-long-test-password",
        },
    )

    response = client.post(
        "/admin/users/invitations",
        headers={
            "Authorization": f"Bearer {registered.json()['access_token']}"
        },
        json={
            "name": "Another User",
            "email": "another@example.com",
            "company": "Acme",
        },
    )

    assert response.status_code == 403
