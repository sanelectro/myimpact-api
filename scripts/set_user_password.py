from datetime import UTC, datetime
from getpass import getpass

from sqlalchemy import func, select

from app.database import SessionLocal
from app.models import UserDB
from app.security import hash_password


def main() -> None:
    email = input("Existing account email: ").strip().lower()
    password = getpass("New password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    with SessionLocal() as db:
        user = db.scalar(
            select(UserDB).where(func.lower(UserDB.email) == email)
        )
        if user is None:
            raise SystemExit("No user exists with that email.")
        user.password_hash = hash_password(password)
        user.updated_at = datetime.now(UTC)
        db.commit()

    print(f"Password updated for {email}.")


if __name__ == "__main__":
    main()
