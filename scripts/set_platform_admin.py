from datetime import UTC, datetime

from sqlalchemy import func, select

from app.database import SessionLocal
from app.models import UserDB


def main() -> None:
    email = input("Existing account email to grant platform admin access: ").strip().lower()
    if not email:
        raise SystemExit("Email must not be blank.")

    with SessionLocal() as db:
        user = db.scalar(
            select(UserDB).where(func.lower(UserDB.email) == email)
        )
        if user is None:
            raise SystemExit("No user exists with that email.")
        if not user.is_active or user.password_hash is None:
            raise SystemExit("Choose an active account with a configured password.")
        if user.is_platform_admin:
            print(f"Platform admin access is already enabled for {email}.")
            return
        user.is_platform_admin = True
        user.updated_at = datetime.now(UTC)
        db.commit()

    print(f"Platform admin access enabled for {email}.")


if __name__ == "__main__":
    main()
