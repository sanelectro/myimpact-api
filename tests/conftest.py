import os

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("AUTH_ISSUER", "https://auth.example.test")
os.environ.setdefault(
    "ALLOWED_ORIGINS",
    "http://localhost:5174,http://127.0.0.1:5174",
)
