# MyImpact API authentication issuer

This service owns registration, password verification, access-token issuance, refresh-token rotation, and logout. Access tokens are short-lived RS256 JWTs. Refresh tokens are random opaque values stored only as SHA-256 hashes in PostgreSQL and delivered to the browser in an HttpOnly cookie. Each refresh record tracks its rolling expiry, its session's absolute expiry, and revocation/rotation state.

## Local setup

1. Apply the Flyway migrations from `myimpact-db`.
2. From this directory, create the environment and install dependencies:

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   cp .env.example .env
   bash scripts/generate-auth-keys.sh
   ```

3. Confirm `DATABASE_URL` in `.env` points to the same MyImpact PostgreSQL database used by `myimpact-ai`.
   `AUTH_ISSUER` must be the canonical URL for this issuer; replace the localhost example value with the deployed HTTPS URL outside local development.
   Set `ALLOWED_ORIGINS` to the exact browser origins that may call the issuer; replace the localhost example values outside local development.
4. For local development, leave `VITE_AUTH_API_BASE_URL` unset; the web app uses port `8001` on the same hostname as the UI. If you set it explicitly, use the same hostname for both apps (for example, use `localhost` for both or `127.0.0.1` for both). Browsers do not send the refresh cookie when these hosts are mixed.
5. Run `.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8001`.

Keep `keys/private.pem` and `.env` out of source control. In production, provision the private key through a secrets manager and set `COOKIE_SECURE=true`.

The issuer uses the common `myimpact-platform` audience. Protected APIs must validate the JWT signature, issuer, audience, expiry, and their required scope using the public key published at `/.well-known/jwks.json`.

Registration requires an organization name. The issuer creates an organization record when it does not exist, or associates the account with the existing organization when the normalized name matches. Registration creates an account for a new email address. Before public production use, add email verification and abuse protection (rate limits and bot controls).

Existing users from before this migration have no password hash and cannot sign in until an administrator provisions one locally with `python -m scripts.set_user_password`. This avoids allowing an unauthenticated registration to claim a pre-existing email address.

Platform administrators are MyImpact operator accounts, not customer-company administrators. They can review customer users' goals, impact, and evidence across companies; invite customer users; and disable or reactivate accounts. Their access is not tied to a customer organization.

To grant platform-admin access to an existing account, first apply the latest database migrations, then run `python -m scripts.set_platform_admin` from this directory and enter the account email. Public registration cannot grant platform-admin privileges. After promotion, sign out and back in so the account receives a token with the platform-admin claim.

Invitations are created from the platform-admin page and expire after 72 hours. The page provides a single-use invitation link for the admin to share with the employee; accepting it sets a password and activates the account. Resending an invitation invalidates any previous pending invitation. Disabling an account blocks new sign-ins and revokes refresh sessions.
