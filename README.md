# Planner FastAPI backend

This service runs separately from Flutter. New accounts, notes, profile data,
record metadata, and refresh sessions are stored in Neon Postgres. New audio
recordings and profile images are stored in Cloudflare R2. The app must call
this API; secrets for Neon, R2, and Supabase belong only on the backend host.

## Legacy Supabase data and accounts

Supabase is retained as a read-only source for existing profiles, notes, and
recordings. On a legacy user's first FastAPI login, the API verifies the
provided email/password against Supabase Auth and copies the profile plus a
password hash into Neon. Supabase does not expose reusable password hashes, so
this first sign-in is required; the password is hashed using Argon2 before it
is stored in Neon. Subsequent sign-ins use FastAPI-issued tokens and Neon only.

Legacy notes and recordings are read through the server using the Supabase
service-role key. Editing or deleting a legacy note/record writes an override
in Neon; the old Supabase row/file is never changed. Supabase credentials are
never sent to the Flutter app.

The API will not automatically copy every legacy row to Neon: doing so would
duplicate the data and contradict keeping older rows on Supabase. Users need
their Supabase records to remain available while the Supabase project and its
service-role credentials remain active. New writes go to Neon/R2.

## Setup

Run commands from this `backend` directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `NEON_DATABASE_URL`, `JWT_SECRET`, Supabase settings, and R2 settings in
`.env`. For Neon, use a PostgreSQL connection string with SSL enabled. Set
`CORS_ORIGINS` to the frontend origins that actually call the API.

In development, if SMTP is not configured, registration and password-reset
responses include a `development_code`. This is disabled in production. Set
`SMTP_HOST`, `SMTP_FROM_EMAIL`, and the appropriate SMTP credentials before
deploying so email verification and password reset work.

Start the service:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The interactive API docs are available at `http://127.0.0.1:8000/docs`; health
is checked at `/health`. The API route prefix defaults to `/api/v1`.

The app creates missing tables on startup. For production, create a database
backup before deploying schema changes and use a migration process rather than
relying on automatic schema creation.

## API outline

- `POST /api/v1/auth/register`, `/verify-email`, `/resend-verification`
- `POST /api/v1/auth/login`, `/refresh`, `/logout`, `/me`
- `POST /api/v1/auth/forgot-password`, `/reset-password`
- `GET/PATCH/DELETE /api/v1/profile`
- `GET/POST /api/v1/notes`, `PUT/DELETE /api/v1/notes/{id}`
- `GET/POST /api/v1/records`, `DELETE /api/v1/records/{id}`
- `GET /health`

Authenticated routes accept `Authorization: Bearer <access_token>`. Refresh
tokens are rotated at each refresh; store them in platform secure storage.

## Tests

```powershell
pip install -r requirements-dev.txt
pytest
```

Tests use an in-memory SQLite database and mocked Supabase responses."# jotify_backend" 
