
BEGIN;

-- 1. Users
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Case-insensitive email uniqueness.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique_idx
    ON public.users (LOWER(email));

-- 2. Email verification OTPs
CREATE TABLE IF NOT EXISTS public.email_verification_otps (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES public.users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS email_verification_otps_user_created_idx
    ON public.email_verification_otps (user_id, created_at DESC);

-- 3. Refresh tokens
CREATE TABLE IF NOT EXISTS public.auth_refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES public.users(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_token_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS auth_refresh_tokens_user_idx
    ON public.auth_refresh_tokens (user_id);

CREATE INDEX IF NOT EXISTS auth_refresh_tokens_family_idx
    ON public.auth_refresh_tokens (family_id);

COMMIT;
