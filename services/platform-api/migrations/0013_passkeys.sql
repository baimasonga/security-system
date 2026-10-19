-- Passkeys (ADR-023). Public keys only; challenges are stored as digests and consumed once.
CREATE TABLE passkeys (
  credential_id text PRIMARY KEY CHECK (credential_id ~ '^[A-Za-z0-9_-]+$' AND length(credential_id) <= 1400),
  user_id text NOT NULL REFERENCES users(id),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  alg integer NOT NULL CHECK (alg IN (-8, -7, -257)),
  public_key_jwk jsonb NOT NULL,
  sign_count bigint NOT NULL CHECK (sign_count >= 0),
  backup_eligible boolean NOT NULL,
  backed_up boolean NOT NULL,
  created_at timestamptz NOT NULL,
  last_used_at timestamptz
);
CREATE INDEX passkeys_user ON passkeys(user_id, created_at);

CREATE TABLE webauthn_challenges (
  challenge_hash text PRIMARY KEY CHECK (challenge_hash ~ '^[0-9a-f]{64}$'),
  purpose text NOT NULL CHECK (purpose IN ('register','login')),
  user_id text REFERENCES users(id),
  session_id text,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  CHECK ((purpose = 'register') = (user_id IS NOT NULL AND session_id IS NOT NULL))
);
CREATE INDEX webauthn_challenges_expiry ON webauthn_challenges(expires_at);
