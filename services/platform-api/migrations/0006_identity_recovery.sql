ALTER TABLE users ADD COLUMN email_verified_at timestamptz;
CREATE TABLE identity_tokens (
  user_id text NOT NULL REFERENCES users(id),
  purpose text NOT NULL CHECK (purpose IN ('reset','verify')),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  PRIMARY KEY (user_id, purpose),
  CHECK (expires_at > created_at)
);
CREATE INDEX identity_tokens_expiry ON identity_tokens (expires_at);
