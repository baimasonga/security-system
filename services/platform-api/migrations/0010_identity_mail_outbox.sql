CREATE TABLE identity_mail_outbox (
  user_id text NOT NULL REFERENCES users(id),
  purpose text NOT NULL CHECK (purpose IN ('reset','verify')),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  sealed text NOT NULL CHECK (length(sealed) BETWEEN 1 AND 8192),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  next_attempt_at timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts BETWEEN 0 AND 6),
  claim text,
  locked_until timestamptz,
  PRIMARY KEY (user_id,purpose),
  CHECK ((claim IS NULL) = (locked_until IS NULL))
);
CREATE INDEX identity_mail_due ON identity_mail_outbox(next_attempt_at,locked_until);
