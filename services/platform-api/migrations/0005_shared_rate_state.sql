-- R-7: abuse-control state that must be shared by every API instance (and survive restarts for lockouts).
BEGIN;

-- Per-account failed-login counters (lockout). Key = sha256 of the normalized email: unknown accounts are
-- tracked too (no existence oracle) without storing the address. Durable, low volume.
CREATE TABLE login_failures (
  key          text PRIMARY KEY CHECK (key ~ '^[0-9a-f]{64}$'),
  count        integer     NOT NULL CHECK (count >= 1),
  locked_until timestamptz,
  updated_at   timestamptz NOT NULL
);
CREATE INDEX login_failures_updated_idx ON login_failures (updated_at);

-- Fixed-window request counters for the HTTP rate limiter. UNLOGGED: no WAL, truncated by crash recovery, not
-- replicated — counters are disposable and this is a write per limited request. Windows are measured with the
-- database clock so every instance agrees.
CREATE UNLOGGED TABLE rate_limits (
  bucket      text PRIMARY KEY,                 -- '<route>|<client key>'
  count       integer     NOT NULL,
  window_end  timestamptz NOT NULL
) WITH (fillfactor = 70);
CREATE INDEX rate_limits_expiry_idx ON rate_limits (window_end);

COMMIT;
