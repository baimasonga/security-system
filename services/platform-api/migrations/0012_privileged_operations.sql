-- Privileged operations (ADR-022): dual-control requests (JIT grants) and freezes.
-- Request rows are an accountability record: the application may insert and update them, never delete them.
CREATE TABLE privileged_requests (
  id text PRIMARY KEY,
  operation text NOT NULL CHECK (operation IN
    ('license.revoke','operator.grant','operator.revoke','org.unfreeze','platform.unfreeze')),
  org_id text CHECK (org_id IS NULL OR org_id ~ '^[a-z]{2,4}_[0-9a-f]{24}$'),
  target_id text CHECK (target_id IS NULL OR length(target_id) BETWEEN 1 AND 64),
  reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  status text NOT NULL CHECK (status IN
    ('pending','approved','executing','executed','rejected','cancelled','failed')),
  decided_by text,
  decided_at timestamptz,
  decision_reason text CHECK (decision_reason IS NULL OR length(decision_reason) BETWEEN 3 AND 500),
  break_glass boolean NOT NULL DEFAULT false,
  witnessed_at timestamptz,
  witness_anchor text,
  execute_before timestamptz,
  executed_at timestamptz,
  failure text CHECK (failure IS NULL OR length(failure) <= 64),
  -- The requester never decides their own request, except through break-glass.
  CHECK (decided_by IS NULL OR decided_by <> requested_by OR break_glass),
  CHECK ((decided_by IS NULL) = (decided_at IS NULL)),
  CHECK (NOT break_glass OR decided_by = requested_by),
  CHECK ((witnessed_at IS NULL) = (witness_anchor IS NULL))
);
CREATE INDEX privileged_requests_recent ON privileged_requests(created_at DESC, id DESC);
CREATE INDEX privileged_requests_status ON privileged_requests(status, created_at DESC);
CREATE INDEX privileged_requests_break_glass ON privileged_requests(decided_by, decided_at)
  WHERE break_glass;

CREATE TABLE privileged_freezes (
  scope text PRIMARY KEY CHECK (scope = 'platform' OR scope ~ '^org:[a-z]{2,4}_[0-9a-f]{24}$'),
  reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
  frozen_by text NOT NULL,
  frozen_at timestamptz NOT NULL
);
