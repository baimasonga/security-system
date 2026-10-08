-- 0001_init: V1 schema (identity, catalog, licensing, devices, audit, signals)
-- Conventions:
--   * ids are application-generated, prefixed, opaque text (usr_, org_, lic_, ...)
--   * every tenant-owned row carries org_id; child rows reference their parent via a
--     COMPOSITE foreign key (id, org_id) so a child can never point at another tenant's parent
--   * secrets are never stored in plaintext: *_hash columns hold HMAC/SHA-256 digests
--   * timestamps are timestamptz, UTC
--   * audit_events is append-only (trigger) and hash-chained

BEGIN;

CREATE TABLE users (
  id             text PRIMARY KEY,
  email          text NOT NULL,
  password_hash  text NOT NULL,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  platform_role  text NOT NULL DEFAULT 'none' CHECK (platform_role IN ('none','platform_admin')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_lower CHECK (email = lower(email))
);
CREATE UNIQUE INDEX users_email_uq ON users (email);

CREATE TABLE organizations (
  id          text PRIMARY KEY,
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind        text NOT NULL CHECK (kind IN ('personal','team')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  org_id      text NOT NULL REFERENCES organizations(id),
  user_id     text NOT NULL REFERENCES users(id),
  role        text NOT NULL CHECK (role IN ('owner','admin','member')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

CREATE TABLE sessions (
  id          text PRIMARY KEY,
  user_id     text NOT NULL REFERENCES users(id),
  token_hash  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz
);
CREATE UNIQUE INDEX sessions_token_hash_uq ON sessions (token_hash);

-- Catalog ---------------------------------------------------------------

CREATE TABLE products (
  id          text PRIMARY KEY,
  code        text NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
  name        text NOT NULL,
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX products_code_uq ON products (code);

CREATE TABLE plans (
  id            text PRIMARY KEY,
  product_id    text NOT NULL REFERENCES products(id),
  code          text NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
  tier          text NOT NULL CHECK (tier IN ('trial','standard','professional','business','enterprise')),
  version       integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  entitlements  jsonb NOT NULL DEFAULT '{}'::jsonb,
  capabilities  text[] NOT NULL DEFAULT '{}',
  device_limit  integer NOT NULL CHECK (device_limit BETWEEN 1 AND 10000),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX plans_product_code_uq ON plans (product_id, code);

-- Commercial ------------------------------------------------------------

CREATE TABLE subscriptions (
  id                  text PRIMARY KEY,
  org_id              text NOT NULL REFERENCES organizations(id),
  plan_id             text NOT NULL REFERENCES plans(id),
  status              text NOT NULL CHECK (status IN ('trialing','active','past_due','suspended','canceled','expired')),
  trial_end           timestamptz,
  current_period_end  timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, org_id)
);
CREATE INDEX subscriptions_org_idx ON subscriptions (org_id);

CREATE TABLE licenses (
  id                    text PRIMARY KEY,
  org_id                text NOT NULL REFERENCES organizations(id),
  product_id            text NOT NULL REFERENCES products(id),
  plan_id               text NOT NULL REFERENCES plans(id),
  subscription_id       text,
  kind                  text NOT NULL CHECK (kind IN ('subscription','trial','perpetual','canary')),
  status                text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  key_hash              text NOT NULL,
  expires_at            timestamptz,
  device_limit_override integer CHECK (device_limit_override BETWEEN 1 AND 10000),
  entitlement_overrides jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, org_id),
  FOREIGN KEY (subscription_id, org_id) REFERENCES subscriptions (id, org_id),
  -- subscription-backed licenses must reference a subscription; perpetual must not expire by subscription
  CONSTRAINT licenses_kind_subscription CHECK (
    (kind IN ('subscription','trial') AND subscription_id IS NOT NULL)
    OR (kind IN ('perpetual','canary'))
  )
);
CREATE UNIQUE INDEX licenses_key_hash_uq ON licenses (key_hash);
CREATE INDEX licenses_org_idx ON licenses (org_id);

-- One trial per (product, org) and per (product, user), recorded server-side so that
-- reinstalling / wiping local state cannot restart a trial.
CREATE TABLE trial_claims (
  product_id  text NOT NULL REFERENCES products(id),
  org_id      text NOT NULL REFERENCES organizations(id),
  user_id     text NOT NULL REFERENCES users(id),
  license_id  text NOT NULL REFERENCES licenses(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (product_id, org_id),
  UNIQUE (product_id, user_id)
);

-- Devices ---------------------------------------------------------------

CREATE TABLE devices (
  id              text PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  thumbprint      text NOT NULL,
  public_key_jwk  jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, org_id)
);
-- A device key identifies exactly one registration; reuse across orgs is a clone/abuse signal.
CREATE UNIQUE INDEX devices_thumbprint_uq ON devices (thumbprint);

CREATE TABLE activations (
  id                text PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  license_id        text NOT NULL,
  device_id         text NOT NULL,
  installation_id   text NOT NULL,
  activated_by      text NOT NULL REFERENCES users(id),
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active','deactivated','revoked')),
  activated_at      timestamptz NOT NULL DEFAULT now(),
  last_validated_at timestamptz,
  last_lease_id     text,
  last_lease_exp    timestamptz,
  deactivated_at    timestamptz,
  UNIQUE (id, org_id),
  FOREIGN KEY (license_id, org_id) REFERENCES licenses (id, org_id),
  FOREIGN KEY (device_id, org_id)  REFERENCES devices  (id, org_id)
);
-- Device-limit accounting reads this index; "one live activation per license+device" is enforced here.
CREATE UNIQUE INDEX activations_one_active_uq ON activations (license_id, device_id) WHERE status = 'active';
CREATE INDEX activations_license_active_idx ON activations (license_id) WHERE status = 'active';

CREATE TABLE leases (
  jti            text PRIMARY KEY,
  org_id         text NOT NULL,
  activation_id  text NOT NULL,
  plan_version   integer NOT NULL,
  issued_at      timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  FOREIGN KEY (activation_id, org_id) REFERENCES activations (id, org_id)
);
CREATE INDEX leases_activation_idx ON leases (activation_id);

CREATE TABLE challenges (
  nonce_hash       text PRIMARY KEY,
  purpose          text NOT NULL CHECK (purpose IN ('activate','validate','refresh','deactivate')),
  installation_id  text NOT NULL,
  subject_id       text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz
);
CREATE INDEX challenges_installation_idx ON challenges (installation_id) WHERE consumed_at IS NULL;

-- Keys (metadata only; private material lives in KMS / secret store, never here) -------

CREATE TABLE signing_keys (
  kid            text PRIMARY KEY,
  purpose        text NOT NULL CHECK (purpose IN ('license')),
  state          text NOT NULL CHECK (state IN ('generated','active','deprecated','revoked','archived','destroyed')),
  public_key_jwk jsonb NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  activated_at   timestamptz,
  deprecated_at  timestamptz,
  revoked_at     timestamptz
);
-- At most one active signing key per purpose.
CREATE UNIQUE INDEX signing_keys_one_active_uq ON signing_keys (purpose) WHERE state = 'active';

-- Audit (append-only, hash-chained) ----------------------------------------------------

CREATE TABLE audit_events (
  seq          bigint PRIMARY KEY,
  id           text NOT NULL UNIQUE,
  occurred_at  timestamptz NOT NULL,
  actor_type   text NOT NULL CHECK (actor_type IN ('user','device','system','operator','anonymous')),
  actor_id     text,
  action       text NOT NULL,
  target_type  text,
  target_id    text,
  org_id       text,
  reason       text,
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash    text NOT NULL,
  hash         text NOT NULL
);
CREATE INDEX audit_events_org_idx ON audit_events (org_id, seq);

CREATE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END $$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();

-- Signals / telemetry (content-free by construction: allow-listed attributes only) ----

CREATE TABLE security_events (
  id           text PRIMARY KEY,
  occurred_at  timestamptz NOT NULL,
  kind         text NOT NULL,
  severity     text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  org_id       text,
  subject      text,
  attributes   jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX security_events_kind_idx ON security_events (kind, occurred_at DESC);

CREATE TABLE telemetry_events (
  id           text PRIMARY KEY,
  occurred_at  timestamptz NOT NULL,
  name         text NOT NULL,
  attributes   jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX telemetry_events_name_idx ON telemetry_events (name, occurred_at DESC);

COMMIT;
