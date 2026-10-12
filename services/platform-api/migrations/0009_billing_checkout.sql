-- One checkout per existing subscription-backed license; no duplicate recurring subscriptions.
CREATE TABLE billing_checkouts (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id),
  user_id text NOT NULL REFERENCES users(id),
  license_id text NOT NULL UNIQUE,
  plan_id text NOT NULL REFERENCES plans(id),
  price_id text NOT NULL CHECK (price_id ~ '^pri_[a-z0-9]{26}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('submitting','uncertain','ready','completed')),
  transaction_id text UNIQUE CHECK (transaction_id ~ '^txn_[a-z0-9]{26}$'),
  checkout_url text,
  provider_subscription_id text UNIQUE CHECK (provider_subscription_id ~ '^sub_[a-z0-9]{26}$'),
  last_event_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (org_id, request_hash),
  FOREIGN KEY (license_id, org_id) REFERENCES licenses(id, org_id)
);
CREATE TABLE billing_events (
  id text PRIMARY KEY,
  checkout_id text NOT NULL REFERENCES billing_checkouts(id),
  body_hash text NOT NULL CHECK (body_hash ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL
);
CREATE INDEX billing_events_checkout_idx ON billing_events(checkout_id);
