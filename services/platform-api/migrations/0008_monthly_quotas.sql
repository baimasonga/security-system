CREATE TABLE quota_charges (
  id text PRIMARY KEY,
  org_id text NOT NULL,
  license_id text NOT NULL,
  user_id text NOT NULL REFERENCES users(id),
  request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
  entitlement text NOT NULL CHECK(entitlement ~ '^[a-z][a-z0-9_]{0,55}_monthly$'),
  period text NOT NULL CHECK(period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  units bigint NOT NULL CHECK(units > 0 AND units <= 1099511627776),
  created_at timestamptz NOT NULL,
  UNIQUE(license_id,request_hash),
  FOREIGN KEY(license_id,org_id) REFERENCES licenses(id,org_id)
);
CREATE INDEX quota_charges_usage_idx ON quota_charges(org_id,license_id,period,entitlement);
