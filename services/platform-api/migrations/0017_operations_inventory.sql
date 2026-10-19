-- OPS-002: content-free inventory. Archive retains immutable identity; no DELETE grants.
BEGIN;
CREATE TABLE operations_accounts (org_id text PRIMARY KEY REFERENCES organizations(id));
CREATE TABLE operations_applications (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id),
  code text NOT NULL CHECK (code ~ '^[a-z][a-z0-9-]{1,47}$'),
  state text NOT NULL CHECK (state IN ('active','disabled','archived')),
  version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  owner_user_id text NOT NULL,
  criticality text NOT NULL CHECK (criticality IN ('low','medium','high','critical')),
  product_id text REFERENCES products(id),
  UNIQUE (org_id, code), UNIQUE (id, org_id),
  FOREIGN KEY (org_id, owner_user_id) REFERENCES memberships(org_id, user_id)
);
CREATE TABLE operations_environments (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id),
  code text NOT NULL CHECK (code ~ '^[a-z][a-z0-9-]{1,47}$'),
  state text NOT NULL CHECK (state IN ('active','disabled','archived')),
  version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  application_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('development','staging','production')),
  UNIQUE (application_id, code), UNIQUE (id, application_id, org_id),
  FOREIGN KEY (application_id, org_id) REFERENCES operations_applications(id,org_id)
);
CREATE TABLE operations_components (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id),
  code text NOT NULL CHECK (code ~ '^[a-z][a-z0-9-]{1,47}$'),
  state text NOT NULL CHECK (state IN ('active','disabled','archived')),
  version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  application_id text NOT NULL,
  environment_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('service','database','storage','worker','scanner','desktop','provider')),
  dependency_ids jsonb NOT NULL CHECK (jsonb_typeof(dependency_ids) = 'array' AND jsonb_array_length(dependency_ids) <= 100),
  UNIQUE (environment_id, code), UNIQUE (id,org_id),
  FOREIGN KEY (environment_id,application_id,org_id) REFERENCES operations_environments(id,application_id,org_id)
);
CREATE INDEX operations_applications_org_idx ON operations_applications(org_id,id);
CREATE INDEX operations_environments_parent_idx ON operations_environments(org_id,application_id,id);
CREATE INDEX operations_components_parent_idx ON operations_components(org_id,application_id,environment_id,id);
CREATE FUNCTION operations_inventory_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state = 'archived' OR NEW.version <> OLD.version + 1 OR
     NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id OR NEW.code <> OLD.code OR
     NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'inventory immutable identity or version';
  END IF;
  IF TG_TABLE_NAME <> 'operations_applications' THEN
    IF NEW.application_id <> OLD.application_id THEN RAISE EXCEPTION 'inventory immutable parent'; END IF;
  END IF;
  IF TG_TABLE_NAME = 'operations_components' THEN
    IF NEW.environment_id <> OLD.environment_id THEN RAISE EXCEPTION 'inventory immutable parent'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operations_applications_guard BEFORE UPDATE ON operations_applications FOR EACH ROW EXECUTE FUNCTION operations_inventory_guard();
CREATE TRIGGER operations_environments_guard BEFORE UPDATE ON operations_environments FOR EACH ROW EXECUTE FUNCTION operations_inventory_guard();
CREATE TRIGGER operations_components_guard BEFORE UPDATE ON operations_components FOR EACH ROW EXECUTE FUNCTION operations_inventory_guard();
COMMIT;
