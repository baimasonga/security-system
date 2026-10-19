-- OPS-003: integration secrets are returned once; only 256-bit verification digests persist.
BEGIN;
CREATE TABLE operations_credentials (
  id text PRIMARY KEY CHECK (id ~ '^opc_[a-f0-9]{32}$'),
  org_id text NOT NULL,
  application_id text NOT NULL,
  environment_id text NOT NULL,
  purpose text NOT NULL CHECK (purpose='events:write'),
  source text NOT NULL CHECK (source='backend_report'),
  secret_hash text NOT NULL CHECK (secret_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at>=created_at AND expires_at<=created_at+interval '90 days'),
  revoked_at timestamptz,
  rotated_at timestamptz,
  FOREIGN KEY (environment_id,application_id,org_id) REFERENCES operations_environments(id,application_id,org_id)
);
CREATE INDEX operations_credentials_scope_idx ON operations_credentials(org_id,application_id,environment_id,id);
CREATE INDEX operations_credentials_active_idx ON operations_credentials(org_id,application_id,environment_id,expires_at) WHERE revoked_at IS NULL;
CREATE FUNCTION operations_credential_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id<>OLD.id OR NEW.org_id<>OLD.org_id OR NEW.application_id<>OLD.application_id OR
     NEW.environment_id<>OLD.environment_id OR NEW.purpose<>OLD.purpose OR NEW.source<>OLD.source OR
     NEW.secret_hash<>OLD.secret_hash OR NEW.created_at<>OLD.created_at OR NEW.expires_at>OLD.expires_at OR
     (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) OR
     (OLD.rotated_at IS NOT NULL AND NEW.rotated_at IS DISTINCT FROM OLD.rotated_at) THEN
    RAISE EXCEPTION 'credential immutable identity or lifecycle';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operations_credentials_guard BEFORE UPDATE ON operations_credentials FOR EACH ROW EXECUTE FUNCTION operations_credential_guard();
COMMIT;
