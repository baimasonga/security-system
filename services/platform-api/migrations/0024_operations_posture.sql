BEGIN;
CREATE TABLE operations_security_evidence (
 id text PRIMARY KEY CHECK(id ~ '^ose_[a-f0-9]{24}$'),
 org_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL, component_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('scan','recovery')),
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 created_by_user_id text NOT NULL REFERENCES users(id),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 UNIQUE(org_id,application_id,environment_id,kind,digest),
 UNIQUE(org_id,application_id,environment_id,component_id,id),
 FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id)
);
CREATE TABLE operations_security_findings (
 id text PRIMARY KEY CHECK(id ~ '^osf_[a-f0-9]{24}$'),
 org_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL, component_id text NOT NULL,
 evidence_id text NOT NULL,
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
 severity text NOT NULL CHECK(severity IN ('low','medium','high','critical')),
 advisory_id text CHECK(advisory_id ~ '^(CVE-[0-9]{4}-[0-9]{4,10}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})$'),
 state text NOT NULL CHECK(state IN ('open','acknowledged','resolved','accepted_risk')),
 assignee_user_id text REFERENCES users(id),
 version integer NOT NULL CHECK(version>=1),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
 CHECK(state NOT IN ('resolved','accepted_risk') OR assignee_user_id IS NOT NULL),
 UNIQUE(evidence_id,fingerprint),
 FOREIGN KEY(org_id,application_id,environment_id,component_id,evidence_id) REFERENCES operations_security_evidence(org_id,application_id,environment_id,component_id,id)
);
CREATE INDEX operations_security_evidence_scope ON operations_security_evidence(org_id,application_id,environment_id,kind,created_at DESC,id);
CREATE INDEX operations_security_findings_scope ON operations_security_findings(org_id,application_id,environment_id,state,severity,created_at DESC,id);
CREATE FUNCTION operations_security_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'security evidence immutable' USING ERRCODE='23514'; END; $$;
CREATE TRIGGER operations_security_immutable BEFORE UPDATE OR DELETE ON operations_security_evidence FOR EACH ROW EXECUTE FUNCTION operations_security_immutable();
CREATE FUNCTION operations_security_finding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'security finding retained' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.state<>'open' OR NEW.assignee_user_id IS NOT NULL THEN RAISE EXCEPTION 'invalid finding creation' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.id,NEW.org_id,NEW.application_id,NEW.environment_id,NEW.component_id,NEW.evidence_id,NEW.fingerprint,NEW.severity,NEW.advisory_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.application_id,OLD.environment_id,OLD.component_id,OLD.evidence_id,OLD.fingerprint,OLD.severity,OLD.advisory_id,OLD.created_at) OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at THEN RAISE EXCEPTION 'invalid finding transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER operations_security_finding_guard BEFORE INSERT OR UPDATE OR DELETE ON operations_security_findings FOR EACH ROW EXECUTE FUNCTION operations_security_finding_guard();
COMMIT;
