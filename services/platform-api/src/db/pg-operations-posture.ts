import { PgAutomationRepo } from './pg-operations-automation.ts';
import type { Queryable } from './pg.ts';
import type {
  CredentialScope,
  SecurityEvidence,
  SecurityFinding,
  PostureRepo,
} from '@trust/operations';
const column = (s: string) => s.replace(/[A-Z]/g, (c) => '_' + c.toLowerCase());
const evidenceFields = [
  'id',
  'orgId',
  'applicationId',
  'environmentId',
  'componentId',
  'kind',
  'digest',
  'body',
  'createdByUserId',
  'createdAt',
] as const;
const findingFields = [
  'id',
  'orgId',
  'applicationId',
  'environmentId',
  'componentId',
  'evidenceId',
  'fingerprint',
  'severity',
  'advisoryId',
  'state',
  'assigneeUserId',
  'version',
  'createdAt',
  'updatedAt',
] as const;
const evidenceFrom = (r: Record<string, unknown>): SecurityEvidence =>
  ({
    ...Object.fromEntries(evidenceFields.map((f) => [f, r[column(f)]])),
    createdAt: new Date(r['created_at'] as Date),
  }) as SecurityEvidence;
const findingFrom = (r: Record<string, unknown>): SecurityFinding =>
  ({
    ...Object.fromEntries(findingFields.map((f) => [f, r[column(f)]])),
    createdAt: new Date(r['created_at'] as Date),
    updatedAt: new Date(r['updated_at'] as Date),
    version: Number(r['version']),
  }) as SecurityFinding;
export class PgPostureRepo extends PgAutomationRepo implements PostureRepo {
  readonly #q: Queryable;
  constructor(q: Queryable) {
    super(q);
    this.#q = q;
  }
  async listSecurityEvidence(s: CredentialScope, kind: SecurityEvidence['kind'], limit: number) {
    const r = await this.#q.query(
      'SELECT * FROM operations_security_evidence WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND kind=$4 ORDER BY created_at DESC,id LIMIT $5',
      [s.orgId, s.applicationId, s.environmentId, kind, limit],
    );
    return r.rows.map(evidenceFrom);
  }
  async insertSecurityEvidence(row: SecurityEvidence) {
    await this.#q.query(
      `INSERT INTO operations_security_evidence (${evidenceFields.map(column).join(',')}) VALUES (${evidenceFields.map((_, i) => '$' + (i + 1)).join(',')})`,
      evidenceFields.map((f) => (f === 'body' ? JSON.stringify(row.body) : row[f])),
    );
  }
  async listSecurityFindings(s: CredentialScope, limit: number) {
    const r = await this.#q.query(
      "SELECT * FROM operations_security_findings WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 ORDER BY (state IN ('resolved','accepted_risk')),CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,created_at DESC,id LIMIT $4",
      [s.orgId, s.applicationId, s.environmentId, limit],
    );
    return r.rows.map(findingFrom);
  }
  async findSecurityFinding(orgId: string, id: string) {
    const r = await this.#q.query(
      'SELECT * FROM operations_security_findings WHERE org_id=$1 AND id=$2',
      [orgId, id],
    );
    return r.rows[0] ? findingFrom(r.rows[0]) : undefined;
  }
  async insertSecurityFinding(row: SecurityFinding) {
    await this.#q.query(
      `INSERT INTO operations_security_findings (${findingFields.map(column).join(',')}) VALUES (${findingFields.map((_, i) => '$' + (i + 1)).join(',')})`,
      findingFields.map((f) => row[f]),
    );
  }
  async updateSecurityFinding(row: SecurityFinding, expectedVersion: number) {
    const r = await this.#q.query(
      `UPDATE operations_security_findings SET ${findingFields.map((f, i) => column(f) + '=$' + (i + 1)).join(',')} WHERE id=$1 AND org_id=$2 AND version=$${findingFields.length + 1}`,
      [...findingFields.map((f) => row[f]), expectedVersion],
    );
    if (r.rowCount !== 1) throw new Error('finding_version');
  }
}
