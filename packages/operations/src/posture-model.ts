import type { CredentialScope } from './model.ts';
export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';
export type FindingState = 'open' | 'acknowledged' | 'resolved' | 'accepted_risk';
export interface SecurityEvidence extends CredentialScope {
  id: string;
  componentId: string;
  kind: 'scan' | 'recovery';
  digest: string;
  body: Record<string, unknown>;
  createdByUserId: string;
  createdAt: Date;
}
export interface SecurityFinding extends CredentialScope {
  id: string;
  componentId: string;
  evidenceId: string;
  fingerprint: string;
  severity: SecuritySeverity;
  advisoryId: string | null;
  state: FindingState;
  assigneeUserId: string | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}
export interface PostureRepo {
  listSecurityEvidence(
    scope: CredentialScope,
    kind: SecurityEvidence['kind'],
    limit: number,
  ): Promise<SecurityEvidence[]>;
  insertSecurityEvidence(row: SecurityEvidence): Promise<void>;
  listSecurityFindings(scope: CredentialScope, limit: number): Promise<SecurityFinding[]>;
  findSecurityFinding(orgId: string, id: string): Promise<SecurityFinding | undefined>;
  insertSecurityFinding(row: SecurityFinding): Promise<void>;
  updateSecurityFinding(row: SecurityFinding, expectedVersion: number): Promise<void>;
}
