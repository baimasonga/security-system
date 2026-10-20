import { MemoryEventRepo } from './events-memory.ts';
import type { CredentialScope, InventoryType, InventoryEntities } from './model.ts';
import type { SecurityEvidence, SecurityFinding, PostureRepo } from './posture-model.ts';
const same = (a: CredentialScope, b: CredentialScope) =>
  a.orgId === b.orgId && a.applicationId === b.applicationId && a.environmentId === b.environmentId;
export abstract class MemoryPostureRepo extends MemoryEventRepo implements PostureRepo {
  abstract find<K extends InventoryType>(
    type: K,
    orgId: string,
    id: string,
  ): Promise<InventoryEntities[K] | undefined>;
  securityEvidence = new Map<string, SecurityEvidence>();
  securityFindings = new Map<string, SecurityFinding>();
  async listSecurityEvidence(
    scope: CredentialScope,
    kind: SecurityEvidence['kind'],
    limit: number,
  ) {
    return [...this.securityEvidence.values()]
      .filter((r) => same(r, scope) && r.kind === kind)
      .sort((a, b) => +b.createdAt - +a.createdAt || a.id.localeCompare(b.id))
      .slice(0, limit)
      .map((r) => structuredClone(r));
  }
  async insertSecurityEvidence(row: SecurityEvidence) {
    const component = await this.find('component', row.orgId, row.componentId);
    if (
      !component ||
      component.applicationId !== row.applicationId ||
      component.environmentId !== row.environmentId
    )
      throw new Error('evidence_scope');
    if (
      this.securityEvidence.has(row.id) ||
      [...this.securityEvidence.values()].some(
        (r) => same(r, row) && r.digest === row.digest && r.kind === row.kind,
      )
    )
      throw new Error('duplicate_evidence');
    this.securityEvidence.set(row.id, structuredClone(row));
  }
  async listSecurityFindings(scope: CredentialScope, limit: number) {
    const ranks = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...this.securityFindings.values()]
      .filter((r) => same(r, scope))
      .sort(
        (a, b) =>
          Number(['resolved', 'accepted_risk'].includes(a.state)) -
            Number(['resolved', 'accepted_risk'].includes(b.state)) ||
          ranks[a.severity] - ranks[b.severity] ||
          +b.createdAt - +a.createdAt ||
          a.id.localeCompare(b.id),
      )
      .slice(0, limit)
      .map((r) => structuredClone(r));
  }
  async findSecurityFinding(orgId: string, id: string) {
    const r = this.securityFindings.get(id);
    return r?.orgId === orgId ? structuredClone(r) : undefined;
  }
  async insertSecurityFinding(row: SecurityFinding) {
    const evidence = this.securityEvidence.get(row.evidenceId);
    if (
      !evidence ||
      !same(evidence, row) ||
      evidence.componentId !== row.componentId ||
      this.securityFindings.has(row.id) ||
      row.version !== 1 ||
      row.state !== 'open' ||
      row.assigneeUserId !== null ||
      row.updatedAt < row.createdAt ||
      [...this.securityFindings.values()].some(
        (r) => r.evidenceId === row.evidenceId && r.fingerprint === row.fingerprint,
      )
    )
      throw new Error('finding_invalid');
    this.securityFindings.set(row.id, structuredClone(row));
  }
  async updateSecurityFinding(row: SecurityFinding, expectedVersion: number) {
    const old = await this.findSecurityFinding(row.orgId, row.id);
    if (['resolved', 'accepted_risk'].includes(row.state) && !row.assigneeUserId)
      throw new Error('finding_assignee');
    if (
      !old ||
      old.version !== expectedVersion ||
      row.version !== old.version + 1 ||
      row.updatedAt < old.updatedAt
    )
      throw new Error('finding_version');
    const immutable = (r: SecurityFinding) => {
      const { state: _s, assigneeUserId: _a, version: _v, updatedAt: _u, ...rest } = r;
      return JSON.stringify(rest);
    };
    if (immutable(old) !== immutable(row)) throw new Error('finding_immutable');
    this.securityFindings.set(row.id, structuredClone(row));
  }
}
