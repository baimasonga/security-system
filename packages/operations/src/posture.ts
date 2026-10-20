import { createHash } from 'node:crypto';
import { z } from 'zod';
import { newId } from '@trust/crypto';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type { CredentialScope, InventoryAuthority, InventoryStore, InventoryTx } from './model.ts';
import type { SecurityEvidence, SecurityFinding } from './posture-model.ts';
const component = z.string().regex(/^opm_[a-f0-9]{24}$/);
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const instant = z.string().datetime();
const initial = z.literal('initial_setup');
export const scanInput = z
  .object({
    component_id: component,
    source: z.enum(['github_dependabot', 'github_secret_scanning']),
    revision: z.string().regex(/^[a-f0-9]{40}$/),
    run_id: z.string().regex(/^[1-9][0-9]{0,19}$/),
    completed_at: instant,
    outcome: z.enum(['completed', 'failed']),
    findings: z
      .array(
        z
          .object({
            fingerprint: hash,
            severity: z.enum(['low', 'medium', 'high', 'critical']),
            advisory_id: z
              .string()
              .regex(
                /^(?:CVE-[0-9]{4}-[0-9]{4,10}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})$/,
              )
              .nullable(),
          })
          .strict(),
      )
      .max(100),
    reason: initial,
  })
  .strict()
  .refine(
    (r) =>
      new Set(r.findings.map((f) => f.fingerprint)).size === r.findings.length &&
      (r.outcome === 'completed' || r.findings.length === 0) &&
      r.findings.every((f) =>
        r.source === 'github_secret_scanning' ? f.advisory_id === null : f.advisory_id !== null,
      ),
  );
const check = z.enum(['passed', 'failed', 'not_run']);
export const recoveryInput = z
  .object({
    component_id: component,
    kind: z.enum(['backup', 'restore', 'rollback']),
    started_at: instant,
    completed_at: instant,
    recovery_point_at: instant.nullable(),
    outcome: z.enum(['succeeded', 'failed']),
    integrity_check: check,
    application_check: check,
    audit_check: check,
    artifact_digest: hash,
    target_rpo_seconds: z.number().int().min(0).max(604800),
    target_rto_seconds: z.number().int().min(1).max(604800),
    reason: initial,
  })
  .strict()
  .refine((r) => {
    const start = +new Date(r.started_at),
      end = +new Date(r.completed_at),
      point = r.recovery_point_at ? +new Date(r.recovery_point_at) : null;
    return (
      start <= end &&
      end - start <= 30 * 86400000 &&
      (point === null || point <= end) &&
      (r.kind !== 'restore' || (point !== null && point <= start)) &&
      (r.outcome !== 'succeeded' ||
        r.kind === 'backup' ||
        [r.integrity_check, r.application_check, r.audit_check].every((v) => v === 'passed'))
    );
  });
export const findingInput = z
  .object({
    expected_version: z.number().int().min(1).max(2147483647),
    state: z.enum(['open', 'acknowledged', 'resolved', 'accepted_risk']),
    assignee_user_id: z
      .string()
      .regex(/^usr_[a-f0-9]{24}$/)
      .nullable(),
    reason: z.enum(['assignment', 'security_response']),
  })
  .strict()
  .refine((r) => !['resolved', 'accepted_risk'].includes(r.state) || r.assignee_user_id !== null);
const invalid = () => new DomainError('invalid_request', 'request rejected');
const missing = () => new DomainError('not_found', 'not found');
const conflict = () => new DomainError('conflict', 'request rejected');
function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input);
  if (!result.success) throw invalid();
  return result.data;
}
const same = (a: CredentialScope, b: CredentialScope) =>
  a.orgId === b.orgId && a.applicationId === b.applicationId && a.environmentId === b.environmentId;
interface PostureDependencies {
  store: InventoryStore;
  clock: Clock;
  enabled(): boolean;
  authority: InventoryAuthority;
}
export class PostureService {
  readonly #d: PostureDependencies;
  constructor(d: PostureDependencies) {
    this.#d = d;
  }
  async #authorized<T>(
    p: UserPrincipal,
    scope: CredentialScope,
    write: boolean,
    fn: (tx: InventoryTx, now: Date) => Promise<T>,
  ) {
    if (!this.#d.enabled()) throw missing();
    const authorize = async (authority: InventoryAuthority) => {
      await authority.authorize(p, scope.orgId, write ? 'ops:manage_security' : 'ops:read');
      if (!(await authority.sessionActive?.(p, this.#d.clock.now())))
        throw new DomainError('unauthenticated', 'authentication required');
      if (write) {
        try {
          await authority.assertWritable(scope.orgId);
        } catch (error) {
          if (error instanceof DomainError && error.code === 'frozen')
            throw new DomainError('forbidden', 'request rejected');
          throw error;
        }
      }
    };
    await authorize(this.#d.authority);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      await authorize(tx.authority ?? this.#d.authority);
      const a = await tx.find('application', scope.orgId, scope.applicationId),
        e = await tx.find('environment', scope.orgId, scope.environmentId);
      if (!a || !e || e.applicationId !== a.id) throw missing();
      if (write && [a, e].some((r) => r.state !== 'active')) throw conflict();
      return fn(tx, await tx.observeHealthTime(scope.orgId, this.#d.clock.now()));
    });
  }
  async #component(tx: InventoryTx, scope: CredentialScope, id: string) {
    const c = await tx.find('component', scope.orgId, id);
    if (!c || c.applicationId !== scope.applicationId || c.environmentId !== scope.environmentId)
      throw missing();
    if (c.state !== 'active') throw conflict();
  }
  async importScan(p: UserPrincipal, scope: CredentialScope, input: unknown) {
    const body = parse(scanInput, input);
    body.findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
    return this.#authorized(p, scope, true, async (tx, now) => {
      await this.#component(tx, scope, body.component_id);
      const completed = +new Date(body.completed_at);
      if (completed > +now || completed < +now - 30 * 86400000) throw invalid();
      return this.#record(tx, p, scope, 'scan', body, now);
    });
  }
  async recordRecovery(p: UserPrincipal, scope: CredentialScope, input: unknown) {
    const body = parse(recoveryInput, input);
    return this.#authorized(p, scope, true, async (tx, now) => {
      await this.#component(tx, scope, body.component_id);
      if (
        +new Date(body.completed_at) > +now ||
        +new Date(body.started_at) < +now - 365 * 86400000 ||
        (body.recovery_point_at && +new Date(body.recovery_point_at) < +now - 365 * 86400000)
      )
        throw invalid();
      return this.#record(tx, p, scope, 'recovery', body, now);
    });
  }
  async #record(
    tx: InventoryTx,
    p: UserPrincipal,
    scope: CredentialScope,
    kind: SecurityEvidence['kind'],
    body: z.infer<typeof scanInput> | z.infer<typeof recoveryInput>,
    now: Date,
  ) {
    const digest = createHash('sha256').update(JSON.stringify(body)).digest('hex');
    const records = await tx.listSecurityEvidence(scope, kind, 101),
      existing = records.find((r) => r.digest === digest);
    if (existing)
      return {
        id: existing.id,
        created: false,
        provenance: 'admin_report',
        independentlyVerified: false,
      };
    if (records.length >= 100) throw new DomainError('quota_exceeded', 'request rejected');
    if (
      'findings' in body &&
      (await tx.listSecurityFindings(scope, 2001)).length + body.findings.length > 2000
    )
      throw new DomainError('quota_exceeded', 'request rejected');
    const row: SecurityEvidence = {
      ...scope,
      id: newId('ose'),
      componentId: body.component_id,
      kind,
      digest,
      body,
      createdByUserId: p.userId,
      createdAt: now,
    };
    await tx.insertSecurityEvidence(row);
    if ('findings' in body)
      for (const f of body.findings)
        await tx.insertSecurityFinding({
          ...scope,
          id: newId('osf'),
          componentId: row.componentId,
          evidenceId: row.id,
          fingerprint: f.fingerprint,
          severity: f.severity,
          advisoryId: f.advisory_id,
          state: 'open',
          assigneeUserId: null,
          version: 1,
          createdAt: now,
          updatedAt: now,
        });
    await tx.audit.append({
      actor: { type: 'user', id: p.userId },
      orgId: scope.orgId,
      action: kind === 'scan' ? 'operations.scan.imported' : 'operations.recovery.recorded',
      target: { type: 'operations_security_evidence', id: row.id },
      reason: 'initial_setup',
      metadata: { component_id: row.componentId, provenance: 'admin_report', kind },
    });
    return { id: row.id, created: true, provenance: 'admin_report', independentlyVerified: false };
  }
  async configureFinding(p: UserPrincipal, scope: CredentialScope, id: string, input: unknown) {
    const b = parse(findingInput, input);
    return this.#authorized(p, scope, true, async (tx, now) => {
      const old = await tx.findSecurityFinding(scope.orgId, id);
      if (!old || !same(old, scope)) throw missing();
      await this.#component(tx, scope, old.componentId);
      if (old.version !== b.expected_version) throw conflict();
      if (
        b.assignee_user_id &&
        !(await (tx.authority ?? this.#d.authority).activeMember(scope.orgId, b.assignee_user_id))
      )
        throw invalid();
      const row: SecurityFinding = {
        ...old,
        state: b.state,
        assigneeUserId: b.assignee_user_id,
        version: old.version + 1,
        updatedAt: now,
      };
      await tx.updateSecurityFinding(row, old.version);
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        orgId: scope.orgId,
        action: 'operations.finding.triaged',
        target: { type: 'operations_security_finding', id },
        reason: b.reason,
        metadata: { state: row.state, assignee_user_id: row.assigneeUserId, version: row.version },
      });
      return row;
    });
  }
  async read(p: UserPrincipal, scope: CredentialScope) {
    return this.#authorized(p, scope, false, async (tx, now) => {
      const scans = await tx.listSecurityEvidence(scope, 'scan', 26),
        recovery = await tx.listSecurityEvidence(scope, 'recovery', 26),
        findings = await tx.listSecurityFindings(scope, 201);
      const evidence = (r: SecurityEvidence) => {
        const b = r.body,
          kind = r.kind === 'scan' ? 'scan' : String(b['kind']);
        const completed = +new Date(String(b['completed_at']));
        const duration = Math.floor((completed - +new Date(String(b['started_at']))) / 1000);
        const rpo =
          kind === 'restore'
            ? Math.floor(
                (+new Date(String(b['started_at'])) - +new Date(String(b['recovery_point_at']))) /
                  1000,
              )
            : null;
        const current =
          +now - completed <= (kind === 'scan' ? 7 : kind === 'backup' ? 1 : 90) * 86400000;
        const base = {
          id: r.id,
          componentId: r.componentId,
          kind,
          provenance: 'admin_report',
          independentlyVerified: false,
          createdAt: r.createdAt,
          completedAt: b['completed_at'],
          freshness: current ? 'current' : 'stale',
          outcome: b['outcome'],
        };
        if (kind === 'scan')
          return {
            ...base,
            source: b['source'],
            revision: b['revision'],
            runId: b['run_id'],
            findingCount: Array.isArray(b['findings']) ? b['findings'].length : 0,
          };
        return {
          ...base,
          artifactDigest: b['artifact_digest'],
          integrityCheck: b['integrity_check'],
          applicationCheck: b['application_check'],
          auditCheck: b['audit_check'],
          rtoSeconds: kind === 'backup' ? null : duration,
          rpoSeconds: rpo,
          targetRpoSeconds: b['target_rpo_seconds'],
          targetRtoSeconds: b['target_rto_seconds'],
          targetMet:
            kind === 'backup'
              ? null
              : b['outcome'] === 'succeeded' &&
                duration <= Number(b['target_rto_seconds']) &&
                (rpo === null || rpo <= Number(b['target_rpo_seconds'])),
        };
      };
      return {
        assessedAt: now,
        provenance: 'admin_report',
        independentlyVerified: false,
        scans: { items: scans.slice(0, 25).map(evidence), truncated: scans.length > 25 },
        findings: { items: findings.slice(0, 200), truncated: findings.length > 200 },
        recovery: { items: recovery.slice(0, 25).map(evidence), truncated: recovery.length > 25 },
      };
    });
  }
}
