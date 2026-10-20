import { expect, it } from 'vitest';
import type { InventoryStore, SecurityEvidence, SecurityFinding } from '../src/index.ts';
import { application } from './store-contract.ts';
export function postureStoreContract(make: () => Promise<InventoryStore>) {
  it('keeps posture snapshots scoped, immutable and atomic with findings and audit', async () => {
    const store = await make();
    const a = application();
    const now = a.createdAt;
    const scope = { orgId: a.orgId, applicationId: a.id, environmentId: 'ope_' + '2'.repeat(24) };
    const componentId = 'opm_' + '3'.repeat(24);
    await store.transaction(a.orgId, async (tx) => {
      await tx.insert('application', a);
      await tx.insert('environment', {
        ...a,
        id: scope.environmentId,
        applicationId: a.id,
        kind: 'staging',
      });
      await tx.insert('component', {
        ...a,
        id: componentId,
        applicationId: a.id,
        environmentId: scope.environmentId,
        kind: 'database',
        dependencyIds: [],
      });
    });
    const record: SecurityEvidence = {
      ...scope,
      id: 'ose_' + '4'.repeat(24),
      componentId,
      kind: 'scan',
      digest: '5'.repeat(64),
      body: {},
      createdByUserId: a.ownerUserId,
      createdAt: now,
    };
    const finding: SecurityFinding = {
      ...scope,
      id: 'osf_' + '6'.repeat(24),
      componentId,
      evidenceId: record.id,
      fingerprint: '7'.repeat(64),
      severity: 'high',
      advisoryId: null,
      state: 'open',
      assigneeUserId: null,
      version: 1,
      createdAt: now,
      updatedAt: now,
    };
    await expect(
      store.transaction(a.orgId, (tx) =>
        tx.insertSecurityEvidence({ ...record, componentId: 'opm_' + 'f'.repeat(24) }),
      ),
    ).rejects.toThrow();
    await expect(
      store.transaction(a.orgId, async (tx) => {
        await tx.insertSecurityEvidence(record);
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(await store.listSecurityEvidence(scope, 'scan', 100)).toEqual([]);
    await store.transaction(a.orgId, async (tx) => {
      await tx.insertSecurityEvidence(record);
      await tx.insertSecurityFinding(finding);
    });
    expect(await store.listSecurityEvidence({ ...scope, orgId: 'org_other' }, 'scan', 100)).toEqual(
      [],
    );
    expect(await store.findSecurityFinding('org_other', finding.id)).toBeUndefined();
    const read = (await store.listSecurityEvidence(scope, 'scan', 100))[0]!;
    read.body['changed'] = true;
    expect((await store.listSecurityEvidence(scope, 'scan', 100))[0]!.body).toEqual({});
    await expect(
      store.transaction(a.orgId, (tx) =>
        tx.insertSecurityEvidence({ ...record, id: 'ose_' + '8'.repeat(24) }),
      ),
    ).rejects.toThrow();
    await expect(
      store.transaction(a.orgId, (tx) =>
        tx.updateSecurityFinding({ ...finding, fingerprint: '9'.repeat(64), version: 2 }, 1),
      ),
    ).rejects.toThrow();
    await store.transaction(a.orgId, (tx) =>
      tx.updateSecurityFinding({ ...finding, state: 'acknowledged', version: 2 }, 1),
    );
    await expect(
      store.transaction(a.orgId, (tx) => tx.updateSecurityFinding({ ...finding, version: 2 }, 1)),
    ).rejects.toThrow();
    expect((await store.listSecurityFindings(scope, 100))[0]!.state).toBe('acknowledged');
  });
}
