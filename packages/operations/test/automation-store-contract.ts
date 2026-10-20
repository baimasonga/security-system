import { expect, it } from 'vitest';
import type { AlertRule, CredentialScope, InventoryStore } from '../src/index.ts';
export function automationStoreContract(
  make: () => Promise<{ store: InventoryStore; scope: CredentialScope; componentId: string }>,
) {
  it('persists scoped rule versions, bounded receipt counts and atomic rollback', async () => {
    const { store, scope, componentId } = await make();
    const now = new Date('2026-10-20T00:00:00Z');
    const rule: AlertRule = {
      ...scope,
      id: 'opr_' + 'a'.repeat(24),
      componentId,
      kind: 'event_count',
      eventType: 'conversion.failed',
      threshold: 2,
      windowSeconds: 60,
      severity: 'warning',
      runbook: 'check_converter',
      enabled: true,
      maintenanceUntil: null,
      createdByUserId: 'usr_' + 'a'.repeat(24),
      version: 1,
      createdAt: now,
      updatedAt: now,
      evaluatedAt: null,
      badSince: null,
      recoverySince: null,
      incidentId: null,
      observation: 'unknown',
      observedCount: 0,
    };
    await store.transaction(scope.orgId, (tx) => tx.insertAlertRule(rule));
    expect(await store.findAlertRule(scope.orgId, rule.id)).toEqual(rule);
    expect(await store.findAlertRule('org_' + 'f'.repeat(24), rule.id)).toBeUndefined();
    expect(
      await store.listAlertRules({ ...scope, environmentId: 'ope_' + 'f'.repeat(24) }),
    ).toEqual([]);
    await expect(
      store.transaction(scope.orgId, async (tx) => {
        await tx.updateAlertRule({ ...rule, version: 2, enabled: false }, 1);
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect((await store.findAlertRule(scope.orgId, rule.id))?.enabled).toBe(true);
    await store.transaction(scope.orgId, (tx) =>
      tx.updateAlertRule({ ...rule, version: 2, enabled: false }, 1),
    );
    await expect(
      store.transaction(scope.orgId, (tx) => tx.updateAlertRule({ ...rule, version: 2 }, 1)),
    ).rejects.toThrow();
    expect(
      await store.countAlertEvents(
        scope,
        componentId,
        'conversion.failed',
        now,
        new Date(+now + 60000),
        2,
      ),
    ).toBe(0);
  });
}
