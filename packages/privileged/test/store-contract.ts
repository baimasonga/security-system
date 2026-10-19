import { describe, expect, it } from 'vitest';
import type { Freeze, PrivilegedRequest, PrivilegedStore } from '../src/index.ts';

export interface PrivilegedHarness {
  store: PrivilegedStore;
  /** Actions of durably committed audit events, oldest first. */
  audited(): Promise<string[]>;
}

const T0 = new Date('2026-03-01T00:00:00.000Z');
const ORG_A = `org_${'a'.repeat(24)}`;
const at = (ms: number) => new Date(T0.getTime() + ms);
let n = 0;

export function request(over: Partial<PrivilegedRequest> = {}): PrivilegedRequest {
  n++;
  return {
    id: `prq_${n}_${Math.random().toString(36).slice(2, 10)}`,
    operation: 'license.revoke',
    orgId: ORG_A,
    targetId: 'lic_1',
    reason: 'customer chargeback',
    requestedBy: 'usr_req',
    createdAt: T0,
    expiresAt: at(86_400_000),
    status: 'pending',
    decidedBy: null,
    decidedAt: null,
    decisionReason: null,
    breakGlass: false,
    witnessedAt: null,
    witnessAnchor: null,
    executeBefore: null,
    executedAt: null,
    failure: null,
    ...over,
  };
}

/** One definition of correct PrivilegedStore behaviour, run against every adapter. */
export function privilegedStoreContract(
  name: string,
  make: () => PrivilegedHarness | Promise<PrivilegedHarness>,
) {
  describe(`PrivilegedStore contract: ${name}`, () => {
    it('round-trips requests exactly, including nulls, dates and booleans', async () => {
      const h = await make();
      const pending = request();
      await h.store.insertRequest(pending);
      expect(await h.store.findRequest(pending.id)).toEqual(pending);
      const full = request({
        operation: 'operator.grant',
        orgId: null,
        targetId: 'usr_x',
        status: 'executed',
        requestedBy: 'usr_app',
        decidedBy: 'usr_app',
        decidedAt: at(1000),
        decisionReason: 'verified with the requester',
        breakGlass: true,
        witnessedAt: at(2000),
        witnessAnchor: 'anc_1',
        executeBefore: at(3000),
        executedAt: at(2500),
        failure: null,
      });
      await h.store.insertRequest(full);
      expect(await h.store.findRequest(full.id)).toEqual(full);
      expect(await h.store.findRequest('prq_missing')).toBeUndefined();
      await expect(h.store.insertRequest(pending)).rejects.toThrow();
    });

    it('updates every mutable column and nothing of another row', async () => {
      const h = await make();
      const a = request();
      const b = request();
      await h.store.insertRequest(a);
      await h.store.insertRequest(b);
      const next: PrivilegedRequest = {
        ...a,
        status: 'failed',
        decidedBy: 'usr_app',
        decidedAt: at(10),
        decisionReason: 'checked with finance',
        executeBefore: at(20),
        failure: 'conflict',
      };
      await h.store.updateRequest(next);
      expect(await h.store.findRequest(a.id)).toEqual(next);
      expect(await h.store.findRequest(b.id)).toEqual(b);
    });

    it('lists newest first, filters by status and bounds the result', async () => {
      const h = await make();
      const rows = [0, 1, 2, 3].map((i) =>
        request({ createdAt: at(i * 1000), status: i === 2 ? 'approved' : 'pending' }),
      );
      for (const r of rows) await h.store.insertRequest(r);
      const all = await h.store.listRequests({ limit: 50 });
      expect(all.map((r) => r.id)).toEqual(
        [...rows]
          .reverse()
          .map((r) => r.id)
          .filter((id) => all.some((x) => x.id === id)),
      );
      expect(
        (await h.store.listRequests({ status: 'approved', limit: 50 })).map((r) => r.id),
      ).toEqual([rows[2]!.id]);
      expect(await h.store.listRequests({ limit: 2 })).toHaveLength(2);
    });

    it('counts only break-glass decisions by that operator since the given time', async () => {
      const h = await make();
      await h.store.insertRequest(
        request({
          breakGlass: true,
          requestedBy: 'usr_a',
          decidedBy: 'usr_a',
          decidedAt: at(5000),
          status: 'approved',
        }),
      );
      await h.store.insertRequest(
        request({
          breakGlass: true,
          requestedBy: 'usr_a',
          decidedBy: 'usr_a',
          decidedAt: at(100),
          status: 'executed',
        }),
      );
      await h.store.insertRequest(
        request({ breakGlass: false, decidedBy: 'usr_a', decidedAt: at(6000), status: 'approved' }),
      );
      await h.store.insertRequest(
        request({
          breakGlass: true,
          requestedBy: 'usr_b',
          decidedBy: 'usr_b',
          decidedAt: at(6000),
          status: 'approved',
        }),
      );
      expect(await h.store.countBreakGlassSince('usr_a', at(1000))).toBe(1);
      expect(await h.store.countBreakGlassSince('usr_a', at(0))).toBe(2);
      expect(await h.store.countBreakGlassSince('usr_c', at(0))).toBe(0);
    });

    it('keeps one freeze per scope; delete is idempotent; lists oldest first', async () => {
      const h = await make();
      const p: Freeze = {
        scope: 'platform',
        reason: 'incident',
        frozenBy: 'usr_a',
        frozenAt: at(2),
      };
      const o: Freeze = {
        scope: `org:${ORG_A}`,
        reason: 'takeover',
        frozenBy: 'usr_b',
        frozenAt: at(1),
      };
      await h.store.insertFreeze(p);
      await h.store.insertFreeze(o);
      await expect(h.store.insertFreeze({ ...p, reason: 'again' })).rejects.toThrow();
      expect(await h.store.getFreeze('platform')).toEqual(p);
      expect(await h.store.listFreezes()).toEqual([o, p]);
      await h.store.deleteFreeze(`org:${ORG_A}`);
      await h.store.deleteFreeze(`org:${ORG_A}`);
      expect(await h.store.getFreeze(`org:${ORG_A}`)).toBeUndefined();
      expect(await h.store.listFreezes()).toEqual([p]);
    });

    it('rolls back writes and audit events together when the transaction fails', async () => {
      const h = await make();
      const r = request();
      await expect(
        h.store.transaction(async (tx) => {
          await tx.insertRequest(r);
          await tx.insertFreeze({
            scope: 'platform',
            reason: 'incident',
            frozenBy: 'u',
            frozenAt: T0,
          });
          await tx.audit.append({
            actor: { type: 'operator', id: 'u' },
            action: 'privileged.test_rolled_back',
          });
          throw new Error('boom');
        }),
      ).rejects.toThrow('boom');
      expect(await h.store.findRequest(r.id)).toBeUndefined();
      expect(await h.store.getFreeze('platform')).toBeUndefined();
      expect(await h.audited()).not.toContain('privileged.test_rolled_back');
      await h.store.transaction(async (tx) => {
        await tx.insertRequest(r);
        await tx.audit.append({
          actor: { type: 'operator', id: 'u' },
          action: 'privileged.test_committed',
        });
      });
      expect(await h.audited()).toContain('privileged.test_committed');
    });

    it('serializes concurrent transitions of one request under its row lock', async () => {
      const h = await make();
      const r = request();
      await h.store.insertRequest(r);
      const approve = (who: string) =>
        h.store.transaction(async (tx) => {
          const cur = await tx.findRequestForUpdate(r.id);
          if (cur?.status !== 'pending') return false;
          await new Promise((res) => setTimeout(res, 20));
          await tx.updateRequest({ ...cur, status: 'approved', decidedBy: who, decidedAt: T0 });
          return true;
        });
      const results = await Promise.all([approve('usr_x'), approve('usr_y'), approve('usr_z')]);
      expect(results.filter(Boolean)).toHaveLength(1);
    });
  });
}
