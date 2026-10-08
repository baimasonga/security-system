import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.ts';
import { makeEnv } from './harness.ts';

const env_ = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;

describe('AUDIT_CHAIN_SHARDS (ADR-008) — operator knob', () => {
  it('validates the range and defaults to a single chain per organization', () => {
    expect(loadConfig(env_({})).auditChainShards).toBe(1);
    expect(loadConfig(env_({ AUDIT_CHAIN_SHARDS: '8' })).auditChainShards).toBe(8);
    for (const bad of ['0', '65', 'abc', '-1']) {
      expect(() => loadConfig(env_({ AUDIT_CHAIN_SHARDS: bad })), bad).toThrow(
        /AUDIT_CHAIN_SHARDS/,
      );
    }
  });

  async function verifyOrg(shards: number) {
    const env = await makeEnv({ config: { auditChainShards: shards } });
    const owner = await env.register('owner@example.test');
    const p = await env.provision(owner.orgId);
    const op = await env.operatorToken();
    for (let i = 0; i < 12; i++) {
      const r = await env.call('POST', `/v1/admin/organizations/${owner.orgId}/licenses`, {
        token: op,
        body: {
          product_id: p.productId,
          plan_id: p.planId,
          kind: 'subscription',
          subscription_id: p.subId,
          reason: 'shard spread test',
        },
      });
      expect(r.status).toBe(201);
    }
    const scoped = await env.call('GET', `/v1/admin/audit/verify?org_id=${owner.orgId}`, {
      token: op,
    });
    const all = await env.call('GET', '/v1/admin/audit/verify', { token: op });
    return { scoped: scoped.body, all: all.body };
  }

  it('the setting reaches the service: one chain per org by default, several when sharded; both verify', async () => {
    const one = await verifyOrg(1);
    expect(one.scoped).toMatchObject({ ok: true, chains: 1 });
    const many = await verifyOrg(4);
    expect(many.scoped).toMatchObject({ ok: true });
    expect(many.scoped.chains).toBeGreaterThan(1);
    expect(many.all).toMatchObject({ ok: true });
    expect(many.scoped.count).toBeGreaterThan(12);
  });
});
