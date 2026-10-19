import { afterEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { totpCode } from '../../../packages/auth/src/mfa.ts';
import { loadConfig } from '../src/config.ts';
import type { AnchorSink } from '../src/anchors.ts';
import { makeEnv, PW, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

const MFA_KEY = randomBytes(32).toString('hex');
const decode = (key: string) => {
  const out: number[] = [];
  let value = 0,
    bits = 0;
  for (const ch of key) {
    value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 255);
    }
  }
  return Buffer.from(out);
};

interface Op {
  userId: string;
  token: string;
  /** A fresh code: advances the clock one step so each code is new (the counter is replay-protected). */
  code: () => string;
}

async function setup(opts?: { dualControl?: boolean; sink?: AnchorSink }) {
  env = await makeEnv({
    config: { mfaEncryptionKey: MFA_KEY, privilegedDualControl: opts?.dualControl ?? false },
    ...(opts?.sink ? { container: { anchorSink: opts.sink } } : {}),
  });
  const operatorWithMfa = async (email: string): Promise<Op> => {
    const u = await env.register(email);
    await env.c.auth.bootstrapPlatformAdmin(email, 'test operator');
    const begin = await env.call('POST', '/v1/auth/mfa/begin', {
      token: u.token,
      body: { password: PW },
    });
    const secret = decode(begin.body.setup_key);
    const now = () => totpCode(secret, Math.floor(env.clock.now().getTime() / 30000));
    await env.call('POST', '/v1/auth/mfa/confirm', {
      token: u.token,
      body: { password: PW, code: now() },
    });
    env.clock.advance(30000);
    const login = await env.call('POST', '/v1/auth/login', {
      body: { email, password: PW, code: now() },
    });
    expect(login.status).toBe(200);
    return {
      userId: u.userId,
      token: login.body.token,
      code: () => {
        env.clock.advance(30000);
        return now();
      },
    };
  };
  const a = await operatorWithMfa('alice-op@example.test');
  const b = await operatorWithMfa('bob-op@example.test');
  const customer = await env.register('customer@example.test');
  const lic = await env.provision(customer.orgId);
  const req = (op: Op, method: string, path: string, body?: unknown) =>
    env.call(method, `/v1/admin${path}`, { token: op.token, ...(body ? { body } : {}) });
  const licenseState = async () =>
    (await req(a, 'GET', `/organizations/${customer.orgId}/licenses`)).body.items.find(
      (l: { id: string }) => l.id === lic.licenseId,
    ).state as string;
  return { a, b, customer, lic, req, licenseState };
}

describe('privileged operations configuration', () => {
  it('validates PRIVILEGED_DUAL_CONTROL and requires the MFA key with it', () => {
    const base = { NODE_ENV: 'test' } as NodeJS.ProcessEnv;
    expect(loadConfig(base).privilegedDualControl).toBe(false);
    expect(() => loadConfig({ ...base, PRIVILEGED_DUAL_CONTROL: 'yes' })).toThrow(/true or false/);
    expect(() => loadConfig({ ...base, PRIVILEGED_DUAL_CONTROL: 'true' })).toThrow(
      /MFA_ENCRYPTION_KEY/,
    );
    expect(
      loadConfig({ ...base, PRIVILEGED_DUAL_CONTROL: 'true', MFA_ENCRYPTION_KEY: MFA_KEY })
        .privilegedDualControl,
    ).toBe(true);
  });

  it('PRIVILEGED_DUAL_CONTROL=true makes the direct revoke endpoint refuse; off, it works', async () => {
    const on = await setup({ dualControl: true });
    const path = `/organizations/${on.customer.orgId}/licenses/${on.lic.licenseId}/revoke`;
    const refused = await on.req(on.a, 'POST', path, { reason: 'chargeback' });
    expect(refused.status).toBe(409);
    expect(refused.body.details).toEqual({ approval_required: true });
    expect(await on.licenseState()).toBe('active');
    await env.app.close();
    const off = await setup({ dualControl: false });
    const path2 = `/organizations/${off.customer.orgId}/licenses/${off.lic.licenseId}/revoke`;
    expect((await off.req(off.a, 'POST', path2, { reason: 'chargeback' })).status).toBe(200);
    expect(await off.licenseState()).toBe('revoked');
  });
});

describe('dual control', () => {
  it('revokes a license only after a distinct operator approves with a fresh code, exactly once', async () => {
    const { a, b, customer, lic, req, licenseState } = await setup({ dualControl: true });
    const created = await req(a, 'POST', '/privileged/requests', {
      operation: 'license.revoke',
      org_id: customer.orgId,
      license_id: lic.licenseId,
      reason: 'confirmed fraudulent purchase',
    });
    expect(created.status).toBe(201);
    const id = created.body.id as string;
    expect(created.body).toMatchObject({ status: 'pending', requested_by: a.userId });
    const approve = (op: Op, code: string) =>
      req(op, 'POST', `/privileged/requests/${id}/approve`, {
        reason: 'checked with finance',
        code,
      });
    expect((await approve(a, a.code())).status).toBe(403); // never your own request
    expect((await approve(b, '000000')).status).toBe(401);
    expect(
      (await req(a, 'POST', `/privileged/requests/${id}/execute`, { reason: 'run it' })).status,
    ).toBe(409);
    const ok = await approve(b, b.code());
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ status: 'approved', decided_by: b.userId });
    expect((await approve(b, b.code())).status).toBe(409); // replayed approval
    expect(
      (await req(b, 'POST', `/privileged/requests/${id}/execute`, { reason: 'run it' })).status,
    ).toBe(403); // the grant binds to the requester
    const done = await req(a, 'POST', `/privileged/requests/${id}/execute`, { reason: 'run it' });
    expect(done.status).toBe(200);
    expect(done.body.status).toBe('executed');
    expect(await licenseState()).toBe('revoked');
    expect(
      (await req(a, 'POST', `/privileged/requests/${id}/execute`, { reason: 'again' })).status,
    ).toBe(409);
    const audit = (await req(a, 'GET', '/audit?limit=200')).body.items.map(
      (e: { action: string }) => e.action,
    );
    for (const action of [
      'privileged.requested',
      'identity.step_up_succeeded',
      'privileged.approved',
      'privileged.execution_started',
      'license.revoked',
      'privileged.executed',
    ])
      expect(audit).toContain(action);
    const listed = await req(b, 'GET', '/privileged/requests?status=executed');
    expect(listed.body.items.map((r: { id: string }) => r.id)).toEqual([id]);
  });

  it('promotes an operator only through an approved request', async () => {
    const { a, b, req } = await setup();
    const c = await env.register('carol@example.test');
    expect((await env.call('GET', '/v1/admin/audit', { token: c.token })).status).toBe(403);
    const r = await req(a, 'POST', '/privileged/requests', {
      operation: 'operator.grant',
      user_id: c.userId,
      reason: 'new on-call engineer',
    });
    expect(r.status).toBe(201);
    await req(b, 'POST', `/privileged/requests/${r.body.id}/approve`, {
      reason: 'manager confirmed',
      code: b.code(),
    });
    expect(
      (await req(a, 'POST', `/privileged/requests/${r.body.id}/execute`, { reason: 'grant' }))
        .status,
    ).toBe(200);
    expect((await env.call('GET', '/v1/admin/audit', { token: c.token })).status).toBe(200);
    // already an operator: a second grant request is refused at creation
    expect(
      (
        await req(a, 'POST', '/privileged/requests', {
          operation: 'operator.grant',
          user_id: c.userId,
          reason: 'duplicate',
        })
      ).status,
    ).toBe(409);
  });

  it('never accepts the same authenticator code twice for approvals', async () => {
    const { a, b, customer, lic, req } = await setup();
    const make = () =>
      req(a, 'POST', '/privileged/requests', {
        operation: 'license.revoke',
        org_id: customer.orgId,
        license_id: lic.licenseId,
        reason: 'chargeback',
      });
    const r1 = (await make()).body.id;
    const r2 = (await make()).body.id;
    const code = b.code();
    const approve = (id: string) =>
      req(b, 'POST', `/privileged/requests/${id}/approve`, { reason: 'approved', code });
    expect((await approve(r1)).status).toBe(200);
    expect((await approve(r2)).status).toBe(401);
  });

  it('refuses an approver without MFA, non-operators and malformed requests', async () => {
    const { a, customer, lic, req } = await setup();
    const plain = await env.register('plain-op@example.test');
    await env.c.auth.bootstrapPlatformAdmin('plain-op@example.test', 'operator without MFA');
    const r = await req(a, 'POST', '/privileged/requests', {
      operation: 'license.revoke',
      org_id: customer.orgId,
      license_id: lic.licenseId,
      reason: 'chargeback',
    });
    const noMfa = await env.call('POST', `/v1/admin/privileged/requests/${r.body.id}/approve`, {
      token: plain.token,
      body: { reason: 'looks fine', code: '123456' },
    });
    expect(noMfa.status).toBe(403);
    expect(
      (await env.call('GET', '/v1/admin/privileged/requests', { token: customer.token })).status,
    ).toBe(403);
    const bad = [
      { operation: 'license.revoke', org_id: customer.orgId, reason: 'missing license' },
      { operation: 'platform.unfreeze', org_id: customer.orgId, reason: 'extra field' },
      { operation: 'delete.everything', reason: 'unknown operation' },
      { operation: 'operator.grant', user_id: plain.userId, reason: 'x' },
    ];
    for (const body of bad)
      expect((await req(a, 'POST', '/privileged/requests', body)).status).toBe(400);
  });
});

describe('freeze', () => {
  it('stops grant-extending writes for a frozen organization while containment and reads work', async () => {
    const { a, b, customer, lic, req, licenseState } = await setup();
    const org = customer.orgId;
    expect(
      (await req(a, 'POST', '/freezes', { scope: 'organization', org_id: org, reason: 'takeover' }))
        .status,
    ).toBe(201);
    expect((await req(b, 'GET', '/freezes')).body.items).toHaveLength(1);
    const issue = await req(a, 'POST', `/organizations/${org}/licenses`, {
      product_id: lic.productId,
      plan_id: lic.planId,
      kind: 'subscription',
      subscription_id: lic.subId,
      reason: 'extra seat',
    });
    expect(issue.status).toBe(423);
    expect(issue.body.code).toBe('frozen');
    expect(
      (
        await req(a, 'PATCH', `/organizations/${org}/subscriptions/${lic.subId}`, {
          status: 'active',
          reason: 'extend',
        })
      ).status,
    ).toBe(423);
    // containment still works; restoring access does not
    const lp = `/organizations/${org}/licenses/${lic.licenseId}`;
    expect((await req(a, 'POST', `${lp}/suspend`, { reason: 'contain' })).status).toBe(200);
    expect((await req(a, 'POST', `${lp}/reinstate`, { reason: 'restore' })).status).toBe(423);
    expect(await licenseState()).toBe('suspended');
    // customers: members see the freeze; outsiders get the same 404 as for any foreign org
    const addMember = (token: string) =>
      env.call('POST', `/v1/organizations/${org}/members`, {
        token,
        body: { email: 'friend@example.test', role: 'member' },
      });
    expect((await addMember(customer.token)).status).toBe(423);
    const outsider = await env.register('outsider@example.test');
    expect((await addMember(outsider.token)).status).toBe(404);
    expect(
      (
        await env.call('POST', `/v1/organizations/${org}/trials`, {
          token: customer.token,
          body: { product_id: lic.productId },
        })
      ).status,
    ).toBe(423);
    // reads keep working
    expect(
      (await env.call('GET', `/v1/organizations/${org}/licenses`, { token: customer.token }))
        .status,
    ).toBe(200);
    // lifting needs dual control
    const lift = await req(a, 'POST', '/privileged/requests', {
      operation: 'org.unfreeze',
      org_id: org,
      reason: 'investigation closed',
    });
    await req(b, 'POST', `/privileged/requests/${lift.body.id}/approve`, {
      reason: 'confirmed closed',
      code: b.code(),
    });
    expect(
      (await req(a, 'POST', `/privileged/requests/${lift.body.id}/execute`, { reason: 'lift' }))
        .status,
    ).toBe(200);
    expect((await req(a, 'POST', `${lp}/reinstate`, { reason: 'restore' })).status).toBe(200);
    expect((await req(b, 'GET', '/freezes')).body.items).toEqual([]);
  });

  it('a platform freeze blocks catalog changes and every organization', async () => {
    const { a, customer, lic, req } = await setup();
    expect(
      (await req(a, 'POST', '/freezes', { scope: 'platform', reason: 'incident' })).status,
    ).toBe(201);
    expect((await req(a, 'POST', '/freezes', { scope: 'platform', reason: 'again' })).status).toBe(
      409,
    );
    expect(
      (await req(a, 'POST', '/products', { code: 'other-app', name: 'Other', reason: 'launch' }))
        .status,
    ).toBe(423);
    expect(
      (await req(a, 'PATCH', `/plans/${lic.planId}`, { device_limit: 9, reason: 'bigger plan' }))
        .status,
    ).toBe(423);
    expect(
      (
        await env.call('POST', `/v1/organizations/${customer.orgId}/members`, {
          token: customer.token,
          body: { email: 'x@example.test', role: 'member' },
        })
      ).status,
    ).toBe(423);
  });
});

describe('break-glass', () => {
  it('is refused without an external witness', async () => {
    const { a, customer, lic, req } = await setup();
    const r = await req(a, 'POST', '/privileged/requests', {
      operation: 'license.revoke',
      org_id: customer.orgId,
      license_id: lic.licenseId,
      reason: 'chargeback',
    });
    const bg = await req(a, 'POST', `/privileged/requests/${r.body.id}/break-glass`, {
      reason: 'nobody else on call',
      code: a.code(),
    });
    expect(bg.status).toBe(409);
  });

  it('self-approves, is usable only after the witness acknowledges, and the witness can be retried', async () => {
    let up = false;
    const published: string[] = [];
    const sink: AnchorSink = {
      destination: 'test-witness',
      publish: async (m) => {
        if (!up) throw new Error('witness unavailable');
        published.push(m.anchor);
        return { receipt: 'rcpt' };
      },
    };
    const { a, customer, lic, req, licenseState } = await setup({ sink });
    const r = await req(a, 'POST', '/privileged/requests', {
      operation: 'license.revoke',
      org_id: customer.orgId,
      license_id: lic.licenseId,
      reason: 'active fraud',
    });
    const id = r.body.id as string;
    const bg = await req(a, 'POST', `/privileged/requests/${id}/break-glass`, {
      reason: 'nobody else on call',
      code: a.code(),
    });
    expect(bg.status).toBe(200);
    expect(bg.body).toMatchObject({ status: 'approved', break_glass: true, witnessed_at: null });
    expect(bg.body.witness.status).toBe('failed');
    expect(
      (await req(a, 'POST', `/privileged/requests/${id}/execute`, { reason: 'run it' })).status,
    ).toBe(409);
    up = true;
    const w = await req(a, 'POST', `/privileged/requests/${id}/witness`, {
      reason: 'retry witness',
    });
    expect(w.status).toBe(200);
    expect(w.body.witness_anchor).toBe(published.at(-1));
    expect(
      (await req(a, 'POST', `/privileged/requests/${id}/execute`, { reason: 'run it' })).status,
    ).toBe(200);
    expect(await licenseState()).toBe('revoked');
    const audit = (await req(a, 'GET', '/audit?limit=200')).body.items.map(
      (e: { action: string }) => e.action,
    );
    expect(audit).toContain('privileged.break_glass');
    expect(audit).toContain('privileged.break_glass_witnessed');
  });
});
