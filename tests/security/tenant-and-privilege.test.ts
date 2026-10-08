import { afterEach, describe, expect, it } from 'vitest';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { buildProofMessage } from '@trust/crypto/verify';
import { DAY, PW, makeEnv, type Env } from '../../services/platform-api/test/harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

/** Strip fields that legitimately differ per request. */
const shape = (r: { status: number; body: any }) => ({
  status: r.status,
  code: r.body?.code,
  message: r.body?.message,
});

async function twoTenants() {
  env = await makeEnv();
  const alice = await env.register('alice@example.test');
  const bob = await env.register('bob@example.test');
  const a = await env.provision(alice.orgId);
  return { alice, bob, ...a };
}

async function activateVia(
  token: string,
  licenseKey: string,
  dev = SoftwareDeviceKey.generate(),
  inst = 'inst_' + Math.random().toString(36).slice(2).padEnd(20, 'x'),
) {
  const ch = await env.call('POST', '/v1/devices/challenges', {
    body: { purpose: 'activate', installation_id: inst },
  });
  const signature = dev.sign(
    buildProofMessage({
      purpose: 'activate',
      nonce: ch.body.nonce,
      installationId: inst,
      subjectId: '',
      thumbprint: dev.thumbprint,
    }),
  );
  const body = {
    license_key: licenseKey,
    installation_id: inst,
    device_public_key: dev.publicJwk,
    nonce: ch.body.nonce,
    signature,
  };
  return { res: await env.call('POST', '/v1/licenses/activate', { token, body }), body, dev, inst };
}

describe('tenant isolation (object-level authorization)', () => {
  it("another tenant's resources are indistinguishable from nonexistent ones (no existence oracle)", async () => {
    const { alice, bob, licenseId } = await twoTenants();
    const real = [
      `/v1/organizations/${alice.orgId}`,
      `/v1/organizations/${alice.orgId}/members`,
      `/v1/organizations/${alice.orgId}/licenses`,
      `/v1/organizations/${alice.orgId}/licenses/${licenseId}`,
      `/v1/organizations/${alice.orgId}/licenses/${licenseId}/activations`,
      `/v1/entitlements?org_id=${alice.orgId}&license_id=${licenseId}`,
    ];
    for (const url of real) {
      const probe = await env.call('GET', url, { token: bob.token });
      const ghost = await env.call(
        'GET',
        url
          .replaceAll(alice.orgId, 'org_000000000000000000000000')
          .replaceAll(licenseId, 'lic_000000000000000000000000'),
        { token: bob.token },
      );
      expect(probe.status, url).toBe(404);
      expect(shape(probe), url).toEqual(shape(ghost));
      expect(JSON.stringify(probe.body)).not.toContain(alice.orgId);
    }
  });

  it("bob cannot use his own org id with alice's license id (cross-reference)", async () => {
    const { bob, licenseId } = await twoTenants();
    const r = await env.call('GET', `/v1/organizations/${bob.orgId}/licenses/${licenseId}`, {
      token: bob.token,
    });
    expect(r.status).toBe(404);
    const e = await env.call(
      'GET',
      `/v1/entitlements?org_id=${bob.orgId}&license_id=${licenseId}`,
      { token: bob.token },
    );
    expect(e.status).toBe(404);
  });

  it("bob cannot deactivate, start trials in, or add himself to alice's org", async () => {
    const { alice, bob, licenseKey } = await twoTenants();
    const { res } = await activateVia(alice.token, licenseKey);
    expect(res.status).toBe(200);
    const actId = res.body.activation_id;
    expect(
      (
        await env.call('POST', `/v1/organizations/${alice.orgId}/activations/${actId}/deactivate`, {
          token: bob.token,
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await env.call('POST', `/v1/organizations/${alice.orgId}/trials`, {
          token: bob.token,
          body: { product_id: 'prd_000000000000000000000000' },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await env.call('POST', `/v1/organizations/${alice.orgId}/members`, {
          token: bob.token,
          body: { email: 'bob@example.test', role: 'owner' },
        })
      ).status,
    ).toBe(404);
    const still = await env.call('GET', `/v1/organizations/${alice.orgId}/licenses`, {
      token: alice.token,
    });
    expect(still.body.items[0].active_devices).toBe(1);
  });

  it('a stolen license key is useless to a user outside the owning org — identical to a wrong key', async () => {
    const { bob, licenseKey, licenseId, alice } = await twoTenants();
    const stolen = await activateVia(bob.token, licenseKey);
    const wrong = await activateVia(bob.token, 'LK-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA');
    expect(shape(stolen.res)).toEqual(shape(wrong.res));
    expect(stolen.res.status).toBe(403);
    const lic = await env.call('GET', `/v1/organizations/${alice.orgId}/licenses/${licenseId}`, {
      token: alice.token,
    });
    expect(lic.body.active_devices).toBe(0);
  });

  it('activation also requires a session — the key alone is not authority', async () => {
    const { licenseKey } = await twoTenants();
    const noSession = await activateVia('', licenseKey);
    expect(noSession.res.status).toBe(401);
  });
});

describe('privilege escalation', () => {
  it('members cannot manage membership; admins cannot mint owners; roles cannot be mass-assigned', async () => {
    env = await makeEnv();
    const owner = await env.register('owner@example.test');
    const admin = await env.register('admin@example.test');
    const member = await env.register('member@example.test');
    await env.register('target@example.test');
    const team = (
      await env.call('POST', '/v1/organizations', { token: owner.token, body: { name: 'Acme' } })
    ).body.id as string;
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/members`, {
          token: owner.token,
          body: { email: 'admin@example.test', role: 'admin' },
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/members`, {
          token: owner.token,
          body: { email: 'member@example.test', role: 'member' },
        })
      ).status,
    ).toBe(201);

    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/members`, {
          token: member.token,
          body: { email: 'target@example.test', role: 'member' },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/members`, {
          token: admin.token,
          body: { email: 'target@example.test', role: 'owner' },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/members`, {
          token: admin.token,
          body: { email: 'target@example.test', role: 'member', platform_role: 'platform_admin' },
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/members`, {
          token: admin.token,
          body: { email: 'target@example.test', role: 'member' },
        })
      ).status,
    ).toBe(201);
    // personal orgs cannot gain members
    expect(
      (
        await env.call('POST', `/v1/organizations/${owner.orgId}/members`, {
          token: owner.token,
          body: { email: 'target@example.test', role: 'member' },
        })
      ).status,
    ).toBe(403);
  });

  it('a member may deactivate only their own device; an admin may deactivate any', async () => {
    env = await makeEnv();
    const owner = await env.register('owner@example.test');
    const m1 = await env.register('m1@example.test');
    const m2 = await env.register('m2@example.test');
    const team = (
      await env.call('POST', '/v1/organizations', { token: owner.token, body: { name: 'Acme' } })
    ).body.id as string;
    for (const e of ['m1@example.test', 'm2@example.test'])
      await env.call('POST', `/v1/organizations/${team}/members`, {
        token: owner.token,
        body: { email: e, role: 'member' },
      });
    const { licenseKey } = await env.provision(team);
    const a1 = (await activateVia(m1.token, licenseKey)).res.body.activation_id;
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/activations/${a1}/deactivate`, {
          token: m2.token,
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/activations/${a1}/deactivate`, {
          token: m1.token,
        })
      ).status,
    ).toBe(200);
    const a2 = (await activateVia(m1.token, licenseKey)).res.body.activation_id;
    expect(
      (
        await env.call('POST', `/v1/organizations/${team}/activations/${a2}/deactivate`, {
          token: owner.token,
        })
      ).status,
    ).toBe(200);
  });

  it('platform-operator routes reject anonymous users and ordinary customers — including org owners', async () => {
    const { alice } = await twoTenants();
    const routes: Array<[string, string, object?]> = [
      ['POST', '/v1/admin/products', { code: 'x-1', name: 'X', reason: 'because' }],
      ['GET', `/v1/admin/organizations/${alice.orgId}/licenses`],
      ['GET', '/v1/admin/audit'],
      ['GET', '/v1/admin/audit/verify'],
    ];
    for (const [m, u, body] of routes) {
      expect((await env.call(m, u, body ? { body } : {})).status, `${m} ${u} anon`).toBe(401);
      expect(
        (await env.call(m, u, { token: alice.token, ...(body ? { body } : {}) })).status,
        `${m} ${u} owner`,
      ).toBe(403);
    }
    expect((await env.c.audit.list({ action: 'admin.access_denied' })).length).toBeGreaterThan(0);
  });

  it('operator role is re-checked per request: demotion takes effect before the session expires', async () => {
    const { alice } = await twoTenants();
    const op = await env.operatorToken();
    const url = `/v1/admin/organizations/${alice.orgId}/licenses`;
    expect((await env.call('GET', url, { token: op })).status).toBe(200);
    await env.c.auth.revokePlatformAdmin('operator@example.test', 'offboarding drill');
    // same, still-valid session token: now refused
    expect((await env.call('GET', '/v1/auth/me', { token: op })).status).toBe(200);
    expect((await env.call('GET', url, { token: op })).status).toBe(403);
    expect((await env.c.audit.list({ action: 'operator.revoked' }))[0]).toMatchObject({
      reason: 'offboarding drill',
    });
  });

  it('operator mutations require a reason and are attributed in the audit log', async () => {
    const { alice, licenseId } = await twoTenants();
    const op = await env.operatorToken();
    for (const body of [{}, { reason: '' }, { reason: 'x' }]) {
      expect(
        (
          await env.call(
            'POST',
            `/v1/admin/organizations/${alice.orgId}/licenses/${licenseId}/suspend`,
            { token: op, body },
          )
        ).status,
      ).toBe(400);
    }
    const ok = await env.call(
      'POST',
      `/v1/admin/organizations/${alice.orgId}/licenses/${licenseId}/suspend`,
      { token: op, body: { reason: 'suspected key sharing, ticket #4821' } },
    );
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ state: 'suspended', status: 'license_suspended' });
    const audit = await env.call('GET', '/v1/admin/audit?action=license.suspended', { token: op });
    expect(audit.body.items[0]).toMatchObject({
      actor: { type: 'operator' },
      reason: 'suspected key sharing, ticket #4821',
      org_id: alice.orgId,
    });
    expect((await env.call('GET', '/v1/admin/audit/verify', { token: op })).body).toMatchObject({
      ok: true,
    });
  });

  it('login/registration cannot be abused to set privileged fields', async () => {
    env = await makeEnv();
    const r = await env.call('POST', '/v1/auth/register', {
      body: { email: 'evil@example.test', password: PW, platform_role: 'platform_admin' },
    });
    expect(r.status).toBe(400);
    await env.register('evil2@example.test');
    const tok = await env.login('evil2@example.test');
    expect((await env.call('GET', '/v1/auth/me', { token: tok })).body.platform_role).toBe('none');
  });
});

describe('abuse resistance', () => {
  it('replayed activation requests are refused (challenge is single use)', async () => {
    const { alice, licenseKey } = await twoTenants();
    const first = await activateVia(alice.token, licenseKey);
    expect(first.res.status).toBe(200);
    const replay = await env.call('POST', '/v1/licenses/activate', {
      token: alice.token,
      body: first.body,
    });
    expect(replay).toMatchObject({ status: 403, body: { code: 'invalid_challenge' } });
    const sink = env.c.telemetrySink as unknown as { security: Array<{ kind: string }> };
    expect(sink.security.map((x) => x.kind)).toContain('challenge_replay');
  });

  it('a canary license looks exactly like an unknown key to the caller, and alerts operators', async () => {
    const { alice, productId, planId } = await twoTenants();
    const op = await env.operatorToken();
    const canary = await env.call('POST', `/v1/admin/organizations/${alice.orgId}/licenses`, {
      token: op,
      body: {
        product_id: productId,
        plan_id: planId,
        kind: 'canary',
        reason: 'honeypot for leaked-key scrapers',
      },
    });
    expect(canary.status).toBe(201);
    const viaCanary = await activateVia(alice.token, canary.body.license_key);
    const viaGhost = await activateVia(alice.token, 'LK-BBBBB-BBBBB-BBBBB-BBBBB-BBBBB');
    expect(shape(viaCanary.res)).toEqual(shape(viaGhost.res));
    const sink = env.c.telemetrySink as unknown as {
      security: Array<{ kind: string; severity: string }>;
    };
    expect(sink.security.find((s) => s.kind === 'canary_license_activated')).toMatchObject({
      severity: 'high',
    });
    // customers never see canaries
    const mine = await env.call('GET', `/v1/organizations/${alice.orgId}/licenses`, {
      token: alice.token,
    });
    expect(mine.body.items.every((l: any) => l.kind !== 'canary')).toBe(true);
  });

  it('device endpoints reject malformed or oversized inputs', async () => {
    env = await makeEnv();
    for (const body of [
      {},
      { purpose: 'activate' },
      { purpose: 'x', installation_id: 'y' },
      { purpose: 'activate', installation_id: 'a'.repeat(500) },
      { purpose: 'activate', installation_id: 'short' },
    ]) {
      expect((await env.call('POST', '/v1/devices/challenges', { body })).status).toBe(400);
    }
    for (const body of [
      {},
      { activation_id: 'act_x', installation_id: 'i', nonce: 'n', signature: 's' },
    ]) {
      const r = await env.call('POST', '/v1/licenses/refresh', { body });
      expect([400, 404]).toContain(r.status);
    }
    void DAY;
  });
});
