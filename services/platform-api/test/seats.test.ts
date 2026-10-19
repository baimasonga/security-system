import { afterEach, describe, expect, it } from 'vitest';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { buildProofMessage } from '@trust/crypto/verify';
import { makeEnv, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

let inst = 0;
async function setup(seats?: number) {
  env = await makeEnv();
  const person = await env.register('owner@example.test');
  // Seats belong to team organizations (personal workspaces have no members).
  const team = await env.call('POST', '/v1/organizations', {
    token: person.token,
    body: { name: 'Kamara Engineering' },
  });
  expect(team.status).toBe(201);
  const owner = { ...person, orgId: team.body.id as string };
  const lic = await env.provision(owner.orgId);
  const op = await env.operatorToken();
  if (seats !== undefined) {
    const r = await env.call('PATCH', `/v1/admin/plans/${lic.planId}`, {
      token: op,
      body: {
        entitlements: { pdf_editing: true, ocr_pages_monthly: 5000, seats },
        reason: 'enterprise seats',
      },
    });
    expect(r.status).toBe(200);
  }
  const member = async (email: string) => {
    const u = await env.register(email);
    const r = await env.call('POST', `/v1/organizations/${owner.orgId}/members`, {
      token: owner.token,
      body: { email, role: 'member' },
    });
    expect(r.status).toBe(201);
    return u;
  };
  const base = `/v1/organizations/${owner.orgId}/licenses/${lic.licenseId}/seats`;
  const assign = (userId: string, token = owner.token) =>
    env.call('POST', base, { token, body: { user_id: userId } });
  const unassign = (userId: string, token = owner.token) =>
    env.call('POST', `${base}/${userId}/unassign`, { token, body: {} });
  const activate = async (token: string) => {
    const dev = SoftwareDeviceKey.generate();
    const installationId = `inst_seatstestseatstest${(++inst).toString().padStart(4, '0')}`;
    const ch = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: installationId },
    });
    return env.call('POST', '/v1/licenses/activate', {
      token,
      body: {
        license_key: lic.licenseKey,
        installation_id: installationId,
        device_public_key: dev.publicJwk,
        nonce: ch.body.nonce,
        signature: dev.sign(
          buildProofMessage({
            purpose: 'activate',
            nonce: ch.body.nonce,
            installationId,
            subjectId: '',
            thumbprint: dev.thumbprint,
          }),
        ),
      },
    });
  };
  return { owner, lic, op, member, base, assign, unassign, activate };
}

describe('seats on seat-based licenses', () => {
  it('leaves licenses without a seats entitlement unchanged', async () => {
    const { owner, base, assign, activate } = await setup();
    const list = await env.call('GET', base, { token: owner.token });
    expect(list.body).toMatchObject({ limit: null, used: 0, items: [] });
    expect((await assign(owner.userId)).status).toBe(409);
    expect((await activate(owner.token)).status).toBe(200);
  });

  it('requires a seat to activate, never exceeds the limit, and only admins assign', async () => {
    const { owner, member, base, assign, activate } = await setup(2);
    const bob = await member('bob@example.test');
    const carol = await member('carol@example.test');
    const noSeat = await activate(owner.token);
    expect(noSeat.status).toBe(403);
    expect(noSeat.body.code).toBe('seat_required');
    expect((await assign(bob.userId, bob.token)).status).toBe(403); // members cannot assign
    expect((await assign(owner.userId)).status).toBe(201);
    expect((await assign(owner.userId)).status).toBe(409); // already has one
    expect((await assign(bob.userId)).status).toBe(201);
    const full = await assign(carol.userId);
    expect(full.status).toBe(409);
    expect(full.body.code).toBe('seat_limit_reached');
    expect((await activate(owner.token)).status).toBe(200);
    expect((await activate(bob.token)).status).toBe(200);
    expect((await activate(carol.token)).status).toBe(403);
    const list = await env.call('GET', base, { token: bob.token });
    expect(list.body).toMatchObject({ limit: 2, used: 2 });
    expect(list.body.items.map((s: { user_id: string }) => s.user_id).sort()).toEqual(
      [owner.userId, bob.userId].sort(),
    );
    const audit = (await env.c.audit.list({ limit: 500 })).map((e) => e.action);
    expect(audit).toContain('seat.assigned');
  });

  it('assigns only members, and hides other organizations', async () => {
    const { assign, base } = await setup(2);
    const stranger = await env.register('stranger@example.test');
    expect((await assign(stranger.userId)).status).toBe(404); // not a member
    expect((await env.call('GET', base, { token: stranger.token })).status).toBe(404);
    expect((await assign(stranger.userId, stranger.token)).status).toBe(404);
  });

  it('removing a seat signs that person’s devices out and says how long offline leases last', async () => {
    const { owner, member, assign, unassign, activate } = await setup(1);
    const bob = await member('bob@example.test');
    const carol = await member('carol@example.test');
    await assign(bob.userId);
    const act = await activate(bob.token);
    expect(act.status).toBe(200);
    expect((await unassign(bob.userId, bob.token)).status).toBe(403);
    const out = await unassign(bob.userId);
    expect(out.status).toBe(200);
    expect(out.body.activations_deactivated).toBe(1);
    expect(out.body.offline_leases_valid_until).toBe(act.body.lease_expires_at);
    expect((await unassign(bob.userId)).status).toBe(404);
    const lic = await env.call('GET', `/v1/organizations/${owner.orgId}/licenses`, {
      token: owner.token,
    });
    expect(lic.body.items[0].active_devices).toBe(0);
    // the freed seat can go to someone else
    expect((await assign(carol.userId)).status).toBe(201);
    expect((await activate(bob.token)).status).toBe(403);
  });

  it('never over-assigns under concurrency', async () => {
    const { member, assign } = await setup(2);
    const people = await Promise.all(
      ['p1', 'p2', 'p3', 'p4', 'p5'].map((n) => member(`${n}@example.test`)),
    );
    const results = await Promise.all(people.map((p) => assign(p.userId)));
    expect(results.filter((r) => r.status === 201)).toHaveLength(2);
    expect(results.filter((r) => r.status === 409)).toHaveLength(3);
  });

  it('a frozen organization cannot hand out seats; outsiders still see 404', async () => {
    const { owner, op, assign } = await setup(2);
    await env.call('POST', '/v1/admin/freezes', {
      token: op,
      body: { scope: 'organization', org_id: owner.orgId, reason: 'investigation' },
    });
    expect((await assign(owner.userId)).status).toBe(423);
    const stranger = await env.register('stranger@example.test');
    expect((await assign(stranger.userId, stranger.token)).status).toBe(404);
  });
});
