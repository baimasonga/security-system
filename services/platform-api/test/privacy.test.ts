import { afterEach, describe, expect, it } from 'vitest';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { buildProofMessage } from '@trust/crypto/verify';
import { makeEnv, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

describe('privacy firewall for client telemetry', () => {
  it('stores allow-listed events, refuses the rest by field and rule, and never echoes values', async () => {
    env = await makeEnv();
    const u = await env.register('telemetry@example.test');
    const send = (events: unknown[], token: string | null = u.token) =>
      env.call('POST', '/v1/telemetry/events', { ...(token ? { token } : {}), body: { events } });
    expect((await send([{ name: 'feature.used', attributes: {} }], null)).status).toBe(401);
    const secret = 'aminata.kamara@example.sl';
    const r = await send([
      { name: 'feature.used', attributes: { feature: 'export.pdf', duration_ms: 900 } },
      { name: 'app.error', attributes: { code: secret } },
      { name: 'document.saved', attributes: { text: 'Quarterly salaries…' } },
      { name: 'app.started', attributes: { app_version: '3.2.1', platform: 'windows' } },
      { name: 'feature.used', attributes: { feature: 'ok', path: 'C:\\Users\\Aminata' } },
    ]);
    expect(r.status).toBe(200);
    expect(r.body.accepted).toBe(2);
    expect(r.body.rejected).toEqual([
      { index: 1, violations: [{ field: 'code', rule: 'looks_like_email' }] },
      { index: 2, violations: [{ field: 'name', rule: 'unknown_event' }] },
      { index: 4, violations: [{ field: 'path', rule: 'unknown_attribute' }] },
    ]);
    const text = JSON.stringify(r.body);
    for (const v of [secret, 'Quarterly', 'Aminata']) expect(text).not.toContain(v);
    const sink = env.c.telemetrySink as { telemetry?: Array<{ name: string; attributes: object }> };
    if (sink.telemetry) {
      const client = sink.telemetry.filter((t) => t.name.startsWith('client.'));
      expect(client.map((t) => t.name)).toEqual(['client.feature.used', 'client.app.started']);
      expect(JSON.stringify(client)).not.toContain(u.userId); // no user reference stored
    }
    const metrics = (
      await env.call('GET', '/v1/admin/metrics', { token: await env.operatorToken() })
    ).body;
    expect(JSON.stringify(metrics)).toContain('telemetry_firewall_rejected_total');
  });

  it('bounds the batch and the shape', async () => {
    env = await makeEnv();
    const u = await env.register('telemetry@example.test');
    const many = Array.from({ length: 51 }, () => ({ name: 'app.started', attributes: {} }));
    expect(
      (await env.call('POST', '/v1/telemetry/events', { token: u.token, body: { events: many } }))
        .status,
    ).toBe(400);
    expect(
      (
        await env.call('POST', '/v1/telemetry/events', {
          token: u.token,
          body: { events: [{ name: 'app.started', attributes: {}, extra: 1 }] },
        })
      ).status,
    ).toBe(400);
  });
});

describe('security center', () => {
  it('explains protection, roles, own devices and collected data — and only the caller’s', async () => {
    env = await makeEnv();
    const u = await env.register('center@example.test');
    const lic = await env.provision(u.orgId);
    const dev = SoftwareDeviceKey.generate();
    const installationId = 'inst_securitycentertest01';
    const ch = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: installationId },
    });
    const act = await env.call('POST', '/v1/licenses/activate', {
      token: u.token,
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
    expect(act.status).toBe(200);
    const r = await env.call('GET', '/v1/security-center', { token: u.token });
    expect(r.status).toBe(200);
    expect(r.body.account).toMatchObject({
      email: 'center@example.test',
      authenticator_enabled: false,
      passkeys: 0,
      operator: false,
    });
    expect(r.body.organizations[0].role).toBe('owner');
    const perms = r.body.organizations[0].permissions.map(
      (x: { permission: string }) => x.permission,
    );
    expect(perms).toContain('license:manage_seats');
    expect(r.body.organizations[0].permissions[0].description).toMatch(/\w+ \w+/);
    expect(r.body.devices).toHaveLength(1);
    expect(r.body.devices[0]).toMatchObject({
      device_id: act.body.device_id,
      posture: 'ALLOW',
      attestation: 'unknown',
    });
    const categories = r.body.data_categories.map((d: { category: string }) => d.category);
    expect(categories).toEqual(
      expect.arrayContaining(['Account', 'Devices', 'Device security signals', 'Usage telemetry']),
    );
    expect(JSON.stringify(r.body)).not.toMatch(/password_hash|sealed|public_key_jwk/);
    // another person sees only their own devices
    const other = await env.register('other@example.test');
    const theirs = await env.call('GET', '/v1/security-center', { token: other.token });
    expect(theirs.body.devices).toEqual([]);
    expect((await env.call('GET', '/v1/security-center')).status).toBe(401);
  });

  it('lists only the caller’s devices even inside a shared organization', async () => {
    env = await makeEnv();
    const owner = await env.register('team-owner@example.test');
    const team = await env.call('POST', '/v1/organizations', {
      token: owner.token,
      body: { name: 'Kamara Engineering' },
    });
    const orgId = team.body.id as string;
    const mate = await env.register('mate@example.test');
    await env.call('POST', `/v1/organizations/${orgId}/members`, {
      token: owner.token,
      body: { email: 'mate@example.test', role: 'member' },
    });
    const lic = await env.provision(orgId);
    const activate = async (token: string, installationId: string) => {
      const dev = SoftwareDeviceKey.generate();
      const ch = await env.call('POST', '/v1/devices/challenges', {
        body: { purpose: 'activate', installation_id: installationId },
      });
      const r = await env.call('POST', '/v1/licenses/activate', {
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
      expect(r.status).toBe(200);
      return r.body.device_id as string;
    };
    const mine = await activate(owner.token, 'inst_securitycenterowner1');
    const theirs = await activate(mate.token, 'inst_securitycentermate01');
    const ownerView = await env.call('GET', '/v1/security-center', { token: owner.token });
    expect(ownerView.body.devices.map((d: { device_id: string }) => d.device_id)).toEqual([mine]);
    const mateView = await env.call('GET', '/v1/security-center', { token: mate.token });
    expect(mateView.body.devices.map((d: { device_id: string }) => d.device_id)).toEqual([theirs]);
  });
});
