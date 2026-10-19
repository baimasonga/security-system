import { afterEach, describe, expect, it } from 'vitest';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { buildProofMessage, type ProofPurpose } from '@trust/crypto/verify';
import { loadConfig } from '../src/config.ts';
import { makeEnv, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

const inst = (n: number) => `inst_devicetrusttest${n.toString().padStart(6, '0')}`;

async function setup(mode: 'observe' | 'enforce') {
  env = await makeEnv({ config: { devicePolicyMode: mode } });
  const u = await env.register('trust@example.test');
  const lic = await env.provision(u.orgId, { deviceLimit: 5 });
  const dev = SoftwareDeviceKey.generate();
  const activate = async (installationId: string, key = dev) => {
    const ch = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: installationId },
    });
    return env.call('POST', '/v1/licenses/activate', {
      token: u.token,
      body: {
        license_key: lic.licenseKey,
        installation_id: installationId,
        device_public_key: key.publicJwk,
        nonce: ch.body.nonce,
        signature: key.sign(
          buildProofMessage({
            purpose: 'activate',
            nonce: ch.body.nonce,
            installationId,
            subjectId: '',
            thumbprint: key.thumbprint,
          }),
        ),
      },
    });
  };
  const device = async (
    purpose: Exclude<ProofPurpose, 'activate'>,
    activationId: string,
    installationId: string,
    opts: { signWith?: SoftwareDeviceKey; claimInstallation?: string } = {},
  ) => {
    const claimed = opts.claimInstallation ?? installationId;
    const ch = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose, installation_id: claimed, subject_id: activationId },
    });
    const path = purpose === 'capability' ? '/v1/capabilities/token' : `/v1/licenses/${purpose}`;
    return env.call('POST', path, {
      body: {
        activation_id: activationId,
        installation_id: claimed,
        nonce: ch.body.nonce,
        signature: (opts.signWith ?? dev).sign(
          buildProofMessage({
            purpose,
            nonce: ch.body.nonce,
            installationId: claimed,
            subjectId: activationId,
            thumbprint: dev.thumbprint,
          }),
        ),
        ...(purpose === 'capability' ? { capability: 'OCR_ADVANCED', service: 'ocr' } : {}),
      },
    });
  };
  const passport = async (deviceId: string, token = u.token) =>
    env.call('GET', `/v1/organizations/${u.orgId}/devices/${deviceId}/passport`, { token });
  return { u, lic, dev, activate, device, passport };
}

/** Same device key re-activated under new installation ids: three switches. */
async function cloneLike(s: Awaited<ReturnType<typeof setup>>) {
  let last;
  for (let i = 1; i <= 4; i++) {
    last = await s.activate(inst(i));
    expect(last.status).toBe(200);
  }
  return {
    activationId: last!.body.activation_id as string,
    deviceId: last!.body.device_id as string,
  };
}

const audit = async () => (await env.c.audit.list({ limit: 1000 })).map((e) => e.action);

describe('device trust', () => {
  it('builds a passport: key identity, attestation unknown, server-observed signals, posture', async () => {
    const s = await setup('observe');
    const first = await s.activate(inst(1));
    const deviceId = first.body.device_id as string;
    const quiet = await s.passport(deviceId);
    expect(quiet.status).toBe(200);
    expect(quiet.body).toMatchObject({
      device_id: deviceId,
      key: { algorithm: 'Ed25519', thumbprint: s.dev.thumbprint },
      attestation: { status: 'unknown' },
      posture: { decision: 'ALLOW', reasons: ['attestation_unknown'], mode: 'observe' },
      signals: [],
    });
    expect(JSON.stringify(quiet.body)).not.toContain(s.dev.publicJwk.x);
    const { deviceId: same } = await cloneLike(s);
    expect(same).toBe(deviceId);
    const after = await s.passport(deviceId);
    expect(after.body.posture.decision).toBe('STEP_UP_AUTH');
    expect(after.body.signals).toHaveLength(3);
    expect(
      after.body.signals.every((x: { provenance: string }) => x.provenance === 'server_observed'),
    ).toBe(true);
    // tenants: another organization's member sees 404; operators can look
    const other = await env.register('other@example.test');
    expect((await s.passport(deviceId, other.token)).status).toBe(404);
    const op = await env.operatorToken();
    const admin = await env.call(
      'GET',
      `/v1/admin/organizations/${s.u.orgId}/devices/${deviceId}/passport`,
      {
        token: op,
      },
    );
    expect(admin.body.posture.decision).toBe('STEP_UP_AUTH');
    expect(await audit()).toContain('device.posture_changed');
  });

  it('observe mode records the posture but never blocks', async () => {
    const s = await setup('observe');
    const { activationId } = await cloneLike(s);
    expect((await s.device('refresh', activationId, inst(4))).status).toBe(200);
    expect((await s.device('validate', activationId, inst(4))).status).toBe(200);
  });

  it('enforce mode asks a suspected clone to step up; re-activating by the person clears it', async () => {
    const s = await setup('enforce');
    const { activationId, deviceId } = await cloneLike(s);
    for (const purpose of ['refresh', 'validate', 'capability'] as const) {
      const r = await s.device(purpose, activationId, inst(4));
      expect(r.status, purpose).toBe(403);
      expect(r.body.code).toBe('step_up_required');
    }
    // deactivation stays possible (users are never locked out of releasing a slot)
    expect(await audit()).toContain('device.step_up_required');
    // the person re-activates on that installation with their session + license key
    expect((await s.activate(inst(4))).status).toBe(200);
    expect((await s.device('refresh', activationId, inst(4))).status).toBe(200);
    expect((await s.passport(deviceId)).body.posture.decision).toBe('ALLOW');
  });

  it('a revoked license is refused as revoked, not hidden behind a step-up', async () => {
    const s = await setup('enforce');
    const { activationId } = await cloneLike(s);
    const op = await env.operatorToken();
    await env.call(
      'POST',
      `/v1/admin/organizations/${s.u.orgId}/licenses/${s.lic.licenseId}/revoke`,
      {
        token: op,
        body: { reason: 'fraud' },
      },
    );
    const r = await s.device('refresh', activationId, inst(4));
    expect(r.body.code).not.toBe('step_up_required');
  });

  it('a burst of failed proofs restricts the device to short offline leases in enforce mode', async () => {
    const s = await setup('enforce');
    const a = await s.activate(inst(1));
    const activationId = a.body.activation_id as string;
    const deviceId = a.body.device_id as string;
    const intruder = SoftwareDeviceKey.generate();
    for (let i = 0; i < 6; i++)
      expect(
        (await s.device('refresh', activationId, inst(1), { signWith: intruder })).status,
      ).toBe(403);
    for (let i = 0; i < 4; i++)
      expect(
        (await s.device('refresh', activationId, inst(1), { claimInstallation: inst(99) })).status,
      ).toBe(403);
    const p = await s.passport(deviceId);
    expect(p.body.posture.decision).toBe('RESTRICT');
    const r = await s.device('refresh', activationId, inst(1));
    expect(r.status).toBe(200);
    const ttl = new Date(r.body.lease_expires_at).getTime() - env.clock.now().getTime();
    expect(ttl).toBeLessThanOrEqual(86_400_000);
    // a day later the burst has left its window: back to normal leases
    env.clock.advance(86_400_000 + 1000);
    const later = await s.device('refresh', activationId, inst(1));
    const ttl2 = new Date(later.body.lease_expires_at).getTime() - env.clock.now().getTime();
    expect(ttl2).toBeGreaterThan(86_400_000);
    // (the session expired with the clock jump: sign in again to read the passport)
    const fin = await s.passport(deviceId, await env.login('trust@example.test'));
    expect(fin.body.posture.decision).toBe('ALLOW');
  });

  it('DEVICE_POLICY accepts only observe or enforce (default observe)', () => {
    const base = { NODE_ENV: 'test' } as NodeJS.ProcessEnv;
    expect(loadConfig(base).devicePolicyMode).toBe('observe');
    expect(loadConfig({ ...base, DEVICE_POLICY: 'enforce' }).devicePolicyMode).toBe('enforce');
    expect(() => loadConfig({ ...base, DEVICE_POLICY: 'strict' })).toThrow(/DEVICE_POLICY/);
  });
});
