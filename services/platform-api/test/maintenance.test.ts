import { afterEach, describe, expect, it } from 'vitest';
import { startMaintenance } from '../src/maintenance.ts';
import { makeEnv, DAY, type Env } from './harness.ts';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { buildProofMessage } from '@trust/crypto/verify';

let env: Env;
afterEach(async () => env?.app.close());

describe('background maintenance', () => {
  async function someChallenges(n: number) {
    for (let i = 0; i < n; i++) {
      await env.call('POST', '/v1/devices/challenges', {
        body: { purpose: 'activate', installation_id: `inst_maintenance_${i}_padpadpad` },
      });
    }
    void SoftwareDeviceKey;
    void buildProofMessage;
  }

  it('deletes expired challenges, records metrics, and never overlaps itself', async () => {
    env = await makeEnv();
    await someChallenges(5);
    env.clock.advance(2 * 3600_000);
    const m = startMaintenance(env.c, { everyMs: 3_600_000 });
    try {
      const [a, b] = await Promise.all([m.runOnce(), m.runOnce()]); // second call is skipped while the first runs
      expect([a, b].filter(Boolean)).toHaveLength(1);
      expect([a, b].find(Boolean)).toMatchObject({ challenges: 5 });
      const snap = env.c.metrics.snapshot();
      expect(snap.counters['maintenance_runs_total{outcome="ok"}']).toBe(1);
      expect(snap.counters['maintenance_deleted_total{table="challenges"}']).toBe(5);
      void DAY;
    } finally {
      m.stop();
    }
  });

  it('counts and reports failures without throwing, then recovers on the next pass', async () => {
    env = await makeEnv();
    const errors: unknown[] = [];
    const m = startMaintenance(env.c, { everyMs: 3_600_000, onError: (e) => errors.push(e) });
    const original = env.c.licensing.runMaintenance.bind(env.c.licensing);
    env.c.licensing.runMaintenance = async () => {
      throw new Error('db down');
    };
    try {
      expect(await m.runOnce()).toBeUndefined();
      expect(errors).toHaveLength(1);
      expect(env.c.metrics.snapshot().counters['maintenance_runs_total{outcome="error"}']).toBe(1);
      env.c.licensing.runMaintenance = original;
      expect(await m.runOnce()).toEqual({ challenges: 0, leases: 0 });
    } finally {
      m.stop();
    }
  });
});

describe('operator knobs actually reach the running service (regression: they were silently ignored)', () => {
  it('CHALLENGE_TTL_SECONDS changes the challenge lifetime and *_RETENTION_SECONDS changes what maintenance deletes', async () => {
    env = await makeEnv({ config: { challengeTtlSeconds: 20, challengeRetentionSeconds: 5 } });
    const r = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: 'inst_knobs_knobs_knobs_1' },
    });
    const ttlS = (Date.parse(r.body.expires_at) - env.clock.now().getTime()) / 1000;
    expect(ttlS).toBe(20); // not the 300 s default
    const m = startMaintenance(env.c, { everyMs: 3_600_000 });
    try {
      env.clock.advance(24_000); // expired 4 s ago, retention is 5 s: still kept
      expect(await m.runOnce()).toEqual({ challenges: 0, leases: 0 });
      env.clock.advance(2_000); // expired 6 s ago > 5 s retention: deleted
      expect(await m.runOnce()).toEqual({ challenges: 1, leases: 0 });
    } finally {
      m.stop();
    }
  });

  it('defaults apply when the knobs are not set (5 min TTL, 1 h retention)', async () => {
    env = await makeEnv();
    const r = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: 'inst_knobs_knobs_knobs_2' },
    });
    expect((Date.parse(r.body.expires_at) - env.clock.now().getTime()) / 1000).toBe(300);
  });
});
