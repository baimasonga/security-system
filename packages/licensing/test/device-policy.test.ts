import { describe, expect, it } from 'vitest';
import { Decision } from '@trust/shared-types';
import {
  evaluateDevicePosture,
  type DeviceSignal,
  type DeviceSignalKind,
} from '../src/device-policy.ts';

const NOW = new Date('2026-03-10T12:00:00Z');
const H = 3_600_000;
let n = 0;
const sig = (kind: DeviceSignalKind, hoursAgo: number): DeviceSignal => ({
  id: `sig_${++n}`,
  orgId: 'org_a',
  deviceId: 'dev_a',
  kind,
  provenance: 'server_observed',
  observedAt: new Date(NOW.getTime() - hoursAgo * H),
  expiresAt: new Date(NOW.getTime() + 90 * 24 * H),
  attributes: {},
});
const allow = { decision: Decision.ALLOW, reasons: [] };
const run = (
  signals: DeviceSignal[],
  o: Partial<Parameters<typeof evaluateDevicePosture>[0]> = {},
) => evaluateDevicePosture({ license: allow, attestation: 'unknown', signals, now: NOW, ...o });

describe('device posture (deterministic)', () => {
  it('allows a quiet device and labels missing hardware evidence as unknown', () => {
    expect(run([])).toEqual({
      decision: 'ALLOW',
      reasons: ['attestation_unknown'],
      reviewAt: null,
    });
    expect(run([], { attestation: 'verified' })).toEqual({
      decision: 'ALLOW',
      reasons: [],
      reviewAt: null,
    });
  });

  it('never overrides a hard license decision, whatever the signals', () => {
    const denied = { decision: Decision.DENY, reasons: ['license_revoked'] };
    expect(run([], { license: denied })).toEqual({
      decision: 'DENY',
      reasons: ['license_revoked'],
      reviewAt: null,
    });
    const many = Array.from({ length: 20 }, () => sig('step_up_completed', 1));
    expect(run(many, { license: denied }).decision).toBe('DENY');
  });

  it('observes installation switches, then asks for step-up at three in seven days', () => {
    expect(run([sig('installation_switch', 2)]).decision).toBe('OBSERVE');
    const three = [
      sig('installation_switch', 2),
      sig('installation_switch', 30),
      sig('installation_switch', 100),
    ];
    const r = run(three);
    expect(r.decision).toBe('STEP_UP_AUTH');
    expect(r.reasons[0]).toMatch(/possible_clone/);
    // the oldest leaves the 7-day window first: that is when to look again
    expect(r.reviewAt).toEqual(new Date(NOW.getTime() - 100 * H + 7 * 24 * H));
    // older than 7 days does not count
    expect(
      run([
        sig('installation_switch', 2),
        sig('installation_switch', 30),
        sig('installation_switch', 7 * 24 + 1),
      ]).decision,
    ).toBe('OBSERVE');
  });

  it('a completed step-up resets clone suspicion recorded before it', () => {
    const s = [
      sig('installation_switch', 50),
      sig('installation_switch', 40),
      sig('installation_switch', 30),
    ];
    expect(run([...s, sig('step_up_completed', 20)]).decision).toBe('ALLOW');
    expect(run([...s, sig('step_up_completed', 35)]).decision).toBe('OBSERVE'); // one switch after the reset
  });

  it('restricts on a burst of failed proofs in 24 hours, and never escalates to SUSPEND or DENY by itself', () => {
    const burst = Array.from({ length: 10 }, (_, i) =>
      sig(i % 2 ? 'invalid_device_proof' : 'installation_mismatch', 1),
    );
    expect(run(burst).decision).toBe('RESTRICT');
    expect(run(burst.slice(0, 9)).decision).toBe('OBSERVE');
    const everything = [
      ...burst,
      ...burst,
      sig('installation_switch', 1),
      sig('installation_switch', 2),
      sig('installation_switch', 3),
    ];
    const worst = run(everything, { attestation: 'failed' });
    expect(worst.decision).toBe('RESTRICT');
    expect(['SUSPEND', 'DENY']).not.toContain(worst.decision);
  });

  it('is deterministic: same inputs, same output, regardless of signal order', () => {
    const s = [
      sig('installation_switch', 3),
      sig('invalid_device_proof', 1),
      sig('installation_switch', 9),
    ];
    expect(run(s)).toEqual(run([...s].reverse()));
  });
});
