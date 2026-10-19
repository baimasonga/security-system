import { Decision } from '@trust/shared-types';

// Device trust (ADR-026): deterministic posture from server-observed signals. No score can override the hard
// license, signature or tenant invariants: those are decided before this runs and are passed in as `license`.

/** Signals the SERVER observes. Nothing a device reports about itself is a signal here. */
export const DEVICE_SIGNAL_KINDS = [
  'installation_switch', // the same device key re-activated under a different installation id
  'installation_mismatch', // device-authenticated call naming another installation than the activation's
  'invalid_device_proof', // a signature that does not verify with this device's registered key
  'step_up_completed', // a person re-activated the device with their session and the license key
] as const;
export type DeviceSignalKind = (typeof DEVICE_SIGNAL_KINDS)[number];

export interface DeviceSignal {
  id: string;
  orgId: string;
  deviceId: string;
  kind: DeviceSignalKind;
  /** Always `server_observed`: self-reported device claims are never evidence (ADR-026). */
  provenance: 'server_observed';
  observedAt: Date;
  /** Retention bound: purged after this. */
  expiresAt: Date;
  attributes: Record<string, string | number | boolean>;
}

export type Attestation = 'verified' | 'failed' | 'unknown';

export interface DevicePosture {
  orgId: string;
  deviceId: string;
  decision: Decision;
  reasons: string[];
  /** Recompute at or after this time (a contributing signal leaves its window); null = stable. */
  reviewAt: Date | null;
  updatedAt: Date;
}

const DAY = 86_400_000;
export const SIGNAL_RETENTION_MS = 90 * DAY;
/** Windows each rule looks back over. */
export const SWITCH_WINDOW_MS = 7 * DAY;
export const PROOF_WINDOW_MS = DAY;
/** Thresholds (documented in ADR-026). */
export const SWITCHES_FOR_STEP_UP = 3;
export const PROOF_FAILURES_FOR_RESTRICT = 10;

const RANK: Record<Decision, number> = {
  ALLOW: 0,
  OBSERVE: 1,
  STEP_UP_AUTH: 2,
  RESTRICT: 3,
  SUSPEND: 4,
  DENY: 5,
};

/**
 * Pure and deterministic: the same inputs always give the same decision and reasons.
 *  1. A license decision other than ALLOW is returned unchanged (hard invariants win, always).
 *  2. Only signals after the latest `step_up_completed` count (a person re-proved control).
 *  3. Clone suspicion (installation switches) leads to OBSERVE, then STEP_UP_AUTH — never to deletion, and never
 *     automatically to SUSPEND (an operator decision).
 *  4. Bursts of failed proofs restrict (shorter offline leases) rather than lock the user out.
 *  5. Missing hardware evidence is reported as `attestation_unknown`; it never counts as evidence either way.
 */
export function evaluateDevicePosture(input: {
  license: { decision: Decision; reasons: string[] };
  attestation: Attestation;
  signals: readonly DeviceSignal[];
  now: Date;
}): { decision: Decision; reasons: string[]; reviewAt: Date | null } {
  if (input.license.decision !== Decision.ALLOW)
    return {
      decision: input.license.decision,
      reasons: [...input.license.reasons],
      reviewAt: null,
    };
  const now = input.now.getTime();
  const reset = Math.max(
    -Infinity,
    ...input.signals
      .filter((s) => s.kind === 'step_up_completed')
      .map((s) => s.observedAt.getTime()),
  );
  const live = input.signals.filter(
    (s) => s.kind !== 'step_up_completed' && s.observedAt.getTime() > reset,
  );
  const within = (kinds: DeviceSignalKind[], windowMs: number) =>
    live.filter((s) => kinds.includes(s.kind) && s.observedAt.getTime() > now - windowMs);

  let decision: Decision = Decision.ALLOW;
  const reasons: string[] = [];
  const raise = (d: Decision, reason: string) => {
    if (RANK[d] > RANK[decision]) decision = d;
    reasons.push(reason);
  };
  const reviews: number[] = [];

  const switches = within(['installation_switch'], SWITCH_WINDOW_MS);
  if (switches.length >= SWITCHES_FOR_STEP_UP)
    raise(Decision.STEP_UP_AUTH, `possible_clone:${switches.length}_installation_switches_7d`);
  else if (switches.length > 0)
    raise(Decision.OBSERVE, `installation_switch:${switches.length}_in_7d`);
  for (const s of switches) reviews.push(s.observedAt.getTime() + SWITCH_WINDOW_MS);

  const proofs = within(['invalid_device_proof', 'installation_mismatch'], PROOF_WINDOW_MS);
  if (proofs.length >= PROOF_FAILURES_FOR_RESTRICT)
    raise(Decision.RESTRICT, `repeated_invalid_proofs:${proofs.length}_in_24h`);
  else if (proofs.length > 0) raise(Decision.OBSERVE, `invalid_proofs:${proofs.length}_in_24h`);
  for (const s of proofs) reviews.push(s.observedAt.getTime() + PROOF_WINDOW_MS);

  if (input.attestation === 'unknown') reasons.push('attestation_unknown');
  else if (input.attestation === 'failed') raise(Decision.RESTRICT, 'attestation_failed');

  const next = reviews.filter((t) => t > now);
  return { decision, reasons, reviewAt: next.length ? new Date(Math.min(...next)) : null };
}
