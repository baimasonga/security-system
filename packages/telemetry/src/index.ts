import { hmacSha256Hex, newId } from '@trust/crypto';
import { redact, type Clock, type Json } from '@trust/shared-types';

// ---------------------------------------------------------------------------------------------
// Privacy-preserving telemetry. Every event name has an explicit attribute allow-list; anything not
// listed is dropped (never stored), strings are length-limited and enum-constrained, and
// identifiers are pseudonymized. There is no free-form payload and no document content, by design.
// ---------------------------------------------------------------------------------------------

type AttrSpec =
  | { type: 'enum'; values: readonly string[] }
  | { type: 'number' }
  | { type: 'string'; max: number };

export const TELEMETRY_SCHEMA = {
  'app.started': {
    app_version: { type: 'string', max: 32 },
    platform: { type: 'enum', values: ['windows', 'macos', 'linux', 'android', 'ios', 'web'] },
  },
  'activation.succeeded': {
    tier: { type: 'string', max: 32 },
    reissued: { type: 'enum', values: ['true', 'false'] },
  },
  'activation.rejected': { reason: { type: 'string', max: 64 } },
  'validation.succeeded': {},
  'validation.failed': { reason: { type: 'string', max: 64 } },
  'lease.refreshed': { tier: { type: 'string', max: 32 } },
  'device.deactivated': { by: { type: 'enum', values: ['device', 'owner', 'operator'] } },
  'trial.started': {},
} as const satisfies Record<string, Record<string, AttrSpec>>;

export type TelemetryName = keyof typeof TELEMETRY_SCHEMA;

export const SECURITY_SIGNALS = {
  canary_license_activated: 'high',
  challenge_replay: 'medium',
  invalid_device_proof: 'medium',
  device_key_conflict: 'high',
  activation_rejected: 'low',
  admin_action_denied: 'medium',
  audit_chain_broken: 'critical',
} as const;
export type SecurityKind = keyof typeof SECURITY_SIGNALS;
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface TelemetryRecord {
  id: string;
  occurredAt: string;
  name: TelemetryName;
  attributes: Record<string, string | number>;
}

export interface SecurityRecord {
  id: string;
  occurredAt: string;
  kind: SecurityKind;
  severity: Severity;
  orgId: string | null;
  /** Pseudonymous subject reference (e.g. installation pseudonym), never raw secrets. */
  subject: string | null;
  attributes: Record<string, Json>;
}

export interface TelemetrySink {
  recordTelemetry(r: TelemetryRecord): void | Promise<void>;
  recordSecurity(r: SecurityRecord): void | Promise<void>;
}

export class InMemoryTelemetrySink implements TelemetrySink {
  readonly telemetry: TelemetryRecord[] = [];
  readonly security: SecurityRecord[] = [];
  recordTelemetry(r: TelemetryRecord): void {
    this.telemetry.push(r);
  }
  recordSecurity(r: SecurityRecord): void {
    this.security.push(r);
  }
}

export function sanitizeAttributes(
  name: TelemetryName,
  attrs: Record<string, unknown> | undefined,
): Record<string, string | number> {
  const spec = TELEMETRY_SCHEMA[name] as Record<string, AttrSpec>;
  const out: Record<string, string | number> = {};
  for (const [key, def] of Object.entries(spec)) {
    const v = attrs?.[key];
    if (v === undefined || v === null) continue;
    if (def.type === 'number' && typeof v === 'number' && Number.isFinite(v)) out[key] = v;
    else if (def.type === 'enum' && typeof v === 'string' && def.values.includes(v)) out[key] = v;
    else if (def.type === 'string' && typeof v === 'string') out[key] = v.slice(0, def.max);
    else if (def.type === 'enum' && typeof v === 'boolean') out[key] = String(v);
  }
  return out;
}

export class Telemetry {
  readonly #sink: TelemetrySink;
  readonly #clock: Clock;
  readonly #pseudonymKey: string;

  constructor(opts: { sink: TelemetrySink; clock: Clock; pseudonymKey: string }) {
    this.#sink = opts.sink;
    this.#clock = opts.clock;
    this.#pseudonymKey = opts.pseudonymKey;
  }

  /** Stable one-way reference for an identifier; lets analytics correlate without holding the id. */
  pseudonym(id: string): string {
    return `ps_${hmacSha256Hex(this.#pseudonymKey, id).slice(0, 24)}`;
  }

  async track(name: TelemetryName, attrs?: Record<string, unknown>): Promise<void> {
    if (!(name in TELEMETRY_SCHEMA)) return;
    await this.#sink.recordTelemetry({
      id: newId('tel'),
      occurredAt: this.#clock.now().toISOString(),
      name,
      attributes: sanitizeAttributes(name, attrs),
    });
  }

  async signal(
    kind: SecurityKind,
    ctx: {
      orgId?: string | undefined;
      subject?: string | undefined;
      attributes?: Record<string, unknown>;
    },
  ): Promise<void> {
    await this.#sink.recordSecurity({
      id: newId('sec'),
      occurredAt: this.#clock.now().toISOString(),
      kind,
      severity: SECURITY_SIGNALS[kind],
      orgId: ctx.orgId ?? null,
      subject: ctx.subject ? this.pseudonym(ctx.subject) : null,
      attributes: redact(ctx.attributes ?? {}) as Record<string, Json>,
    });
  }
}
