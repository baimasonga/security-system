import { timingSafeEqual } from 'node:crypto';
import { sha256Hex } from '@trust/crypto';
import { contentViolation } from '@trust/telemetry';
import { DomainError, type Clock } from '@trust/shared-types';
import type { CredentialService } from './credentials.ts';
import type { InventoryStore } from './model.ts';
import type { EventInput, EventCounter, OperationEvent } from './events-model.ts';

type Rule = readonly string[] | { min: number; max: number };
const range = (min: number, max: number) => ({ min, max });
const duration = range(0, 86400000),
  age = range(0, 604800);
const formats = ['pdf', 'image', 'office', 'text', 'other'];
const roles = ['none', 'member', 'admin', 'owner'];
const TYPES: Record<string, Record<string, Rule>> = {
  'component.heartbeat': { status: ['healthy', 'degraded', 'unavailable', 'unknown'] },
  'upload.failed': {
    stage: ['initiate', 'transfer', 'finalize'],
    reason: ['timeout', 'storage_unavailable', 'quota', 'validation', 'internal'],
    duration_ms: duration,
    size_bucket: ['small', 'medium', 'large', 'unknown'],
  },
  'conversion.failed': {
    source_type: formats,
    target_type: formats,
    reason: ['timeout', 'unsupported', 'worker_unavailable', 'internal'],
    duration_ms: duration,
  },
  'scanner.unavailable': {
    reason: ['timeout', 'connection', 'worker_unavailable'],
    queue_age_seconds: age,
    queue_count: range(0, 1000000),
  },
  'malware.detected': { verdict: ['malicious', 'suspicious'] },
  'email.delivery_failed': {
    provider: ['resend', 'cloudflare', 'other'],
    reason: ['timeout', 'rejected', 'provider_unavailable', 'exhausted'],
    attempts: range(1, 100),
    queue_age_seconds: age,
  },
  'request.submission_received': {
    file_count: range(0, 1000),
    state: ['received', 'quarantined', 'ready'],
  },
  'link.abuse_reported': {
    category: ['spam', 'malware', 'phishing', 'other'],
    state: ['received', 'triaged'],
  },
  'workspace.role_changed': { from_role: roles, to_role: roles, outcome: ['allowed', 'denied'] },
};
const rejected = (rule: 'schema' | 'unknown_attribute' = 'schema') =>
  new DomainError('unprocessable', 'request rejected', { rule });
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);
function exact(v: Record<string, unknown>, keys: string[]) {
  if (Object.keys(v).some((k) => !keys.includes(k))) throw rejected('unknown_attribute');
  if (Object.keys(v).length !== keys.length || keys.some((k) => !Object.hasOwn(v, k)))
    throw rejected();
}
/** All diagnostics are fixed codes; caller-supplied keys, values and raw parser errors never escape. */
export function validateEventBatch(value: unknown): EventInput[] {
  if (!object(value)) throw rejected();
  exact(value, ['schema', 'events']);
  if (
    value.schema !== 1 ||
    !Array.isArray(value.events) ||
    value.events.length < 1 ||
    value.events.length > 100
  )
    throw rejected();
  const events = value.events.map((event) => {
    if (!object(event)) throw rejected();
    exact(event, ['id', 'component_id', 'occurred_at', 'type', 'attributes']);
    if (
      typeof event.id !== 'string' ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(event.id) ||
      typeof event.component_id !== 'string' ||
      !/^opm_[a-f0-9]{24}$/.test(event.component_id)
    )
      throw rejected();
    if (typeof event.occurred_at !== 'string' || !event.occurred_at.endsWith('Z')) throw rejected();
    const parts = event.occurred_at.slice(0, -1).split('.');
    if (
      parts.length > 2 ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(parts[0]!) ||
      (parts.length === 2 && !/^[0-9]+$/.test(parts[1]!))
    )
      throw rejected();
    const time = new Date(event.occurred_at);
    if (
      !Number.isFinite(+time) ||
      time.toISOString().slice(0, 19) !== event.occurred_at.slice(0, 19)
    )
      throw rejected();
    if (
      typeof event.type !== 'string' ||
      !Object.hasOwn(TYPES, event.type) ||
      !object(event.attributes)
    )
      throw rejected();
    const rules = TYPES[event.type]!;
    exact(event.attributes, Object.keys(rules));
    for (const [key, rule] of Object.entries(rules)) {
      const v = event.attributes[key];
      if (Array.isArray(rule)) {
        if (typeof v !== 'string' || !rule.includes(v) || contentViolation(v)) throw rejected();
      } else {
        const bounds = rule as { min: number; max: number };
        if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < bounds.min || v > bounds.max)
          throw rejected();
      }
    }
    return {
      id: event.id,
      component_id: event.component_id,
      occurred_at: event.occurred_at,
      type: event.type,
      attributes: structuredClone(event.attributes) as EventInput['attributes'],
    };
  });
  if (Buffer.byteLength(JSON.stringify({ schema: 1, events })) > 262144)
    throw new DomainError('too_large', 'request rejected');
  return events;
}
const DAY = 86400000;
const canonical = (e: EventInput) =>
  JSON.stringify([
    e.type,
    e.component_id,
    e.occurred_at,
    Object.entries(e.attributes).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  ]);
export class EventService {
  readonly #store: InventoryStore;
  readonly #credentials: CredentialService;
  readonly #clock: Clock;
  readonly #enabled: () => boolean;
  constructor(d: {
    store: InventoryStore;
    credentials: CredentialService;
    clock: Clock;
    enabled: () => boolean;
  }) {
    this.#store = d.store;
    this.#credentials = d.credentials;
    this.#clock = d.clock;
    this.#enabled = d.enabled;
  }
  async ingest(token: string | undefined, body: unknown) {
    if (!this.#enabled()) throw new DomainError('not_found', 'not found');
    const outcome = await this.#credentials.withCredential(
      token,
      { purpose: 'events:write', source: 'backend_report' },
      async (tx, identity) => {
        if (!this.#enabled()) throw new DomainError('not_found', 'not found');
        const now = this.#clock.now();
        const requestKey = `request:${identity.credentialId}`;
        const request = await tx.getEventCounter(identity.orgId, requestKey);
        const times = (request?.requestTimes ?? []).filter((t) => t > +now - 60000);
        if (times.length >= 60) throw new DomainError('rate_limited', 'request rejected');
        await tx.putEventCounter({
          orgId: identity.orgId,
          key: requestKey,
          count: 0,
          bytes: 0,
          requestTimes: [...times, +now],
          expiresAt: new Date(+now + 60000),
        });
        // Client refusals commit only the authenticated request charge. Stage all
        // event/quota changes before writing, so rejected mixed batches stay atomic.
        const plan = async () => {
          const inputs = validateEventBatch(body);
          const unique = new Map<string, { input: EventInput; hash: string; size: number }>();
          for (const input of inputs) {
            const text = canonical(input),
              hash = sha256Hex(text);
            const old = unique.get(input.id);
            if (old && old.hash !== hash) throw new DomainError('conflict', 'request rejected');
            unique.set(input.id, { input, hash, size: Buffer.byteLength(text) + 512 });
          }
          const accepted: Array<{
            id: string;
            disposition: 'stored' | 'duplicate';
            received_at: string;
          }> = [];
          const fresh: OperationEvent[] = [];
          for (const { input, hash, size } of unique.values()) {
            const stored = await tx.findEvent(identity, input.id);
            if (stored && stored.expiresAt > now) {
              if (
                !timingSafeEqual(Buffer.from(stored.contentHash, 'hex'), Buffer.from(hash, 'hex'))
              )
                throw new DomainError('conflict', 'request rejected');
              accepted.push({
                id: input.id,
                disposition: 'duplicate',
                received_at: stored.receivedAt.toISOString(),
              });
              continue;
            }
            const at = +new Date(input.occurred_at);
            if (at < +now - DAY || at > +now + 300000) throw rejected();
            const component = await tx.find('component', identity.orgId, input.component_id);
            if (
              !component ||
              component.applicationId !== identity.applicationId ||
              component.environmentId !== identity.environmentId
            )
              throw new DomainError('not_found', 'not found');
            if (component.state !== 'active') throw rejected();
            // Expired identities are removed by retention; never overwrite them on the request path.
            if (stored) throw new DomainError('conflict', 'request rejected');
            fresh.push({
              orgId: identity.orgId,
              applicationId: identity.applicationId,
              environmentId: identity.environmentId,
              credentialId: identity.credentialId,
              source: identity.source,
              id: input.id,
              componentId: input.component_id,
              type: input.type,
              attributes: input.attributes,
              occurredAt: input.occurred_at,
              receivedAt: now,
              expiresAt: new Date(+now + 30 * DAY),
              contentHash: hash,
              sizeBytes: size,
            });
            accepted.push({ id: input.id, disposition: 'stored', received_at: now.toISOString() });
          }
          const bytes = fresh.reduce((n, r) => n + r.sizeBytes, 0);
          const day = now.toISOString().slice(0, 10);
          const counters: [string, number, number, Date | null][] = [
            [`day:org:${day}`, 100000, Infinity, new Date(Date.parse(day) + 2 * DAY)],
            [
              `day:env:${identity.environmentId}:${day}`,
              10000,
              Infinity,
              new Date(Date.parse(day) + 2 * DAY),
            ],
            ['storage:org', Infinity, 2 * 1024 ** 3, null],
            [`storage:env:${identity.environmentId}`, Infinity, 500 * 1024 ** 2, null],
          ];
          const updates: EventCounter[] = [];
          for (const [key, maxCount, maxBytes, expiresAt] of counters) {
            const counter = await tx.getEventCounter(identity.orgId, key);
            const count = (counter?.count ?? 0) + fresh.length,
              totalBytes = (counter?.bytes ?? 0) + bytes;
            if (count > maxCount || totalBytes > maxBytes)
              throw new DomainError('rate_limited', 'request rejected');
            if (fresh.length)
              updates.push({
                orgId: identity.orgId,
                key,
                count,
                bytes: totalBytes,
                expiresAt,
                requestTimes: [],
              });
          }
          return { fresh, accepted, updates };
        };
        let prepared: Awaited<ReturnType<typeof plan>>;
        try {
          prepared = await plan();
        } catch (error) {
          if (error instanceof DomainError) return { ok: false as const, error };
          throw error;
        }
        for (const counter of prepared.updates) await tx.putEventCounter(counter);
        for (const event of prepared.fresh) {
          await tx.insertEvent(event);
          const hour = new Date(Math.floor(+now / 3600000) * 3600000);
          await tx.addEventAggregate({
            orgId: event.orgId,
            applicationId: event.applicationId,
            environmentId: event.environmentId,
            componentId: event.componentId,
            type: event.type,
            outcome: String(
              event.attributes.status ??
                event.attributes.reason ??
                event.attributes.verdict ??
                event.attributes.outcome ??
                event.attributes.state,
            ),
            hour,
            count: 1,
            expiresAt: new Date(+hour + 90 * DAY),
          });
        }
        // withCredential resolves only after the transaction's actual commit.
        return { ok: true as const, receipt: { schema: 1 as const, accepted: prepared.accepted } };
      },
    );
    if (!outcome.ok) throw outcome.error;
    return outcome.receipt;
  }
  /** Bounded, idempotent retention; storage accounting and event deletion commit together. */
  async retain() {
    const now = this.#clock.now();
    let deleted = 0;
    for (const orgId of await this.#store.expiredEventOrganizations(now, 25)) {
      deleted += await this.#store.transaction(orgId, async (tx) => {
        const rows = await tx.pruneEventRows(orgId, now, 1000);
        const releases = new Map<string, { count: number; bytes: number }>();
        for (const row of rows)
          for (const key of ['storage:org', `storage:env:${row.environmentId}`]) {
            const value = releases.get(key) ?? { count: 0, bytes: 0 };
            value.count++;
            value.bytes += row.sizeBytes;
            releases.set(key, value);
          }
        for (const [key, release] of releases) {
          const counter = await tx.getEventCounter(orgId, key);
          if (!counter || counter.count < release.count || counter.bytes < release.bytes)
            throw new Error('operations accounting invariant');
          await tx.putEventCounter({
            ...counter,
            count: counter.count - release.count,
            bytes: counter.bytes - release.bytes,
          });
        }
        await tx.pruneEventMetadata(orgId, now, 1000);
        return rows.length;
      });
    }
    return deleted;
  }
}
