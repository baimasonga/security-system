import { createHmac, timingSafeEqual } from 'node:crypto';

export interface BillingEvent {
  id: string;
  type: string;
  occurredAt: string;
  data: Record<string, unknown>;
}
/** Verify before parsing; callers must persist event ids and resolve a SERVER-created checkout mapping. */
export interface BillingWebhookVerifier {
  verify(rawBody: string, signature: string): BillingEvent;
}
export class PaddleWebhookVerifier implements BillingWebhookVerifier {
  readonly #secret: string;
  readonly #now: () => number;
  constructor(opts: { secret: string; now?: () => number }) {
    if (opts.secret.length < 16) throw new Error('billing webhook secret must be configured');
    this.#secret = opts.secret;
    this.#now = opts.now ?? Date.now;
  }
  verify(rawBody: string, signature: string): BillingEvent {
    const rejected = () => new Error('invalid billing webhook');
    if (Buffer.byteLength(rawBody) > 1024 * 1024 || signature.length > 2048) throw rejected();
    const timestamps: string[] = [];
    const signatures: string[] = [];
    for (const part of signature.split(';')) {
      const [name, value, extra] = part.trim().split('=');
      if (extra || !value) throw rejected();
      if (name === 'ts') timestamps.push(value);
      else if (name === 'h1') signatures.push(value);
      else throw rejected();
    }
    if (timestamps.length !== 1 || signatures.length < 1 || signatures.length > 10)
      throw rejected();
    const timestamp = timestamps[0]!;
    const seconds = Number(timestamp);
    if (
      !Number.isSafeInteger(seconds) ||
      String(seconds) !== timestamp ||
      Math.abs(Math.floor(this.#now() / 1000) - seconds) > 300
    )
      throw rejected();
    const expected = createHmac('sha256', this.#secret).update(`${timestamp}:${rawBody}`).digest();
    if (
      !signatures.some(
        (candidate) =>
          /^[a-f0-9]{64}$/.test(candidate) &&
          timingSafeEqual(Buffer.from(candidate, 'hex'), expected),
      )
    )
      throw rejected();
    let event: unknown;
    try {
      event = JSON.parse(rawBody);
    } catch {
      throw rejected();
    }
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw rejected();
    const e = event as Record<string, unknown>;
    if (
      typeof e.event_id !== 'string' ||
      !/^evt_[a-z0-9]+$/.test(e.event_id) ||
      e.event_id.length > 100 ||
      typeof e.event_type !== 'string' ||
      e.event_type.length > 100 ||
      typeof e.occurred_at !== 'string' ||
      !Number.isFinite(Date.parse(e.occurred_at)) ||
      !e.data ||
      typeof e.data !== 'object' ||
      Array.isArray(e.data)
    )
      throw rejected();
    return {
      id: e.event_id,
      type: e.event_type,
      occurredAt: e.occurred_at,
      data: e.data as Record<string, unknown>,
    };
  }
}
