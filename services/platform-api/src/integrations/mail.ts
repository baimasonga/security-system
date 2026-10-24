import type { PlatformConfig } from '../config.ts';
/** Delivery seam for upcoming account verification/reset. Never log message content or provider keys. */
export interface TransactionalMessage {
  id: string;
  to: string;
  subject: string;
  text: string;
}
export interface MailDelivery {
  send(message: TransactionalMessage): Promise<{ id: string }>;
}
/** Test/local adapter only. Captured content must never be exposed by a production HTTP route. */
export class MemoryMailDelivery implements MailDelivery {
  readonly messages: TransactionalMessage[] = [];
  async send(message: TransactionalMessage): Promise<{ id: string }> {
    const existing = this.messages.find((item) => item.id === message.id);
    if (!existing) this.messages.push({ ...message });
    return { id: message.id };
  }
}
export class ResendMailDelivery implements MailDelivery {
  readonly #key: string;
  readonly #from: string;
  readonly #fetch: typeof fetch;
  constructor(opts: { apiKey: string; from: string; fetch?: typeof fetch }) {
    if (!opts.apiKey || !opts.from || /[\r\n]/.test(opts.from))
      throw new Error('Resend requires an API key and verified sender');
    this.#key = opts.apiKey;
    this.#from = opts.from;
    this.#fetch = opts.fetch ?? fetch;
  }
  async send(message: TransactionalMessage): Promise<{ id: string }> {
    if (!message.id || message.id.length > 128 || !/^[A-Za-z0-9_-]+$/.test(message.id))
      throw new Error('invalid message id');
    if (
      !message.to ||
      /[\r\n]/.test(message.to) ||
      message.subject.length > 200 ||
      /[\r\n]/.test(message.subject)
    )
      throw new Error('invalid email envelope');
    let response: Response;
    try {
      response = await this.#fetch('https://api.resend.com/emails', {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
        headers: {
          authorization: `Bearer ${this.#key}`,
          'content-type': 'application/json',
          'idempotency-key': message.id,
        },
        body: JSON.stringify({
          from: this.#from,
          to: [message.to],
          subject: message.subject,
          text: message.text,
        }),
      });
    } catch {
      throw new Error('email delivery unavailable');
    }
    if (!response.ok) throw new Error(`email delivery rejected (HTTP ${response.status})`);
    const result: unknown = await response.json();
    if (!result || typeof result !== 'object' || !('id' in result) || typeof result.id !== 'string')
      throw new Error('invalid email delivery response');
    return { id: result.id };
  }
}
/**
 * Cloudflare Email Sending REST API. Cloudflare documents no idempotency key, so an ambiguous
 * timeout can repeat a message on retry; callers already treat delivery as at-least-once.
 */
export class CloudflareMailDelivery implements MailDelivery {
  readonly #token: string;
  readonly #accountId: string;
  readonly #from: string | { address: string; name: string };
  readonly #fetch: typeof fetch;
  constructor(opts: { apiToken: string; accountId: string; from: string; fetch?: typeof fetch }) {
    if (!opts.apiToken || !/^[a-f0-9]{32}$/i.test(opts.accountId))
      throw new Error('Cloudflare email requires an API token and account ID');
    if (!opts.from || /[\r\n]/.test(opts.from))
      throw new Error('Cloudflare email requires a verified sender');
    const named = /^(.*?)<([^<>]+)>$/.exec(opts.from);
    this.#from = named ? { address: named[2]!.trim(), name: named[1]!.trim() } : opts.from;
    this.#token = opts.apiToken;
    this.#accountId = opts.accountId;
    this.#fetch = opts.fetch ?? fetch;
  }
  async send(message: TransactionalMessage): Promise<{ id: string }> {
    if (!message.id || message.id.length > 128 || !/^[A-Za-z0-9_-]+$/.test(message.id))
      throw new Error('invalid message id');
    if (
      !message.to ||
      /[\r\n]/.test(message.to) ||
      message.subject.length > 200 ||
      /[\r\n]/.test(message.subject)
    )
      throw new Error('invalid email envelope');
    let response: Response;
    try {
      response = await this.#fetch(
        `https://api.cloudflare.com/client/v4/accounts/${this.#accountId}/email/sending/send`,
        {
          method: 'POST',
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
          headers: { authorization: `Bearer ${this.#token}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            from: this.#from,
            to: message.to,
            subject: message.subject,
            text: message.text,
          }),
        },
      );
    } catch {
      throw new Error('email delivery unavailable');
    }
    if (!response.ok) throw new Error(`email delivery rejected (HTTP ${response.status})`);
    // Never echo the body: it names recipients and provider details.
    let result: unknown;
    try {
      result = await response.json();
    } catch {
      throw new Error('invalid email delivery response');
    }
    const r = result as {
      success?: unknown;
      result?: Record<'delivered' | 'queued' | 'permanent_bounces', unknown>;
    } | null;
    const has = (list: unknown) =>
      Array.isArray(list) &&
      list.some((v) => typeof v === 'string' && v.toLowerCase() === message.to.toLowerCase());
    if (
      r?.success !== true ||
      has(r.result?.permanent_bounces) ||
      !(has(r.result?.delivered) || has(r.result?.queued))
    )
      throw new Error('email delivery not accepted');
    return { id: message.id };
  }
}
/** The configured transactional provider, if any. */
export function configuredMailDelivery(
  config: NonNullable<PlatformConfig['emailDelivery']>,
): MailDelivery {
  return config.provider === 'cloudflare'
    ? new CloudflareMailDelivery(config)
    : new ResendMailDelivery(config);
}
