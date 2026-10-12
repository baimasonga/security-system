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

export interface CheckoutRequest {
  intentId: string;
  priceId: string;
}
export interface ProviderCheckout {
  transactionId: string;
  url: string;
  status: string;
}
export interface CheckoutProvider {
  createCheckout(request: CheckoutRequest): Promise<ProviderCheckout>;
  getCheckout(transactionId: string, request: CheckoutRequest): Promise<ProviderCheckout>;
}

/** One creation attempt only. The caller persists the intent first and reconciles uncertain outcomes. */
export class PaddleCheckoutProvider implements CheckoutProvider {
  readonly #key: string;
  readonly #base: string;
  readonly #payment: URL;
  readonly #fetch: typeof fetch;
  constructor(opts: {
    apiKey: string;
    environment: 'sandbox' | 'live';
    paymentUrl: string;
    fetch?: typeof fetch;
  }) {
    if (
      !opts.apiKey ||
      /[\r\n]/.test(opts.apiKey) ||
      !['sandbox', 'live'].includes(opts.environment)
    )
      throw new Error('Paddle checkout configuration required');
    let payment: URL;
    try {
      payment = new URL(opts.paymentUrl);
    } catch {
      throw new Error('approved HTTPS payment URL required');
    }
    if (
      payment.protocol !== 'https:' ||
      payment.username ||
      payment.password ||
      payment.hash ||
      payment.search
    )
      throw new Error('approved HTTPS payment URL required');
    this.#key = opts.apiKey;
    this.#base =
      opts.environment === 'live' ? 'https://api.paddle.com' : 'https://sandbox-api.paddle.com';
    this.#payment = payment;
    this.#fetch = opts.fetch ?? fetch;
  }
  #input(request: CheckoutRequest): void {
    if (
      !/^bco_[a-z0-9_-]{16,64}$/.test(request.intentId) ||
      !/^pri_[a-z0-9]{26}$/.test(request.priceId)
    )
      throw new Error('invalid checkout request');
  }
  async #call(
    method: 'GET' | 'POST',
    path: string,
    request: CheckoutRequest,
    body?: unknown,
  ): Promise<ProviderCheckout> {
    this.#input(request);
    let response: Response;
    try {
      response = await this.#fetch(this.#base + path, {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
        headers: { authorization: `Bearer ${this.#key}`, 'content-type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      throw new Error(
        method === 'POST'
          ? 'billing checkout outcome uncertain'
          : 'billing reconciliation unavailable',
      );
    }
    if (!response.ok)
      throw new Error(
        method === 'POST'
          ? 'billing checkout outcome uncertain'
          : 'billing reconciliation unavailable',
      );
    let value: unknown;
    try {
      if (!response.body) throw new Error();
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      for await (const chunk of response.body) {
        bytes += chunk.byteLength;
        if (bytes > 1024 * 1024) throw new Error();
        chunks.push(chunk);
      }
      value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new Error('invalid billing provider response');
    }
    if (
      !value ||
      typeof value !== 'object' ||
      !('data' in value) ||
      !value.data ||
      typeof value.data !== 'object'
    )
      throw new Error('invalid billing provider response');
    const data = value.data as Record<string, unknown>;
    const custom = data.custom_data as Record<string, unknown> | undefined;
    const checkout = data.checkout as Record<string, unknown> | undefined;
    const items = data.items;
    if (
      typeof data.id !== 'string' ||
      !/^txn_[a-z0-9]{26}$/.test(data.id) ||
      typeof data.status !== 'string' ||
      !['draft', 'ready', 'billed', 'paid', 'completed', 'past_due', 'canceled'].includes(
        data.status,
      ) ||
      data.collection_mode !== 'automatic' ||
      custom?.trust_checkout_id !== request.intentId ||
      !Array.isArray(items) ||
      items.length !== 1
    )
      throw new Error('invalid billing provider response');
    const item = items[0] as Record<string, unknown> | undefined,
      price = item?.price as Record<string, unknown> | undefined;
    if (item?.quantity !== 1 || price?.id !== request.priceId || typeof checkout?.url !== 'string')
      throw new Error('invalid billing provider response');
    let url: URL;
    try {
      url = new URL(checkout.url);
    } catch {
      throw new Error('invalid billing provider response');
    }
    if (
      url.origin !== this.#payment.origin ||
      url.pathname !== this.#payment.pathname ||
      url.username ||
      url.password ||
      url.hash ||
      url.searchParams.getAll('_ptxn').length !== 1 ||
      url.searchParams.get('_ptxn') !== data.id ||
      [...url.searchParams.keys()].some((k) => k !== '_ptxn')
    )
      throw new Error('invalid billing provider response');
    return { transactionId: data.id, url: url.href, status: data.status };
  }
  createCheckout(request: CheckoutRequest): Promise<ProviderCheckout> {
    return this.#call('POST', '/transactions', request, {
      items: [{ price_id: request.priceId, quantity: 1 }],
      collection_mode: 'automatic',
      custom_data: { trust_checkout_id: request.intentId },
      checkout: { url: this.#payment.href },
    });
  }
  async getCheckout(transactionId: string, request: CheckoutRequest): Promise<ProviderCheckout> {
    if (!/^txn_[a-z0-9]{26}$/.test(transactionId)) throw new Error('invalid checkout transaction');
    const result = await this.#call('GET', '/transactions/' + transactionId, request);
    if (result.transactionId !== transactionId)
      throw new Error('invalid billing provider response');
    return result;
  }
}
