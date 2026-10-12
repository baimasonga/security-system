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
