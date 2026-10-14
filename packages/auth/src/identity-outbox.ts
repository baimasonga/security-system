import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Clock } from '@trust/shared-types';
import type { AuthStore, AuthTx, IdentityMail } from './model.ts';
import type { IdentityDelivery } from './service.ts';

type Message = Parameters<IdentityDelivery['send']>[0];
export class IdentityMailCipher {
  readonly #key: Buffer;
  constructor(hex: string) {
    if (!/^[0-9a-f]{64}$/i.test(hex) || new Set(hex.toLowerCase()).size < 8)
      throw new Error('MAIL_OUTBOX_ENCRYPTION_KEY must be a random 32-byte hex key');
    this.#key = Buffer.from(hex, 'hex');
  }
  #aad(r: Pick<IdentityMail, 'userId' | 'purpose' | 'tokenHash' | 'createdAt' | 'expiresAt'>) {
    return Buffer.from(
      JSON.stringify([
        'trust/identity-mail/v1',
        r.userId,
        r.purpose,
        r.tokenHash,
        r.createdAt.toISOString(),
        r.expiresAt.toISOString(),
      ]),
    );
  }
  seal(row: IdentityMail, message: Message) {
    const plain = Buffer.from(JSON.stringify(message));
    if (plain.length > 4096) throw new Error('identity message too large');
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(this.#aad(row));
    const bytes = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), bytes]).toString('base64url');
  }
  open(row: IdentityMail): Message {
    if (!/^[A-Za-z0-9_-]{40,8192}$/.test(row.sealed)) throw new Error('invalid encrypted mail');
    const bytes = Buffer.from(row.sealed, 'base64url');
    const cipher = createDecipheriv('aes-256-gcm', this.#key, bytes.subarray(0, 12));
    cipher.setAAD(this.#aad(row));
    cipher.setAuthTag(bytes.subarray(12, 28));
    const parsed: unknown = JSON.parse(
      Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8'),
    );
    if (!parsed || typeof parsed !== 'object') throw new Error('invalid encrypted mail');
    const m = parsed as Record<string, unknown>;
    if (
      m.id !== row.tokenHash ||
      typeof m.to !== 'string' ||
      !m.to ||
      m.to.length > 254 ||
      /[\r\n]/.test(m.to) ||
      typeof m.subject !== 'string' ||
      m.subject.length > 200 ||
      /[\r\n]/.test(m.subject) ||
      typeof m.text !== 'string' ||
      m.text.length > 4096
    )
      throw new Error('invalid encrypted mail');
    return { id: row.tokenHash, to: m.to, subject: m.subject, text: m.text };
  }
}

const empty = () => ({ sent: 0, retried: 0, discarded: 0 });
/** Persisted/fenced claims, then network delivery outside retryable database transactions. */
export class IdentityMailOutbox {
  readonly #onOutcome: ((outcome: 'sent' | 'retried' | 'discarded') => void) | undefined;
  readonly #store: AuthStore;
  readonly #clock: Clock;
  readonly #delivery: IdentityDelivery;
  readonly cipher: IdentityMailCipher;
  #running: Promise<ReturnType<typeof empty>> | undefined;
  #stopping = false;
  constructor(opts: {
    store: AuthStore;
    clock: Clock;
    delivery: IdentityDelivery;
    key: string;
    onOutcome?: (outcome: 'sent' | 'retried' | 'discarded') => void;
  }) {
    this.#store = opts.store;
    this.#clock = opts.clock;
    this.#delivery = opts.delivery;
    this.cipher = new IdentityMailCipher(opts.key);
    this.#onOutcome = opts.onOutcome;
  }
  runOnce(): Promise<ReturnType<typeof empty>> {
    if (this.#stopping) return Promise.resolve(empty());
    if (this.#running) return this.#running;
    const pass = this.#pass();
    this.#running = pass;
    void pass
      .finally(() => {
        this.#running = undefined;
      })
      .catch(() => undefined);
    return pass;
  }
  async stop() {
    this.#stopping = true;
    await this.#running?.catch(() => undefined);
  }
  async #discard(tx: AuthTx, row: IdentityMail) {
    await tx.deleteIdentityMail(row.tokenHash);
    await tx.audit.append({
      actor: { type: 'system' },
      action: 'identity.delivery_discarded',
      target: { type: 'user', id: row.userId },
      metadata: { purpose: row.purpose },
    });
  }
  async #pass() {
    const counts = empty();
    const candidates = await this.#store.listDueIdentityMail(this.#clock.now(), 25);
    for (const candidate of candidates) {
      if (this.#stopping) break;
      const claim = randomBytes(24).toString('hex');
      const reserved = await this.#store.transaction(async (tx) => {
        const user = await tx.findUserForUpdate(candidate.userId);
        const row = await tx.findIdentityMailForUpdate(candidate.tokenHash);
        const now = this.#clock.now();
        if (
          !row ||
          row.userId !== candidate.userId ||
          row.nextAttemptAt > now ||
          (row.lockedUntil && row.lockedUntil > now)
        )
          return undefined;
        const token = await tx.findUserIdentityToken(row.userId, row.purpose);
        if (
          !user ||
          user.status !== 'active' ||
          row.expiresAt <= now ||
          row.attempts >= 6 ||
          !token ||
          token.tokenHash !== row.tokenHash ||
          token.usedAt ||
          token.expiresAt <= now
        ) {
          await this.#discard(tx, row);
          return { discarded: true as const };
        }
        let message: Message;
        try {
          message = this.cipher.open(row);
          if (message.to !== user.email) throw new Error('recipient changed');
        } catch {
          await this.#discard(tx, row);
          return { discarded: true as const };
        }
        const leased = {
          ...row,
          attempts: row.attempts + 1,
          claim,
          lockedUntil: new Date(+now + 60000),
        };
        await tx.putIdentityMail(leased);
        await tx.audit.append({
          actor: { type: 'system' },
          action: 'identity.delivery_claimed',
          target: { type: 'user', id: row.userId },
          metadata: { purpose: row.purpose, attempt: leased.attempts },
        });
        return { row: leased, message };
      });
      if (!reserved) continue;
      if ('discarded' in reserved) {
        counts.discarded++;
        this.#onOutcome?.('discarded');
        continue;
      }
      let accepted = false;
      try {
        // Recheck time immediately before sending; provider latency never extends token validity.
        if (reserved.row.expiresAt > this.#clock.now()) {
          await this.#delivery.send(reserved.message);
          accepted = true;
        }
      } catch {
        /* Never retain or log provider error bodies. */
      }
      const outcome = await this.#store.transaction(async (tx) => {
        await tx.findUserForUpdate(reserved.row.userId);
        const row = await tx.findIdentityMailForUpdate(reserved.row.tokenHash);
        if (!row || row.claim !== claim) return undefined; // stale acknowledgements cannot erase another worker's claim
        const now = this.#clock.now();
        if (!accepted && (row.attempts >= 6 || row.expiresAt <= now)) {
          await this.#discard(tx, row);
          return 'discarded' as const;
        }
        if (accepted) await tx.deleteIdentityMail(row.tokenHash);
        else
          await tx.putIdentityMail({
            ...row,
            claim: null,
            lockedUntil: null,
            nextAttemptAt: new Date(+now + Math.min(60000, 5000 * 2 ** (row.attempts - 1))),
          });
        await tx.audit.append({
          actor: { type: 'system' },
          action: accepted ? 'identity.delivery_sent' : 'identity.delivery_retry',
          target: { type: 'user', id: row.userId },
          metadata: { purpose: row.purpose, attempt: row.attempts },
        });
        return accepted ? ('sent' as const) : ('retried' as const);
      });
      if (outcome) {
        counts[outcome]++;
        this.#onOutcome?.(outcome);
      }
    }
    return counts;
  }
}
