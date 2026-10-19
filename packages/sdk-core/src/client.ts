import { randomBytes } from 'node:crypto';
import {
  buildProofMessage,
  jwkThumbprint,
  normalizePublicJwk,
  type ProofPurpose,
} from '@trust/crypto/verify';
import type { LeaseClaims } from '@trust/shared-types';
import { SoftwareDeviceKey, type DeviceKey, type SecureStore } from './device-key.ts';
import { verifyLease, type LeaseCheck, type TrustBundle } from './lease-verifier.ts';

export class PlatformError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = 'PlatformError';
    this.code = code;
    this.status = status;
  }
}

export interface ClientOptions {
  baseUrl: string;
  productCode: string;
  trust: TrustBundle;
  store: SecureStore;
  /** Host-owned persistent key (OS/native service). Failure never falls back to software. */
  deviceKeyProvider?: (installationId: string) => Promise<DeviceKey>;
  fetch?: typeof fetch;
  now?: () => Date;
  issuer?: string;
  skewSeconds?: number;
}

export interface Entitlements {
  state: LeaseCheck['state'];
  entitlements: Record<string, boolean | number>;
  capabilities: string[];
  tier: string | null;
  planVersion: number | null;
  /** When the offline lease stops being honoured. */
  leaseExpiresAt: Date | null;
  refreshAfter: Date | null;
}

/** Online authoritative usage; timestamps use the API's ISO 8601 wire format. */
export interface QuotaUsage {
  license_id: string;
  period: string;
  resets_at: string;
  status: 'valid' | 'unavailable';
  items: Array<{ entitlement: string; limit: number; used: number; remaining: number }>;
}

/** Accounting receipt, not an execution capability or proof of completed work. */
export interface CheckoutState {
  id: string;
  license_id: string;
  plan_id: string;
  status: 'submitting' | 'uncertain' | 'ready' | 'completed';
  checkout_url: string | null;
  created_at: string;
  subscription_status: string | null;
  current_period_end: string | null;
}

export interface QuotaReceipt {
  id: string;
  license_id: string;
  entitlement: string;
  period: string;
  units: number;
  created_at: string;
}

const K = {
  lease: 'lease',
  activation: 'activation_id',
  installation: 'installation_id',
  devicePem: 'device_key',
  lastSeen: 'last_seen',
};

/**
 * Thin client over the platform API. All security decisions of consequence are made by the server;
 * this class only (a) proves device possession, (b) verifies signed evidence, (c) persists it.
 *
 * Roadmap methods (not implemented in V1): requestCapability, registerDevice (hardware attestation),
 * getTrustState, checkForUpdates, reportSecurityEvent.
 */
export class TrustPlatformClient {
  readonly #o: ClientOptions;
  readonly #fetch: typeof fetch;
  #key: DeviceKey | undefined;
  #installationId: string | undefined;
  #keyPending: Promise<DeviceKey> | undefined;
  #installationPending: Promise<string> | undefined;

  constructor(opts: ClientOptions) {
    this.#o = opts;
    this.#fetch = opts.fetch ?? fetch;
  }

  #now(): Date {
    return this.#o.now?.() ?? new Date();
  }

  /** Install-scoped random id. Generated once; reinstall = new id (the server tracks trial history). */
  async installationId(): Promise<string> {
    if (this.#installationId) return this.#installationId;
    if (!this.#installationPending)
      this.#installationPending = this.#loadInstallation().finally(() => {
        this.#installationPending = undefined;
      });
    return this.#installationPending;
  }

  async #loadInstallation(): Promise<string> {
    let id = await this.#o.store.get(K.installation);
    if (!id) {
      id = `inst_${randomBytes(18).toString('base64url')}`;
      await this.#o.store.set(K.installation, id);
    }
    return (this.#installationId = id);
  }

  async deviceKey(): Promise<DeviceKey> {
    if (this.#key) return this.#key;
    if (!this.#keyPending)
      this.#keyPending = this.#loadKey().finally(() => {
        this.#keyPending = undefined;
      });
    return this.#keyPending;
  }

  async #loadKey(): Promise<DeviceKey> {
    if (this.#o.deviceKeyProvider) {
      const key = await this.#o.deviceKeyProvider(await this.installationId());
      const publicJwk = normalizePublicJwk(key.publicJwk);
      if (jwkThumbprint(publicJwk) !== key.thumbprint)
        throw new PlatformError('invalid_device_key', 0, 'host device key binding is invalid');
      return (this.#key = {
        publicJwk,
        thumbprint: key.thumbprint,
        sign: (message) => key.sign(message),
      });
    }
    const pem = await this.#o.store.get(K.devicePem);
    if (pem) return (this.#key = SoftwareDeviceKey.fromPem(pem));
    const k = SoftwareDeviceKey.generate();
    await this.#o.store.set(K.devicePem, k.exportPem());
    return (this.#key = k);
  }

  async #call<T>(method: string, path: string, body?: unknown, bearer?: string): Promise<T> {
    const res = await this.#fetch(new URL(path, this.#o.baseUrl), {
      method,
      headers: {
        'content-type': 'application/json',
        ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      },
      body: body === undefined ? null : JSON.stringify(body),
    });
    const text = await res.text();
    const json = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    if (!res.ok) {
      throw new PlatformError(
        String(json['code'] ?? 'internal'),
        res.status,
        String(json['message'] ?? res.statusText),
      );
    }
    return json as T;
  }

  async #challenge(purpose: ProofPurpose, subjectId: string) {
    const installationId = await this.installationId();
    const ch = await this.#call<{ nonce: string }>('POST', '/v1/devices/challenges', {
      purpose,
      installation_id: installationId,
      ...(subjectId ? { subject_id: subjectId } : {}),
    });
    const key = await this.deviceKey();
    const signature = await key.sign(
      buildProofMessage({
        purpose,
        nonce: ch.nonce,
        installationId,
        subjectId,
        thumbprint: key.thumbprint,
      }),
    );
    return { installationId, nonce: ch.nonce, signature };
  }

  async #acceptLease(lease: string, activationId: string): Promise<LeaseCheck> {
    // Never trust the network response: verify the signature and every binding locally first.
    const check = await this.#verify(lease);
    if (check.state === 'invalid')
      throw new PlatformError(
        'invalid_lease',
        502,
        `server returned an unverifiable lease (${check.reason})`,
      );
    await this.#o.store.set(K.lease, lease);
    await this.#o.store.set(K.activation, activationId);
    return check;
  }

  async #verify(lease: string): Promise<LeaseCheck> {
    const key = await this.deviceKey();
    const lastSeenRaw = await this.#o.store.get(K.lastSeen);
    const check = verifyLease(lease, {
      trust: this.#o.trust,
      productCode: this.#o.productCode,
      installationId: await this.installationId(),
      deviceThumbprint: key.thumbprint,
      now: this.#now(),
      lastSeenAt: lastSeenRaw ? new Date(lastSeenRaw) : undefined,
      ...(this.#o.issuer ? { issuer: this.#o.issuer } : {}),
      ...(this.#o.skewSeconds !== undefined ? { skewSeconds: this.#o.skewSeconds } : {}),
    });
    if (check.state !== 'invalid')
      await this.#o.store.set(K.lastSeen, check.nextLastSeenAt.toISOString());
    return check;
  }

  /** Sign in is done by the host app; `sessionToken` is the bearer token from /v1/auth/login. */
  async activate(sessionToken: string, licenseKey: string): Promise<LeaseCheck> {
    const key = await this.deviceKey();
    const { installationId, nonce, signature } = await this.#challenge('activate', '');
    const grant = await this.#call<{ lease: string; activation_id: string }>(
      'POST',
      '/v1/licenses/activate',
      {
        license_key: licenseKey,
        installation_id: installationId,
        device_public_key: key.publicJwk,
        nonce,
        signature,
      },
      sessionToken,
    );
    return this.#acceptLease(grant.lease, grant.activation_id);
  }

  async #deviceCall<T>(purpose: Exclude<ProofPurpose, 'activate'>, path: string): Promise<T> {
    const activationId = await this.#o.store.get(K.activation);
    if (!activationId)
      throw new PlatformError('not_activated', 0, 'this installation is not activated');
    const { installationId, nonce, signature } = await this.#challenge(purpose, activationId);
    return this.#call<T>('POST', path, {
      activation_id: activationId,
      installation_id: installationId,
      nonce,
      signature,
    });
  }

  /** Ask the server whether this activation is still good (no new lease). */
  async validateLicense(): Promise<{ status: string }> {
    return this.#deviceCall('validate', '/v1/licenses/validate');
  }

  async refreshLease(): Promise<LeaseCheck> {
    const grant = await this.#deviceCall<{ lease: string; activation_id: string }>(
      'refresh',
      '/v1/licenses/refresh',
    );
    return this.#acceptLease(grant.lease, grant.activation_id);
  }

  /**
   * A short-lived token proving this activation may use `capability` at processing service `service` (ADR-024).
   * Pass it to that service with the request; never cache it beyond `expires_at`.
   */
  async capabilityToken(
    capability: string,
    service: string,
  ): Promise<{ token: string; expires_at: string; capability: string; audience: string }> {
    const activationId = await this.#o.store.get(K.activation);
    if (!activationId)
      throw new PlatformError('not_activated', 0, 'this installation is not activated');
    const { installationId, nonce, signature } = await this.#challenge('capability', activationId);
    return this.#call('POST', '/v1/capabilities/token', {
      activation_id: activationId,
      installation_id: installationId,
      nonce,
      signature,
      capability,
      service,
    });
  }

  async deactivate(): Promise<void> {
    await this.#deviceCall('deactivate', '/v1/licenses/deactivate');
    await this.#o.store.delete(K.lease);
    await this.#o.store.delete(K.activation);
  }

  #usagePath(sessionToken: string, orgId: string, licenseId: string): string {
    if (!sessionToken || !/^[A-Za-z0-9_-]+$/.test(orgId) || !/^[A-Za-z0-9_-]+$/.test(licenseId))
      throw new PlatformError(
        'invalid_request',
        0,
        'session and valid organization/license IDs are required',
      );
    return `/v1/organizations/${orgId}/licenses/${licenseId}/usage`;
  }

  /** Online administrator/owner action. Reuse one durable operation ID; payment does not occur here. */
  async createCheckout(
    sessionToken: string,
    orgId: string,
    licenseId: string,
    planId: string,
    operationId: string,
  ): Promise<CheckoutState> {
    return this.#call(
      'POST',
      this.#usagePath(sessionToken, orgId, licenseId).replace(/usage$/, 'checkout'),
      { plan_id: planId, idempotency_key: operationId },
      sessionToken,
    );
  }
  async getCheckout(
    sessionToken: string,
    orgId: string,
    licenseId: string,
  ): Promise<CheckoutState> {
    return this.#call(
      'GET',
      this.#usagePath(sessionToken, orgId, licenseId).replace(/usage$/, 'checkout'),
      undefined,
      sessionToken,
    );
  }

  /** Online only. Remaining allowance does not authorize execution. */
  async getUsage(sessionToken: string, orgId: string, licenseId: string): Promise<QuotaUsage> {
    return this.#call(
      'GET',
      this.#usagePath(sessionToken, orgId, licenseId),
      undefined,
      sessionToken,
    );
  }

  /** Persist one operation ID per logical job and reuse it on retries, including after restart.
   * No automatic retry: the caller owns durable job deduplication and execution ordering.
   */
  async consumeQuota(
    sessionToken: string,
    orgId: string,
    licenseId: string,
    input: { entitlement: string; units: number; idempotencyKey: string },
  ): Promise<QuotaReceipt> {
    return this.#call(
      'POST',
      this.#usagePath(sessionToken, orgId, licenseId),
      {
        entitlement: input.entitlement,
        units: input.units,
        idempotency_key: input.idempotencyKey,
      },
      sessionToken,
    );
  }

  /** Offline-capable: answers from the locally stored, locally verified lease. */
  async getEntitlements(): Promise<Entitlements> {
    const lease = await this.#o.store.get(K.lease);
    const none: Entitlements = {
      state: 'invalid',
      entitlements: {},
      capabilities: [],
      tier: null,
      planVersion: null,
      leaseExpiresAt: null,
      refreshAfter: null,
    };
    if (!lease) return none;
    const check = await this.#verify(lease);
    if (check.state === 'invalid') return none;
    const c: LeaseClaims = check.claims;
    const usable = check.state === 'valid' || check.state === 'refresh_recommended';
    return {
      state: check.state,
      // Entitlements are only surfaced while the lease is usable; hosts degrade otherwise (never delete data).
      entitlements: usable ? c.ent : {},
      capabilities: usable ? c.cap : [],
      tier: c.tier,
      planVersion: c.plv,
      leaseExpiresAt: new Date(c.exp * 1000),
      refreshAfter: new Date(c.refresh_after * 1000),
    };
  }

  /** Convenience for hosts: refresh if due and reachable; never throws on network failure. */
  async maintainLease(): Promise<LeaseCheck | undefined> {
    const current = await this.getEntitlements();
    if (current.state === 'valid') return undefined;
    try {
      return await this.refreshLease();
    } catch (e) {
      if (e instanceof PlatformError && e.status !== 0 && e.status < 500) throw e; // definitive server answer
      return undefined; // offline / transient: keep using the existing lease until it expires
    }
  }
}
