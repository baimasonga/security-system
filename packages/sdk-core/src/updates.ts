import { createHash } from 'node:crypto';
import { mkdtemp, open, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
  canonicalJson,
  isPublicJwk,
  jwkThumbprint,
  verifyJws,
  type PublicJwk,
} from '@trust/crypto/verify';
import type { SecureStore } from './device-key.ts';
import {
  MAX_EVIDENCE_BYTES,
  evidenceUrls,
  verifyReleaseEvidence,
  type EvidencePolicy,
  type VerifiedEvidence,
} from './release-evidence.ts';

export interface UpdateRole {
  threshold: number;
  keys: Array<{ kid: string; jwk: PublicJwk }>;
}
export interface UpdateRoot {
  schema: 1;
  version: number;
  expires: number;
  root: UpdateRole;
  release: UpdateRole;
  artifact_origins: string[];
}
export interface UpdateManifest {
  schema: 1;
  product: string;
  platform: string;
  channel: string;
  sequence: number;
  version: string;
  minimum_sequence: number;
  issued_at: number;
  expires: number;
  paused: boolean;
  artifact: {
    url: string;
    size: number;
    sha256: string;
    sbom_sha256: string;
    provenance_sha256: string;
  };
}
export interface SignedUpdateEnvelope {
  signatures: string[];
}
export interface UpdateOptions {
  root: UpdateRoot;
  product: string;
  platform: string;
  channel: string;
  store: SecureStore;
  now?: () => Date;
  fetch?: typeof fetch;
  /** Defaults to 256 MiB; checked before download and while streaming. */
  maxArtifactBytes?: number;
}
interface Checkpoint {
  root: UpdateRoot;
  last_seen: number;
  targets: Record<string, { sequence: number; digest: string }>;
}
function reject(reason: string): never {
  throw new Error(`update rejected: ${reason}`);
}
function shape(v: unknown, keys: string[]): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return reject('malformed');
  const o = v as Record<string, unknown>;
  if (Object.keys(o).length !== keys.length || keys.some((k) => !Object.hasOwn(o, k)))
    return reject('malformed');
  return o;
}
function integer(n: unknown, min = 1): n is number {
  return Number.isSafeInteger(n) && (n as number) >= min;
}
function label(s: unknown): s is string {
  return typeof s === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(s);
}
function digest(s: unknown): s is string {
  return typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
}
function httpsUrl(s: unknown): URL {
  if (typeof s !== 'string' || s.length > 2048) return reject('artifact URL');
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return reject('artifact URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash)
    return reject('artifact URL');
  return url;
}
function role(v: unknown): UpdateRole {
  const o = shape(v, ['threshold', 'keys']);
  if (
    !Array.isArray(o.keys) ||
    o.keys.length < 1 ||
    o.keys.length > 16 ||
    !integer(o.threshold) ||
    o.threshold > o.keys.length
  )
    return reject('key policy');
  const ids = new Set<string>(),
    keys = new Set<string>();
  for (const item of o.keys) {
    const k = shape(item, ['kid', 'jwk']);
    shape(k.jwk, ['kty', 'crv', 'x']);
    if (!label(k.kid) || !isPublicJwk(k.jwk) || ids.has(k.kid) || keys.has(jwkThumbprint(k.jwk)))
      return reject('key policy');
    ids.add(k.kid);
    keys.add(jwkThumbprint(k.jwk));
  }
  return v as UpdateRole;
}
function root(v: unknown): UpdateRoot {
  const o = shape(v, ['schema', 'version', 'expires', 'root', 'release', 'artifact_origins']);
  if (o.schema !== 1 || !integer(o.version) || !integer(o.expires)) return reject('root schema');
  const a = role(o.root),
    b = role(o.release);
  if (
    a.keys.some((k) =>
      b.keys.some(
        (other) => other.kid === k.kid || jwkThumbprint(other.jwk) === jwkThumbprint(k.jwk),
      ),
    )
  )
    return reject('key separation');
  if (
    !Array.isArray(o.artifact_origins) ||
    o.artifact_origins.length < 1 ||
    o.artifact_origins.length > 16 ||
    o.artifact_origins.some((origin) => httpsUrl(origin).origin !== origin)
  )
    return reject('origin policy');
  return v as UpdateRoot;
}
function manifest(v: unknown): UpdateManifest {
  const o = shape(v, [
    'schema',
    'product',
    'platform',
    'channel',
    'sequence',
    'version',
    'minimum_sequence',
    'issued_at',
    'expires',
    'paused',
    'artifact',
  ]);
  if (
    o.schema !== 1 ||
    !label(o.product) ||
    !label(o.platform) ||
    !label(o.channel) ||
    !label(o.version) ||
    !integer(o.sequence) ||
    !integer(o.minimum_sequence, 0) ||
    o.minimum_sequence > o.sequence ||
    !integer(o.issued_at) ||
    !integer(o.expires) ||
    typeof o.paused !== 'boolean'
  )
    return reject('manifest schema');
  const a = shape(o.artifact, ['url', 'size', 'sha256', 'sbom_sha256', 'provenance_sha256']);
  httpsUrl(a.url);
  if (
    !integer(a.size) ||
    !digest(a.sha256) ||
    !digest(a.sbom_sha256) ||
    !digest(a.provenance_sha256)
  )
    return reject('artifact schema');
  return v as UpdateManifest;
}
function signed(
  envelope: SignedUpdateEnvelope,
  policy: UpdateRole,
  typ: string,
  expected?: unknown,
): unknown {
  const e = shape(envelope, ['signatures']);
  if (
    !Array.isArray(e.signatures) ||
    e.signatures.length < 1 ||
    e.signatures.length > 32 ||
    e.signatures.some((s) => typeof s !== 'string' || s.length > 16 * 1024)
  )
    return reject('signature envelope');
  const verified = new Set<string>();
  let payload = expected;
  let canonical = expected === undefined ? undefined : canonicalJson(expected);
  for (const token of e.signatures) {
    try {
      const result = verifyJws(token, {
        typ,
        resolveKey: (kid) => policy.keys.find((k) => k.kid === kid)?.jwk,
      });
      const candidate = canonicalJson(result.payload);
      if (canonical !== undefined && canonical !== candidate)
        return reject('conflicting signatures');
      canonical = candidate;
      payload = result.payload;
      verified.add(result.header.kid);
    } catch (error) {
      if (error instanceof Error && error.message === 'update rejected: conflicting signatures')
        throw error;
      // Unknown keys are expected during a dual-signed root rotation. They never count.
    }
  }
  if (verified.size < policy.threshold || payload === undefined)
    return reject('signature threshold');
  return payload;
}

/** Verification and staging only. Host must serialize this store across processes and install atomically. */
export class SecureUpdateClient {
  readonly #o: UpdateOptions;
  readonly #initial: UpdateRoot;
  readonly #key: string;
  #tail: Promise<unknown> = Promise.resolve();
  constructor(options: UpdateOptions) {
    this.#o = options;
    this.#initial = structuredClone(root(options.root));
    if (![options.product, options.platform, options.channel].every(label)) reject('target');
    if (options.maxArtifactBytes !== undefined && !integer(options.maxArtifactBytes))
      reject('download limit');
    // The root namespace is shared across channels of a product, preserving global rotation.
    this.#key = `updates_v1_${options.product}`;
  }
  #serial<T>(work: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(work);
    this.#tail = result.catch(() => {});
    return result;
  }
  #now(): number {
    const n = Math.floor((this.#o.now?.() ?? new Date()).getTime() / 1000);
    if (!integer(n)) return reject('clock');
    return n;
  }
  async #state(now: number): Promise<Checkpoint> {
    const text = await this.#o.store.get(this.#key);
    let state: Checkpoint;
    if (!text) state = { root: structuredClone(this.#initial), last_seen: 0, targets: {} };
    else {
      let value: unknown;
      try {
        value = JSON.parse(text);
      } catch {
        return reject('checkpoint');
      }
      const o = shape(value, ['root', 'last_seen', 'targets']);
      root(o.root);
      if (
        !integer(o.last_seen, 0) ||
        !o.targets ||
        typeof o.targets !== 'object' ||
        Array.isArray(o.targets)
      )
        return reject('checkpoint');
      for (const v of Object.values(o.targets)) {
        const t = shape(v, ['sequence', 'digest']);
        if (!integer(t.sequence) || !digest(t.digest)) reject('checkpoint');
      }
      state = value as Checkpoint;
    }
    if (state.root.version < this.#initial.version) reject('root rollback');
    if (now < state.last_seen - 60) reject('clock rollback');
    if (state.root.expires <= now) reject('expired root');
    return state;
  }
  async #save(state: Checkpoint, now: number): Promise<void> {
    state.last_seen = Math.max(state.last_seen, now);
    await this.#o.store.set(this.#key, JSON.stringify(state));
  }
  async rotateRoot(envelope: SignedUpdateEnvelope): Promise<void> {
    return this.#serial(async () => {
      const now = this.#now(),
        state = await this.#state(now);
      const next = root(signed(envelope, state.root.root, 'trust-update-root+jws'));
      if (next.version !== state.root.version + 1 || next.expires <= now)
        reject('root version or expiry');
      signed(envelope, next.root, 'trust-update-root+jws', next);
      state.root = next;
      await this.#save(state, now);
    });
  }
  #check(envelope: SignedUpdateEnvelope, state: Checkpoint, now: number): UpdateManifest {
    const m = manifest(signed(envelope, state.root.release, 'trust-update-manifest+jws'));
    if (
      m.product !== this.#o.product ||
      m.platform !== this.#o.platform ||
      m.channel !== this.#o.channel
    )
      reject('binding');
    if (
      m.expires <= now ||
      m.issued_at > now + 60 ||
      m.expires <= m.issued_at ||
      m.expires - m.issued_at > 7 * 86400
    )
      reject('freshness');
    if (!state.root.artifact_origins.includes(httpsUrl(m.artifact.url).origin))
      reject('artifact origin');
    const target = `${m.platform}/${m.channel}`,
      previous = state.targets[target];
    const hash = createHash('sha256').update(canonicalJson(m)).digest('hex');
    if (previous && m.sequence < previous.sequence) reject('rollback');
    if (previous && m.sequence === previous.sequence && hash !== previous.digest)
      reject('equivocation');
    state.targets[target] = { sequence: m.sequence, digest: hash };
    return m;
  }
  async verifyManifest(envelope: SignedUpdateEnvelope): Promise<UpdateManifest> {
    return this.#serial(async () => {
      const now = this.#now(),
        state = await this.#state(now),
        m = this.#check(envelope, state, now);
      await this.#save(state, now);
      return m;
    });
  }
  /** Fetch a bounded signed feed from a root-allowed origin, then verify and persist its watermark. */
  async checkForUpdates(
    manifestUrl: string,
  ): Promise<{ envelope: SignedUpdateEnvelope; manifest: UpdateManifest }> {
    return this.#serial(async () => {
      const now = this.#now(),
        state = await this.#state(now),
        url = httpsUrl(manifestUrl);
      if (!state.root.artifact_origins.includes(url.origin)) reject('metadata origin');
      const response = await (this.#o.fetch ?? fetch)(url.href, {
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok || !response.body || (response.url && response.url !== url.href))
        reject('metadata response');
      const chunks: Uint8Array[] = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.byteLength;
        if (size > 512 * 1024) reject('metadata size');
        chunks.push(chunk);
      }
      let envelope: SignedUpdateEnvelope;
      try {
        envelope = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return reject('metadata response');
      }
      const finished = this.#now();
      if (finished < now - 60 || state.root.expires <= finished) reject('freshness');
      const m = this.#check(envelope, state, finished);
      await this.#save(state, finished);
      return { envelope, manifest: m };
    });
  }

  /**
   * Downloads the SBOM and provenance published next to the artifact (`<url>.cdx.json`, `<url>.intoto.json`) and
   * verifies them against the signed manifest and the product's trusted builders (ADR-028). Call before
   * installing; a release without valid evidence should not be installed.
   */
  async verifyEvidence(
    envelope: SignedUpdateEnvelope,
    policy: EvidencePolicy,
  ): Promise<VerifiedEvidence & { manifest: UpdateManifest }> {
    const m = await this.verifyManifest(envelope);
    const urls = evidenceUrls(m.artifact.url);
    const get = async (u: string): Promise<Uint8Array> => {
      const url = httpsUrl(u);
      const state = await this.#state(this.#now());
      if (!state.root.artifact_origins.includes(url.origin)) reject('evidence origin');
      const response = await (this.#o.fetch ?? fetch)(url.href, {
        redirect: 'error',
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok || !response.body || (response.url && response.url !== url.href))
        reject('evidence response');
      const chunks: Uint8Array[] = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.byteLength;
        if (size > MAX_EVIDENCE_BYTES) reject('evidence size');
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    };
    const [sbom, provenance] = [await get(urls.sbom), await get(urls.provenance)];
    return { ...verifyReleaseEvidence(m, { sbom, provenance }, policy), manifest: m };
  }

  /** Returns a private verified staging file. Caller removes its directory after installation. */
  async stageArtifact(
    envelope: SignedUpdateEnvelope,
    directory: string,
  ): Promise<{ path: string; manifest: UpdateManifest }> {
    return this.#serial(async () => {
      const now = this.#now(),
        state = await this.#state(now),
        m = this.#check(envelope, state, now);
      if (m.paused) reject('release paused');
      const max = this.#o.maxArtifactBytes ?? 256 * 1024 * 1024;
      if (m.artifact.size > max) reject('download limit');
      await this.#save(state, now);
      const tmp = await mkdtemp(join(directory, 'trust-update-'));
      const path = join(tmp, 'artifact');
      try {
        const response = await (this.#o.fetch ?? fetch)(m.artifact.url, {
          redirect: 'error',
          signal: AbortSignal.timeout(120_000),
          headers: { 'accept-encoding': 'identity' },
        });
        if (!response.ok || !response.body || (response.url && response.url !== m.artifact.url))
          reject('download response');
        const length = response.headers.get('content-length');
        if (length !== null && (!/^\d+$/.test(length) || Number(length) !== m.artifact.size))
          reject('artifact size');
        // Path is generated beneath the host-selected staging directory, never taken from metadata.
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        const file = await open(path, 'wx', 0o600);
        try {
          const hash = createHash('sha256');
          let size = 0;
          for await (const chunk of response.body) {
            size += chunk.byteLength;
            if (size > m.artifact.size || size > max) reject('artifact size');
            hash.update(chunk);
            await file.writeFile(chunk);
          }
          if (size !== m.artifact.size || hash.digest('hex') !== m.artifact.sha256)
            reject('artifact integrity');
          await file.sync();
        } finally {
          await file.close();
        }
        // Metadata cannot expire or be revoked through rotation during this serialized download.
        const finished = this.#now();
        if (m.expires <= finished || state.root.expires <= finished || finished < now - 60)
          reject('freshness');
        await this.#save(state, finished);
        return { path, manifest: m };
      } catch (error) {
        await rm(tmp, { recursive: true, force: true });
        throw error;
      }
    });
  }
}
