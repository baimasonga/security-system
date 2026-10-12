const encoder = new TextEncoder();
export const b64 = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
const unb64 = (text) => {
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1)
    throw new Error('Malformed encoding');
  const bytes = Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
    c.charCodeAt(0),
  );
  if (b64(bytes) !== text) throw new Error('Noncanonical encoding');
  return bytes;
};
export async function thumbprint(jwk) {
  return b64(
    await crypto.subtle.digest(
      'SHA-256',
      encoder.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })),
    ),
  );
}
export function proofMessage(purpose, nonce, installation, subject, thumb) {
  return ['trust-platform/v1/device-proof', purpose, nonce, installation, subject, thumb].join(
    '\n',
  );
}
export async function checkOffline(token, options) {
  try {
    if (typeof token !== 'string' || token.length > 16384) throw new Error('Malformed lease');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Malformed lease');
    const header = JSON.parse(new TextDecoder().decode(unb64(parts[0])));
    const claims = JSON.parse(new TextDecoder().decode(unb64(parts[1])));
    if (
      header.alg !== 'EdDSA' ||
      header.typ !== 'lease+jws' ||
      typeof header.kid !== 'string' ||
      header.kid.length > 128
    )
      throw new Error('Invalid lease header');
    const jwk = options.trust.keys.find((k) => k.kid === header.kid)?.jwk;
    if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519')
      throw new Error('Unknown verification key');
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify']);
    if (
      !(await crypto.subtle.verify(
        'Ed25519',
        key,
        unb64(parts[2]),
        encoder.encode(`${parts[0]}.${parts[1]}`),
      ))
    )
      throw new Error('Invalid signature');
    const numbers = ['iat', 'nbf', 'exp', 'refresh_after', 'plv', 'dl'];
    const strings = [
      'jti',
      'iss',
      'aud',
      'lic',
      'org',
      'prd',
      'pln',
      'act',
      'inst',
      'dev',
      'kind',
      'tier',
    ];
    if (
      claims.v !== 1 ||
      numbers.some((k) => !Number.isFinite(claims[k])) ||
      strings.some((k) => typeof claims[k] !== 'string') ||
      !claims.ent ||
      Array.isArray(claims.ent) ||
      typeof claims.ent !== 'object' ||
      Object.values(claims.ent).some(
        (v) => typeof v !== 'boolean' && !(typeof v === 'number' && Number.isFinite(v)),
      ) ||
      !Array.isArray(claims.cap) ||
      claims.cap.some((v) => typeof v !== 'string')
    )
      throw new Error('Invalid claims');
    if (
      claims.iss !== 'trust-platform' ||
      claims.aud !== `product:${options.product}` ||
      claims.inst !== options.installation ||
      claims.cnf?.jkt !== options.thumb
    )
      throw new Error('Lease binding mismatch');
    if (claims.exp <= claims.iat || claims.nbf > claims.exp) throw new Error('Invalid lease times');
    const now = options.now ?? Date.now();
    const nowS = Math.floor(now / 1000);
    const last = options.lastSeen ?? 0;
    const state =
      now < last - 300000 || nowS < claims.nbf - 300
        ? 'clock_anomaly'
        : nowS > claims.exp + 300
          ? 'expired'
          : nowS >= claims.refresh_after
            ? 'refresh_recommended'
            : 'valid';
    return {
      state,
      claims,
      lastSeen: Math.max(now, last),
      entitlements: ['valid', 'refresh_recommended'].includes(state) ? claims.ent : {},
      capabilities: ['valid', 'refresh_recommended'].includes(state) ? claims.cap : [],
    };
  } catch (e) {
    return { state: 'invalid', reason: e.message, entitlements: {}, capabilities: [] };
  }
}
async function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('trust-device-demo', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('device');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Browser device storage unavailable'));
  });
}
async function read() {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('device');
      const request = tx.objectStore('device').get('identity');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}
async function write(value) {
  const db = await database();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('device', 'readwrite');
      tx.objectStore('device').put(value, 'identity');
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
// Serialize all demo state changes across tabs so stale reads cannot restore a deactivated lease.
let queue = Promise.resolve();
function exclusively(action) {
  if (typeof navigator !== 'undefined' && navigator.locks)
    return navigator.locks.request('trust-device-demo', action);
  const pending = queue.then(action, action);
  queue = pending.catch(() => undefined);
  return pending;
}
export class BrowserDevice {
  async identity() {
    let identity = await read();
    if (!identity) {
      const pair = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
      const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
      const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
      identity = {
        privateKey: pair.privateKey,
        jwk: pub,
        thumb: await thumbprint(pub),
        installation: `inst_${crypto.randomUUID()}`,
        lease: null,
        activation: null,
        trust: null,
        product: null,
        lastSeen: 0,
      };
      await write(identity);
    }
    return identity;
  }
  async #summary() {
    const d = await this.identity();
    return {
      installation_id: d.installation,
      key_storage: 'Non-extractable WebCrypto key in this browser',
      activation_id: d.activation || 'Not activated',
      product: d.product || '—',
    };
  }
  async proof(purpose, d, api) {
    const subject = purpose === 'activate' ? '' : d.activation;
    const ch = await api('/v1/devices/challenges', 'POST', {
      purpose,
      installation_id: d.installation,
      ...(subject ? { subject_id: subject } : {}),
    });
    const signature = b64(
      await crypto.subtle.sign(
        'Ed25519',
        d.privateKey,
        encoder.encode(proofMessage(purpose, ch.nonce, d.installation, subject, d.thumb)),
      ),
    );
    return { installation_id: d.installation, nonce: ch.nonce, signature };
  }
  async accept(grant, d) {
    const check = await checkOffline(grant.lease, {
      trust: d.trust,
      product: d.product,
      installation: d.installation,
      thumb: d.thumb,
      lastSeen: d.lastSeen,
    });
    if (!['valid', 'refresh_recommended'].includes(check.state))
      throw new Error(`Lease rejected: ${check.state}`);
    d.lease = grant.lease;
    d.activation = grant.activation_id;
    d.lastSeen = check.lastSeen;
    await write(d);
    return { state: check.state, activation_id: d.activation, entitlements: check.entitlements };
  }
  async #activate(licenseKey, product, api) {
    const d = await this.identity();
    if (d.activation)
      throw new Error(
        'Deactivate the current demo installation before activating another license.',
      );
    d.product = product;
    d.trust = await api('/v1/keys/trust-bundle');
    const proof = await this.proof('activate', d, api);
    const grant = await api('/v1/licenses/activate', 'POST', {
      ...proof,
      license_key: licenseKey,
      device_public_key: d.jwk,
    });
    return this.accept(grant, d);
  }
  async #call(purpose, api) {
    const d = await this.identity();
    if (!d.activation) throw new Error('Activate this browser first.');
    const proof = await this.proof(purpose, d, api);
    const result = await api(`/v1/licenses/${purpose}`, 'POST', {
      ...proof,
      activation_id: d.activation,
    });
    if (purpose === 'refresh') return this.accept(result, d);
    if (purpose === 'deactivate') {
      d.activation = null;
      d.lease = null;
      await write(d);
    }
    return result;
  }
  async #offline() {
    const d = await this.identity();
    if (!d.lease) throw new Error('No cached lease. Activate this browser first.');
    const result = await checkOffline(d.lease, {
      trust: d.trust,
      product: d.product,
      installation: d.installation,
      thumb: d.thumb,
      lastSeen: d.lastSeen,
    });
    if (result.lastSeen) {
      d.lastSeen = result.lastSeen;
      await write(d);
    }
    return {
      state: result.state,
      reason: result.reason,
      entitlements: result.entitlements,
      capabilities: result.capabilities,
    };
  }
  summary() {
    return exclusively(() => this.#summary());
  }
  activate(licenseKey, product, api) {
    return exclusively(() => this.#activate(licenseKey, product, api));
  }
  call(purpose, api) {
    return exclusively(() => this.#call(purpose, api));
  }
  offline() {
    return exclusively(() => this.#offline());
  }
}
