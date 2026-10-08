import { spawn, type ChildProcess } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import pg from 'pg';
import { buildProofMessage } from '@trust/crypto/verify';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { loadConfig } from '../../services/platform-api/src/config.ts';
import { createContainer } from '../../services/platform-api/src/container.ts';
import { MIGRATIONS_DIR, applyMigrations } from '../../services/platform-api/src/db/migrate.ts';
import { Http, sleep, type OpResult, type Requester } from './lib.ts';

export const SIGNING_PEM = generateKeyPairSync('ed25519')
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();
export const PEPPER = 'loadtest-pepper-'.padEnd(48, 'p');
export const PSEUDONYM = 'loadtest-pseudonym-'.padEnd(48, 'q');

export interface SeedUser {
  token: string;
  orgId: string;
  licenseKey: string;
  licenseId: string;
}
export interface World {
  dbUrl: string;
  operatorToken: string;
  users: SeedUser[];
  productId: string;
  planId: string;
}

export async function migrate(dbUrl: string) {
  const c = new pg.Client({ connectionString: dbUrl });
  await c.connect();
  try {
    await applyMigrations(c, MIGRATIONS_DIR);
  } finally {
    await c.end();
  }
}

const baseEnv = (dbUrl: string): NodeJS.ProcessEnv => ({
  NODE_ENV: 'development',
  PERSISTENCE: 'postgres',
  DATABASE_URL: dbUrl,
  LICENSE_KEY_PEPPER: PEPPER,
  PSEUDONYM_KEY: PSEUDONYM,
  LICENSE_SIGNING_KEY_PEM: SIGNING_PEM,
});

/** Seeds users/orgs/subscriptions/licenses through the real services (fast scrypt: seeding only). */
export async function seedWorld(
  dbUrl: string,
  o: {
    users: number;
    deviceLimit: number;
    concurrency?: number;
    extraOrgs?: Array<{ name: string; deviceLimit: number }>;
  },
): Promise<World & { extras: Record<string, SeedUser> }> {
  await migrate(dbUrl);
  const c = await createContainer({
    ...loadConfig({ ...baseEnv(dbUrl), PORT: '0' } as NodeJS.ProcessEnv),
    scrypt: { N: 1024, r: 8, p: 1 },
  });
  const PW = 'load-test-password-1';
  try {
    await c.auth.register({ email: 'operator@load.test', password: PW });
    await c.auth.bootstrapPlatformAdmin('operator@load.test');
    const operatorToken = (await c.auth.login({ email: 'operator@load.test', password: PW })).token;
    const op = { id: 'seed', reason: 'load test seeding' };
    const product = await c.licensing.createProduct({ code: 'load-product', name: 'Load' }, op);
    const mkPlan = (code: string, limit: number) =>
      c.licensing.createPlan(
        {
          productId: product.id,
          code,
          tier: 'professional',
          entitlements: { pdf_editing: true },
          capabilities: ['OCR_ADVANCED'],
          deviceLimit: limit,
        },
        op,
      );
    const plan = await mkPlan('load-plan', o.deviceLimit);

    const makeUser = async (email: string, p: { id: string }): Promise<SeedUser> => {
      const { personalOrg } = await c.auth.register({ email, password: PW });
      const sub = await c.licensing.createSubscription(
        {
          orgId: personalOrg.id,
          planId: p.id,
          status: 'active',
          currentPeriodEnd: new Date(Date.now() + 365 * 86400_000),
        },
        op,
      );
      const { license, licenseKey } = await c.licensing.issueLicense(
        {
          orgId: personalOrg.id,
          productId: product.id,
          planId: p.id,
          kind: 'subscription',
          subscriptionId: sub.id,
        },
        op,
      );
      const token = (await c.auth.login({ email, password: PW })).token;
      return { token, orgId: personalOrg.id, licenseKey, licenseId: license.id };
    };

    const users: SeedUser[] = new Array(o.users);
    let next = 0;
    await Promise.all(
      Array.from({ length: o.concurrency ?? 12 }, async () => {
        for (;;) {
          const i = next++;
          if (i >= o.users) return;
          users[i] = await makeUser(`user${i}@load.test`, plan);
        }
      }),
    );
    const extras: Record<string, SeedUser> = {};
    for (const e of o.extraOrgs ?? [])
      extras[e.name] = await makeUser(
        `${e.name}@load.test`,
        await mkPlan(`plan-${e.name}`, e.deviceLimit),
      );
    return { dbUrl, operatorToken, users, productId: product.id, planId: plan.id, extras };
  } finally {
    await c.close();
  }
}

export interface Server {
  pid: number;
  base: string;
  stop(): Promise<void>;
}

export async function startServer(
  dbUrl: string,
  o: { port: number; pool: number; logLevel?: string; extraEnv?: Record<string, string> },
): Promise<Server> {
  const big = '10000000';
  const child: ChildProcess = spawn('node', ['services/platform-api/src/main.ts'], {
    // LT_DEBUG=1 shows the server's structured log (otherwise discarded to keep the measurement quiet).
    stdio: ['ignore', process.env['LT_DEBUG'] ? 'inherit' : 'ignore', 'inherit'],
    env: {
      ...process.env,
      ...baseEnv(dbUrl),
      PORT: String(o.port),
      HOST: '127.0.0.1',
      DB_POOL_MAX: String(o.pool),
      LOG_LEVEL: o.logLevel ?? 'info',
      RATE_LIMIT_GLOBAL: big,
      RATE_LIMIT_LOGIN: big,
      RATE_LIMIT_REGISTER: big,
      RATE_LIMIT_CHALLENGE: big,
      RATE_LIMIT_ACTIVATE: big,
      ...o.extraEnv, // explicit overrides win over the tool's defaults
    },
  });
  const base = `http://127.0.0.1:${o.port}`;
  const probe = new Http(base, 1);
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('server exited during start-up');
    try {
      if ((await probe.request('GET', '/healthz')).status === 200) break;
    } catch {
      /* not up yet */
    }
    await sleep(100);
  }
  probe.destroy();
  return {
    pid: child.pid!,
    base,
    async stop() {
      child.kill('SIGTERM');
      await new Promise((r) => child.once('exit', r));
    },
  };
}

// ---- virtual devices ---------------------------------------------------------------------------
export class VDev {
  readonly key = SoftwareDeviceKey.generate();
  readonly inst = `inst_${randomBytes(18).toString('base64url')}`;
  activationId: string | undefined;
  user: SeedUser;
  constructor(user: SeedUser) {
    this.user = user;
  }

  async #challenge(
    h: Requester,
    purpose: 'activate' | 'validate' | 'refresh' | 'deactivate',
    subject: string,
  ) {
    const r = await h.request('POST', '/v1/devices/challenges', {
      purpose,
      installation_id: this.inst,
      ...(subject ? { subject_id: subject } : {}),
    });
    if (r.status !== 201) throw Object.assign(new Error('challenge'), { result: r });
    return r.body.nonce as string;
  }
  #sign(
    purpose: 'activate' | 'validate' | 'refresh' | 'deactivate',
    nonce: string,
    subject: string,
  ) {
    return this.key.sign(
      buildProofMessage({
        purpose,
        nonce,
        installationId: this.inst,
        subjectId: subject,
        thumbprint: this.key.thumbprint,
      }),
    );
  }
  static classify(r: { status: number; body: any }): OpResult {
    return r.status === 200
      ? { ok: true, code: 'ok' }
      : { ok: false, code: String(r.body?.code ?? `http_${r.status}`) };
  }

  async activate(h: Requester): Promise<OpResult> {
    const nonce = await this.#challenge(h, 'activate', '');
    const r = await h.request(
      'POST',
      '/v1/licenses/activate',
      {
        license_key: this.user.licenseKey,
        installation_id: this.inst,
        device_public_key: this.key.publicJwk,
        nonce,
        signature: this.#sign('activate', nonce, ''),
      },
      this.user.token,
    );
    if (r.status === 200) this.activationId = r.body.activation_id;
    return VDev.classify(r);
  }
  async deviceCall(h: Requester, purpose: 'refresh' | 'validate'): Promise<OpResult> {
    const act = this.activationId!;
    const nonce = await this.#challenge(h, purpose, act);
    return VDev.classify(
      await h.request('POST', `/v1/licenses/${purpose}`, {
        activation_id: act,
        installation_id: this.inst,
        nonce,
        signature: this.#sign(purpose, nonce, act),
      }),
    );
  }
}
