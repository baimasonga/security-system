import { afterEach, expect, it } from 'vitest';
import { chromium, type Browser, type Page } from 'playwright-core';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { SoftwareDeviceKey } from '@trust/sdk-core';
import { buildProofMessage } from '@trust/crypto/verify';
import { totpCode } from '../../packages/auth/src/mfa.ts';
import { MemoryMailDelivery } from '../../services/platform-api/src/integrations/mail.ts';
import { makeEnv, PW, type Env } from '../../services/platform-api/test/harness.ts';

let env: Env;
let browser: Browser;
afterEach(async () => {
  await browser?.close();
  await env?.app.close();
});
const section = (page: Page, name: string) =>
  page.locator('section.panel').filter({ has: page.getByRole('heading', { name, exact: true }) });
async function login(page: Page, code?: string) {
  await page.getByLabel('Email', { exact: true }).fill('center@example.test');
  await page.getByLabel('Password', { exact: true }).fill(PW);
  if (code) await page.getByLabel('Authenticator or recovery code (if enabled)').fill(code);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Security center', exact: true }).click();
  await page.getByRole('heading', { name: 'Your account', exact: true }).waitFor();
}
async function setup(passkeys = false) {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
  const mail = new MemoryMailDelivery();
  env = await makeEnv({
    identityDelivery: mail,
    config: {
      mfaEncryptionKey: randomBytes(32).toString('hex'),
      operationsInventoryEnabled: true,
      ...(passkeys
        ? {
            webauthn: {
              rpId: 'localhost',
              origin: `http://localhost:${port}`,
              rpName: 'Security test',
            },
          }
        : {}),
    },
  });
  env.clock.set(new Date());
  const owner = await env.register('center@example.test');
  await env.app.listen({ host: '127.0.0.1', port });
  browser = await chromium.launch({
    executablePath: process.env['CHROMIUM_PATH'],
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(`http://localhost:${port}`);
  await login(page);
  return { page, mail, owner };
}
function decode(text: string) {
  let value = 0,
    bits = 0;
  const bytes: number[] = [];
  for (const c of text) {
    value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }
  return Buffer.from(bytes);
}
it('enables and disables real authenticator protection and sends verification from Security center', async () => {
  const { page, mail, owner } = await setup();
  await section(page, 'Your account')
    .getByRole('button', { name: 'Send verification email', exact: true })
    .click();
  await env.c.auth.flushIdentityMail();
  expect(mail.messages).toHaveLength(1);
  expect(mail.messages[0]!.to).toBe('center@example.test');
  expect(await section(page, 'Passkeys').textContent()).toContain('not available');
  expect(
    await section(page, 'Passkeys').getByRole('button', { name: 'Add a passkey' }).count(),
  ).toBe(0);
  const mfa = section(page, 'Authenticator protection');
  await mfa.getByLabel('Current password', { exact: true }).fill(PW);
  await mfa.getByRole('button', { name: 'Set up authenticator', exact: true }).click();
  const setupKey = page.getByLabel('Authenticator setup key');
  await setupKey.waitFor();
  const secret = await setupKey.inputValue();
  const key = decode(secret);
  const factor = () => totpCode(key, Math.floor(+env.clock.now() / 30000));
  const confirmation = section(page, 'Confirm your authenticator');
  await confirmation.getByLabel('Current password', { exact: true }).fill(PW);
  await confirmation.getByLabel('Six-digit authenticator code', { exact: true }).fill(factor());
  await confirmation.getByRole('button', { name: 'Enable authenticator', exact: true }).click();
  await page.getByLabel('One-time recovery codes').waitFor();
  expect((await env.call('GET', '/v1/auth/me', { token: owner.token })).status).toBe(401);
  expect(
    await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage)),
  ).not.toContain(secret);
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  env.clock.advance(30000);
  await login(page, factor());
  const enabled = section(page, 'Authenticator protection');
  await enabled.getByLabel('Current password', { exact: true }).fill(PW);
  env.clock.advance(30000);
  await enabled.getByLabel('Authenticator or recovery code', { exact: true }).fill(factor());
  await enabled.getByLabel('Reason for disabling', { exact: true }).fill('Replace authenticator');
  await enabled.getByRole('button', { name: 'Disable authenticator', exact: true }).click();
  await page.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
  const token = await env.login('center@example.test');
  expect((await env.call('GET', '/v1/auth/me', { token })).body.mfa_enabled).toBe(false);
});
it('registers and removes a real WebAuthn passkey without leaving Security center', async () => {
  const { page, owner } = await setup(true);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const keys = section(page, 'Passkeys');
  await keys.getByLabel('Name for this passkey (for example "Work laptop")').fill('Test laptop');
  await keys.getByLabel('Current password', { exact: true }).fill(PW);
  await keys.getByRole('button', { name: 'Add a passkey', exact: true }).click();
  await section(page, 'Passkeys').getByRole('cell', { name: 'Test laptop', exact: true }).waitFor();
  expect(await page.getByRole('heading', { name: 'Security center', exact: true }).count()).toBe(1);
  expect(
    (await env.call('GET', '/v1/auth/passkeys', { token: owner.token })).body.items,
  ).toHaveLength(1);
  page.once('dialog', (dialog) => dialog.accept(PW));
  await section(page, 'Passkeys').getByRole('button', { name: 'Remove', exact: true }).click();
  await section(page, 'Passkeys').getByText('No passkeys yet.', { exact: true }).waitFor();
  expect(
    (await env.call('GET', '/v1/auth/passkeys', { token: owner.token })).body.items,
  ).toHaveLength(0);
});
it('deactivates only the displayed own device after confirmation and opens the correct monitoring workspace', async () => {
  const { page, owner } = await setup();
  const team = await env.call('POST', '/v1/organizations', {
    token: owner.token,
    body: { name: 'Monitoring team' },
  });
  const other = await env.register('member-host@example.test');
  const otherPrincipal = await env.c.auth.authenticate(other.token);
  const memberTeam = await env.c.auth.createOrganization(otherPrincipal, 'Member workspace');
  await env.c.auth.addMember(otherPrincipal, memberTeam.id, 'center@example.test', 'member');
  const lic = await env.provision(team.body.id);
  const device = SoftwareDeviceKey.generate();
  const installationId = 'inst_securitycenteraction';
  const challenge = await env.call('POST', '/v1/devices/challenges', {
    body: { purpose: 'activate', installation_id: installationId },
  });
  const activation = await env.call('POST', '/v1/licenses/activate', {
    token: owner.token,
    body: {
      license_key: lic.licenseKey,
      installation_id: installationId,
      device_public_key: device.publicJwk,
      nonce: challenge.body.nonce,
      signature: device.sign(
        buildProofMessage({
          purpose: 'activate',
          nonce: challenge.body.nonce,
          installationId,
          subjectId: '',
          thumbprint: device.thumbprint,
        }),
      ),
    },
  });
  expect(activation.status).toBe(200);
  // Refresh the membership list through a new browser sign-in.
  await page.getByRole('button', { name: 'Sign out', exact: true }).first().click();
  await login(page);
  await section(page, 'Member workspace — member')
    .getByRole('heading', { name: 'Member workspace — member', exact: true })
    .waitFor();
  expect(
    await section(page, 'Member workspace — member')
      .getByRole('button', { name: 'Manage application monitoring', exact: true })
      .count(),
  ).toBe(0);
  const devices = section(page, 'Your devices');
  await devices.getByRole('cell', { name: activation.body.device_id, exact: true }).waitFor();
  page.once('dialog', (dialog) => dialog.dismiss());
  await devices.getByRole('button', { name: 'Deactivate device', exact: true }).click();
  expect(
    (await env.call('GET', '/v1/security-center', { token: owner.token })).body.devices,
  ).toHaveLength(1);
  page.once('dialog', (dialog) => {
    expect(dialog.message()).toContain('offline');
    return dialog.accept();
  });
  await devices.getByRole('button', { name: 'Deactivate device', exact: true }).click();
  await section(page, 'Your devices')
    .getByText('You have not activated any devices.', { exact: true })
    .waitFor();
  expect(
    (await env.call('GET', '/v1/security-center', { token: owner.token })).body.devices,
  ).toHaveLength(0);
  const org = section(page, 'Monitoring team — owner');
  await org.getByRole('button', { name: 'Manage application monitoring', exact: true }).click();
  await page.getByRole('heading', { name: 'Register application', exact: true }).waitFor();
  expect(await page.getByLabel('Current organization').inputValue()).toBe(team.body.id);
});

it('does not show late recovery codes after leaving the security view', async () => {
  const { page } = await setup();
  const mfa = section(page, 'Authenticator protection');
  await mfa.getByLabel('Current password', { exact: true }).fill(PW);
  await mfa.getByRole('button', { name: 'Set up authenticator', exact: true }).click();
  const secret = page.getByLabel('Authenticator setup key');
  await secret.waitFor();
  const key = decode(await secret.inputValue());
  const confirmation = section(page, 'Confirm your authenticator');
  await confirmation.getByLabel('Current password', { exact: true }).fill(PW);
  await confirmation
    .getByLabel('Six-digit authenticator code', { exact: true })
    .fill(totpCode(key, Math.floor(+env.clock.now() / 30000)));
  let release!: () => void;
  let committed!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const commit = new Promise<void>((resolve) => {
    committed = resolve;
  });
  await page.route('**/v1/auth/mfa/confirm', async (route) => {
    const response = await route.fetch();
    committed();
    await gate;
    await route.fulfill({ response });
  });
  await confirmation.getByRole('button', { name: 'Enable authenticator', exact: true }).click();
  await commit;
  // Enrollment invalidated this session. Navigating now returns to sign-in.
  await page.getByRole('button', { name: 'Licenses', exact: true }).click();
  await page.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
  const finished = page.waitForResponse((r) => r.url().endsWith('/v1/auth/mfa/confirm'));
  release();
  await finished;
  await expect.poll(() => page.getByLabel('One-time recovery codes').count()).toBe(0);
  expect(await page.locator('dialog[open]').count()).toBe(0);
});
