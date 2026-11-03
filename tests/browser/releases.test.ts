import { afterEach, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright-core';
import { randomUUID } from 'node:crypto';
import { KeyRing, signJws } from '@trust/crypto';
import { makeEnv, PW, type Env } from '../../services/platform-api/test/harness.ts';
let env: Env;
let browser: Browser;
afterEach(async () => {
  await browser?.close();
  await env?.app.close();
});
async function setup(enabled = true, operator = true) {
  env = await makeEnv({ config: { updateCatalogEnabled: enabled } });
  const owner = await env.register('release-customer@example.test');
  const { productId } = await env.provision(owner.orgId);
  const token = await env.operatorToken();
  const ring = new KeyRing();
  const rootKey = ring.generate('license');
  const releaseKey = ring.generate('license');
  ring.activate(releaseKey.kid);
  const now = Math.floor(env.clock.now().getTime() / 1000);
  const root = {
    schema: 1,
    version: 1,
    expires: now + 3600,
    root: { threshold: 1, keys: [{ kid: rootKey.kid, jwk: rootKey.publicJwk }] },
    release: { threshold: 1, keys: [{ kid: releaseKey.kid, jwk: releaseKey.publicJwk }] },
    artifact_origins: ['https://updates.example'],
  };
  const path = `/v1/admin/products/${productId}/update-registry`;
  if (enabled) {
    expect(
      (await env.call('POST', path, { token, body: { root, reason: 'Public test authority' } }))
        .status,
    ).toBe(201);
    expect(
      (
        await env.call('POST', path + '/targets', {
          token,
          body: { platform: 'windows-x64', channel: 'stable', reason: 'Test target' },
        })
      ).status,
    ).toBe(201);
  }
  const address = await env.app.listen({ host: '127.0.0.1', port: 0 });
  browser = await chromium.launch({
    executablePath: process.env['CHROMIUM_PATH'] || undefined,
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  await page.goto(address);
  await page
    .getByLabel('Email', { exact: true })
    .fill(operator ? 'operator@example.test' : 'release-customer@example.test');
  await page.getByLabel('Password', { exact: true }).fill(PW);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Account', exact: true }).waitFor();
  if (operator) {
    await page.getByRole('button', { name: 'Operator console', exact: true }).click();
    await page.getByLabel('Operator action').selectOption({ label: 'Product releases' });
  }
  const card = page
    .locator('section.panel')
    .filter({ has: page.getByRole('heading', { name: 'Product releases', exact: true }) });
  const select = async (operation: string) => {
    await card.getByLabel('Release operation', { exact: true }).selectOption({ label: operation });
    const form = card.locator('form:visible');
    await form.getByLabel('Release product ID', { exact: true }).fill(productId);
    return form;
  };
  page.on('dialog', (dialog) => void dialog.accept());
  return { page, card, select, productId, token, path, ring, releaseKey, now };
}
it('retains reservation inputs after an uncertain response and publishes a verified pause with history and current feed', async () => {
  const f = await setup();
  let form = await f.select('Read update registry');
  await form.getByRole('button', { name: 'Read update registry', exact: true }).click();
  await f.card.getByRole('cell', { name: 'windows-x64', exact: true }).waitFor();
  form = await f.select('Reserve release sequence');
  const uuid = randomUUID();
  await form.getByLabel('Reservation request UUID', { exact: true }).fill(uuid);
  await form.getByLabel('Release change reason', { exact: true }).fill('Publish approved pause');
  let lost = false;
  await f.page.route('**/update-registry/reservations', async (route) => {
    const result = await route.fetch();
    if (!lost) {
      lost = true;
      await route.abort();
    } else await route.fulfill({ response: result });
  });
  await form.getByRole('button', { name: 'Reserve release sequence', exact: true }).click();
  await f.page.locator('#notice.error').waitFor();
  expect(await form.getByLabel('Reservation request UUID', { exact: true }).inputValue()).toBe(
    uuid,
  );
  expect(await form.getByLabel('Release change reason', { exact: true }).inputValue()).toBe(
    'Publish approved pause',
  );
  await form.getByRole('button', { name: 'Reserve release sequence', exact: true }).click();
  await f.card.locator('pre').waitFor();
  const reservation = JSON.parse((await f.card.locator('pre').textContent())!);
  expect(reservation.sequence).toBe(1);
  expect((await env.c.updateRegistry.read(f.productId)).targets[0]!.reservedSequence).toBe(1);
  const manifest = {
    schema: 1,
    product: 'pdf-pro',
    platform: 'windows-x64',
    channel: 'stable',
    sequence: 1,
    version: '1.0',
    minimum_sequence: 0,
    issued_at: f.now,
    expires: f.now + 300,
    paused: true,
    artifact: {
      url: 'https://updates.example/setup.exe',
      size: 10,
      sha256: 'a'.repeat(64),
      sbom_sha256: 'b'.repeat(64),
      provenance_sha256: 'c'.repeat(64),
    },
  };
  const envelope = {
    signatures: [
      await signJws(
        manifest,
        { kid: f.releaseKey.kid, typ: 'trust-update-manifest+jws' },
        f.ring.custody,
      ),
    ],
  };
  form = await f.select('Publish signed release or pause');
  await form.getByLabel('Reservation request UUID', { exact: true }).fill(uuid);
  await form
    .getByLabel('Externally signed envelope (JSON)', { exact: true })
    .fill(JSON.stringify({ signatures: ['invalid'] }));
  await form.getByLabel('Release change reason', { exact: true }).fill('Approved withdrawal');
  await form.getByRole('button', { name: 'Publish signed release or pause', exact: true }).click();
  await f.page.locator('#notice.error').waitFor();
  expect(
    (
      await env.c.updateRegistry.history(f.productId, {
        platform: 'windows-x64',
        channel: 'stable',
        limit: 20,
      })
    ).length,
  ).toBe(0);
  await form
    .getByLabel('Externally signed envelope (JSON)', { exact: true })
    .fill(JSON.stringify(envelope));
  await form.getByRole('button', { name: 'Publish signed release or pause', exact: true }).click();
  await f.card.getByRole('heading', { name: 'Signed pause recorded', exact: true }).waitFor();
  form = await f.select('Read release history');
  await form.getByRole('button', { name: 'Read release history', exact: true }).click();
  await f.card.getByRole('cell', { name: 'Paused', exact: true }).waitFor();
  await f.page.route('**/update-registry/releases?**', (route) =>
    route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'History unavailable' }),
    }),
  );
  await form.getByRole('button', { name: 'Read release history', exact: true }).click();
  await f.page.locator('#notice.error').waitFor();
  expect(await f.card.getByRole('table').count()).toBe(0);
  await f.page.unroute('**/update-registry/releases?**');
  let authorization: string | undefined;
  f.page.on('request', (request) => {
    if (request.url().includes('/current?')) authorization = request.headers()['authorization'];
  });
  form = await f.select('Read current signed feed');
  await form.getByRole('button', { name: 'Read current signed feed', exact: true }).click();
  await f.card.locator('pre').waitFor();
  expect(JSON.parse((await f.card.locator('pre').textContent())!)).toEqual(envelope);
  expect(authorization).toBeUndefined();
  env.clock.advance(301000);
  await form.getByRole('button', { name: 'Read current signed feed', exact: true }).click();
  await f.card.getByText('No current feed established.', { exact: false }).waitFor();
  await f.page.setViewportSize({ width: 390, height: 844 });
  expect(await f.page.evaluate('document.documentElement.scrollWidth <= innerWidth')).toBe(true);
});
it('leaves a disabled registry unavailable without inventing a publication status', async () => {
  const f = await setup(false);
  const form = await f.select('Read update registry');
  await form.getByRole('button', { name: 'Read update registry', exact: true }).click();
  await f.page.locator('#notice.error').waitFor();
  expect(
    await f.card.getByRole('heading', { name: 'Registered update targets', exact: false }).count(),
  ).toBe(0);
});
it('does not offer release administration to a customer', async () => {
  const { page } = await setup(true, false);
  expect(await page.getByRole('button', { name: 'Operator console', exact: true }).count()).toBe(0);
  expect(await page.getByLabel('Release operation', { exact: true }).count()).toBe(0);
});
