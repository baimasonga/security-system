import { afterEach, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright-core';
import { makeEnv, PW, type Env } from '../../services/platform-api/test/harness.ts';

let env: Env;
let browser: Browser;
afterEach(async () => {
  await browser?.close();
  await env?.app.close();
});
it('shows live operator evidence, handles unavailable data and preserves existing actions', async () => {
  env = await makeEnv();
  await env.operatorToken();
  const address = await env.app.listen({ host: '127.0.0.1', port: 0 });
  browser = await chromium.launch({
    executablePath: process.env['CHROMIUM_PATH'],
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(address);
  await page.getByLabel('Email', { exact: true }).fill('operator@example.test');
  await page.getByLabel('Password', { exact: true }).fill(PW);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Operator console', exact: true }).click();
  await page.getByRole('heading', { name: 'Operations overview', exact: true }).waitFor();
  expect(await page.getByText('Not configured', { exact: true }).count()).toBe(1);
  expect(await page.getByText('No publication recorded', { exact: true }).count()).toBe(1);
  await page.getByRole('button', { name: 'Check audit integrity', exact: true }).click();
  await page.getByText('Audit chains are internally consistent.', { exact: false }).waitFor();
  expect(
    await page.getByRole('link', { name: 'Open IT incident brief in GitHub' }).getAttribute('href'),
  ).toBe('https://github.com/baimasonga/security-system/actions/workflows/it-incident-brief.yml');
  await page.route('**/v1/admin/audit/anchors?limit=10', (route) =>
    route.fulfill({ status: 503, contentType: 'application/json', body: '{}' }),
  );
  await page.getByRole('button', { name: 'Refresh audit status' }).click();
  await page.getByText('Audit status unavailable.', { exact: false }).waitFor();
  expect(await page.getByText('Not configured', { exact: true }).count()).toBe(0);
  await page.unroute('**/v1/admin/audit/anchors?limit=10');
  await page.route('**/v1/admin/audit/anchors?limit=10', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        configured: true,
        items: [
          { created_at: '2026-10-25T12:00:00.000Z', status: 'failed', chains: 2, events: 10 },
        ],
      }),
    }),
  );
  await page.getByRole('button', { name: 'Refresh audit status' }).click();
  await page.getByText('Configured', { exact: true }).waitFor();
  expect(await page.getByRole('cell', { name: 'failed', exact: true }).count()).toBe(1);
  await page.route('**/v1/admin/audit/verify', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":false}' }),
  );
  await page.getByRole('button', { name: 'Check audit integrity', exact: true }).click();
  await page.getByText('Audit integrity check failed.', { exact: false }).waitFor();
  await page.getByLabel('Operator action').selectOption({ label: 'Mobile app downloads' });
  await page.route('**/v1/admin/mobile-distribution', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 'available',
        downloads: 17,
        asset_id: 123,
        created_at: '2026-10-25T00:00:00Z',
        updated_at: '2026-10-25T00:00:00Z',
        checked_at: '2026-10-25T00:00:00Z',
      }),
    }),
  );
  await page.getByRole('button', { name: 'Refresh APK downloads' }).click();
  await page.getByRole('cell', { name: '17', exact: true }).waitFor();
  expect(
    await page
      .getByText('Website downloads served from Cloudflare’s cache', { exact: false })
      .isVisible(),
  ).toBe(true);
  expect(
    await page.getByText('GitHub downloads do not report app usage.', { exact: false }).isVisible(),
  ).toBe(true);
  await page.unroute('**/v1/admin/mobile-distribution');
  await page.route('**/v1/admin/mobile-distribution', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: '{"status":"unavailable"}',
    }),
  );
  await page.getByRole('button', { name: 'Refresh APK downloads' }).click();
  await page.getByText('Download evidence unavailable.', { exact: false }).waitFor();
  expect(await page.getByRole('cell', { name: '17', exact: true }).count()).toBe(0);
  await page.getByLabel('Operator action').selectOption({ label: 'Mobile app usage' });
  await page.getByRole('button', { name: 'Refresh mobile usage' }).click();
  await page.getByRole('cell', { name: 'No app reports received', exact: true }).waitFor();
  expect(await page.getByText('Not configured; country is unknown', { exact: true }).count()).toBe(
    1,
  );
  await page.getByLabel('Operator action').selectOption({ label: 'Create product' });
  await page.getByRole('heading', { name: 'Create product', exact: true }).waitFor();
  expect(await page.getByRole('heading', { name: 'Operations overview' }).isVisible()).toBe(false);
}, 30000);
