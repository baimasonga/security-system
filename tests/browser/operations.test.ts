import { afterEach, expect, it } from 'vitest';
import { chromium, type Browser, type Page } from 'playwright-core';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { makeEnv, PW, type Env } from '../../services/platform-api/test/harness.ts';
import { totpCode } from '../../packages/auth/src/mfa.ts';

let env: Env;
let browser: Browser;
afterEach(async () => {
  await browser?.close();
  await env?.app.close();
});
const decode = (text: string) => {
  let value = 0,
    bits = 0;
  const bytes = [];
  for (const c of text) {
    value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }
  return Buffer.from(bytes);
};
async function setup() {
  env = await makeEnv({
    config: {
      operationsInventoryEnabled: true,
      operationsIncidentsEnabled: true,
      operationsHealthEnabled: true,
      operationsIngestionEnabled: true,
      operationsAutomationEnabled: true,
      operationsPostureEnabled: true,
      operationsCredentialsEnabled: true,
      mfaEncryptionKey: randomBytes(32).toString('hex'),
      sharing: undefined,
    },
  });
  env.clock.set(new Date());
  const owner = await env.register('portal-owner@example.test');
  const other = await env.register('portal-other@example.test');
  const team = await env.call('POST', '/v1/organizations', {
    token: owner.token,
    body: { name: 'Portal team' },
  });
  expect(team.status).toBe(201);
  owner.orgId = team.body.id;
  const membership = await env.call('POST', `/v1/organizations/${owner.orgId}/members`, {
    token: owner.token,
    body: { email: 'portal-other@example.test', role: 'member' },
  });
  expect(membership.status).toBe(201);
  const started = await env.call('POST', '/v1/auth/mfa/begin', {
    token: owner.token,
    body: { password: PW },
  });
  expect(started.status).toBe(200);
  const key = decode(started.body.setup_key);
  const factor = () => totpCode(key, Math.floor(env.clock.now().getTime() / 30000));
  expect(
    (
      await env.call('POST', '/v1/auth/mfa/confirm', {
        token: owner.token,
        body: { password: PW, code: factor() },
      })
    ).status,
  ).toBe(200);
  const next = () => {
    env.clock.advance(30000);
    return factor();
  };
  const address = await env.app.listen({ host: '127.0.0.1', port: 0 });
  browser = await chromium.launch({
    ...(process.env['CHROMIUM_PATH'] ? { executablePath: process.env['CHROMIUM_PATH'] } : {}),
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(address);
  await page.getByLabel('Email', { exact: true }).fill('portal-owner@example.test');
  await page.getByLabel('Password', { exact: true }).fill(PW);
  await page.getByLabel('Authenticator or recovery code (if enabled)').fill(next());
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Current organization').selectOption(owner.orgId);
  await page.getByRole('button', { name: 'Applications', exact: true }).click();
  await page.getByRole('heading', { name: 'Register application', exact: true }).waitFor();
  const live = await env.call('POST', '/v1/auth/login', {
    body: { email: 'portal-owner@example.test', password: PW, code: next() },
  });
  expect(live.status).toBe(200);
  owner.token = live.body.token;
  return { page, next, owner, other, address };
}
const section = (p: Page, heading: string) =>
  p.locator('section').filter({ has: p.getByRole('heading', { name: heading, exact: true }) });
async function registerApp(page: Page, name: string) {
  const s = section(page, 'Register application');
  await s.getByLabel('Code (permanent)').fill(name);
  await s.getByRole('button', { name: 'Register application', exact: true }).click();
  const row = page.getByRole('row').filter({ has: page.getByRole('cell', { name, exact: true }) });
  // This action changes SPA content, not the document URL; explicitly await its destination below.
  await row.getByRole('button', { name: 'Open', exact: true }).click({ noWaitAfter: true });
  await page.getByRole('heading', { name: 'Environments', exact: true }).waitFor();
}
async function addEnv(page: Page) {
  const s = section(page, 'Add environment');
  await s.getByLabel('Code (permanent)').fill('production');
  await s.getByLabel('Environment kind').selectOption('production');
  await s.getByRole('button', { name: 'Add environment', exact: true }).click();
  await page
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'production', exact: true }).first() })
    .getByRole('button', { name: 'Open' })
    .click();
  await page.getByRole('heading', { name: 'Integration credentials' }).waitFor();
}
it('manages inventory, dependencies and fresh-MFA credentials through the real browser/API, clears secrets and preserves emergency revocation', async () => {
  const { page, next } = await setup();
  // Model a slow component fetch; selection assertions must await rendering.
  await page.route(/\/components\/opm_[a-f0-9]{24}$/, async (route) => {
    if (route.request().method() === 'GET') await new Promise((resolve) => setTimeout(resolve, 50));
    await route.continue();
  });
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await registerApp(page, 'portal-trial');
  // Existing values in select controls must be preserved when editing.
  const appSettings = section(page, 'Application settings');
  expect(await appSettings.getByLabel('Criticality').inputValue()).toBe('medium');
  await appSettings.getByLabel('Criticality').selectOption('high');
  await appSettings.getByRole('button', { name: 'Save application', exact: true }).click();
  await page.getByText('Application · active · version 2', { exact: true }).waitFor();
  expect(await section(page, 'Application settings').getByLabel('Criticality').inputValue()).toBe(
    'high',
  );
  await addEnv(page);
  await page.getByRole('heading', { name: 'Reported health', exact: true }).waitFor();
  expect(await section(page, 'Reported health').textContent()).toContain(
    'No components to monitor',
  );
  for (const name of ['database', 'web']) {
    const form = section(page, 'Add component');
    await form.getByLabel('Code (permanent)').fill(name);
    if (name === 'web')
      await form.getByLabel('Dependencies in this environment').selectOption({ label: 'database' });
    await form.getByRole('button', { name: 'Add component', exact: true }).click();
    await section(page, 'Components').getByRole('cell', { name, exact: true }).waitFor();
  }
  await page
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'web', exact: true }) })
    .getByRole('button', { name: 'Open' })
    .click();
  const component = section(page, 'Component settings');
  await expect
    .poll(
      () =>
        component
          .getByLabel('Dependencies in this environment')
          .locator('option:checked')
          .allTextContents(),
      { timeout: 10000 },
    )
    .toEqual(['database']);
  expect(await section(page, 'Recent event history').textContent()).toContain(
    'No retained observations',
  );
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  const issue = section(page, 'Integration credentials');
  await issue.getByLabel('Fresh authenticator code').fill(next());
  await issue.getByRole('button', { name: 'Issue credential', exact: true }).click();
  const secret = page.getByLabel('One-time integration credential');
  await secret.waitFor();
  const first = await secret.inputValue();
  expect(first).toMatch(/^ops_v1\.opc_[a-f0-9]{32}\.[a-f0-9]{64}$/);
  expect(
    await page.evaluate('JSON.stringify(localStorage) + JSON.stringify(sessionStorage)'),
  ).not.toContain(first);
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  expect(await secret.count()).toBe(0);
  await page.getByRole('button', { name: 'Rotate', exact: true }).click();
  const modal = page.getByRole('dialog');
  await modal.getByLabel('Fresh authenticator code').fill(next());
  await modal.getByRole('button', { name: 'Rotate credential', exact: true }).click();
  await secret.waitFor();
  expect(await secret.inputValue()).not.toBe(first);
  // Escape must clear the secret after the browser delivers the dialog cancel event.
  await page.keyboard.press('Escape');
  await secret.waitFor({ state: 'detached' });
  expect(await secret.count()).toBe(0);
  const lifecycle = section(page, 'Environment lifecycle');
  await lifecycle.getByRole('button', { name: 'Apply lifecycle change' }).click();
  await page.getByText(/production environment · disabled/).waitFor();
  expect(await page.getByRole('button', { name: 'Issue credential', exact: true }).count()).toBe(0);
  expect(await page.getByRole('button', { name: 'Rotate', exact: true }).count()).toBe(0);
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  await modal.getByLabel('Fresh authenticator code').fill(next());
  page.once('dialog', (d) => d.accept());
  await modal.getByRole('button', { name: 'Revoke credential', exact: true }).click();
  await page.locator('dialog:not([open])').waitFor({ state: 'attached' });
  expect(await page.getByRole('button', { name: 'Revoke', exact: true }).count()).toBe(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate('document.documentElement.scrollWidth <= innerWidth')).toBe(true);
  expect(errors).toEqual([]);
});

it('suppresses a late issued secret after workspace switch and blocks ordinary member controls', async () => {
  const { page, next, other, owner } = await setup();
  await registerApp(page, 'late-secret');
  await addEnv(page);
  const extra = await env.call('POST', '/v1/organizations', {
    token: other.token,
    body: { name: 'Second workspace' },
  });
  await env.call('POST', `/v1/organizations/${extra.body.id}/members`, {
    token: other.token,
    body: { email: 'portal-owner@example.test', role: 'member' },
  });
  // Re-authenticate to load membership without retaining a browser bearer token in this test.
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await page.getByLabel('Email', { exact: true }).fill('portal-owner@example.test');
  await page.getByLabel('Password', { exact: true }).fill(PW);
  await page.getByLabel('Authenticator or recovery code (if enabled)').fill(next());
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Current organization').selectOption(owner.orgId);
  await page.getByRole('button', { name: 'Applications', exact: true }).click();
  await page
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'late-secret', exact: true }) })
    .getByRole('button', { name: 'Open' })
    .click();
  await page
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'production', exact: true }).first() })
    .getByRole('button', { name: 'Open' })
    .click();
  let release!: () => void;
  let arrived!: () => void;
  const ready = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route('**/credentials', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    const result = await route.fetch();
    arrived();
    await gate;
    await route.fulfill({ response: result });
  });
  await section(page, 'Integration credentials')
    .getByLabel('Fresh authenticator code')
    .fill(next());
  await page.getByRole('button', { name: 'Issue credential', exact: true }).click();
  await ready;
  expect(
    await section(page, 'Integration credentials')
      .getByLabel('Fresh authenticator code')
      .inputValue(),
  ).toBe('');
  await page.getByLabel('Current organization').selectOption(extra.body.id);
  await page.getByText('Only organization owners and admins', { exact: false }).waitFor();
  const response = page.waitForResponse(
    (r) => r.request().method() === 'POST' && r.url().endsWith('/credentials'),
  );
  release();
  await response;
  // Wait for a same-renderer turn after the late response handler.
  await page.evaluate('new Promise(resolve => setTimeout(resolve, 100))');
  expect(await page.getByLabel('One-time integration credential').count()).toBe(0);
  expect(
    await page.getByRole('button', { name: 'Register application', exact: true }).count(),
  ).toBe(0);
  const denied = await env.call('GET', `/v1/organizations/${owner.orgId}/operations/applications`, {
    token: other.token,
  });
  expect(denied.status).toBe(403);
});

it('loads every application page and can reopen archived records by ID for emergency revocation', async () => {
  const { page, owner, next } = await setup();
  await registerApp(page, 'archive-trial');
  await addEnv(page);
  await section(page, 'Integration credentials')
    .getByLabel('Fresh authenticator code')
    .fill(next());
  await page.getByRole('button', { name: 'Issue credential', exact: true }).click();
  await page.getByLabel('One-time integration credential').waitFor();
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  const envId = (await page.getByText(/^Environment ID:/).textContent())!.split(': ')[1]!;
  const lifecycle = section(page, 'Environment lifecycle');
  await lifecycle.getByLabel('Lifecycle action').selectOption('archived');
  page.once('dialog', (dialog) => dialog.accept());
  await lifecycle.getByRole('button', { name: 'Apply lifecycle change' }).click();
  await page.getByText(/Archived permanently/).waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  expect(await page.getByRole('cell', { name: 'production', exact: true }).count()).toBe(0);
  await page.getByLabel('Record ID', { exact: true }).fill(envId);
  await page.getByRole('button', { name: 'Open record', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke', exact: true }).waitFor();
  expect(await page.getByRole('button', { name: 'Issue credential', exact: true }).count()).toBe(0);
  const modal = page.getByRole('dialog');
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  await modal.getByLabel('Fresh authenticator code').fill(next());
  page.once('dialog', (dialog) => dialog.accept());
  await modal.getByRole('button', { name: 'Revoke credential', exact: true }).click();
  await page.locator('dialog:not([open])').waitFor({ state: 'attached' });
  for (let i = 0; i < 26; i++) {
    expect(
      (
        await env.call('POST', `/v1/organizations/${owner.orgId}/operations/applications`, {
          token: owner.token,
          body: {
            code: `paged-${i}`,
            owner_user_id: owner.userId,
            product_id: null,
            criticality: 'low',
            reason: 'initial_setup',
          },
        })
      ).status,
    ).toBe(201);
  }
  await page.getByRole('button', { name: 'Applications', exact: true }).click();
  await page.getByRole('button', { name: 'Load more', exact: true }).click();
  await expect.poll(() => page.locator('tbody tr').count()).toBe(27);
  expect(await page.getByRole('button', { name: 'Load more', exact: true }).isVisible()).toBe(
    false,
  );
});

it('shows rollout unavailability without pretending monitoring works, and rejects a reused MFA factor', async () => {
  const { page, next } = await setup();
  await registerApp(page, 'mfa-refusal');
  await addEnv(page);
  const code = next();
  await section(page, 'Integration credentials').getByLabel('Fresh authenticator code').fill(code);
  await page.getByRole('button', { name: 'Issue credential', exact: true }).click();
  await page.getByLabel('One-time integration credential').waitFor();
  await page.keyboard.press('Escape');
  const heading = page.getByRole('heading', { name: 'New credential', exact: true });
  await heading.waitFor();
  await section(page, 'Integration credentials').getByLabel('Fresh authenticator code').fill(code);
  await page.getByRole('button', { name: 'Issue credential', exact: true }).click();
  await page.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
  expect(await page.getByLabel('One-time integration credential').count()).toBe(0);
  await page.getByLabel('Email', { exact: true }).fill('portal-owner@example.test');
  await page.getByLabel('Password', { exact: true }).fill(PW);
  await page.getByLabel('Authenticator or recovery code (if enabled)').fill(next());
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  env.c.config.operationsInventoryEnabled = false;
  await page.getByRole('button', { name: 'Applications', exact: true }).click();
  await page
    .getByText('Application management is unavailable in this deployment.', { exact: true })
    .waitFor();
  expect(
    await page.getByRole('button', { name: 'Register application', exact: true }).count(),
  ).toBe(0);
});

it('opens, assigns, acknowledges and resolves a manual incident using dashboard controls', async () => {
  const { page } = await setup();
  await registerApp(page, 'incident-app');
  await addEnv(page);
  const add = section(page, 'Add component');
  await add.getByLabel('Code (permanent)').fill('api');
  await add.getByRole('button', { name: 'Add component', exact: true }).click();
  const incidents = section(page, 'Incidents');
  await incidents.getByLabel('Incident severity', { exact: true }).selectOption('warning');
  await incidents.getByRole('button', { name: 'Open incident', exact: true }).click();
  await incidents.getByRole('cell', { name: 'open', exact: true }).waitFor();
  await incidents.getByLabel('Filter incident severity').selectOption('critical');
  await incidents.getByText('No loaded incidents match these filters.', { exact: true }).waitFor();
  expect(
    await incidents.getByRole('button', { name: 'Manage incident', exact: true }).count(),
  ).toBe(0);
  expect(await incidents.getByRole('status').textContent()).toContain('0 matching of 1 loaded');
  await incidents.getByLabel('Filter incident state').selectOption('acknowledged');
  await incidents.getByLabel('Filter incident severity').selectOption('warning');
  await incidents.getByText('No loaded incidents match these filters.', { exact: true }).waitFor();
  await incidents.getByRole('button', { name: 'Clear incident filters' }).click();
  await incidents.getByRole('cell', { name: 'open', exact: true }).waitFor();
  expect(await incidents.getByRole('status').textContent()).toContain('1 matching of 1 loaded');
  await incidents.getByRole('button', { name: 'Manage incident', exact: true }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByLabel('Assigned responder').selectOption({ label: 'You' });
  await dialog.getByRole('button', { name: 'Assign incident', exact: true }).click();
  await expect
    .poll(() => incidents.getByRole('cell', { name: 'You', exact: true }).count())
    .toBe(1);
  await incidents.getByRole('button', { name: 'Manage incident', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'Acknowledge incident', exact: true }).click();
  await incidents.getByRole('cell', { name: 'acknowledged', exact: true }).waitFor();
  await incidents.getByRole('button', { name: 'Manage incident', exact: true }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Resolve incident', exact: true })
    .click();
  await incidents.getByRole('cell', { name: 'resolved', exact: true }).waitFor();
  expect(
    await incidents.getByRole('button', { name: 'Manage incident', exact: true }).count(),
  ).toBe(0);
});

it('keeps pagination available when loaded incident filters match nothing', async () => {
  const { page } = await setup();
  await registerApp(page, 'filtered-pages');
  await addEnv(page);
  const add = section(page, 'Add component');
  await add.getByLabel('Code (permanent)').fill('api');
  await add.getByRole('button', { name: 'Add component', exact: true }).click();
  const incidents = section(page, 'Incidents');
  await incidents.getByRole('button', { name: 'Open incident', exact: true }).click();
  await incidents.getByRole('cell', { name: 'open', exact: true }).waitFor();
  let fixture: Record<string, unknown> = {};
  // Exercise paginated rendering with controlled read responses; mutations still use the real API.
  await page.route(/\/incidents\?limit=25/, async (route) => {
    if (!fixture.id) {
      const response = await route.fetch();
      fixture = (await response.json()).items[0];
    }
    const more = new URL(route.request().url()).searchParams.has('after');
    await route.fulfill({
      json: more
        ? {
            items: [{ ...fixture, id: 'opi_' + 'f'.repeat(24), severity: 'critical' }],
            next_after: null,
          }
        : { items: [{ ...fixture, severity: 'warning' }], next_after: fixture.id },
    });
  });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await incidents.getByLabel('Filter incident severity').selectOption('critical');
  await incidents.getByText('No loaded incidents match these filters.', { exact: true }).waitFor();
  expect(await incidents.getByRole('status').textContent()).toContain('More records remain');
  await incidents.getByRole('button', { name: 'Load more incidents' }).click();
  await incidents.getByRole('cell', { name: 'critical', exact: true }).waitFor();
  expect(await incidents.getByRole('status').textContent()).toContain('1 matching of 2 loaded');
  expect(await incidents.getByRole('status').textContent()).toContain('All available');
  expect(await incidents.getByRole('button', { name: 'Load more incidents' }).isVisible()).toBe(
    false,
  );
  await incidents.getByRole('button', { name: 'Clear incident filters' }).click();
  expect(await incidents.getByRole('cell', { name: 'open', exact: true }).count()).toBe(2);
});

it('does not reopen an incident workspace when a late mutation response arrives after navigation', async () => {
  const { page } = await setup();
  await registerApp(page, 'late-incident');
  await addEnv(page);
  await section(page, 'Add component').getByLabel('Code (permanent)').fill('api');
  await section(page, 'Add component')
    .getByRole('button', { name: 'Add component', exact: true })
    .click();
  let signal!: () => void, release!: () => void;
  const captured = new Promise<void>((r) => {
    signal = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  await page.route(/\/incidents$/, async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    const response = await route.fetch();
    signal();
    await gate;
    await route.fulfill({ response });
  });
  const finished = page.waitForResponse(
    (r) => r.request().method() === 'POST' && r.url().endsWith('/incidents'),
  );
  await section(page, 'Incidents')
    .getByRole('button', { name: 'Open incident', exact: true })
    .click();
  await captured;
  await page.getByRole('button', { name: 'Licenses', exact: true }).click();
  await page.getByRole('heading', { name: 'Licenses', exact: true }).waitFor();
  release();
  await finished;
  await page.waitForLoadState('networkidle');
  expect(await page.getByRole('heading', { name: 'Licenses', exact: true }).count()).toBe(1);
  expect(await page.getByRole('heading', { name: 'Incidents', exact: true }).count()).toBe(0);
});

it('creates, evaluates, mutes and disables automatic alerts through real dashboard controls', async () => {
  const { page, owner } = await setup();
  let rulePath = '';
  page.on('request', (request) => {
    if (request.method() === 'GET' && request.url().endsWith('/rules'))
      rulePath = new URL(request.url()).pathname;
  });
  await registerApp(page, 'alert-dashboard');
  await addEnv(page);
  const add = section(page, 'Add component');
  await add.getByLabel('Code (permanent)').fill('scanner');
  await add.getByRole('button', { name: 'Add component', exact: true }).click();
  await section(page, 'Components').getByRole('cell', { name: 'scanner', exact: true }).waitFor();
  const alerts = section(page, 'Automatic alerts');
  await alerts.locator('summary', { hasText: 'Create an automatic rule' }).click();
  await alerts.getByLabel('Condition', { exact: true }).selectOption('heartbeat');
  await alerts.getByRole('button', { name: 'Create rule', exact: true }).click();
  await alerts.getByRole('cell', { name: 'unknown', exact: true }).waitFor();
  const mutations: string[] = [];
  page.on('request', (request) => {
    if (request.method() !== 'GET') mutations.push(request.url());
  });
  const beforeGuide = mutations.length;
  await alerts.getByRole('button', { name: 'Open response guide', exact: true }).click();
  const guide = page.getByRole('dialog');
  await guide.getByRole('heading', { name: 'Investigate component', exact: true }).waitFor();
  expect(await guide.textContent()).toContain('Affected component: scanner');
  expect(await guide.textContent()).toContain('Require fresh healthy observations');
  expect(await guide.textContent()).toContain('Escalate to the application owner');
  expect(mutations.length).toBe(beforeGuide);
  await guide.getByRole('button', { name: 'Close', exact: true }).click();
  await alerts.getByRole('button', { name: 'Evaluate rules now', exact: true }).click();
  await page.waitForLoadState('networkidle');
  // The scheduler can evaluate after rendering without changing rule settings.
  await env.c.operationsAutomation.tick();
  await alerts.getByRole('button', { name: 'Mute for 1 hour', exact: true }).click();
  await alerts.getByRole('button', { name: 'End maintenance', exact: true }).waitFor();
  await alerts.getByRole('button', { name: 'Disable rule', exact: true }).click();
  await alerts.getByRole('button', { name: 'Enable rule', exact: true }).waitFor();
  await page.waitForLoadState('networkidle');
  const latest = (await env.call('GET', rulePath, { token: owner.token })).body.items[0];
  expect(
    (
      await env.call('PATCH', `${rulePath}/${latest.id}`, {
        token: owner.token,
        body: {
          expected_version: latest.version,
          enabled: true,
          maintenance_until: null,
          reason: 'maintenance',
        },
      })
    ).status,
  ).toBe(200);
  await alerts.getByRole('button', { name: 'Enable rule', exact: true }).click();
  await page
    .getByText('Rule settings changed. Refresh this view and try again.', { exact: true })
    .waitFor();
  expect(
    (await env.call('GET', rulePath, { token: owner.token })).body.items[0].maintenance_until,
  ).toBeNull();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate('document.documentElement.scrollWidth <= innerWidth')).toBe(true);
});

it('does not replace the current page after a late automatic rule creation response', async () => {
  const { page } = await setup();
  await registerApp(page, 'late-rule');
  await addEnv(page);
  const add = section(page, 'Add component');
  await add.getByLabel('Code (permanent)').fill('scanner');
  await add.getByRole('button', { name: 'Add component', exact: true }).click();
  await section(page, 'Components').getByRole('cell', { name: 'scanner', exact: true }).waitFor();
  let release!: () => void, arrived!: () => void;
  const began = new Promise<void>((r) => {
      arrived = r;
    }),
    gate = new Promise<void>((r) => {
      release = r;
    });
  await page.route('**/rules', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    const response = await route.fetch();
    arrived();
    await gate;
    await route.fulfill({ response });
  });
  await section(page, 'Automatic alerts')
    .locator('summary', { hasText: 'Create an automatic rule' })
    .click();
  await page.getByRole('button', { name: 'Create rule', exact: true }).click();
  await began;
  await page.getByRole('button', { name: 'Licenses', exact: true }).click();
  await page.getByRole('heading', { name: 'Licenses', exact: true }).waitFor();
  release();
  await page.unrouteAll({ behavior: 'wait' });
  expect(await page.getByRole('heading', { name: 'Licenses', exact: true }).isVisible()).toBe(true);
  expect(await page.getByRole('heading', { name: 'Automatic alerts', exact: true }).count()).toBe(
    0,
  );
});

it('imports security findings, assigns a responder and records explicitly reported restore evidence', async () => {
  const { page, owner } = await setup();
  await registerApp(page, 'posture-dashboard');
  await addEnv(page);
  const add = section(page, 'Add component');
  await add.getByLabel('Code (permanent)').fill('database');
  await add.getByRole('button', { name: 'Add component', exact: true }).click();
  await section(page, 'Components').getByRole('cell', { name: 'database', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Security & recovery', exact: true }).click();
  await page.getByRole('heading', { name: 'Security & recovery', exact: true }).waitFor();
  const scans = section(page, 'Imported scan reports');
  await scans.locator('summary', { hasText: 'Import a normalized GitHub scan' }).click();
  const component = await scans.getByLabel('Scan component').inputValue();
  const input = {
    component_id: component,
    source: 'github_dependabot',
    revision: 'a'.repeat(40),
    run_id: '123',
    completed_at: env.clock.now().toISOString(),
    outcome: 'completed',
    findings: [
      { fingerprint: 'b'.repeat(64), severity: 'critical', advisory_id: 'CVE-2026-12345' },
    ],
    reason: 'initial_setup',
  };
  await scans.getByLabel('Normalized scan JSON').setInputFiles({
    name: 'safe-scan.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(input)),
  });
  await scans.getByRole('button', { name: 'Import scan', exact: true }).click();
  const findings = section(page, 'Security findings');
  await findings.getByRole('cell', { name: 'CVE-2026-12345', exact: true }).waitFor();
  await findings.locator('summary', { hasText: 'Edit finding' }).click();
  await findings.getByLabel('Finding responder').selectOption(owner.userId);
  await findings.getByLabel('Finding state').selectOption('acknowledged');
  await findings.getByRole('button', { name: 'Save finding', exact: true }).click();
  await findings.getByRole('cell', { name: 'acknowledged', exact: true }).waitFor();
  const recovery = section(page, 'Recovery evidence');
  await recovery.locator('summary', { hasText: 'Record a recovery report' }).click();
  await recovery.getByLabel('Recovery type').selectOption('restore');
  await recovery
    .getByLabel('Started at (UTC)')
    .fill(new Date(+env.clock.now() - 60000).toISOString());
  await recovery.getByLabel('Completed at (UTC)').fill(env.clock.now().toISOString());
  await recovery
    .getByLabel('Recovered data timestamp (UTC)')
    .fill(new Date(+env.clock.now() - 120000).toISOString());
  for (const label of ['integrity check', 'application check', 'audit check'])
    await recovery.getByLabel(label, { exact: true }).selectOption('passed');
  await recovery.getByLabel('Evidence artifact SHA-256').fill('c'.repeat(64));
  await recovery.getByRole('button', { name: 'Record report', exact: true }).click();
  await recovery.getByRole('cell', { name: 'restore / succeeded', exact: true }).waitFor();
  await recovery.getByRole('cell', { name: 'Reported targets met', exact: true }).waitFor();
  expect(await recovery.getByText(/not been independently verified/).count()).toBe(1);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate('document.documentElement.scrollWidth <= innerWidth')).toBe(true);
});

async function overviewInventory(
  owner: { token: string; orgId: string; userId: string },
  code: string,
  environmentCount = 1,
) {
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  const app = await env.call('POST', base, {
    token: owner.token,
    body: {
      code,
      owner_user_id: owner.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    },
  });
  expect(app.status).toBe(201);
  const scopes: { appId: string; envId: string; path: string }[] = [];
  for (let i = 0; i < environmentCount; i++) {
    const e = await env.call('POST', `${base}/${app.body.id}/environments`, {
      token: owner.token,
      body: { code: `production-${i}`, kind: 'production', reason: 'initial_setup' },
    });
    expect(e.status).toBe(201);
    scopes.push({
      appId: app.body.id,
      envId: e.body.id,
      path: `${base}/${app.body.id}/environments/${e.body.id}`,
    });
  }
  return { appId: app.body.id as string, scopes };
}

it('security overview prioritizes open critical findings and opens their real scoped triage controls', async () => {
  const { page, owner } = await setup();
  const critical = await overviewInventory(owner, 'z-critical-service');
  await overviewInventory(owner, 'missing-reports');
  const path = critical.scopes[0]!.path;
  const component = await env.call('POST', `${path}/components`, {
    token: owner.token,
    body: { code: 'api', kind: 'service', dependency_ids: [], reason: 'initial_setup' },
  });
  expect(component.status).toBe(201);
  expect(
    (
      await env.call('POST', `${path}/security/scans`, {
        token: owner.token,
        body: {
          component_id: component.body.id,
          source: 'github_dependabot',
          revision: 'a'.repeat(40),
          run_id: '123',
          completed_at: env.clock.now().toISOString(),
          outcome: 'completed',
          findings: [
            { fingerprint: 'b'.repeat(64), severity: 'critical', advisory_id: 'CVE-2026-12345' },
          ],
          reason: 'initial_setup',
        },
      })
    ).status,
  ).toBe(201);
  await page.getByRole('button', { name: 'Review security overview', exact: true }).click();
  await page.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  const reports = section(page, 'Environment reports');
  expect(await reports.getByRole('row').nth(1).textContent()).toContain(
    'z-critical-service / production-0',
  );
  expect(await reports.getByText('1 shown · 1 critical · 0 high', { exact: true }).count()).toBe(1);
  expect(await reports.getByText('No scan report shown', { exact: true }).count()).toBe(1);
  expect(await reports.getByText('No restore report shown', { exact: true }).count()).toBe(2);
  if (process.env['PORTAL_ARTIFACTS'])
    await page.screenshot({
      path: join(process.env['PORTAL_ARTIFACTS'], 'security-overview-desktop.png'),
      fullPage: true,
    });
  await page.setViewportSize({ width: 390, height: 844 });
  if (process.env['PORTAL_ARTIFACTS'])
    await page.screenshot({
      path: join(process.env['PORTAL_ARTIFACTS'], 'security-overview-mobile.png'),
      fullPage: true,
    });
  expect(await page.evaluate('document.documentElement.scrollWidth <= innerWidth')).toBe(true);
  await reports
    .getByRole('button', { name: 'Review z-critical-service / production-0', exact: true })
    .click();
  await page.getByRole('heading', { name: 'Security & recovery', exact: true }).waitFor();
  await section(page, 'Security findings').getByText('CVE-2026-12345', { exact: true }).waitFor();
});

it('security overview keeps unavailable reporting unknown and never substitutes an empty successful read', async () => {
  const { page, owner } = await setup();
  await overviewInventory(owner, 'unavailable-service');
  await page.route('**/security', (route) =>
    route.fulfill({ status: 503, json: { code: 'unavailable', message: 'request rejected' } }),
  );
  await page.getByRole('button', { name: 'Review security overview', exact: true }).click();
  await page.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  const reports = section(page, 'Environment reports');
  expect(await reports.getByText('Reporting unavailable', { exact: true }).count()).toBe(1);
  expect(await reports.getByText('Unknown', { exact: true }).count()).toBe(2);
  expect(await reports.getByText(/^0 shown/).count()).toBe(0);
  expect(await section(page, 'Coverage').textContent()).toContain('Coverage is partial');
  await reports
    .getByRole('button', { name: 'Open unavailable-service / production-0', exact: true })
    .click();
  await page.getByRole('heading', { name: 'Integration credentials', exact: true }).waitFor();
});

it('security overview bounds inventory reads and explicitly marks further applications and environments as partial', async () => {
  const { page, owner } = await setup();
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  for (let i = 0; i < 11; i++) {
    await overviewInventory(owner, `coverage-${i}`, 0);
    env.clock.advance(1);
  }
  const apps = await env.call('GET', `${base}?limit=100`, { token: owner.token });
  const appId = apps.body.items[0].id;
  for (let i = 0; i < 6; i++)
    expect(
      (
        await env.call('POST', `${base}/${appId}/environments`, {
          token: owner.token,
          body: { code: `production-${i}`, kind: 'production', reason: 'initial_setup' },
        })
      ).status,
    ).toBe(201);
  // Simulate an over-wide upstream response: the browser still applies its own read budgets.
  await page.route(`**/operations/applications?limit=10`, (route) =>
    route.fulfill({ json: apps.body }),
  );
  const environments = await env.call('GET', `${base}/${appId}/environments?limit=100`, {
    token: owner.token,
  });
  await page.route(`**/${appId}/environments?limit=5`, (route) =>
    route.fulfill({ json: environments.body }),
  );
  let postureReads = 0,
    environmentReads = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/security')) postureReads++;
    if (request.url().includes('/environments?limit=5')) environmentReads++;
  });
  await page.getByRole('button', { name: 'Review security overview', exact: true }).click();
  await page.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  expect(postureReads).toBe(5);
  expect(environmentReads).toBe(10);
  expect(await section(page, 'Coverage').textContent()).toContain(
    '10 applications and 5 environments reviewed',
  );
  expect(await section(page, 'Coverage').textContent()).toContain('Coverage is partial');
});

it('security overview stops new batches and suppresses late evidence after workspace navigation', async () => {
  const { page, owner } = await setup();
  await overviewInventory(owner, 'late-overview', 5);
  let arrived!: () => void, release!: () => void;
  const ready = new Promise<void>((r) => {
    arrived = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let reads = 0;
  await page.route('**/security', async (route) => {
    const result = await route.fetch();
    if (++reads === 4) arrived();
    await gate;
    await route.fulfill({ response: result });
  });
  await page.getByRole('button', { name: 'Review security overview', exact: true }).click();
  await ready;
  await page.getByRole('button', { name: 'Licenses', exact: true }).click();
  await page.getByRole('heading', { name: 'Licenses', exact: true }).waitFor();
  const responses = page.waitForResponse((r) => r.url().endsWith('/security'));
  release();
  await responses;
  await page.evaluate('new Promise(resolve => setTimeout(resolve, 100))');
  expect(reads).toBe(4);
  expect(await page.getByRole('heading', { name: 'Security overview', exact: true }).count()).toBe(
    0,
  );
});

it('security overview refuses authorization failures without rendering a partial cached view', async () => {
  const { page, owner } = await setup();
  await overviewInventory(owner, 'authorization-overview');
  await page.route('**/security', (route) =>
    route.fulfill({ status: 403, json: { code: 'forbidden', message: 'request rejected' } }),
  );
  await page.getByRole('button', { name: 'Review security overview', exact: true }).click();
  await page.getByText('Could not load this view.', { exact: true }).waitFor();
  expect(await page.getByRole('heading', { name: 'Security overview', exact: true }).count()).toBe(
    0,
  );
  expect(
    await page.getByRole('heading', { name: 'Environment reports', exact: true }).count(),
  ).toBe(0);
});
