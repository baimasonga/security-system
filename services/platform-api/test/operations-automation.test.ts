import { afterEach, expect, it } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
let env: Env;
afterEach(async () => env?.app.close());
async function setup(enabled = true) {
  env = await makeEnv({
    config: {
      operationsInventoryEnabled: true,
      operationsCredentialsEnabled: true,
      operationsIngestionEnabled: true,
      operationsHealthEnabled: true,
      operationsIncidentsEnabled: true,
      operationsAutomationEnabled: enabled,
    },
  });
  const owner = await env.register('owner@example.test'),
    other = await env.register('other@example.test');
  const p = await env.c.auth.authenticate(owner.token);
  const team = await env.c.auth.createOrganization(p, 'Alerts');
  await env.c.auth.addMember(p, team.id, 'other@example.test', 'member');
  const a = await env.c.operations.createApplication(p, team.id, {
    code: 'alerts',
    ownerUserId: owner.userId,
    criticality: 'high',
    productId: null,
    reason: 'initial_setup',
  });
  const e = await env.c.operations.createEnvironment(
    p,
    { orgId: team.id, applicationId: a.id },
    { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  );
  const scope = { orgId: team.id, applicationId: a.id, environmentId: e.id };
  const c = await env.c.operations.createComponent(p, scope, {
    code: 'scanner',
    kind: 'scanner',
    dependencyIds: [],
    reason: 'initial_setup',
  });
  const path = `/v1/organizations/${team.id}/operations/applications/${a.id}/environments/${e.id}`;
  const body = {
    component_id: c.id,
    kind: 'heartbeat',
    event_type: null,
    threshold: 1,
    window_seconds: 60,
    severity: 'warning',
    runbook: 'check_scanner',
    reason: 'initial_setup',
  };
  return { owner, other, p, scope, c, path, body };
}
it('gates automation and validates required feature dependencies', async () => {
  expect(loadConfig({ NODE_ENV: 'test' }).operationsAutomationEnabled).toBe(false);
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_AUTOMATION_ENABLED: 'true' })).toThrow(
    'requires',
  );
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_AUTOMATION_ENABLED: 'yes' })).toThrow(
    'true or false',
  );
  const f = await setup(false);
  expect((await env.call('GET', f.path + '/rules', { token: f.owner.token })).status).toBe(404);
});
it('provides strict scoped owner-managed rules while ordinary members are refused and destinations stay fixed', async () => {
  const f = await setup();
  const token = f.owner.token;
  expect(
    (await env.call('POST', f.path + '/rules', { token: f.other.token, body: f.body })).status,
  ).toBe(403);
  const created = await env.call('POST', f.path + '/rules', { token, body: f.body });
  expect(created.status).toBe(201);
  expect(created.body.observation).toBe('unknown');
  expect((await env.call('GET', f.path + '/rules', { token: f.other.token })).status).toBe(403);
  expect(
    (await env.call('POST', f.path + '/rules/evaluate', { token: f.other.token, body: {} })).status,
  ).toBe(403);
  expect((await env.call('POST', f.path + '/rules/evaluate', { token, body: {} })).status).toBe(
    200,
  );
  expect(
    (
      await env.call('GET', f.path.replace(f.scope.orgId, f.other.orgId) + '/rules', {
        token: f.other.token,
      })
    ).status,
  ).toBe(404);
  for (const patch of [
    { destination: 'https://private.invalid' },
    { threshold: 0 },
    { window_seconds: 3601 },
    { event_type: 'user.password' },
    { kind: 'heartbeat', event_type: 'conversion.failed' },
    { component_id: 'opm_' + 'f'.repeat(24) },
  ]) {
    expect(
      (await env.call('POST', f.path + '/rules', { token, body: { ...f.body, ...patch } })).status,
    ).toBe(patch.component_id ? 404 : 400);
  }
  const path = f.path + '/rules/' + created.body.id;
  const current = (await env.call('GET', f.path + '/rules', { token })).body.items[0];
  const config = {
    expected_version: current.version,
    enabled: true,
    maintenance_until: new Date(+env.clock.now() + 3600000).toISOString(),
    reason: 'maintenance',
  };
  expect((await env.call('PATCH', path, { token, body: config })).status).toBe(200);
  expect((await env.call('PATCH', path, { token, body: config })).status).toBe(409);
  expect(
    (
      await env.call('GET', f.path + '/notifications?recipient_user_id=' + f.other.userId, {
        token,
      })
    ).status,
  ).toBe(400);
  expect((await env.call('GET', f.path + '/notifications', { token })).body.items).toEqual([]);
  const audit = await env.c.audit.list();
  expect(audit.filter((r) => r.action === 'operations.rule.created')).toHaveLength(1);
  expect(audit.filter((r) => r.action === 'operations.rule.configured')).toHaveLength(1);
});
