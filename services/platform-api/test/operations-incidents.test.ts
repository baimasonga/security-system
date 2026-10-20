import { afterEach, expect, it } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
let env: Env;
afterEach(async () => env?.app.close());
async function setup(enabled = true) {
  env = await makeEnv({
    config: { operationsInventoryEnabled: true, operationsIncidentsEnabled: enabled },
  });
  const owner = await env.register('owner@example.test'),
    other = await env.register('other@example.test');
  const p = await env.c.auth.authenticate(owner.token);
  const org = await env.c.auth.createOrganization(p, 'Incident response');
  await env.c.auth.addMember(p, org.id, 'other@example.test', 'member');
  const a = await env.c.operations.createApplication(p, org.id, {
    code: 'incident-app',
    ownerUserId: owner.userId,
    criticality: 'high',
    productId: null,
    reason: 'initial_setup',
  });
  const e = await env.c.operations.createEnvironment(
    p,
    { orgId: org.id, applicationId: a.id },
    { code: 'production', kind: 'production', reason: 'initial_setup' },
  );
  const c = await env.c.operations.createComponent(
    p,
    { orgId: org.id, applicationId: a.id, environmentId: e.id },
    { code: 'api', kind: 'service', dependencyIds: [], reason: 'initial_setup' },
  );
  const path = `/v1/organizations/${org.id}/operations/applications/${a.id}/environments/${e.id}/incidents`;
  return { owner, other, p, org, a, e, c, path };
}
it('gates incident APIs and requires inventory in configuration', async () => {
  expect(loadConfig({ NODE_ENV: 'test' }).operationsIncidentsEnabled).toBe(false);
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_INCIDENTS_ENABLED: 'true' })).toThrow(
    'requires inventory',
  );
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_INCIDENTS_ENABLED: 'yes' })).toThrow(
    'true or false',
  );
  const f = await setup(false);
  expect((await env.call('GET', f.path, { token: f.owner.token })).status).toBe(404);
  expect(
    (
      await env.call('POST', f.path, {
        token: f.owner.token,
        body: { component_id: f.c.id, severity: 'warning', reason: 'security_response' },
      })
    ).status,
  ).toBe(404);
});
it('provides actionable audited incidents without granting member or integration-key access', async () => {
  const f = await setup();
  const token = f.owner.token;
  const body = { component_id: f.c.id, severity: 'warning', reason: 'security_response' };
  const created = await env.call('POST', f.path, { token, body });
  expect(created.status).toBe(200);
  expect(created.body.created).toBe(true);
  const row = created.body.incident;
  const path = f.path + '/' + row.id;
  expect(row.source).toBe('manual_triage');
  expect((await env.call('POST', f.path, { token, body })).body).toMatchObject({
    created: false,
    incident: { id: row.id, version: 1 },
  });
  const listed = await env.call('GET', f.path, { token });
  expect(listed.body.items).toHaveLength(1);
  expect(listed.headers['cache-control']).toBe('no-store');
  expect((await env.call('GET', f.path, { token: f.other.token })).status).toBe(403);
  expect((await env.call('POST', f.path, { token: f.other.token, body })).status).toBe(403);
  expect((await env.call('GET', f.path, { token: 'ops_v1.invalid' })).status).toBe(401);
  expect(
    (await env.call('GET', f.path.replace(f.org.id, f.other.orgId), { token: f.other.token }))
      .status,
  ).toBe(404);
  expect(
    (
      await env.call('POST', path + '/assign', {
        token,
        body: {
          expected_version: 1,
          reason: 'assignment',
          assignee_user_id: 'usr_' + 'f'.repeat(24),
        },
      })
    ).status,
  ).toBe(404);
  const assigned = await env.call('POST', path + '/assign', {
    token,
    body: { expected_version: 1, reason: 'assignment', assignee_user_id: f.owner.userId },
  });
  expect(assigned.body).toMatchObject({ version: 2, assignee_user_id: f.owner.userId });
  expect(
    (
      await env.call('POST', path + '/acknowledge', {
        token,
        body: { expected_version: 1, reason: 'incident_ack' },
      })
    ).status,
  ).toBe(409);
  expect(
    (
      await env.call('POST', path + '/acknowledge', {
        token,
        body: { expected_version: 2, reason: 'incident_ack' },
      })
    ).body.state,
  ).toBe('acknowledged');
  expect(
    (
      await env.call('POST', path + '/resolve', {
        token,
        body: { expected_version: 3, reason: 'incident_resolution' },
      })
    ).body.state,
  ).toBe('resolved');
  expect(
    (
      await env.call('POST', path + '/assign', {
        token,
        body: { expected_version: 4, reason: 'assignment', assignee_user_id: null },
      })
    ).status,
  ).toBe(409);
  for (const bad of [
    { ...body, reason: '' },
    { ...body, payload: 'private@example.test' },
    { ...body, component_id: 'opm_' + 'f'.repeat(24) },
  ]) {
    expect([400, 404]).toContain((await env.call('POST', f.path, { token, body: bad })).status);
  }
  expect((await env.call('GET', f.path + '?limit=101', { token })).status).toBe(400);
  expect((await env.call('GET', f.path + '?email=private@example.test', { token })).status).toBe(
    400,
  );
  expect(
    (await env.call('POST', path + '/resolve', { token, body: { expected_version: 4 } })).status,
  ).toBe(400);
  const events = await env.c.audit.list();
  expect(
    events.filter((e) => e.action.startsWith('operations.incident.')).map((e) => e.action),
  ).toEqual([
    'operations.incident.opened',
    'operations.incident.assigned',
    'operations.incident.acknowledged',
    'operations.incident.resolved',
  ]);
});

it.each([
  ['23514', '23514'],
  ['private SQL parameters', 'unknown'],
])('logs only a bounded SQLSTATE for unavailable code %s', async (code, safe) => {
  const f = await setup();
  const { vi } = await import('vitest');
  const spy = vi.spyOn(env.app.log, 'error').mockImplementation(() => {});
  vi.spyOn(env.c.operationsIncidents, 'open').mockRejectedValueOnce(
    Object.assign(new Error('private SQL parameters must not be logged'), { code }),
  );
  const result = await env.call('POST', f.path, {
    token: f.owner.token,
    body: { component_id: f.c.id, severity: 'informational', reason: 'security_response' },
  });
  expect(result.status).toBe(503);
  expect(result.body.code).toBe('unavailable');
  expect(spy.mock.calls[0]).toEqual([
    { failure: 'operations_unavailable', sqlstate: safe },
    'operations request failed',
  ]);
  expect(JSON.stringify(spy.mock.calls)).not.toContain('private SQL parameters');
  spy.mockRestore();
});

it.each([
  ['permission denied for table operations_incidents', 'operations_incidents'],
  ['permission denied for table private_customer_data', 'unknown'],
])('logs only allowlisted permission targets: %s', async (message, target) => {
  const f = await setup();
  const { vi } = await import('vitest');
  const spy = vi.spyOn(env.app.log, 'error').mockImplementation(() => {});
  vi.spyOn(env.c.operationsIncidents, 'open').mockRejectedValueOnce(
    Object.assign(new Error(message), { code: '42501' }),
  );
  expect(
    (
      await env.call('POST', f.path, {
        token: f.owner.token,
        body: { component_id: f.c.id, severity: 'informational', reason: 'security_response' },
      })
    ).status,
  ).toBe(503);
  expect(spy.mock.calls[0]).toEqual([
    { failure: 'operations_unavailable', sqlstate: '42501', permission_target: target },
    'operations request failed',
  ]);
  expect(JSON.stringify(spy.mock.calls)).not.toContain('private_customer_data');
  spy.mockRestore();
});
