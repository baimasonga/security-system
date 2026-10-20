import { afterEach, expect, it } from 'vitest';
import { makeEnv, PW, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
let env: Env;
afterEach(async () => env?.app.close());
async function setup(enabled = true) {
  env = await makeEnv({
    config: { operationsInventoryEnabled: true, operationsPostureEnabled: enabled },
  });
  const owner = await env.register('posture-owner@example.test');
  const other = await env.register('posture-other@example.test');
  const p = await env.c.auth.authenticate(owner.token);
  const org = await env.c.auth.createOrganization(p, 'Posture');
  await env.c.auth.addMember(p, org.id, 'posture-other@example.test', 'member');
  const a = await env.c.operations.createApplication(p, org.id, {
    code: 'posture',
    ownerUserId: owner.userId,
    criticality: 'high',
    productId: null,
    reason: 'initial_setup',
  });
  const e = await env.c.operations.createEnvironment(
    p,
    { orgId: org.id, applicationId: a.id },
    { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  );
  const scope = { orgId: org.id, applicationId: a.id, environmentId: e.id };
  const c = await env.c.operations.createComponent(p, scope, {
    code: 'database',
    kind: 'database',
    dependencyIds: [],
    reason: 'initial_setup',
  });
  const path = `/v1/organizations/${org.id}/operations/applications/${a.id}/environments/${e.id}/security`;
  const scan = {
    component_id: c.id,
    source: 'github_dependabot',
    revision: 'a'.repeat(40),
    run_id: '123',
    completed_at: env.clock.now().toISOString(),
    outcome: 'completed',
    findings: [{ fingerprint: 'b'.repeat(64), severity: 'high', advisory_id: 'CVE-2026-12345' }],
    reason: 'initial_setup',
  };
  const recovery = {
    component_id: c.id,
    kind: 'restore',
    started_at: new Date(+env.clock.now() - 60000).toISOString(),
    completed_at: env.clock.now().toISOString(),
    recovery_point_at: new Date(+env.clock.now() - 120000).toISOString(),
    outcome: 'succeeded',
    integrity_check: 'passed',
    application_check: 'passed',
    audit_check: 'passed',
    artifact_digest: 'c'.repeat(64),
    target_rpo_seconds: 300,
    target_rto_seconds: 7200,
    reason: 'initial_setup',
  };
  return { owner, other, p, org, a, e, c, scope, path, scan, recovery };
}
it('gates posture and requires inventory without affecting existing licensing', async () => {
  expect(loadConfig({ NODE_ENV: 'test' }).operationsPostureEnabled).toBe(false);
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_POSTURE_ENABLED: 'true' })).toThrow(
    'requires',
  );
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_POSTURE_ENABLED: 'yes' })).toThrow();
  const f = await setup(false);
  expect((await env.call('GET', f.path, { token: f.owner.token })).status).toBe(404);
  await expect(env.c.operationsPosture.read(f.p, f.scope)).rejects.toMatchObject({
    code: 'not_found',
  });
});
it('imports bounded snapshots idempotently, labels provenance and refuses unknown/raw secret fields', async () => {
  const f = await setup();
  const token = f.owner.token;
  for (const body of [
    { ...f.scan, secret: 'never-store-this' },
    { ...f.scan, findings: [{ ...f.scan.findings[0], filename: 'private.txt' }] },
    { ...f.scan, findings: [{ ...f.scan.findings[0], advisory_id: 'https://internal.invalid' }] },
    { ...f.scan, source: 'github_secret_scanning' },
    { ...f.scan, outcome: 'failed' },
    { ...f.scan, completed_at: new Date(+env.clock.now() + 1).toISOString() },
    { ...f.scan, findings: Array(101).fill(f.scan.findings[0]) },
  ]) {
    const result = await env.call('POST', f.path + '/scans', { token, body });
    expect(result.status).toBe(400);
    expect(JSON.stringify(result.body)).not.toContain('never-store-this');
    expect(JSON.stringify(result.body)).not.toContain('private.txt');
  }
  const created = await env.call('POST', f.path + '/scans', { token, body: f.scan });
  expect(created.status).toBe(201);
  const duplicate = await env.call('POST', f.path + '/scans', { token, body: f.scan });
  expect(duplicate.status).toBe(200);
  expect(duplicate.body.id).toBe(created.body.id);
  const view = (await env.call('GET', f.path, { token })).body;
  expect(view.scans.items).toHaveLength(1);
  expect(view.findings.items).toHaveLength(1);
  expect(view.scans.items[0].provenance).toBe('admin_report');
  expect(view.scans.items[0].independently_verified).toBe(false);
  expect(view.scans.items[0].freshness).toBe('current');
  env.clock.advance(8 * 86400000);
  const fresh = (
    await env.call('POST', '/v1/auth/login', {
      body: { email: 'posture-owner@example.test', password: PW },
    })
  ).body.token;
  expect((await env.call('GET', f.path, { token: fresh })).body.scans.items[0].freshness).toBe(
    'stale',
  );
  env.clock.advance(-8 * 86400000);
  expect((await env.call('GET', f.path, { token })).body.scans.items[0].freshness).toBe('stale');
});
it('enforces tenant, role, session, ancestry, assignee and optimistic remediation controls', async () => {
  const f = await setup();
  const token = f.owner.token;
  expect(
    (await env.call('POST', f.path + '/scans', { token: f.other.token, body: f.scan })).status,
  ).toBe(403);
  expect((await env.call('GET', f.path, { token: f.other.token })).status).toBe(403);
  expect(
    (await env.call('GET', f.path.replace(f.org.id, f.other.orgId), { token: f.other.token }))
      .status,
  ).toBe(404);
  await env.call('POST', f.path + '/scans', { token, body: f.scan });
  const finding = (await env.call('GET', f.path, { token })).body.findings.items[0];
  const patch = {
    expected_version: 1,
    state: 'acknowledged',
    assignee_user_id: f.owner.userId,
    reason: 'assignment',
  };
  expect(
    (
      await env.call('PATCH', f.path + '/findings/' + finding.id, {
        token,
        body: { ...patch, assignee_user_id: 'usr_' + 'f'.repeat(24) },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await env.call('PATCH', f.path + '/findings/' + finding.id, {
        token: f.other.token,
        body: patch,
      })
    ).status,
  ).toBe(403);
  expect(
    (await env.call('PATCH', f.path + '/findings/' + finding.id, { token, body: patch })).status,
  ).toBe(200);
  expect(
    (await env.call('PATCH', f.path + '/findings/' + finding.id, { token, body: patch })).status,
  ).toBe(409);
  expect(
    (
      await env.call('PATCH', f.path + '/findings/' + finding.id, {
        token,
        body: { ...patch, expected_version: 2, state: 'resolved', assignee_user_id: null },
      })
    ).status,
  ).toBe(400);
  await env.c.operations.update(f.p, 'component', f.scope, f.c.id, {
    expectedVersion: 1,
    state: 'disabled',
    reason: 'maintenance',
  });
  expect(
    (await env.call('POST', f.path + '/scans', { token, body: { ...f.scan, run_id: '124' } }))
      .status,
  ).toBe(409);
  expect(
    (
      await env.call('PATCH', f.path + '/findings/' + finding.id, {
        token,
        body: { ...patch, expected_version: 2 },
      })
    ).status,
  ).toBe(409);
});
it('keeps backups separate from reported restores, derives RPO/RTO and refuses unearned verification', async () => {
  const f = await setup();
  const token = f.owner.token;
  for (const body of [
    { ...f.recovery, independently_verified: true },
    { ...f.recovery, audit_check: 'not_run' },
    { ...f.recovery, started_at: new Date(+env.clock.now() + 1000).toISOString() },
    { ...f.recovery, recovery_point_at: f.recovery.completed_at },
    { ...f.recovery, artifact_digest: 'secret' },
    { ...f.recovery, target_rto_seconds: -1 },
  ])
    expect((await env.call('POST', f.path + '/recovery', { token, body })).status).toBe(400);
  expect(
    (
      await env.call('POST', f.path + '/recovery', {
        token,
        body: {
          ...f.recovery,
          kind: 'backup',
          integrity_check: 'not_run',
          application_check: 'not_run',
          audit_check: 'not_run',
        },
      })
    ).status,
  ).toBe(201);
  let view = (await env.call('GET', f.path, { token })).body;
  expect(view.recovery.items.filter((r: { kind: string }) => r.kind === 'restore')).toHaveLength(0);
  expect((await env.call('POST', f.path + '/recovery', { token, body: f.recovery })).status).toBe(
    201,
  );
  view = (await env.call('GET', f.path, { token })).body;
  const restore = view.recovery.items.find((r: { kind: string }) => r.kind === 'restore');
  expect(restore.rpo_seconds).toBe(60);
  expect(restore.rto_seconds).toBe(60);
  expect(restore.target_met).toBe(true);
  expect(restore.independently_verified).toBe(false);
  expect(restore.provenance).toBe('admin_report');
  const events = await env.c.audit.list();
  expect(events.filter((e) => e.action === 'operations.recovery.recorded')).toHaveLength(2);
});

it('preserves reads during freeze, denies mutation and rejects a revoked session in the service', async () => {
  const f = await setup();
  await env.c.privileged.freeze('test-operator', f.org.id, 'test freeze');
  expect(
    (await env.call('POST', f.path + '/scans', { token: f.owner.token, body: f.scan })).status,
  ).toBe(403);
  expect((await env.call('GET', f.path, { token: f.owner.token })).status).toBe(200);
  expect((await env.call('GET', f.path + '?secret=private', { token: f.owner.token })).status).toBe(
    400,
  );
  await env.call('POST', '/v1/auth/logout', { token: f.owner.token, body: {} });
  await expect(env.c.operationsPosture.read(f.p, f.scope)).rejects.toMatchObject({
    code: 'unauthenticated',
  });
});
