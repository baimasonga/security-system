import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { requireVerifiedRelease } from '../../../tools/cloudflare-release-policy.mjs';
const config = () =>
  JSON.parse(
    readFileSync(
      new URL('../../../infrastructure/cloudflare/wrangler.json', import.meta.url),
      'utf8',
    ),
  );
const names = [
  'Format, lint, types, tests',
  'PostgreSQL migration and schema tests',
  'Browser operations workflows',
  'Windows protected-storage integration',
  'Dependency and secret scanning',
  'Cloudflare standby bundle',
  'analyze',
];
const checks = () =>
  names.map((name, id) => ({
    name,
    id,
    status: 'completed',
    conclusion: 'success',
    app: { slug: 'github-actions' },
  }));
it('permits only the disabled fixed-host release after all exact-revision checks pass', () => {
  expect(() => requireVerifiedRelease(config(), checks())).not.toThrow();
});
it.each(['failure', 'cancelled', 'skipped', null])(
  'refuses incomplete or unsuccessful source checks: %s',
  (conclusion) => {
    const rows = checks();
    rows[0].conclusion = conclusion;
    expect(() => requireVerifiedRelease(config(), rows)).toThrow();
  },
);
it('refuses missing checks, other apps and a newer failed attempt', () => {
  expect(() => requireVerifiedRelease(config(), checks().slice(1))).toThrow();
  const rows = checks();
  rows[0].app.slug = 'another-app';
  expect(() => requireVerifiedRelease(config(), rows)).toThrow();
  expect(() =>
    requireVerifiedRelease(config(), [
      ...checks(),
      { ...checks()[0], id: 100, conclusion: 'failure' },
    ]),
  ).toThrow();
});
it.each([
  (c) => (c.vars.TRAFFIC_ENABLED = 'true'),
  (c) => (c.vars.PUBLIC_HOST = 'other.test'),
  (c) => (c.workers_dev = true),
  (c) => (c.preview_urls = true),
  (c) => (c.containers[0].max_instances = 2),
  (c) => (c.routes[0].pattern = 'other.test'),
  (c) => (c.routes[0].custom_domain = false),
])('refuses traffic, route or replica changes in the provisioning workflow', (mutate) => {
  const c = config();
  mutate(c);
  expect(() => requireVerifiedRelease(c, checks())).toThrow();
});
