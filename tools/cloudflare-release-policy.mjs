// Manual deployment still requires the exact source revision's independent CI checks.
const required = [
  'Format, lint, types, tests',
  'PostgreSQL migration and schema tests',
  'Browser operations workflows',
  'Windows protected-storage integration',
  'Dependency and secret scanning',
  'Cloudflare standby bundle',
  'analyze',
];
export function requireVerifiedRelease(config, checks) {
  if (
    config.name !== 'warrior-standby' ||
    config.vars?.TRAFFIC_ENABLED !== 'false' ||
    config.vars?.PUBLIC_HOST !== 'warrior.quantixsl.com' ||
    config.workers_dev !== false ||
    config.preview_urls !== false ||
    config.containers?.length !== 1 ||
    config.containers[0].max_instances !== 1 ||
    config.routes?.length !== 1 ||
    config.routes[0].pattern !== 'warrior.quantixsl.com' ||
    config.routes[0].custom_domain !== true
  )
    throw new Error('Only the disabled, scoped Cloudflare deployment is permitted');
  for (const name of required) {
    const latest = checks
      .filter((c) => c.name === name && c.app?.slug === 'github-actions')
      .sort((a, b) => b.id - a.id)[0];
    if (!latest || latest.status !== 'completed' || latest.conclusion !== 'success')
      throw new Error('Required source checks have not completed successfully');
  }
}
