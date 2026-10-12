import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';
import { createContainer } from './container.ts';
import { describeConnectionTarget } from './db/connection.ts';
import { startAnchoring } from './anchors.ts';
import { startMaintenance } from './maintenance.ts';

const config = loadConfig();
if (config.persistence === 'postgres' && config.databaseUrl) {
  // Non-secret facts only (never the password): makes a wrong host/user obvious from the first log line.
  const t = describeConnectionTarget(config.databaseUrl);
  console.log(
    `database: host=${t?.host} port=${t?.port} user=${t?.user} schema=${config.dbSchema ?? '(default)'} tls=${config.databaseCaPem ? 'verified (CA configured)' : 'sslmode from URL'}`,
  );
}
const container = await createContainer(config);
const app = await buildApp(container, { logger: true });

if (
  config.env !== 'production' &&
  !process.env['LICENSE_SIGNING_KEY_FILE'] &&
  !process.env['LICENSE_SIGNING_KEY_PEM']
) {
  app.log.warn(
    'using an EPHEMERAL license-signing key: issued leases will not verify after restart (development only)',
  );
}

for (const w of container.dbWarnings) app.log.warn(`database role: ${w}`);

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(
    sig,
    () =>
      void app
        .close()
        .then(() => container.close())
        .then(() => process.exit(0)),
  );
}
const maintenance = startMaintenance(container, {
  everyMs: config.maintenanceIntervalSeconds * 1000,
  onError: (e) =>
    app.log.error(
      { err: { name: (e as Error)?.name, message: (e as Error)?.message } },
      'maintenance failed',
    ),
});
app.addHook('onClose', async () => maintenance.stop());
if (container.anchors && config.auditAnchor) {
  const anchoring = startAnchoring(container.anchors, {
    everyMs: config.auditAnchor.intervalSeconds * 1000,
    onError: (e) =>
      app.log.error(
        { err: { name: (e as Error)?.name, message: (e as Error)?.message } },
        'audit anchoring failed',
      ),
    onOutcome: (o) => {
      if (o.status === 'chain_invalid')
        app.log.error(
          { chain: o.chain, brokenAtSeq: o.brokenAtSeq, reason: o.reason },
          'AUDIT LOG FAILED VERIFICATION: not anchored',
        );
      else if (o.status === 'failed')
        app.log.warn({ error: o.record.error }, 'audit anchor not published');
    },
  });
  app.addHook('onClose', async () => anchoring.stop());
} else if (config.env === 'production') {
  app.log.warn(
    'audit anchoring is DISABLED: a database superuser could rewrite history undetected (R-13)',
  );
}
await app.listen({ host: config.host, port: config.port });

// Private child-process acknowledgement used by the load driver; never exposes settings or secrets.
const address = app.server.address();
if (process.send && process.connected && address && typeof address !== 'string')
  process.send({ type: 'trust-platform-ready', port: address.port }, () => undefined);
