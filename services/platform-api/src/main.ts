import { startIdentityMailWorker } from './identity-mail-worker.ts';
import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';
import { createContainer } from './container.ts';
import { describeConnectionTarget } from './db/connection.ts';
import { startAnchoring } from './anchors.ts';
import { startMaintenance } from './maintenance.ts';
import { startSharingWorker } from './sharing-worker.ts';
import { buildContentApp } from './integrations/object-store-local.ts';

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
if (config.emailDelivery && !config.identityMailEncryptionKey)
  app.log.warn(
    'identity email uses direct delivery without durable retry; enable MAIL_OUTBOX_ENCRYPTION_KEY after migration 0010 and app grants',
  );

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
if (config.identityMailEncryptionKey) {
  const mail = startIdentityMailWorker(container, {
    onError: () => app.log.error('identity mail worker failed; pending work remains queued'),
  });
  app.addHook('onClose', async () => mail.stop());
}
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
if (container.sharing && config.sharing) {
  const worker = startSharingWorker(container, {
    everyMs: config.sharing.jobIntervalSeconds * 1000,
    onError: () => app.log.error('sharing worker failed; pending jobs remain queued'),
  });
  app.addHook('onClose', async () => worker.stop());
  if (!config.sharing.clamd)
    app.log.warn(
      'sharing uploads get structural checks only; set CLAMD_HOST to add antivirus scanning',
    );
  const st = config.sharing.storage;
  if (st.kind === 'local' && container.sharingLocalStore) {
    // The isolated content origin: a separate listener that serves only signed object URLs.
    const content = await buildContentApp(container.sharingLocalStore, {
      allowedOrigin: config.sharing.publicOrigin,
      logger: false,
    });
    await content.listen({ host: st.contentHost, port: st.contentPort });
    app.addHook('onClose', async () => content.close());
    app.log.warn(
      `sharing uses LOCAL object storage (development only); content origin ${st.contentOrigin}`,
    );
  }
}
await app.listen({ host: config.host, port: config.port });

// Private child-process acknowledgement used by the load driver; never exposes settings or secrets.
const address = app.server.address();
if (process.send && process.connected && address && typeof address !== 'string')
  process.send({ type: 'trust-platform-ready', port: address.port }, () => undefined);
