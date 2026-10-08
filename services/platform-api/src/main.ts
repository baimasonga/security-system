import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';
import { createContainer } from './container.ts';

const config = loadConfig();
const container = createContainer(config);
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

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => void app.close().then(() => process.exit(0)));
}
await app.listen({ host: config.host, port: config.port });
