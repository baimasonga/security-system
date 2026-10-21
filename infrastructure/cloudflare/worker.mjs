import { Container } from '@cloudflare/containers';
import { runtimeConfig, forward } from './config.mjs';

export class WarriorContainer extends Container {
  defaultPort = 8080;
  sleepAfter = '10m';
  envVars = runtimeConfig(this.env);
  // The application's durable workers must continue during quiet HTTP periods.
  async onActivityExpired() {
    await this.renewActivityTimeout();
  }
  onError() {
    throw new Error('Container unavailable');
  }
}

export default { fetch: forward };
