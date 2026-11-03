import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import {
  SecureUpdateClient,
  MemorySecureStore,
  type UpdateRoot,
  type SignedUpdateEnvelope,
} from '../src/index.ts';
interface Vector {
  name: string;
  root: UpdateRoot;
  envelope: SignedUpdateEnvelope;
  now: number;
  product: string;
  platform: string;
  channel: string;
  accepted: boolean;
}
const fixture = JSON.parse(
  readFileSync(new URL('../../../docs/api/update-metadata-vectors.json', import.meta.url), 'utf8'),
) as { cases: Vector[] };
for (const c of fixture.cases)
  it(`shared .NET metadata vector: ${c.name}`, async () => {
    const run = async () => {
      const client = new SecureUpdateClient({
        root: c.root,
        product: c.product,
        platform: c.platform,
        channel: c.channel,
        now: () => new Date(c.now * 1000),
        store: new MemorySecureStore(),
      });
      return client.verifyManifest(c.envelope);
    };
    if (c.accepted) {
      const m = await run();
      expect(m.sequence).toBe(2);
      expect(m.artifact.sha256).toBe('a'.repeat(64));
    } else await expect(run()).rejects.toThrow();
  });
