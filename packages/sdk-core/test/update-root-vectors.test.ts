import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import {
  SecureUpdateClient,
  MemorySecureStore,
  type UpdateRoot,
  type SignedUpdateEnvelope,
} from '../src/index.ts';
const fixture = JSON.parse(
  readFileSync(new URL('../../../docs/api/update-root-vectors.json', import.meta.url), 'utf8'),
) as {
  cases: Array<{
    name: string;
    root: UpdateRoot;
    envelope: SignedUpdateEnvelope;
    now: number;
    accepted: boolean;
  }>;
};
for (const c of fixture.cases)
  it(`shared .NET rotation vector: ${c.name}`, async () => {
    const client = new SecureUpdateClient({
      root: c.root,
      product: 'sierra-business',
      platform: 'windows-x64',
      channel: 'stable',
      now: () => new Date(c.now * 1000),
      store: new MemorySecureStore(),
    });
    if (c.accepted) {
      await expect(client.rotateRoot(c.envelope)).resolves.toBeUndefined();
      await expect(client.rotateRoot(c.envelope)).rejects.toThrow();
    } else await expect(client.rotateRoot(c.envelope)).rejects.toThrow();
  });
