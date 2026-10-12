import { expect, it, vi } from 'vitest';
import { TrustPlatformClient, SoftwareDeviceKey } from '../src/index.ts';

it('uses a host-owned asynchronous key without persisting private PEM', async () => {
  const key = SoftwareDeviceKey.generate();
  const get = vi.fn(async (name: string) =>
    name === 'installation_id' ? 'inst_native' : undefined,
  );
  const set = vi.fn(async (_key: string, _value: string) => {});
  const provider = vi.fn(async (id: string) => {
    expect(id).toBe('inst_native');
    return {
      publicJwk: key.publicJwk,
      thumbprint: key.thumbprint,
      sign: async (message: string) => key.sign(message),
    };
  });
  const sdk = new TrustPlatformClient({
    baseUrl: 'https://example.test',
    productCode: 'editor',
    trust: { schema: 1, keys: [] },
    store: { get, set, delete: async () => {} },
    deviceKeyProvider: provider,
  });
  const a = await sdk.deviceKey();
  expect(await a.sign('proof')).toBe(key.sign('proof'));
  expect(await sdk.deviceKey()).toBe(a);
  expect(provider).toHaveBeenCalledTimes(1);
  expect(get).not.toHaveBeenCalledWith('device_key');
  expect(set).not.toHaveBeenCalled();
});

it('does not fall back to software keys when the host key is unavailable', async () => {
  const set = vi.fn(async (_key: string, _value: string) => {});
  const sdk = new TrustPlatformClient({
    baseUrl: 'https://example.test',
    productCode: 'editor',
    trust: { schema: 1, keys: [] },
    store: { get: async () => 'inst_native', set, delete: async () => {} },
    deviceKeyProvider: async () => {
      throw new Error('hardware key unavailable');
    },
  });
  await expect(sdk.deviceKey()).rejects.toThrow('hardware key unavailable');
  expect(set).not.toHaveBeenCalled();
});

it('serializes concurrent installation and key creation and rejects mismatched identities', async () => {
  const key = SoftwareDeviceKey.generate();
  const provider = vi.fn(async () => ({
    publicJwk: key.publicJwk,
    thumbprint: 'wrong',
    sign: async (message: string) => key.sign(message),
  }));
  const set = vi.fn(async (_key: string, _value: string) => {});
  const sdk = new TrustPlatformClient({
    baseUrl: 'https://example.test',
    productCode: 'editor',
    trust: { schema: 1, keys: [] },
    store: { get: async () => undefined, set, delete: async () => {} },
    deviceKeyProvider: provider,
  });
  const results = await Promise.allSettled([sdk.deviceKey(), sdk.deviceKey()]);
  expect(results.every((r) => r.status === 'rejected')).toBe(true);
  expect(provider).toHaveBeenCalledTimes(1);
  expect(set).toHaveBeenCalledTimes(1);
  expect(set.mock.calls[0]?.[0]).toBe('installation_id');
});

it('awaits native signing when answering an activation challenge and sends only public key members', async () => {
  const key = SoftwareDeviceKey.generate();
  const values = new Map<string, string>();
  let sent: Record<string, unknown> | undefined;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url, opts) => {
    const body = JSON.parse(String(opts?.body));
    if (String(url).endsWith('/challenges')) return Response.json({ nonce: 'challenge' });
    sent = body;
    return Response.json({ code: 'forbidden', message: 'test refusal' }, { status: 403 });
  });
  const sdk = new TrustPlatformClient({
    baseUrl: 'https://example.test',
    productCode: 'editor',
    trust: { schema: 1, keys: [] },
    store: {
      get: async (k) => values.get(k),
      set: async (k, v) => {
        values.set(k, v);
      },
      delete: async () => {},
    },
    fetch: fetcher,
    deviceKeyProvider: async () => ({
      publicJwk: { ...key.publicJwk, d: 'must-not-be-sent' },
      thumbprint: key.thumbprint,
      sign: async (message) => key.sign(message),
    }),
  });
  await expect(sdk.activate('session', 'license')).rejects.toMatchObject({ status: 403 });
  expect(typeof sent?.signature).toBe('string');
  expect(sent?.device_public_key).not.toHaveProperty('d');
});
