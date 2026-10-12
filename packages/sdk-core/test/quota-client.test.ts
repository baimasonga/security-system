import { expect, it, vi } from 'vitest';
import { TrustPlatformClient, PlatformError } from '../src/index.ts';

function client(fetcher: typeof fetch) {
  return new TrustPlatformClient({
    baseUrl: 'https://platform.example',
    productCode: 'editor',
    trust: { schema: 1, keys: [] },
    fetch: fetcher,
    store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
  });
}

it('reads online usage with explicit tenant scope and session authorization', async () => {
  const usage = {
    license_id: 'lic_a',
    period: '2026-10',
    resets_at: '2026-11-01T00:00:00.000Z',
    status: 'valid',
    items: [],
  };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json(usage));
  expect(await client(fetcher).getUsage('session', 'org_a', 'lic_a')).toEqual(usage);
  const [url, options] = fetcher.mock.calls[0]!;
  expect(String(url)).toBe('https://platform.example/v1/organizations/org_a/licenses/lic_a/usage');
  expect(options?.headers).toMatchObject({ authorization: 'Bearer session' });
  expect(options?.method).toBe('GET');
});

it('preserves the caller operation ID on retries and forwards exhaustion instead of granting offline access', async () => {
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation(async () =>
      Response.json({ code: 'conflict', message: 'monthly quota exhausted' }, { status: 409 }),
    );
  const sdk = client(fetcher);
  const input = {
    entitlement: 'ocr_pages_monthly',
    units: 3,
    idempotencyKey: 'operation_123456789',
  };
  for (let i = 0; i < 2; i++) {
    await expect(sdk.consumeQuota('session', 'org_a', 'lic_a', input)).rejects.toMatchObject({
      code: 'conflict',
      status: 409,
    });
  }
  expect(fetcher.mock.calls).toHaveLength(2);
  for (const [, options] of fetcher.mock.calls) {
    expect(options?.method).toBe('POST');
    expect(options?.headers).toMatchObject({ authorization: 'Bearer session' });
    expect(JSON.parse(String(options?.body))).toEqual({
      entitlement: input.entitlement,
      units: 3,
      idempotency_key: input.idempotencyKey,
    });
  }
});

it('rejects path injection and missing sessions before any request', async () => {
  const fetcher = vi.fn<typeof fetch>();
  const sdk = client(fetcher);
  await expect(sdk.getUsage('', 'org_a', 'lic_a')).rejects.toBeInstanceOf(PlatformError);
  await expect(sdk.getUsage('session', '../org_b', 'lic_a')).rejects.toBeInstanceOf(PlatformError);
  expect(fetcher).not.toHaveBeenCalled();
});

it('uses the tenant session and a caller-owned durable operation ID for checkout', async () => {
  const response = {
    id: 'bco_example',
    license_id: 'lic_a',
    plan_id: 'pln_a',
    status: 'uncertain',
    checkout_url: null,
    created_at: '2026-10-12T00:00:00Z',
    subscription_status: 'trialing',
    current_period_end: null,
  };
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => Response.json(response));
  const sdk = client(fetcher);
  expect(
    await sdk.createCheckout('session', 'org_a', 'lic_a', 'pln_a', 'checkout-request-001'),
  ).toEqual(response);
  expect(String(fetcher.mock.calls[0]?.[0])).toBe(
    'https://platform.example/v1/organizations/org_a/licenses/lic_a/checkout',
  );
  expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({
    plan_id: 'pln_a',
    idempotency_key: 'checkout-request-001',
  });
  expect(await sdk.getCheckout('session', 'org_a', 'lic_a')).toEqual(response);
  expect(fetcher.mock.calls[1]?.[1]?.method).toBe('GET');
});
