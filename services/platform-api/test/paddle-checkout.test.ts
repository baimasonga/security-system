import { expect, it, vi } from 'vitest';
import { PaddleCheckoutProvider } from '../src/integrations/billing.ts';
const txn = 'txn_' + 'a'.repeat(26),
  price = 'pri_' + 'b'.repeat(26),
  intent = 'bco_' + 'c'.repeat(24);
const result = () => ({
  data: {
    id: txn,
    status: 'draft',
    collection_mode: 'automatic',
    custom_data: { trust_checkout_id: intent },
    items: [{ price: { id: price }, quantity: 1 }],
    checkout: { url: 'https://pay.example/checkout?_ptxn=' + txn },
  },
});
function setup(fetcher: typeof fetch, environment: 'sandbox' | 'live' = 'sandbox') {
  return new PaddleCheckoutProvider({
    apiKey: 'test-provider-key',
    environment,
    paymentUrl: 'https://pay.example/checkout',
    fetch: fetcher,
  });
}
it('creates an automatic catalog transaction at the fixed sandbox endpoint and checks its binding', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json(result(), { status: 201 }));
  expect(await setup(fetcher).createCheckout({ intentId: intent, priceId: price })).toEqual({
    transactionId: txn,
    url: 'https://pay.example/checkout?_ptxn=' + txn,
    status: 'draft',
  });
  const [url, opts] = fetcher.mock.calls[0]!;
  expect(url).toBe('https://sandbox-api.paddle.com/transactions');
  expect(opts?.redirect).toBe('error');
  expect(JSON.parse(String(opts?.body))).toEqual({
    items: [{ price_id: price, quantity: 1 }],
    collection_mode: 'automatic',
    custom_data: { trust_checkout_id: intent },
    checkout: { url: 'https://pay.example/checkout' },
  });
  expect(opts?.headers).toMatchObject({ authorization: 'Bearer test-provider-key' });
});
it('retrieves a known transaction for reconciliation using the same server mapping', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json(result()));
  await setup(fetcher, 'live').getCheckout(txn, { intentId: intent, priceId: price });
  expect(fetcher.mock.calls[0]?.[0]).toBe('https://api.paddle.com/transactions/' + txn);
  expect(fetcher.mock.calls[0]?.[1]?.method).toBe('GET');
});
it.each([
  () => {
    const r = result();
    r.data.checkout.url = 'https://evil.example/?_ptxn=' + txn;
    return r;
  },
  () => {
    const r = result();
    r.data.checkout.url = 'https://pay.example/checkout?_ptxn=txn_wrong';
    return r;
  },
  () => {
    const r = result();
    r.data.custom_data.trust_checkout_id = 'other';
    return r;
  },
  () => {
    const r = result();
    r.data.items[0]!.price.id = 'pri_wrong';
    return r;
  },
  () => {
    const r = result();
    r.data.collection_mode = 'manual';
    return r;
  },
])(
  'rejects redirect, transaction, intent, price and collection-mode substitution',
  async (response) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json(response()));
    await expect(
      setup(fetcher).createCheckout({ intentId: intent, priceId: price }),
    ).rejects.toThrow('invalid billing provider response');
  },
);
it('never retries an ambiguous provider submission and sanitizes exceptions', async () => {
  const fetcher = vi
    .fn<typeof fetch>()
    .mockRejectedValue(new Error('secret key exposed by transport'));
  await expect(setup(fetcher).createCheckout({ intentId: intent, priceId: price })).rejects.toThrow(
    'billing checkout outcome uncertain',
  );
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it('rejects missing credentials, insecure payment URLs and malformed identifiers before calling', async () => {
  const fetcher = vi.fn<typeof fetch>();
  expect(
    () =>
      new PaddleCheckoutProvider({
        apiKey: '',
        environment: 'sandbox',
        paymentUrl: 'https://pay.example',
        fetch: fetcher,
      }),
  ).toThrow();
  expect(
    () =>
      new PaddleCheckoutProvider({
        apiKey: 'key',
        environment: 'sandbox',
        paymentUrl: 'http://pay.example',
        fetch: fetcher,
      }),
  ).toThrow();
  await expect(
    setup(fetcher).createCheckout({ intentId: '../other', priceId: price }),
  ).rejects.toThrow('invalid checkout');
  expect(fetcher).not.toHaveBeenCalled();
});
