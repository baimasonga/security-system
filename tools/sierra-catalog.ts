import { TIERS } from '@trust/shared-types';
import { validateDeviceLimit } from '@trust/entitlements';
export class CatalogSetupError extends Error {}
export type CatalogRequest = (
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
) => Promise<unknown>;
export interface SierraCatalogOptions {
  planCode: string;
  tier: string;
  deviceLimit: number;
  reason: string;
  apply?: boolean;
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new CatalogSetupError('invalid API response');
  return value as Record<string, unknown>;
}
function items(value: unknown) {
  const list = object(value).items;
  if (!Array.isArray(list)) throw new CatalogSetupError('invalid API response');
  return list.map(object);
}
function identifier(value: unknown, prefix: string): string {
  if (
    typeof value !== 'string' ||
    !value.startsWith(prefix + '_') ||
    !/^[a-z]{2,4}_[0-9a-f]{24}$/.test(value)
  )
    throw new CatalogSetupError('invalid API identifier');
  return value;
}
export async function provisionSierraCatalog(
  request: CatalogRequest,
  options: SierraCatalogOptions,
) {
  if (
    !/^[a-z0-9][a-z0-9-]{1,63}$/.test(options.planCode) ||
    !(TIERS as readonly string[]).includes(options.tier) ||
    options.reason.trim().length < 3 ||
    options.reason.trim().length > 500
  )
    throw new CatalogSetupError('invalid catalog settings');
  try {
    validateDeviceLimit(options.deviceLimit);
  } catch {
    throw new CatalogSetupError('invalid device limit');
  }
  if (object(await request('GET', '/v1/auth/me')).platform_role !== 'platform_admin')
    throw new CatalogSetupError('platform operator session required');
  const products = items(await request('GET', '/v1/catalog/products')).filter(
    (p) => p.code === 'sierra-business',
  );
  if (products.length > 1) throw new CatalogSetupError('ambiguous product catalog');
  let product = products[0];
  const created: string[] = [];
  if (!product && options.apply) {
    product = object(
      await request('POST', '/v1/admin/products', {
        code: 'sierra-business',
        name: 'Rokela Business Admin',
        reason: options.reason.trim(),
      }),
    );
    created.push('product');
  }
  const productId = product ? identifier(product.id, 'prd') : null;
  if (product && (product.code !== 'sierra-business' || product.status !== 'active'))
    throw new CatalogSetupError('product mismatch');
  const plans = productId
    ? items(await request('GET', `/v1/catalog/products/${productId}/plans`)).filter(
        (p) => p.code === options.planCode,
      )
    : [];
  if (plans.length > 1) throw new CatalogSetupError('ambiguous plan catalog');
  let plan = plans[0];
  if (!plan && productId && options.apply) {
    plan = object(
      await request('POST', `/v1/admin/products/${productId}/plans`, {
        code: options.planCode,
        tier: options.tier,
        device_limit: options.deviceLimit,
        entitlements: { business_write: true },
        capabilities: [],
        reason: options.reason.trim(),
      }),
    );
    created.push('plan');
  }
  if (
    plan &&
    (plan.product_id !== productId ||
      plan.code !== options.planCode ||
      plan.tier !== options.tier ||
      plan.device_limit !== options.deviceLimit ||
      object(plan.entitlements).business_write !== true)
  )
    throw new CatalogSetupError(
      'existing plan mismatch; review in operator console instead of overwriting',
    );
  const planId = plan ? identifier(plan.id, 'pln') : null;
  const missing = [...(!product ? ['product'] : []), ...(!plan ? ['plan'] : [])];
  return {
    productCode: 'sierra-business',
    planCode: options.planCode,
    productId,
    planId,
    ready: missing.length === 0,
    missing,
    created,
    mode: options.apply ? 'apply' : 'preview',
  };
}

/** No redirects: operator bearer credentials must remain on the explicitly selected origin. */
export function catalogHttpRequest(
  origin: string,
  token: string,
  allowLocal = false,
  fetcher: typeof fetch = fetch,
): CatalogRequest {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new CatalogSetupError('invalid API origin');
  }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (
    (url.protocol !== 'https:' && !(allowLocal && loopback && url.protocol === 'http:')) ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  )
    throw new CatalogSetupError(
      'API origin must be HTTPS without credentials, path, query or fragment',
    );
  if (!token || /[\r\n]/.test(token))
    throw new CatalogSetupError('TRUST_OPERATOR_TOKEN is required');
  return async (method, path, body) => {
    if (!path.startsWith('/v1/') || new URL(path, url).origin !== url.origin)
      throw new CatalogSetupError('invalid API request path');
    try {
      const response = await fetcher(new URL(path, url), {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(30_000),
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) throw new CatalogSetupError(`API HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      if (error instanceof CatalogSetupError && /^API HTTP [0-9]{3}$/.test(error.message))
        throw error;
      throw new CatalogSetupError(
        'API request failed; check access and rerun preview before any retry',
      );
    }
  };
}
