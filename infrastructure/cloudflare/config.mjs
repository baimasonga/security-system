// The Worker may forward only reviewed runtime settings, never deployment-owner credentials.
const allowed = new Set(
  `DATABASE_URL DATABASE_CA_PEM DB_SCHEMA DB_POOL_MAX
LICENSE_KEY_PEPPER PSEUDONYM_KEY LICENSE_SIGNING_KEY_PEM MFA_ENCRYPTION_KEY
MAIL_OUTBOX_ENCRYPTION_KEY REQUIRE_OPERATOR_MFA PRIVILEGED_DUAL_CONTROL DEVICE_POLICY
PUBLIC_ORIGIN AUDIT_ANCHOR_URL AUDIT_ANCHOR_TOKEN AUDIT_ANCHOR_DISABLED
OPERATIONS_INVENTORY_ENABLED OPERATIONS_CREDENTIALS_ENABLED OPERATIONS_INGESTION_ENABLED
OPERATIONS_HEALTH_ENABLED OPERATIONS_INCIDENTS_ENABLED OPERATIONS_AUTOMATION_ENABLED
OPERATIONS_POSTURE_ENABLED OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED MAIL_PROVIDER
RESEND_API_KEY CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_EMAIL_API_TOKEN EMAIL_FROM WEBAUTHN_RP_ID WEBAUTHN_ORIGIN
WEBAUTHN_RP_NAME SHARING_STORAGE SHARING_S3_ENDPOINT SHARING_S3_REGION SHARING_S3_BUCKET
SHARING_S3_ACCESS_KEY_ID SHARING_S3_SECRET_ACCESS_KEY SHARING_SECRET SHARING_PUBLIC_ORIGIN
SHARING_SHORT_ORIGIN SHARING_CONTENT_ORIGIN SHARING_CONTENT_HOST SHARING_BLOCKED_HOSTS
CLAMD_HOST CLAMD_PORT PADDLE_API_KEY PADDLE_CLIENT_TOKEN PADDLE_ENVIRONMENT
PADDLE_PRICE_MAP PADDLE_WEBHOOK_SECRET PADDLE_PAYMENT_URL`.split(/\s+/),
);

export function runtimeConfig(bindings) {
  try {
    const values = {};
    for (const [key, value] of Object.entries(bindings)) {
      if (['WARRIOR', 'TRAFFIC_ENABLED', 'PUBLIC_HOST'].includes(key)) continue;
      if (
        !allowed.has(key) ||
        typeof value !== 'string' ||
        new globalThis.TextEncoder().encode(value).length > 5000
      )
        throw new Error();
      values[key] = value;
    }
    for (const key of [
      'DATABASE_URL',
      'DATABASE_CA_PEM',
      'DB_SCHEMA',
      'LICENSE_KEY_PEPPER',
      'PSEUDONYM_KEY',
      'LICENSE_SIGNING_KEY_PEM',
      'PUBLIC_ORIGIN',
    ])
      if (!values[key]) throw new Error();
    const origin = new globalThis.URL(values.PUBLIC_ORIGIN);
    if (
      origin.protocol !== 'https:' ||
      origin.host !== bindings.PUBLIC_HOST ||
      origin.origin !== values.PUBLIC_ORIGIN ||
      origin.username ||
      origin.password
    )
      throw new Error();
    if (values.CLAMD_HOST?.endsWith('.railway.internal')) throw new Error();
    return {
      ...values,
      NODE_ENV: 'production',
      PERSISTENCE: 'postgres',
      HOST: '0.0.0.0',
      PORT: '8080',
      TRUST_PROXY: 'true',
      RATE_LIMIT_STORE: 'postgres',
    };
  } catch {
    throw new Error('Standby configuration is unavailable');
  }
}

const unavailable = () =>
  new globalThis.Response('Service unavailable', {
    status: 503,
    headers: { 'Cache-Control': 'no-store', 'Retry-After': '30' },
  });

export async function forward(request, bindings) {
  if (bindings.TRAFFIC_ENABLED !== 'true') return unavailable();
  try {
    const origin = new globalThis.URL(request.url);
    if (origin.protocol !== 'https:' || origin.host !== bindings.PUBLIC_HOST) return unavailable();
    runtimeConfig(bindings);
    const ip = request.headers.get('CF-Connecting-IP');
    if (!ip || !/^[0-9a-fA-F:.]{2,45}$/.test(ip)) return unavailable();
    const headers = new globalThis.Headers(request.headers);
    for (const key of [
      'forwarded',
      'x-forwarded-for',
      'x-forwarded-host',
      'x-forwarded-proto',
      'x-real-ip',
    ])
      headers.delete(key);
    headers.set('X-Forwarded-For', ip);
    headers.set('X-Forwarded-Proto', 'https');
    headers.set('X-Forwarded-Host', origin.host);
    return await bindings.WARRIOR.getByName('warrior-singleton').fetch(
      new globalThis.Request(request, { headers }),
    );
  } catch {
    return unavailable();
  }
}
