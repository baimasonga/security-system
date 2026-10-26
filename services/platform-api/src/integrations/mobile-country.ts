import { isIP } from 'node:net';
import { open, type Reader, type CountryResponse } from 'maxmind';

export const WARRIOR_PUBLIC_DOMAIN = 'trustplatform-api-production.up.railway.app';
/** Enable the documented Railway edge header only in the intended deployment. */
export function railwayCountrySourceEnabled(env: NodeJS.ProcessEnv) {
  return (
    env['MOBILE_USE_RAILWAY_IP'] === '1' &&
    env['RAILWAY_PUBLIC_DOMAIN'] === WARRIOR_PUBLIC_DOMAIN &&
    env['RAILWAY_SERVICE_ID'] === '65ed934a-51a6-428a-8ba6-95f8f3bd6a18' &&
    env['RAILWAY_PROJECT_ID'] === '05a9a91d-5099-4e32-897e-d882b9367ef2' &&
    env['RAILWAY_ENVIRONMENT_ID'] === '1e6c985f-6089-403c-a2b1-d80b6dedd357'
  );
}
export function railwayClientIp(headers: Record<string, unknown>): string {
  if (headers['host'] !== WARRIOR_PUBLIC_DOMAIN) return '';
  const ip = headers['x-real-ip'];
  return typeof ip === 'string' && ip.length <= 45 && isIP(ip) ? ip : '';
}

export interface CountryStatus {
  state: 'not_configured' | 'unavailable' | 'stale' | 'ready';
  built_at: string | null;
}
/** Local country database; never sends IPs to a provider or exposes filesystem paths. */
export function createCountryLookup(path?: string, now = () => new Date()) {
  let database: Promise<Reader<CountryResponse>> | undefined;
  let retryAt = 0;
  const load = async () => {
    if (!path || +now() < retryAt) return null;
    try {
      database ??= open<CountryResponse>(path);
      const loaded = await database;
      if (!/^[A-Z]{2}$/.test(loaded.get('8.8.8.8')?.country?.iso_code ?? '')) return null;
      return loaded;
    } catch {
      database = undefined;
      retryAt = +now() + 30000;
      return null;
    }
  };
  const describe = (reader: Reader<CountryResponse> | null): CountryStatus => {
    if (!path) return { state: 'not_configured', built_at: null };
    const built = reader?.metadata.buildEpoch;
    if (
      !reader ||
      !built ||
      !Number.isFinite(+built) ||
      !/country/i.test(reader.metadata.databaseType) ||
      +built > +now() + 7 * 86400000
    )
      return { state: 'unavailable', built_at: null };
    return {
      state: +now() - +built > 120 * 86400000 ? 'stale' : 'ready',
      built_at: built.toISOString(),
    };
  };
  const lookup = async (ip: string): Promise<string | null> => {
    if (!isIP(ip)) return null;
    const reader = await load();
    if (!reader || describe(reader).state !== 'ready') return null;
    try {
      const country = reader.get(ip)?.country?.iso_code;
      return country && /^[A-Z]{2}$/.test(country) ? country : null;
    } catch {
      return null;
    }
  };
  return Object.assign(lookup, { status: async () => describe(await load()) });
}
/** Only the configured number of ingress-added hops is trusted, never a supplied country. */
export function mobileClientIp(forwarded: string | undefined, hops: number): string {
  if (!Number.isInteger(hops) || hops < 1 || hops > 5 || !forwarded || forwarded.length > 1024)
    return '';
  const parts = forwarded.split(',').map((s) => s.trim());
  const ip = parts[parts.length - hops];
  return ip && isIP(ip) ? ip : '';
}
