import { isIP } from 'node:net';
import { open, type Reader, type CountryResponse } from 'maxmind';

/** Local DB-IP/GeoLite-compatible country database; never sends IPs to a provider. */
export function createCountryLookup(path?: string) {
  let database: Promise<Reader<CountryResponse>> | undefined;
  return async (ip: string): Promise<string | null> => {
    if (!path || !isIP(ip)) return null;
    try {
      database ??= open<CountryResponse>(path);
      const record = (await database).get(ip);
      const country = record?.country?.iso_code;
      return country && /^[A-Z]{2}$/.test(country) ? country : null;
    } catch {
      database = undefined;
      return null;
    }
  };
}
/** Only the configured number of ingress-added hops is trusted, never a supplied country. */
export function mobileClientIp(forwarded: string | undefined, hops: number): string {
  if (!Number.isInteger(hops) || hops < 1 || hops > 5 || !forwarded || forwarded.length > 1024)
    return '';
  const parts = forwarded.split(',').map((s) => s.trim());
  const ip = parts[parts.length - hops];
  return ip && isIP(ip) ? ip : '';
}
