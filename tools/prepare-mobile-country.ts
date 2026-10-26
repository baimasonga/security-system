// Build-time public data only. No user IPs, API keys, or configurable download hosts.
import { createHash } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { Reader, type CountryResponse } from 'maxmind';

const MAX_DOWNLOAD = 16 * 1024 * 1024;
const MAX_DATABASE = 64 * 1024 * 1024;
export async function prepareCountry(
  directory: string,
  edition: string,
  request: typeof fetch = fetch,
  now = new Date(),
  timeoutMs = 30000,
) {
  if (!/^20\d{2}-(0[1-9]|1[0-2])$/.test(edition)) throw new Error('invalid country edition');
  const source = `https://download.db-ip.com/free/dbip-country-lite-${edition}.mmdb.gz`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const response = await request(source, {
      redirect: 'error',
      credentials: 'omit',
      signal: controller.signal,
    });
    if (response.status !== 200 || response.redirected || !response.body)
      throw new Error('country download unavailable');
    if (Number(response.headers.get('content-length') ?? '0') > MAX_DOWNLOAD)
      throw new Error('country download too large');
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_DOWNLOAD) throw new Error('country download too large');
      chunks.push(next.value);
    }
    const bytes = gunzipSync(Buffer.concat(chunks), { maxOutputLength: MAX_DATABASE });
    const database = new Reader<CountryResponse>(bytes);
    const built = database.metadata.buildEpoch;
    const start = Date.parse(`${edition}-01T00:00:00Z`);
    if (
      !/country/i.test(database.metadata.databaseType) ||
      !Number.isFinite(+built) ||
      +built < start - 32 * 86400000 ||
      +built > start + 32 * 86400000 ||
      +built < +now - 120 * 86400000 ||
      +built > +now + 7 * 86400000 ||
      !/^[A-Z]{2}$/.test(database.get('8.8.8.8')?.country?.iso_code ?? '')
    )
      throw new Error('invalid country database');
    const manifest = {
      provider: 'DB-IP Lite',
      license: 'CC BY 4.0',
      attribution: 'https://db-ip.com/',
      edition,
      source,
      built_at: built.toISOString(),
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
    await mkdir(directory, { recursive: true });
    const target = join(directory, 'mobile-country.mmdb');
    await writeFile(target + '.tmp', bytes, { mode: 0o644 });
    await rename(target + '.tmp', target);
    await writeFile(
      join(directory, 'mobile-country.json'),
      JSON.stringify(manifest, null, 2) + '\n',
    );
    return manifest;
  } finally {
    clearTimeout(timer);
    controller.abort();
    await reader?.cancel().catch(() => undefined);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const directory = process.argv[2];
  const edition = process.argv[3];
  if (!directory || !edition)
    throw new Error('usage: prepare-mobile-country.ts DIRECTORY YYYY-MM [--optional]');
  try {
    console.log(JSON.stringify(await prepareCountry(directory, edition)));
  } catch {
    if (!process.argv.includes('--optional')) {
      console.error('Country database preparation failed; no verified artifact produced.');
      process.exitCode = 1;
    } else {
      // A country-data outage must not prevent the security platform from deploying.
      await mkdir(directory, { recursive: true });
      await rm(join(directory, 'mobile-country.mmdb'), { force: true });
      await rm(join(directory, 'mobile-country.mmdb.tmp'), { force: true });
      await rm(join(directory, 'mobile-country.json'), { force: true });
      console.log('Country database unavailable; runtime will report unknown country.');
    }
  }
}
