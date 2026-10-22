// Fixed public assets only: no credentials, configurable targets or private records.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { setTimeout } from 'node:timers/promises';
import { checkAvailability } from './check-warrior-availability.mjs';

const origin = 'https://trustplatform-api-production.up.railway.app';
const assets = [
  ['/', 'index.html'],
  ['/portal.css', 'portal.css'],
  ['/portal.mjs', 'portal.mjs'],
  ['/operations.mjs', 'operations.mjs'],
];
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const expected = assets.map(([path, file]) => [
  path,
  digest(readFileSync(new URL(`../services/platform-api/src/web/${file}`, import.meta.url))),
]);

export async function checkRelease(request = globalThis.fetch, timeoutMs = 10000) {
  const health = await checkAvailability(request, timeoutMs);
  if (health.some((entry) => entry.outcome !== 'passed')) return false;
  for (const [path, hash] of expected) {
    const controller = new globalThis.AbortController();
    let reader;
    let timer;
    try {
      const probe = async () => {
        const response = await request(origin + path, {
          redirect: 'error',
          credentials: 'omit',
          cache: 'no-store',
          headers: { 'Cache-Control': 'no-cache' },
          signal: controller.signal,
        });
        reader = response.body?.getReader();
        if (
          response.status !== 200 ||
          response.redirected ||
          Number(response.headers.get('age') ?? '0') !== 0 ||
          !reader
        )
          return false;
        const hashState = createHash('sha256');
        let size = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 1024 * 1024) return false;
          hashState.update(value);
        }
        return hashState.digest('hex') === hash;
      };
      const deadline = new Promise((resolve) => {
        timer = globalThis.setTimeout(() => resolve(false), timeoutMs);
      });
      if (!(await Promise.race([probe(), deadline]))) return false;
    } catch {
      return false;
    } finally {
      globalThis.clearTimeout(timer);
      controller.abort();
      void reader?.cancel().catch(() => {});
    }
  }
  return true;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // Permit a deployment to finish; no probe attempt can exceed this overall window.
  const until = globalThis.performance.now() + 360000;
  let matched = false;
  do {
    const remaining = until - globalThis.performance.now();
    if (remaining <= 0) break;
    matched = await checkRelease(globalThis.fetch, Math.min(5000, remaining / 6));
    if (matched) break;
    if (until - globalThis.performance.now() < 15000) break;
    await setTimeout(15000);
  } while (globalThis.performance.now() < until);
  console.log(
    matched
      ? 'Live health/readiness and release UI assets verified.'
      : 'Live release could not be verified within the deployment window.',
  );
  console.log(
    'Public read-only checks do not establish authenticated workflows or exact backend commit identity.',
  );
  if (!matched) process.exitCode = 1;
}
