// Only the disposable local image-check container; never a production URL or credential.
import { readFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
const origin = 'http://127.0.0.1:18080';
const until = globalThis.performance.now() + 30000;
let healthy = false;
while (globalThis.performance.now() < until) {
  try {
    const response = await globalThis.fetch(`${origin}/healthz`, {
      signal: globalThis.AbortSignal.timeout(1000),
    });
    healthy = response.status === 200 && (await response.json()).status === 'ok';
    if (healthy) break;
  } catch {
    /* Bounded cold-start wait. */
  }
  await setTimeout(500);
}
if (!healthy) throw new Error('Local image liveness failed');
const ready = await globalThis.fetch(`${origin}/readyz`, {
  signal: globalThis.AbortSignal.timeout(3000),
});
if (ready.status !== 200 || (await ready.json()).status !== 'ready')
  throw new Error('Local fixture readiness failed');
const hash = (value) => createHash('sha256').update(value).digest('hex');
for (const [path, file] of [
  ['/', 'index.html'],
  ['/portal.css', 'portal.css'],
  ['/portal.mjs', 'portal.mjs'],
  ['/operations.mjs', 'operations.mjs'],
]) {
  const response = await globalThis.fetch(`${origin}${path}`, {
    signal: globalThis.AbortSignal.timeout(3000),
  });
  const expected = readFileSync(
    new URL(`../services/platform-api/src/web/${file}`, import.meta.url),
  );
  if (response.status !== 200 || hash(Buffer.from(await response.arrayBuffer())) !== hash(expected))
    throw new Error('Local image serves unexpected UI assets');
}
console.log(
  'Local non-root Node image: liveness, fixture readiness and exact UI assets passed. This is not production database acceptance.',
);
