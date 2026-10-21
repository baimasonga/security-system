// Independent observer: no integration credential, destination input or Warrior dependency.
import { resolve } from 'node:path';
import { setTimeout, clearTimeout } from 'node:timers';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';

const checks = [
  ['liveness', 'https://trustplatform-api-production.up.railway.app/healthz', 'ok'],
  ['readiness', 'https://trustplatform-api-production.up.railway.app/readyz', 'ready'],
];

export async function checkAvailability(request = globalThis.fetch, timeoutMs = 10000) {
  return Promise.all(
    checks.map(async ([check, url, expected]) => {
      const controller = new globalThis.AbortController();
      let timer;
      let reader;
      const probe = async () => {
        const response = await request(url, {
          method: 'GET',
          redirect: 'error',
          credentials: 'omit',
          cache: 'no-store',
          headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
          signal: controller.signal,
        });
        reader = response.body?.getReader();
        if (
          response.status !== 200 ||
          response.redirected ||
          !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '') ||
          Number(response.headers.get('age') ?? '0') !== 0 ||
          !reader
        )
          return false;
        const chunks = [];
        let size = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 1024) return false;
          chunks.push(value);
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.byteLength;
        }
        const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        return (
          body !== null &&
          typeof body === 'object' &&
          !Array.isArray(body) &&
          Object.keys(body).length === 1 &&
          body.status === expected
        );
      };
      try {
        const expired = new Promise((resolve) => {
          timer = setTimeout(() => {
            controller.abort();
            resolve(false);
          }, timeoutMs);
        });
        const passed = await Promise.race([probe(), expired]);
        return { check, outcome: passed ? 'passed' : 'failed' };
      } catch {
        // Never print provider bodies, errors, headers, redirects or URLs.
        return { check, outcome: 'failed' };
      } finally {
        clearTimeout(timer);
        controller.abort();
        void reader?.cancel().catch(() => {});
      }
    }),
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const results = await checkAvailability();
  console.log(JSON.stringify({ observer: 'github_external', results }));
  process.exitCode = results.every((r) => r.outcome === 'passed') ? 0 : 1;
}
