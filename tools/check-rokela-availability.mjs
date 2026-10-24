// Independent observer for Rokela PDF (https://www.rokelapdf.com): runs on GitHub-hosted runners, so it still
// reports when Railway (which hosts both Rokela PDF and Warrior) is down. Fixed public URLs only; no credentials,
// destination input or Warrior dependency. A failing check fails the scheduled job, and GitHub's own failed-run
// notification is the alert. It proves only what each request saw, never connected-application health.
import { resolve } from 'node:path';
import { setTimeout, clearTimeout } from 'node:timers';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';

const origin = 'https://www.rokelapdf.com';

// [check, url, content type, byte limit, body predicate]
const checks = [
  // Liveness plus database reachability: the app answers exactly {"ok":true}.
  [
    'health',
    `${origin}/api/v1/health`,
    /^application\/json(?:\s*;|$)/i,
    1024,
    (text) => {
      const body = JSON.parse(text);
      return (
        body !== null &&
        typeof body === 'object' &&
        !Array.isArray(body) &&
        Object.keys(body).length === 1 &&
        body.ok === true
      );
    },
  ],
  // The sign-in page itself, served directly: a redirect (such as the loop of 24 October 2026) or an error page fails.
  [
    'signin',
    `${origin}/signin`,
    /^text\/html(?:\s*;|$)/i,
    256 * 1024,
    (text) => text.includes('<title>Rokela PDF Pro</title>'),
  ],
];

export async function checkRokelaAvailability(request = globalThis.fetch, timeoutMs = 10000) {
  return Promise.all(
    checks.map(async ([check, url, contentType, limit, accept]) => {
      const controller = new globalThis.AbortController();
      let timer;
      let reader;
      const probe = async () => {
        const response = await request(url, {
          method: 'GET',
          redirect: 'error',
          credentials: 'omit',
          cache: 'no-store',
          headers: { Accept: 'application/json, text/html', 'Cache-Control': 'no-cache' },
          signal: controller.signal,
        });
        reader = response.body?.getReader();
        if (
          response.status !== 200 ||
          response.redirected ||
          !contentType.test(response.headers.get('content-type') ?? '') ||
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
          if (size > limit) return false;
          chunks.push(value);
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.byteLength;
        }
        return accept(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
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
  const results = await checkRokelaAvailability();
  console.log(JSON.stringify({ observer: 'github_external', application: 'rokela-pdf', results }));
  process.exitCode = results.every((r) => r.outcome === 'passed') ? 0 : 1;
}
