/** Operator-local, read-only collector. Raw provider bodies and credentials never leave this process. */
import { pathToFileURL } from 'node:url';
import { EnvHttpProxyAgent } from 'undici';
import { normalizeSecurityExport } from './normalize-security-export.ts';

export interface GitHubCollectionOptions {
  source: string;
  repository: string;
  revision: string;
  runId: string;
  componentId: string;
}
interface Dependencies {
  token: string;
  request: typeof fetch;
  now?: () => Date;
}
const refused = () => new Error('GitHub security collection refused');
const API = 'https://api.github.com';
const ALERT_BYTES = 10 * 1024 * 1024;

async function readJson(response: Response, maxBytes: number): Promise<unknown> {
  if (
    response.status !== 200 ||
    !/^application\/(?:json|vnd\.github\+json)(?:;|$)/i.test(
      response.headers.get('content-type') ?? '',
    ) ||
    response.headers.has('link') ||
    Number(response.headers.get('content-length')) > maxBytes
  ) {
    void response.body?.cancel().catch(() => undefined);
    throw refused();
  }
  const reader = response.body?.getReader();
  if (!reader) throw refused();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) throw refused();
      chunks.push(chunk.value);
    }
    return JSON.parse(Buffer.concat(chunks, size).toString('utf8')) as unknown;
  } finally {
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function collectGitHubSecurity(options: GitHubCollectionOptions, d: Dependencies) {
  try {
    const repository = options.repository.toLowerCase();
    if (
      !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9_.-]{1,100}$/.test(repository) ||
      ['.', '..'].includes(repository.split('/')[1]!) ||
      !d.token ||
      d.token.length > 4096 ||
      /[\r\n]/.test(d.token)
    )
      throw refused();
    const now = d.now ?? (() => new Date());
    const normalized = { ...options, repository, completedAt: now().toISOString() };
    // Validate every selector through the same strict import contract before using it in a URL.
    normalizeSecurityExport([], normalized);
    const signal = AbortSignal.timeout(15_000);
    const init: RequestInit = {
      method: 'GET',
      redirect: 'error',
      signal,
      headers: {
        authorization: `Bearer ${d.token}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'Warrior-read-only-security-collector',
      },
    };
    const commit = await readJson(
      await d.request(`${API}/repos/${repository}/commits/${options.revision}`, init),
      64 * 1024,
    );
    if (
      !commit ||
      typeof commit !== 'object' ||
      (commit as Record<string, unknown>)['sha'] !== options.revision
    )
      throw refused();
    const path = options.source === 'github_dependabot' ? 'dependabot' : 'secret-scanning';
    const alerts = await readJson(
      await d.request(`${API}/repos/${repository}/${path}/alerts?state=open&per_page=100`, init),
      ALERT_BYTES,
    );
    if (!Array.isArray(alerts) || alerts.some(Array.isArray)) throw refused();
    return normalizeSecurityExport(alerts, { ...normalized, completedAt: now().toISOString() });
  } catch {
    // Never include provider bodies, URLs, credentials or arbitrary error messages.
    throw refused();
  }
}

export function parseCollectorArgs(args: string[]): GitHubCollectionOptions {
  const fields: Record<string, keyof GitHubCollectionOptions> = {
    '--source': 'source',
    '--repository': 'repository',
    '--revision': 'revision',
    '--run-id': 'runId',
    '--component': 'componentId',
  };
  const result: Partial<GitHubCollectionOptions> = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = fields[args[i]!];
    if (!key || result[key] !== undefined || !args[i + 1] || args[i + 1]!.startsWith('--'))
      throw refused();
    result[key] = args[i + 1]!;
  }
  if (Object.keys(result).length !== 5) throw refused();
  return result as GitHubCollectionOptions;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const dispatcher = new EnvHttpProxyAgent();
  try {
    const report = await collectGitHubSecurity(parseCollectorArgs(process.argv.slice(2)), {
      token: process.env['GITHUB_SECURITY_TOKEN'] ?? '',
      request: (url, init) => fetch(url, { ...init, dispatcher } as unknown as RequestInit),
    });
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } catch {
    process.stderr.write(
      'GitHub security collection refused. Check read-only access, selectors, provider availability and complete-result limits. No source values were printed.\n',
    );
    process.exitCode = 1;
  } finally {
    await dispatcher.close();
  }
}
