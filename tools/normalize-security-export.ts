/** Local-only normalizer: raw provider exports never enter Warrior or its logs. */
import { createHash } from 'node:crypto';
import { readSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { scanInput } from '../packages/operations/src/posture.ts';
export function normalizeSecurityExport(
  raw: unknown,
  options: {
    source: string;
    repository: string;
    revision: string;
    runId: string;
    completedAt: string;
    componentId: string;
  },
) {
  if (!/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(options.repository))
    throw new Error('invalid export');
  const rows = Array.isArray(raw) ? raw.flat(1) : null;
  if (!rows || rows.length > 100) throw new Error('invalid export');
  const findings = rows.map((entry: unknown) => {
    if (!entry || typeof entry !== 'object') throw new Error('invalid export');
    const r = entry as Record<string, unknown>;
    if (!Number.isSafeInteger(r['number']) || Number(r['number']) < 1 || r['state'] !== 'open')
      throw new Error('invalid export');
    const advisory = r['security_advisory'] as Record<string, unknown> | undefined;
    return {
      fingerprint: createHash('sha256')
        .update(JSON.stringify([options.source, options.repository, r['number']]))
        .digest('hex'),
      severity: options.source === 'github_secret_scanning' ? 'critical' : advisory?.['severity'],
      advisory_id:
        options.source === 'github_secret_scanning'
          ? null
          : (advisory?.['ghsa_id'] ?? advisory?.['cve_id']),
    };
  });
  const result = scanInput.safeParse({
    component_id: options.componentId,
    source: options.source,
    revision: options.revision,
    run_id: options.runId,
    completed_at: options.completedAt,
    outcome: 'completed',
    findings,
    reason: 'initial_setup',
  });
  if (!result.success) throw new Error('invalid export');
  return result.data;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const flags = process.argv.slice(2);
    const get = (flag: string) => {
      const i = flags.indexOf(flag);
      if (i < 0 || !flags[i + 1]) throw new Error('invalid arguments');
      return flags[i + 1]!;
    };
    const chunks: Buffer[] = [];
    let size = 0;
    for (;;) {
      const chunk = Buffer.alloc(8192);
      const n = readSync(0, chunk, 0, chunk.length, null);
      if (!n) break;
      size += n;
      if (size > 10 * 1024 * 1024) throw new Error('export too large');
      chunks.push(chunk.subarray(0, n));
    }
    const raw = Buffer.concat(chunks, size);
    const report = normalizeSecurityExport(JSON.parse(raw.toString()), {
      source: get('--source'),
      repository: get('--repository'),
      revision: get('--revision'),
      runId: get('--run-id'),
      completedAt: get('--completed-at'),
      componentId: get('--component'),
    });
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } catch {
    process.stderr.write(
      'Security export refused: check schema, pagination, open-alert scope and the 100-finding limit. No source values were printed.\n',
    );
    process.exitCode = 1;
  }
}
