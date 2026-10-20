// Deployment runners may tokenize a command without a shell. Never rely on && for security gates.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

type Execute = (
  file: string,
  args: string[],
  options: { stdio: 'inherit' },
) => { status: number | null; signal: string | null; error?: Error };
export function runPredeploy(execute: Execute = spawnSync): number {
  for (const script of ['migrate.ts', 'db-grants.ts', 'db-check.ts']) {
    const result = execute(process.execPath, [fileURLToPath(new URL(script, import.meta.url))], {
      stdio: 'inherit',
    });
    if (result.error || result.signal || result.status === null) return 1;
    if (result.status !== 0) return result.status;
  }
  return 0;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runPredeploy();
  if (process.exitCode === 0)
    console.log('predeploy completed: migrations, grants and profile verification');
}
