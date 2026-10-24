import { poolSettings, readCaPem, tlsProblem } from '../services/platform-api/src/db/connection.ts';

/** Use runtime CA handling without loading unrelated application secrets or starting workers. */
export function auditVerifierPoolSettings(
  env: NodeJS.ProcessEnv,
  readFile: (path: string) => string,
) {
  const databaseUrl = env['DATABASE_URL'];
  if (!databaseUrl) throw new Error('DATABASE_URL required');
  const caPem = readCaPem(env, readFile);
  const problem = tlsProblem(databaseUrl);
  // An explicit CA forces verified TLS through poolSettings even when URL options disagree.
  if (!caPem && problem) throw new Error(problem);
  return poolSettings({ databaseUrl, max: 2, caPem });
}
