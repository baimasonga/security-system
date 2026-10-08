#!/usr/bin/env node
// Runs a command with DATABASE_URL pointing at a PostgreSQL instance.
//  - If DATABASE_URL is already set (CI service container), it is used as is.
//  - Otherwise a throwaway local cluster is created, used, and destroyed.
// Usage: node tools/with-postgres.mjs <command> [args...]
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [cmd, ...args] = process.argv.slice(2);
if (!cmd) {
  console.error('usage: with-postgres.mjs <command> [args...]');
  process.exit(2);
}

const run = (c, a, opts = {}) => spawnSync(c, a, { stdio: 'inherit', ...opts });

if (process.env.DATABASE_URL) {
  process.exit(run(cmd, args).status ?? 1);
}

const bin = [
  '/usr/lib/postgresql/16/bin',
  '/usr/lib/postgresql/17/bin',
  '/usr/lib/postgresql/15/bin',
].find((d) => {
  try {
    execFileSync(join(d, 'pg_ctl'), ['--version']);
    return true;
  } catch {
    return false;
  }
});
if (!bin) {
  console.error('no local PostgreSQL found; set DATABASE_URL');
  process.exit(2);
}

const asRoot = process.getuid?.() === 0;
const dir = mkdtempSync(join(tmpdir(), 'pg-'));
chmodSync(dir, 0o755);
if (asRoot) execFileSync('chown', ['postgres', dir]);
const as = (c, a) =>
  asRoot ? ['su', ['postgres', '-c', [c, ...a].map((x) => `'${x}'`).join(' ')]] : [c, a];
const exec = (c, a, o = {}) => {
  const [cc, aa] = as(c, a);
  return execFileSync(cc, aa, { stdio: 'pipe', ...o });
};

const port = String(20000 + Math.floor(Math.random() * 20000));
const data = join(dir, 'data');
let started = false;
let code = 1;
try {
  exec(join(bin, 'initdb'), ['-D', data, '-A', 'trust', '-U', 'postgres']);
  exec(join(bin, 'pg_ctl'), [
    '-D',
    data,
    '-o',
    `-p ${port} -c listen_addresses=127.0.0.1 -c fsync=${process.env.PG_FSYNC === 'on' ? 'on' : 'off'} -c max_connections=300 -c unix_socket_directories=${dir}`,
    '-l',
    join(dir, 'log'),
    '-w',
    'start',
  ]);
  started = true;
  exec(join(bin, 'createdb'), ['-h', '127.0.0.1', '-p', port, '-U', 'postgres', 'trust_test']);
  code =
    run(cmd, args, {
      env: { ...process.env, DATABASE_URL: `postgres://postgres@127.0.0.1:${port}/trust_test` },
    }).status ?? 1;
} catch (e) {
  console.error(String(e.stderr ?? e.message ?? e));
} finally {
  if (started) {
    try {
      exec(join(bin, 'pg_ctl'), ['-D', data, '-m', 'immediate', '-w', 'stop']);
    } catch {
      /* best effort */
    }
  }
  rmSync(dir, { recursive: true, force: true });
}
process.exit(code);
