import { expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditVerifierPoolSettings } from '../../../tools/audit-verifier-connection.ts';

const pem = '-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----';
const url = 'postgresql://user:private@db.example.test/postgres?sslmode=require';
it('the actual verifier refuses invalid CA before connecting and does not echo secrets', () => {
  const dir = mkdtempSync(join(tmpdir(), 'verifier-ca-'));
  try {
    const file = join(dir, 'manifest.json');
    writeFileSync(file, JSON.stringify({ v: 1 }));
    const result = spawnSync(process.execPath, ['tools/verify-anchor.ts', file], {
      encoding: 'utf8',
      timeout: 5000,
      env: {
        DATABASE_URL: 'postgresql://user:SECRET_PASSWORD@127.0.0.1:1/db',
        DATABASE_CA_PEM: 'SECRET_INVALID_CA',
      },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('invalid database TLS configuration');
    expect(result.stderr + result.stdout).not.toContain('SECRET');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
it('uses the configured inline CA and prevents URL TLS options overriding verification', () => {
  const settings = auditVerifierPoolSettings(
    { DATABASE_URL: url, DATABASE_CA_PEM: pem.replaceAll('\n', '\\n') },
    () => {
      throw new Error('unexpected file read');
    },
  );
  expect(settings.ssl).toEqual({ ca: pem, rejectUnauthorized: true });
  expect(settings.connectionString).not.toContain('sslmode');
});
it('reads a CA file with the same connection settings as runtime', () => {
  const paths: string[] = [];
  const settings = auditVerifierPoolSettings(
    { DATABASE_URL: url, DATABASE_CA_FILE: '/operator/ca.pem' },
    (path) => {
      paths.push(path);
      return pem;
    },
  );
  expect(paths).toEqual(['/operator/ca.pem']);
  expect(settings.ssl).toEqual({ ca: pem, rejectUnauthorized: true });
});
it('preserves local non-TLS restore-drill support', () => {
  expect(
    auditVerifierPoolSettings({ DATABASE_URL: 'postgresql://localhost/fixture' }, () => ''),
  ).toEqual({ connectionString: 'postgresql://localhost/fixture', max: 2 });
});
it.each([
  {},
  { DATABASE_URL: 'postgresql://user:private@db.example.test/db' },
  { DATABASE_URL: url, DATABASE_CA_PEM: 'invalid' },
  { DATABASE_URL: url, DATABASE_CA_PEM: pem, DATABASE_CA_FILE: '/operator/ca.pem' },
])('refuses missing or invalid transport configuration', (env) => {
  expect(() => auditVerifierPoolSettings(env, () => pem)).toThrow();
});
