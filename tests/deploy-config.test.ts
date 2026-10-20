import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const root = new URL('../', import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root), 'utf8');

describe('Railway deployment config', () => {
  it('runs migrations, grants and the role check before each deploy, using tools the image contains', () => {
    const cfg = JSON.parse(read('railway.json'));
    expect(cfg.build).toEqual({ builder: 'DOCKERFILE', dockerfilePath: 'Dockerfile' });
    expect(cfg.deploy.healthcheckPath).toBe('/healthz');
    const tools = [
      ...cfg.deploy.preDeployCommand.join(' ').matchAll(/node (tools\/[\w-]+\.ts)/g),
    ].map((m) => m[1]);
    expect(tools).toEqual(['tools/predeploy.ts']);
    const copied = /COPY (tools\/[^\n]+) \.\/tools\//.exec(read('Dockerfile'))![1]!.split(/\s+/);
    for (const t of [...tools, 'tools/migrate.ts', 'tools/db-grants.ts', 'tools/db-check.ts'])
      expect(copied, `${t} must be copied into the image`).toContain(t);
  });

  it('builds the private ClamAV service from its own Dockerfile', () => {
    const cfg = JSON.parse(read('infrastructure/railway/clamav/railway.json'));
    expect(existsSync(new URL(cfg.build.dockerfilePath, root))).toBe(true);
    expect(read(cfg.build.dockerfilePath)).toMatch(/StreamMaxLength 300M/);
  });
});
