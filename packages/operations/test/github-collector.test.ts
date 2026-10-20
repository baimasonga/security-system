import { describe, expect, it, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  collectGitHubSecurity,
  parseCollectorArgs,
} from '../../../tools/collect-github-security.ts';
const options = {
  source: 'github_secret_scanning',
  repository: 'Owner/Repo',
  revision: 'a'.repeat(40),
  runId: '123',
  componentId: 'opm_' + 'a'.repeat(24),
};
const now = () => new Date('2026-10-20T12:00:00Z');
const alert = {
  number: 1,
  state: 'open',
  secret: 'NEVER-PRINT-SECRET',
  html_url: 'https://private.invalid',
  locations: [{ path: 'private.txt' }],
};
function transport(alerts: unknown = [alert], headers: Record<string, string> = {}) {
  return vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(Response.json({ sha: options.revision }))
    .mockResolvedValueOnce(Response.json(alerts, { headers }));
}

describe('operator-local GitHub security collection', () => {
  it('authenticates only fixed read-only endpoints and projects safe metadata', async () => {
    const request = transport();
    const result = await collectGitHubSecurity(options, { token: 'private-token', request, now });
    expect(request.mock.calls.map((c) => c[0])).toEqual([
      `https://api.github.com/repos/owner/repo/commits/${options.revision}`,
      'https://api.github.com/repos/owner/repo/secret-scanning/alerts?state=open&per_page=100',
    ]);
    for (const [, init] of request.mock.calls) {
      expect(init?.method).toBe('GET');
      expect(init?.redirect).toBe('error');
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer private-token');
      expect(init?.signal).toBeInstanceOf(AbortSignal);
    }
    expect(request.mock.calls[0]![1]!.signal).toBe(request.mock.calls[1]![1]!.signal);
    expect(result).toMatchObject({
      source: 'github_secret_scanning',
      revision: options.revision,
      run_id: '123',
      completed_at: now().toISOString(),
      outcome: 'completed',
    });
    expect(result.findings).toHaveLength(1);
    for (const forbidden of [
      'NEVER-PRINT',
      'private-token',
      'private.invalid',
      'private.txt',
      'html_url',
      'locations',
      'independently_verified',
    ])
      expect(JSON.stringify(result)).not.toContain(forbidden);
    expect(
      await collectGitHubSecurity(
        { ...options, repository: 'owner/repo' },
        { token: 't', request: transport(), now },
      ),
    ).toEqual(result);
  });
  it('supports Dependabot and refuses to manufacture success after malformed findings', async () => {
    const request = transport([
      {
        number: 2,
        state: 'open',
        security_advisory: { severity: 'high', ghsa_id: 'GHSA-2345-6789-cfgh' },
      },
    ]);
    const report = await collectGitHubSecurity(
      { ...options, source: 'github_dependabot' },
      { token: 't', request, now },
    );
    expect(String(request.mock.calls[1]![0])).toContain('/dependabot/alerts?state=open');
    expect(report.findings[0]).toMatchObject({
      severity: 'high',
      advisory_id: 'GHSA-2345-6789-cfgh',
    });
    await expect(
      collectGitHubSecurity(
        { ...options, source: 'github_dependabot' },
        { token: 't', request: transport([alert]), now },
      ),
    ).rejects.toThrow('GitHub security collection refused');
  });
  it('accepts a complete empty inventory only after a successful provider response', async () => {
    const result = await collectGitHubSecurity(options, {
      token: 't',
      request: transport([]),
      now,
    });
    expect(result.findings).toEqual([]);
    expect(result.outcome).toBe('completed');
  });
  it.each([301, 302, 401, 403, 404, 429, 500, 503])(
    'refuses provider status %s without echoing its secret-bearing body',
    async (status) => {
      const request = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(Response.json({ sha: options.revision }))
        .mockResolvedValueOnce(
          Response.json([], {
            status,
            headers: { location: 'http://169.254.169.254' },
          }),
        );
      await expect(
        collectGitHubSecurity(options, { token: 'private-token', request, now }),
      ).rejects.toThrow(/^GitHub security collection refused$/);
      expect(request).toHaveBeenCalledTimes(2);
    },
  );
  it('refuses pagination without following provider-supplied links or emitting truncated success', async () => {
    const request = transport([alert], { link: '<http://169.254.169.254/latest>; rel="next"' });
    await expect(collectGitHubSecurity(options, { token: 't', request, now })).rejects.toThrow(
      'GitHub security collection refused',
    );
    expect(request).toHaveBeenCalledTimes(2);
  });
  it('enforces the streamed byte cap even if content-length is absent or lies', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ sha: options.revision }))
      .mockResolvedValueOnce(
        new Response('[' + ' '.repeat(10 * 1024 * 1024) + ']', {
          headers: { 'content-type': 'application/json', 'content-length': '1' },
        }),
      );
    await expect(collectGitHubSecurity(options, { token: 't', request, now })).rejects.toThrow(
      'GitHub security collection refused',
    );
  });
  it('refuses incomplete, duplicate, closed or over-cap inventories', async () => {
    for (const rows of [
      { message: 'secret provider error' },
      [alert, alert],
      [{ ...alert, state: 'resolved' }],
      Array.from({ length: 101 }, (_, i) => ({ ...alert, number: i + 1 })),
    ])
      await expect(
        collectGitHubSecurity(options, { token: 't', request: transport(rows), now }),
      ).rejects.toThrow('GitHub security collection refused');
  });
  it('requires an exact verified repository commit before fetching alerts', async () => {
    const request = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ sha: 'b'.repeat(40) }));
    await expect(collectGitHubSecurity(options, { token: 't', request, now })).rejects.toThrow(
      'GitHub security collection refused',
    );
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('rejects bad selectors or missing credentials before any network call', async () => {
    const request = transport();
    for (const patch of [
      { repository: 'https://evil.invalid' },
      { repository: 'owner/../repo' },
      { revision: 'main' },
      { componentId: 'cross-tenant' },
      { source: 'arbitrary' },
      { runId: 'not-a-run' },
    ])
      await expect(
        collectGitHubSecurity({ ...options, ...patch }, { token: 't', request, now }),
      ).rejects.toThrow('GitHub security collection refused');
    await expect(collectGitHubSecurity(options, { token: '', request, now })).rejects.toThrow(
      'GitHub security collection refused',
    );
    expect(request).not.toHaveBeenCalled();
  });
  it('requires JSON and hides malformed JSON, transport errors and provider diagnostics', async () => {
    for (const response of [
      new Response('<html>secret</html>'),
      new Response('{secret', { headers: { 'content-type': 'application/json' } }),
    ]) {
      const request = vi.fn<typeof fetch>().mockResolvedValue(response);
      await expect(collectGitHubSecurity(options, { token: 't', request, now })).rejects.toThrow(
        /^GitHub security collection refused$/,
      );
    }
    await expect(
      collectGitHubSecurity(options, {
        token: 't',
        request: vi.fn().mockRejectedValue(Error('private-token')),
        now,
      }),
    ).rejects.toThrow(/^GitHub security collection refused$/);
  });
  it('rejects unknown, duplicate or missing CLI arguments, including token arguments', () => {
    const args = [
      '--source',
      options.source,
      '--repository',
      options.repository,
      '--revision',
      options.revision,
      '--run-id',
      options.runId,
      '--component',
      options.componentId,
    ];
    expect(parseCollectorArgs(args)).toEqual(options);
    for (const bad of [
      [],
      args.slice(1),
      [...args, '--token', 'secret'],
      [...args, '--source', 'github_dependabot'],
      [...args, '--unexpected'],
    ])
      expect(() => parseCollectorArgs(bad)).toThrow();
  });
  it('the executable emits no partial JSON or sensitive arguments on failure', () => {
    const r = spawnSync(
      process.execPath,
      ['tools/collect-github-security.ts', '--token', 'SYNTHETIC-SECRET'],
      {
        encoding: 'utf8',
        timeout: 10000,
        env: { ...process.env, GITHUB_SECURITY_TOKEN: '' },
      },
    );
    expect(r.status).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('GitHub security collection refused');
    expect(r.stderr).not.toContain('SYNTHETIC-SECRET');
  });
});
