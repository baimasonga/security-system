import { expect, it } from 'vitest';
import { normalizeSecurityExport } from '../../../tools/normalize-security-export.ts';
const options = {
  source: 'github_secret_scanning',
  repository: 'owner/repo',
  revision: 'a'.repeat(40),
  runId: '123',
  completedAt: '2026-10-20T00:00:00Z',
  componentId: 'opm_' + 'a'.repeat(24),
};
it('projects secret-scanning exports without retaining secrets, locations, URLs or arbitrary source fields', () => {
  const raw = [
    {
      number: 1,
      state: 'open',
      secret: 'DO-NOT-RETAIN',
      html_url: 'https://private.invalid',
      locations: [{ path: 'customer.txt' }],
    },
  ];
  const report = normalizeSecurityExport([raw], options);
  expect(report.findings).toHaveLength(1);
  expect(report.findings[0]!.advisory_id).toBeNull();
  const output = JSON.stringify(report);
  for (const forbidden of [
    'DO-NOT-RETAIN',
    'private.invalid',
    'customer.txt',
    'html_url',
    'locations',
  ])
    expect(output).not.toContain(forbidden);
  expect(normalizeSecurityExport(raw, options)).toEqual(report);
});
it('rejects malformed, closed, excessive and unrecognized provider results instead of silently declaring a clean scan', () => {
  for (const raw of [
    {},
    [{ number: 1, state: 'closed' }],
    Array(101).fill({ number: 1, state: 'open' }),
    [{ number: 'bad', state: 'open' }],
  ])
    expect(() => normalizeSecurityExport(raw, options)).toThrow('invalid export');
  expect(() =>
    normalizeSecurityExport(
      [{ number: 1, state: 'open', security_advisory: { severity: 'extreme', ghsa_id: 'secret' } }],
      { ...options, source: 'github_dependabot' },
    ),
  ).toThrow('invalid export');
  expect(() =>
    normalizeSecurityExport([], { ...options, repository: 'https://internal.invalid' }),
  ).toThrow('invalid export');
});
