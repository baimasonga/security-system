import { expect, it } from 'vitest';
import { summarizePosture } from '../src/web/operations.mjs';
const blank = () => ({
  scans: { items: [], truncated: false },
  findings: { items: [], truncated: false },
  recovery: { items: [], truncated: false },
});
it('treats missing and unavailable evidence as unknown rather than a clean bill of health', () => {
  expect(summarizePosture(null)).toMatchObject({
    available: false,
    findingText: 'Unknown',
    scanText: 'Reporting unavailable',
  });
  expect(summarizePosture(blank())).toMatchObject({
    available: true,
    scanText: 'No scan report shown',
    restoreText: 'No restore report shown',
  });
});
it('prioritizes shown critical and high open snapshots without counting closed or accepted risk as open', () => {
  const view = blank();
  view.findings.items = [
    { state: 'resolved', severity: 'critical' },
    { state: 'accepted_risk', severity: 'critical' },
    { state: 'open', severity: 'high' },
    { state: 'acknowledged', severity: 'low' },
  ];
  const high = summarizePosture(view);
  expect(high.findingText).toBe('2 shown · 0 critical · 1 high');
  view.findings.items.push({ state: 'open', severity: 'critical' });
  expect(summarizePosture(view).rank).toBeLessThan(high.rank);
});
it('never counts a backup or rollback as a restore exercise', () => {
  const view = blank();
  view.recovery.items = [
    {
      kind: 'backup',
      outcome: 'succeeded',
      freshness: 'current',
      completed_at: '2026-10-20T12:00:00Z',
    },
    {
      kind: 'rollback',
      outcome: 'succeeded',
      freshness: 'current',
      completed_at: '2026-10-20T12:01:00Z',
    },
  ];
  expect(summarizePosture(view).restoreText).toBe('No restore report shown');
});
it('uses completion time within shown reports, not import order, and does not replace a newer failed restore with an older success', () => {
  const view = blank();
  view.scans.items = [
    { outcome: 'failed', freshness: 'current', completed_at: '2026-10-20T11:00:00Z' },
    { outcome: 'completed', freshness: 'current', completed_at: '2026-10-20T12:00:00Z' },
  ];
  view.recovery.items = [
    {
      kind: 'restore',
      outcome: 'succeeded',
      freshness: 'current',
      completed_at: '2026-10-19T11:00:00Z',
    },
    {
      kind: 'restore',
      outcome: 'failed',
      freshness: 'current',
      completed_at: '2026-10-20T12:00:00Z',
    },
  ];
  const result = summarizePosture(view);
  expect(result.scanText).toContain('completed · current');
  expect(result.restoreText).toContain('failed · current');
  expect(result.rank).toBe(2);
});
it('labels truncated lists as partial even when no open snapshots appear in the visible portion', () => {
  for (const collection of ['scans', 'findings', 'recovery']) {
    const view = blank();
    view[collection].truncated = true;
    expect(summarizePosture(view).partial).toBe(true);
  }
  const view = blank();
  view.findings.truncated = true;
  expect(summarizePosture(view).findingText).toContain('more findings not shown');
});
it('keeps stale and missing scan/restore reports ahead of current reported evidence without claiming independent security', () => {
  const view = blank();
  view.scans.items = [
    { outcome: 'completed', freshness: 'current', completed_at: '2026-10-20T12:00:00Z' },
  ];
  view.recovery.items = [
    {
      kind: 'restore',
      outcome: 'succeeded',
      freshness: 'current',
      completed_at: '2026-10-20T12:00:00Z',
    },
  ];
  const current = summarizePosture(view);
  view.scans.items[0].freshness = 'stale';
  expect(summarizePosture(view).rank).toBeLessThan(current.rank);
  expect(JSON.stringify(current)).not.toMatch(/independently_verified|secure|healthy/i);
});
