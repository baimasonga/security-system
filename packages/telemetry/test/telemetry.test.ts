import { describe, expect, it } from 'vitest';
import { InMemoryTelemetrySink, Telemetry, sanitizeAttributes } from '../src/index.ts';

const clock = { now: () => new Date('2026-01-01T00:00:00Z') };
const make = () => {
  const sink = new InMemoryTelemetrySink();
  return { sink, t: new Telemetry({ sink, clock, pseudonymKey: 'k' }) };
};

describe('telemetry privacy firewall (V1 minimal)', () => {
  it('drops attributes that are not allow-listed (e.g. document content, emails)', async () => {
    const { sink, t } = make();
    await t.track('app.started', {
      app_version: '5.0.0',
      platform: 'windows',
      document_text: 'Q3 salary table',
      email: 'a@b.c',
    });
    expect(sink.telemetry[0]!.attributes).toEqual({ app_version: '5.0.0', platform: 'windows' });
    expect(JSON.stringify(sink.telemetry)).not.toMatch(/salary|a@b\.c/);
  });

  it('constrains enums and truncates strings', () => {
    expect(
      sanitizeAttributes('app.started', { platform: 'toaster', app_version: 'x'.repeat(100) }),
    ).toEqual({
      app_version: 'x'.repeat(32),
    });
  });

  it('ignores unknown event names', async () => {
    const { sink, t } = make();
    await t.track('made.up' as never, { a: 1 });
    expect(sink.telemetry).toHaveLength(0);
  });

  it('pseudonymizes security-signal subjects and redacts secret-looking attributes', async () => {
    const { sink, t } = make();
    await t.signal('canary_license_activated', {
      orgId: 'org_1',
      subject: 'inst_secretinstall',
      attributes: { license_key: 'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE', ip_class: 'datacenter' },
    });
    const rec = sink.security[0]!;
    expect(rec.severity).toBe('high');
    expect(rec.subject).toMatch(/^ps_[0-9a-f]{24}$/);
    expect(rec.subject).toBe(t.pseudonym('inst_secretinstall'));
    expect(JSON.stringify(rec)).not.toMatch(/LK-AAAAA|inst_secretinstall/);
    expect(rec.attributes['ip_class']).toBe('datacenter');
  });
});
