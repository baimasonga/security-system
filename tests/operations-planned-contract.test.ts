import { readFileSync } from 'node:fs';
import { Ajv, type AnySchemaObject } from 'ajv';
import addFormats from 'ajv-formats';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';

// This validates a design target, not running HTTP authorization or persistence.
const planned = parse(
  readFileSync(new URL('../docs/api/operations-planned.openapi.yaml', import.meta.url), 'utf8'),
) as {
  'x-implementation-status': string;
  paths: Record<
    string,
    Record<
      string,
      {
        operationId: string;
        'x-implementation-status': string;
        'x-required-permission': string;
        security: Record<string, unknown>[];
        responses: Record<string, unknown>;
      }
    >
  >;
  components: { schemas: Record<string, AnySchemaObject> };
};
const examples = JSON.parse(
  readFileSync(new URL('../docs/api/operations-safe-examples.json', import.meta.url), 'utf8'),
) as { schema: number; events: Record<string, unknown>[] };
const ajv = new Ajv({ strict: true, allErrors: true });
// Named CJS import through the package's default namespace works in NodeNext.
addFormats.default(ajv);
const definitions = JSON.parse(
  JSON.stringify(planned.components.schemas).replaceAll('#/components/schemas/', '#/$defs/'),
) as Record<string, AnySchemaObject>;
const validate = (name: string) => ajv.compile({ $defs: definitions, $ref: `#/$defs/${name}` });
const batch = validate('EventBatch');
const receipt = validate('EventAcknowledgement');
const issued = validate('IssuedCredential');
const metadata = validate('Credential');
const event = () => structuredClone(examples.events[0]!);
const asBatch = (value: Record<string, unknown>) => ({ schema: 1, events: [value] });

describe('OPS-001 planned operations contract (not implemented endpoints)', () => {
  it('compiles every planned schema and resolves every OpenAPI reference', () => {
    for (const name of Object.keys(definitions)) expect(validate(name)).toBeTypeOf('function');
    const visit = (value: unknown): void => {
      if (!value || typeof value !== 'object') return;
      if ('$ref' in value) {
        const ref = String(value.$ref);
        expect(ref.startsWith('#/')).toBe(true);
        let target: unknown = planned;
        for (const key of ref.slice(2).split('/')) {
          expect(target).toBeTypeOf('object');
          target = (target as Record<string, unknown>)[key];
        }
        expect(target, ref).toBeDefined();
      }
      for (const child of Object.values(value)) visit(child);
    };
    visit(planned);
  });

  it('keeps planned operations separate from live routes and assigns explicit authority', () => {
    const live = parse(
      readFileSync(new URL('../docs/api/openapi.yaml', import.meta.url), 'utf8'),
    ) as { paths: Record<string, unknown> };
    expect(planned['x-implementation-status']).toBe('planned');
    const names = new Set<string>();
    for (const [path, methods] of Object.entries(planned.paths)) {
      expect(live.paths[path], path).toBeUndefined();
      for (const op of Object.values(methods)) {
        expect(op['x-implementation-status']).toBe('planned');
        expect(names.has(op.operationId)).toBe(false);
        names.add(op.operationId);
        if (path === '/v1/operations/events') {
          expect(op.security).toEqual([{ IntegrationBearer: [] }]);
          expect(op['x-required-permission']).toBe('events:write');
          expect(op.responses['202']).toBeUndefined();
          expect(op.responses['200']).toBeDefined();
        } else {
          expect(op.security).toEqual([{ AccountSession: [] }]);
          expect(op['x-required-permission'].startsWith('ops:')).toBe(true);
        }
      }
    }
  });

  it('accepts safe fixtures for all nine distinct backend event types', () => {
    expect(batch(examples), ajv.errorsText(batch.errors)).toBe(true);
    expect(new Set(examples.events.map((e) => e.type)).size).toBe(9);
    expect(batch({ schema: 1, events: Array.from({ length: 100 }, event) })).toBe(true);
  });

  it.each([
    'org_id',
    'application_id',
    'environment_id',
    'source',
    'severity',
    'message',
    'request_id',
  ])('rejects client-supplied event authority or arbitrary content in %s', (field) => {
    expect(batch(asBatch({ ...event(), [field]: 'spoofed' }))).toBe(false);
  });

  it.each(['filename', 'recipient', 'url', 'password', 'stack', 'document_content'])(
    'rejects unapproved attribute %s for every event type',
    (field) => {
      for (const sample of examples.events) {
        const attrs = sample.attributes as Record<string, unknown>;
        expect(batch(asBatch({ ...sample, attributes: { ...attrs, [field]: 'untrusted' } }))).toBe(
          false,
        );
      }
    },
  );

  it.each([
    'person@example.test',
    'https://example.test/private',
    '/tmp/customer/document.pdf',
    'not_an_enum',
  ])('rejects non-enumerated strings in every enum attribute', (value) => {
    for (const sample of examples.events) {
      const attrs = sample.attributes as Record<string, unknown>;
      for (const [name, current] of Object.entries(attrs)) {
        if (typeof current === 'string')
          expect(batch(asBatch({ ...sample, attributes: { ...attrs, [name]: value } }))).toBe(
            false,
          );
      }
    }
  });

  it('rejects wrong schema, empty/oversized batches, malformed IDs/times and arbitrary event types', () => {
    for (const value of [
      { ...examples, schema: 2 },
      { ...examples, org_id: 'spoofed' },
      { schema: 1, events: [] },
      { schema: 1, events: Array.from({ length: 101 }, event) },
      asBatch({ ...event(), id: 'document-name.pdf' }),
      asBatch({ ...event(), component_id: 'org_' + 'a'.repeat(24) }),
      asBatch({ ...event(), occurred_at: '2026-02-30T12:00:00Z' }),
      asBatch({ ...event(), occurred_at: '2026-10-19T12:00:00+01:00' }),
      asBatch({ ...event(), type: 'run.command' }),
    ])
      expect(batch(value)).toBe(false);
  });

  it('rejects negative, fractional and out-of-budget numeric attributes', () => {
    for (const sample of examples.events) {
      const attrs = sample.attributes as Record<string, unknown>;
      for (const [name, current] of Object.entries(attrs)) {
        if (typeof current !== 'number') continue;
        for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER])
          expect(batch(asBatch({ ...sample, attributes: { ...attrs, [name]: value } }))).toBe(
            false,
          );
      }
    }
  });

  it('requires committed per-event receipts, with exact response fields', () => {
    const ack = {
      schema: 1,
      accepted: [{ id: event().id, disposition: 'stored', received_at: '2026-10-19T12:00:01Z' }],
    };
    expect(receipt(ack)).toBe(true);
    expect(receipt({ schema: 1, accepted: [] })).toBe(false);
    expect(receipt({ ...ack, accepted: [{ ...ack.accepted[0], disposition: 'queued' }] })).toBe(
      false,
    );
    expect(receipt({ ...ack, token: 'secret' })).toBe(false);
  });

  it('keeps issuance secrets out of metadata and bounds credential rotation overlap', () => {
    const credential = {
      id: 'opc_' + 'a'.repeat(32),
      org_id: 'org_' + 'a'.repeat(24),
      application_id: 'opa_' + 'a'.repeat(24),
      environment_id: 'ope_' + 'a'.repeat(24),
      purpose: 'events:write',
      source: 'backend_report',
      expires_at: '2026-10-20T12:00:00Z',
      created_at: '2026-10-19T12:00:00Z',
      revoked_at: null,
    };
    const token = 'ops_v1.' + credential.id + '.' + 'b'.repeat(64);
    expect(issued({ credential, token })).toBe(true);
    expect(issued({ credential })).toBe(false);
    expect(metadata({ ...credential, token })).toBe(false);
    expect(metadata({ ...credential, secret_digest: 'verification-material' })).toBe(false);
    expect(metadata({ ...credential, purpose: 'license:activate' })).toBe(false);
    for (const schema of ['IssueCredential', 'RotateCredential', 'RevokeCredential']) {
      const check = validate(schema);
      const request = {
        reason: 'security_response',
        ...(schema === 'IssueCredential' ? { purpose: 'events:write' } : {}),
        ...(schema === 'RevokeCredential' ? {} : { ttl_seconds: 86400 }),
        ...(schema === 'RotateCredential' ? { overlap_seconds: 0 } : {}),
      };
      expect(check({ ...request, mfa_code: '123456' })).toBe(true);
      expect(check(request)).toBe(false);
      expect(check({ ...request, mfa_code: 'a'.repeat(32) })).toBe(false);
      expect(check({ ...request, mfa_authenticated: true })).toBe(false);
    }
    const rotation = validate('RotateCredential');
    for (const overlap of [0, 3600])
      expect(
        rotation({
          ttl_seconds: 86400,
          overlap_seconds: overlap,
          mfa_code: '123456',
          reason: 'routine_rotation',
        }),
      ).toBe(true);
    for (const overlap of [-1, 3601])
      expect(
        rotation({
          ttl_seconds: 86400,
          overlap_seconds: overlap,
          mfa_code: '123456',
          reason: 'routine_rotation',
        }),
      ).toBe(false);
  });

  it('requires management reasons, versions and immutable codes', () => {
    const update = validate('UpdateApplication');
    const change = { expected_version: 1, reason: 'maintenance', state: 'disabled' };
    expect(update(change)).toBe(true);
    expect(update({ ...change, code: 'changed-code' })).toBe(false);
    expect(update({ expected_version: 1, state: 'disabled', criticality: 'high' })).toBe(false);
    expect(update({ reason: 'maintenance', state: 'disabled', criticality: 'high' })).toBe(false);
    expect(update({ ...change, reason: 'person@example.test' })).toBe(false);
    expect(update({ expected_version: 1, reason: 'maintenance' })).toBe(false);
  });
});
