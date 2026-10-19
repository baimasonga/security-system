import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { parse } from 'yaml';

it('live OpenAPI references resolve and operations have real response maps', () => {
  const doc = parse(
    readFileSync(new URL('../../../docs/api/openapi.yaml', import.meta.url), 'utf8'),
  );
  let references = 0;
  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (!node || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node)) {
      if (key === '$ref' && typeof value === 'string' && value.startsWith('#/')) {
        let target: unknown = doc;
        for (const part of value.slice(2).split('/'))
          target =
            target && typeof target === 'object'
              ? (target as Record<string, unknown>)[part.replace(/~1/g, '/').replace(/~0/g, '~')]
              : undefined;
        expect(target, `unresolved ${value}`).toBeTruthy();
        references++;
      } else walk(value);
    }
  };
  walk(doc);
  expect(references).toBeGreaterThan(100);
  for (const [path, item] of Object.entries(doc.paths as Record<string, Record<string, unknown>>))
    for (const [method, operation] of Object.entries(item)) {
      expect(
        [
          'get',
          'post',
          'put',
          'patch',
          'delete',
          'head',
          'options',
          'trace',
          'parameters',
          'summary',
          'description',
          '$ref',
        ].includes(method) || method.startsWith('x-'),
        `unexpected path-item key ${path} ${method}`,
      ).toBe(true);
      if (['get', 'post', 'put', 'patch', 'delete'].includes(method)) {
        const responses = (operation as { responses: unknown }).responses;
        expect(responses, `${method} ${path} needs responses`).toBeTruthy();
        for (const response of Object.values(responses as Record<string, object>)) {
          expect(
            Object.keys(response).every(
              (key) =>
                ['$ref', 'description', 'summary', 'headers', 'content', 'links'].includes(key) ||
                key.startsWith('x-'),
            ),
            `unexpected response property at ${method} ${path}`,
          ).toBe(true);
        }

        expect(
          Object.keys(responses as object).some((key) => /^[1-5][0-9]{2}$/.test(key)),
          `${method} ${path} needs a status response`,
        ).toBe(true);
      }
    }
});

it('live OpenAPI tags do not contain accidental comma-separated map keys', () => {
  const doc = parse(
    readFileSync(new URL('../../../docs/api/openapi.yaml', import.meta.url), 'utf8'),
  );
  for (const tag of doc.tags)
    expect(
      Object.keys(tag).every(
        (key) => ['name', 'description', 'externalDocs'].includes(key) || key.startsWith('x-'),
      ),
    ).toBe(true);
});
