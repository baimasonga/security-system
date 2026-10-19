import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  INVENTORY_REASONS,
  type InventoryScope,
  type InventoryType,
  type UpdateInventory,
} from '@trust/operations';
import { DomainError } from '@trust/shared-types';
import type { Container } from '../container.ts';
import { authenticated, principalOf, toWire } from '../http.ts';

const ID_PATTERNS = {
  org: /^org_[a-f0-9]{24}$/,
  usr: /^usr_[a-f0-9]{24}$/,
  prd: /^prd_[a-f0-9]{24}$/,
  opa: /^opa_[a-f0-9]{24}$/,
  ope: /^ope_[a-f0-9]{24}$/,
  opm: /^opm_[a-f0-9]{24}$/,
} as const;
const id = (prefix: keyof typeof ID_PATTERNS) => z.string().regex(ID_PATTERNS[prefix]);
const code = z.string().regex(/^[a-z][a-z0-9-]{1,47}$/);
const reason = z.enum(INVENTORY_REASONS);
const version = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const criticality = z.enum(['low', 'medium', 'high', 'critical']);
const componentKind = z.enum([
  'service',
  'database',
  'storage',
  'worker',
  'scanner',
  'desktop',
  'provider',
]);
const state = z.enum(['active', 'disabled']);
const deps = z
  .array(id('opm'))
  .max(100)
  .refine((a) => new Set(a).size === a.length);
const application = z
  .object({ code, owner_user_id: id('usr'), criticality, product_id: id('prd').nullable(), reason })
  .strict();
const environment = z
  .object({ code, kind: z.enum(['development', 'staging', 'production']), reason })
  .strict();
const component = z.object({ code, kind: componentKind, dependency_ids: deps, reason }).strict();
const patch = { expected_version: version, reason };
const updates = {
  application: z
    .object({
      ...patch,
      owner_user_id: id('usr').optional(),
      criticality: criticality.optional(),
      product_id: id('prd').nullable().optional(),
      state: state.optional(),
    })
    .strict()
    .refine((v) => Object.keys(v).length > 2),
  environment: z.object({ ...patch, state }).strict(),
  component: z
    .object({
      ...patch,
      kind: componentKind.optional(),
      dependency_ids: deps.optional(),
      state: state.optional(),
    })
    .strict()
    .refine((v) => Object.keys(v).length > 2),
};
const archive = z.object(patch).strict();
/** Do not echo paths/unknown names/values from validation errors. */
function safeParse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  const result = schema.safeParse(value ?? {});
  if (!result.success) throw new DomainError('invalid_request', 'request rejected');
  return result.data;
}
const base = '/v1/organizations/:orgId/operations/applications';
const specs = [
  { type: 'application', path: base, key: 'applicationId' },
  { type: 'environment', path: base + '/:applicationId/environments', key: 'environmentId' },
  {
    type: 'component',
    path: base + '/:applicationId/environments/:environmentId/components',
    key: 'componentId',
  },
] as const;
export function registerOperationsRoutes(app: FastifyInstance, c: Container) {
  void app.register(async (scoped) => {
    // Operations errors carry fixed diagnostics, never DB/validation messages or submitted values.
    scoped.setErrorHandler((error, req, reply) => {
      const status =
        error instanceof DomainError
          ? error.status
          : ((error as { statusCode?: number }).statusCode ?? 503);
      const codes: Record<number, string> = {
        400: 'invalid_request',
        401: 'unauthenticated',
        403: 'forbidden',
        404: 'not_found',
        409: 'conflict',
        413: 'too_large',
        415: 'unsupported_media_type',
        429: 'rate_limited',
      };
      const safeStatus = status in codes ? status : 503;
      return reply
        .status(safeStatus)
        .type('application/problem+json')
        .send({
          code: codes[safeStatus] ?? 'unavailable',
          message:
            safeStatus === 401
              ? 'authentication required'
              : safeStatus === 404
                ? 'not found'
                : safeStatus === 503
                  ? 'service unavailable'
                  : 'request rejected',
          request_id: req.id,
        });
    });
    registerInventoryRoutes(scoped, c);
  });
}
function registerInventoryRoutes(app: FastifyInstance, c: Container) {
  const pre = {
    // Automatic request logs include raw query strings. Audit/metrics provide safe diagnostics.
    logLevel: 'silent' as const,
    preHandler: [
      authenticated(c),
      async () => {
        if (!c.config.operationsInventoryEnabled) throw new DomainError('not_found', 'not found');
      },
    ],
  };
  for (const spec of specs) {
    const params = {
      orgId: id('org'),
      ...(spec.type !== 'application' ? { applicationId: id('opa') } : {}),
      ...(spec.type === 'component' ? { environmentId: id('ope') } : {}),
    };
    function scope(raw: unknown, item = false): { scope: InventoryScope; itemId?: string } {
      const parsed = safeParse(
        z
          .object({
            ...params,
            ...(item
              ? {
                  [spec.key]: id(
                    ({ application: 'opa', environment: 'ope', component: 'opm' } as const)[
                      spec.type
                    ],
                  ),
                }
              : {}),
          })
          .strict(),
        raw,
      ) as Record<string, string>;
      return {
        scope: {
          orgId: parsed.orgId!,
          ...(spec.type !== 'application' ? { applicationId: parsed.applicationId! } : {}),
          ...(spec.type === 'component' ? { environmentId: parsed.environmentId! } : {}),
        },
        itemId: parsed[spec.key],
      };
    }
    app.get(spec.path, pre, async (req) => {
      const s = scope(req.params).scope;
      const query = safeParse(
        z
          .object({
            limit: z.coerce.number().int().min(1).max(100).optional(),
            cursor: z.string().min(1).max(512).optional(),
          })
          .strict(),
        req.query,
      );
      return toWire(await c.operations.list(principalOf(req), spec.type, s, query));
    });
    app.post(spec.path, pre, async (req, reply) => {
      const s = scope(req.params).scope;
      const p = principalOf(req);
      let out;
      if (spec.type === 'application') {
        const input = safeParse(application, req.body);
        out = await c.operations.createApplication(p, s.orgId, {
          code: input.code,
          ownerUserId: input.owner_user_id,
          criticality: input.criticality,
          productId: input.product_id,
          reason: input.reason,
        });
      } else if (spec.type === 'environment') {
        const input = safeParse(environment, req.body);
        out = await c.operations.createEnvironment(
          p,
          { orgId: s.orgId, applicationId: s.applicationId! },
          input,
        );
      } else {
        const input = safeParse(component, req.body);
        out = await c.operations.createComponent(
          p,
          { orgId: s.orgId, applicationId: s.applicationId!, environmentId: s.environmentId! },
          {
            code: input.code,
            kind: input.kind,
            dependencyIds: input.dependency_ids,
            reason: input.reason,
          },
        );
      }
      return reply.status(201).send(toWire(out));
    });
    const itemPath = spec.path + '/:'.concat(spec.key);
    app.get(itemPath, pre, async (req) => {
      const s = scope(req.params, true);
      return toWire(await c.operations.get(principalOf(req), spec.type, s.scope, s.itemId!));
    });
    for (const method of ['PATCH', 'DELETE'] as const) {
      app.route({
        method,
        url: itemPath,
        ...pre,
        handler: async (req) => {
          const s = scope(req.params, true);
          const raw = safeParse(
            method === 'DELETE' ? archive : updates[spec.type],
            req.body,
          ) as Record<string, unknown>;
          const input: UpdateInventory = {
            expectedVersion: raw.expected_version as number,
            reason: raw.reason as UpdateInventory['reason'],
          };
          const mapping = {
            owner_user_id: 'ownerUserId',
            criticality: 'criticality',
            product_id: 'productId',
            kind: 'kind',
            dependency_ids: 'dependencyIds',
            state: 'state',
          } as const;
          for (const [wire, domain] of Object.entries(mapping))
            if (wire in raw) Object.assign(input, { [domain]: raw[wire] });
          if (method === 'DELETE') input.state = 'archived';
          return toWire(
            await c.operations.update(
              principalOf(req),
              spec.type as InventoryType,
              s.scope,
              s.itemId!,
              input,
            ),
          );
        },
      });
    }
  }
}
