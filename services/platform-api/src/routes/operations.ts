import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  ALERT_EVENTS,
  RUNBOOKS,
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
  opc: /^opc_[a-f0-9]{32}$/,
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
        422: 'unprocessable',
        429: 'rate_limited',
      };
      const safeStatus = status in codes ? status : 503;
      if (safeStatus === 503) {
        const code = (error as { code?: unknown }).code;
        const message = (error as { message?: unknown }).message;
        const target =
          typeof message === 'string'
            ? /^permission denied for table (operations_incidents|operations_accounts|users|sessions|memberships|privileged_freezes|audit_events|audit_chains)$/.exec(
                message,
              )?.[1]
            : undefined;
        app.log.error(
          {
            failure: 'operations_unavailable',
            sqlstate: typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code) ? code : 'unknown',
            ...(code === '42501' ? { permission_target: target ?? 'unknown' } : {}),
          },
          'operations request failed',
        );
      }
      if (safeStatus === 429) reply.header('retry-after', '60');
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
          ...(safeStatus === 422
            ? {
                details: {
                  field: 'body',
                  rule:
                    error instanceof DomainError && error.details?.rule === 'unknown_attribute'
                      ? 'unknown_attribute'
                      : 'schema',
                },
              }
            : {}),
        });
    });
    registerInventoryRoutes(scoped, c);
    registerCredentialRoutes(scoped, c);
    registerEventRoutes(scoped, c);
    registerHealthRoutes(scoped, c);
    registerIncidentRoutes(scoped, c);
    registerAutomationRoutes(scoped, c);
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

function registerCredentialRoutes(app: FastifyInstance, c: Container) {
  const path = base + '/:applicationId/environments/:environmentId/credentials';
  const pre = {
    logLevel: 'silent' as const,
    preHandler: [
      authenticated(c),
      async () => {
        if (!c.config.operationsCredentialsEnabled || !c.config.operationsInventoryEnabled)
          throw new DomainError('not_found', 'not found');
      },
    ],
  };
  const scopeParams = z
    .object({ orgId: id('org'), applicationId: id('opa'), environmentId: id('ope') })
    .strict();
  const itemParams = scopeParams.extend({ credentialId: id('opc') });
  const common = { reason, mfa_code: z.string().regex(/^[0-9]{6}$/) };
  const ttl = z.number().int().min(86400).max(7776000);
  app.get(path, pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const scope = safeParse(scopeParams, req.params);
    const query = safeParse(
      z
        .object({
          limit: z.coerce.number().int().min(1).max(100).optional(),
          cursor: z.string().min(1).max(512).optional(),
        })
        .strict(),
      req.query,
    );
    return toWire(await c.operationsCredentials.list(principalOf(req), scope, query));
  });
  app.post(path, pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const scope = safeParse(scopeParams, req.params);
    const input = safeParse(
      z.object({ ...common, purpose: z.literal('events:write'), ttl_seconds: ttl }).strict(),
      req.body,
    );
    const issued = await c.operationsCredentials.issue(principalOf(req), scope, {
      purpose: input.purpose,
      ttlSeconds: input.ttl_seconds,
      mfaCode: input.mfa_code,
      reason: input.reason,
    });
    return reply.status(201).send(toWire(issued));
  });
  app.post(path + '/:credentialId/rotate', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const { credentialId, ...scope } = safeParse(itemParams, req.params);
    const input = safeParse(
      z
        .object({ ...common, ttl_seconds: ttl, overlap_seconds: z.number().int().min(0).max(3600) })
        .strict(),
      req.body,
    );
    return reply.status(201).send(
      toWire(
        await c.operationsCredentials.rotate(principalOf(req), scope, credentialId, {
          ttlSeconds: input.ttl_seconds,
          overlapSeconds: input.overlap_seconds,
          mfaCode: input.mfa_code,
          reason: input.reason,
        }),
      ),
    );
  });
  app.post(path + '/:credentialId/revoke', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const { credentialId, ...scope } = safeParse(itemParams, req.params);
    const input = safeParse(z.object(common).strict(), req.body);
    return toWire(
      await c.operationsCredentials.revoke(principalOf(req), scope, credentialId, {
        mfaCode: input.mfa_code,
        reason: input.reason,
      }),
    );
  });
}

function registerEventRoutes(app: FastifyInstance, c: Container) {
  app.post(
    '/v1/operations/events',
    {
      logLevel: 'silent',
      bodyLimit: 262144,
      config: { rateLimit: { max: 120, timeWindow: '1 minute', groupId: 'operations-ingestion' } },
      onRequest: async (req) => {
        if (!c.config.operationsIngestionEnabled) throw new DomainError('not_found', 'not found');
        if (req.url.includes('?')) throw new DomainError('invalid_request', 'request rejected');
        if (
          (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') ||
          !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')
        )
          throw new DomainError('unsupported_media_type', 'request rejected');
      },
    },
    async (req) => {
      const h = req.headers.authorization;
      const token = h && /^Bearer (ops_v1\.opc_[a-f0-9]{32}\.[a-f0-9]{64})$/.exec(h)?.[1];
      const receipt = await c.operationsEvents.ingest(token, req.body);
      for (const disposition of ['stored', 'duplicate'])
        c.metrics.inc(
          'operations_events_total',
          { disposition },
          receipt.accepted.filter((r) => r.disposition === disposition).length,
        );
      return receipt;
    },
  );
}

function registerHealthRoutes(app: FastifyInstance, c: Container) {
  const path = base + '/:applicationId/environments/:environmentId';
  const params = z
    .object({ orgId: id('org'), applicationId: id('opa'), environmentId: id('ope') })
    .strict();
  const pre = {
    logLevel: 'silent' as const,
    preHandler: [
      authenticated(c),
      async () => {
        if (!c.config.operationsHealthEnabled) throw new DomainError('not_found', 'not found');
      },
    ],
  };
  app.get(path + '/health', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    return toWire(
      await c.operationsHealth.snapshot(principalOf(req), safeParse(params, req.params)),
    );
  });
  app.get(path + '/components/:componentId/history', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const { componentId, ...scope } = safeParse(
      params.extend({ componentId: id('opm') }),
      req.params,
    );
    const q = safeParse(
      z
        .object({ from: z.string().datetime().optional(), to: z.string().datetime().optional() })
        .strict()
        .refine((q) => !!q.from === !!q.to),
      req.query,
    );
    const to = q.to ? new Date(q.to) : c.clock.now();
    const from = q.from ? new Date(q.from) : new Date(+to - 86400000);
    return toWire(await c.operationsHealth.history(principalOf(req), scope, componentId, from, to));
  });
}

function registerIncidentRoutes(app: FastifyInstance, c: Container) {
  const path = base + '/:applicationId/environments/:environmentId/incidents';
  const scopeParams = z
    .object({ orgId: id('org'), applicationId: id('opa'), environmentId: id('ope') })
    .strict();
  const incidentId = z.string().regex(/^opi_[a-f0-9]{24}$/);
  const pre = {
    logLevel: 'silent' as const,
    preHandler: [
      authenticated(c),
      async () => {
        if (!c.config.operationsInventoryEnabled || !c.config.operationsIncidentsEnabled)
          throw new DomainError('not_found', 'not found');
      },
    ],
  };
  app.get(path, pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const q = safeParse(
      z
        .object({
          limit: z.coerce.number().int().min(1).max(100).default(50),
          after: incidentId.optional(),
        })
        .strict(),
      req.query,
    );
    return toWire(
      await c.operationsIncidents.list(principalOf(req), safeParse(scopeParams, req.params), q),
    );
  });
  app.post(path, pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    const b = safeParse(
      z
        .object({
          component_id: id('opm'),
          severity: z.enum(['informational', 'warning', 'critical']),
          reason: z.literal('security_response'),
        })
        .strict(),
      req.body,
    );
    return toWire(
      await c.operationsIncidents.open(principalOf(req), safeParse(scopeParams, req.params), {
        componentId: b.component_id,
        severity: b.severity,
        reason: b.reason,
      }),
    );
  });
  for (const action of ['acknowledge', 'resolve', 'assign'] as const)
    app.post(`${path}/:incidentId/${action}`, pre, async (req, reply) => {
      reply.header('Cache-Control', 'no-store');
      safeParse(z.object({}).strict(), req.query);
      const { incidentId: incident, ...scope } = safeParse(
        scopeParams.extend({ incidentId }).strict(),
        req.params,
      );
      const expected = { expected_version: z.number().int().min(1) };
      let result;
      if (action === 'assign') {
        const b = safeParse(
          z
            .object({
              ...expected,
              reason: z.literal('assignment'),
              assignee_user_id: id('usr').nullable(),
            })
            .strict(),
          req.body,
        );
        result = await c.operationsIncidents.act(principalOf(req), scope, incident, {
          action,
          expectedVersion: b.expected_version,
          reason: b.reason,
          assigneeUserId: b.assignee_user_id,
        });
      } else if (action === 'acknowledge') {
        const b = safeParse(
          z.object({ ...expected, reason: z.literal('incident_ack') }).strict(),
          req.body,
        );
        result = await c.operationsIncidents.act(principalOf(req), scope, incident, {
          action,
          expectedVersion: b.expected_version,
          reason: b.reason,
        });
      } else {
        const b = safeParse(
          z.object({ ...expected, reason: z.literal('incident_resolution') }).strict(),
          req.body,
        );
        result = await c.operationsIncidents.act(principalOf(req), scope, incident, {
          action,
          expectedVersion: b.expected_version,
          reason: b.reason,
        });
      }
      return toWire(result);
    });
}

function registerAutomationRoutes(app: FastifyInstance, c: Container) {
  const path = base + '/:applicationId/environments/:environmentId';
  const scopeParams = z
    .object({ orgId: id('org'), applicationId: id('opa'), environmentId: id('ope') })
    .strict();
  const pre = {
    logLevel: 'silent' as const,
    preHandler: [
      authenticated(c),
      async () => {
        if (!c.config.operationsAutomationEnabled) throw new DomainError('not_found', 'not found');
      },
    ],
  };
  const params = z
    .object({
      orgId: id('org'),
      applicationId: id('opa'),
      environmentId: id('ope'),
      ruleId: z.string().regex(/^opr_[a-f0-9]{24}$/),
    })
    .strict();
  app.get(path + '/rules', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    return toWire(
      await c.operationsAutomation.list(principalOf(req), safeParse(scopeParams, req.params)),
    );
  });
  app.post(path + '/rules', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    const b = safeParse(
      z
        .object({
          component_id: id('opm'),
          kind: z.enum(['event_count', 'heartbeat']),
          event_type: z.enum(ALERT_EVENTS).nullable(),
          threshold: z.number().int().min(1).max(1000),
          window_seconds: z.number().int().min(60).max(3600),
          severity: z.enum(['informational', 'warning', 'critical']),
          runbook: z.enum(RUNBOOKS),
          reason: z.literal('initial_setup'),
        })
        .strict(),
      req.body,
    );
    return reply.code(201).send(
      toWire(
        await c.operationsAutomation.create(principalOf(req), safeParse(scopeParams, req.params), {
          componentId: b.component_id,
          kind: b.kind,
          eventType: b.event_type,
          threshold: b.threshold,
          windowSeconds: b.window_seconds,
          severity: b.severity,
          runbook: b.runbook,
          reason: b.reason,
        }),
      ),
    );
  });
  app.patch(path + '/rules/:ruleId', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    const { ruleId, ...scope } = safeParse(params, req.params);
    const b = safeParse(
      z
        .object({
          expected_version: version,
          enabled: z.boolean(),
          maintenance_until: z.string().datetime().nullable(),
          reason: z.enum(['maintenance', 'security_response']),
        })
        .strict(),
      req.body,
    );
    return toWire(
      await c.operationsAutomation.configure(principalOf(req), scope, ruleId, {
        expectedVersion: b.expected_version,
        enabled: b.enabled,
        maintenanceUntil: b.maintenance_until ? new Date(b.maintenance_until) : null,
        reason: b.reason,
      }),
    );
  });
  app.post(path + '/rules/evaluate', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    safeParse(z.object({}).strict(), req.body);
    return toWire(
      await c.operationsAutomation.evaluateNow(
        principalOf(req),
        safeParse(scopeParams, req.params),
      ),
    );
  });
  app.get(path + '/notifications', pre, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    safeParse(z.object({}).strict(), req.query);
    return toWire(
      await c.operationsAutomation.notifications(
        principalOf(req),
        safeParse(scopeParams, req.params),
      ),
    );
  });
}
