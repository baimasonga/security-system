import type { FastifyInstance } from 'fastify';
import { DomainError } from '@trust/shared-types';
import type { Container } from '../container.ts';
import { operator, parse, principalOf, toWire } from '../http.ts';
import { emptyBody } from '../schemas.ts';
import {
  registerRootBody,
  registryParams,
  targetBody,
  reserveBody,
  publicationBody,
  floorBody,
  releaseQuery,
  historyQuery,
} from '../release-registry.ts';

export function registerUpdateRegistryRoutes(app: FastifyInstance, c: Container) {
  const pre = {
    bodyLimit: 32768,
    preHandler: [
      operator(c),
      async () => {
        if (!c.config.updateCatalogEnabled) throw new DomainError('not_found', 'not found');
      },
    ],
  };
  const path = '/v1/admin/products/:productId/update-registry';
  app.get(path, pre, async (req) => {
    const { productId } = parse(registryParams, req.params);
    parse(emptyBody, req.query);
    return toWire(await c.updateRegistry.read(productId));
  });
  app.post(path, pre, async (req, reply) => {
    const { productId } = parse(registryParams, req.params);
    const b = parse(registerRootBody, req.body);
    await c.privileged.assertWritable(null);
    return reply
      .status(201)
      .send(toWire(await c.updateRegistry.register(productId, b, principalOf(req).userId)));
  });
  app.post(path + '/targets', pre, async (req, reply) => {
    const { productId } = parse(registryParams, req.params);
    const b = parse(targetBody, req.body);
    await c.privileged.assertWritable(null);
    return reply
      .status(201)
      .send(toWire(await c.updateRegistry.addTarget(productId, b, principalOf(req).userId)));
  });
  app.post(path + '/sequence-floor', pre, async (req) => {
    const { productId } = parse(registryParams, req.params);
    const b = parse(floorBody, req.body);
    await c.privileged.assertWritable(null);
    return toWire(await c.updateRegistry.raiseFloor(productId, b, principalOf(req).userId));
  });
  app.post(path + '/releases', { ...pre, bodyLimit: 524288 }, async (req) => {
    const { productId } = parse(registryParams, req.params);
    const b = parse(publicationBody, req.body);
    await c.privileged.assertWritable(null);
    return toWire(await c.updateRegistry.publish(productId, b, principalOf(req).userId));
  });
  app.get(path + '/releases', pre, async (req) => {
    const { productId } = parse(registryParams, req.params);
    const b = parse(historyQuery, req.query);
    return { items: toWire(await c.updateRegistry.history(productId, b)) };
  });
  app.get('/v1/updates/:productId/current', async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    if (!c.config.updateCatalogEnabled) throw new DomainError('not_found', 'not found');
    const { productId } = parse(registryParams, req.params);
    const b = parse(releaseQuery, req.query);
    return c.updateRegistry.current(productId, b);
  });
  app.post(path + '/reservations', pre, async (req) => {
    const { productId } = parse(registryParams, req.params);
    const b = parse(reserveBody, req.body);
    await c.privileged.assertWritable(null);
    return toWire(await c.updateRegistry.reserve(productId, b, principalOf(req).userId));
  });
}
