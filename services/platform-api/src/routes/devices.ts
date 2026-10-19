import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf, toWire } from '../http.ts';
import { activateBody, capabilityTokenBody, challengeBody, deviceAuthBody } from '../schemas.ts';

/**
 * Device-facing endpoints. Activation needs a user session; refresh/validate/deactivate are
 * authenticated by a device signature over a single-use challenge (no session, no bearer token).
 */
export function registerDeviceRoutes(app: FastifyInstance, c: Container): void {
  const rl = c.config.rateLimits;

  app.post(
    '/v1/devices/challenges',
    { config: { rateLimit: { max: rl.challenge, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const b = parse(challengeBody, req.body);
      const g = await c.licensing.issueChallenge({
        purpose: b.purpose,
        installationId: b.installation_id,
        ...(b.subject_id ? { subjectId: b.subject_id } : {}),
      });
      return reply.status(201).send(toWire(g));
    },
  );

  app.post(
    '/v1/licenses/activate',
    {
      preHandler: authenticated(c),
      config: { rateLimit: { max: rl.activate, timeWindow: '1 minute' } },
    },
    async (req) => {
      const b = parse(activateBody, req.body);
      const g = await c.licensing.activate(principalOf(req), {
        licenseKey: b.license_key,
        installationId: b.installation_id,
        devicePublicKey: b.device_public_key,
        nonce: b.nonce,
        signature: b.signature,
      });
      return toWire(g);
    },
  );

  const deviceRl = { config: { rateLimit: { max: rl.activate, timeWindow: '1 minute' } } };
  const toInput = (b: ReturnType<typeof deviceAuthBody.parse>) => ({
    activationId: b.activation_id,
    installationId: b.installation_id,
    nonce: b.nonce,
    signature: b.signature,
  });

  app.post('/v1/licenses/validate', deviceRl, async (req) =>
    toWire(await c.licensing.validate(toInput(parse(deviceAuthBody, req.body)))),
  );
  // Short-lived, device-bound token for one capability, verified offline by processing services (ADR-024).
  app.post('/v1/capabilities/token', deviceRl, async (req) => {
    const b = parse(capabilityTokenBody, req.body);
    return toWire(
      await c.licensing.issueCapabilityToken({
        ...toInput(b),
        capability: b.capability,
        service: b.service,
      }),
    );
  });
  app.post('/v1/licenses/refresh', deviceRl, async (req) =>
    toWire(await c.licensing.refresh(toInput(parse(deviceAuthBody, req.body)))),
  );
  app.post('/v1/licenses/deactivate', deviceRl, async (req) =>
    toWire(await c.licensing.deactivateByDevice(toInput(parse(deviceAuthBody, req.body)))),
  );

  // Public verification material only. Cacheable by clients; contains no secrets.
  app.get('/v1/keys/trust-bundle', async (_req, reply) => {
    void reply.header('cache-control', 'public, max-age=300');
    return c.licensing.trustBundle();
  });
}
