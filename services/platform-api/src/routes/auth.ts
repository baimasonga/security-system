import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf, toWire } from '../http.ts';
import {
  loginBody,
  mfaBeginBody,
  mfaConfirmBody,
  mfaDisableBody,
  registerBody,
  recoveryRequestBody,
  recoveryCompleteBody,
  verificationBody,
  emptyBody,
  passkeyBeginBody,
  passkeyLoginFinishBody,
  passkeyParams,
  passkeyRegisterFinishBody,
} from '../schemas.ts';

export function registerAuthRoutes(app: FastifyInstance, c: Container): void {
  const rl = c.config.rateLimits;
  const mfaOptions = {
    preHandler: authenticated(c),
    config: { rateLimit: { max: rl.login, timeWindow: '1 minute' } },
  };
  app.post('/v1/auth/mfa/begin', mfaOptions, async (req) => {
    const body = parse(mfaBeginBody, req.body);
    return toWire(await c.auth.beginMfa(principalOf(req), body.password));
  });
  app.post('/v1/auth/mfa/confirm', mfaOptions, async (req) => {
    const body = parse(mfaConfirmBody, req.body);
    return toWire(await c.auth.confirmMfa(principalOf(req), body.password, body.code));
  });
  app.post('/v1/auth/mfa/disable', mfaOptions, async (req, reply) => {
    const body = parse(mfaDisableBody, req.body);
    await c.auth.disableMfa(principalOf(req), body.password, body.code, body.reason);
    return reply.status(204).send();
  });
  app.get('/v1/auth/options', async () => ({
    email_recovery_configured: c.auth.deliveryConfigured,
    passkeys_configured: c.auth.passkeysConfigured,
  }));

  // ---- passkeys (ADR-023) ----
  const bytes = (s: string) => Buffer.from(s, 'base64url');
  const anonLimited = { config: { rateLimit: { max: rl.login, timeWindow: '1 minute' } } };
  app.post('/v1/auth/passkeys/register/begin', mfaOptions, async (req) => {
    const { password } = parse(passkeyBeginBody, req.body);
    return c.auth.beginPasskeyRegistration(principalOf(req), password);
  });
  app.post('/v1/auth/passkeys/register/finish', mfaOptions, async (req, reply) => {
    const b = parse(passkeyRegisterFinishBody, req.body);
    const out = await c.auth.finishPasskeyRegistration(principalOf(req), {
      name: b.name,
      clientDataJSON: bytes(b.credential.response.clientDataJSON),
      attestationObject: bytes(b.credential.response.attestationObject),
    });
    return reply.status(201).send(toWire(out));
  });
  app.post('/v1/auth/passkeys/login/begin', anonLimited, async (req) => {
    parse(emptyBody, req.body);
    return c.auth.beginPasskeyLogin();
  });
  app.post('/v1/auth/passkeys/login/finish', anonLimited, async (req) => {
    const { credential: cr } = parse(passkeyLoginFinishBody, req.body);
    const s = await c.auth.finishPasskeyLogin({
      credentialId: cr.id,
      clientDataJSON: bytes(cr.response.clientDataJSON),
      authenticatorData: bytes(cr.response.authenticatorData),
      signature: bytes(cr.response.signature),
      ...(cr.response.userHandle ? { userHandle: bytes(cr.response.userHandle) } : {}),
    });
    return { token: s.token, expires_at: s.expiresAt.toISOString(), user_id: s.userId };
  });
  app.get('/v1/auth/passkeys', { preHandler: authenticated(c) }, async (req) => ({
    items: toWire(await c.auth.listPasskeys(principalOf(req))),
  }));
  app.post('/v1/auth/passkeys/:credentialId/delete', mfaOptions, async (req, reply) => {
    const { credentialId } = parse(passkeyParams, req.params);
    const { password } = parse(passkeyBeginBody, req.body);
    await c.auth.deletePasskey(principalOf(req), credentialId, password);
    return reply.status(204).send();
  });
  app.post(
    '/v1/auth/password/request',
    { config: { rateLimit: { max: rl.register, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const { email } = parse(recoveryRequestBody, req.body);
      await c.auth.requestPasswordReset(email);
      return reply
        .status(202)
        .send({ message: 'If the account can receive email, a recovery link will be sent.' });
    },
  );
  app.post(
    '/v1/auth/password/reset',
    { config: { rateLimit: { max: rl.login, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const { token, password } = parse(recoveryCompleteBody, req.body);
      await c.auth.completeIdentityToken(token, 'reset', password);
      return reply.status(204).send();
    },
  );
  app.post(
    '/v1/auth/email/request',
    {
      preHandler: authenticated(c),
      config: { rateLimit: { max: rl.register, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      parse(emptyBody, req.body);
      await c.auth.requestEmailVerification(principalOf(req));
      return reply.status(202).send({ message: 'A verification link will be sent when needed.' });
    },
  );
  app.post(
    '/v1/auth/email/verify',
    { config: { rateLimit: { max: rl.login, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const { token } = parse(verificationBody, req.body);
      await c.auth.completeIdentityToken(token, 'verify');
      return reply.status(204).send();
    },
  );

  app.post(
    '/v1/auth/register',
    { config: { rateLimit: { max: rl.register, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const body = parse(registerBody, req.body);
      const { user, personalOrg } = await c.auth.register(body);
      return reply.status(201).send({
        user: { id: user.id, email: user.email },
        personal_org: { id: personalOrg.id, name: personalOrg.name },
      });
    },
  );

  app.post(
    '/v1/auth/login',
    { config: { rateLimit: { max: rl.login, timeWindow: '1 minute' } } },
    async (req) => {
      const body = parse(loginBody, req.body);
      const s = await c.auth.login(body);
      return { token: s.token, expires_at: s.expiresAt.toISOString(), user_id: s.userId };
    },
  );

  app.post('/v1/auth/logout', { preHandler: authenticated(c) }, async (req, reply) => {
    await c.auth.logout(principalOf(req));
    return reply.status(204).send();
  });

  app.get('/v1/auth/me', { preHandler: authenticated(c) }, async (req) => {
    const p = principalOf(req);
    return toWire(await c.auth.account(p));
  });
}
