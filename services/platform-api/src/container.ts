import { AuthService, InMemoryAuthStore } from '@trust/auth';
import { InMemoryAuditLog, type AuditLog } from '@trust/audit';
import { KeyRing } from '@trust/crypto';
import {
  InMemoryLicensingStore,
  LicensingService,
  defaultLicensingConfig,
  type LicensingConfig,
} from '@trust/licensing';
import { systemClock, type Clock } from '@trust/shared-types';
import { InMemoryTelemetrySink, Telemetry, type TelemetrySink } from '@trust/telemetry';
import type { PlatformConfig } from './config.ts';

export interface Container {
  config: PlatformConfig;
  clock: Clock;
  audit: AuditLog;
  auth: AuthService;
  licensing: LicensingService;
  keyring: KeyRing;
  telemetry: Telemetry;
  telemetrySink: TelemetrySink;
}

/** Composition root. Everything environment-specific is chosen here and nowhere else. */
export function createContainer(
  config: PlatformConfig,
  overrides?: { clock?: Clock; licensing?: Partial<LicensingConfig> },
): Container {
  const clock = overrides?.clock ?? systemClock;
  const audit = new InMemoryAuditLog(clock);
  const telemetrySink = new InMemoryTelemetrySink();
  const telemetry = new Telemetry({
    sink: telemetrySink,
    clock,
    pseudonymKey: config.pseudonymKey,
  });

  const keyring = new KeyRing({
    now: () => clock.now(),
    // Key lifecycle changes are high-blast-radius: always audited, never including key material.
    onEvent: (e) => {
      void audit.append({
        actor: { type: 'system' },
        action: `key.${e.action}`,
        target: { type: 'signing_key', id: e.kid },
        reason: e.reason,
        metadata: { purpose: e.purpose, from: e.from, to: e.to },
      });
    },
  });
  const key = config.signingKeyPem
    ? keyring.importPrivateKeyPem('license', config.signingKeyPem)
    : keyring.generate('license');
  keyring.activate(key.kid, 'initial activation at startup');

  const auth = new AuthService({
    store: new InMemoryAuthStore(),
    clock,
    audit,
    ...(config.scrypt ? { config: { scrypt: config.scrypt } } : {}),
  });

  const licensing = new LicensingService({
    store: new InMemoryLicensingStore(),
    clock,
    audit,
    telemetry,
    keyring,
    config: defaultLicensingConfig({
      licenseKeyPepper: config.licenseKeyPepper,
      ...overrides?.licensing,
    }),
    authorize: async (p, orgId, permission) => {
      await auth.requireOrgPermission(p, orgId, permission);
    },
    orgExists: (id) => auth.orgExists(id),
  });

  return { config, clock, audit, auth, licensing, keyring, telemetry, telemetrySink };
}
