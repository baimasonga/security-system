import { defineConfig } from 'vitest/config';

const common = { environment: 'node' as const, testTimeout: 20_000 };

export default defineConfig({
  test: {
    coverage: { provider: 'v8', include: ['packages/*/src/**', 'services/*/src/**'] },
    projects: [
      {
        extends: true,
        test: {
          ...common,
          name: 'portal',
          include: ['tests/browser/**/*.test.ts'],
          testTimeout: 90_000,
          hookTimeout: 30_000,
          fileParallelism: false,
        },
      },
      {
        extends: true,
        test: {
          ...common,
          name: 'unit',
          include: [
            'packages/*/test/**/*.test.ts',
            'services/*/test/**/*.test.ts',
            'services/*/test/**/*.test.mjs',
            'tests/**/*.test.ts',
          ],
          exclude: ['**/node_modules/**', '**/*.db.test.ts', 'tests/browser/**'],
        },
      },
      {
        // Requires PostgreSQL: `npm run test:db` (spins up a throwaway cluster) or DATABASE_URL in CI.
        // Runs the PostgreSQL-specific tests AND re-runs the behavioural suites against the PG adapters
        // (each test gets its own migrated schema, see tests/support/pg.ts).
        extends: true,
        test: {
          ...common,
          name: 'db',
          include: [
            '**/*.db.test.ts',
            'packages/licensing/test/activation.test.ts',
            'packages/licensing/test/lifecycle-regressions.test.ts',
            'services/platform-api/test/api.test.ts',
            'services/platform-api/test/catalog.test.ts',
            'services/platform-api/test/operations.test.ts',
            'services/platform-api/test/operations-credentials.test.ts',
            'services/platform-api/test/operations-events.test.ts',
            'services/platform-api/test/operations-health.test.ts',
            'services/platform-api/test/operations-events-store.db.test.ts',
            'services/platform-api/test/operations-credentials-store.db.test.ts',
            'services/platform-api/test/operations-store.db.test.ts',
            'services/platform-api/test/recovery.test.ts',
            'services/platform-api/test/identity-outbox.test.ts',
            'services/platform-api/test/mfa.test.ts',
            'services/platform-api/test/quotas.test.ts',
            'services/platform-api/test/billing-api.test.ts',
            'services/platform-api/test/sharing.test.ts',
            'services/platform-api/test/sharing-security.test.ts',
            'services/platform-api/test/privileged.test.ts',
            'services/platform-api/test/passkeys.test.ts',
            'services/platform-api/test/capabilities.test.ts',
            'services/platform-api/test/seats.test.ts',
            'services/platform-api/test/device-trust.test.ts',
            'services/platform-api/test/privacy.test.ts',
            'tests/security/**/*.test.ts',
            'tests/integration/**/*.test.ts',
          ],
          exclude: ['**/node_modules/**'],
          env: { TRUST_TEST_PERSISTENCE: 'postgres' },
          fileParallelism: false,
        },
      },
      {
        // The same behavioural suites, but the application connects as the LEAST-PRIVILEGE role of the managed
        // profile (ADR-012): it owns nothing, cannot rewrite the audit log, cannot run DDL. If any code path needs
        // a privilege that profile withholds, this project fails.
        extends: true,
        test: {
          ...common,
          name: 'db-approle',
          include: [
            'packages/licensing/test/activation.test.ts',
            'packages/licensing/test/lifecycle-regressions.test.ts',
            'services/platform-api/test/api.test.ts',
            'services/platform-api/test/catalog.test.ts',
            'services/platform-api/test/operations.test.ts',
            'services/platform-api/test/operations-credentials.test.ts',
            'services/platform-api/test/operations-events.test.ts',
            'services/platform-api/test/operations-health.test.ts',
            'services/platform-api/test/operations-events-store.db.test.ts',
            'services/platform-api/test/operations-credentials-store.db.test.ts',
            'services/platform-api/test/operations-store.db.test.ts',
            'services/platform-api/test/recovery.test.ts',
            'services/platform-api/test/identity-outbox.test.ts',
            'services/platform-api/test/mfa.test.ts',
            'services/platform-api/test/quotas.test.ts',
            'services/platform-api/test/billing-api.test.ts',
            'services/platform-api/test/sharing.test.ts',
            'services/platform-api/test/sharing-security.test.ts',
            'services/platform-api/test/privileged.test.ts',
            'services/platform-api/test/passkeys.test.ts',
            'services/platform-api/test/capabilities.test.ts',
            'services/platform-api/test/seats.test.ts',
            'services/platform-api/test/device-trust.test.ts',
            'services/platform-api/test/privacy.test.ts',
            'tests/security/**/*.test.ts',
            'tests/integration/**/*.test.ts',
          ],
          exclude: ['**/node_modules/**'],
          env: { TRUST_TEST_PERSISTENCE: 'postgres', TRUST_TEST_APP_ROLE: '1' },
          fileParallelism: false,
        },
      },
    ],
  },
});
