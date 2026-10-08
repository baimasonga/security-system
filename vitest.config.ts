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
          name: 'unit',
          include: [
            'packages/*/test/**/*.test.ts',
            'services/*/test/**/*.test.ts',
            'tests/**/*.test.ts',
          ],
          exclude: ['**/node_modules/**', '**/*.db.test.ts'],
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
            'services/platform-api/test/api.test.ts',
            'tests/security/**/*.test.ts',
            'tests/integration/**/*.test.ts',
          ],
          exclude: ['**/node_modules/**'],
          env: { TRUST_TEST_PERSISTENCE: 'postgres' },
          fileParallelism: false,
        },
      },
    ],
  },
});
