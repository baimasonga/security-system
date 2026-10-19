import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';

export default tseslint.config(
  {
    files: ['services/platform-api/src/web/*.mjs'],
    languageOptions: {
      globals: Object.fromEntries(
        [
          'document',
          'window',
          'location',
          'history',
          'URLSearchParams',
          'fetch',
          'Node',
          'confirm',
          'crypto',
          'indexedDB',
          'navigator',
          'btoa',
          'atob',
          'TextEncoder',
          'TextDecoder',
          'localStorage',
          'setTimeout',
          'Blob',
          'URL',
          'Uint8Array',
          'prompt',
          'File',
        ].map((name) => [name, 'readonly']),
      ),
    },
  },
  { ignores: ['node_modules', 'coverage', 'dist'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    rules: {
      // Keep the ESLint 9 rule baseline during the toolchain migration. Audit
      // these new recommended rules separately from dependency compatibility.
      'preserve-caught-error': 'off',
      'no-useless-assignment': 'off',
      eqeqeq: ['error', 'always'],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': 'error',
      // Object keys here come from validated, allow-listed schemas; the rule is noise for this codebase.
      'security/detect-object-injection': 'off',
      // We build regexes only from constants; literal-regex ReDoS analysis stays on.
      'security/detect-non-literal-regexp': 'error',
    },
  },
  {
    files: ['**/test/**', 'tests/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'security/detect-non-literal-fs-filename': 'off',
    },
  },
  {
    // Measurement scripts parse untyped JSON from the server under test; `any` is pragmatic here and these
    // files never ship in the service.
    files: ['tools/loadtest/**'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
  {
    files: [
      'services/platform-api/src/config.ts',
      'services/platform-api/src/db/migrate.ts',
      'services/platform-api/src/routes/portal.ts',
    ],
    rules: { 'security/detect-non-literal-fs-filename': 'off' }, // paths come from operator-controlled env/CLI arguments, by design
  },
  {
    // Local object store: every path is <operator root>/<sha256 digest | random hex id>, built by the store itself;
    // tenant-supplied names never reach the filesystem.
    files: ['services/platform-api/src/integrations/object-store-local.ts'],
    rules: { 'security/detect-non-literal-fs-filename': 'off' },
  },
  {
    files: ['**/*.mjs', 'tools/**'],
    languageOptions: { globals: { console: 'readonly', process: 'readonly', URL: 'readonly' } },
    // Build tooling reads repo paths it computed itself; no attacker-controlled input.
    rules: {
      'security/detect-non-literal-fs-filename': 'off',
      'security/detect-unsafe-regex': 'off',
    },
  },
);
