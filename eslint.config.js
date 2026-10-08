import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';

export default tseslint.config(
  { ignores: ['node_modules', 'coverage', 'dist'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    rules: {
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
    files: ['services/platform-api/src/config.ts', 'services/platform-api/src/db/migrate.ts'],
    rules: { 'security/detect-non-literal-fs-filename': 'off' }, // paths come from operator-controlled env/CLI arguments, by design
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
