# Dependency update compatibility

CI runs the API, SDK and database suites on Node 22; package engines require at least 22.18.
Keep `@types/node` on major 22 so type checking cannot silently allow APIs missing from the
oldest supported runtime. Dependabot still proposes compatible minor/patch updates. Review
runtime/CI/type major upgrades together; Node 26 types alone are not a runtime upgrade.

ESLint, `@eslint/js`, `eslint-plugin-security` and `typescript-eslint` are one toolchain.
Dependabot groups them because changing only one major can produce peer-dependency conflicts
or plugin crashes. ESLint 10 and `@eslint/js` 10 require a security plugin that supports the
current rule context API (4.2 or newer). Install normally and regenerate the lockfile; do not
use `--force` or `--legacy-peer-deps` to suppress an incompatible dependency tree.

`npm run check` must pass before pushing. `tests/lint-toolchain.test.ts` loads the real lint
configuration and verifies that unsafe regexes in production sources are still rejected.
New ESLint recommendations are applied normally. The narrow `preserve-caught-error` exceptions
in constraint mappings and the anchor transport deliberately discard PostgreSQL tenant data
and private witness URLs; attaching those raw causes could leak them in logs. Other throws
retain that lint check. No security plugin rule is globally disabled for this migration.

The JWK importer uses the normalized public-key object directly rather than importing a
Node-version-specific `JsonWebKey` alias. The ClamAV test server accepts both string and
buffer socket event typings. These compatibility fixes also type-check with Node 26 typings;
the default runtime/type policy remains Node 22. Schema changes, production signing and
monitoring implementation are outside this dependency-maintenance change.
