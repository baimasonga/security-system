# Build and delivery diagnosis — 2026-10-12

Reviewed revision: bdd8983. The remote development branch matches the checkout.

## Confirmed findings

- This is a source-run Node application, not a compiled frontend. Node >=22.18 is required for native TypeScript stripping. Docker uses Node 22, CI uses Node 22, and package exports point to `.ts` source. Missing `npm run build` is intentional.
- The Dockerfile copies workspace manifests/source, production dependencies, migrations, and operator tools. Relative tool imports remain inside copied services/packages. It runs as the non-root `node` user.
- Docker healthcheck was hardcoded to 8080 while the API uses `PORT`. Fixed to read the same variable, with 8080 fallback. Verified the exact healthcheck command against an HTTP server on a non-default injected port.
- The image defaults to development mode. Production must explicitly set `NODE_ENV=production`; otherwise memory persistence and ephemeral secrets are permitted. This documented default is an operational risk, not the cause demonstrated in the supplied logs. Production configuration guards require durable storage and credentials.
- HTTP `/healthz` is liveness, not a continuing database-connectivity test. Startup checks configuration, database role and migrations before listening. A healthy root path is not required; `/` returns 404 by design.
- CI-created database roles previously lacked passwords. Password-authenticated PostgreSQL reproduced the SCRAM failures; revision bdd8983 supplies test-only role credentials and preserves owner credentials. All 306 database tests passed on a separate SCRAM-authenticated cluster. Earlier trust-authenticated local tests were insufficient evidence for CI compatibility.
- CodeQL requires workflow-run API access while preparing SARIF metadata. The official action source calls GET workflow-run metadata from `getWorkflowRelativePath`, used to compute its analysis key. The older provided run had no Actions read permission, matching its 403. Current repository workflow explicitly requests `actions: read`, `contents: read`, and `security-events: write`. The newest failed run's error/permissions have not been retrieved, so its cause remains unconfirmed.
- Gitleaks lacked PR-read permission, demonstrated by a 403 listing PR commits. The workflow now grants read access and the user supplied a later passing result.
- Dependency review explicitly reported unsupported repository configuration. Enabling Dependabot alone does not establish dependency-review entitlement. Current visibility/eligibility and latest error require verification.

## Validation limits and next evidence

GitHub REST access from this environment is blocked by the proxy. A complete CodeQL diagnosis needs the newest bdd8983 run's workflow identity, effective GITHUB_TOKEN permissions, and final error. Do not infer that a newer run failed for the same reason as an older one. No personal token or broader write permissions are justified by the existing evidence.

Docker build failed at `npm ci --omit=dev --ignore-scripts` with npm reporting `Exit handler never called!`. An independent Node container failed DNS resolution for registry.npmjs.org with `EAI_AGAIN`. Registry connectivity is a confirmed blocker; the npm internal error is not independently diagnosed. Image build/start validation is therefore incomplete in this environment; this does not prove an application build error. Railway's actual service start/pre-deploy overrides, deployed commit and live logs are not available through authenticated tools here.

Required production sequence remains owner migrations, app grants, then API startup with the separate app role and verified TLS. Preserve signing key and license-key pepper across deployments. Existing local test passes do not establish deployed production health.

## Retrieved GitHub evidence after access was enabled

Run 38251197556 (CodeQL, bdd8983) reports code scanning is not enabled for the repository. Its error differs from the older missing-Actions-permission failure. Repository API reports private visibility. Appropriate GitHub feature enablement/eligibility is required; broader token permissions do not fix feature availability.

Run 38251197862 (CI, bdd8983) passed database tests but failed refresh-ramp seed setup with email already registered. Both smoke commands reused the same PostgreSQL database and seedWorld registers a fixed operator identity. CI now allocates separate disposable databases for activate and refresh scenarios.
