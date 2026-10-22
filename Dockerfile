# syntax=docker/dockerfile:1
# Runs from source with Node's native type stripping (ADR-003); no build step.
# Production needs PERSISTENCE=postgres, DATABASE_URL, LICENSE_SIGNING_KEY_FILE and strong secrets
# (config.ts refuses to start otherwise). Apply migrations first: `node tools/migrate.ts`.
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY services ./services
RUN npm ci --omit=dev --ignore-scripts --strict-ssl=true

FROM node:22-slim
ENV NODE_ENV=development HOST=0.0.0.0 PORT=8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY packages ./packages
COPY services ./services
# Operator tooling that must be runnable inside the deployment (e.g. `railway ssh` / one-off jobs).
COPY tools/predeploy.ts tools/migrate.ts tools/db-grants.ts tools/db-check.ts tools/bootstrap-operator.ts tools/verify-anchor.ts ./tools/
# Normalize restricted checkout modes without making application code writable by the runtime user.
RUN chmod -R a+rX /app/package.json /app/packages /app/services /app/tools
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || '8080') + '/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "services/platform-api/src/main.ts"]
