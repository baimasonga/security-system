# Development image. Production is intentionally blocked until the PostgreSQL adapters ship
# (see docs/architecture/05-v1-status-and-handoff.md); config.ts refuses NODE_ENV=production.
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY services ./services
RUN npm ci --omit=dev --ignore-scripts

FROM node:22-slim
ENV NODE_ENV=development HOST=0.0.0.0 PORT=8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY packages ./packages
COPY services ./services
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "services/platform-api/src/main.ts"]
