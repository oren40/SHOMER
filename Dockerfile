# Shomer - runtime control plane for enterprise AI agents
# Build-time dependencies come from the npm registry; RUNTIME makes no outbound
# calls (no telemetry, no phone-home): the only egress is what YOU configure
# (broker tool destinations and the optional checkpoint sink).

FROM node:20-alpine

WORKDIR /app

# Runtime env knobs (all optional):
#   PORT, SHOMER_DATA_DIR, SHOMER_ADMIN_KEY,
#   SHOMER_CHECKPOINT_DIR, SHOMER_CHECKPOINT_KEY_PATH, SHOMER_CHECKPOINT_EVERY,
#   SHOMER_CHECKPOINT_INTERVAL_S, SHOMER_CHECKPOINT_SINK_URL,
#   SHOMER_BROKER_MAX_RESPONSE_BYTES
ENV NODE_ENV=production \
    PORT=8787 \
    SHOMER_DATA_DIR=/app/data

# tsx is a devDependency but is the runtime loader, so install with dev deps.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
COPY dashboard ./dashboard

# Persisted state + signed checkpoints. Mount these as volumes in production.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npm", "run", "start"]