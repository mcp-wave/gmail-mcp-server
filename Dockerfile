# Build stage: needs the dev toolchain (typescript) to produce dist/.
FROM node:20-slim AS build

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Copy source files and config first
COPY tsconfig.json ./
COPY src ./src

# Install dependencies (which will trigger build via prepare script)
RUN npm ci

# Runtime stage: production dependencies and compiled output only. The test
# and build toolchain never reaches the image, so a vulnerability in vitest or
# typescript is not a vulnerability in the deployed service.
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./

# --ignore-scripts is required (the `prepare` script builds with tsc, which is
# not installed here) and is worth having on its own: no dependency lifecycle
# script runs in the image.
RUN npm ci --omit=dev --ignore-scripts

COPY --from=build /app/dist ./dist

# Create directory for credentials and config
RUN mkdir -p /gmail-server /root/.gmail-mcp

# Set environment variables
ENV NODE_ENV=production
ENV GMAIL_CREDENTIALS_PATH=/gmail-server/credentials.json
ENV GMAIL_OAUTH_PATH=/root/.gmail-mcp/gcp-oauth.keys.json

# Expose port for the local OAuth callback (stdio mode) and the
# Streamable HTTP + OAuth endpoint (remote mode: run with `http`).
EXPOSE 3000

# Default entrypoint runs stdio mode; pass `http` (e.g. via compose `command`)
# to start the remote claude.ai connector.
ENTRYPOINT ["node", "dist/index.js"]
