# Better Auth service: OAuth 2.1 authorization server for the orders MCP server.
FROM node:22.23.5-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
COPY group_scopes.json public-clients.json mcp-clients.json ./
RUN npm run build

FROM node:22.23.5-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY --from=build /app/dist ./dist
COPY group_scopes.json public-clients.json mcp-clients.json ./
USER 10001:10001
EXPOSE 3000
CMD ["node", "dist/server.js"]
