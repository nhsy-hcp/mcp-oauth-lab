/** Creates or corrects the OAuth clients. Safe to re-run; a disabled client stays disabled. */

import { serializeSignedCookie } from "better-call";
import { createAuth, SEEDER_EMAIL, seedState } from "./auth.js";
import { loadConfig, loadMachineClients, loadPublicClients } from "./config.js";
import { logEvent } from "./log.js";
import { ALL_SCOPES } from "./policy.js";
import { SERVICE_ACCOUNT_METHOD } from "./serviceAccount.js";

interface DesiredClient {
  id: string;
  scopes: string[];
  redirectUris: string[];
  machineScopes: string[];
  authMethod: string;
  grantTypes: string[];
  body: Record<string, unknown>;
}

interface StoredClient {
  id: string;
  clientId: string;
  tokenEndpointAuthMethod?: string | null;
  grantTypes?: string[] | string | null;
  scopes?: string[] | string | null;
  redirectUris?: string[] | string | null;
  clientCredentialsScopes?: string[] | string | null;
}

const list = (value: string[] | string | null | undefined): string[] => {
  if (Array.isArray(value)) return [...value].sort();
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String).sort() : [];
  } catch {
    return value.split(/[ ,]/).filter(Boolean).sort();
  }
};
const same = (a: string[], b: string[]) => JSON.stringify(a) === JSON.stringify([...b].sort());

const config = loadConfig();
const auth = createAuth(config);
const context = await auth.$context;

const desired: DesiredClient[] = [
  ...loadPublicClients().map((client) => ({
    id: client.id,
    scopes: ALL_SCOPES,
    redirectUris: client.redirectUris,
    machineScopes: [],
    authMethod: "none",
    grantTypes: ["authorization_code", "refresh_token"],
    body: {
      client_name: client.id,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: client.redirectUris,
      scope: ALL_SCOPES.join(" "),
      application_type: "native",
      resources: [config.mcpResource],
    },
  })),
  ...loadMachineClients().map((client) => ({
    id: client.id,
    scopes: client.scopes,
    redirectUris: [],
    machineScopes: client.scopes,
    authMethod: SERVICE_ACCOUNT_METHOD,
    grantTypes: ["client_credentials"],
    body: {
      client_name: client.id,
      token_endpoint_auth_method: SERVICE_ACCOUNT_METHOD,
      grant_types: ["client_credentials"],
      response_types: [],
      scope: client.scopes.join(" "),
      client_credentials_scopes: client.scopes,
      resources: [config.mcpResource],
    },
  })),
];

const seeder =
  (await context.internalAdapter.findUserByEmail(SEEDER_EMAIL))?.user ??
  (await context.internalAdapter.createUser({ email: SEEDER_EMAIL, name: "seeder", emailVerified: true }, { method: "admin" }));
const session = await context.internalAdapter.createSession(seeder.id);
const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, session.token, context.secret)).split(";")[0] ?? "";
const headers = new Headers({ cookie });

try {
  // A client removed from the lists must stop working.
  const wanted = new Set(desired.map((client) => client.id));
  const owned = await context.adapter.findMany<StoredClient>({ model: "oauthClient", where: [{ field: "userId", value: seeder.id }] });
  for (const client of owned.filter((stored) => !wanted.has(stored.clientId))) {
    await context.adapter.delete({ model: "oauthClient", where: [{ field: "clientId", value: client.clientId }] });
    logEvent("client_removed", { client: client.clientId });
  }

  for (const client of desired) {
    const where = [{ field: "clientId", value: client.id }];
    const stored = await context.adapter.findOne<StoredClient>({ model: "oauthClient", where });
    if (stored) {
      const links = await context.adapter.findMany<{ resourceId: string }>({ model: "oauthClientResource", where });
      const unchanged =
        stored.tokenEndpointAuthMethod === client.authMethod &&
        same(list(stored.grantTypes), client.grantTypes) &&
        same(list(stored.scopes), client.scopes) &&
        same(list(stored.redirectUris), client.redirectUris) &&
        same(list(stored.clientCredentialsScopes), client.machineScopes) &&
        same(links.map((link) => link.resourceId).sort(), [config.mcpResource]);
      if (unchanged) continue;
      // Linked resources and the auth method are create-only, so a changed client is recreated.
      await context.adapter.delete({ model: "oauthClient", where });
    }
    seedState.nextClientId = client.id;
    await auth.api.adminCreateOAuthClient({ body: client.body as never, headers });
    logEvent("client_seeded", { client: client.id, replaced: Boolean(stored) });
  }
} finally {
  seedState.nextClientId = undefined;
  await context.internalAdapter.deleteSession(session.token);
}
process.exit(0);
