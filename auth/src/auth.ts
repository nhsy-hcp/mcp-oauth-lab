import { mcp } from "@better-auth/mcp";
import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { genericOAuth, jwt } from "better-auth/plugins";
import { decodeJwt, type JWTPayload } from "jose";
import pg from "pg";
import { type AuthConfig, loadGroupScopes, loadMachineClients } from "./config.js";
import { logEvent } from "./log.js";
import { ALL_SCOPES, allowedScopes, IDENTITY_SCOPES, narrowScopes, scopesPermitted, signInIsCurrent } from "./policy.js";
import { createServiceAccountAuth, SERVICE_ACCOUNT_METHOD } from "./serviceAccount.js";

export const SEEDER_EMAIL = "seeder@auth.internal";
const SESSION_SECONDS = 8 * 3600;
const USER_GRANTS: ReadonlySet<unknown> = new Set(["authorization_code", "refresh_token"]);

/** Set only by the seed job, so seeded clients get stable, readable ids. */
export const seedState: { nextClientId?: string } = {};

export function createAuth(config: AuthConfig) {
  const groupScopes = loadGroupScopes();
  const denied = (description: string) => new APIError("FORBIDDEN", { error: "access_denied", error_description: description });

  // Identity comes from the Dex ID token Better Auth verified and stored at the last sign-in. Fails closed.
  async function dexClaims(userId: string | undefined): Promise<JWTPayload> {
    if (!userId) return {};
    try {
      const context = await auth.$context;
      const accounts = await context.internalAdapter.findAccounts(userId);
      const idToken = accounts.find((account) => account.providerId === "dex")?.idToken;
      return idToken ? decodeJwt(idToken) : {};
    } catch (error) {
      logEvent("dex_claims_unavailable", { error: error instanceof Error ? error.message : "unknown" });
      return {};
    }
  }

  const auth = betterAuth({
    baseURL: config.baseUrl,
    secret: config.secret,
    trustedOrigins: [config.baseUrl],
    database: new pg.Pool({ connectionString: config.databaseUrl, max: 5 }),
    disabledPaths: [
      "/token",
      "/oauth2/update-consent",
      "/update-user",
      "/change-email",
      "/delete-user",
      "/link-social",
      "/unlink-account",
      "/get-access-token",
      "/refresh-token",
    ],
    // A browser session must not outlive the sign-in limit, or a new login could not reach Dex.
    session: { expiresIn: Math.min(SESSION_SECONDS, config.signInTtlSeconds) },
    // server.ts sets this header from the socket address, so a client cannot choose its rate-limit bucket.
    advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"] } },
    rateLimit: { enabled: true, customRules: { "/sign-in/social": { window: 10, max: 30 } } },
    databaseHooks: {
      account: {
        update: {
          // A Dex sign-in may change the user's groups, so old consent must not outlive it.
          after: async (account) => {
            if (account.providerId !== "dex") return;
            const context = await auth.$context;
            await context.adapter.deleteMany({ model: "oauthConsent", where: [{ field: "userId", value: account.userId }] });
          },
        },
      },
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        // User tokens are always issued for the MCP resource, so they always pass the scope check below.
        if (ctx.path === "/oauth2/token" && USER_GRANTS.has(ctx.body?.grant_type) && !ctx.body?.resource) {
          return { context: { body: { ...ctx.body, resource: config.mcpResource } } };
        }
        if (ctx.path !== "/oauth2/consent" || ctx.body?.accept !== true) return;
        const session = await getSessionFromCtx(ctx);
        const allowed = allowedScopes((await dexClaims(session?.user.id)).groups, groupScopes);
        const signed = new URLSearchParams(typeof ctx.body.oauth_query === "string" ? ctx.body.oauth_query : "");
        const asked = (typeof ctx.body.scope === "string" ? ctx.body.scope : (signed.get("scope") ?? "")).split(" ").filter(Boolean);
        const scopes = narrowScopes(asked, allowed);
        if (!scopes) {
          logEvent("consent_denied", { user: session?.user.id, requested: asked });
          throw denied("no requested scope is allowed for this user");
        }
        return { context: { body: { ...ctx.body, scope: scopes.join(" ") } } };
      }),
    },
    plugins: [
      jwt({ disableSettingJwtHeader: true, jwks: { keyPairConfig: { alg: "ES256" } } }),
      genericOAuth({
        config: [
          {
            providerId: "dex",
            clientId: "better-auth",
            clientSecret: config.dexClientSecret,
            discoveryUrl: `${config.dexIssuer}/.well-known/openid-configuration`,
            requireIdTokenVerification: true,
            scopes: ["openid", "email", "profile", "groups"],
            overrideUserInfo: true,
            getUserInfo: async (tokens) => {
              const claims = decodeJwt(tokens.idToken ?? "");
              const email = typeof claims.email === "string" ? claims.email : "";
              const name = typeof claims.preferred_username === "string" ? claims.preferred_username : email;
              return { id: String(claims.sub), sub: claims.sub, email, emailVerified: true, name };
            },
          },
        ],
      }),
      mcp({
        loginPage: "/sign-in",
        consentPage: "/consent",
        resource: config.mcpResource,
        scopes: ALL_SCOPES,
        accessTokenExpiresIn: config.accessTokenTtlSeconds,
        m2mAccessTokenExpiresIn: config.accessTokenTtlSeconds,
        refreshTokenExpiresIn: SESSION_SECONDS,
        refreshTokenReuseInterval: 0,
        // All laptop traffic shares one address through k3d, so the defaults are too low for the lab's clients and demos.
        rateLimit: { token: { window: 60, max: 300 }, authorize: { window: 60, max: 120 } },
        generateClientId: () => seedState.nextClientId ?? crypto.randomUUID(),
        clientPrivileges: ({ user }) => user?.email === SEEDER_EMAIL,
        customAccessTokenClaims: async ({ user, scopes }) => {
          if (user === undefined) return {};
          const claims = await dexClaims(user?.id);
          const requested = scopes as string[];
          // The Dex ID token's issue time is the sign-in time, so refreshing never extends this limit.
          if (user && !signInIsCurrent(claims.iat, Math.floor(Date.now() / 1000), config.signInTtlSeconds)) {
            logEvent("token_refused", { user: user.id, reason: "sign_in_expired" });
            throw new APIError("BAD_REQUEST", { error: "invalid_grant", error_description: "sign-in has expired" });
          }
          if (!user || !scopesPermitted(requested, allowedScopes(claims.groups, groupScopes))) {
            logEvent("token_refused", { user: user?.id, scopes: requested });
            throw denied("scopes exceed what this user may hold");
          }
          logEvent("token_issued", {
            sub: user.id,
            preferred_username: claims.preferred_username,
            scopes: requested.filter((scope) => !IDENTITY_SCOPES.has(scope)),
          });
          return { preferred_username: claims.preferred_username };
        },
        extensions: [{ clientAuthentication: { [SERVICE_ACCOUNT_METHOD]: createServiceAccountAuth(loadMachineClients(), config.issuer) } }],
      }),
    ],
  });
  return auth;
}
