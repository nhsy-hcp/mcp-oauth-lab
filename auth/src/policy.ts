/** Who may hold which scope. Better Auth is the only place this decision is made. */

export const IDENTITY_SCOPES: ReadonlySet<string> = new Set(["openid", "profile", "email", "offline_access"]);
export const TOOL_SCOPES = ["orders:list", "orders:get", "whoami"] as const;
export const ALL_SCOPES = [...IDENTITY_SCOPES, ...TOOL_SCOPES];

export type GroupScopes = Record<string, string[]>;

/** Scopes the groups allow. Anything that is not a list of strings allows nothing. */
export function allowedScopes(groups: unknown, map: GroupScopes): Set<string> {
  if (!Array.isArray(groups)) return new Set();
  const allowed = new Set<string>();
  for (const group of groups) {
    if (typeof group !== "string" || !Object.hasOwn(map, group)) continue;
    for (const scope of map[group] ?? []) allowed.add(scope);
  }
  return allowed;
}

/** The consent decision: requested scopes narrowed to what the user may hold, or null if no tool scope remains. */
export function narrowScopes(requested: string[], allowed: ReadonlySet<string>): string[] | null {
  const scopes = requested.filter((scope) => IDENTITY_SCOPES.has(scope) || allowed.has(scope));
  return scopes.some((scope) => allowed.has(scope)) ? scopes : null;
}

const CLOCK_SKEW_SECONDS = 60;

/** Whether the Dex sign-in is recent enough to issue tokens. Refreshing cannot extend this limit. */
export function signInIsCurrent(issuedAt: unknown, nowSeconds: number, maxAgeSeconds: number): boolean {
  if (typeof issuedAt !== "number" || !Number.isFinite(issuedAt)) return false;
  return issuedAt <= nowSeconds + CLOCK_SKEW_SECONDS && nowSeconds - issuedAt < maxAgeSeconds;
}

/** The issuance check, on every code exchange and refresh: no tool scope beyond what the user may hold. */
export function scopesPermitted(scopes: string[], allowed: ReadonlySet<string>): boolean {
  return allowed.size > 0 && scopes.every((scope) => IDENTITY_SCOPES.has(scope) || allowed.has(scope));
}
