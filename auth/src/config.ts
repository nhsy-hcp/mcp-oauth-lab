import { readFileSync } from "node:fs";

export interface AuthConfig {
  baseUrl: string;
  issuer: string;
  secret: string;
  databaseUrl: string;
  dexIssuer: string;
  dexClientSecret: string;
  mcpResource: string;
  accessTokenTtlSeconds: number;
  signInTtlSeconds: number;
  port: number;
}

export interface PublicClient {
  id: string;
  redirectUris: string[];
}

export interface MachineClient {
  id: string;
  serviceAccount: string;
  scopes: string[];
}

interface WorkloadEntry {
  name: string;
  application_name: string;
  scopes?: string[];
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function positiveInt(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AuthConfig {
  const baseUrl = required(env, "BETTER_AUTH_URL").replace(/\/$/, "");
  return {
    baseUrl,
    issuer: `${baseUrl}/api/auth`,
    secret: required(env, "BETTER_AUTH_SECRET"),
    databaseUrl: required(env, "DATABASE_URL"),
    dexIssuer: required(env, "DEX_ISSUER").replace(/\/$/, ""),
    dexClientSecret: required(env, "DEX_CLIENT_SECRET"),
    mcpResource: required(env, "MCP_RESOURCE"),
    accessTokenTtlSeconds: positiveInt(env, "ACCESS_TOKEN_TTL_SECONDS", 300),
    signInTtlSeconds: positiveInt(env, "SIGN_IN_TTL_SECONDS", 8 * 3600),
    port: positiveInt(env, "PORT", 3000),
  };
}

function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(new URL(`../${file}`, import.meta.url), "utf8")) as T;
}

export const loadGroupScopes = (): Record<string, string[]> => readJson("group_scopes.json");
export const loadPublicClients = (): PublicClient[] => readJson("public-clients.json");

/** Pods with at least one scope are OAuth clients. Their identity is their exact ServiceAccount. */
export function toMachineClients(entries: WorkloadEntry[]): MachineClient[] {
  return entries
    .filter((entry) => (entry.scopes ?? []).length > 0)
    .map((entry) => ({
      id: entry.application_name,
      serviceAccount: `system:serviceaccount:${entry.name}:${entry.name}-sa`,
      scopes: entry.scopes ?? [],
    }));
}

export const loadMachineClients = (): MachineClient[] => toMachineClients(readJson("mcp-clients.json"));
