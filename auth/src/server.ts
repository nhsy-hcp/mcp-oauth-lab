import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { oauthProviderAuthServerMetadata, oauthProviderOpenIdConfigMetadata } from "@better-auth/oauth-provider";
import { toNodeHandler } from "better-auth/node";
import { createAuth } from "./auth.js";
import { loadConfig } from "./config.js";
import { consentPagePolicy } from "./consent.js";
import { logEvent } from "./log.js";

const MAX_FORM_BYTES = 64 * 1024;
const SHUTDOWN_GRACE_MS = 5000;

const config = loadConfig();
const auth = createAuth(config);
const apiHandler = toNodeHandler(auth);
const serverMetadata = oauthProviderAuthServerMetadata(auth);
const openIdMetadata = oauthProviderOpenIdConfigMetadata(auth);

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

async function sendResponse(res: ServerResponse, response: Response): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, key) => {
    if (key !== "set-cookie") headers[key] = value;
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) headers["set-cookie"] = cookies;
  res.writeHead(response.status, headers).end(Buffer.from(await response.arrayBuffer()));
}

function callAuthApi(path: string, body: unknown, req: IncomingMessage): Promise<Response> {
  return auth.handler(
    new Request(`${config.issuer}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        origin: config.baseUrl,
        cookie: req.headers.cookie ?? "",
        "x-forwarded-for": req.socket.remoteAddress ?? "unknown",
      },
      body: JSON.stringify(body),
    }),
  );
}

async function redirectFromApi(response: Response, res: ServerResponse): Promise<void> {
  const body = (await response
    .clone()
    .json()
    .catch(() => ({}))) as { url?: string; redirect_uri?: string };
  const location = body.url ?? body.redirect_uri;
  if (!response.ok || !location) {
    res.writeHead(response.ok ? 502 : response.status, { "content-type": "application/json" }).end(JSON.stringify(body));
    return;
  }
  const headers: Record<string, string | string[]> = { location };
  const cookies = response.headers.getSetCookie();
  if (cookies.length) headers["set-cookie"] = cookies;
  res.writeHead(302, headers).end();
}

function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      data += chunk;
      if (data.length > MAX_FORM_BYTES) reject(new Error("form too large"));
    });
    req.on("end", () => resolve(new URLSearchParams(data)));
    req.on("error", reject);
  });
}

function consentPage(url: URL): string {
  const client = escapeHtml(url.searchParams.get("client_id") ?? "unknown client");
  const scopes = (url.searchParams.get("scope") ?? "").split(" ").filter(Boolean);
  const items = scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Allow access</title></head><body>
<h1>Allow ${client}?</h1><p>It asks for the following. You will only receive the permissions your groups allow.</p><ul>${items}</ul>
<form method="post" action="/consent"><input type="hidden" name="oauth_query" value="${escapeHtml(url.search.slice(1))}">
<button name="accept" value="true">Allow</button> <button name="accept" value="false">Deny</button></form></body></html>`;
}

function signOutPage(signedOut: boolean): string {
  const body = signedOut
    ? "<h1>Signed out</h1><p>Your browser session has ended. You will need to sign in again.</p>"
    : '<h1>Sign out?</h1><p>This ends your browser session. To clear Claude Code\'s tokens too, run <code>claude mcp logout orders</code>.</p><form method="post" action="/sign-out"><button>Sign out</button></form>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign out</title></head><body>${body}</body></html>`;
}

function refuseCrossOrigin(req: IncomingMessage, res: ServerResponse): boolean {
  if (!req.headers.origin || req.headers.origin === config.baseUrl) return false;
  res.writeHead(403, { "content-type": "text/plain" }).end("cross-origin request refused");
  return true;
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  req.headers["x-forwarded-for"] = req.socket.remoteAddress ?? "unknown";
  const url = new URL(req.url ?? "/", config.baseUrl);
  const webRequest = () => new Request(url, { headers: req.headers as Record<string, string> });
  const issuerPath = new URL(config.issuer).pathname;

  if (url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" }).end("ok");
  } else if (url.pathname === `/.well-known/oauth-authorization-server${issuerPath}`) {
    await sendResponse(res, await serverMetadata(webRequest()));
  } else if (url.pathname === `/.well-known/openid-configuration${issuerPath}` || url.pathname === `${issuerPath}/.well-known/openid-configuration`) {
    await sendResponse(res, await openIdMetadata(webRequest()));
  } else if (url.pathname.startsWith(`${issuerPath}/`)) {
    await apiHandler(req, res);
  } else if (url.pathname === "/sign-in" && req.method === "GET") {
    await redirectFromApi(await callAuthApi("/sign-in/social", { provider: "dex", callbackURL: "/signed-in", oauth_query: url.search.slice(1) }, req), res);
  } else if (url.pathname === "/signed-in" && req.method === "GET") {
    res.writeHead(200, { "content-type": "text/plain" }).end("Signed in. You can close this window.");
  } else if (url.pathname === "/consent" && req.method === "GET") {
    res
      .writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": consentPagePolicy(url.searchParams.get("redirect_uri")) })
      .end(consentPage(url));
  } else if (url.pathname === "/consent" && req.method === "POST") {
    if (refuseCrossOrigin(req, res)) return;
    const form = await readForm(req);
    await redirectFromApi(
      await callAuthApi("/oauth2/consent", { accept: form.get("accept") === "true", oauth_query: form.get("oauth_query") ?? "" }, req),
      res,
    );
  } else if (url.pathname === "/sign-out" && req.method === "GET") {
    res
      .writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": consentPagePolicy(null) })
      .end(signOutPage(url.searchParams.has("done")));
  } else if (url.pathname === "/sign-out" && req.method === "POST") {
    if (refuseCrossOrigin(req, res)) return;
    const response = await callAuthApi("/sign-out", {}, req);
    if (!response.ok) {
      await sendResponse(res, response);
      return;
    }
    res.writeHead(303, { location: "/sign-out?done=1", "set-cookie": response.headers.getSetCookie() }).end();
  } else {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  }
}

const server = http.createServer((req, res) => {
  route(req, res).catch((error: unknown) => {
    logEvent("request_failed", { path: req.url?.split("?")[0], error: error instanceof Error ? error.message : "unknown" });
    if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain" });
    res.end("internal error");
  });
});

server.listen(config.port, "0.0.0.0", () => logEvent("listening", { port: config.port, issuer: config.issuer, resource: config.mcpResource }));

function shutdown(signal: string): void {
  logEvent("stopping", { signal });
  server.close(() => process.exit(0));
  server.closeIdleConnections();
  setTimeout(() => process.exit(0), SHUTDOWN_GRACE_MS).unref();
}

process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));
