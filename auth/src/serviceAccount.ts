/** OAuth client authentication for pods: a Kubernetes ServiceAccount JWT checked with TokenReview. */

import { readFileSync } from "node:fs";
import https from "node:https";
import { APIError } from "better-auth/api";
import type { MachineClient } from "./config.js";
import { logEvent } from "./log.js";

export const SERVICE_ACCOUNT_METHOD = "kubernetes_service_account";
export const SERVICE_ACCOUNT_ASSERTION = "urn:lab:params:oauth:client-assertion-type:kubernetes-service-account";

const SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";

export interface TokenReviewStatus {
  authenticated?: boolean;
  audiences?: string[];
  user?: { username?: string };
}

export type TokenReviewer = (token: string, audience: string) => Promise<TokenReviewStatus>;

export const reviewToken: TokenReviewer = (token, audience) => {
  const body = JSON.stringify({ apiVersion: "authentication.k8s.io/v1", kind: "TokenReview", spec: { token, audiences: [audience] } });
  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        host: process.env.KUBERNETES_SERVICE_HOST,
        port: process.env.KUBERNETES_SERVICE_PORT,
        path: "/apis/authentication.k8s.io/v1/tokenreviews",
        method: "POST",
        ca: readFileSync(`${SA_DIR}/ca.crt`),
        headers: { authorization: `Bearer ${readFileSync(`${SA_DIR}/token`, "utf8").trim()}`, "content-type": "application/json" },
        timeout: 5000,
      },
      (response) => {
        let data = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => {
          data += chunk;
        });
        response.on("end", () => {
          if (response.statusCode !== 201) {
            reject(new Error(`TokenReview returned ${response.statusCode}`));
            return;
          }
          try {
            resolve((JSON.parse(data) as { status?: TokenReviewStatus }).status ?? {});
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("TokenReview timed out")));
    request.on("error", reject);
    request.end(body);
  });
};

const refuse = (description: string) => new APIError("UNAUTHORIZED", { error: "invalid_client", error_description: description });

/**
 * Proves which OAuth client a pod is. Every failure refuses the request. Better Auth then checks that the
 * client exists, is enabled and uses this method, and caps its scopes.
 *
 * A projected token is reused until the kubelet rotates it, so this cannot enforce single use.
 * The token is bound to this issuer's audience and expires within 10 minutes.
 */
export function createServiceAccountAuth(clients: MachineClient[], issuer: string, review: TokenReviewer = reviewToken) {
  const byServiceAccount = new Map(clients.map((client) => [client.serviceAccount, client.id]));
  return {
    assertionTypes: [SERVICE_ACCOUNT_ASSERTION],
    async authenticate({ assertion, clientId }: { assertion: string; clientId?: string }) {
      let status: TokenReviewStatus;
      try {
        status = await review(assertion, issuer);
      } catch (error) {
        logEvent("client_auth_failed", { reason: "tokenreview_unavailable", error: error instanceof Error ? error.message : "unknown" });
        throw refuse("service account token could not be verified");
      }
      const username = status.user?.username;
      if (status.authenticated !== true || !status.audiences?.includes(issuer) || !username) {
        logEvent("client_auth_failed", { reason: "token_rejected" });
        throw refuse("service account token rejected");
      }
      const id = byServiceAccount.get(username);
      if (!id) {
        logEvent("client_auth_failed", { reason: "unmapped_service_account", service_account: username });
        throw refuse("service account is not an OAuth client");
      }
      if (clientId && clientId !== id) {
        logEvent("client_auth_failed", { reason: "client_id_mismatch", service_account: username });
        throw refuse("client_id does not match service account");
      }
      logEvent("client_authenticated", { client: id, service_account: username });
      return { clientId: id };
    },
  };
}
