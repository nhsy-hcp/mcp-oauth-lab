import { beforeEach, describe, expect, it, vi } from "vitest";
import { toMachineClients } from "../src/config.js";
import { createServiceAccountAuth, type TokenReviewStatus } from "../src/serviceAccount.js";

const ISSUER = "http://localhost:3000/api/auth";
const clients = toMachineClients([
  { name: "mcp-client-orders-agent", application_name: "orders-agent", scopes: ["orders:list"] },
  { name: "mcp-client-unlisted", application_name: "unlisted-agent", scopes: [] },
]);
const ORDERS_SA = "system:serviceaccount:mcp-client-orders-agent:mcp-client-orders-agent-sa";
const valid: TokenReviewStatus = { authenticated: true, audiences: [ISSUER], user: { username: ORDERS_SA } };

function strategy(status: TokenReviewStatus | Error) {
  const review = vi.fn(async () => {
    if (status instanceof Error) throw status;
    return status;
  });
  return { review, auth: createServiceAccountAuth(clients, ISSUER, review) };
}

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => undefined);
});

describe("toMachineClients", () => {
  it("makes OAuth clients only for workloads with scopes", () => {
    expect(clients).toEqual([{ id: "orders-agent", serviceAccount: ORDERS_SA, scopes: ["orders:list"] }]);
  });
});

describe("service account client authentication", () => {
  it("maps a reviewed token to its client and reviews it for this issuer", async () => {
    const { auth, review } = strategy(valid);
    await expect(auth.authenticate({ assertion: "jwt" })).resolves.toEqual({ clientId: "orders-agent" });
    expect(review).toHaveBeenCalledWith("jwt", ISSUER);
  });

  it("accepts a matching client_id", async () => {
    await expect(strategy(valid).auth.authenticate({ assertion: "jwt", clientId: "orders-agent" })).resolves.toEqual({ clientId: "orders-agent" });
  });

  it.each<[string, TokenReviewStatus]>([
    ["not authenticated (expired, deleted or forged)", { ...valid, authenticated: false }],
    ["missing authenticated flag", { audiences: [ISSUER], user: { username: ORDERS_SA } }],
    ["wrong audience", { ...valid, audiences: ["https://kubernetes.default.svc"] }],
    ["no audiences", { authenticated: true, user: { username: ORDERS_SA } }],
    ["no username", { authenticated: true, audiences: [ISSUER] }],
    ["unmapped service account", { ...valid, user: { username: "system:serviceaccount:mcp-server-dev:mcp-server-dev-sa" } }],
    ["workload without scopes", { ...valid, user: { username: "system:serviceaccount:mcp-client-unlisted:mcp-client-unlisted-sa" } }],
  ])("refuses %s", async (_name, status) => {
    await expect(strategy(status).auth.authenticate({ assertion: "jwt" })).rejects.toMatchObject({ body: { error: "invalid_client" } });
  });

  it("refuses a client_id that differs from the service account", async () => {
    await expect(strategy(valid).auth.authenticate({ assertion: "jwt", clientId: "reporting-agent" })).rejects.toMatchObject({
      body: { error: "invalid_client" },
    });
  });

  it("fails closed when TokenReview is unavailable", async () => {
    await expect(strategy(new Error("connection refused")).auth.authenticate({ assertion: "jwt" })).rejects.toMatchObject({
      body: { error: "invalid_client" },
    });
  });
});
