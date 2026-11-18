import { describe, expect, it } from "vitest";
import { allowedScopes, narrowScopes, scopesPermitted, signInIsCurrent } from "../src/policy.js";

const map = { reader: ["orders:list", "orders:get", "whoami"], reporter: ["orders:list"] };
const ALL = ["openid", "offline_access", "orders:list", "orders:get", "whoami"];

describe("allowedScopes", () => {
  it("combines the scopes of known groups", () => {
    expect([...allowedScopes(["reporter", "unknown"], map)]).toEqual(["orders:list"]);
  });

  it.each([[undefined], [null], ["reader"], [{ reader: true }], [[1, null]], [["__proto__"]], [["constructor"]]])("allows nothing for %j", (groups) => {
    expect(allowedScopes(groups, map).size).toBe(0);
  });
});

describe("narrowScopes", () => {
  it("keeps identity scopes and the tool scopes the user may hold", () => {
    expect(narrowScopes(ALL, allowedScopes(["reporter"], map))).toEqual(["openid", "offline_access", "orders:list"]);
  });

  it("refuses when no tool scope remains", () => {
    expect(narrowScopes(["openid", "orders:get"], allowedScopes(["reporter"], map))).toBeNull();
    expect(narrowScopes(ALL, new Set())).toBeNull();
  });

  it("drops unknown scopes", () => {
    expect(narrowScopes(["orders:list", "orders:delete"], allowedScopes(["reader"], map))).toEqual(["orders:list"]);
  });
});

describe("signInIsCurrent", () => {
  const now = 1_000_000;
  const eightHours = 8 * 3600;

  it("accepts a sign-in inside the limit", () => {
    expect(signInIsCurrent(now - eightHours + 1, now, eightHours)).toBe(true);
  });

  it("refuses a sign-in at or beyond the limit", () => {
    expect(signInIsCurrent(now - eightHours, now, eightHours)).toBe(false);
  });

  it("allows small clock differences but not a future sign-in", () => {
    expect(signInIsCurrent(now + 30, now, eightHours)).toBe(true);
    expect(signInIsCurrent(now + 3600, now, eightHours)).toBe(false);
  });

  it.each([[undefined], [null], ["1000000"], [Number.NaN]])("refuses %j", (issuedAt) => {
    expect(signInIsCurrent(issuedAt, now, eightHours)).toBe(false);
  });
});

describe("scopesPermitted", () => {
  it("accepts scopes within the allowed set", () => {
    expect(scopesPermitted(["openid", "orders:list"], allowedScopes(["reporter"], map))).toBe(true);
  });

  it("refuses any scope beyond the allowed set", () => {
    expect(scopesPermitted(["orders:list", "orders:get"], allowedScopes(["reporter"], map))).toBe(false);
  });

  it("refuses a user with no allowed scope, even for identity scopes alone", () => {
    expect(scopesPermitted(["openid"], new Set())).toBe(false);
  });
});
