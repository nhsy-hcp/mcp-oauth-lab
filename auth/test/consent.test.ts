import { describe, expect, it } from "vitest";
import { consentPagePolicy } from "../src/consent.js";

describe("consentPagePolicy", () => {
  it("allows the redirect to the client's loopback callback", () => {
    expect(consentPagePolicy("http://localhost:33418/callback")).toBe("default-src 'none'; frame-ancestors 'none'; form-action 'self' http://localhost:33418");
  });

  it.each([[null], ["not a url"], ["javascript:alert(1)"], ["claude://callback"]])("allows only this site for %j", (redirectUri) => {
    expect(consentPagePolicy(redirectUri)).toBe("default-src 'none'; frame-ancestors 'none'; form-action 'self'");
  });

  it("cannot be used to inject another directive", () => {
    expect(consentPagePolicy("http://localhost:1/;script-src *")).toBe("default-src 'none'; frame-ancestors 'none'; form-action 'self' http://localhost:1");
  });
});
