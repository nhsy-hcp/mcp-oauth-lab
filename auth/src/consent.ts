/** Security policy for the consent page. */
export function consentPagePolicy(redirectUri: string | null): string {
  // Browsers such as Chrome apply form-action to redirects after the form post, so the client's callback must be allowed.
  const sources = ["'self'"];
  try {
    const url = new URL(redirectUri ?? "");
    if (url.protocol === "http:" || url.protocol === "https:") sources.push(url.origin);
  } catch {
    // No usable callback: only this site may receive the form.
  }
  return `default-src 'none'; frame-ancestors 'none'; form-action ${sources.join(" ")}`;
}
