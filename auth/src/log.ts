/** One JSON object per line. Tokens, secrets and passwords are never passed here. */
export function logEvent(event: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}
