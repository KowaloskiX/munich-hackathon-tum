// HTTP base for REST calls (incident reports). The live feed is WebSocket
// (see useLive.ts); this derives the matching http origin from VITE_WS_URL, or
// an explicit VITE_API_URL override.
export function apiBase(): string {
  const explicit = import.meta.env.VITE_API_URL as string | undefined;
  if (explicit) return explicit.replace(/\/$/, "");
  const ws = (import.meta.env.VITE_WS_URL as string | undefined) ?? "ws://localhost:8000/live";
  return ws.replace(/^ws/, "http").replace(/\/live$/, "");
}

export function incidentReportUrl(incidentId: string): string {
  return `${apiBase()}/incidents/${encodeURIComponent(incidentId)}/report.md`;
}
