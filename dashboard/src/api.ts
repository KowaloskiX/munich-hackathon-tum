import type { DemoResetResult } from "./types";

function localBackendOrigin(protocol: "http" | "ws"): string {
  const hostname = typeof window === "undefined" ? "localhost" : window.location.hostname;
  return `${protocol}://${hostname || "localhost"}:8000`;
}

// Keep REST and WebSocket calls on the same hostname as the page. This matters
// in local development where localhost and 127.0.0.1 are different CORS origins.
export function apiBase(): string {
  const explicit = import.meta.env.VITE_API_URL as string | undefined;
  if (explicit) return explicit.replace(/\/$/, "");
  const ws = import.meta.env.VITE_WS_URL as string | undefined;
  if (ws) return ws.replace(/^ws/, "http").replace(/\/live$/, "");
  return localBackendOrigin("http");
}

export function liveUrl(): string {
  const explicit = import.meta.env.VITE_WS_URL as string | undefined;
  return explicit ?? `${localBackendOrigin("ws")}/live`;
}

export function emailLiveUrl(): string {
  const explicit = import.meta.env.VITE_EMAIL_WS_URL as string | undefined;
  return explicit ?? `${localBackendOrigin("ws")}/v1/email/live`;
}

export function incidentReportUrl(incidentId: string): string {
  return `${apiBase()}/incidents/${encodeURIComponent(incidentId)}/report.md`;
}

export function commandReportUrl(reportId: string): string {
  return `${apiBase()}/v1/command/reports/${encodeURIComponent(reportId)}.md`;
}

export async function flushFixes(): Promise<DemoResetResult> {
  const response = await fetch(`${apiBase()}/demo/reset`, { method: "POST" });
  if (!response.ok) throw new Error(`Reset failed (${response.status})`);
  return (await response.json()) as DemoResetResult;
}
