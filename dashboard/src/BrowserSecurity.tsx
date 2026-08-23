import "./BrowserSecurity.css";

import { useEffect, useMemo, useRef, useState } from "react";

import { isLinkEvent, LINK_PHASES, linkPhaseIndex, linkVerdictFromEvent } from "./browserView";
import type { LinkLiveEvent } from "./browserView";
import type { LinkScanIn, LinkVerdict } from "./types";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const LIVE_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/live";

const PHASE_COPY = {
  LINK_SUBMITTED: ["01", "Submitted", "Normalize the URL and open a fresh case."],
  LINK_BROWSING: ["02", "Browse", "Inspect the destination and the page it presents."],
  LINK_RESEARCHING: ["03", "Research", "Check ownership, reputation and impersonation signals."],
  LINK_VERDICT: ["04", "Verdict", "Combine independent signals into one legitimacy score."],
} as const;

function safeUrl(value: string): string | null {
  try {
    const parsed = new URL(value.trim());
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}

function verdictLabel(verdict: LinkVerdict["verdict"]): string {
  if (verdict === "legit") return "Looks legitimate";
  if (verdict === "suspicious") return "Proceed with caution";
  return "Likely malicious";
}

export function BrowserSecurity() {
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<LinkLiveEvent[]>([]);
  const [verdict, setVerdict] = useState<LinkVerdict | null>(null);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const activeUrl = useRef<string | null>(null);

  useEffect(() => {
    let socket: WebSocket | undefined;
    let retry: ReturnType<typeof setTimeout>;
    let closed = false;
    const connect = () => {
      socket = new WebSocket(LIVE_URL);
      socket.onopen = () => setConnected(true);
      socket.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 1200);
      };
      socket.onmessage = (message) => {
        try {
          const raw = JSON.parse(message.data) as { type?: unknown; payload?: unknown };
          if (typeof raw.type !== "string" || !isLinkEvent(raw.type) || typeof raw.payload !== "object" || raw.payload === null) return;
          const incoming = raw as LinkLiveEvent;
          const eventUrl = String(incoming.payload.url ?? "");
          if (activeUrl.current === null || (eventUrl && eventUrl !== activeUrl.current)) return;
          setEvents((current) => [incoming, ...current].slice(0, 12));
          const nextVerdict = linkVerdictFromEvent(incoming);
          if (nextVerdict) {
            setVerdict(nextVerdict);
            setBusy(false);
            activeUrl.current = null;
          }
        } catch {
          // Ignore malformed live frames; boundary validation happens in the backend.
        }
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      socket?.close();
    };
  }, []);

  const activePhase = useMemo(() => linkPhaseIndex(events[0]?.type ?? null), [events]);

  const submit = async () => {
    const normalized = safeUrl(url);
    if (!normalized) {
      setError("Enter a complete http:// or https:// address.");
      return;
    }
    const payload: LinkScanIn = { url: normalized, source: "dashboard" };
    setError(null);
    setVerdict(null);
    setEvents([]);
    setBusy(true);
    activeUrl.current = normalized;
    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error((await response.text()) || `Scan failed: ${response.status}`);
    } catch (reason) {
      setBusy(false);
      activeUrl.current = null;
      setError(reason instanceof Error ? reason.message : "Could not start the scan");
    }
  };

  return (
    <main className="browser-workspace">
      <section className="browser-intro">
        <div>
          <span className="browser-kicker">02 / Browser shield</span>
          <h1>PASTE THE LINK.<br /><em>SCOPE THE TRAP.</em></h1>
        </div>
        <p>Two independent agents inspect what the page shows and what the internet knows. SCOPE turns both into one clear legitimacy score.</p>
      </section>

      <section className="link-console" aria-labelledby="link-scan-title">
        <div className="link-console-heading">
          <div><span className="browser-kicker">Manual scan</span><h2 id="link-scan-title">Check any URL</h2></div>
          <span className="browser-connection" data-connected={connected || undefined}><i />{connected ? "Live events connected" : "Connecting to backend"}</span>
        </div>
        <form onSubmit={(event) => { event.preventDefault(); void submit(); }}>
          <label htmlFor="link-url">Website address</label>
          <div className="link-input-row">
            <input id="link-url" type="url" inputMode="url" placeholder="https://example.com" value={url} onChange={(event) => setUrl(event.target.value)} />
            <button type="submit" disabled={busy}>{busy ? "Scanning…" : "Scan link"}<span aria-hidden="true">↗</span></button>
          </div>
          {error ? <p className="browser-error" role="alert">{error}</p> : null}
        </form>
        <div className="example-links">
          <span>Quick test</span>
          <button type="button" onClick={() => setUrl("https://paypal.com")}>Official domain</button>
          <button type="button" onClick={() => setUrl("https://paypal-login.pages.dev")}>Suspicious domain</button>
        </div>
      </section>

      <section className="scan-pipeline" aria-label="Link scan pipeline">
        {LINK_PHASES.map((phase, index) => {
          const [number, title, copy] = PHASE_COPY[phase];
          const state = index < activePhase ? "done" : index === activePhase ? "active" : "waiting";
          return <article data-state={state} key={phase}><span>{number}</span><div><strong>{title}</strong><p>{copy}</p></div><i aria-hidden="true" /></article>;
        })}
      </section>

      <section className="link-result" data-verdict={verdict?.verdict ?? "waiting"} aria-live="polite">
        {verdict ? (
          <>
            <div className="result-score"><strong>{Math.round(verdict.legit_score * 100)}</strong><span>/ 100<br />legitimacy</span></div>
            <div className="result-copy">
              <span>{verdict.verdict}</span>
              <h2>{verdictLabel(verdict.verdict)}</h2>
              <p>{verdict.url}</p>
              {verdict.impersonated_brand ? <b>Possible impersonation: {verdict.impersonated_brand}</b> : null}
            </div>
            <div className="result-signals">
              <span>Top signals</span>
              {verdict.top_signals.length > 0 ? verdict.top_signals.map((signal) => <p key={signal}>{signal}</p>) : <p>No suspicious host or impersonation signals.</p>}
            </div>
          </>
        ) : (
          <div className="result-empty"><i aria-hidden="true" /><strong>{busy ? "Agents are investigating" : "No verdict yet"}</strong><span>{busy ? "Live steps will appear above as the scan progresses." : "Submit a URL to start the autonomous browser and research agents."}</span></div>
        )}
      </section>
    </main>
  );
}
