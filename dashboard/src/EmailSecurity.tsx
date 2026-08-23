import "./EmailSecurity.css";
import { useCallback, useEffect, useRef, useState } from "react";

import { apiBase, emailLiveUrl } from "./api";
import type {
  EmailAnalysisDetail,
  EmailAnalysisList,
  EmailAnalysisSummary,
  EmailConnectionStatus,
  EmailImportResult,
  EmailLiveEvent,
  EmailMessagePreview,
  EmailMessagePreviewList,
  EmailMonitoringMode,
  EmailReviewDecision,
} from "./types";
import { emailVerdictLabel, formatRiskScore, newestEmailsFirst, pendingEmailCount } from "./emailView";

const API_URL = apiBase();
const EMAIL_WS_URL = emailLiveUrl();

const EMPTY_STATUS: EmailConnectionStatus = {
  connected: false,
  email: null,
  mode: "ALL",
  watch_expiration: null,
  last_sync: null,
  labels: { scan: "", pending_review: "", confirmed_dangerous: "", not_dangerous: "" },
  csrf_token: null,
};

function clock(value: number | null): string {
  if (value === null) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value * 1000));
}

async function jsonRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { credentials: "include", ...init });
  if (response.status === 401) throw new GmailSessionExpiredError();
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const detail = typeof body === "object" && body !== null && "detail" in body
      ? (body as { detail?: unknown }).detail
      : null;
    throw new Error(typeof detail === "string" ? detail : `Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

class GmailSessionExpiredError extends Error {
  constructor() {
    super("Gmail connection expired. Reconnect Gmail.");
  }
}

export function EmailSecurity() {
  const [status, setStatus] = useState<EmailConnectionStatus>(EMPTY_STATUS);
  const [items, setItems] = useState<EmailAnalysisSummary[]>([]);
  const [selected, setSelected] = useState<EmailAnalysisDetail | null>(null);
  const [consented, setConsented] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [mailboxItems, setMailboxItems] = useState<EmailMessagePreview[]>([]);
  const [nextPageToken, setNextPageToken] = useState<string | null>(null);
  const [mailboxError, setMailboxError] = useState<string | null>(null);
  const [selectedMessageIds, setSelectedMessageIds] = useState<string[]>([]);
  const [messageLimit, setMessageLimit] = useState(10);
  const [mailboxBusy, setMailboxBusy] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);
  const selectedId = useRef<number | null>(null);
  const mailboxLimit = useRef(50);
  const pickerOpenRef = useRef(false);
  const pickerCloseButton = useRef<HTMLButtonElement | null>(null);
  const refreshing = useRef(false);

  const closePicker = useCallback(() => {
    setPickerOpen(false);
    pickerOpenRef.current = false;
    setSelectedMessageIds([]);
  }, []);

  const clearExpiredSession = useCallback(() => {
    setStatus(EMPTY_STATUS);
    setItems([]);
    setSelected(null);
    selectedId.current = null;
    setMailboxItems([]);
    setNextPageToken(null);
    closePicker();
  }, [closePicker]);

  const refresh = useCallback(async () => {
    if (refreshing.current) return;
    refreshing.current = true;
    try {
      const nextStatus = await jsonRequest<EmailConnectionStatus>("/v1/gmail/status");
      if (!nextStatus.connected) {
        clearExpiredSession();
        return;
      }
      setStatus(nextStatus);
      const detailRequest = selectedId.current === null
        ? Promise.resolve(null)
        : jsonRequest<EmailAnalysisDetail>(`/v1/email/analyses/${selectedId.current}`);
      const [analysesResult, detailResult] = await Promise.allSettled([
        jsonRequest<EmailAnalysisList>("/v1/email/analyses"),
        detailRequest,
      ]);
      if (
        analysesResult.status === "rejected"
        && analysesResult.reason instanceof GmailSessionExpiredError
      ) {
        clearExpiredSession();
      }
      if (analysesResult.status === "fulfilled") setItems(analysesResult.value.items);
      if (detailResult.status === "fulfilled" && detailResult.value !== null) {
        setSelected(detailResult.value);
      }
    } catch (reason) {
      if (reason instanceof GmailSessionExpiredError) clearExpiredSession();
      else setError(reason instanceof Error ? reason.message : "Could not refresh Gmail");
    } finally {
      refreshing.current = false;
    }
  }, [clearExpiredSession]);

  useEffect(() => {
    const initialRefresh = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(initialRefresh);
  }, [refresh]);

  const loadMailbox = useCallback(async (limit: number, pageToken: string | null = null) => {
    setMailboxBusy(true);
    setError(null);
    setMailboxError(null);
    setPickerOpen(true);
    pickerOpenRef.current = true;
    mailboxLimit.current = limit;
    if (pageToken === null) {
      setMailboxItems([]);
      setNextPageToken(null);
      setSelectedMessageIds([]);
    }
    try {
      const tokenQuery = pageToken === null ? "" : `&page_token=${encodeURIComponent(pageToken)}`;
      const result = await jsonRequest<EmailMessagePreviewList>(`/v1/email/messages?limit=${limit}${tokenQuery}`);
      setMailboxItems((current) => {
        const combined = pageToken === null ? result.items : [...current, ...result.items];
        return newestEmailsFirst([...new Map(combined.map((item) => [item.gmail_message_id, item])).values()]);
      });
      setNextPageToken(result.next_page_token);
    } catch (reason) {
      if (reason instanceof GmailSessionExpiredError) clearExpiredSession();
      const message = reason instanceof Error ? reason.message : "Could not load Gmail messages";
      setError(message);
      setMailboxError(message);
    } finally {
      setMailboxBusy(false);
    }
  }, [clearExpiredSession]);

  useEffect(() => {
    if (!pickerOpen) return;
    pickerCloseButton.current?.focus();
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closePicker();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [closePicker, pickerOpen]);

  useEffect(() => {
    if (!status.connected) return;
    let closed = false;
    let socket: WebSocket | undefined;
    let retry: ReturnType<typeof setTimeout>;
    const poll = setInterval(() => void refresh(), 1500);
    const connect = () => {
      socket = new WebSocket(EMAIL_WS_URL);
      socket.onmessage = (message) => {
        const event = JSON.parse(message.data) as EmailLiveEvent;
        void refresh();
        if (event.type === "EMAIL_RECEIVED" && pickerOpenRef.current) {
          void loadMailbox(mailboxLimit.current);
        }
      };
      socket.onclose = () => {
        if (!closed) retry = setTimeout(connect, 1500);
      };
    };
    connect();
    return () => {
      closed = true;
      clearInterval(poll);
      clearTimeout(retry);
      socket?.close();
    };
  }, [loadMailbox, refresh, status.connected]);

  const mutate = useCallback(async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await work();
      await refresh();
    } catch (reason) {
      if (reason instanceof GmailSessionExpiredError) clearExpiredSession();
      setError(reason instanceof Error ? reason.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }, [clearExpiredSession, refresh]);

  const changeMode = (mode: EmailMonitoringMode) => mutate(async () => {
    const next = await jsonRequest<EmailConnectionStatus>("/v1/gmail/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": status.csrf_token ?? "" },
      body: JSON.stringify({ mode }),
    });
    setStatus(next);
    setSelectedMessageIds([]);
    if (pickerOpenRef.current) await loadMailbox(mailboxLimit.current);
  });

  const importLatest = () => mutate(async () => {
    closePicker();
    setMailboxItems([]);
    setNextPageToken(null);
    const result = await jsonRequest<EmailImportResult>("/v1/email/import", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": status.csrf_token ?? "" },
      body: JSON.stringify({ message_ids: [], limit: messageLimit }),
    });
    setNotice(
      `${result.imported} new email${result.imported === 1 ? "" : "s"} queued. ${result.duplicates} already imported and not downloaded again.`,
    );
  });

  const importSelected = () => mutate(async () => {
    const result: EmailImportResult = { scanned: 0, imported: 0, duplicates: 0 };
    for (let index = 0; index < selectedMessageIds.length; index += 50) {
      const batch = await jsonRequest<EmailImportResult>("/v1/email/import", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": status.csrf_token ?? "" },
        body: JSON.stringify({ message_ids: selectedMessageIds.slice(index, index + 50), limit: null }),
      });
      result.scanned += batch.scanned;
      result.imported += batch.imported;
      result.duplicates += batch.duplicates;
    }
    setNotice(
      result.imported > 0
        ? `${result.imported} email${result.imported === 1 ? "" : "s"} queued for analysis. ${result.duplicates} already imported.`
        : `No new emails imported. ${result.duplicates} of ${result.scanned} already existed.`,
    );
    closePicker();
    setMailboxItems([]);
    setNextPageToken(null);
  });

  const toggleMessage = (messageId: string, checked: boolean) => {
    setSelectedMessageIds((current) => checked
      ? [...new Set([...current, messageId])]
      : current.filter((id) => id !== messageId));
  };

  const loadDetail = async (id: number) => {
    setError(null);
    selectedId.current = id;
    try {
      setSelected(await jsonRequest<EmailAnalysisDetail>(`/v1/email/analyses/${id}`));
    } catch (reason) {
      if (reason instanceof GmailSessionExpiredError) clearExpiredSession();
      setError(reason instanceof Error ? reason.message : "Could not load analysis");
    }
  };

  const review = (decision: EmailReviewDecision) => {
    if (!selected) return Promise.resolve();
    return mutate(async () => {
      const updated = await jsonRequest<EmailAnalysisDetail>(`/v1/email/analyses/${selected.id}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": status.csrf_token ?? "" },
        body: JSON.stringify({ decision }),
      });
      setSelected(updated);
    });
  };

  if (!status.connected) {
    return (
      <main className="email-onboarding">
        <section className="email-connect-card">
          <span className="email-kicker">Gmail threat review</span>
          <h1>Give INBOX one mailbox to protect.</h1>
          <p>New Inbox mail or messages carrying Sentinel/Scan are analyzed. Flagged mail waits for your decision.</p>
          <label className="consent-row">
            <input type="checkbox" checked={consented} onChange={(event) => setConsented(event.target.checked)} />
            <span>I understand selected message content and agent-selected attachments are processed by DAM SECURE through Cognition/Devin.</span>
          </label>
          <button
            className="primary-action"
            type="button"
            disabled={!consented}
            onClick={() => { window.location.href = `${API_URL}/v1/gmail/oauth/start`; }}
          >
            Connect Gmail
          </button>
          <small>Requires the backend Gmail OAuth and Pub/Sub configuration.</small>
        </section>
      </main>
    );
  }

  return (
    <main className="email-workspace">
      <section className="email-toolbar flow-card">
        <div>
          <span className="email-kicker">Connected inbox</span>
          <strong>{status.email}</strong>
          <small>Last sync {clock(status.last_sync)}</small>
        </div>
        <label>
          Monitoring
          <select value={status.mode} disabled={busy} onChange={(event) => void changeMode(event.target.value as EmailMonitoringMode)}>
            <option value="ALL">All new Inbox mail</option>
            <option value="SELECTED">Sentinel/Scan only</option>
          </select>
        </label>
        <div className="watch-health">
          <span>Watch expires</span>
          <strong>{clock(status.watch_expiration)}</strong>
        </div>
        <button
          className="secondary-action"
          type="button"
          disabled={busy}
          onClick={() => void mutate(async () => {
            await fetch(`${API_URL}/v1/gmail/disconnect`, {
              method: "POST",
              credentials: "include",
              headers: { "X-CSRF-Token": status.csrf_token ?? "" },
            }).then((response) => { if (!response.ok) throw new Error("Disconnect failed"); });
            setStatus(EMPTY_STATUS);
            setItems([]);
            setMailboxItems([]);
            setNextPageToken(null);
            closePicker();
            setSelected(null);
            selectedId.current = null;
            setNotice(null);
          })}
        >Disconnect &amp; delete data</button>
      </section>

      {error ? <div className="email-error" role="alert">{error}</div> : null}
      {notice ? <div className="email-notice" role="status">{notice}</div> : null}
      {pickerOpen ? (
        <div className="gmail-modal-backdrop">
          <section className="gmail-picker-modal" role="dialog" aria-modal="true" aria-labelledby="gmail-picker-title">
            <header>
              <div><span className="email-kicker">Choose emails</span><h2 id="gmail-picker-title">Gmail history</h2></div>
              <button ref={pickerCloseButton} className="secondary-action" type="button" onClick={closePicker} aria-label="Close email picker">Close</button>
            </header>
            <div className="gmail-preview-list" aria-label="Newest Gmail messages">
              {mailboxBusy && mailboxItems.length === 0 ? <div className="email-empty">Loading Gmail messages…</div> : null}
              {!mailboxBusy && mailboxItems.length === 0 && mailboxError ? <div className="email-empty">Could not load Gmail history.</div> : null}
              {!mailboxBusy && mailboxItems.length === 0 && !mailboxError ? <div className="email-empty">No Gmail messages found.</div> : null}
              {mailboxItems.map((item) => (
                <label className="gmail-preview-row" key={item.gmail_message_id} data-imported={item.already_imported || undefined}>
                  <input
                    type="checkbox"
                    aria-label={`Select ${item.subject}`}
                    checked={selectedMessageIds.includes(item.gmail_message_id)}
                    disabled={item.already_imported || busy}
                    onChange={(event) => toggleMessage(item.gmail_message_id, event.target.checked)}
                  />
                  <span className="email-message"><strong>{item.subject}</strong><small>{item.from_address}</small><small>{item.snippet}</small></span>
                  <span className="gmail-import-state">{item.already_imported ? "Imported" : "Ready"}</span>
                  <time>{clock(item.received_at)}</time>
                </label>
              ))}
            </div>
            <footer className="gmail-import-bar">
              <span>{mailboxItems.length} loaded · {selectedMessageIds.length} selected</span>
              {nextPageToken ? (
                <button className="secondary-action" type="button" disabled={mailboxBusy} onClick={() => void loadMailbox(50, nextPageToken)}>
                  {mailboxBusy ? "Loading…" : "Load 50 more"}
                </button>
              ) : <span>{mailboxError ? "History unavailable" : "Full Gmail history loaded"}</span>}
              <button className="secondary-action" type="button" disabled={busy || selectedMessageIds.length === 0} onClick={() => void importSelected()}>
                {busy ? "Importing…" : "Import selected"}
              </button>
            </footer>
          </section>
        </div>
      ) : null}

      <section className="email-list flow-card" aria-labelledby="email-review-heading">
        <div className="email-section-heading gmail-picker-heading">
          <div><span className="email-kicker">Gmail inbox</span><h1>Newest messages</h1></div>
          <form className="gmail-limit-controls" onSubmit={(event) => { event.preventDefault(); void importLatest(); }}>
            <label>
              Show latest
              <input
                type="number"
                min="1"
                max="50"
                value={messageLimit}
                onChange={(event) => setMessageLimit(Math.min(50, Math.max(1, Number(event.target.value) || 1)))}
              />
            </label>
            <button className="secondary-action" type="submit" disabled={busy}>{busy ? "Importing…" : "Import latest"}</button>
            <button className="secondary-action" type="button" disabled={mailboxBusy} onClick={() => void loadMailbox(50)}>{mailboxBusy ? "Loading…" : "Choose emails"}</button>
          </form>
        </div>
        <p className="gmail-quick-note">Import latest sends new messages directly to the analysis queue below. Choose emails opens individual selection in a popup.</p>
        <div className="email-section-divider" />
        <div className="email-section-heading">
          <div><span className="email-kicker">Human review</span><h1 id="email-review-heading">Email analyses</h1></div>
          <div className="email-heading-actions"><strong>{pendingEmailCount(items)} pending</strong></div>
        </div>
        <div className="email-table-head" aria-hidden="true"><span>Message</span><span>Risk</span><span>Status</span><span>Received</span></div>
        <div className="email-table">
          {items.length === 0 ? <div className="email-empty">No analyses yet. Select Gmail messages above or wait for a new Gmail event.</div> : newestEmailsFirst(items).map((item) => (
            <button className="email-row" type="button" key={item.id} data-active={selected?.id === item.id || undefined} onClick={() => void loadDetail(item.id)}>
              <span className="email-message"><strong>{item.subject}</strong><small>{item.from_address}</small><small>{item.snippet}</small></span>
              <strong className="risk-score">{formatRiskScore(item.risk_score)}</strong>
              <span className="email-verdict" data-status={item.status.toLowerCase()}>{emailVerdictLabel(item)}</span>
              <time>{clock(item.received_at)}</time>
            </button>
          ))}
        </div>
      </section>

      <aside className="email-detail flow-card" aria-label="Email analysis details">
        {selected ? (
          <>
            <div className="detail-heading"><span className="email-kicker">Threat report</span><h2>{selected.subject}</h2><p>{selected.from_address}</p></div>
            <div className="risk-panel"><strong>{formatRiskScore(selected.risk_score)}</strong><span>risk score</span><small>{selected.report ? `${Math.round(selected.report.confidence * 100)}% confidence` : "No report"}</small></div>
            <p className="report-summary">{selected.report?.summary ?? selected.error ?? "Analysis in progress."}</p>
            <div className="evidence-list">
              {selected.report?.reasons.map((reason, index) => (
                <article key={`${reason.category}-${index}`}><strong>{reason.category}</strong><span>{reason.severity}</span><p>{reason.evidence}</p></article>
              ))}
              {selected.report?.checks.map((check, index) => (
                <article key={`${check.artifact}-${index}`}><strong>{check.artifact}</strong><span>{check.result}</span><p>{check.why}</p></article>
              ))}
            </div>
            {selected.devin_session_url ? <a className="devin-link" href={selected.devin_session_url} target="_blank" rel="noreferrer">Open Devin session</a> : null}
            <div className="review-actions">
              <button type="button" disabled={busy} onClick={() => void review("NOT_DANGEROUS")}>Not dangerous</button>
              <button className="danger-action" type="button" disabled={busy} onClick={() => void review("CONFIRMED_DANGEROUS")}>Confirm dangerous</button>
            </div>
          </>
        ) : <div className="email-empty">Select an analysis to inspect the agent’s evidence.</div>}
      </aside>
    </main>
  );
}
