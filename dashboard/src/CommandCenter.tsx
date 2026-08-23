import "./CommandCenter.css";

import { useCallback, useEffect, useState } from "react";

import { apiBase, commandReportUrl } from "./api";
import type {
  CommandDemoSeedResult,
  CommandOverview,
  CommandReport,
  IntelligenceObservation,
} from "./types";

const API_URL = apiBase();

const EMPTY_OVERVIEW: CommandOverview = {
  assessing: false,
  metrics: {
    window_end_ts: 0,
    email_current_total: 0,
    email_current_flagged: 0,
    email_baseline_total: 0,
    email_baseline_flagged: 0,
    current_flagged_rate: 0,
    baseline_flagged_rate: 0,
    phishing_spike: false,
    signal_incidents: 0,
    malicious_scope_checks: 0,
    shared_entities: [],
  },
  observations: [],
  assessments: [],
  reports: [],
};

async function jsonRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, init);
  if (!response.ok) throw new Error(`COMMAND request failed (${response.status})`);
  return response.json() as Promise<T>;
}

function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function clock(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value * 1000));
}

function sourceLabel(item: IntelligenceObservation): string {
  if (item.source === "SIGNAL") return "Network response";
  if (item.source === "INBOX") return "Email analysis";
  return "Link investigation";
}

export function CommandCenter() {
  const [overview, setOverview] = useState(EMPTY_OVERVIEW);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [report, setReport] = useState<CommandReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [seeding, setSeeding] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const next = await jsonRequest<CommandOverview>("/v1/command/overview");
      setOverview(next);
      setError(null);
      setSelectedId((current) => current ?? next.reports[0]?.id ?? null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "COMMAND is unavailable");
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const poll = window.setInterval(() => void refresh(), 1500);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(poll);
    };
  }, [refresh]);

  useEffect(() => {
    if (!selectedId) return;
    void jsonRequest<CommandReport>(`/v1/command/reports/${encodeURIComponent(selectedId)}`)
      .then(setReport)
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "Could not load report");
      });
  }, [selectedId]);

  const loadScenario = async () => {
    setSeeding(true);
    setError(null);
    try {
      await jsonRequest<CommandDemoSeedResult>("/v1/command/demo/seed", { method: "POST" });
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not seed scenario");
    } finally {
      setSeeding(false);
    }
  };

  const metrics = overview.metrics;
  const activity = overview.observations.slice(0, 12);

  return (
    <main className="command-workspace">
      <section className="command-hero">
        <div>
          <span className="command-kicker">04 / Autonomous security command</span>
          <h1>THE CREW SEES.<br /><em>COMMAND UNDERSTANDS.</em></h1>
        </div>
        <div className="command-posture" data-alert={metrics.phishing_spike || undefined}>
          <span>{overview.assessing ? "ASSESSING NOW" : metrics.phishing_spike ? "ELEVATED ACTIVITY" : "CONTINUOUS WATCH"}</span>
          <strong>{metrics.phishing_spike ? "Phishing spike detected" : "Company posture monitored"}</strong>
          <p>Every completed activity is compared with history. Devin decides when evidence deserves a separate company report.</p>
        </div>
      </section>

      {error ? <div className="command-error" role="alert">{error}</div> : null}

      <section className="command-metrics" aria-label="Cross-domain metrics">
        <article data-alert={metrics.phishing_spike || undefined}>
          <span>Today / flagged email</span>
          <strong>{metrics.email_current_flagged}<i>/{metrics.email_current_total}</i></strong>
          <small>{percent(metrics.current_flagged_rate)} of current email activity</small>
        </article>
        <article>
          <span>Prior seven days</span>
          <strong>{metrics.email_baseline_flagged}<i>/{metrics.email_baseline_total}</i></strong>
          <small>{percent(metrics.baseline_flagged_rate)} historical flagged rate</small>
        </article>
        <article>
          <span>SIGNAL responses</span>
          <strong>{metrics.signal_incidents}</strong>
          <small>Network incidents in current window</small>
        </article>
        <article>
          <span>Cross-surface entities</span>
          <strong>{metrics.shared_entities.length}</strong>
          <small>{metrics.shared_entities[0] ?? "No shared entity yet"}</small>
        </article>
      </section>

      <section className="command-grid">
        <div className="command-evidence command-card">
          <header>
            <div><span className="command-kicker">Evidence ledger</span><h2>What the crew observed</h2></div>
            <button type="button" disabled={seeding} onClick={() => void loadScenario()}>{seeding ? "Loading…" : "Load phishing scenario"}</button>
          </header>
          <div className="command-evidence-list">
            {activity.length === 0 ? <p className="command-empty">Waiting for SIGNAL, INBOX, or SCOPE activity.</p> : activity.map((item) => (
              <article key={item.id} data-source={item.source}>
                <div><b>{item.source}</b><span>{sourceLabel(item)}</span><i>{item.provenance}</i></div>
                <strong>{item.title}</strong>
                <p>{item.summary}</p>
                <footer><span>Evidence #{item.id}</span><time>{clock(item.occurred_ts)}</time><b>{item.risk_score ?? "—"} risk</b></footer>
              </article>
            ))}
          </div>
        </div>

        <aside className="command-decisions command-card">
          <header><div><span className="command-kicker">Autonomy log</span><h2>Report decisions</h2></div></header>
          <div>
            {overview.assessments.length === 0 ? <p className="command-empty">No assessments yet.</p> : overview.assessments.slice(0, 8).map((item) => (
              <article key={item.id} data-status={item.status}>
                <span>{item.status}</span>
                <strong>{item.decision || "Devin evaluating evidence"}</strong>
                <p>{item.reason || item.error || "Comparing activity with history and researching entities."}</p>
                {item.session_url ? <a href={item.session_url} target="_blank" rel="noreferrer">Open Devin investigation ↗</a> : null}
              </article>
            ))}
          </div>
        </aside>
      </section>

      <section className="command-reports command-card">
        <header><div><span className="command-kicker">Company artifacts</span><h2>Autonomous situation reports</h2></div><span>{overview.reports.length} generated</span></header>
        <div className="command-report-layout">
          <nav aria-label="COMMAND reports">
            {overview.reports.length === 0 ? <p className="command-empty">COMMAND has not found reportable activity yet.</p> : overview.reports.map((item) => (
              <button key={item.id} type="button" data-active={item.id === selectedId || undefined} onClick={() => setSelectedId(item.id)}>
                <span><b>{item.id}</b><i>{item.provenance}</i></span>
                <strong>{item.title}</strong>
                <small>{item.urgency} · {Math.round(item.confidence * 100)}% confidence</small>
              </button>
            ))}
          </nav>
          <div className="command-report-detail">
            {report ? (
              <>
                <div className="command-report-title"><span>{report.id} / {report.urgency}</span><h2>{report.title}</h2><p>{report.executive_summary}</p></div>
                <div className="command-report-columns">
                  <section><h3>What happened</h3>{report.what_happened.map((item) => <p key={item}>{item}</p>)}</section>
                  <section><h3>Cause analysis</h3>{report.cause_analysis.map((item) => <p key={item}>{item}</p>)}</section>
                  <section><h3>Verified actions</h3>{report.actions_taken.map((item) => <p key={item}>{item}</p>)}</section>
                  <section><h3>Next actions</h3>{report.recommendations.map((item) => <p key={item}>{item}</p>)}</section>
                </div>
                {report.correlations.length > 0 ? <section className="command-correlations"><h3>Cross-domain correlations</h3>{report.correlations.map((item) => <article key={item.claim}><strong>{Math.round(item.confidence * 100)}%</strong><div><b>{item.claim}</b><p>{item.explanation}</p><small>Evidence {item.evidence_ids.join(", ")}</small></div></article>)}</section> : null}
                {report.attacker_context.length > 0 ? <section className="command-attribution"><h3>Attacker OSINT <span>Hypotheses, not identity claims</span></h3>{report.attacker_context.map((item) => <article key={`${item.entity}-${item.finding}`}><strong>{Math.round(item.confidence * 100)}%</strong><div><b>{item.entity}</b><p>{item.finding}</p><small>Evidence {item.evidence_ids.join(", ")}</small>{item.sources.length > 0 ? <nav aria-label={`Research sources for ${item.entity}`}>{item.sources.map((source) => <a key={source} href={source} target="_blank" rel="noreferrer">Source ↗</a>)}</nav> : null}</div></article>)}</section> : null}
                {report.employee_advisory.needed ? <section className="command-advisory"><span>Ready-to-use employee advisory</span><strong>{report.employee_advisory.subject}</strong><p>{report.employee_advisory.body}</p></section> : null}
                <footer><a href={commandReportUrl(report.id)} download={`${report.id}.md`}>Download verified report ↓</a><code>Evidence {report.evidence_sha256.slice(0, 16)}…</code></footer>
              </>
            ) : <p className="command-empty">Select a generated report.</p>}
          </div>
        </div>
      </section>
    </main>
  );
}
