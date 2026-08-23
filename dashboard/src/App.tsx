import "./App.css";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { BrowserSecurity } from "./BrowserSecurity";
import { incidentReportUrl } from "./api";
import { selectAttackHistory, selectFrameFeed } from "./dashboardView";
import type { AttackRecord } from "./dashboardView";
import { EmailSecurity } from "./EmailSecurity";
import type { NodeView, TimelineLine } from "./types";
import { useLive } from "./useLive";
import { hashForRoute, routeFromHash } from "./routes";
import type { AppRoute } from "./routes";

const EVENT_NAMES: Record<TimelineLine["type"], string> = {
  NODE_UP: "Node online",
  NODE_DOWN: "Node offline",
  ANOMALY_DETECTED: "Anomaly",
  AGENT_ANALYZING: "Analysis",
  AGENT_STEP: "Sandbox",
  FILTER_GENERATED: "Filter generated",
  VERIFYING: "Oracle replay",
  VERIFY_FAILED: "Verification failed",
  VERIFY_PASSED: "Verification passed",
  OTA_DEPLOYING: "OTA deploy",
  DEPLOYED: "Filter deployed",
  FRAME_BLOCKED: "Frame blocked",
  LINK_SUBMITTED: "Link submitted",
  LINK_BROWSING: "Browser analysis",
  LINK_RESEARCHING: "Reputation check",
  LINK_VERDICT: "Link verdict",
};

function formatClock(ts: number): string {
  const milliseconds = ts < 1_000_000_000_000 ? ts * 1000 : ts;
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(milliseconds));
}

function compactNumber(value: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function displayRouterName(value: string): string {
  return value.replace(/\besp(?=-|\b)/gi, "router");
}

const AGENTS: Array<{
  route: Exclude<AppRoute, "home">;
  eyebrow: string;
  name: string;
  title: string;
  description: string;
  image: string;
  imageAlt: string;
  tone: string;
  status: string;
}> = [
  {
    route: "network",
    eyebrow: "01 / LIVE DEFENSE",
    name: "SIGNAL",
    title: "Stops attacks at the edge.",
    description: "Detects hostile traffic, writes a filter, proves it works and deploys it — autonomously.",
    image: "/beaver-antenna.png",
    imageAlt: "Beaver agent holding a radio antenna",
    tone: "orange",
    status: "Live now",
  },
  {
    route: "phishing",
    eyebrow: "02 / BROWSER SHIELD",
    name: "SCOPE",
    title: "Calls out the fake before you click.",
    description: "Checks links, domains and page signals in the browser, right where the decision happens.",
    image: "/beaver-scope.png",
    imageAlt: "Beaver agent inspecting with a magnifying glass",
    tone: "yellow",
    status: "Live now",
  },
  {
    route: "mail",
    eyebrow: "03 / INBOX SCANNER",
    name: "INBOX",
    title: "Reads the email. Spots the trap.",
    description: "Scans messages and attachments for impersonation, pressure tactics and malicious intent.",
    image: "/logo.jpg",
    imageAlt: "Beaver agent working on a laptop",
    tone: "blue",
    status: "Live now",
  },
];

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <button className="brand" data-compact={compact || undefined} type="button" onClick={() => navigate("home")}>
      <span className="brand-dam" aria-hidden="true"><i /><i /><i /></span>
      <span className="brand-name">DAM<span>SECURE</span></span>
    </button>
  );
}

function navigate(route: AppRoute): void {
  window.location.hash = hashForRoute(route);
}

function ArrowIcon() {
  return <span aria-hidden="true">↗</span>;
}

function LandingPage() {
  return (
    <div className="landing-shell">
      <header className="landing-nav">
        <Brand />
        <nav aria-label="Primary navigation">
          <a href="#agents">Agents</a>
          <a href="#how-it-works">How it works</a>
        </nav>
        <button className="nav-cta" type="button" onClick={() => navigate("network")}>Open live defense <ArrowIcon /></button>
      </header>

      <main>
        <section className="hero-section">
          <div className="hero-kicker"><span>Autonomous security crew</span><i /> Built for the attack, not the report</div>
          <h1>THREE AGENTS.<br /><em>ZERO EASY TARGETS.</em></h1>
          <div className="hero-bottom">
            <p>One tireless crew protects your network, browser and inbox — before a threat becomes somebody's very bad day.</p>
            <a href="#agents" className="hero-link">Meet the crew <span aria-hidden="true">↓</span></a>
          </div>
        </section>

        <section className="agents-section" id="agents" aria-labelledby="agents-title">
          <div className="section-intro">
            <span>Choose your agent</span>
            <h2 id="agents-title">Security that actually does the work.</h2>
          </div>
          <div className="agent-grid">
            {AGENTS.map((agent) => (
              <button
                className="agent-card"
                data-tone={agent.tone}
                key={agent.route}
                type="button"
                onClick={() => navigate(agent.route)}
                aria-label={`Open ${agent.name}: ${agent.title}`}
              >
                <span className="agent-card-top"><span>{agent.eyebrow}</span><b>{agent.status}</b></span>
                <span className="agent-art"><img src={agent.image} alt={agent.imageAlt} /></span>
                <span className="agent-copy">
                  <strong>{agent.name}</strong>
                  <span>{agent.title}</span>
                  <small>{agent.description}</small>
                </span>
                <span className="agent-open">Open agent <ArrowIcon /></span>
              </button>
            ))}
          </div>
        </section>

        <section className="method-section" id="how-it-works" aria-labelledby="method-title">
          <div className="method-lead">
            <span>How the crew works</span>
            <h2 id="method-title">Not another dashboard that watches the fire.</h2>
            <p>Each agent closes the loop: it sees the signal, makes the call and takes action at machine speed.</p>
          </div>
          <ol className="method-steps">
            <li><b>01</b><strong>Observe</strong><span>Watch the attack surface continuously, without waiting for a ticket.</span></li>
            <li><b>02</b><strong>Decide</strong><span>Separate a real threat from noise using evidence from the live environment.</span></li>
            <li><b>03</b><strong>Act</strong><span>Block, warn or isolate the threat — then show exactly what happened.</span></li>
          </ol>
        </section>

        <section className="proof-strip" aria-label="Product principles">
          <div><strong>3</strong><span>attack surfaces</span></div>
          <div><strong>1</strong><span>autonomous crew</span></div>
          <div><strong>24/7</strong><span>eyes open</span></div>
          <p>No fatigue.<br />No panic clicks.<br />No easy targets.</p>
        </section>

        <section className="final-cta">
          <span>Start with the agent that is live today</span>
          <h2>BUILD THE DAM<br /><em>BEFORE THE FLOOD.</em></h2>
          <button type="button" onClick={() => navigate("network")}>Open live network defense <ArrowIcon /></button>
        </section>
      </main>
      <footer className="landing-footer"><Brand compact /><p>Autonomous defense for the network, browser and inbox.</p><span>© 2026 DAM SECURE</span></footer>
    </div>
  );
}

function SignalIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4.8 14.7a10.2 10.2 0 0 1 14.4 0M7.7 17.5a6.1 6.1 0 0 1 8.6 0M10.6 20.3a2 2 0 0 1 2.8 0" />
    </svg>
  );
}

function RouterBoard({ state }: { state: NodeView["state"] }) {
  return (
    <svg className="router-board" viewBox="0 0 120 56" role="img" aria-label={`Router ${state.toLowerCase()}`}>
      <rect className="board-base" x="8" y="15" width="104" height="32" rx="5" />
      <path className="board-antenna" d="M19 34h8V25h8v9h8V25h8v9h8" />
      <rect className="board-chip" x="67" y="23" width="24" height="18" rx="3" />
      <path className="board-trace" d="M59 32h8m24 0h11M79 23v-7" />
      <circle className="board-led" cx="101" cy="23" r="2.5" />
    </svg>
  );
}

function NodeCard({ node }: { node: NodeView }) {
  const label = displayRouterName(node.label);

  return (
    <article
      className="sensor-card"
      data-state={node.state.toLowerCase()}
      aria-label={`${label}, ${node.state.toLowerCase()}, firmware ${node.fw_version}`}
    >
      <span className="sensor-card-top">
        <span className="sensor-identity">
          <span className="sensor-status" />
          {label}
        </span>
        <span className="sensor-state">{node.state}</span>
      </span>
      <RouterBoard state={node.state} />
    </article>
  );
}

function SensorRail({ nodes }: { nodes: NodeView[] }) {
  return (
    <section className="sensor-stage flow-card" data-empty={nodes.length === 0 || undefined} aria-label="Router sensor rail">
      <div className="panel-heading sensor-heading">
        <div><span className="panel-index">01 / EDGE NODES</span><h2>Network perimeter</h2></div>
        <span className="panel-count">{nodes.length} nodes</span>
      </div>
      <div className="rail-wrap">
        <div className="rail-axis" aria-hidden="true">
          <span>RF edge</span>
          <span>Packet path</span>
        </div>
        <div className="node-rail">
          {nodes.length === 0 ? (
            <div className="rail-empty">
              <SignalIcon />
              <span>Waiting for sensor heartbeat</span>
            </div>
          ) : (
            nodes.map((node) => <NodeCard key={node.node_id} node={node} />)
          )}
        </div>
      </div>
    </section>
  );
}

function FrameFeed({ timeline }: { timeline: TimelineLine[] }) {
  const frames = selectFrameFeed(timeline, 9);

  return (
    <aside className="frame-log flow-card" aria-labelledby="frames-heading">
      <div className="panel-heading">
        <div><span className="panel-index">02 / LIVE TRAFFIC</span><h2 id="frames-heading">Frame feed</h2></div>
        <span className="live-wave" role="status" aria-label="Feed active">
          <i />
          live
        </span>
      </div>

      <div className="frame-columns" aria-hidden="true">
        <span>Time</span>
        <span>Source</span>
        <span>Event</span>
      </div>

      <div className="frame-list" aria-live="polite">
        {frames.length === 0 ? (
          <div className="frame-empty">
            Listening for live traffic
          </div>
        ) : (
          frames.map((frame) => (
            <div className="frame-row" data-tone={frame.tone} key={frame.id}>
              <time>{formatClock(frame.ts)}</time>
              <span className="frame-source">{frame.node_id ? displayRouterName(frame.node_id) : "system"}</span>
              <span className="frame-event">
                <strong>{EVENT_NAMES[frame.type]}</strong>
                <small>{displayRouterName(frame.text)}</small>
              </span>
            </div>
          ))
        )}
      </div>
    </aside>
  );
}

function attackId(attack: AttackRecord): string {
  return `ATK-${String(attack.id).padStart(4, "0")}`;
}

async function downloadReport(incidentId: string, label: string): Promise<void> {
  const res = await fetch(incidentReportUrl(incidentId));
  if (!res.ok) return;
  const blob = new Blob([await res.text()], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${label}.md`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function AttackHistory({ timeline, activeAttack }: { timeline: TimelineLine[]; activeAttack: string | null }) {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const attacks = selectAttackHistory(timeline, activeAttack).slice(0, 6);

  return (
    <section className="attack-history" aria-labelledby="attack-history-heading">
      <div className="attack-history-heading">
        <div>
          <span className="panel-index">03 / INCIDENT MEMORY</span>
          <h2 id="attack-history-heading">Attack history</h2>
          <p>Detected incidents and autonomous response state</p>
        </div>
        <span>{attacks.length} attacks</span>
      </div>

      <div className="attack-history-columns" aria-hidden="true">
        <span>Attack</span>
        <span>Router</span>
        <span>Packets</span>
        <span>Status</span>
        <span>Time</span>
        <span />
      </div>

      <div className="attack-history-list">
        {attacks.length === 0 ? (
          <div className="attack-history-empty" role="status">
            <div className="attack-empty-card">
              <span className="attack-empty-status"><i aria-hidden="true" /> Perimeter clear</span>
              <strong>No attacks recorded</strong>
              <p>Nothing has crossed the line. SIGNAL is watching for the next anomaly.</p>
              <small>Live monitoring active</small>
            </div>
          </div>
        ) : (
          attacks.map((attack) => {
            const expanded = expandedId === attack.id;
            const panelId = `attack-${attack.id}-thread`;
            return (
              <article className="attack-history-item" data-expanded={expanded || undefined} key={attack.id}>
                <button
                  className="attack-history-toggle"
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={panelId}
                  onClick={() => setExpandedId(expanded ? null : attack.id)}
                >
                  <span className="attack-identity">
                    <strong>{attack.name}</strong>
                    <small>{attackId(attack)}</small>
                  </span>
                  <span>{displayRouterName(attack.nodeId)}</span>
                  <strong className="attack-packet-count">{attack.packetCount}</strong>
                  <span className="attack-status">{attack.status}</span>
                  <time>{formatClock(attack.ts)}</time>
                  <span className="attack-toggle-label">{expanded ? "Hide thread" : "View thread"}</span>
                </button>

                {expanded && (
                  <div className="attack-thread" id={panelId}>
                    <div className="attack-thread-heading">
                      <strong>Devin response thread</strong>
                      <span>{attack.events.length} steps · {displayRouterName(attack.nodeId)}</span>
                      {attack.incidentId && (
                        <button
                          className="attack-report-download"
                          type="button"
                          onClick={() => void downloadReport(attack.incidentId!, attackId(attack))}
                        >
                          Download report
                        </button>
                      )}
                    </div>
                    <ol className="attack-thread-list">
                      {attack.events.map((ev) => (
                        <li className="attack-thread-step" data-tone={ev.tone} key={ev.id}>
                          <time>{formatClock(ev.ts)}</time>
                          <span className="attack-thread-name">{EVENT_NAMES[ev.type]}</span>
                          <span className="attack-thread-text">{displayRouterName(ev.text)}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </article>
            );
          })
        )}
      </div>
    </section>
  );
}

function NetworkDashboard() {
  const { state, connected } = useLive();
  const nodes = Object.values(state.nodes).sort((a, b) => a.node_id.localeCompare(b.node_id));

  return (
    <div className="dashboard-shell">
      <header className="topbar">
        <div className="dashboard-brand">
          <Brand compact />
          <span className="dashboard-agent-name"><i>Agent 01</i><strong>SIGNAL</strong></span>
        </div>
        <div className="topbar-metrics" role="group" aria-label="Fleet totals">
          <div><strong>{state.counters.active_nodes}</strong><span>nodes</span></div>
          <div><strong>{state.counters.threats_detected}</strong><span>threats</span></div>
          <div><strong>{state.counters.filters_deployed}</strong><span>filters</span></div>
          <div><strong>{compactNumber(state.counters.frames_blocked)}</strong><span>blocked</span></div>
        </div>
        <div className="dashboard-actions">
          <span className="connection-state" data-connected={connected || undefined}><i />{connected ? "System live" : "Connecting"}</span>
          <button className="dashboard-back" type="button" onClick={() => navigate("home")}>All agents <span aria-hidden="true">↗</span></button>
        </div>
      </header>

      <main className="workspace">
        <SensorRail nodes={nodes} />
        <FrameFeed timeline={state.timeline} />
        <section className="defense-workspace flow-card" aria-label="Attack history">
          <AttackHistory timeline={state.timeline} activeAttack={state.activeAttack} />
        </section>
      </main>
    </div>
  );
}

function AgentWorkspace({ route, children }: { route: Exclude<AppRoute, "home">; children: ReactNode }) {
  const agent = AGENTS.find((item) => item.route === route);
  if (!agent) return null;

  return (
    <div className="agent-product-shell" data-tone={agent.tone}>
      <header className="agent-product-nav">
        <div className="agent-product-brand"><Brand compact /><span><i>{agent.eyebrow.split(" / ")[0]}</i><strong>{agent.name}</strong></span></div>
        <nav aria-label="Switch security agent">
          {AGENTS.map((item) => <button key={item.route} type="button" data-active={item.route === route || undefined} onClick={() => navigate(item.route)}>{item.name}</button>)}
        </nav>
        <button className="agent-home-link" type="button" onClick={() => navigate("home")}>All agents <span aria-hidden="true">↗</span></button>
      </header>
      {children}
    </div>
  );
}

function FeaturePage({ route }: { route: "phishing" | "mail" }) {
  return (
    <AgentWorkspace route={route}>
      {route === "phishing" ? <BrowserSecurity /> : <EmailSecurity />}
    </AgentWorkspace>
  );
}

export default function App() {
  const [route, setRoute] = useState<AppRoute>(() => routeFromHash(window.location.hash));

  useEffect(() => {
    const updateRoute = () => setRoute(routeFromHash(window.location.hash));
    window.addEventListener("hashchange", updateRoute);
    return () => window.removeEventListener("hashchange", updateRoute);
  }, []);

  if (route === "network") return <NetworkDashboard />;
  if (route === "phishing" || route === "mail") return <FeaturePage route={route} />;
  return <LandingPage />;
}
