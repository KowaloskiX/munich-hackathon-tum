import "./App.css";

import { useState } from "react";

import { selectAttackHistory, selectAttackPackets, selectFrameFeed } from "./dashboardView";
import type { AttackRecord } from "./dashboardView";
import type { NodeView, TimelineLine } from "./types";
import { useLive } from "./useLive";

const EVENT_NAMES: Record<TimelineLine["type"], string> = {
  NODE_UP: "Node online",
  NODE_DOWN: "Node offline",
  ANOMALY_DETECTED: "Anomaly",
  AGENT_ANALYZING: "Analysis",
  FILTER_GENERATED: "Filter generated",
  VERIFYING: "Oracle replay",
  VERIFY_FAILED: "Verification failed",
  VERIFY_PASSED: "Verification passed",
  OTA_DEPLOYING: "OTA deploy",
  DEPLOYED: "Filter deployed",
  FRAME_BLOCKED: "Frame blocked",
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

function Wordmark() {
  return (
    <div className="wordmark" role="img" aria-label="Sentinel autonomous defense">
      <span className="wordmark-mark" aria-hidden="true">
        <img src="/logo.jpg" alt="" />
      </span>
      <span>Sentinel</span>
      <span className="wordmark-edition">ROUTER</span>
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
    <section className="sensor-stage flow-card" aria-label="Router sensor rail">
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
        <h2 id="frames-heading">Frame feed</h2>
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
            <span className="scan-line" />
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

function AttackHistory({ timeline, activeAttack }: { timeline: TimelineLine[]; activeAttack: string | null }) {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const attacks = selectAttackHistory(timeline, activeAttack).slice(0, 6);

  return (
    <section className="attack-history" aria-labelledby="attack-history-heading">
      <div className="attack-history-heading">
        <div>
          <h2 id="attack-history-heading">Attack history</h2>
          <p>Detected incidents and Devin response state</p>
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
          <div className="attack-history-empty">
            <strong>No attacks recorded</strong>
            <span>Waiting for an anomaly detection event.</span>
          </div>
        ) : (
          attacks.map((attack) => {
            const expanded = expandedId === attack.id;
            const packets = expanded ? selectAttackPackets(attack) : [];
            const packetPanelId = `attack-${attack.id}-packets`;
            return (
              <article className="attack-history-item" data-expanded={expanded || undefined} key={attack.id}>
                <button
                  className="attack-history-toggle"
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={packetPanelId}
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
                  <span className="attack-toggle-label">{expanded ? "Hide packets" : "View packets"}</span>
                </button>

                {expanded && (
                  <div className="attack-packet-window" id={packetPanelId}>
                    <div className="attack-packet-heading">
                      <strong>Connected packet sample</strong>
                      <span>{packets.length} of {attack.packetCount} packets</span>
                    </div>
                    <div className="attack-packet-columns" aria-hidden="true">
                      <span>Packet ID</span>
                      <span>Router</span>
                      <span>Frame</span>
                      <span>Match</span>
                    </div>
                    <div className="attack-packet-list">
                      {packets.map((packet) => (
                        <div className="attack-packet-row" key={packet.id}>
                          <code>{packet.id}</code>
                          <span>{displayRouterName(packet.nodeId)}</span>
                          <span>{packet.frameType}</span>
                          <span>{packet.match}</span>
                        </div>
                      ))}
                    </div>
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

export default function App() {
  const { state } = useLive();
  const nodes = Object.values(state.nodes).sort((a, b) => a.node_id.localeCompare(b.node_id));

  return (
    <div className="dashboard-shell">
      <header className="topbar">
        <Wordmark />
        <div className="topbar-metrics" role="group" aria-label="Fleet totals">
          <div><strong>{state.counters.active_nodes}</strong><span>nodes</span></div>
          <div><strong>{state.counters.threats_detected}</strong><span>threats</span></div>
          <div><strong>{state.counters.filters_deployed}</strong><span>filters</span></div>
          <div><strong>{compactNumber(state.counters.frames_blocked)}</strong><span>blocked</span></div>
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
