import "./App.css";

import { useLive } from "./useLive";
import type { NodeView, Stage } from "./types";

const PIPELINE: { key: Stage; label: string }[] = [
  { key: "trigger", label: "① Anomaly" },
  { key: "agent", label: "② Agent writes filter" },
  { key: "verify", label: "③ Oracle verifies" },
  { key: "ota", label: "④ OTA deploy" },
];

const STAGE_ORDER: Stage[] = ["idle", "trigger", "agent", "verify", "ota", "done"];

function StatTile({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="tile" style={accent ? { borderColor: accent } : undefined}>
      <div className="tile-value" style={accent ? { color: accent } : undefined}>
        {value.toLocaleString()}
      </div>
      <div className="tile-label">{label}</div>
    </div>
  );
}

function NodeTile({ node }: { node: NodeView }) {
  return (
    <div className={`node node-${node.state.toLowerCase()}`}>
      <div className="node-id">{node.label}</div>
      <div className="node-state">{node.state}</div>
      <div className="node-meta">
        {node.fw_version} · {node.blocked.toLocaleString()} blocked
      </div>
    </div>
  );
}

export default function App() {
  const { state, connected } = useLive();
  const nodes = Object.values(state.nodes).sort((a, b) => a.node_id.localeCompare(b.node_id));
  const activeIdx = STAGE_ORDER.indexOf(state.stage);

  return (
    <div className="app">
      <header className="header">
        <h1>
          <span className="shield">🛡</span> Autonomous Anomaly Defense
        </h1>
        <div className={`conn ${connected ? "on" : "off"}`}>
          {connected ? "LIVE" : "reconnecting…"}
        </div>
      </header>

      <section className="counters">
        <StatTile label="Active nodes" value={state.counters.active_nodes} />
        <StatTile label="Threats detected" value={state.counters.threats_detected} accent="#e0a53f" />
        <StatTile label="Filters deployed" value={state.counters.filters_deployed} accent="#4ad98a" />
        <StatTile label="Frames blocked" value={state.counters.frames_blocked} accent="#d94a4a" />
      </section>

      <section className="main">
        <div className="panel grid-panel">
          <h2>Fleet</h2>
          <div className="node-grid">
            {nodes.length === 0 && <div className="empty">waiting for nodes…</div>}
            {nodes.map((n) => (
              <NodeTile key={n.node_id} node={n} />
            ))}
          </div>
        </div>

        <div className="panel pipe-panel">
          <h2>Defense loop {state.activeAttack ? `· ${state.activeAttack}` : ""}</h2>
          <div className="pipeline">
            {PIPELINE.map((step) => {
              const idx = STAGE_ORDER.indexOf(step.key);
              const cls = idx < activeIdx ? "past" : idx === activeIdx ? "active" : "future";
              return (
                <div key={step.key} className={`pstep ${cls}`}>
                  <div className="pdot" />
                  <div className="plabel">{step.label}</div>
                </div>
              );
            })}
          </div>
          <div className="pipe-note">
            No human in the loop — deploy only after the oracle passes on held-out captures.
          </div>
        </div>
      </section>

      <section className="panel timeline-panel">
        <h2>Live timeline</h2>
        <ul className="timeline">
          {state.timeline.map((l) => (
            <li key={l.id} className={`line ${l.tone}`}>
              {l.text}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
