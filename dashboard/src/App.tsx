import "./App.css";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useRef } from "react";

import { getWorkflowView, selectFrameFeed, selectLatestAnomaly } from "./dashboardView";
import type { NodeView, Stage, TimelineLine } from "./types";
import { useLive } from "./useLive";

gsap.registerPlugin(useGSAP, ScrollTrigger);

const STAGE_ORDER: Stage[] = ["idle", "trigger", "agent", "verify", "ota", "done"];

const FILTER_STAGES: { key: Stage; label: string; owner: string }[] = [
  { key: "trigger", label: "Detect", owner: "Detector" },
  { key: "agent", label: "Generate", owner: "Devin" },
  { key: "verify", label: "Verify", owner: "Devin" },
  { key: "ota", label: "Deploy", owner: "Devin" },
  { key: "done", label: "Protect", owner: "Router" },
];

const RESPONSE_STATUS: Record<Stage, string> = {
  idle: "Monitoring airspace",
  trigger: "Anomaly isolated",
  agent: "Devin generating filter",
  verify: "Oracle replay running",
  ota: "Deploying to router",
  done: "Threat contained",
};

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
        <span />
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
    <svg className="router-board" viewBox="0 0 140 74" role="img" aria-label={`Router ${state.toLowerCase()}`}>
      <g className="board-pins">
        {Array.from({ length: 8 }, (_, index) => (
          <circle key={`top-${index}`} cx={18 + index * 15} cy="7" r="2.4" />
        ))}
        {Array.from({ length: 8 }, (_, index) => (
          <circle key={`bottom-${index}`} cx={18 + index * 15} cy="67" r="2.4" />
        ))}
      </g>
      <rect className="board-base" x="8" y="12" width="124" height="50" rx="7" />
      <path className="board-antenna" d="M20 42h8V30h8v12h8V30h8v12h8" />
      <rect className="board-chip" x="70" y="25" width="29" height="24" rx="3" />
      <path className="board-trace" d="M60 37h10m29 0h18M84 25V17m0 32v7" />
      <circle className="board-led" cx="117" cy="22" r="3" />
    </svg>
  );
}

function NodeCard({ node, active }: { node: NodeView; active: boolean }) {
  const label = displayRouterName(node.label);

  return (
    <button
      className="sensor-card"
      data-state={node.state.toLowerCase()}
      data-active={active || undefined}
      type="button"
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
    </button>
  );
}

function SensorRail({ nodes, activeNode }: { nodes: NodeView[]; activeNode: string | null }) {
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
            nodes.map((node) => <NodeCard key={node.node_id} node={node} active={node.node_id === activeNode} />)
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

function FilterEngine({ stage, attack }: { stage: Stage; attack: string | null }) {
  const activeIndex = STAGE_ORDER.indexOf(stage);
  const { detectorActive, devinActive, retryActive, devinStatus } = getWorkflowView(stage, attack);

  return (
    <div className="filter-engine">
      <div className="panel-heading filter-heading">
        <h2>Adaptive filter</h2>
        <div className="filter-glyph" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
      </div>

      <div className="filter-body">
        <div className="agent-activity" aria-label="Detection and generation activity">
          <div className="activity-card detector-activity" data-active={detectorActive || undefined}>
            <span className="detector-radar" aria-hidden="true"><i /></span>
            <span className="activity-copy">
              <span>Detection</span>
              <strong>Signal detector</strong>
              <small>{detectorActive ? "Anomaly signature found" : "Scanning packet windows"}</small>
            </span>
            <span className="activity-signal" aria-hidden="true"><i /><i /><i /></span>
          </div>

          <div className="activity-card devin-activity" data-active={devinActive || undefined}>
            <span className="devin-mark" aria-hidden="true">D</span>
            <span className="activity-copy">
              <span>Generation agent</span>
              <strong>Devin</strong>
              <small>{devinStatus}</small>
            </span>
            <span className="activity-signal" aria-hidden="true"><i /><i /><i /></span>
          </div>
        </div>

        <div className="workflow-map">
          <div className="stage-rail" role="list" aria-label={`Defense loop ${stage}`}>
            {FILTER_STAGES.map((item) => {
              const index = STAGE_ORDER.indexOf(item.key);
              const phase = index < activeIndex ? "past" : index === activeIndex ? "active" : "future";
              return (
                <div className="stage-step" data-phase={phase} key={item.key} role="listitem">
                  <span className="stage-node" />
                  <span className="stage-label">{item.label}</span>
                  <span className="stage-owner">{item.owner}</span>
                </div>
              );
            })}
          </div>
          <svg
            className="retry-loop"
            data-active={retryActive || undefined}
            viewBox="0 0 44 100"
            preserveAspectRatio="none"
            role="img"
            aria-label="Failed verification returns to Devin generation"
          >
            <path className="retry-path" d="M22 50 C2 50 2 30 22 30" pathLength="1" />
          </svg>
        </div>
      </div>
    </div>
  );
}

function AnomalyFocus({
  attack,
  node,
  stage,
  timeline,
}: {
  attack: string | null;
  node: string | null;
  stage: Stage;
  timeline: TimelineLine[];
}) {
  const latestAnomaly = selectLatestAnomaly(timeline);
  const anomalyNode = node ?? latestAnomaly?.node_id;
  const hasAnomaly = Boolean(attack || latestAnomaly);
  const attackName = attack?.replaceAll("_", " ") ?? "Unclassified signal anomaly";

  return (
    <div className="anomaly-focus">
      <div className="panel-heading anomaly-heading">
        <h2>Active anomaly</h2>
        <span className="anomaly-severity" data-active={hasAnomaly || undefined}>
          {hasAnomaly ? "High priority" : "Monitoring"}
        </span>
      </div>

      <div className="anomaly-card" data-active={hasAnomaly || undefined}>
        <div className="anomaly-wave" aria-hidden="true">
          {Array.from({ length: 11 }, (_, index) => <i key={index} />)}
        </div>
        <div className="anomaly-copy">
          <span>{hasAnomaly ? "Signal anomaly detected" : "No anomaly in current window"}</span>
          <h3>{hasAnomaly ? attackName : "Airspace clear"}</h3>
          <p>{anomalyNode ? displayRouterName(anomalyNode) : "Waiting for detector"}</p>
        </div>
        <div className="anomaly-response">
          <span>Response</span>
          <strong>{RESPONSE_STATUS[stage]}</strong>
          {latestAnomaly && (
            <time dateTime={new Date(latestAnomaly.ts * 1000).toISOString()}>{formatClock(latestAnomaly.ts)}</time>
          )}
        </div>
        {hasAnomaly && (
          <div className="anomaly-orbit" aria-hidden="true"><span /></div>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const { state } = useLive();
  const shellRef = useRef<HTMLDivElement>(null);
  const nodes = Object.values(state.nodes).sort((a, b) => a.node_id.localeCompare(b.node_id));

  useGSAP(
    () => {
      if (globalThis.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const flowCards = gsap.utils.toArray<HTMLElement>(".flow-card");
      const boards = gsap.utils.toArray<SVGElement>(".router-board");
      if (flowCards.length > 0) {
        gsap.fromTo(
          flowCards,
          { y: 28, scale: 0.97, opacity: 0 },
          { y: 0, scale: 1, opacity: 1, duration: 0.85, stagger: 0.08, ease: "power3.out" },
        );
      }
      if (boards.length > 0) {
        gsap.fromTo(
          boards,
          { scale: 0.8, opacity: 0.2 },
          { scale: 1, opacity: 1, duration: 1, stagger: 0.09, ease: "back.out(1.4)" },
        );
      }
    },
    { scope: shellRef, dependencies: [nodes.length], revertOnUpdate: true },
  );

  useGSAP(
    () => {
      if (state.seq === 0 || globalThis.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const latestFrame = gsap.utils.toArray<HTMLElement>(".frame-row:first-child");
      if (latestFrame.length > 0) {
        gsap.fromTo(
          latestFrame,
          { x: 18, opacity: 0, backgroundColor: "rgba(180, 255, 52, 0.12)" },
          { x: 0, opacity: 1, backgroundColor: "rgba(180, 255, 52, 0)", duration: 0.7, ease: "power2.out" },
        );
      }
    },
    { scope: shellRef, dependencies: [state.seq], revertOnUpdate: true },
  );

  useGSAP(
    () => {
      if (globalThis.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const activeCards = gsap.utils.toArray<HTMLElement>(".activity-card[data-active='true']");
      if (activeCards.length > 0) {
        gsap.fromTo(
          activeCards,
          { y: 7, scale: 0.97, opacity: 0.55 },
          { y: 0, scale: 1, opacity: 1, duration: 0.55, ease: "power2.out" },
        );
      }
    },
    { scope: shellRef, dependencies: [state.stage], revertOnUpdate: true },
  );

  return (
    <div className="dashboard-shell" ref={shellRef}>
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
        <SensorRail nodes={nodes} activeNode={state.activeNode} />
        <FrameFeed timeline={state.timeline} />
        <section className="defense-workspace flow-card" aria-label="Adaptive response workflow and active anomaly">
          <FilterEngine stage={state.stage} attack={state.activeAttack} />
          <AnomalyFocus
            attack={state.activeAttack}
            node={state.activeNode}
            stage={state.stage}
            timeline={state.timeline}
          />
        </section>
      </main>
    </div>
  );
}
