import { useState, useEffect } from "react";
import { useTalus } from "./hooks/useTalus";
import { EventsPanel } from "./components/EventsPanel";
import { ProcessesPanel } from "./components/ProcessesPanel";
import { NetworkPanel } from "./components/NetworkPanel";
import { FilesPanel } from "./components/FilesPanel";
import { ExtensionsPanel } from "./components/ExtensionsPanel";
import { AlertsPanel } from "./components/AlertsPanel";
import { RateChart } from "./components/RateChart";
import "./styles/dashboard.css";

const DEFAULT_HOST = "localhost:3080";

function fmtDur(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h${Math.floor((secs % 3600) / 60)}m`;
}

interface RateSmooth {
  exec: number;
  open: number;
  alert: number;
}

function useSmoothedRates(
  rates: { exec_count: number; open_count: number; alert_count: number }[]
): RateSmooth {
  const [smooth, setSmooth] = useState<RateSmooth>({ exec: 0, open: 0, alert: 0 });
  const alpha = 0.25;

  useEffect(() => {
    if (rates.length === 0) return;
    const last = rates[rates.length - 1];
    setSmooth((s) => ({
      exec: s.exec * (1 - alpha) + last.exec_count * alpha,
      open: s.open * (1 - alpha) + last.open_count * alpha,
      alert: s.alert * (1 - alpha) + last.alert_count * alpha,
    }));
  }, [rates.length]);

  return smooth;
}

function App() {
  const [host] = useState(DEFAULT_HOST);
  const state = useTalus(host);
  const smooth = useSmoothedRates(state.rates);

  return (
    <div className="app">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="header">
        <h1>⚡ TALUS — Endpoint Security Agent</h1>
        <div className="meta">
          <span>
            events: <span className="val">{state.stats.total_events.toLocaleString()}</span>
          </span>
          <span>
            lost:{" "}
            <span className={state.stats.total_lost > 0 ? "lost" : "val"}>
              {state.stats.total_lost}
            </span>
          </span>
          <span>
            alerts:{" "}
            <span className={state.alerts.length > 0 ? "alerts-val" : "val"}>
              {state.alerts.length}
            </span>
          </span>
          <span>
            uptime: <span className="val">{fmtDur(state.stats.uptime_secs)}</span>
          </span>
          <span>
            pids: <span className="val">{state.stats.active_pids}</span>
          </span>
        </div>
      </div>

      {/* ── Toolbar ─────────────────────────────────────────────────── */}
      <div className="toolbar">
        <div className={`status-dot ${state.connected ? "" : "disconnected"}`} />
        <span className="status-text">
          WebSocket: {state.connected ? "connected" : "disconnected"}
        </span>
        <span className="status-text" style={{ marginLeft: 12 }}>
          threshold: {state.stats.threshold}/s
        </span>
      </div>

      {/* ── 3×2 Grid + Chart ───────────────────────────────────────── */}
      <div className="grid">
        <EventsPanel events={state.events} />
        <ProcessesPanel processes={state.processes} />
        <AlertsPanel alerts={state.alerts} />

        <NetworkPanel network={state.network} />
        <FilesPanel files={state.files} />
        <ExtensionsPanel extensions={state.extensions} />

        {/* Rate chart spans full width in a separate row */}
        <div style={{ gridColumn: "span 3" }}>
          <RateChart
            rates={state.rates}
            smoothExec={smooth.exec}
            smoothOpen={smooth.open}
            smoothAlert={smooth.alert}
          />
        </div>
      </div>
    </div>
  );
}

export default App;
