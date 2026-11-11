import { useState, useEffect, useCallback, useRef } from "react";
import type {
  TalusEvent,
  ProcessInfo,
  FileRank,
  ExtensionCount,
  RateSample,
  Stats,
  NetworkEntry,
} from "../types";

const MAX_EVENTS = 500;
const MAX_NET = 200;

export interface TalusState {
  connected: boolean;
  events: TalusEvent[];
  alerts: TalusEvent[];
  processes: ProcessInfo[];
  files: FileRank[];
  extensions: ExtensionCount[];
  rates: RateSample[];
  network: NetworkEntry[];
  stats: Stats;
}

const defaultStats: Stats = {
  total_events: 0,
  total_lost: 0,
  uptime_secs: 0,
  active_pids: 0,
  threshold: 50,
};

export function useTalus(baseUrl: string) {
  const [state, setState] = useState<TalusState>({
    connected: false,
    events: [],
    alerts: [],
    processes: [],
    files: [],
    extensions: [],
    rates: [],
    network: [],
    stats: defaultStats,
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── WebSocket connection ────────────────────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const wsUrl = `ws://${baseUrl}/ws`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setState((s) => ({ ...s, connected: true }));
    };

    ws.onclose = () => {
      setState((s) => ({ ...s, connected: false }));
      // Auto-reconnect after 2s
      reconnectTimer.current = setTimeout(connect, 2000);
    };

    ws.onerror = () => {
      ws.close();
    };

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as TalusEvent;
        setState((prev) => {
          const next = { ...prev };

          if (data.type === "alert") {
            next.alerts = [data, ...prev.alerts].slice(0, 100);
          }

          if (data.type === "event" || data.type === "alert") {
            next.events = [data, ...prev.events].slice(0, MAX_EVENTS);
          }

          // Network events
          if (
            data.type === "event" &&
            data.kind &&
            ["connect", "accept", "sendto", "recvfrom"].includes(data.kind)
          ) {
            const entry: NetworkEntry = {
              ts: data.ts,
              pid: data.pid,
              comm: data.comm,
              kind: data.kind,
              addr: data.file || "",
            };
            next.network = [entry, ...prev.network].slice(0, MAX_NET);
          }

          next.stats = {
            ...prev.stats,
            total_events: prev.stats.total_events + 1,
          };

          return next;
        });
      } catch {
        // Not JSON — skip
      }
    };
  }, [baseUrl]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  // ── Poll REST API for processes, files, extensions, stats ────────────
  useEffect(() => {
    const api = async () => {
      try {
        const [statsRes, procsRes, filesRes, extsRes] = await Promise.all([
          fetch(`http://${baseUrl}/api/v1/stats`),
          fetch(`http://${baseUrl}/api/v1/processes`),
          fetch(`http://${baseUrl}/api/v1/files`),
          fetch(`http://${baseUrl}/api/v1/extensions`),
        ]);

        const statsJson = await statsRes.json();
        const procsJson = await procsRes.json();
        const filesJson = await filesRes.json();
        const extsJson = await extsRes.json();

        setState((prev) => ({
          ...prev,
          stats: statsJson.ok ? statsJson.data : prev.stats,
          processes: procsJson.ok ? procsJson.data : prev.processes,
          files: filesJson.ok ? filesJson.data : prev.files,
          extensions: extsJson.ok ? extsJson.data : prev.extensions,
        }));
      } catch {
        // Server not running yet
      }
    };

    api();
    const interval = setInterval(api, 3000);
    return () => clearInterval(interval);
  }, [baseUrl]);

  return state;
}
