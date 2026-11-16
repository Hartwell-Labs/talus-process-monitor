// ── Talus monitor event types ─────────────────────────────────────────

export type EventKind =
  | "exec"
  | "open"
  | "connect"
  | "accept"
  | "sendto"
  | "recvfrom"
  | "unlink"
  | "mkdir"
  | "chmod"
  | "kill";

export interface TalusEvent {
  ts: string;
  type: "event" | "alert" | "response";
  kind?: EventKind;
  pid: number;
  uid?: number;
  comm: string;
  file?: string;
  extension?: string;
  argv?: string;
  // alert-specific
  opens?: number;
  score?: number;
  early?: boolean;
  reasons?: string[];
  // response-specific
  action?: string;
  success?: boolean;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  comm: string;
  total_opens: number;
  total_execs: number;
  alerts: number;
  extensions?: Record<string, number>;
  window_opens?: number;
}

export interface FileRank {
  path: string;
  count: number;
  extension: string;
  entropy: number;
}

export interface ExtensionCount {
  extension: string;
  count: number;
}

export interface RateSample {
  ts: string;
  exec_count: number;
  open_count: number;
  alert_count: number;
}

export interface Stats {
  total_events: number;
  total_lost: number;
  uptime_secs: number;
  active_pids: number;
  threshold: number;
}

// Network connection aggregation
export interface NetworkEntry {
  ts: string;
  pid: number;
  comm: string;
  kind: string;
  addr: string;
}

// Process tree node
export interface TreeNode {
  depth: number;
  pid: number;
  comm: string;
  opens: number;
  alerts: number;
}
