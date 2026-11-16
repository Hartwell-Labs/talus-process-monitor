import { memo } from "react";
import type { TalusEvent } from "../types";

export const AlertsPanel = memo(function AlertsPanel({
  alerts,
}: {
  alerts: TalusEvent[];
}) {
  return (
    <div className="panel">
      <div className="panel-header">
        ALERTS <span className="count">{alerts.length}</span>
      </div>
      <div className="panel-body">
        {alerts.length === 0 && (
          <div className="empty">no alerts triggered</div>
        )}
        {alerts.map((a, i) => (
          <div key={i} className="event-row">
            <span className="ts">{a.ts}</span>
            <span className="tag tag-alert">
              {a.early ? "⚠ EARLY" : "⚠ ALERT"}
            </span>
            <span className="pid">[{a.pid}]</span>
            <span className="comm">{a.comm}</span>
            <span
              className="file"
              title={a.reasons?.length ? a.reasons.join(", ") : undefined}
            >
              {a.opens} opens/s
              {a.score ? ` · score ${a.score}` : ""}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
});
