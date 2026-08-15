import type { LiveStatus, SecurityEvent } from "../services/api";
import { Table, Th, Td } from "../components/ui/Table";
import { Panel, PanelHeader, PanelContent } from "../components/ui/Panel";
import { Button } from "../components/ui/Button";

interface LiveMonitoringProps {
  liveStatus: LiveStatus | null;
  events: SecurityEvent[];
  onStart: () => void;
  onPause: () => void;
  onResume: () => void;
  onReset: () => void;
}

export function LiveMonitoring({
  liveStatus,
  events,
  onStart,
  onPause,
  onResume,
  onReset
}: LiveMonitoringProps) {
  const isRunning = liveStatus?.status === "running";
  const isPaused = liveStatus?.status === "paused";

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h1 className="page-title">Live Monitoring</h1>
          <p className="page-description">Real-time synthetic event ingestion and processing</p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {!isRunning && !isPaused && (
            <Button variant="primary" onClick={onStart}>Start Engine</Button>
          )}
          {isRunning && (
            <Button variant="secondary" onClick={onPause}>Pause</Button>
          )}
          {isPaused && (
            <Button variant="primary" onClick={onResume}>Resume</Button>
          )}
          <Button variant="danger" onClick={onReset}>Reset</Button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem", marginBottom: "2rem" }}>
        <Panel>
          <PanelContent style={{ textAlign: "center" }}>
            <div style={{ fontSize: "0.875rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>Engine Status</div>
            <div style={{ fontSize: "1.25rem", fontWeight: 600, color: isRunning ? "var(--normal)" : "var(--text-bright)" }}>
              {liveStatus?.status.toUpperCase() || "STOPPED"}
            </div>
          </PanelContent>
        </Panel>
        <Panel>
          <PanelContent style={{ textAlign: "center" }}>
            <div style={{ fontSize: "0.875rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>Events Processed</div>
            <div style={{ fontSize: "1.25rem", fontWeight: 600, color: "var(--accent)" }}>
              {liveStatus?.event_count || 0}
            </div>
          </PanelContent>
        </Panel>
        <Panel>
          <PanelContent style={{ textAlign: "center" }}>
            <div style={{ fontSize: "0.875rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>Event Queue</div>
            <div style={{ fontSize: "1.25rem", fontWeight: 600, color: "var(--text-bright)" }}>
              {liveStatus?.queue_size || 0}
            </div>
          </PanelContent>
        </Panel>
      </div>

      <Panel>
        <PanelHeader title="Raw Event Stream" />
        <PanelContent>
          <div style={{ height: "400px", overflowY: "auto" }}>
            {events.length === 0 ? (
              <p style={{ color: "var(--text-muted)", textAlign: "center", paddingTop: "2rem" }}>
                Waiting for events...
              </p>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Time</Th>
                    <Th>Event ID</Th>
                    <Th>Host</Th>
                    <Th>Severity</Th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((evt, idx) => (
                    <tr key={idx}>
                      <Td style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>{evt.SystemTime}</Td>
                      <Td>{evt.EventID}</Td>
                      <Td>{evt.Computer}</Td>
                      <Td>{evt.Severity}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </div>
        </PanelContent>
      </Panel>
    </div>
  );
}
