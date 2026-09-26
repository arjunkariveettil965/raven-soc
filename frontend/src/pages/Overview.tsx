import type { LiveStatus, Incident } from "../services/api";
import { MetricCard } from "../components/ui/MetricCard";
import { Panel, PanelHeader, PanelContent } from "../components/ui/Panel";
import { Table, Th, Td } from "../components/ui/Table";
import { SeverityBadge } from "../components/ui/SeverityBadge";

interface OverviewProps {
  liveStatus: LiveStatus | null;
  incidents: Incident[];
  onIncidentSelect: (id: string) => void;
}

export function Overview({ liveStatus, incidents, onIncidentSelect }: OverviewProps) {
  const topIncidents = incidents.slice(0, 5);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">SOC Overview</h1>
        <p className="page-description">Real-time operational metrics and critical incidents</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem", marginBottom: "2rem" }}>
        <MetricCard label="Active Alerts" value={liveStatus?.alert_count ?? 0} />
        <MetricCard label="Correlated Incidents" value={liveStatus?.incident_count ?? incidents.length} />
        <MetricCard label="Events Processed" value={liveStatus?.event_count ?? 0} />
        <MetricCard label="Active Tactic" value={liveStatus?.current_mitre_tactic || "None"} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "2rem" }}>
        <Panel>
          <PanelHeader title="Recent Critical Activity" />
          <PanelContent>
            {topIncidents.length === 0 ? (
              <p style={{ color: "var(--text-muted)" }}>No recent incidents detected.</p>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Severity</Th>
                    <Th>Incident</Th>
                    <Th>Status</Th>
                    <Th>Score</Th>
                  </tr>
                </thead>
                <tbody>
                  {topIncidents.map(inc => (
                    <tr 
                      key={inc.IncidentID} 
                      style={{ cursor: "pointer" }} 
                      onClick={() => onIncidentSelect(inc.IncidentID)}
                    >
                      <Td><SeverityBadge severity={inc.Severity} /></Td>
                      <Td style={{ fontWeight: 500 }}>{inc.IncidentType}</Td>
                      <Td>{inc.State}</Td>
                      <Td>{inc.Score}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </PanelContent>
        </Panel>

        <Panel>
          <PanelHeader title="System Status" />
          <PanelContent>
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-muted)" }}>Live Engine</span>
                <span style={{ color: liveStatus?.status === "running" ? "var(--normal)" : "var(--text-main)" }}>
                  {liveStatus?.status.toUpperCase() || "STOPPED"}
                </span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-muted)" }}>Current Scenario</span>
                <span style={{ color: "var(--text-bright)" }}>{liveStatus?.scenario || "None"}</span>
              </div>
            </div>
          </PanelContent>
        </Panel>
      </div>
    </div>
  );
}
