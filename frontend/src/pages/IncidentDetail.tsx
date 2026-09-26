import type { Incident, AnalystMetadata } from "../services/api";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Panel, PanelHeader, PanelContent } from "../components/ui/Panel";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";

interface IncidentDetailProps {
  incident: Incident | null;
  aiReport: any;
  analystMetadata: AnalystMetadata | null;
  isAnalyzing: boolean;
  actionMessage: string | null;
  onBack: () => void;
  onTriggerAI: () => void;
  onApproveAction: () => void;
  onRejectAction: () => void;
}

export function IncidentDetail({
  incident,
  aiReport,
  analystMetadata,
  isAnalyzing,
  actionMessage,
  onBack,
  onTriggerAI,
  onApproveAction,
  onRejectAction
}: IncidentDetailProps) {
  if (!incident) {
    return <p>Loading incident details...</p>;
  }

  const recommendation = incident.DefenderRecommendation || (
    aiReport?.RecommendedActionID ? {
      ActionID: aiReport.RecommendedActionID,
      Mitigation: aiReport.RecommendedActionID.replace(/_/g, " "),
      Target: aiReport.Target || incident.MachineOverview?.MachineID || incident.IncidentID || "",
      Rationale: aiReport.SuspicionReason || aiReport.Summary || "Analysis recommendation.",
      Status: aiReport.RequiresApproval === false ? "auto-executed" : "pending",
      Message: "",
    } : null
  );

  return (
    <div>
      <div className="page-header" style={{ display: "flex", gap: "1rem", alignItems: "flex-start" }}>
        <Button onClick={onBack}>← Back</Button>
        <div>
          <h1 className="page-title">{incident.IncidentType}</h1>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginTop: "0.5rem" }}>
            <SeverityBadge severity={incident.Severity} />
            <Badge variant="default">{incident.State}</Badge>
            <span style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
              ID: {incident.IncidentID}
            </span>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "2rem" }}>
        {/* Left Column */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          
          <Panel>
            <PanelHeader title="Affected Entities" />
            <PanelContent>
              {incident.MachineOverview ? (
                <div>
                  <p><strong>Host:</strong> {incident.MachineOverview.MachineID}</p>
                  <p><strong>Criticality:</strong> {incident.MachineOverview.Criticality}</p>
                  <p><strong>Host Status:</strong> {incident.MachineOverview.HostStatus || "Unknown"}</p>
                </div>
              ) : (
                <p style={{ color: "var(--text-muted)" }}>No entity overview available.</p>
              )}
            </PanelContent>
          </Panel>

          <Panel>
            <PanelHeader title="Timeline & Evidence" />
            <PanelContent>
              {incident.Timeline && incident.Timeline.length > 0 ? (
                <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: "1rem" }}>
                  {incident.Timeline.map((evt: any, i: number) => (
                    <li key={i} style={{ borderLeft: "2px solid var(--border-color)", paddingLeft: "1rem" }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{evt.Timestamp || evt.TimelineTime}</div>
                      <div style={{ fontWeight: 500, color: "var(--text-bright)" }}>{evt.Event || evt.AlertType}</div>
                      {evt.Evidence && <div style={{ fontSize: "0.875rem", marginTop: "0.25rem" }}>{evt.Evidence}</div>}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ color: "var(--text-muted)" }}>No timeline available.</p>
              )}
            </PanelContent>
          </Panel>
        </div>

        {/* Right Column */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          <Panel>
            <PanelHeader title="AI Analyst" />
            <PanelContent>
              {!aiReport ? (
                <div style={{ textAlign: "center", padding: "1rem 0" }}>
                  <p style={{ color: "var(--text-muted)", marginBottom: "1rem" }}>No analysis available for this incident.</p>
                  <Button variant="primary" onClick={onTriggerAI} disabled={isAnalyzing}>
                    {isAnalyzing ? "Analyzing..." : "Trigger Analysis"}
                  </Button>
                </div>
              ) : (
                <div>
                  <h4 style={{ color: "var(--text-bright)", margin: "0 0 0.5rem 0" }}>Analysis</h4>
                  <p style={{ fontSize: "0.875rem", marginBottom: "1rem" }}>{aiReport.Summary || aiReport.SuspicionReason}</p>
                  
                  {analystMetadata && (
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "1rem", padding: "0.5rem", backgroundColor: "var(--bg-main)", borderRadius: "4px" }}>
                      <strong>Model:</strong> {analystMetadata.ModelName || "Unknown"}<br />
                      <strong>Mode:</strong> {analystMetadata.AnalystMode || "Unknown"}
                    </div>
                  )}

                  {recommendation && (
                    <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid var(--border-color)" }}>
                      <h4 style={{ color: "var(--text-bright)", margin: "0 0 0.5rem 0" }}>Recommended Action</h4>
                      <Badge variant="high" style={{ marginBottom: "0.5rem" }}>{recommendation.ActionID}</Badge>
                      <p style={{ fontSize: "0.875rem", marginBottom: "1rem" }}>{recommendation.Rationale}</p>
                      
                      {recommendation.Status === "pending" && (
                        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                          <Button variant="primary" onClick={onApproveAction} disabled={incident?.actions_supported === false}>Approve Action</Button>
                          <Button variant="danger" onClick={onRejectAction} disabled={incident?.actions_supported === false}>Reject Action</Button>
                          {incident?.actions_supported === false && (
                            <div style={{ width: "100%", fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
                              Actions are unavailable for this incident.
                            </div>
                          )}
                        </div>
                      )}
                      {recommendation.Status !== "pending" && (
                        <Badge variant={recommendation.Status === "Executed" || recommendation.Status === "auto-executed" ? "normal" : "default"}>
                          Status: {recommendation.Status}
                        </Badge>
                      )}
                      {actionMessage && <p style={{ fontSize: "0.875rem", marginTop: "0.5rem", color: "var(--accent)" }}>{actionMessage}</p>}
                    </div>
                  )}
                </div>
              )}
            </PanelContent>
          </Panel>
        </div>
      </div>
    </div>
  );
}
