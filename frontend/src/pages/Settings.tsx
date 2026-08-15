import type { HealthStatus } from "../services/api";
import { Panel, PanelHeader, PanelContent } from "../components/ui/Panel";
import { Badge } from "../components/ui/Badge";

interface SettingsProps {
  health: HealthStatus | null;
}

export function Settings({ health }: SettingsProps) {
  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">System Settings & Health</h1>
        <p className="page-description">Diagnostic overview of the RAVEN-SOC platform</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2rem" }}>
        <Panel>
          <PanelHeader title="Core Services" />
          <PanelContent>
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-muted)" }}>API Backend</span>
                <Badge variant={health?.status === "healthy" ? "normal" : "critical"}>
                  {health?.status || "Unknown"}
                </Badge>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-muted)" }}>Database</span>
                <Badge variant={health?.database?.available ? "normal" : "critical"}>
                  {health?.database?.available ? "Connected" : "Disconnected"}
                </Badge>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.875rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Service Name</span>
                <span>{health?.service || "N/A"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.875rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Version</span>
                <span>{health?.version || "N/A"}</span>
              </div>
            </div>
          </PanelContent>
        </Panel>

        <Panel>
          <PanelHeader title="AI Configuration" />
          <PanelContent>
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-muted)" }}>Ollama Local AI</span>
                <Badge variant={health?.ollama?.checked ? "normal" : "critical"}>
                  {health?.ollama?.checked ? "Available" : "Unavailable"}
                </Badge>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.875rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Endpoint</span>
                <span>{health?.ollama?.configured_url || "N/A"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.875rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Default Model</span>
                <span>{health?.ollama?.default_model || "N/A"}</span>
              </div>
            </div>
          </PanelContent>
        </Panel>

        <Panel style={{ gridColumn: "1 / -1" }}>
          <PanelHeader title="Platform Capabilities" />
          <PanelContent>
            <div style={{ display: "flex", gap: "2rem", flexWrap: "wrap" }}>
              {Object.entries(health?.capabilities || {}).map(([key, enabled]) => (
                <div key={key} style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <div className={`health-dot ${enabled ? "healthy" : "unhealthy"}`}></div>
                  <span style={{ fontSize: "0.875rem", textTransform: "capitalize", color: "var(--text-bright)" }}>
                    {key.replace(/_/g, " ")}
                  </span>
                </div>
              ))}
            </div>
          </PanelContent>
        </Panel>
      </div>
    </div>
  );
}
