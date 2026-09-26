import type { LiveStatus } from "../services/api";
import { Panel, PanelHeader, PanelContent } from "../components/ui/Panel";
import { Button } from "../components/ui/Button";

interface ScenariosProps {
  liveStatus: LiveStatus | null;
  selectedScenario: string;
  setSelectedScenario: (s: string) => void;
  speed: number;
  setSpeed: (s: number) => void;
  onStart: () => void;
}

export function Scenarios({
  liveStatus,
  selectedScenario,
  setSelectedScenario,
  speed,
  setSpeed,
  onStart
}: ScenariosProps) {
  const isRunning = liveStatus?.status === "running" || liveStatus?.status === "paused";

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Attack Scenarios</h1>
        <p className="page-description">Configure and deploy synthetic attack simulations</p>
      </div>

      <Panel style={{ maxWidth: "600px" }}>
        <PanelHeader title="Scenario Configuration" />
        <PanelContent>
          <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
            <div>
              <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: 500, color: "var(--text-muted)" }}>
                Select Scenario
              </label>
              <select
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value)}
                disabled={isRunning}
                style={{
                  width: "100%",
                  padding: "0.75rem",
                  backgroundColor: "var(--bg-main)",
                  color: "var(--text-bright)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "4px"
                }}
              >
                {liveStatus?.supported_scenarios?.map((scen: string) => (
                  <option key={scen} value={scen}>{scen}</option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: 500, color: "var(--text-muted)" }}>
                Simulation Speed
              </label>
              <select
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                disabled={isRunning}
                style={{
                  width: "100%",
                  padding: "0.75rem",
                  backgroundColor: "var(--bg-main)",
                  color: "var(--text-bright)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "4px"
                }}
              >
                {liveStatus?.supported_speeds?.map((s: number) => (
                  <option key={s} value={s}>{s}x Normal Speed</option>
                ))}
              </select>
            </div>

            <div>
              <Button 
                variant="primary" 
                onClick={onStart} 
                disabled={isRunning}
                style={{ width: "100%" }}
              >
                Deploy Simulation
              </Button>
              {isRunning && (
                <p style={{ marginTop: "0.75rem", fontSize: "0.875rem", color: "var(--text-muted)", textAlign: "center" }}>
                  A simulation is currently active. Stop the engine to configure a new scenario.
                </p>
              )}
            </div>
          </div>
        </PanelContent>
      </Panel>
    </div>
  );
}
