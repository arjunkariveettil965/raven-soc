import type { SecurityAlert } from "../services/api";
import { Table, Th, Td } from "../components/ui/Table";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Panel, PanelContent } from "../components/ui/Panel";

interface AlertsProps {
  alerts: SecurityAlert[];
}

export function Alerts({ alerts }: AlertsProps) {
  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Alert Queue</h1>
        <p className="page-description">Raw security alerts triggered by detection rules</p>
      </div>

      <Panel>
        <PanelContent>
          {alerts.length === 0 ? (
            <p style={{ color: "var(--text-muted)", textAlign: "center", padding: "2rem" }}>
              No alerts in queue.
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Severity</Th>
                  <Th>Timestamp</Th>
                  <Th>Alert Type</Th>
                  <Th>Tactic</Th>
                  <Th>Technique</Th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alrt, idx) => (
                  <tr key={alrt.AlertID || idx}>
                    <Td><SeverityBadge severity={alrt.Severity} /></Td>
                    <Td style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      {alrt.Timestamp}
                    </Td>
                    <Td style={{ fontWeight: 500 }}>{alrt.RuleName}</Td>
                    <Td>{alrt.Tactic}</Td>
                    <Td>{alrt.Technique}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </PanelContent>
      </Panel>
    </div>
  );
}
