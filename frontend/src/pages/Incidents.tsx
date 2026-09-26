import type { Incident } from "../services/api";
import { Table, Th, Td } from "../components/ui/Table";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Panel, PanelContent } from "../components/ui/Panel";

interface IncidentsProps {
  incidents: Incident[];
  onSelect: (id: string) => void;
}

export function Incidents({ incidents, onSelect }: IncidentsProps) {
  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Incident Investigation Queue</h1>
        <p className="page-description">Correlated alerts and multi-stage attacks</p>
      </div>

      <Panel>
        <PanelContent>
          {incidents.length === 0 ? (
            <p style={{ color: "var(--text-muted)", textAlign: "center", padding: "2rem" }}>
              No incidents in queue.
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Severity</Th>
                  <Th>Incident ID</Th>
                  <Th>Type</Th>
                  <Th>Status</Th>
                  <Th>Score</Th>
                </tr>
              </thead>
              <tbody>
                {incidents.map(inc => (
                  <tr 
                    key={inc.IncidentID} 
                    style={{ cursor: "pointer" }}
                    onClick={() => onSelect(inc.IncidentID)}
                  >
                    <Td><SeverityBadge severity={inc.Severity} /></Td>
                    <Td style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      {inc.IncidentID.substring(0, 12)}
                    </Td>
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
    </div>
  );
}
