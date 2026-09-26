import type { Incident } from "../services/api";
import { Panel, PanelHeader, PanelContent } from "../components/ui/Panel";
import { Table, Th, Td } from "../components/ui/Table";

interface MitreProps {
  incidents: Incident[];
}

export function Mitre({ incidents }: MitreProps) {
  // Extract unique techniques from incidents
  const techniques = new Map<string, { tactic: string, count: number }>();
  
  incidents.forEach(inc => {
    const alerts = inc.Alerts || inc.AlertMappings || [];
    alerts.forEach((alrt: any) => {
      const tech = alrt.Technique || alrt.MITRETechnique;
      const tactic = alrt.Tactic || alrt.MITRETactic;
      
      if (tech) {
        const existing = techniques.get(tech) || { tactic: tactic || "Unknown", count: 0 };
        existing.count += 1;
        techniques.set(tech, existing);
      }
    });
  });

  const sortedTechniques = Array.from(techniques.entries()).sort((a, b) => b[1].count - a[1].count);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">MITRE ATT&CK Mapping</h1>
        <p className="page-description">Adversary tactics and techniques observed in the environment</p>
      </div>

      <Panel>
        <PanelHeader title="Observed Techniques" />
        <PanelContent>
          {sortedTechniques.length === 0 ? (
            <p style={{ color: "var(--text-muted)", textAlign: "center", padding: "2rem" }}>
              No MITRE techniques observed.
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Technique</Th>
                  <Th>Tactic</Th>
                  <Th>Observed Count</Th>
                </tr>
              </thead>
              <tbody>
                {sortedTechniques.map(([tech, data]) => (
                  <tr key={tech}>
                    <Td style={{ fontWeight: 500, color: "var(--accent)" }}>{tech}</Td>
                    <Td>{data.tactic}</Td>
                    <Td>{data.count}</Td>
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
