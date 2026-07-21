import { formatConfidence, formatDateTime, formatSeverity, safeText, truncateId } from '../utils/formatters';
import StatusBadge from './StatusBadge';

export default function IncidentTable({ incidents, onSelect, sortLabel }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Incident ID</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Target</th>
            <th>Action</th>
            <th>Approval</th>
            <th>First Seen</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.IncidentID} className="clickable-row" onClick={() => onSelect?.(incident)}>
              <td title={incident.IncidentID}>{truncateId(incident.IncidentID, 8)}</td>
              <td>{safeText(incident.IncidentType || incident.CorrelationPattern)}</td>
              <td><StatusBadge tone={formatSeverity(incident.IncidentSeverity || incident.Severity).toLowerCase()}>{formatSeverity(incident.IncidentSeverity || incident.Severity)}</StatusBadge></td>
              <td>{formatConfidence(incident.IncidentConfidence || incident.Confidence)}</td>
              <td>{safeText(incident.Target || incident.AffectedDevice || incident.SourceIP)}</td>
              <td>{safeText(incident.RecommendedActionID)}</td>
              <td>{incident.RequiresApproval ? 'Yes' : 'No'}</td>
              <td>{formatDateTime(incident.FirstSeen)}</td>
              <td>{formatDateTime(incident.LastSeen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {sortLabel ? <div className="table-footnote">Sorted by {sortLabel}</div> : null}
    </div>
  );
}
