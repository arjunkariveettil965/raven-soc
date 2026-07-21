import { formatBoolean, formatConfidence, formatDateTime, safeText, toRows } from '../utils/formatters';
import AttackChain from './AttackChain';

export default function IncidentDetails({ incident, analysis, actionDecision }) {
  if (!incident) return null;
  const alertTypes = incident.RelatedAlertTypes || incident.RelatedAlerts || [];
  const alertIds = incident.RelatedAlertIDs || incident.EvidenceIDs || [];
  return (
    <div className="panel-stack">
      <section className="panel">
        <div className="panel-title">Incident summary</div>
        <dl className="details-grid">
          <Detail label="Incident ID" value={incident.IncidentID} />
          <Detail label="Type" value={incident.IncidentType || incident.CorrelationPattern} />
          <Detail label="Severity" value={incident.IncidentSeverity || incident.Severity} />
          <Detail label="Confidence" value={formatConfidence(incident.IncidentConfidence || incident.Confidence)} />
          <Detail label="Target" value={incident.Target || incident.AffectedDevice || incident.SourceIP} />
          <Detail label="Affected user" value={incident.AffectedUser} />
          <Detail label="Affected device" value={incident.AffectedDevice} />
          <Detail label="Source IP" value={incident.SourceIP} />
          <Detail label="First seen" value={formatDateTime(incident.FirstSeen)} />
          <Detail label="Last seen" value={formatDateTime(incident.LastSeen)} />
          <Detail label="Approval required" value={formatBoolean(incident.RequiresApproval)} />
          <Detail label="Recommended action" value={incident.RecommendedActionID} />
          <Detail label="Correlation reason" value={incident.ClassificationReason || incident.CorrelationReason} />
        </dl>
      </section>

      <section className="panel">
        <div className="panel-title">Related evidence</div>
        <div className="chip-row">
          {(Array.isArray(alertTypes) ? alertTypes : []).map((value) => <span className="chip" key={value}>{safeText(value)}</span>)}
        </div>
        <div className="chip-row">
          {(Array.isArray(alertIds) ? alertIds : []).map((value) => <span className="chip" key={value}>{safeText(value)}</span>)}
        </div>
        <div className="chip-row">
          {(incident.MITRETactics || []).map((value) => <span className="chip" key={value}>{safeText(value)}</span>)}
        </div>
        <div className="chip-row">
          {(incident.MITRETechniques || []).map((value) => <span className="chip" key={value}>{safeText(value)}</span>)}
        </div>
      </section>

      <AttackChain stages={incident.AttackStages || []} />

      {analysis ? (
        <section className="panel">
          <div className="panel-title">Latest analyst result</div>
          <div className="details-grid">
            {toRows(analysis).slice(0, 12).map((row) => (
              <Detail key={row.key} label={row.key} value={Array.isArray(row.value) ? row.value.join(', ') : String(row.value)} />
            ))}
          </div>
        </section>
      ) : null}

      {actionDecision ? (
        <section className="panel">
          <div className="panel-title">Simulation decision</div>
          <dl className="details-grid">
            <Detail label="Decision" value={actionDecision.Decision} />
            <Detail label="Execution mode" value={actionDecision.ExecutionMode} />
            <Detail label="Message" value={actionDecision.Message} />
            <Detail label="Timestamp" value={formatDateTime(actionDecision.Timestamp)} />
          </dl>
        </section>
      ) : null}
    </div>
  );
}

function Detail({ label, value }) {
  return (
    <div className="detail-item">
      <dt>{label}</dt>
      <dd>{safeText(value)}</dd>
    </div>
  );
}
