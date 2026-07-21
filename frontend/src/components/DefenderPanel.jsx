import { formatBoolean, safeText } from '../utils/formatters';

export default function DefenderPanel({ decision, incident, onApprove, onReject, busy, disabled }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div className="panel-title">Defender</div>
        <div className="panel-actions">
          <button className="button button-primary" type="button" onClick={onApprove} disabled={busy || disabled}>
            Approve simulated action
          </button>
          <button className="button button-secondary" type="button" onClick={onReject} disabled={busy || disabled}>
            Reject recommendation
          </button>
        </div>
      </div>
      <div className="notice">Simulation only. No real endpoint, account, network rule, or process will be modified.</div>
      {decision ? (
        <dl className="details-grid">
          <Detail label="Action" value={decision.ActionID} />
          <Detail label="Trusted target" value={decision.Target} />
          <Detail label="Decision" value={decision.Decision} />
          <Detail label="Execution mode" value={decision.ExecutionMode} />
          <Detail label="Message" value={decision.Message} />
          <Detail label="Timestamp" value={decision.Timestamp} />
          <Detail label="Approval required" value={formatBoolean(incident?.RequiresApproval)} />
        </dl>
      ) : (
        <div className="state-panel">No persisted decision yet.</div>
      )}
    </section>
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
