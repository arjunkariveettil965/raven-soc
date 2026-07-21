import { safeText } from '../utils/formatters';

export default function AttackChain({ stages = [] }) {
  if (!Array.isArray(stages) || stages.length === 0) {
    return (
      <section className="panel">
        <div className="panel-title">Attack chain</div>
        <div className="state-panel">No timeline stages available.</div>
      </section>
    );
  }
  return (
    <section className="panel">
      <div className="panel-title">Attack chain</div>
      <div className="attack-chain">
        {stages.map((stage, index) => (
          <div key={`${stage.Stage || stage.TimelineTime || index}`} className="attack-stage">
            <div className="attack-stage-index">{index + 1}</div>
            <div className="attack-stage-body">
              <div className="attack-stage-name">{safeText(stage.Stage || stage.MITRETactic)}</div>
              <div className="attack-stage-copy">{safeText(stage.Alert || stage.AlertType)}</div>
              <div className="attack-stage-meta">{safeText(stage.MITRETechnique)}</div>
            </div>
            {index < stages.length - 1 ? <div className="attack-stage-arrow">→</div> : null}
          </div>
        ))}
      </div>
    </section>
  );
}
