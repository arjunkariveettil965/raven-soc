import { formatConfidence, formatBoolean, safeText } from '../utils/formatters';

export default function AnalystPanel({ result, metadata, onAnalyze, mode, setMode, model, setModel, busy }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div className="panel-title">Analyst</div>
        <div className="panel-actions">
          <select value={mode} onChange={(e) => setMode(e.target.value)} aria-label="Analyst mode">
            <option value="Deterministic">Deterministic</option>
            <option value="Hybrid">Hybrid</option>
          </select>
          <input value={model} onChange={(e) => setModel(e.target.value)} aria-label="Model name" placeholder="gemma3:4b-it-qat" />
          <button className="button button-primary" type="button" onClick={onAnalyze} disabled={busy}>
            {busy ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
      </div>
      {mode === 'Hybrid' ? <div className="notice warning">Hybrid mode uses local Ollama. Fallback is safe and explicit.</div> : null}
      {result ? (
        <div className="details-grid">
          <Field label="Status" value={result.Status} />
          <Field label="Threat type" value={result.ThreatType} />
          <Field label="Severity" value={result.Severity} />
          <Field label="Confidence" value={formatConfidence(result.Confidence)} />
          <Field label="Summary" value={result.Summary} />
          <Field label="Suspicion reason" value={result.SuspicionReason} />
          <Field label="Observed evidence" value={(result.ObservedEvidence || []).join(', ')} />
          <Field label="Inferences" value={(result.Inferences || []).join(' | ')} />
          <Field label="MITRE techniques" value={(result.MITRETechniques || []).join(', ')} />
          <Field label="Recommended action" value={result.RecommendedActionID} />
          <Field label="Target" value={result.Target} />
          <Field label="Approval requirement" value={formatBoolean(result.RequiresApproval)} />
          <Field label="Fallback used" value={formatBoolean(metadata?.UsedFallback)} />
          <Field label="Fallback reason" value={metadata?.FallbackReason} />
          <Field label="Validation errors" value={(metadata?.ValidationErrors || []).join('; ')} />
          <Field label="Normalization applied" value={formatBoolean(metadata?.NormalizationApplied)} />
          <Field label="Model name" value={metadata?.ModelName} />
        </div>
      ) : (
        <div className="state-panel">Run an analysis to view the strict analyst response.</div>
      )}
    </section>
  );
}

function Field({ label, value }) {
  return (
    <div className="detail-item">
      <dt>{label}</dt>
      <dd>{safeText(value)}</dd>
    </div>
  );
}
