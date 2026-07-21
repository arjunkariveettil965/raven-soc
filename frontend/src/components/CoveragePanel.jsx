export default function CoveragePanel({ coverage }) {
  if (!coverage) return null;
  return (
    <div className="panel-stack">
      <section className="panel">
        <div className="panel-title">Detection rules</div>
        <div className="coverage-grid">
          {coverage.DetectionRules?.map((item) => (
            <article className="coverage-card" key={item.RuleID}>
              <div className="coverage-name">{item.Name}</div>
              <div className="coverage-copy">{item.RuleID}</div>
              <div className="coverage-copy">{item.MITRETechnique}</div>
              <div className="coverage-copy">{item.DataSource}</div>
              <div className="coverage-copy">{item.RecommendedActionID}</div>
              <div className="coverage-copy">{item.RequiresApproval ? 'Approval required' : 'No approval required'}</div>
            </article>
          ))}
        </div>
      </section>
      <section className="panel">
        <div className="panel-title">Correlation patterns</div>
        <div className="coverage-grid">
          {coverage.CorrelationPatterns?.map((item) => (
            <article className="coverage-card" key={item.PatternID}>
              <div className="coverage-name">{item.Name}</div>
              <div className="coverage-copy">{item.PatternID}</div>
              <div className="coverage-copy">{item.MITRETechniques}</div>
              <div className="coverage-copy">{item.DataSource}</div>
              <div className="coverage-copy">{item.RecommendedActionID}</div>
              <div className="coverage-copy">{item.RequiresApproval ? 'Approval required' : 'No approval required'}</div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
