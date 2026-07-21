import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ravenApi } from '../api/ravenApi';
import ErrorState from '../components/ErrorState';
import LoadingState from '../components/LoadingState';
import ScenarioForm from '../components/ScenarioForm';
import { formatBoolean, safeText, truncateId } from '../utils/formatters';

const initialForm = {
  scenario_mode: 'select',
  scenario_name: '',
  difficulty: 'Medium',
  noise_level: 'Low',
  seed: '',
  environment: 'Finance SME',
  analyst_mode: 'Deterministic',
  ollama_model: 'gemma3:4b-it-qat',
  reveal_answer: false
};

export default function ScenarioLabPage() {
  const [scenarios, setScenarios] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState(null);
  const [validationError, setValidationError] = useState('');
  const [form, setForm] = useState(initialForm);

  useEffect(() => {
    let cancelled = false;
    ravenApi.scenarios()
      .then((items) => {
        if (!cancelled) {
          setScenarios(items);
          setForm((current) => ({ ...current, scenario_name: items[0]?.ScenarioName || '' }));
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingState label="scenario lab" />;
  if (error) return <ErrorState title="Scenario catalog unavailable" message={error} onRetry={() => window.location.reload()} />;

  function submit(event) {
    event.preventDefault();
    setValidationError('');
    if (!form.seed) {
      setValidationError('Seed is required.');
      return;
    }
    if (form.scenario_mode === 'select' && !form.scenario_name) {
      setValidationError('Choose a scenario when Select mode is active.');
      return;
    }
    const payload = {
      scenario_mode: form.scenario_mode,
      scenario_name: form.scenario_mode === 'select' ? form.scenario_name : undefined,
      difficulty: form.difficulty,
      noise_level: form.noise_level,
      seed: Number(form.seed),
      environment: safeText(form.environment, 'Finance SME'),
      analyst_mode: form.analyst_mode,
      ollama_model: safeText(form.ollama_model, 'gemma3:4b-it-qat'),
      reveal_answer: Boolean(form.reveal_answer)
    };
    setRunning(true);
    ravenApi.runScenario(payload)
      .then((result) => setRunResult(result))
      .catch((err) => setValidationError(err.message))
      .finally(() => setRunning(false));
  }

  return (
    <div className="page-stack">
      <ScenarioForm scenarios={scenarios} form={form} setForm={setForm} onSubmit={submit} busy={running} error={validationError} />

      {runResult ? (
        <section className="panel">
          <div className="panel-title">Run result</div>
          <div className="metrics-grid compact">
            <Metric label="Run ID" value={truncateId(runResult.RunID, 8)} />
            <Metric label="Scenario label" value={runResult.ScenarioLabel} />
            <Metric label="Scenario mode" value={runResult.ScenarioMode || form.scenario_mode} />
            <Metric label="Difficulty" value={runResult.Difficulty} />
            <Metric label="Noise" value={runResult.NoiseLevel} />
            <Metric label="Events" value={runResult.EventCount} />
            <Metric label="Alerts" value={runResult.Alerts?.length || 0} />
            <Metric label="Incidents" value={runResult.Incidents?.length || 0} />
            <Metric label="Overall pass" value={formatBoolean(runResult.Evaluation?.OverallPassed)} />
          </div>
          <div className="panel-stack">
            <section className="panel panel-inner">
              <div className="panel-title">Selected incident</div>
              <div className="details-grid">
                <Detail label="Incident ID" value={runResult.SelectedIncident?.IncidentID} />
                <Detail label="Type" value={runResult.SelectedIncident?.IncidentType || runResult.SelectedIncident?.CorrelationPattern} />
                <Detail label="Severity" value={runResult.SelectedIncident?.IncidentSeverity || runResult.SelectedIncident?.Severity} />
                <Detail label="Target" value={runResult.SelectedIncident?.Target} />
              </div>
              {runResult.SelectedIncident?.IncidentID ? (
                <Link className="text-link" to={`/incidents/${runResult.SelectedIncident.IncidentID}`}>
                  Open incident details
                </Link>
              ) : null}
            </section>
            <section className="panel panel-inner">
              <div className="panel-title">Analyst and defender</div>
              <div className="details-grid">
                <Detail label="Analyst status" value={runResult.AnalystResult?.Status} />
                <Detail label="Threat type" value={runResult.AnalystResult?.ThreatType} />
                <Detail label="Recommended action" value={runResult.DefenderRecommendation?.ActionID} />
                <Detail label="Simulation decision" value={runResult.DefenderRecommendation?.DecisionReason || 'Simulation only'} />
              </div>
            </section>
            <section className="panel panel-inner">
              <div className="panel-title">Evaluation</div>
              <div className="details-grid">
                <Detail label="Overall passed" value={formatBoolean(runResult.Evaluation?.OverallPassed)} />
                <Detail label="Detected" value={formatBoolean(runResult.Evaluation?.Detected)} />
                <Detail label="Incident type matched" value={formatBoolean(runResult.Evaluation?.IncidentTypeMatched)} />
                <Detail label="Target matched" value={formatBoolean(runResult.Evaluation?.TargetMatched)} />
              </div>
              {runResult.AnswerRevealed && runResult.Evaluation ? (
                <div className="notice">Answer details were returned by the API for this run.</div>
              ) : null}
            </section>
          </div>
        </section>
      ) : null}

      <section className="panel">
        <div className="panel-title">Scenario catalog</div>
        <div className="coverage-grid">
          {scenarios.map((scenario) => (
            <article className="coverage-card" key={scenario.ScenarioName}>
              <div className="coverage-name">{scenario.ScenarioName}</div>
              <div className="coverage-copy">{scenario.Description}</div>
              <div className="coverage-copy">Difficulties: {scenario.SupportedDifficulties.join(', ')}</div>
              <div className="coverage-copy">Noise: {scenario.SupportedNoiseLevels.join(', ')}</div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{safeText(value)}</div>
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
