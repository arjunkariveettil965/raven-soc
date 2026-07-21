import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ravenApi } from '../api/ravenApi';
import ErrorState from '../components/ErrorState';
import LoadingState from '../components/LoadingState';
import { formatDateTime, safeText, truncateId } from '../utils/formatters';

export default function RunsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [runs, setRuns] = useState([]);
  const [selectedRun, setSelectedRun] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState({
    scenario_label: searchParams.get('scenario_label') || '',
    difficulty: searchParams.get('difficulty') || '',
    limit: searchParams.get('limit') || 20
  });

  useEffect(() => {
    refresh();
  }, []);

  function refresh(nextFilters = filters) {
    setLoading(true);
    setError('');
    ravenApi.runs({ ...nextFilters, limit: Number(nextFilters.limit) })
      .then((result) => {
        setRuns(result.Runs || []);
        setLoading(false);
        if (result.Runs?.[0] && !selectedRun) {
          setSelectedRun(result.Runs[0]);
        }
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }

  function applyFilters(event) {
    event.preventDefault();
    setSearchParams(filters);
    refresh(filters);
  }

  if (loading) return <LoadingState label="runs" />;
  if (error) return <ErrorState title="Run history unavailable" message={error} onRetry={() => refresh()} />;

  function loadDetail(runId) {
    ravenApi.runDetail(runId).then((detail) => setSelectedRun({ ...detail.Run, Incidents: detail.Incidents }));
  }

  return (
    <div className="page-stack">
      <section className="panel">
        <div className="panel-title">Run filters</div>
        <form className="form-grid form-inline" onSubmit={applyFilters}>
          <label>
            Scenario label
            <input value={filters.scenario_label} onChange={(e) => setFilters({ ...filters, scenario_label: e.target.value })} />
          </label>
          <label>
            Difficulty
            <input value={filters.difficulty} onChange={(e) => setFilters({ ...filters, difficulty: e.target.value })} />
          </label>
          <label>
            Limit
            <input type="number" min="1" max="500" value={filters.limit} onChange={(e) => setFilters({ ...filters, limit: e.target.value })} />
          </label>
          <div className="form-actions">
            <button className="button button-primary" type="submit">Apply</button>
          </div>
        </form>
      </section>

      <section className="panel">
        <div className="panel-title">Run history</div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Scenario</th>
                <th>Difficulty</th>
                <th>Noise</th>
                <th>Events</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.RunID} className="clickable-row" onClick={() => loadDetail(run.RunID)}>
                  <td>{truncateId(run.RunID, 8)}</td>
                  <td>{safeText(run.ScenarioLabel)}</td>
                  <td>{safeText(run.Difficulty)}</td>
                  <td>{safeText(run.NoiseLevel)}</td>
                  <td>{run.EventCount}</td>
                  <td>{formatDateTime(run.CreatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selectedRun ? (
        <section className="panel">
          <div className="panel-title">Run detail</div>
          <div className="details-grid">
            <Detail label="Run ID" value={selectedRun.RunID} />
            <Detail label="Scenario label" value={selectedRun.ScenarioLabel} />
            <Detail label="Scenario mode" value={selectedRun.ScenarioMode} />
            <Detail label="Difficulty" value={selectedRun.Difficulty} />
            <Detail label="Noise level" value={selectedRun.NoiseLevel} />
            <Detail label="Answer revealed" value={selectedRun.AnswerRevealed ? 'Yes' : 'No'} />
            <Detail label="Event count" value={selectedRun.EventCount} />
            <Detail label="Attack event count" value={selectedRun.AttackEventCount} />
            <Detail label="Benign event count" value={selectedRun.BenignEventCount} />
          </div>
          {selectedRun.Evaluation ? (
            <section className="panel panel-inner">
              <div className="panel-title">Evaluation summary</div>
              <div className="details-grid">
                <Detail label="Overall passed" value={selectedRun.Evaluation.OverallPassed ? 'Yes' : 'No'} />
                <Detail label="Detected" value={selectedRun.Evaluation.Detected ? 'Yes' : 'No'} />
                <Detail label="Incident matched" value={selectedRun.Evaluation.IncidentTypeMatched ? 'Yes' : 'No'} />
                <Detail label="Recommended action accepted" value={selectedRun.Evaluation.RecommendedActionAccepted ? 'Yes' : 'No'} />
              </div>
            </section>
          ) : null}
          {Array.isArray(selectedRun.Incidents) ? (
            <section className="panel panel-inner">
              <div className="panel-title">Related incidents</div>
              <div className="table-mini">
                {selectedRun.Incidents.map((incident) => (
                  <div className="table-mini-row" key={incident.IncidentID}>
                    <span>{truncateId(incident.IncidentID, 8)}</span>
                    <span>{safeText(incident.IncidentType || incident.CorrelationPattern)}</span>
                    <span>{safeText(incident.IncidentSeverity || incident.Severity)}</span>
                    <span>{safeText(incident.Target)}</span>
                  </div>
                ))}
              </div>
            </section>
          ) : null}
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
