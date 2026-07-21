import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ravenApi } from '../api/ravenApi';
import ErrorState from '../components/ErrorState';
import LoadingState from '../components/LoadingState';
import MetricCard from '../components/MetricCard';
import StatusBadge from '../components/StatusBadge';
import { formatDateTime, formatSeverity, safeText, truncateId } from '../utils/formatters';

export default function DashboardPage() {
  const [state, setState] = useState({ loading: true, error: null, data: null });

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      ravenApi.health(),
      ravenApi.incidents({ limit: 10 }),
      ravenApi.runs({ limit: 10 }),
      ravenApi.coverage()
    ])
      .then(([health, incidents, runs, coverage]) => {
        if (!cancelled) setState({ loading: false, error: null, data: { health, incidents: incidents.Incidents || [], runs: runs.Runs || [], coverage } });
      })
      .catch((error) => {
        if (!cancelled) setState({ loading: false, error: error.message, data: null });
      });
    return () => { cancelled = true; };
  }, []);

  if (state.loading) return <LoadingState label="dashboard" />;
  if (state.error) {
    return (
      <ErrorState
        title="Backend offline"
        message={state.error}
        onRetry={() => window.location.reload()}
      />
    );
  }

  const { health, incidents, runs, coverage } = state.data;
  const highIncidents = incidents.filter((incident) => ['High', 'Critical'].includes(formatSeverity(incident.IncidentSeverity || incident.Severity)));
  const latestRun = runs[0];
  const latestIncident = incidents[0];

  return (
    <div className="page-stack">
      <section className="notice">
        Simulation only. The frontend shows persisted API data and never executes containment.
      </section>

      <div className="metrics-grid">
        <MetricCard label="Backend" value={health.status || 'unknown'} hint={health.database?.backend || 'offline'} />
        <MetricCard label="Persistence" value={health.database?.persistent ? 'Enabled' : 'Disabled'} hint={health.database?.path_display || 'N/A'} />
        <MetricCard label="Default analyst model" value={health.ollama?.default_model || 'N/A'} hint={health.ollama?.configured_url || 'N/A'} />
        <MetricCard label="Total incidents" value={incidents.length} hint={`${highIncidents.length} high severity`} />
        <MetricCard label="Total runs" value={runs.length} hint={latestRun ? `Latest ${truncateId(latestRun.RunID, 6)}` : 'No runs yet'} />
        <MetricCard label="Coverage" value={coverage.DetectionRules?.length || 0} hint="Detection rules implemented" />
      </div>

      <div className="grid-two">
        <section className="panel">
          <div className="panel-head">
            <div className="panel-title">Recent incidents</div>
            <Link className="text-link" to="/incidents">View all</Link>
          </div>
          {latestIncident ? (
            <div className="table-mini">
              {incidents.slice(0, 5).map((incident) => (
                <Link key={incident.IncidentID} className="table-mini-row" to={`/incidents/${incident.IncidentID}`}>
                  <span>{truncateId(incident.IncidentID, 8)}</span>
                  <span>{safeText(incident.IncidentType || incident.CorrelationPattern)}</span>
                  <span><StatusBadge tone={formatSeverity(incident.IncidentSeverity || incident.Severity).toLowerCase()}>{formatSeverity(incident.IncidentSeverity || incident.Severity)}</StatusBadge></span>
                  <span>{formatDateTime(incident.LastSeen)}</span>
                </Link>
              ))}
            </div>
          ) : (
            <div className="state-panel">No incidents have been stored yet.</div>
          )}
        </section>
        <section className="panel">
          <div className="panel-head">
            <div className="panel-title">Recent runs</div>
            <Link className="text-link" to="/runs">View all</Link>
          </div>
          {latestRun ? (
            <div className="table-mini">
              {runs.slice(0, 5).map((run) => (
                <Link key={run.RunID} className="table-mini-row" to={`/runs?run=${run.RunID}`}>
                  <span>{truncateId(run.RunID, 8)}</span>
                  <span>{safeText(run.ScenarioLabel)}</span>
                  <span>{safeText(run.Difficulty)}</span>
                  <span>{formatDateTime(run.CreatedAt)}</span>
                </Link>
              ))}
            </div>
          ) : (
            <div className="state-panel">No runs have been recorded yet.</div>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel-title">Coverage summary</div>
        <div className="coverage-summary">
          <div>{coverage.DetectionRules?.length || 0} detection rules</div>
          <div>{coverage.CorrelationPatterns?.length || 0} correlation patterns</div>
          <div>Local origins only</div>
        </div>
      </section>
    </div>
  );
}
