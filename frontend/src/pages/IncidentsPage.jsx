import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ravenApi } from '../api/ravenApi';
import ErrorState from '../components/ErrorState';
import LoadingState from '../components/LoadingState';
import IncidentTable from '../components/IncidentTable';
import { SEVERITY_ORDER } from '../utils/constants';
import { safeText } from '../utils/formatters';

export default function IncidentsPage() {
  const [state, setState] = useState({ loading: true, error: '', incidents: [] });
  const [filters, setFilters] = useState({ severity: '', incidentType: '', search: '', sort: 'newest' });
  const navigate = useNavigate();

  useEffect(() => {
    ravenApi.incidents({ limit: 200 })
      .then((result) => setState({ loading: false, error: '', incidents: result.Incidents || [] }))
      .catch((err) => setState({ loading: false, error: err.message, incidents: [] }));
  }, []);

  const filtered = useMemo(() => {
    let items = [...state.incidents];
    if (filters.severity) items = items.filter((incident) => safeText(incident.IncidentSeverity || incident.Severity) === filters.severity);
    if (filters.incidentType) items = items.filter((incident) => safeText(incident.IncidentType || incident.CorrelationPattern).toLowerCase().includes(filters.incidentType.toLowerCase()));
    if (filters.search) {
      const q = filters.search.toLowerCase();
      items = items.filter((incident) => [incident.IncidentID, incident.Target, incident.AffectedDevice, incident.SourceIP].some((value) => safeText(value).toLowerCase().includes(q)));
    }
    items.sort((a, b) => {
      if (filters.sort === 'severity') {
        return (SEVERITY_ORDER[safeText(b.IncidentSeverity || b.Severity)] || 0) - (SEVERITY_ORDER[safeText(a.IncidentSeverity || a.Severity)] || 0);
      }
      if (filters.sort === 'confidence') {
        return Number(b.IncidentConfidence || b.Confidence || 0) - Number(a.IncidentConfidence || a.Confidence || 0);
      }
      return new Date(b.LastSeen || 0) - new Date(a.LastSeen || 0);
    });
    return items;
  }, [filters, state.incidents]);

  if (state.loading) return <LoadingState label="incidents" />;
  if (state.error) return <ErrorState title="Incidents unavailable" message={state.error} onRetry={() => window.location.reload()} />;

  return (
    <div className="page-stack">
      <section className="panel">
        <div className="panel-title">Incident filters</div>
        <div className="form-grid form-inline">
          <label>
            Severity
            <input value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })} placeholder="High" />
          </label>
          <label>
            Incident type
            <input value={filters.incidentType} onChange={(e) => setFilters({ ...filters, incidentType: e.target.value })} placeholder="Intrusion" />
          </label>
          <label>
            Search
            <input value={filters.search} onChange={(e) => setFilters({ ...filters, search: e.target.value })} placeholder="ID or target" />
          </label>
          <label>
            Sort
            <select value={filters.sort} onChange={(e) => setFilters({ ...filters, sort: e.target.value })}>
              <option value="newest">Newest</option>
              <option value="severity">Severity</option>
              <option value="confidence">Confidence</option>
            </select>
          </label>
        </div>
      </section>
      <IncidentTable incidents={filtered} onSelect={(incident) => navigate(`/incidents/${incident.IncidentID}`)} sortLabel={filters.sort} />
    </div>
  );
}
