import { get, post } from './client';

export const ravenApi = {
  health: () => get('/api/v1/health'),
  scenarios: () => get('/api/v1/scenarios'),
  runScenario: (payload) => post('/api/v1/scenarios/run', payload),
  coverage: () => get('/api/v1/coverage'),
  runs: (params = {}) => {
    const search = new URLSearchParams();
    if (params.limit) search.set('limit', params.limit);
    if (params.scenario_label) search.set('scenario_label', params.scenario_label);
    if (params.difficulty) search.set('difficulty', params.difficulty);
    if (params.created_after) search.set('created_after', params.created_after);
    if (params.created_before) search.set('created_before', params.created_before);
    return get(`/api/v1/runs${search.toString() ? `?${search.toString()}` : ''}`);
  },
  runDetail: (runId) => get(`/api/v1/runs/${encodeURIComponent(runId)}`),
  incidents: (params = {}) => {
    const search = new URLSearchParams();
    if (params.limit) search.set('limit', params.limit);
    if (params.severity) search.set('severity', params.severity);
    if (params.incident_type) search.set('incident_type', params.incident_type);
    return get(`/api/v1/incidents${search.toString() ? `?${search.toString()}` : ''}`);
  },
  incident: (incidentId) => get(`/api/v1/incidents/${encodeURIComponent(incidentId)}`),
  analysis: (incidentId) => get(`/api/v1/incidents/${encodeURIComponent(incidentId)}/analysis`),
  analyzeIncident: (incidentId, payload) => post(`/api/v1/incidents/${encodeURIComponent(incidentId)}/analyze`, payload),
  actionStatus: (incidentId) => get(`/api/v1/actions/${encodeURIComponent(incidentId)}`),
  approveAction: (incidentId) => post(`/api/v1/actions/${encodeURIComponent(incidentId)}/approve`, {}),
  rejectAction: (incidentId) => post(`/api/v1/actions/${encodeURIComponent(incidentId)}/reject`, {})
};
