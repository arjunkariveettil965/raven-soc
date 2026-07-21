import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ravenApi } from '../api/ravenApi';
import ErrorState from '../components/ErrorState';
import LoadingState from '../components/LoadingState';
import AnalystPanel from '../components/AnalystPanel';
import DefenderPanel from '../components/DefenderPanel';
import IncidentDetails from '../components/IncidentDetails';

export default function IncidentPage() {
  const { incidentId } = useParams();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [incident, setIncident] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [analysisMeta, setAnalysisMeta] = useState(null);
  const [actionDecision, setActionDecision] = useState(null);
  const [analystMode, setAnalystMode] = useState('Hybrid');
  const [model, setModel] = useState('gemma3:4b-it-qat');
  const [busy, setBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      ravenApi.incident(incidentId),
      ravenApi.analysis(incidentId),
      ravenApi.actionStatus(incidentId)
    ])
      .then(([incidentResult, analysisResult, actionResult]) => {
        if (incidentResult.status === 'fulfilled') setIncident(incidentResult.value.Incident);
        if (analysisResult.status === 'fulfilled') {
          setAnalysis(analysisResult.value.AnalystResult);
          setAnalysisMeta(analysisResult.value.AnalystMetadata);
        } else {
          setAnalysis(null);
          setAnalysisMeta(null);
        }
        if (actionResult.status === 'fulfilled') setActionDecision(actionResult.value);
        else setActionDecision(null);
        setError('');
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [incidentId]);

  function analyze() {
    setBusy(true);
    ravenApi.analyzeIncident(incidentId, { mode: analystMode, ollama_model: model })
      .then((response) => {
        setAnalysis(response.AnalystResult);
        setAnalysisMeta(response.AnalystMetadata);
      })
      .catch((err) => setError(err.message))
      .finally(() => setBusy(false));
  }

  function approve() {
    if (!window.confirm('Approve this simulation-only action?')) return;
    setActionBusy(true);
    ravenApi.approveAction(incidentId)
      .then((response) => setActionDecision(response))
      .catch((err) => setError(err.message))
      .finally(() => setActionBusy(false));
  }

  function reject() {
    if (!window.confirm('Reject this recommendation?')) return;
    setActionBusy(true);
    ravenApi.rejectAction(incidentId)
      .then((response) => setActionDecision(response))
      .catch((err) => setError(err.message))
      .finally(() => setActionBusy(false));
  }

  if (loading) return <LoadingState label="incident" />;
  if (error && !incident) return <ErrorState title="Incident unavailable" message={error} onRetry={() => window.location.reload()} />;

  return (
    <div className="page-stack">
      {error ? <div className="notice error">{error}</div> : null}
      <IncidentDetails incident={incident} analysis={analysis} actionDecision={actionDecision} />
      <AnalystPanel
        result={analysis}
        metadata={analysisMeta}
        onAnalyze={analyze}
        mode={analystMode}
        setMode={setAnalystMode}
        model={model}
        setModel={setModel}
        busy={busy}
      />
      <DefenderPanel
        decision={actionDecision}
        incident={incident}
        onApprove={approve}
        onReject={reject}
        busy={actionBusy}
        disabled={!!actionDecision?.Decision}
      />
    </div>
  );
}
