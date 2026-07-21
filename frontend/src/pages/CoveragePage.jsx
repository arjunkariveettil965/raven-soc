import { useEffect, useState } from 'react';
import { ravenApi } from '../api/ravenApi';
import CoveragePanel from '../components/CoveragePanel';
import ErrorState from '../components/ErrorState';
import LoadingState from '../components/LoadingState';

export default function CoveragePage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [coverage, setCoverage] = useState(null);

  useEffect(() => {
    ravenApi.coverage()
      .then((result) => setCoverage(result))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState label="coverage" />;
  if (error) return <ErrorState title="Coverage unavailable" message={error} onRetry={() => window.location.reload()} />;

  return (
    <div className="page-stack">
      <CoveragePanel coverage={coverage} />
    </div>
  );
}
