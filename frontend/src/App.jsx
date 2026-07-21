import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import DashboardPage from './pages/DashboardPage';
import ScenarioLabPage from './pages/ScenarioLabPage';
import RunsPage from './pages/RunsPage';
import IncidentsPage from './pages/IncidentsPage';
import IncidentPage from './pages/IncidentPage';
import CoveragePage from './pages/CoveragePage';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="scenarios" element={<ScenarioLabPage />} />
        <Route path="runs" element={<RunsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:incidentId" element={<IncidentPage />} />
        <Route path="coverage" element={<CoveragePage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
