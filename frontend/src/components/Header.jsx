import { useLocation } from 'react-router-dom';
import { labelize } from '../utils/formatters';

export default function Header() {
  const location = useLocation();
  const title = labelize(location.pathname.split('/').filter(Boolean).slice(-1)[0] || 'Dashboard');
  return (
    <header className="header">
      <div>
        <div className="page-eyebrow">Local SOC workspace</div>
        <h1 className="page-title">{title === 'Dashboard' ? 'Dashboard' : title}</h1>
      </div>
      <div className="header-chip">FastAPI connected</div>
    </header>
  );
}
