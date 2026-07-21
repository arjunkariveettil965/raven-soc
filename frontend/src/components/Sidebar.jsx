import { NavLink } from 'react-router-dom';

const links = [
  { to: '/', label: 'Dashboard' },
  { to: '/scenarios', label: 'Scenario Lab' },
  { to: '/runs', label: 'Runs' },
  { to: '/incidents', label: 'Incidents' },
  { to: '/coverage', label: 'Coverage' }
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div>
        <div className="brand-mark">RAVEN-SOC</div>
        <div className="brand-subtitle">FastAPI console</div>
      </div>
      <nav className="sidebar-nav" aria-label="Primary">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === '/'}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footnote">Simulation only. No real containment.</div>
    </aside>
  );
}
