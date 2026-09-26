import "./layout.css";

interface TopbarProps {
  apiOnline: boolean;
}

export function Topbar({ apiOnline }: TopbarProps) {
  return (
    <header className="topbar">
      <div className="topbar-section">
        {/* Search could go here if implemented */}
      </div>
      <div className="topbar-section">
        <span className="env-indicator">LOCAL / DEMO</span>
        <div className="health-status">
          <div className={`health-dot ${apiOnline ? "healthy" : "unhealthy"}`}></div>
          <span>{apiOnline ? "API Connected" : "API Offline"}</span>
        </div>
      </div>
    </header>
  );
}
