import "./layout.css";
import type { LiveStatus } from "../../services/api";

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: any) => void;
  liveStatus: LiveStatus | null;
}

export function Sidebar({ currentTab, setCurrentTab, liveStatus }: SidebarProps) {
  const tabs = [
    { id: "dashboard", label: "Overview", icon: "📊" },
    { id: "incidents", label: "Incidents", icon: "🚨" },
    { id: "alerts", label: "Alerts", icon: "🔔" },
    { id: "live", label: "Live Monitoring", icon: "📡" },
    { id: "scenarios", label: "Scenarios", icon: "🧪" },
    { id: "mitre", label: "MITRE ATT&CK", icon: "🕸️" },
    { id: "settings", label: "System", icon: "⚙️" },
  ];

  return (
    <aside className="main-sidebar">
      <div className="sidebar-brand">
        <span className="shield-icon">🛡️</span>
        <h2>RAVEN-SOC</h2>
      </div>
      <nav className="sidebar-nav">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`nav-item ${currentTab === tab.id ? "active" : ""}`}
            onClick={() => setCurrentTab(tab.id as any)}
          >
            <span className="icon">{tab.icon}</span> {tab.label}
            {tab.id === "live" && liveStatus?.status === "running" && <span className="live-pulse-dot" />}
          </button>
        ))}
      </nav>
    </aside>
  );
}
