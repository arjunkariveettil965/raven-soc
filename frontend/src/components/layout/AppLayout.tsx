import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import type { LiveStatus } from "../../services/api";
import "./layout.css";

interface AppLayoutProps {
  currentTab: string;
  setCurrentTab: (tab: any) => void;
  liveStatus: LiveStatus | null;
  apiOnline: boolean;
  children: React.ReactNode;
}

export function AppLayout({ currentTab, setCurrentTab, liveStatus, apiOnline, children }: AppLayoutProps) {
  return (
    <div className="app-layout">
      <Sidebar currentTab={currentTab} setCurrentTab={setCurrentTab} liveStatus={liveStatus} />
      <div className="layout-content">
        <Topbar apiOnline={apiOnline} />
        <main className="page-container">
          {children}
        </main>
      </div>
    </div>
  );
}
