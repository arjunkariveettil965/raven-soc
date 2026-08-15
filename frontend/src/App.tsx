import { useState, useEffect, useRef } from "react";
import { ApiService, mergeIncidentsById } from "./services/api";
import type { AnalystMetadata, HealthStatus, LiveStatus, SecurityEvent, SecurityAlert, Incident } from "./services/api";
import "./App.css";


import { AppLayout } from "./components/layout/AppLayout";
import { Overview } from "./pages/Overview";
import { Incidents } from "./pages/Incidents";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Alerts } from "./pages/Alerts";
import { LiveMonitoring } from "./pages/LiveMonitoring";
import { Scenarios } from "./pages/Scenarios";
import { Mitre } from "./pages/Mitre";
import { Settings } from "./pages/Settings";
import { ReportGenerator } from "./pages/ReportGenerator";
import { PreventionStrategy } from "./pages/PreventionStrategy";

function App() {
  const [currentTab, setCurrentTab] = useState<string>("dashboard");
  
  // App States
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [liveStatus, setLiveStatus] = useState<LiveStatus | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  
  // Incident details & actions states
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [aiReport, setAiReport] = useState<any | null>(null);
  const [analystMetadata, setAnalystMetadata] = useState<AnalystMetadata | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [apiOnline, setApiOnline] = useState<boolean>(false);

  // Live monitor config
  const [selectedScenario, setSelectedScenario] = useState<string>("Multi Stage Intrusion");
  const [speed, setSpeed] = useState<number>(1.0);

  // Poll intervals
  const pollIntervalRef = useRef<any>(null);
  const liveIncidentsRef = useRef<Incident[]>([]);

  const refreshLiveFeeds = async () => {
    try {
      const [statusData, liveEvts, liveAlrts, liveIncs] = await Promise.all([
        ApiService.getLiveStatus(),
        ApiService.getLiveEvents(50),
        ApiService.getLiveAlerts(50),
        ApiService.getLiveIncidents(20),
      ]);
      setLiveStatus(statusData);
      liveIncidentsRef.current = liveIncs;
      setEvents(liveEvts);
      setAlerts(liveAlrts);
      setIncidents(liveIncs);
      setApiOnline(true);
    } catch (err) {
      console.error("Error refreshing live feeds:", err);
      setApiOnline(false);
    }
  };

  // Fetch initial health and status
  useEffect(() => {
    async function init() {
      try {
        const healthData = await ApiService.getHealth();
        setHealth(healthData);
        setApiOnline(healthData.status === "healthy");
        
        const statusData = await ApiService.getLiveStatus();
        setLiveStatus(statusData);
        setSpeed(statusData.speed || 1.0);
        if (statusData.supported_scenarios?.length > 0) {
          setSelectedScenario(statusData.scenario || statusData.supported_scenarios[0]);
        }
      } catch (err) {
        console.error("Initialization error:", err);
        setApiOnline(false);
      }
    }
    init();
  }, []);

  // Fetch lists based on current tab
  useEffect(() => {
    async function loadData() {
      try {
        if (currentTab === "dashboard") {
          const list = await ApiService.listIncidents(5);
          setIncidents(list);
          const activeStatus = await ApiService.getLiveStatus();
          setLiveStatus(activeStatus);
          setSpeed(activeStatus.speed || 1.0);
        } else if (currentTab === "live") {
          await refreshLiveFeeds();
        } else if (currentTab === "incidents") {
          const [list, liveIncs] = await Promise.all([
            ApiService.listIncidents(50),
            ApiService.getLiveIncidents(20).catch(() => [] as Incident[]),
          ]);
          liveIncidentsRef.current = liveIncs;
          setIncidents(mergeIncidentsById(list, liveIncs));
        }
      } catch (err) {
        console.error("Error fetching tab data:", err);
      }
    }
    loadData();
  }, [currentTab]);

  // Handle active live monitoring polling
  useEffect(() => {
    if (liveStatus?.status === "running") {
      pollIntervalRef.current = setInterval(async () => {
        try {
          const statusData = await ApiService.getLiveStatus();
          setLiveStatus(statusData);
          if (statusData.speed !== undefined) {
            setSpeed(statusData.speed);
          }

          if (currentTab === "live") {
            const [liveEvts, liveAlrts, liveIncs] = await Promise.all([
              ApiService.getLiveEvents(50),
              ApiService.getLiveAlerts(50),
              ApiService.getLiveIncidents(20),
            ]);
            liveIncidentsRef.current = liveIncs;
            setEvents(liveEvts);
            setAlerts(liveAlrts);
            setIncidents(liveIncs);
          } else if (currentTab === "dashboard") {
            const [list, activeStatus] = await Promise.all([
              ApiService.listIncidents(5),
              ApiService.getLiveStatus(),
            ]);
            setLiveStatus(activeStatus);
            setIncidents(list);
          }
        } catch (err) {
          console.error("Polling error:", err);
        }
      }, 3000);
    } else {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [liveStatus?.status, currentTab]);

  // Load detailed incident when selected
  useEffect(() => {
    async function loadIncidentDetails() {
      if (!selectedIncidentId) {
        setSelectedIncident(null);
        setAiReport(null);
        setActionMessage(null);
        return;
      }
      try {
        const details = await ApiService.getIncident(selectedIncidentId);
        setSelectedIncident(details);
        setAiReport(details.AnalystResult ?? null);
        setAnalystMetadata(details.AnalystMetadata ?? null);
        setActionMessage(null);

        if (!details.AnalystResult) {
          try {
            const analysis = await ApiService.getLatestAnalysis(selectedIncidentId);
            if (analysis && analysis.AnalystResult) {
              setAiReport(analysis.AnalystResult);
              setAnalystMetadata(analysis.AnalystMetadata ?? null);
            }
          } catch (_) {
            // ignore missing persisted analysis
          }
        }
      } catch (err) {
        console.error("Error loading incident details:", err);
      }
    }
    loadIncidentDetails();
  }, [selectedIncidentId]);

  // Live controls
  const handleStart = async () => {
    try {
      const status = await ApiService.startLive(selectedScenario, speed);
      setLiveStatus(status);
      setSpeed(status.speed || speed);
      if (currentTab === "live") {
        await refreshLiveFeeds();
      }
    } catch (err) {
      alert("Failed to start live monitoring");
    }
  };

  const handlePause = async () => {
    try {
      const status = await ApiService.pauseLive();
      setLiveStatus(status);
      setSpeed(status.speed || speed);
    } catch (err) {
      alert("Failed to pause live monitoring");
    }
  };

  const handleResume = async () => {
    try {
      const status = await ApiService.resumeLive(speed);
      setLiveStatus(status);
      setSpeed(status.speed || speed);
      if (currentTab === "live") {
        await refreshLiveFeeds();
      }
    } catch (err) {
      alert("Failed to resume live monitoring");
    }
  };

  const handleReset = async () => {
    try {
      const status = await ApiService.resetLive();
      setLiveStatus(status);
      setSpeed(status.speed || 1.0);
      setEvents([]);
      setAlerts([]);
      setIncidents([]);
    } catch (err) {
      alert("Failed to reset live monitoring");
    }
  };

  // AI Analyst Trigger
  const handleTriggerAI = async () => {
    if (!selectedIncidentId) return;
    setIsAnalyzing(true);
    try {
      const mode = health?.capabilities.hybrid_analyst ? 'Hybrid' : 'Deterministic';
      const res = await ApiService.analyzeIncident(selectedIncidentId, mode);
      setAiReport(res.AnalystResult);
      setAnalystMetadata(res.AnalystMetadata ?? null);
    } catch (err) {
      alert("AI analysis execution failed");
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Action decisions
  const handleApproveAction = async () => {
    if (!selectedIncidentId) return;
    try {
      const res = await ApiService.approveAction(selectedIncidentId);
      setActionMessage(`Approved: ${res.Message}`);
      // Refresh incident status
      const details = await ApiService.getIncident(selectedIncidentId);
      setSelectedIncident(details);
      setIncidents(prev => prev.map(inc =>
        inc.IncidentID === selectedIncidentId ? details : inc
      ));
    } catch (err) {
      alert("Failed to approve action");
    }
  };

  const handleRejectAction = async () => {
    if (!selectedIncidentId) return;
    try {
      const res = await ApiService.rejectAction(selectedIncidentId);
      setActionMessage(`Rejected: ${res.Message}`);
      // Refresh incident status
      const details = await ApiService.getIncident(selectedIncidentId);
      setSelectedIncident(details);
      setIncidents(prev => prev.map(inc =>
        inc.IncidentID === selectedIncidentId ? details : inc
      ));
    } catch (err) {
      alert("Failed to reject action");
    }
  };

  return (
    <AppLayout
      currentTab={selectedIncidentId ? "incident_detail" : currentTab}
      setCurrentTab={(tab) => {
        setSelectedIncidentId(null);
        setCurrentTab(tab);
      }}
      liveStatus={liveStatus}
      apiOnline={apiOnline}
    >
      {selectedIncidentId ? (
        <IncidentDetail
          incident={selectedIncident}
          aiReport={aiReport}
          analystMetadata={analystMetadata}
          isAnalyzing={isAnalyzing}
          actionMessage={actionMessage}
          onBack={() => setSelectedIncidentId(null)}
          onTriggerAI={handleTriggerAI}
          onApproveAction={handleApproveAction}
          onRejectAction={handleRejectAction}
        />
      ) : currentTab === "dashboard" ? (
        <Overview
          liveStatus={liveStatus}
          incidents={incidents}
          onIncidentSelect={(id) => setSelectedIncidentId(id)}
        />
      ) : currentTab === "incidents" ? (
        <Incidents
          incidents={incidents}
          onSelect={(id) => setSelectedIncidentId(id)}
        />
      ) : currentTab === "alerts" ? (
        <Alerts alerts={alerts} />
      ) : currentTab === "live" ? (
        <LiveMonitoring
          liveStatus={liveStatus}
          events={events}
          onStart={handleStart}
          onPause={handlePause}
          onResume={handleResume}
          onReset={handleReset}
        />
      ) : currentTab === "scenarios" ? (
        <Scenarios
          liveStatus={liveStatus}
          selectedScenario={selectedScenario}
          setSelectedScenario={setSelectedScenario}
          speed={speed}
          setSpeed={setSpeed}
          onStart={handleStart}
        />
      ) : currentTab === "mitre" ? (
        <Mitre incidents={incidents} />
      ) : currentTab === "reports" ? (
        <ReportGenerator />
      ) : currentTab === "prevention" ? (
        <PreventionStrategy />
      ) : currentTab === "settings" ? (
        <Settings health={health} />
      ) : (
        <Overview
          liveStatus={liveStatus}
          incidents={incidents}
          onIncidentSelect={(id) => setSelectedIncidentId(id)}
        />
      )}
    </AppLayout>
  );
}

export default App;
