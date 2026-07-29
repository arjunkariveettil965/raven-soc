import { useState, useEffect, useRef } from "react";
import { ApiService } from "./services/api";
import type { HealthStatus, LiveStatus, SecurityEvent, SecurityAlert, Incident } from "./services/api";
import "./App.css";


function App() {
  const [currentTab, setCurrentTab] = useState<"dashboard" | "live" | "incidents" | "settings">("dashboard");
  
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
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Live monitor config
  const [selectedScenario, setSelectedScenario] = useState<string>("Multi Stage Intrusion");
  const [speed, setSpeed] = useState<number>(1.0);

  // Poll intervals
  const pollIntervalRef = useRef<any>(null);

  // Fetch initial health and status
  useEffect(() => {
    async function init() {
      try {
        const healthData = await ApiService.getHealth();
        setHealth(healthData);
        
        const statusData = await ApiService.getLiveStatus();
        setLiveStatus(statusData);
        if (statusData.supported_scenarios?.length > 0) {
          setSelectedScenario(statusData.scenario || statusData.supported_scenarios[0]);
        }
      } catch (err) {
        console.error("Initialization error:", err);
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
        } else if (currentTab === "live") {
          const liveEvts = await ApiService.getLiveEvents(50);
          setEvents(liveEvts);
          const liveAlrts = await ApiService.getLiveAlerts(50);
          setAlerts(liveAlrts);
          const liveIncs = await ApiService.getLiveIncidents(20);
          setIncidents(liveIncs);
        } else if (currentTab === "incidents") {
          const list = await ApiService.listIncidents(50);
          setIncidents(list);
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

          if (currentTab === "live") {
            const liveEvts = await ApiService.getLiveEvents(50);
            setEvents(liveEvts);
            const liveAlrts = await ApiService.getLiveAlerts(50);
            setAlerts(liveAlrts);
            const liveIncs = await ApiService.getLiveIncidents(20);
            setIncidents(liveIncs);
          } else if (currentTab === "dashboard") {
            const list = await ApiService.listIncidents(5);
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
        setAiReport(null);
        setActionMessage(null);

        // check if there's any existing analysis report
        try {
          const analysis = await ApiService.getLatestAnalysis(selectedIncidentId);
          if (analysis && analysis.AnalystResult) {
            setAiReport(analysis.AnalystResult);
          }
        } catch (_) {
          // ignore
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
    } catch (err) {
      alert("Failed to start live monitoring");
    }
  };

  const handlePause = async () => {
    try {
      const status = await ApiService.pauseLive();
      setLiveStatus(status);
    } catch (err) {
      alert("Failed to pause live monitoring");
    }
  };

  const handleResume = async () => {
    try {
      const status = await ApiService.resumeLive(speed);
      setLiveStatus(status);
    } catch (err) {
      alert("Failed to resume live monitoring");
    }
  };

  const handleReset = async () => {
    try {
      const status = await ApiService.resetLive();
      setLiveStatus(status);
      setEvents([]);
      setAlerts([]);
      setIncidents([]);
    } catch (err) {
      alert("Failed to reset live monitoring");
    }
  };

  // AI Analyst Trigger
  const handleTriggerAI = async (mode: 'Deterministic' | 'Hybrid') => {
    if (!selectedIncidentId) return;
    setIsAnalyzing(true);
    try {
      const res = await ApiService.analyzeIncident(selectedIncidentId, mode);
      setAiReport(res.AnalystResult);
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
    } catch (err) {
      alert("Failed to reject action");
    }
  };

  return (
    <div className="app-container">
      
      {/* Top Banner & Health status */}
      <header className="main-header">
        <div className="header-brand">
          <div className="shield-icon">🛡️</div>
          <div>
            <h1>RAVEN-SOC</h1>
            <p className="subtitle">Real-Time AI Vigilance & Automated Security Operations</p>
          </div>
        </div>
        <div className="health-badge-container">
          <div className={`health-indicator ${health?.status === "healthy" ? "healthy" : "unhealthy"}`}></div>
          <span className="health-text">
            API: {health?.status === "healthy" ? "Connected" : "Offline (Mock Mode)"}
          </span>
        </div>
      </header>

      <div className="workspace">
        
        {/* Navigation Sidebar */}
        <aside className="main-sidebar">
          <nav>
            <button 
              className={`nav-item ${currentTab === "dashboard" ? "active" : ""}`}
              onClick={() => setCurrentTab("dashboard")}
            >
              <span className="icon">📊</span> Dashboard
            </button>
            <button 
              className={`nav-item ${currentTab === "live" ? "active" : ""}`}
              onClick={() => setCurrentTab("live")}
            >
              <span className="icon">📡</span> Live Monitoring
              {liveStatus?.status === "running" && <span className="live-pulse-dot"></span>}
            </button>
            <button 
              className={`nav-item ${currentTab === "incidents" ? "active" : ""}`}
              onClick={() => setCurrentTab("incidents")}
            >
              <span className="icon">🚨</span> Incident Investigation
            </button>
            <button 
              className={`nav-item ${currentTab === "settings" ? "active" : ""}`}
              onClick={() => setCurrentTab("settings")}
            >
              <span className="icon">⚙️</span> Settings & Diagnostics
            </button>
          </nav>

          {/* Quick Stats Widget */}
          <div className="sidebar-widget">
            <h4>Live Feed Status</h4>
            <div className="widget-row">
              <span>Status:</span>
              <span className={`status-label ${liveStatus?.status}`}>
                {liveStatus?.status.toUpperCase() || "STOPPED"}
              </span>
            </div>
            <div className="widget-row">
              <span>Events Ingested:</span>
              <span className="stat-count">{liveStatus?.event_count ?? 0}</span>
            </div>
            <div className="widget-row">
              <span>Incidents Correlated:</span>
              <span className="stat-count">{liveStatus?.incident_count ?? 0}</span>
            </div>
          </div>
        </aside>

        {/* Content View */}
        <main className="main-content">
          
          {/* TAB 1: DASHBOARD */}
          {currentTab === "dashboard" && (
            <div className="view-panel">
              <section className="dashboard-stats-grid">
                <div className="metric-card">
                  <h3>Active Alerts</h3>
                  <div className="metric-value text-warn">{liveStatus?.alert_count ?? 0}</div>
                  <p className="metric-desc">Unresolved security triggers</p>
                </div>
                <div className="metric-card">
                  <h3>Correlated Incidents</h3>
                  <div className="metric-value text-danger">{liveStatus?.incident_count ?? incidents.length}</div>
                  <p className="metric-desc">Multi-stage attack pathways</p>
                </div>
                <div className="metric-card">
                  <h3>Ingested Event Count</h3>
                  <div className="metric-value text-info">{liveStatus?.event_count ?? 0}</div>
                  <p className="metric-desc">Raw normalized Windows Logs</p>
                </div>
                <div className="metric-card">
                  <h3>Active Attack Tactic</h3>
                  <div className="metric-value text-accent">{liveStatus?.current_mitre_tactic || "None"}</div>
                  <p className="metric-desc">Current threat phase</p>
                </div>
              </section>

              <section className="dashboard-double-panel">
                {/* Recent Incidents Panel */}
                <div className="dashboard-section card-style">
                  <div className="section-header">
                    <h2>Recent Correlated Incidents</h2>
                    <button className="text-button" onClick={() => setCurrentTab("incidents")}>View All</button>
                  </div>
                  {incidents.length === 0 ? (
                    <div className="empty-state">No incidents correlated yet. Run Live Ingestion or Scenario Lab.</div>
                  ) : (
                    <div className="incident-compact-list">
                      {incidents.slice(0, 5).map((inc) => (
                        <div 
                          key={inc.IncidentID} 
                          className={`incident-compact-item severity-${inc.Severity?.toLowerCase()}`}
                          onClick={() => {
                            setSelectedIncidentId(inc.IncidentID);
                            setCurrentTab("incidents");
                          }}
                        >
                          <div className="inc-meta">
                            <span className="inc-id">{inc.IncidentID}</span>
                            <span className={`severity-badge ${inc.Severity?.toLowerCase()}`}>{inc.Severity}</span>
                          </div>
                          <div className="inc-title">{inc.IncidentType}</div>
                          <div className="inc-details-row">
                            <span>Score: <strong>{inc.Score}</strong></span>
                            <span>Status: <strong>{inc.State || "Active"}</strong></span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* System Capabilities / Config */}
                <div className="dashboard-section card-style">
                  <div className="section-header">
                    <h2>Active Detection Engines</h2>
                  </div>
                  <div className="detection-engines-grid">
                    <div className="engine-status-item">
                      <span className="engine-status-dot active"></span>
                      <div>
                        <h4>Rule Engine & Bursts</h4>
                        <p>Real-time log correlation with Sigmas</p>
                      </div>
                    </div>
                    <div className="engine-status-item">
                      <span className="engine-status-dot active"></span>
                      <div>
                        <h4>UEBA Anomaly Detection</h4>
                        <p>User and Entity Behavior profiling</p>
                      </div>
                    </div>
                    <div className="engine-status-item">
                      <span className="engine-status-dot active"></span>
                      <div>
                        <h4>FastAPI Orchestrator</h4>
                        <p>Event routing and sqlite baseline database</p>
                      </div>
                    </div>
                    <div className="engine-status-item">
                      <span className={`engine-status-dot ${health?.capabilities.hybrid_analyst ? "active" : "inactive"}`}></span>
                      <div>
                        <h4>AI Analyst Copilot</h4>
                        <p>{health?.capabilities.hybrid_analyst ? "Ollama model ready for Hybrid analysis" : "Ollama offline; using Local Deterministic mode"}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </section>
            </div>
          )}

          {/* TAB 2: LIVE MONITORING */}
          {currentTab === "live" && (
            <div className="view-panel">
              <section className="live-controls-panel card-style">
                <div className="controls-group">
                  <label htmlFor="scenario-select">Simulation Scenario:</label>
                  <select 
                    id="scenario-select"
                    value={selectedScenario}
                    onChange={(e) => setSelectedScenario(e.target.value)}
                    disabled={liveStatus?.status === "running"}
                  >
                    {liveStatus?.supported_scenarios?.map(s => (
                      <option key={s} value={s}>{s}</option>
                    )) || <option value="Multi Stage Intrusion">Multi Stage Intrusion</option>}
                  </select>
                </div>

                <div className="controls-group">
                  <label htmlFor="speed-select">Ingestion Speed:</label>
                  <select 
                    id="speed-select"
                    value={speed}
                    onChange={(e) => setSpeed(parseFloat(e.target.value))}
                  >
                    {liveStatus?.supported_speeds?.map(sp => (
                      <option key={sp} value={sp}>{sp}x</option>
                    )) || <option value="1">1.0x</option>}
                  </select>
                </div>

                <div className="button-group">
                  {liveStatus?.status !== "running" ? (
                    <button className="btn btn-success" onClick={handleStart}>
                      ▶ Start Ingestion
                    </button>
                  ) : (
                    <button className="btn btn-warning" onClick={handlePause}>
                      ⏸ Pause
                    </button>
                  )}
                  {liveStatus?.status === "paused" && (
                    <button className="btn btn-info" onClick={handleResume}>
                      ⏯ Resume
                    </button>
                  )}
                  <button className="btn btn-danger" onClick={handleReset}>
                    🔄 Reset Feed
                  </button>
                </div>
              </section>

              <section className="live-feeds-grid">
                
                {/* Alerts Stream */}
                <div className="feed-panel card-style">
                  <h3>Active Rules Triggered (Alerts)</h3>
                  <div className="table-wrapper">
                    <table>
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Rule / Indicator</th>
                          <th>Tactic / Technique</th>
                        </tr>
                      </thead>
                      <tbody>
                        {alerts.length === 0 ? (
                          <tr>
                            <td colSpan={3} className="table-empty">No alerts triggered yet.</td>
                          </tr>
                        ) : (
                          alerts.map((al, idx) => (
                            <tr key={al.AlertID || idx}>
                              <td><span className={`severity-badge ${al.Severity?.toLowerCase()}`}>{al.Severity}</span></td>
                              <td>
                                <strong>{al.RuleName}</strong>
                                <div className="text-sub">{al.Description}</div>
                              </td>
                              <td>
                                <span className="tactic-tag">{al.Tactic}</span>
                                <div className="text-sub">{al.Technique}</div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Raw Normalized Events Stream */}
                <div className="feed-panel card-style">
                  <h3>Normalized Log Stream (Latest 50)</h3>
                  <div className="table-wrapper">
                    <table>
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>ID / Channel</th>
                          <th>Source Computer</th>
                          <th>Log Message Detail</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="table-empty">Log stream empty. Start simulation.</td>
                          </tr>
                        ) : (
                          events.map((ev, idx) => (
                            <tr key={idx}>
                              <td className="text-nowrap">{ev.SystemTime ? new Date(ev.SystemTime).toLocaleTimeString() : "--"}</td>
                              <td>
                                <span className="channel-badge">{ev.Channel}</span>
                                <div className="text-sub">ID: {ev.EventID}</div>
                              </td>
                              <td className="text-nowrap">{ev.Computer}</td>
                              <td className="text-code">{ev.Message}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

              </section>
            </div>
          )}

          {/* TAB 3: INCIDENT INVESTIGATION */}
          {currentTab === "incidents" && (
            <div className="view-panel incident-investigation-layout">
              
              {/* Incidents Browser Sidebar */}
              <div className="incident-browser card-style">
                <h3>Incident Logs</h3>
                <div className="browser-list">
                  {incidents.length === 0 ? (
                    <div className="empty-state">No incidents found.</div>
                  ) : (
                    incidents.map((inc) => (
                      <div 
                        key={inc.IncidentID} 
                        className={`browser-item ${selectedIncidentId === inc.IncidentID ? "selected" : ""} severity-${inc.Severity?.toLowerCase()}`}
                        onClick={() => setSelectedIncidentId(inc.IncidentID)}
                      >
                        <div className="item-meta">
                          <span className="inc-id">{inc.IncidentID}</span>
                          <span className={`severity-badge ${inc.Severity?.toLowerCase()}`}>{inc.Severity}</span>
                        </div>
                        <h4 className="item-title">{inc.IncidentType}</h4>
                        <div className="item-stats">
                          <span>Risk Score: {inc.Score}</span>
                          <span>State: {inc.State}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Detailed Investigation Workspace */}
              <div className="incident-workspace">
                {selectedIncident ? (
                  <div className="investigation-details card-style">
                    
                    {/* Header */}
                    <div className="investigation-header">
                      <div>
                        <h2>{selectedIncident.IncidentType}</h2>
                        <p className="incident-guid">ID: {selectedIncident.IncidentID} | Risk Score: <strong className="text-danger">{selectedIncident.Score}</strong></p>
                      </div>
                      <div>
                        <span className={`severity-badge large ${selectedIncident.Severity?.toLowerCase()}`}>{selectedIncident.Severity} Severity</span>
                      </div>
                    </div>

                    <div className="investigation-body-grid">
                      
                      {/* Left side: Assets & Alerts */}
                      <div className="details-col-left">
                        
                        {/* Machine overview */}
                        {selectedIncident.MachineOverview && (
                          <div className="sub-panel">
                            <h3>Impacted Asset Overview</h3>
                            <div className="asset-details">
                              <div className="asset-stat-row">
                                <span>Host Name:</span>
                                <strong>{selectedIncident.MachineOverview.MachineID}</strong>
                              </div>
                              <div className="asset-stat-row">
                                <span>Criticality:</span>
                                <span className={`criticality-label ${selectedIncident.MachineOverview.Criticality?.toLowerCase()}`}>
                                  {selectedIncident.MachineOverview.Criticality}
                                </span>
                              </div>
                              <div className="asset-stat-row">
                                <span>Anomalies Count:</span>
                                <strong>{selectedIncident.MachineOverview.AnomaliesCount}</strong>
                              </div>
                              <div className="asset-stat-row">
                                <span>Risk Assessment:</span>
                                <strong>{selectedIncident.MachineOverview.RiskScore}/100</strong>
                              </div>
                              {selectedIncident.MachineOverview.HostStatus && (
                                <div className="asset-stat-row">
                                  <span>Host Status:</span>
                                  <span className={`status-tag ${selectedIncident.MachineOverview.HostStatus.toLowerCase()}`}>
                                    {selectedIncident.MachineOverview.HostStatus}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Associated Alerts */}
                        <div className="sub-panel">
                          <h3>Correlated Indicators & Rules</h3>
                          <ul className="correlated-alerts-list">
                            {selectedIncident.Alerts?.map((a, i) => (
                              <li key={i} className="alert-list-item">
                                <span className="alert-rule-name">{a.RuleName || "Trigger Rule"}</span>
                                <span className="alert-severity-badge">{a.Severity}</span>
                              </li>
                            )) || <li className="empty-state">No direct alert mappings.</li>}
                          </ul>
                        </div>

                        {/* Timeline */}
                        <div className="sub-panel">
                          <h3>Attack Path Timeline</h3>
                          <div className="timeline-container">
                            {selectedIncident.Timeline?.map((t, i) => (
                              <div key={i} className="timeline-item">
                                <div className="timeline-time">{t.Timestamp ? new Date(t.Timestamp).toLocaleTimeString() : "--"}</div>
                                <div className="timeline-desc">{t.Event}</div>
                              </div>
                            )) || <div className="empty-state">Timeline unavailable.</div>}
                          </div>
                        </div>

                      </div>

                      {/* Right side: AI Analyst & Defender Mitigation Actions */}
                      <div className="details-col-right">
                        
                        {/* AI Copilot Panel */}
                        <div className="sub-panel ai-analyst-panel">
                          <div className="ai-header">
                            <h3>🤖 AI SOC Analyst</h3>
                            <div className="ai-controls">
                              <button 
                                className="btn btn-sm btn-info"
                                onClick={() => handleTriggerAI('Deterministic')}
                                disabled={isAnalyzing}
                              >
                                {isAnalyzing ? "Analyzing..." : "Run AI Analysis"}
                              </button>
                            </div>
                          </div>
                          
                          <div className="ai-result-box">
                            {aiReport ? (
                              <div className="ai-report">
                                <h4>Summary</h4>
                                <p>{aiReport.Summary}</p>
                                {aiReport.RootCause && (
                                  <>
                                    <h4>Root Cause</h4>
                                    <p>{aiReport.RootCause}</p>
                                  </>
                                )}
                                {aiReport.Impact && (
                                  <>
                                    <h4>Business Impact</h4>
                                    <p>{aiReport.Impact}</p>
                                  </>
                                )}
                              </div>
                            ) : (
                              <div className="empty-state">No analyst report generated yet. Click "Run AI Analysis" to trigger our correlation engines.</div>
                            )}
                          </div>
                        </div>

                        {/* Defender Mitigation Recommendation */}
                        {selectedIncident.DefenderRecommendation && (
                          <div className="sub-panel mitigation-panel">
                            <h3>🛡️ Simulated Defender Action</h3>
                            <div className="mitigation-box">
                              <div className="mitigation-recommendation">
                                <strong>Recommended Action:</strong>
                                <span className="mitigation-badge">{selectedIncident.DefenderRecommendation.Mitigation}</span>
                              </div>
                              <div className="mitigation-target">
                                <span>Target Endpoint:</span>
                                <strong>{selectedIncident.DefenderRecommendation.Target}</strong>
                              </div>
                              <div className="mitigation-rationale">
                                <span>Rationale:</span>
                                <p>{selectedIncident.DefenderRecommendation.Rationale}</p>
                              </div>
                              <div className="mitigation-status">
                                <span>Action Status:</span>
                                <span className={`status-tag ${selectedIncident.DefenderRecommendation.Status}`}>
                                  {selectedIncident.DefenderRecommendation.Status.toUpperCase()}
                                </span>
                              </div>

                              {actionMessage && (
                                <div className="action-feedback-message">
                                  {actionMessage}
                                </div>
                              )}

                              {selectedIncident.DefenderRecommendation.Status === "pending" && (
                                <div className="mitigation-actions">
                                  <button className="btn btn-success" onClick={handleApproveAction}>
                                    Approve Action
                                  </button>
                                  <button className="btn btn-danger" onClick={handleRejectAction}>
                                    Reject Action
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                      </div>

                    </div>

                  </div>
                ) : (
                  <div className="workspace-empty card-style">
                    <div className="shield-watermark">🛡️</div>
                    <h3>Select an incident from the log list to begin your active investigation.</h3>
                  </div>
                )}
              </div>

            </div>
          )}

          {/* TAB 4: SETTINGS & DIAGNOSTICS */}
          {currentTab === "settings" && (
            <div className="view-panel card-style">
              <h2>Settings & Diagnostics</h2>
              <div className="settings-grid">
                
                <div className="settings-section">
                  <h3>Backend Service Details</h3>
                  <table className="settings-table">
                    <tbody>
                      <tr>
                        <td>Service Name</td>
                        <td><code>{health?.service || "raven-soc-api"}</code></td>
                      </tr>
                      <tr>
                        <td>API Version</td>
                        <td><code>{health?.version || "0.1.0"}</code></td>
                      </tr>
                      <tr>
                        <td>DB Location</td>
                        <td><code>{health?.database.path || "database/raven_soc_api.db"}</code></td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="settings-section">
                  <h3>Ollama Integration Status</h3>
                  <table className="settings-table">
                    <tbody>
                      <tr>
                        <td>Ollama URL</td>
                        <td><code>{health?.ollama.configured_url || "http://localhost:11434"}</code></td>
                      </tr>
                      <tr>
                        <td>Default LLM Model</td>
                        <td><code>{health?.ollama.default_model || "llama3"}</code></td>
                      </tr>
                      <tr>
                        <td>Hybrid AI Capability</td>
                        <td>
                          <span className={`status-badge ${health?.capabilities.hybrid_analyst ? "active" : "inactive"}`}>
                            {health?.capabilities.hybrid_analyst ? "Available" : "Unavailable (Deterministic Mode Fallback)"}
                          </span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

              </div>
            </div>
          )}

        </main>

      </div>
    </div>
  );
}

export default App;