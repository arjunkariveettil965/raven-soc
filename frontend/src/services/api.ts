// API Service for RAVEN-SOC FastAPI backend
// With fallback mock data to support Azure Static Web Apps / offline modes

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

async function safeFetch<T>(url: string, options?: RequestInit, fallbackData?: T): Promise<T> {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });
    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }
    return await response.json() as T;
  } catch (error) {
    console.warn(`Failed to fetch from ${url}, using mock fallback. Error:`, error);
    if (fallbackData !== undefined) {
      return fallbackData;
    }
    throw error;
  }
}

// Interfaces
export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  database: {
    available: boolean;
    path: string;
    event_count?: number;
  };
  ollama: {
    configured_url: string;
    default_model: string;
    checked: boolean;
  };
  capabilities: {
    scenario_lab: boolean;
    detection: boolean;
    correlation: boolean;
    hybrid_analyst: boolean;
    simulated_defender: boolean;
  };
}

export interface AnalystMetadata {
  AnalystMode?: string;
  ModelName?: string;
  UsedFallback?: boolean;
  FallbackReason?: string | null;
  ValidationErrors?: string[];
  NormalizationApplied?: boolean;
  RawModelOutputAvailable?: boolean;
}

export interface AnalystAnalysisResponse {
  IncidentID: string;
  AnalystResult: Record<string, any>;
  AnalystMetadata: AnalystMetadata;
}

export interface LiveStatus {
  status: string;
  scenario: string;
  speed: number;
  event_count: number;
  queue_size: number;
  alert_count: number;
  incident_count: number;
  current_mitre_tactic: string;
  current_severity: string;
  latest_event: any | null;
  latest_alert: any | null;
  latest_incident: any | null;
  last_error: string | null;
  updated_at: string;
  supported_scenarios: string[];
  supported_speeds: number[];
}

export interface SecurityEvent {
  SystemTime: string;
  Channel: string;
  EventID: number;
  Severity: string;
  Computer: string;
  Message: string;
  [key: string]: any;
}

export interface SecurityAlert {
  AlertID: string;
  RuleName: string;
  Severity: string;
  Timestamp: string;
  Tactic: string;
  Technique: string;
  Description: string;
  EventCount: number;
}

export interface Incident {
  IncidentID: string;
  IncidentType: string;
  Severity: string;
  State: string;
  Score: number;
  Timeline: any[];
  Alerts: any[];
  MachineOverview?: {
    MachineID: string;
    RiskScore: number;
    Criticality: string;
    EventsAnalyzed: number;
    AnomaliesCount: number;
    HostStatus?: string;
    ContainmentStatus?: string;
  };
  DefenderRecommendation?: {
    ActionID: string;
    Mitigation: string;
    Target: string;
    Rationale: string;
    Status: string;
    Message?: string;
  };
  AnalystResult?: any;
  [key: string]: any;
}

// Normalize incident objects from live stream and historical database structures
export function normalizeIncident(data: any): Incident {
  const rawIncident = (data && data.Incident) ? data.Incident : data;
  
  const timeline = data?.Timeline || rawIncident?.Timeline || [];
  const recommendation = data?.DefenderRecommendation || rawIncident?.DefenderRecommendation || null;
  const analysis = data?.AnalystResult || rawIncident?.AnalystResult || null;
  const decision = rawIncident?.ActionDecision || null;

  // Normalize defender recommendation status and text
  let defenderRec = null;
  if (recommendation) {
    let status = "pending";
    if (decision) {
      status = decision.Decision;
    } else if (recommendation.Status) {
      status = recommendation.Status;
    } else if (recommendation.RequiresApproval === false) {
      status = "auto-executed";
    }

    defenderRec = {
      ActionID: recommendation.ActionID || recommendation.RecommendedActionID || "NO_ACTION",
      Mitigation: recommendation.ActionID ? recommendation.ActionID.replace(/_/g, ' ') : (recommendation.Mitigation || "Monitor"),
      Target: recommendation.Target || "",
      Rationale: recommendation.DecisionReason || recommendation.Rationale || "No reasoning provided.",
      Status: status,
      Message: recommendation.SimulationMessage || recommendation.Message || ""
    };
  } else if (rawIncident?.ActionDecision) {
    defenderRec = {
      ActionID: rawIncident.ActionDecision.ActionID,
      Mitigation: rawIncident.ActionDecision.ActionID ? rawIncident.ActionDecision.ActionID.replace(/_/g, ' ') : "Action Decision",
      Target: rawIncident.ActionDecision.Target || "",
      Rationale: "Determined from historical run.",
      Status: rawIncident.ActionDecision.Decision,
      Message: rawIncident.ActionDecision.Message || ""
    };
  }

  // Normalize machine overview if available
  const machineOverview = rawIncident?.MachineOverview || (rawIncident?.DeviceName ? {
    MachineID: rawIncident.DeviceName,
    RiskScore: rawIncident.Score || rawIncident.RiskScore || 50,
    Criticality: rawIncident.Criticality || "Medium",
    EventsAnalyzed: rawIncident.EventsCount || 0,
    AnomaliesCount: rawIncident.AnomaliesCount || 0
  } : null);

  return {
    ...rawIncident,
    IncidentID: rawIncident.IncidentID || rawIncident.incident_id,
    IncidentType: rawIncident.IncidentType || rawIncident.CorrelationPattern || rawIncident.incident_type || "Unknown Intrusion",
    Severity: rawIncident.Severity || rawIncident.IncidentSeverity || "Medium",
    Score: rawIncident.Score || rawIncident.RiskScore || 0,
    State: rawIncident.State || (decision ? "Mitigated" : "New"),
    Timeline: timeline,
    MachineOverview: machineOverview,
    DefenderRecommendation: defenderRec,
    AnalystResult: analysis
  };
}

// Fallback Mock Data
const mockHealth: HealthStatus = {
  status: "healthy",
  service: "raven-soc-api (Mock)",
  version: "0.1.0",
  database: { available: true, path: "database/mock.db", event_count: 105 },
  ollama: { configured_url: "http://localhost:11434", default_model: "gemma3:4b-it-qat", checked: false },
  capabilities: { scenario_lab: true, detection: true, correlation: true, hybrid_analyst: true, simulated_defender: true }
};

const mockLiveStatus: LiveStatus = {
  status: "stopped",
  scenario: "Multi Stage Intrusion",
  speed: 1.0,
  event_count: 0,
  queue_size: 0,
  alert_count: 0,
  incident_count: 0,
  current_mitre_tactic: "None",
  current_severity: "Informational",
  latest_event: null,
  latest_alert: null,
  latest_incident: null,
  last_error: null,
  updated_at: new Date().toISOString(),
  supported_scenarios: ["Multi Stage Intrusion", "Ransomware Execution", "Credential Theft"],
  supported_speeds: [0.5, 1.0, 2.0, 5.0]
};

const mockEvents: SecurityEvent[] = [
  { SystemTime: new Date(Date.now() - 10000).toISOString(), Channel: "Security", EventID: 4624, Severity: "Low", Computer: "FIN-SRV-01", Message: "Successful logon for user Administrator" },
  { SystemTime: new Date(Date.now() - 20000).toISOString(), Channel: "System", EventID: 7045, Severity: "Medium", Computer: "FIN-SRV-01", Message: "A service was installed in the system: WmiPrvSE" },
  { SystemTime: new Date(Date.now() - 30000).toISOString(), Channel: "Security", EventID: 4679, Severity: "High", Computer: "FIN-SRV-01", Message: "An attempt was made to access a privilege service" }
];

const mockAlerts: SecurityAlert[] = [
  { AlertID: "ALT-001", RuleName: "Suspicious Service Installation", Severity: "Medium", Timestamp: new Date(Date.now() - 20000).toISOString(), Tactic: "Persistence", Technique: "System Services", Description: "New service WmiPrvSE installed with admin privileges", EventCount: 1 },
  { AlertID: "ALT-002", RuleName: "LSASS Memory Dump", Severity: "High", Timestamp: new Date(Date.now() - 5000).toISOString(), Tactic: "Credential Access", Technique: "OS Credential Dumping", Description: "Access to LSASS process memory from unverified binary", EventCount: 2 }
];

const mockIncidents = [
  {
    Incident: {
      IncidentID: "INC-2026-001",
      IncidentType: "Credential Theft & Lateral Movement",
      Severity: "High",
      State: "New",
      Score: 78,
      DeviceName: "FIN-SRV-01",
      EventsCount: 450,
      AnomaliesCount: 4
    },
    Timeline: [
      { Timestamp: new Date(Date.now() - 60000).toISOString(), Event: "Initial access detected via suspicious RDP logon" },
      { Timestamp: new Date(Date.now() - 30000).toISOString(), Event: "Credential dumping attempted on FIN-SRV-01" }
    ],
    DefenderRecommendation: {
      ActionID: "ISOLATE_DEVICE",
      Target: "FIN-SRV-01",
      DecisionReason: "Host is actively communicating with known malicious C2 and credentials have been dumped.",
      RequiresApproval: true
    }
  }
];

export const ApiService = {
  async getHealth(): Promise<HealthStatus> {
    return safeFetch<HealthStatus>(`${API_BASE_URL}/health`, undefined, mockHealth);
  },

  // Live Ingestion Services
  async getLiveStatus(): Promise<LiveStatus> {
    return safeFetch<LiveStatus>(`${API_BASE_URL}/live/status`, undefined, mockLiveStatus);
  },

  async startLive(scenarioName: string, speed: number, seed?: number): Promise<LiveStatus> {
    return safeFetch<LiveStatus>(`${API_BASE_URL}/live/start`, {
      method: 'POST',
      body: JSON.stringify({ scenario_name: scenarioName, speed, seed }),
    }, {
      ...mockLiveStatus,
      status: "running",
      scenario: scenarioName,
      speed,
    });
  },

  async pauseLive(): Promise<LiveStatus> {
    return safeFetch<LiveStatus>(`${API_BASE_URL}/live/pause`, { method: 'POST' }, { ...mockLiveStatus, status: "paused" });
  },

  async resumeLive(speed?: number): Promise<LiveStatus> {
    return safeFetch<LiveStatus>(`${API_BASE_URL}/live/resume`, {
      method: 'POST',
      body: speed !== undefined ? JSON.stringify({ speed }) : undefined,
    }, { ...mockLiveStatus, status: "running" });
  },

  async resetLive(): Promise<LiveStatus> {
    return safeFetch<LiveStatus>(`${API_BASE_URL}/live/reset`, { method: 'POST' }, mockLiveStatus);
  },

  async getLiveEvents(limit = 200): Promise<SecurityEvent[]> {
    const data = await safeFetch<{ events: any[] }>(`${API_BASE_URL}/live/events?limit=${limit}`, undefined, { events: mockEvents });
    // Normalize live event keys to conform to table view
    return data.events.map(ev => ({
      SystemTime: ev.timestamp || ev.SystemTime || "",
      Channel: ev.source || ev.Channel || "",
      EventID: ev.event_id || ev.EventID || 0,
      Severity: ev.severity || ev.Severity || "Informational",
      Computer: ev.hostname || ev.Computer || "",
      Message: ev.description || ev.Message || ""
    }));
  },

  async getLiveAlerts(limit = 200): Promise<SecurityAlert[]> {
    const data = await safeFetch<{ alerts: SecurityAlert[] }>(`${API_BASE_URL}/live/alerts?limit=${limit}`, undefined, { alerts: mockAlerts });
    return data.alerts;
  },

  async getLiveIncidents(limit = 100): Promise<Incident[]> {
    const data = await safeFetch<{ incidents: any[] }>(`${API_BASE_URL}/live/incidents?limit=${limit}`, undefined, { incidents: mockIncidents });
    return data.incidents.map(inc => normalizeIncident(inc));
  },

  // Historical Incidents Services
  async listIncidents(limit = 50, severity?: string, type?: string): Promise<Incident[]> {
    let url = `${API_BASE_URL}/incidents?limit=${limit}`;
    if (severity) url += `&severity=${severity}`;
    if (type) url += `&incident_type=${type}`;
    const data = await safeFetch<{ Incidents: any[] }>(url, undefined, { Incidents: mockIncidents });
    return data.Incidents.map(inc => normalizeIncident(inc));
  },

  async getIncident(id: string): Promise<Incident> {
    const data = await safeFetch<{ Incident: any }>(`${API_BASE_URL}/incidents/${id}`, undefined, { Incident: mockIncidents[0] });
    return normalizeIncident(data.Incident);
  },

  async analyzeIncident(id: string, mode: 'Deterministic' | 'Hybrid' = 'Hybrid', model?: string): Promise<any> {
    return safeFetch<any>(`${API_BASE_URL}/incidents/${id}/analyze`, {
      method: 'POST',
      body: JSON.stringify({ mode, ollama_model: model }),
    }, {
      IncidentID: id,
      AnalystResult: {
        Summary: "Mock Analyst Report: Identified credential theft via lsass.exe process dump.",
        RootCause: "Execution of suspected Mimikatz payload by compromised user Administrator.",
        Impact: "Potential domain compromise if credentials are used for lateral movement.",
        MitigationStatus: "Action recommended."
      },
      AnalystMetadata: {
        generated_at: new Date().toISOString(),
        AnalystMode: mode === 'Hybrid' ? 'ollama' : 'deterministic',
        ModelName: "gemma3:4b-it-qat",
        UsedFallback: false
      }
    });
  },

  async getLatestAnalysis(id: string): Promise<AnalystAnalysisResponse> {
    return safeFetch<any>(`${API_BASE_URL}/incidents/${id}/analysis`, undefined, {
      IncidentID: id,
      AnalystResult: {
        Summary: "Mock Analyst Report: Identified credential theft via lsass.exe process dump.",
        RootCause: "Execution of suspected Mimikatz payload by compromised user Administrator."
      },
      AnalystMetadata: {
        AnalystMode: "ollama",
        ModelName: "gemma3:4b-it-qat",
        UsedFallback: false
      }
    });
  },

  // Action Recommendation Approvals
  async approveAction(incidentId: string): Promise<any> {
    return safeFetch<any>(`${API_BASE_URL}/actions/${incidentId}/approve`, { method: 'POST' }, {
      IncidentID: incidentId,
      ActionID: "ACT-MOCK",
      Target: "FIN-SRV-01",
      Decision: "approved",
      ExecutionMode: "Automated",
      Message: "Isolation sequence initiated successfully.",
      Timestamp: new Date().toISOString()
    });
  },

  async rejectAction(incidentId: string): Promise<any> {
    return safeFetch<any>(`${API_BASE_URL}/actions/${incidentId}/reject`, { method: 'POST' }, {
      IncidentID: incidentId,
      ActionID: "ACT-MOCK",
      Target: "FIN-SRV-01",
      Decision: "rejected",
      ExecutionMode: "Manual",
      Message: "Action rejected by SOC Analyst.",
      Timestamp: new Date().toISOString()
    });
  }
};
