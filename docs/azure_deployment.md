# 🛡️ RAVEN-SOC
### AI-Powered Security Operations Center | Real-Time Threat Detection | Azure Deployment Ready

RAVEN-SOC is an AI-assisted Security Operations Center (SOC) platform that simulates enterprise-grade threat detection, incident investigation, and automated security operations.

The platform combines deterministic detection logic with a local Small Language Model (SLM) running through Ollama to provide intelligent incident analysis while maintaining strict security boundaries. Every AI response is validated before being passed to the deterministic response engine, ensuring explainable and predictable security decisions.

> **Status:** Azure Deployment Ready ✅

---

# 📌 Key Highlights

- 🛡️ Real-time Windows Event Log monitoring
- ⚡ FastAPI REST backend
- 💻 React + TypeScript frontend
- 🤖 AI SOC Analyst powered by Ollama
- 🎯 MITRE ATT&CK mapping
- 🔍 Alert correlation engine
- 🚨 Multi-stage incident investigation
- 🖥️ Live Monitoring dashboard
- 🔒 Simulation-only Defender Response Center
- ☁️ Azure App Service & Azure Static Web Apps ready

---

# 📷 Screenshots

## Dashboard

> *(Add screenshot here)*

![Dashboard](docs/images/dashboard.png)

---

## Live Monitoring

> *(Add screenshot here)*

![Live Monitoring](docs/images/live-monitoring.png)

---

## Incident Investigation

> *(Add screenshot here)*

![Incident Investigation](docs/images/incident-investigation.png)

---

## AI SOC Analyst

> *(Add screenshot here)*

![AI Analyst](docs/images/ai-analyst.png)

---

# 🏗 Architecture

```
                 Windows Event Logs
                         │
                         ▼
              Event Normalization Engine
                         │
                         ▼
               Detection Rule Engine
                         │
                         ▼
             Alert Correlation Engine
                         │
                         ▼
                Incident Generation
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
 AI SOC Analyst (Ollama)      Deterministic Baseline
          │                             │
          └──────────────┬──────────────┘
                         ▼
            Validated Incident Analysis
                         │
                         ▼
       Defender Recommendation Simulator
                         │
                         ▼
      React Investigation & Live Monitoring UI
```

---

# 🚀 Features

## Threat Detection

- Windows Event Log ingestion
- CSV log ingestion
- Event normalization
- Rule-based detection engine
- MITRE ATT&CK mapping
- Detection scoring

---

## Incident Correlation

- Multi-alert correlation
- Incident risk scoring
- Timeline generation
- Evidence aggregation
- Alert grouping

---

## AI SOC Analyst

Supports two operating modes:

### Deterministic Mode

- Rule-based analysis
- No AI dependency
- Fully reproducible output

### Hybrid Mode

Uses:

- Ollama
- Gemma3 4B IT QAT

The model enriches:

- Executive Summary
- Threat Classification
- Confidence
- Inferences
- Recommended Actions

If AI fails, RAVEN-SOC automatically falls back to deterministic analysis.

---

## Defender Response Center

Simulation only.

Supported actions include:

- Device Isolation
- User Disable
- Block Hash
- Network Containment

Every high-impact action requires analyst approval.

No real endpoint modifications are ever performed.

---

## Live Monitoring Engine

Phase 10B introduces an isolated synthetic live monitoring engine.

Features include:

- Continuous event generation
- Real-time detection
- Alert correlation
- Incident generation
- MITRE mapping
- AI analysis
- Defender recommendations

Supported scenarios:

- Multi-Stage Intrusion
- Credential Attack
- Insider Threat
- Ransomware

Playback speeds:

- 0.5x
- 1x
- 2x
- 5x
- 10x

---

# 🛠 Tech Stack

## Backend

- Python
- FastAPI
- Streamlit
- SQLite
- Pydantic

---

## Frontend

- React
- TypeScript
- Vite
- CSS

---

## AI

- Ollama
- Gemma3 4B IT QAT

---

## Security

- Windows Event Logs
- MITRE ATT&CK Framework
- Rule-based Detection
- Incident Correlation

---

## Deployment

- Azure App Service
- Azure Static Web Apps

---

# 📂 Project Structure

```
RAVEN-SOC
│
├── backend/
│   ├── api/
│   ├── services/
│   ├── repositories/
│   └── schemas/
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── staticwebapp.config.json
│
├── database/
│
├── docs/
│
├── tests/
│
├── startup.sh
├── requirements.txt
└── README.md
```

---

# ⚙️ Quick Start

Clone the repository

```bash
git clone https://github.com/yourusername/raven-soc.git
cd raven-soc
```

Install dependencies

```powershell
python -m pip install -r requirements.txt
```

Download AI model

```powershell
ollama pull gemma3:4b-it-qat
```

Run Streamlit

```powershell
python -m streamlit run app.py
```

Run FastAPI

```powershell
python -m uvicorn backend.main:app --reload
```

Run Frontend

```powershell
cd frontend
npm install
npm run dev
```

---

# 🌐 API

Swagger

```
http://localhost:8000/docs
```

Health

```
GET /api/v1/health
```

Runs

```
GET /api/v1/runs
```

Incident Analysis

```
GET /api/v1/incidents/{incident_id}/analysis
```

Defender Actions

```
GET /api/v1/actions/{incident_id}
```

---

# ⚙ Environment Variables

Example:

```env
RAVEN_API_DB_PATH=database/raven_soc_api.db
RAVEN_API_ALLOWED_ORIGINS=http://localhost:5173
RAVEN_API_ENV=development

RAVEN_OLLAMA_URL=http://localhost:11434
RAVEN_OLLAMA_MODEL=gemma3:4b-it-qat

VITE_API_URL=https://your-api.azurewebsites.net/api/v1
```

---

# ☁ Azure Deployment

Frontend

- Azure Static Web Apps

Backend

- Azure App Service

Configuration:

- startup.sh
- staticwebapp.config.json
- .env.example

See:

```
docs/azure_deployment.md
```

---

# 🧪 Testing

Run all tests

```powershell
python -m pytest -q
```

Current Status

```
215 Tests Passed
```

Frontend

```powershell
npm run build
```

Current Status

```
Production Build Successful
```

---

# 🔒 Safety

RAVEN-SOC **never performs real containment actions**.

The platform does **NOT**

- Isolate endpoints
- Disable user accounts
- Kill processes
- Modify firewalls
- Block network traffic

All Defender actions are simulated for educational and demonstration purposes.

---

# 📚 Documentation

- Architecture
- Azure Deployment Guide
- Demo Script
- Release Checklist
- Synthetic Lab Documentation

Located in:

```
docs/
```

---

# 🎥 Demo

*(Add YouTube demo link here)*

---

# 🗺 Roadmap

- Azure deployment
- Authentication
- Role-based access control
- Microsoft Sentinel integration
- Microsoft Defender integration
- Live Event Hub ingestion
- Threat intelligence feeds
- Multi-user SOC

---

# 👨‍💻 Author

**Arjun K**

Cyber Security | Microsoft Security | SOC Engineering | Azure Security

GitHub:

https://github.com/arjunkariveettil1965

---

# 📄 License

MIT License