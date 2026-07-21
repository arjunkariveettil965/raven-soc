# RAVEN-SOC

RAVEN-SOC is a local, simulation-only security operations lab. It ingests or generates Windows-style security telemetry, normalizes events, applies deterministic detection and correlation rules, sends a strict incident object through the Analyst layer, and produces Defender-style recommendations that are never executed on the host.

The project is designed for demos, learning, and safe experimentation with hybrid local SLM analysis. Security contracts stay strict: flexible model output is normalized into the existing Analyst schema, validated, and then passed to deterministic Defender policy with human approval for high-impact simulated actions.

## Features

- Streamlit SOC dashboard with presentation mode.
- Live local Windows Event Log ingestion with checkpointing.
- CSV log upload and ASIM-inspired normalization.
- Extensible deterministic detection rules.
- Multi-pattern incident correlation.
- Randomized synthetic attack lab with expected-answer reveal.
- Hybrid Analyst mode backed by Ollama, with deterministic fallback.
- Simulation-only Defender action center.
- Detection coverage and architecture documentation.

## Quick Start

```powershell
python -m pip install -r requirements.txt
ollama pull gemma3:4b-it-qat
python -m streamlit run app.py
```

The default local Ollama model is `gemma3:4b-it-qat`. The dashboard model input remains editable, so another local model can be supplied for testing.

## Frontend

Phase 10A adds a local React + Vite frontend for the FastAPI backend. Streamlit remains available and unchanged.

Install and run the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Local URLs:

- Frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8000`

Configure the frontend API base URL with `VITE_API_BASE_URL` in `frontend/.env.local` if needed. The example file is [`frontend/.env.example`](frontend/.env.example).

This frontend is for local development and demonstrations. It does not add authentication and it does not execute real containment actions.

## Backend API

Phase 9B adds a FastAPI layer around the existing modular monolith and shares the same neutral scenario orchestration used by Streamlit. It does not replace Streamlit and is not production-ready yet.

Start the API locally:

```powershell
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Useful endpoints:

- API root: `http://127.0.0.1:8000/`
- Swagger: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- Health: `http://127.0.0.1:8000/api/v1/health`
- Run history: `http://127.0.0.1:8000/api/v1/runs`
- Latest incident analysis: `http://127.0.0.1:8000/api/v1/incidents/{incident_id}/analysis`
- Action decision status: `http://127.0.0.1:8000/api/v1/actions/{incident_id}`

API scenario runs, incidents, analyses, Defender recommendations, and simulated action decisions are persisted in a separate SQLite database. By default this is `database/raven_soc_api.db`, deliberately separate from Streamlit's `database/raven_soc.db`.

Configuration:

- `RAVEN_API_DB_PATH`: override the API SQLite database path.
- `RAVEN_API_ALLOWED_ORIGINS`: comma-separated local frontend origins. Defaults to local React/Next.js/Vite origins on ports `3000` and `5173`.
- `RAVEN_API_ENV`: environment label, default `development`.

CORS is restricted to explicit local-development origins; wildcard origins are not enabled. Authentication is not implemented yet.

To reset the API development database, stop the API process and delete only:

```powershell
Remove-Item database\raven_soc_api.db, database\raven_soc_api.db-* -ErrorAction SilentlyContinue
```

Do not delete `database\raven_soc.db` unless you intend to reset Streamlit-ingested event data.

## Analyst Modes

- `deterministic`: uses the deterministic incident baseline only.
- `hybrid`: gives the local model trusted incident context and asks for model-owned decision fields.
- `local`: attempts local model analysis directly through Ollama.

Hybrid mode preserves strict boundaries:

- Baseline-owned fields: `ObservedEvidence`, `MITRETechniques`, `EvidenceIDs`, `Target`.
- Model-owned fields: `Status`, `ThreatType`, `Severity`, `Confidence`, `Summary`, `SuspicionReason`, `Inferences`, `RecommendedActionID`.
- Safety-merged field: `RequiresApproval`.

If the model output cannot be normalized and validated, RAVEN-SOC falls back to the deterministic baseline and reports the fallback reason in diagnostics.

## Safety

RAVEN-SOC does not perform real endpoint isolation, account disabling, firewall changes, process termination, or network blocking. Defender responses are advisory simulation records only. Do not deploy this project as a production SOC, EDR, SIEM, SOAR, or automated response system without a full security review, integration design, and operational controls.

## Tests

Use a unique temporary directory on Windows to avoid cleanup collisions:

```powershell
$testTemp = Join-Path $env:TEMP "raven-tests-$([guid]::NewGuid())"
python -m pytest -v --basetemp="$testTemp"
```

Focused examples:

```powershell
python -m pytest tests\test_ollama_client.py tests\test_incident_demo.py -v --basetemp="$testTemp"
python -m pytest tests\test_phase6_scenario_lab.py -v --basetemp="$testTemp"
```

## Documentation

- [Architecture](docs/architecture.md)
- [Demo Script](docs/demo_script.md)
- [Release Checklist](docs/release_checklist.md)
- [Synthetic Lab](docs/synthetic_lab.md)

## License

License: not yet specified.
