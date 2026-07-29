# Azure Deployment Guide

## Backend

Run the FastAPI service with:

```powershell
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Recommended environment variables:

- `RAVEN_API_DB_PATH`: absolute or relative path for the API SQLite database.
- `RAVEN_API_ALLOWED_ORIGINS`: comma-separated frontend origins.
- `RAVEN_API_ENV`: deployment label such as `production`.
- `RAVEN_API_REPOSITORY`: repository backend, typically `sqlite`.

The API database is separate from the Streamlit demo database by default. Keep that separation in production unless you are intentionally migrating historical demo data.

## Frontend

The frontend is a Vite build and should be deployed as a static site, such as Azure Static Web Apps.

Build locally with:

```powershell
cd frontend
npm run build
```

Set `VITE_API_URL` to the deployed API base URL, for example `https://<your-api-host>/api/v1`.

## Database

- Keep the API SQLite path configurable with `RAVEN_API_DB_PATH`.
- Preserve the separate API database used for scenarios, incidents, analysis, and action decisions.
- Document any migration from local SQLite to a managed production store before cutting over.

## Security

- Restrict CORS to the deployed frontend origin(s).
- Keep secrets and API keys out of the repository and out of the frontend bundle.
- Verify `.gitignore` excludes local databases, logs, and temporary output.

## AI Deployment

Development uses local Ollama with `gemma3:4b-it-qat`.

Production options:

- Keep the deterministic fallback path and disable Ollama at runtime.
- Replace the Ollama integration with a hosted model or Azure AI endpoint behind the same analyst contract.

The application must continue to function when Ollama is unavailable.