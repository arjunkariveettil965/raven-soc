# RAVEN-SOC Architecture

```mermaid
flowchart TD
    R[React / Vite frontend] -->|HTTP JSON| A[FastAPI backend]
    S[Streamlit dashboard] --> C[Core scenario pipeline]
    A --> C
    C --> D[Detection / Correlation / Analyst / Defender]
    D --> E[SQLite API persistence]
    S --> F[Streamlit DB raven_soc.db]
    A --> G[API DB raven_soc_api.db]
```

## Security Contracts

The Analyst boundary accepts flexible local model text only before normalization. The internal Analyst object remains strict and is still checked by the existing validator.

Model-owned fields:

- `Status`
- `ThreatType`
- `Severity`
- `Confidence`
- `Summary`
- `SuspicionReason`
- `Inferences`
- `RecommendedActionID`

Baseline-owned fields:

- `ObservedEvidence`
- `MITRETechniques`
- `EvidenceIDs`
- `Target`

Safety-merged field:

- `RequiresApproval`

The model may increase approval requirements, but it may not remove an approval requirement established by the deterministic baseline.

## Detection and Correlation

Detection rules operate on normalized event fields and emit structured alerts with severity, confidence, MITRE mapping, evidence, and recommended action metadata. Correlation patterns merge related alerts into incidents while preserving the deterministic evidence identifiers and target selected by the pipeline.

Implemented correlation patterns include multi-stage intrusion, password spray, malware download and execution, and command-and-control beaconing.

## Fallback Behavior

Hybrid Analyst mode fails closed. If Ollama is unavailable, the model returns malformed output, a field cannot be normalized, or the strict validator rejects the result, RAVEN-SOC uses the deterministic baseline and records fallback metadata for diagnostics.

## State and Storage

The Streamlit dashboard stores interaction state in `st.session_state`. Live ingestion uses checkpoints so monitoring can resume from the intended Windows Event Log position. The Streamlit SQLite database stores ingested events for dashboard exploration.

The FastAPI backend uses a separate SQLite database, `database/raven_soc_api.db`, for API-created scenario runs, incidents, Analyst results, and simulated action decisions. The databases are separate in Phase 9B so backend persistence can evolve without migrating or mutating the existing Streamlit runtime event store.

The React/Vite frontend talks to FastAPI over JSON only. It does not access either database directly.

## Defender Boundary

Defender recommendations are policy decisions, not real actions. Approval and rejection produce simulation-only audit records. The application never executes model output and never modifies endpoints, accounts, firewall rules, or processes.
