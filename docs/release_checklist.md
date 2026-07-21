# Release Checklist

## Safety

- [ ] Confirm Defender behavior is simulation-only.
- [ ] Confirm high-impact actions still require human approval.
- [ ] Confirm model output is never executed or rendered as HTML.
- [ ] Confirm strict Analyst validation remains unchanged.
- [ ] Confirm `database/raven_soc.db` was not modified for release.

## Analyst

- [ ] Confirm default Ollama model is `gemma3:4b-it-qat`.
- [ ] Confirm custom Ollama model names remain accepted.
- [ ] Confirm Hybrid fallback diagnostics are collapsed.
- [ ] Confirm raw model output is limited to 5000 characters when displayed.

## Detection Lab

- [ ] Run at least one deterministic synthetic scenario.
- [ ] Run at least one randomized synthetic scenario.
- [ ] Confirm expected-answer reveal matches the scenario metadata.
- [ ] Confirm detection coverage page lists implemented rules and correlations.

## Verification

- [ ] Run `python -m py_compile app.py ai_analyst\agent.py ai_analyst\ollama_client.py`.
- [ ] Run focused Analyst and demo tests.
- [ ] Run the full pytest suite with a unique Windows temp directory.
- [ ] Review `git status --short` before packaging or committing.
