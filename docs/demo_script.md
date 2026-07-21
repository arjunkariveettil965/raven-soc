# RAVEN-SOC Demo Script

## 5 to 7 Minute Flow

1. Open the dashboard:

   ```powershell
   python -m streamlit run app.py
   ```

2. Confirm Presentation Mode is enabled. Point out the simulation-only banner and the default local model `gemma3:4b-it-qat`.

3. In the synthetic incident lab, choose a scenario or random scenario, set a seed, and run the pipeline.

4. Walk through the pipeline status: events generated, alerts detected, incidents correlated, Analyst completed, and Defender recommendation produced.

5. Show the incident summary, attack chain, MITRE techniques, and deterministic correlation explanation.

6. Review the Analyst result. In Hybrid mode, explain that the local model owns only classification and reasoning fields, while evidence IDs and targets come from the deterministic baseline.

7. Move to Defender Action Center. Approve or reject the simulated action and call out that no endpoint, account, network rule, or process is modified.

## Recovery Path

If Ollama is unavailable or the local model output fails validation, keep going. The dashboard reports Hybrid fallback and uses the deterministic baseline. Open the collapsed diagnostics only if you need to explain why fallback occurred.

## Presenter Notes

- Do not paste real secrets, credentials, or customer event logs into the demo.
- Do not describe Defender actions as real containment.
- Use the Detection Coverage section to show what is implemented.
- Use the scenario answer reveal only after the audience has seen the pipeline result.
