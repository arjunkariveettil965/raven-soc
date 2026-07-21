import { ANALYST_MODES, DIFFICULTIES, NOISE_LEVELS, SCENARIO_MODES } from '../utils/constants';

export default function ScenarioForm({
  scenarios,
  form,
  setForm,
  onSubmit,
  busy,
  error
}) {
  const randomMode = form.scenario_mode === 'random';

  return (
    <section className="panel">
      <div className="panel-title">Scenario lab</div>
      <form className="form-grid" onSubmit={onSubmit}>
        <label>
          Scenario mode
          <select value={form.scenario_mode} onChange={(e) => setForm({ ...form, scenario_mode: e.target.value })}>
            {SCENARIO_MODES.map((mode) => <option key={mode.value} value={mode.value}>{mode.label}</option>)}
          </select>
        </label>
        <label>
          Scenario name
          <select value={form.scenario_name} disabled={randomMode} onChange={(e) => setForm({ ...form, scenario_name: e.target.value })}>
            <option value="">Select a scenario</option>
            {scenarios.map((scenario) => (
              <option key={scenario.ScenarioName} value={scenario.ScenarioName}>
                {scenario.ScenarioName}
              </option>
            ))}
          </select>
        </label>
        <label>
          Difficulty
          <select value={form.difficulty} onChange={(e) => setForm({ ...form, difficulty: e.target.value })}>
            {DIFFICULTIES.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label>
          Noise level
          <select value={form.noise_level} onChange={(e) => setForm({ ...form, noise_level: e.target.value })}>
            {NOISE_LEVELS.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label>
          Seed
          <input type="number" value={form.seed} onChange={(e) => setForm({ ...form, seed: e.target.value })} required />
        </label>
        <label>
          Environment
          <input value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} />
        </label>
        <label>
          Analyst mode
          <select value={form.analyst_mode} onChange={(e) => setForm({ ...form, analyst_mode: e.target.value })}>
            {ANALYST_MODES.map((mode) => <option key={mode.value} value={mode.value}>{mode.label}</option>)}
          </select>
        </label>
        <label>
          Ollama model
          <input value={form.ollama_model} onChange={(e) => setForm({ ...form, ollama_model: e.target.value })} />
        </label>
        <label className="checkbox-row">
          <input type="checkbox" checked={form.reveal_answer} onChange={(e) => setForm({ ...form, reveal_answer: e.target.checked })} />
          Reveal answer
        </label>
        <div className="form-actions">
          <button className="button button-primary" type="submit" disabled={busy}>
            {busy ? 'Running…' : 'Run scenario'}
          </button>
        </div>
      </form>
      {error ? <div className="notice error">{error}</div> : null}
    </section>
  );
}
