import "./styles.css";

export function MetricCard({ label, value, description, className = "" }: { label: string; value: React.ReactNode; description?: string; className?: string }) {
  return (
    <div className={`ui-metric ${className}`.trim()}>
      <div className="ui-metric-label">{label}</div>
      <div className="ui-metric-value">{value}</div>
      {description && <div className="ui-metric-desc">{description}</div>}
    </div>
  );
}
