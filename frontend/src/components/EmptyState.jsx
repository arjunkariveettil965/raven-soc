export default function EmptyState({ title, description }) {
  return (
    <div className="state-panel">
      <div className="state-title">{title}</div>
      {description ? <div className="state-copy">{description}</div> : null}
    </div>
  );
}
