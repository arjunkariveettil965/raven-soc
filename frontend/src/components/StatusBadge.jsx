export default function StatusBadge({ tone = 'neutral', children }) {
  return <span className={`status-badge tone-${tone}`}>{children}</span>;
}
