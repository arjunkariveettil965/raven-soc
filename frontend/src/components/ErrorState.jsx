export default function ErrorState({ title = 'Something went wrong', message, onRetry }) {
  return (
    <div className="state-panel state-error">
      <div className="state-title">{title}</div>
      <div className="state-copy">{message}</div>
      {onRetry ? (
        <button className="button button-secondary" type="button" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}
