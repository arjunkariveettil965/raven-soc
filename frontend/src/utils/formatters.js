export function safeText(value, fallback = 'N/A') {
  if (value === null || value === undefined) return fallback;
  const text = String(value).trim();
  return text || fallback;
}

export function truncateId(value, size = 10) {
  const text = safeText(value, '');
  if (!text) return 'N/A';
  return text.length <= size * 2 ? text : `${text.slice(0, size)}…${text.slice(-size)}`;
}

export function formatDateTime(value) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return safeText(value);
  return date.toLocaleString();
}

export function formatSeverity(value) {
  const text = safeText(value, 'Unknown');
  const normalized = text.toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'low') return 'Low';
  return text;
}

export function formatConfidence(value) {
  if (value === null || value === undefined || value === '') return 'N/A';
  const num = Number(value);
  if (Number.isNaN(num)) return safeText(value);
  return `${Math.round(num)}%`;
}

export function formatBoolean(value) {
  return value ? 'Yes' : 'No';
}

export function labelize(value) {
  return safeText(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/_/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function toRows(object) {
  if (!object || typeof object !== 'object') return [];
  return Object.entries(object).map(([key, value]) => ({ key, value }));
}
