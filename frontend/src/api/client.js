const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
const DEFAULT_TIMEOUT_MS = 15000;

function safeMessage(detail, fallback) {
  if (!detail) return fallback;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((item) => safeMessage(item, fallback)).join('; ');
  if (typeof detail === 'object') {
    if (typeof detail.detail === 'string') return detail.detail;
    if (Array.isArray(detail.detail)) return detail.detail.map((item) => safeMessage(item, fallback)).join('; ');
  }
  return fallback;
}

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      return await response.json();
    } catch {
      throw new Error('Backend returned malformed JSON.');
    }
  }
  return { detail: await response.text() };
}

export async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs || DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal
    });
    const payload = await parseResponse(response);
    if (!response.ok) {
      const message = safeMessage(payload, `Request failed with status ${response.status}.`);
      const error = new Error(message);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error.name === 'AbortError') {
      const timeoutError = new Error('Request timed out.');
      timeoutError.status = 0;
      throw timeoutError;
    }
    if (error instanceof TypeError && /fetch/i.test(error.message)) {
      const networkError = new Error('Backend offline or unreachable.');
      networkError.status = 0;
      throw networkError;
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

export function get(path, options = {}) {
  return request(path, { ...options, method: 'GET' });
}

export function post(path, body, options = {}) {
  return request(path, { ...options, method: 'POST', body });
}

export { API_BASE_URL };
