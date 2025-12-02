const API_BASE = '/api';

let csrfToken = null;

export async function fetchCsrfToken() {
  const response = await fetch(`${API_BASE}/csrf-token`, { credentials: 'include' });
  const data = await response.json();
  csrfToken = data.csrfToken;
  return csrfToken;
}

export function getCsrfToken() { return csrfToken; }
export function setCsrfToken(token) { csrfToken = token; }

function needsCsrf(method) {
  return ['POST', 'PUT', 'DELETE'].includes(method);
}

async function ensureCsrfToken() {
  if (!csrfToken) {
    await fetchCsrfToken();
  }
}

function updateTokenFromResponse(data) {
  if (data?.csrfToken) {
    csrfToken = data.csrfToken;
  }
}

function isCsrfError(status, data) {
  return status === 403 && (data?.message?.includes('CSRF') || data?.error?.includes('CSRF'));
}

async function executeWithRetry(url, options, headers) {
  await fetchCsrfToken();
  if (!csrfToken) {
    return null;
  }
  
  const retryHeaders = { ...headers, 'X-CSRF-Token': csrfToken };
  const retryResponse = await fetch(url, { ...options, headers: retryHeaders, credentials: 'include' });
  const retryData = await retryResponse.json();
  updateTokenFromResponse(retryData);
  
  return retryResponse.ok ? retryData : null;
}

async function executeWithAuthRetry(url, options, headers) {
  try {
    const statusResp = await fetch(`${API_BASE}/auth/status`, { credentials: 'include' });
    const statusData = await statusResp.json().catch(() => null);
    if (statusData && statusData.csrfToken) {
      csrfToken = statusData.csrfToken;
    }
    const retryHeaders = { ...headers, 'X-CSRF-Token': csrfToken };
    const retryResponse = await fetch(url, { ...options, headers: retryHeaders, credentials: 'include' });
    const retryData = await retryResponse.json().catch(() => null);
    if (retryData) updateTokenFromResponse(retryData);
    return retryResponse.ok ? retryData : null;
  } catch {
    return null;
  }
}

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  
  if (needsCsrf(options.method)) {
    await ensureCsrfToken();
  }

  const headers = { 'Content-Type': 'application/json', ...options.headers };
  
  if (needsCsrf(options.method) && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(url, { ...options, headers, credentials: 'include' });
  const data = await response.json();
  
  updateTokenFromResponse(data);
  
  if (!response.ok) {
    if (isCsrfError(response.status, data) && needsCsrf(options.method)) {
      const retryData = await executeWithRetry(url, options, headers);
      if (retryData) {
        return retryData;
      }
    }
    if (response.status === 401) {
      const retryData = await executeWithAuthRetry(url, options, headers);
      if (retryData) return retryData;
    }
    throw new ApiError(data.message || data.error || 'Request failed', response.status, data);
  }
  return data;
}

export class ApiError extends Error {
  constructor(message, status, data) { super(message); this.name = 'ApiError'; this.status = status; this.data = data; }
}

export const authApi = {
  async getStatus() { return apiRequest('/auth/status'); },
  async register(password) { return apiRequest('/auth/register', { method: 'POST', body: JSON.stringify({ password }) }); },
  async login(password) { return apiRequest('/auth/login', { method: 'POST', body: JSON.stringify({ password }) }); },
  async logout() { return apiRequest('/auth/logout', { method: 'POST' }); },
  async check() { return apiRequest('/auth/check'); },
};

export const vaultApi = {
  async list() { return apiRequest('/vault/list'); },
  async get(id) { return apiRequest(`/vault/${id}`); },
  async add(credential) { return apiRequest('/vault/add', { method: 'POST', body: JSON.stringify(credential) }); },
  async update(id, updates) { return apiRequest(`/vault/${id}`, { method: 'PUT', body: JSON.stringify(updates) }); },
  async delete(id) { return apiRequest(`/vault/${id}`, { method: 'DELETE' }); },
  async search(query) { return apiRequest(`/vault/search?q=${encodeURIComponent(query)}`); },
  async getCategories() { return apiRequest('/vault/categories'); },
  async generatePassword(options = {}) { return apiRequest('/vault/generate-password', { method: 'POST', body: JSON.stringify(options) }); },
};

