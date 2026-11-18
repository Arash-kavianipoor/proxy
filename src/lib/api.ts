import type {
  DashboardState,
  IpAuditResult,
  ProbeResult,
  ProxyProtocol,
  ProxyToken,
  SystemSettings,
  TransportType,
} from '../types.ts';

const TOKEN_STORAGE_KEY = 'arash_proxy_session_token';

export function getStoredToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota issues
  }
}

async function apiRequest<T>(url: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');
  headers.set('X-Requested-With', 'ArashProxyConsole');
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `خطای سرور (${res.status})`);
  }
  return data as T;
}

export async function login(username: string, password: string): Promise<{ token: string; username: string }> {
  const data = await apiRequest<{ authenticated: boolean; token: string; username: string }>(
    '/api/auth/login',
    {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }
  );
  setStoredToken(data.token);
  return { token: data.token, username: data.username };
}

export async function checkSession(): Promise<{ authenticated: boolean; username?: string }> {
  try {
    return await apiRequest<{ authenticated: boolean; username: string }>('/api/auth/session');
  } catch {
    setStoredToken(null);
    return { authenticated: false };
  }
}

export async function logout(): Promise<void> {
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' });
  } finally {
    setStoredToken(null);
  }
}

export function fetchDashboard(): Promise<DashboardState> {
  return apiRequest<DashboardState>('/api/dashboard');
}

export function createProxyToken(payload: {
  name: string;
  protocol: ProxyProtocol;
  cleanIp: string;
  port: number;
  transport: TransportType;
  fingerprint: 'chrome' | 'firefox' | 'safari' | 'random';
  tlsFragmentEnabled: boolean;
}): Promise<{ token: ProxyToken; dashboard: DashboardState }> {
  return apiRequest('/api/tokens', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function updateProxyToken(
  id: string,
  payload: Partial<Pick<ProxyToken, 'name' | 'cleanIp' | 'port' | 'enabled' | 'tlsFragmentEnabled' | 'ipMaskMode'>>
): Promise<{ token: ProxyToken; dashboard: DashboardState }> {
  return apiRequest(`/api/tokens/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export function rotateProxyToken(id: string): Promise<{ token: ProxyToken; dashboard: DashboardState }> {
  return apiRequest(`/api/tokens/${encodeURIComponent(id)}/rotate`, {
    method: 'POST',
  });
}

export function deleteProxyToken(id: string): Promise<{ dashboard: DashboardState }> {
  return apiRequest(`/api/tokens/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export function updateSystemSettings(
  settings: Partial<SystemSettings>
): Promise<{ dashboard: DashboardState }> {
  return apiRequest('/api/settings', {
    method: 'PUT',
    body: JSON.stringify(settings),
  });
}

export function rotateSubscriptionSecret(): Promise<{ dashboard: DashboardState }> {
  return apiRequest('/api/settings/rotate-sub', {
    method: 'POST',
  });
}

export function fetchWorkerScript(): Promise<{ script: string; dashboard: DashboardState }> {
  return apiRequest('/api/worker-script');
}

export function fetchIncyExport(): Promise<{ filename: string; content: string }> {
  return apiRequest('/api/export/incy');
}

export function fetchV2RayExport(tokenId: string): Promise<{ filename: string; content: string }> {
  return apiRequest(`/api/export/v2ray/${encodeURIComponent(tokenId)}`);
}

export function probeEndpoint(
  target: string,
  port = 443,
  sni?: string
): Promise<{ probe: ProbeResult; dashboard: DashboardState }> {
  return apiRequest('/api/network/probe', {
    method: 'POST',
    body: JSON.stringify({ target, port, sni }),
  });
}

export function probeAllCleanIps(): Promise<{
  results: Array<{ ip: string; probe: ProbeResult }>;
  dashboard: DashboardState;
}> {
  return apiRequest('/api/network/probe-all', {
    method: 'POST',
  });
}

export function runIpAudit(): Promise<IpAuditResult> {
  return apiRequest('/api/network/ip-audit');
}
