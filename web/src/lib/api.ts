const API_BASE = "/api";

function getToken(): string | null {
  return localStorage.getItem("reflag_token");
}

export function setToken(token: string) {
  localStorage.setItem("reflag_token", token);
}

export function clearToken() {
  localStorage.removeItem("reflag_token");
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// --- Types ---

export interface Flag {
  id: string;
  key: string;
  name: string;
  description: string;
  type: "boolean" | "string" | "number" | "object";
  enabled: boolean;
  variations: Variation[];
  targeting_rules: TargetingRule[];
  default_rule: DefaultRule | null;
  created_at: string;
  updated_at: string;
}

export interface Variation {
  id: string;
  value: unknown;
  label: string;
}

export interface TargetingRule {
  id: string;
  name: string;
  conditions: Condition[];
  variation_id: string;
}

export interface Condition {
  id: string;
  attribute: string;
  operator: string;
  values: string[];
}

export interface DefaultRule {
  variation_id: string;
  percentage?: Record<string, number>;
}

export interface Environment {
  id: string;
  key: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Segment {
  id: string;
  key: string;
  name: string;
  description: string;
  conditions: Condition[];
  created_at: string;
  updated_at: string;
}

export interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  environment_id: string;
  scopes: string[];
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
  revoked: boolean;
}

export interface AuditEntry {
  id: string;
  actor: string;
  action: string;
  resource: string;
  resource_id: string;
  details: string;
  timestamp: string;
}

// --- API Functions ---

export const api = {
  // Auth
  oidcStart: () =>
    request<{ authorization_url: string; state: string }>("/auth/oidc/start", {
      method: "POST",
    }),

  // Flags
  listFlags: () => request<Flag[]>("/flags"),
  getFlag: (id: string) => request<Flag>(`/flags/${id}`),
  createFlag: (data: Partial<Flag>) =>
    request<Flag>("/flags", { method: "POST", body: JSON.stringify(data) }),
  updateFlag: (id: string, data: Partial<Flag>) =>
    request<Flag>(`/flags/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deleteFlag: (id: string) =>
    request<void>(`/flags/${id}`, { method: "DELETE" }),

  // Environments
  listEnvironments: () => request<Environment[]>("/environments"),
  createEnvironment: (data: Partial<Environment>) =>
    request<Environment>("/environments", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  deleteEnvironment: (id: string) =>
    request<void>(`/environments/${id}`, { method: "DELETE" }),

  // Segments
  listSegments: () => request<Segment[]>("/segments"),
  createSegment: (data: Partial<Segment>) =>
    request<Segment>("/segments", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  deleteSegment: (id: string) =>
    request<void>(`/segments/${id}`, { method: "DELETE" }),

  // API Keys
  listAPIKeys: () => request<APIKey[]>("/api-keys"),
  createAPIKey: (data: { name: string; environment_id: string; scopes: string[] }) =>
    request<{ id: string; name: string; key: string; key_prefix: string }>(
      "/api-keys",
      { method: "POST", body: JSON.stringify(data) }
    ),
  revokeAPIKey: (id: string) =>
    request<void>(`/api-keys/${id}`, { method: "DELETE" }),

  // Audit
  listAudit: (limit = 50, offset = 0) =>
    request<AuditEntry[]>(`/audit?limit=${limit}&offset=${offset}`),
};
