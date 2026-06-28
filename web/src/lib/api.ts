const API_BASE = "/api";

// Token is now stored in an HttpOnly cookie set by the server.
// The frontend no longer touches localStorage for the JWT.
// fetch() automatically sends cookies with credentials: 'include'.

export function clearToken() {
  // The cookie is cleared by the server's /auth/logout endpoint.
  // No client-side cleanup needed.
}

export function setToken(_token: string) {
  // No-op: token is now set as an HttpOnly cookie by the server.
  // Kept for backward compatibility with LoginPage.tsx.
}

export function isAuthenticated(): boolean {
  // R15-M4: Check if we have a role in sessionStorage as a proxy for auth state.
  // The JWT is in an HttpOnly cookie (not readable by JS), so we use the role
  // as a signal that login has occurred. The server still enforces auth on
  // every API request — this is only a client-side UX optimization.
  return sessionStorage.getItem("reflag_role") !== null;
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });
  if (res.status === 401) {
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
  type: "boolean" | "string" | "number" | "object" | "secret";
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

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface OrgMember {
  id: string;
  user_id: string;
  org_id: string;
  role: string;
  created_at: string;
  user_name?: string;
  user_email?: string;
}

export interface Secret {
  id: string;
  key: string;
  name: string;
  description: string;
  value?: string;
  environment_id?: string;
  created_at: string;
  updated_at: string;
}

// --- API Functions ---

export const api = {
  // Auth
  oidcStart: () =>
    request<{ authorization_url: string; state: string }>("/auth/oidc/start", {
      method: "POST",
    }),
  adminLogin: (data: { email: string; password: string }) =>
    request<{ user: User }>("/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
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

  // Secrets
  listSecrets: () => request<Secret[]>("/secrets"),
  getSecret: (id: string) => request<Secret & { value: string }>(`/secrets/${id}`),
  createSecret: (data: { key: string; name: string; description: string; value: string; environment_id: string }) =>
    request<Secret>("/secrets", { method: "POST", body: JSON.stringify(data) }),
  updateSecret: (id: string, data: Partial<Secret> & { value?: string }) =>
    request<Secret>(`/secrets/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deleteSecret: (id: string) =>
    request<void>(`/secrets/${id}`, { method: "DELETE" }),

  // Organizations
  listOrgs: () => request<Organization[]>("/organizations"),
  createOrg: (data: Partial<Organization>) =>
    request<Organization>("/organizations", { method: "POST", body: JSON.stringify(data) }),
  deleteOrg: (id: string) =>
    request<void>(`/organizations/${id}`, { method: "DELETE" }),
  listOrgMembers: (orgId: string) =>
    request<OrgMember[]>(`/organizations/${orgId}/members`),
  addOrgMember: (orgId: string, data: { email: string; role: string }) =>
    request<OrgMember>(`/organizations/${orgId}/members`, { method: "POST", body: JSON.stringify(data) }),
  updateOrgMemberRole: (memberId: string, role: string) =>
    request<{ status: string; role: string }>(`/organizations/members/${memberId}`, { method: "PUT", body: JSON.stringify({ role }) }),
  removeOrgMember: (memberId: string) =>
    request<void>(`/organizations/members/${memberId}`, { method: "DELETE" }),
};
