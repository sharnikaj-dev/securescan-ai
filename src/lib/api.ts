import {
  DashboardPayload,
  ScanComparisonPayload,
  ScanJobStatus,
  ScanPreferences,
  ScanSummary,
  ThemeMode,
  UserProfile,
  VulnerabilityFinding,
} from "../types";

let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

export function getAuthToken(): string | null {
  return authToken;
}

async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (authToken) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }
  if (!(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, { ...options, headers });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  try {
    data = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    data = { error: text || `Request failed with status ${res.status}` };
  }

  if (!res.ok) {
    throw new Error(String(data.error || `Request failed (${res.status})`));
  }
  return data as T;
}

export const api = {
  health: () =>
    apiRequest<{ status: string; geminiConfigured: boolean; database: string }>("/api/health"),

  register: (payload: {
    name: string;
    email: string;
    password: string;
    organization?: string;
    role?: string;
  }) =>
    apiRequest<{ token: string; user: UserProfile }>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  login: (payload: { email: string; password: string }) =>
    apiRequest<{ token: string; user: UserProfile }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  logout: () =>
    apiRequest<{ ok: boolean }>("/api/auth/logout", {
      method: "POST",
    }),

  me: () => apiRequest<{ user: UserProfile }>("/api/auth/me"),

  updateProfile: (payload: {
    name?: string;
    organization?: string;
    role?: string;
    themePreference?: ThemeMode;
    scanPreferences?: ScanPreferences;
    currentPassword?: string;
    newPassword?: string;
  }) =>
    apiRequest<{ user: UserProfile }>("/api/profile", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteAccount: () =>
    apiRequest<{ ok: boolean }>("/api/profile", {
      method: "DELETE",
    }),

  getDashboard: () => apiRequest<DashboardPayload>("/api/dashboard"),

  listScans: () => apiRequest<{ scans: ScanSummary[] }>("/api/scans"),

  getScan: (scanId: number) =>
    apiRequest<{ scan: ScanSummary; vulnerabilities: VulnerabilityFinding[] }>(
      `/api/scans/${scanId}`
    ),

  deleteScan: (scanId: number) =>
    apiRequest<{ ok: boolean }>(`/api/scans/${scanId}`, {
      method: "DELETE",
    }),

  compareScans: (idA: number, idB: number) =>
    apiRequest<ScanComparisonPayload>(`/api/scans/compare?a=${idA}&b=${idB}`),

  uploadScan: (formData: FormData) =>
    apiRequest<ScanJobStatus>("/api/scans/upload", {
      method: "POST",
      body: formData,
    }),

  getJobStatus: (jobId: string) => apiRequest<ScanJobStatus>(`/api/scans/jobs/${jobId}`),

  runDemoScan: () =>
    apiRequest<{ scanId: number; isDemo: boolean }>("/api/scans/demo", {
      method: "POST",
    }),

  analyzeVulnerability: (vulnId: number, force = false) =>
    apiRequest<{ vulnerability: VulnerabilityFinding; cached: boolean }>(
      `/api/vulnerabilities/${vulnId}/analyze`,
      {
        method: "POST",
        body: JSON.stringify({ force }),
      }
    ),

  analyzeScanBatch: (scanId: number) =>
    apiRequest<{ analyzedCount: number; errors: string[] }>(`/api/scans/${scanId}/analyze-all`, {
      method: "POST",
    }),
};
