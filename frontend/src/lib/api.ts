import axios from "axios";
import type { TokenResponse, User, Target, Scan, ScanStats, Vulnerability } from "@/types";

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1",
  headers: { "Content-Type": "application/json" },
});

// Attach JWT from localStorage
api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("access_token");
    if (token) config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  (r) => r,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refresh = localStorage.getItem("refresh_token");
      if (refresh) {
        try {
          const { data } = await axios.post(
            `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1"}/auth/refresh`,
            { refresh_token: refresh }
          );
          localStorage.setItem("access_token", data.access_token);
          original.headers.Authorization = `Bearer ${data.access_token}`;
          return api(original);
        } catch {
          localStorage.clear();
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(error);
  }
);

// Auth
export const authApi = {
  register: (data: { email: string; username: string; password: string; full_name?: string }) =>
    api.post<User>("/auth/register", data),
  login: (data: { username: string; password: string; ethics_accepted: boolean }) =>
    api.post<TokenResponse>("/auth/login", data),
  me: () => api.get<User>("/auth/me"),
  acceptEthics: (acknowledgement: string) =>
    api.post("/auth/accept-ethics", { accepted: true, acknowledgement }),
};

// Targets
export const targetsApi = {
  list: (params?: { skip?: number; limit?: number; search?: string }) =>
    api.get<Target[]>("/targets", { params }),
  create: (data: {
    name: string; value: string; type: string; criticality: string;
    description?: string; tags?: string; organization?: string;
    authorization_confirmed: boolean;
  }) => api.post<Target>("/targets", data),
  get: (id: string) => api.get<Target>(`/targets/${id}`),
  update: (id: string, data: Partial<Target>) => api.patch<Target>(`/targets/${id}`, data),
  delete: (id: string) => api.delete(`/targets/${id}`),
};

// Scans
export const scansApi = {
  list: (params?: { skip?: number; limit?: number; status?: string; target_id?: string }) =>
    api.get<Scan[]>("/scans", { params }),
  create: (data: { target_id: string; scan_type?: string; modules?: string[] }) =>
    api.post<Scan>("/scans", data),
  get: (id: string) => api.get<Scan>(`/scans/${id}`),
  stats: () => api.get<ScanStats>("/scans/stats"),
  cancel: (id: string) => api.delete(`/scans/${id}`),
  markFalsePositive: (scanId: string, vulnId: string) =>
    api.patch(`/scans/${scanId}/vulnerabilities/${vulnId}/false-positive`),
};

export default api;
