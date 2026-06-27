export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type ScanType = "full" | "headers" | "tls" | "cookies" | "cors" | "fingerprint" | "subdomains" | "owasp" | "port_scan";
export type UserRole = "admin" | "analyst" | "viewer";
export type TargetType = "url" | "domain" | "subdomain" | "ip";
export type TargetCriticality = "low" | "medium" | "high" | "critical";

export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  ethics_accepted: boolean;
  created_at: string;
}

export interface Target {
  id: string;
  name: string;
  value: string;
  type: TargetType;
  criticality: TargetCriticality;
  description: string | null;
  tags: string | null;
  organization: string | null;
  authorization_confirmed: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  module: string;
  cvss_score: number | null;
  cve: string | null;
  owasp_category: string | null;
  affected_url: string | null;
  evidence: Record<string, unknown> | null;
  recommendation: string | null;
  references: string[] | null;
  is_false_positive: boolean;
  created_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  owner_id: string;
  status: ScanStatus;
  scan_type: ScanType;
  modules: string[] | null;
  risk_score: number | null;
  findings_count: number;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  vulnerabilities?: Vulnerability[];
}

export interface ScanStats {
  total_scans: number;
  scans_by_status: Record<string, number>;
  vulnerabilities_by_severity: Record<string, number>;
  average_risk_score: number;
  recent_scans: Scan[];
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

export const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "Critical", color: "text-red-400", bg: "bg-red-400/10", border: "border-red-400/30" },
  high: { label: "High", color: "text-orange-400", bg: "bg-orange-400/10", border: "border-orange-400/30" },
  medium: { label: "Medium", color: "text-yellow-400", bg: "bg-yellow-400/10", border: "border-yellow-400/30" },
  low: { label: "Low", color: "text-blue-400", bg: "bg-blue-400/10", border: "border-blue-400/30" },
  informational: { label: "Info", color: "text-gray-400", bg: "bg-gray-400/10", border: "border-gray-400/30" },
};
