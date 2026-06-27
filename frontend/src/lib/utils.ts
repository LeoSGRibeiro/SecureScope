import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { formatDistanceToNow, format } from "date-fns";
import type { Severity } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | null | undefined): string {
  if (!date) return "—";
  return format(new Date(date), "dd MMM yyyy HH:mm");
}

export function timeAgo(date: string | null | undefined): string {
  if (!date) return "—";
  return formatDistanceToNow(new Date(date), { addSuffix: true });
}

export function severityColor(sev: Severity | string): string {
  const map: Record<string, string> = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-yellow-400",
    low: "text-blue-400",
    informational: "text-gray-400",
  };
  return map[sev] || "text-gray-400";
}

export function severityBg(sev: Severity | string): string {
  const map: Record<string, string> = {
    critical: "bg-red-400/10 border-red-400/30",
    high: "bg-orange-400/10 border-orange-400/30",
    medium: "bg-yellow-400/10 border-yellow-400/30",
    low: "bg-blue-400/10 border-blue-400/30",
    informational: "bg-gray-400/10 border-gray-400/30",
  };
  return map[sev] || "bg-gray-400/10 border-gray-400/30";
}

export function riskScoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

export function riskScoreLabel(score: number): string {
  if (score >= 80) return "Low Risk";
  if (score >= 60) return "Medium Risk";
  if (score >= 40) return "High Risk";
  return "Critical Risk";
}

export function scanStatusColor(status: string): string {
  const map: Record<string, string> = {
    completed: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30",
    running: "text-blue-400 bg-blue-400/10 border-blue-400/30",
    pending: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
    failed: "text-red-400 bg-red-400/10 border-red-400/30",
    cancelled: "text-gray-400 bg-gray-400/10 border-gray-400/30",
  };
  return map[status] || "text-gray-400";
}
