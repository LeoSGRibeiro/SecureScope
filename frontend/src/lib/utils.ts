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
    critical: "text-rose-500",
    high: "text-orange-500",
    medium: "text-yellow-400",
    low: "text-green-500",
    informational: "text-slate-400",
  };
  return map[sev] || "text-slate-400";
}

export function severityBg(sev: Severity | string): string {
  const map: Record<string, string> = {
    critical: "bg-rose-500/10 border-rose-500/30",
    high: "bg-orange-500/10 border-orange-500/30",
    medium: "bg-yellow-400/10 border-yellow-400/30",
    low: "bg-green-500/10 border-green-500/30",
    informational: "bg-slate-400/10 border-slate-400/30",
  };
  return map[sev] || "bg-slate-400/10 border-slate-400/30";
}

export function riskScoreColor(score: number): string {
  if (score >= 80) return "text-green-500";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-500";
  return "text-rose-500";
}

export function riskScoreLabel(score: number): string {
  if (score >= 80) return "Low Risk";
  if (score >= 60) return "Medium Risk";
  if (score >= 40) return "High Risk";
  return "Critical Risk";
}

export function scanStatusColor(status: string): string {
  const map: Record<string, string> = {
    completed: "text-green-500 bg-green-500/10 border-green-500/30",
    running: "text-teal-400 bg-teal-400/10 border-teal-400/30",
    pending: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
    failed: "text-rose-500 bg-rose-500/10 border-rose-500/30",
    cancelled: "text-slate-400 bg-slate-400/10 border-slate-400/30",
  };
  return map[status] || "text-slate-400";
}
