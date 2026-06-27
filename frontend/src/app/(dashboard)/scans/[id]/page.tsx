"use client";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowLeft, RefreshCw, Shield, Clock } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { scansApi } from "@/lib/api";
import { VulnerabilityRow } from "@/components/scans/vulnerability-row";
import { SeverityChart } from "@/components/dashboard/severity-chart";
import { cn, scanStatusColor, riskScoreColor, riskScoreLabel, formatDate, timeAgo } from "@/lib/utils";
import type { Severity } from "@/types";
import toast from "react-hot-toast";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();

  const { data: scan, isLoading, refetch } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => scansApi.get(id).then((r) => r.data),
    refetchInterval: (q) =>
      q.state.data?.status === "running" || q.state.data?.status === "pending" ? 4_000 : false,
  });

  const fpMutation = useMutation({
    mutationFn: (vulnId: string) => scansApi.markFalsePositive(id, vulnId),
    onSuccess: () => {
      toast.success("Updated");
      qc.invalidateQueries({ queryKey: ["scan", id] });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4 max-w-5xl mx-auto">
        <div className="h-8 w-48 glass rounded animate-pulse" />
        <div className="h-40 glass rounded-xl animate-pulse" />
        <div className="h-64 glass rounded-xl animate-pulse" />
      </div>
    );
  }

  if (!scan) return <div className="text-muted-foreground p-8">Scan not found.</div>;

  const vulnsBySeverity = SEVERITY_ORDER.reduce<Record<string, number>>((acc, sev) => {
    acc[sev] = scan.vulnerabilities?.filter((v) => v.severity === sev && !v.is_false_positive).length ?? 0;
    return acc;
  }, {});

  const sortedVulns = [...(scan.vulnerabilities ?? [])].sort((a, b) => {
    const si = SEVERITY_ORDER.indexOf(a.severity as Severity);
    const ti = SEVERITY_ORDER.indexOf(b.severity as Severity);
    return si - ti;
  });

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href="/scans" className="text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="font-mono text-xl font-bold text-foreground">
              SCAN #{scan.id.slice(0, 8).toUpperCase()}
            </h1>
            <span className={cn(
              "text-xs font-bold uppercase px-2.5 py-1 rounded border",
              scanStatusColor(scan.status)
            )}>
              {scan.status}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1 flex items-center gap-2">
            <Clock className="w-3 h-3" />
            Started {timeAgo(scan.created_at)}
            {scan.completed_at && ` · Completed ${formatDate(scan.completed_at)}`}
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="p-2 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Running indicator */}
      {(scan.status === "running" || scan.status === "pending") && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center gap-3 p-4 rounded-xl border border-blue-400/30 bg-blue-400/5"
        >
          <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
          <p className="text-sm text-blue-400">
            Scan in progress — results will appear automatically as modules complete.
          </p>
        </motion.div>
      )}

      {/* Risk score + summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-5 flex flex-col items-center justify-center">
          <Shield className={cn("w-8 h-8 mb-2", scan.risk_score != null ? riskScoreColor(scan.risk_score) : "text-gray-400")} />
          <div className={cn("text-4xl font-bold tabular-nums", scan.risk_score != null ? riskScoreColor(scan.risk_score) : "text-gray-400")}>
            {scan.risk_score?.toFixed(0) ?? "—"}
          </div>
          <div className="text-xs text-muted-foreground mt-1">
            {scan.risk_score != null ? riskScoreLabel(scan.risk_score) : "Risk Score"}
          </div>
        </div>

        <div className="md:col-span-2 glass rounded-xl p-5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
            Findings by Severity
          </h3>
          <div className="grid grid-cols-5 gap-2">
            {SEVERITY_ORDER.map((sev) => {
              const count = vulnsBySeverity[sev] ?? 0;
              const colors = {
                critical: "text-red-400 bg-red-400/10 border-red-400/30",
                high: "text-orange-400 bg-orange-400/10 border-orange-400/30",
                medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
                low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
                informational: "text-gray-400 bg-gray-400/10 border-gray-400/30",
              };
              return (
                <div key={sev} className={cn("flex flex-col items-center p-2 rounded-lg border", colors[sev])}>
                  <span className="text-2xl font-bold tabular-nums">{count}</span>
                  <span className="text-[10px] uppercase font-medium mt-0.5 capitalize">{sev.slice(0, 4)}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Error */}
      {scan.error_message && (
        <div className="p-4 rounded-xl border border-red-400/30 bg-red-400/5 text-sm text-red-400">
          <strong>Error:</strong> {scan.error_message}
        </div>
      )}

      {/* Vulnerabilities */}
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
          Findings ({sortedVulns.length})
        </h2>
        {sortedVulns.length === 0 ? (
          <div className="glass rounded-xl p-12 flex flex-col items-center text-muted-foreground gap-3">
            <Shield className="w-10 h-10 opacity-30" />
            <p className="text-sm">
              {scan.status === "completed" ? "No findings detected." : "Scan in progress..."}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {sortedVulns.map((v, i) => (
              <VulnerabilityRow
                key={v.id}
                vuln={v}
                index={i}
                onMarkFP={fpMutation.mutate}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
