"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Plus, RefreshCw, ChevronRight, Clock, AlertCircle } from "lucide-react";
import Link from "next/link";
import { scansApi } from "@/lib/api";
import { cn, scanStatusColor, riskScoreColor, timeAgo } from "@/lib/utils";
import type { ScanStatus } from "@/types";
import toast from "react-hot-toast";

const STATUS_FILTERS: { label: string; value: ScanStatus | "" }[] = [
  { label: "All", value: "" },
  { label: "Completed", value: "completed" },
  { label: "Running", value: "running" },
  { label: "Pending", value: "pending" },
  { label: "Failed", value: "failed" },
];

export default function ScansPage() {
  const [statusFilter, setStatusFilter] = useState<ScanStatus | "">("");
  const qc = useQueryClient();

  const { data: scans, isLoading, refetch } = useQuery({
    queryKey: ["scans", statusFilter],
    queryFn: () => scansApi.list({ status: statusFilter || undefined, limit: 100 }).then((r) => r.data),
    refetchInterval: 8_000,
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => {
      toast.success("Scan cancelled");
      qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Scans</h1>
          <p className="text-sm text-muted-foreground mt-1">{scans?.length ?? 0} total scans</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="p-2 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <Link
            href="/scans/new"
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Scan
          </Link>
        </div>
      </div>

      {/* Status filters */}
      <div className="flex gap-2 flex-wrap">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setStatusFilter(f.value as ScanStatus | "")}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors",
              statusFilter === f.value
                ? "bg-primary/20 border-primary/40 text-primary"
                : "border-border text-muted-foreground hover:text-foreground hover:bg-accent/50"
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Scan list */}
      {isLoading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 rounded-xl glass animate-pulse" />
          ))}
        </div>
      ) : !scans?.length ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-4">
          <AlertCircle className="w-10 h-10 opacity-30" />
          <p className="text-sm">No scans found.</p>
          <Link href="/scans/new" className="text-primary hover:underline text-sm">Create your first scan</Link>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan, i) => (
            <motion.div
              key={scan.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              className="glass rounded-xl"
            >
              <Link
                href={`/scans/${scan.id}`}
                className="flex items-center gap-4 p-4 hover:bg-accent/20 transition-colors group rounded-xl"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-muted-foreground">
                      #{scan.id.slice(0, 8).toUpperCase()}
                    </span>
                    <span className={cn(
                      "text-[10px] font-bold uppercase px-2 py-0.5 rounded border",
                      scanStatusColor(scan.status)
                    )}>
                      {scan.status}
                    </span>
                    {scan.name ? (
                      <span className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate max-w-xs">
                        {scan.name}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground capitalize">{scan.scan_type}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {timeAgo(scan.created_at)}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {scan.findings_count} findings
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-4 flex-shrink-0">
                  {scan.risk_score != null && (
                    <div className="text-right">
                      <div className={cn("text-lg font-bold tabular-nums", riskScoreColor(scan.risk_score))}>
                        {scan.risk_score}
                      </div>
                      <div className="text-[10px] text-muted-foreground">risk score</div>
                    </div>
                  )}
                  {(scan.status === "pending" || scan.status === "running") && (
                    <button
                      onClick={(e) => { e.preventDefault(); cancelMutation.mutate(scan.id); }}
                      className="text-xs text-red-400 hover:text-red-300 border border-red-400/30 px-2 py-1 rounded hover:bg-red-400/10 transition-colors"
                    >
                      Cancel
                    </button>
                  )}
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                </div>
              </Link>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
