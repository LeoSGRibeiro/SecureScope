"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, RefreshCw, ChevronRight, Clock, AlertCircle, Trash2, Globe } from "lucide-react";
import Link from "next/link";
import { scansApi, targetsApi } from "@/lib/api";
import { cn, scanStatusColor, riskScoreColor, timeAgo } from "@/lib/utils";
import type { ScanStatus, Target } from "@/types";
import toast from "react-hot-toast";

const STATUS_FILTERS: { label: string; value: ScanStatus | "" }[] = [
  { label: "Todos", value: "" },
  { label: "Concluído", value: "completed" },
  { label: "Rodando", value: "running" },
  { label: "Pendente", value: "pending" },
  { label: "Falhou", value: "failed" },
];

export default function ScansPage() {
  const [statusFilter, setStatusFilter] = useState<ScanStatus | "">("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const qc = useQueryClient();

  const { data: scans, isLoading, refetch } = useQuery({
    queryKey: ["scans", statusFilter],
    queryFn: () => scansApi.list({ status: statusFilter || undefined, limit: 200 }).then((r) => r.data),
    refetchInterval: 8_000,
  });

  const { data: targets } = useQuery({
    queryKey: ["targets"],
    queryFn: () => targetsApi.list({ limit: 200 }).then((r) => r.data),
  });

  const targetMap: Record<string, Target> = {};
  targets?.forEach((t) => { targetMap[t.id] = t; });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => {
      toast.success("Scan removido");
      setConfirmDelete(null);
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scan-stats"] });
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Erro ao remover"),
  });

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Scans</h1>
          <p className="text-sm text-muted-foreground mt-1">{scans?.length ?? 0} scans no total</p>
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
            Novo Scan
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
            <div key={i} className="h-20 rounded-xl glass animate-pulse" />
          ))}
        </div>
      ) : !scans?.length ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-4">
          <AlertCircle className="w-10 h-10 opacity-30" />
          <p className="text-sm">Nenhum scan encontrado.</p>
          <Link href="/scans/new" className="text-primary hover:underline text-sm">Criar primeiro scan</Link>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan, i) => {
            const target = targetMap[scan.target_id];
            return (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.03 }}
                className="glass rounded-xl"
              >
                <div className="flex items-center gap-4 p-4">
                  <Link
                    href={`/scans/${scan.id}`}
                    className="flex items-center gap-4 flex-1 min-w-0 hover:text-primary transition-colors group"
                  >
                    {/* Target icon */}
                    <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                      <Globe className="w-4 h-4 text-primary" />
                    </div>

                    <div className="flex-1 min-w-0">
                      {/* Target name + scan ID + status */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate">
                          {scan.name || target?.name || `Scan #${scan.id.slice(0, 8).toUpperCase()}`}
                        </span>
                        <span className={cn(
                          "text-[10px] font-bold uppercase px-2 py-0.5 rounded border flex-shrink-0",
                          scanStatusColor(scan.status)
                        )}>
                          {scan.status}
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground/60">
                          #{scan.id.slice(0, 8).toUpperCase()}
                        </span>
                      </div>
                      {/* Target URL + time */}
                      <div className="flex items-center gap-3 mt-0.5">
                        {target && (
                          <span className="text-xs text-muted-foreground font-mono truncate max-w-[200px]">
                            {target.value}
                          </span>
                        )}
                        <span className="text-xs text-muted-foreground flex items-center gap-1 flex-shrink-0">
                          <Clock className="w-3 h-3" />
                          {timeAgo(scan.created_at)}
                        </span>
                        <span className="text-xs text-muted-foreground flex-shrink-0">
                          {scan.findings_count} findings
                        </span>
                      </div>
                    </div>

                    {/* Risk score */}
                    <div className="flex items-center gap-3 flex-shrink-0">
                      {scan.risk_score != null && (
                        <div className="text-right">
                          <div className={cn("text-lg font-bold tabular-nums", riskScoreColor(scan.risk_score))}>
                            {scan.risk_score}
                          </div>
                          <div className="text-[10px] text-muted-foreground">risk</div>
                        </div>
                      )}
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    </div>
                  </Link>

                  {/* Delete button */}
                  {confirmDelete === scan.id ? (
                    <div className="flex items-center gap-2 flex-shrink-0 pl-2 border-l border-border">
                      <span className="text-xs text-muted-foreground">Confirmar?</span>
                      <button
                        onClick={() => deleteMutation.mutate(scan.id)}
                        disabled={deleteMutation.isPending}
                        className="px-2 py-1 text-xs font-medium text-red-400 border border-red-400/30 rounded hover:bg-red-400/10 transition-colors disabled:opacity-50"
                      >
                        {deleteMutation.isPending ? "..." : "Sim"}
                      </button>
                      <button
                        onClick={() => setConfirmDelete(null)}
                        className="px-2 py-1 text-xs text-muted-foreground border border-border rounded hover:bg-accent/50 transition-colors"
                      >
                        Não
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirmDelete(scan.id)}
                      className="p-2 text-muted-foreground hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors flex-shrink-0"
                      title="Remover scan"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
