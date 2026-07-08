"use client";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield, Scan as ScanIcon, AlertTriangle, TrendingUp, Activity,
  Clock, Globe, Server, Plus, ChevronRight,
} from "lucide-react";
import { StatsCard } from "@/components/dashboard/stats-card";
import { SeverityChart } from "@/components/dashboard/severity-chart";
import { scansApi, targetsApi } from "@/lib/api";
import { cn, scanStatusColor, riskScoreColor, riskScoreLabel, timeAgo } from "@/lib/utils";
import type { Scan, Target } from "@/types";
import Link from "next/link";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"] as const;
const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-400/10 border-red-400/30",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/30",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  informational: "text-gray-400 bg-gray-400/10 border-gray-400/30",
};
const CRITICALITY_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-400/30",
  high: "text-orange-400 border-orange-400/30",
  medium: "text-yellow-400 border-yellow-400/30",
  low: "text-blue-400 border-blue-400/30",
};

function TargetCard({ target, scans, index }: { target: Target; scans: Scan[]; index: number }) {
  const sorted = [...scans].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );
  const latest = sorted[0];
  const completed = sorted.filter((s) => s.status === "completed");
  const latestCompleted = completed[0];

  const countsBySev = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = 0;
    return acc;
  }, {});

  // Aggregate findings from all completed scans for this target
  // We use findings_count as proxy — no detail without loading each scan
  const totalFindings = completed.reduce((sum, s) => sum + (s.findings_count || 0), 0);
  const isRunning = latest?.status === "running" || latest?.status === "pending";

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.07 }}
      className="glass rounded-2xl p-5 flex flex-col gap-4"
    >
      {/* Target header */}
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          {target.type === "ip" ? <Server className="w-4 h-4 text-primary" /> : <Globe className="w-4 h-4 text-primary" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-foreground text-sm truncate">{target.name}</span>
            <span className={cn("text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border", CRITICALITY_COLORS[target.criticality])}>
              {target.criticality}
            </span>
          </div>
          <p className="text-xs text-muted-foreground font-mono truncate mt-0.5">{target.value}</p>
        </div>
        <Link
          href={`/scans/new?target=${target.id}`}
          className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium bg-primary/10 border border-primary/20 text-primary rounded-lg hover:bg-primary/20 transition-colors flex-shrink-0"
        >
          <Plus className="w-3 h-3" />
          Scan
        </Link>
      </div>

      {/* Latest scan summary */}
      {!latest ? (
        <div className="flex items-center gap-2 p-3 rounded-lg border border-dashed border-border text-muted-foreground">
          <ScanIcon className="w-4 h-4 opacity-50" />
          <span className="text-xs">Nenhum scan ainda</span>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Risk score + status */}
          <div className="flex items-center gap-3">
            {isRunning ? (
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                <span className="text-xs text-blue-400 font-medium">Scan em andamento…</span>
              </div>
            ) : latestCompleted ? (
              <>
                <div className={cn("text-3xl font-bold tabular-nums", riskScoreColor(latestCompleted.risk_score ?? 100))}>
                  {latestCompleted.risk_score?.toFixed(0) ?? "—"}
                </div>
                <div>
                  <p className="text-xs font-medium text-foreground">{riskScoreLabel(latestCompleted.risk_score ?? 100)}</p>
                  <p className="text-[10px] text-muted-foreground">Risk Score</p>
                </div>
              </>
            ) : (
              <span className="text-xs text-muted-foreground">
                Último scan: <span className={cn("font-medium", scanStatusColor(latest.status))}>{latest.status}</span>
              </span>
            )}

            <div className="ml-auto text-right">
              <p className="text-xs text-muted-foreground flex items-center gap-1 justify-end">
                <Clock className="w-3 h-3" />
                {timeAgo(latest.created_at)}
              </p>
              <p className="text-[10px] text-muted-foreground">{scans.length} scan{scans.length !== 1 ? "s" : ""} total</p>
            </div>
          </div>

          {/* Last completed scan name/id */}
          {latestCompleted && (
            <Link
              href={`/scans/${latestCompleted.id}`}
              className="flex items-center gap-2 p-2.5 rounded-lg bg-accent/30 hover:bg-accent/50 transition-colors group"
            >
              <Shield className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-foreground group-hover:text-primary transition-colors truncate">
                  {latestCompleted.name || `Scan #${latestCompleted.id.slice(0, 8).toUpperCase()}`}
                </p>
                <p className="text-[10px] text-muted-foreground">{latestCompleted.findings_count} findings</p>
              </div>
              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
            </Link>
          )}
        </div>
      )}

      {/* All scans link */}
      <Link
        href={`/scans?target=${target.id}`}
        className="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 mt-auto"
      >
        Ver todos os scans →
      </Link>
    </motion.div>
  );
}

export default function DashboardPage() {
  const { data: stats, isLoading: loadingStats } = useQuery({
    queryKey: ["scan-stats"],
    queryFn: () => scansApi.stats().then((r) => r.data),
    refetchInterval: 15_000,
  });

  const { data: targets, isLoading: loadingTargets } = useQuery({
    queryKey: ["targets"],
    queryFn: () => targetsApi.list({ limit: 200 }).then((r) => r.data),
  });

  const { data: allScans } = useQuery({
    queryKey: ["scans", ""],
    queryFn: () => scansApi.list({ limit: 200 }).then((r) => r.data),
    refetchInterval: 10_000,
  });

  // Group scans by target_id
  const scansByTarget: Record<string, Scan[]> = {};
  allScans?.forEach((s) => {
    if (!scansByTarget[s.target_id]) scansByTarget[s.target_id] = [];
    scansByTarget[s.target_id].push(s);
  });

  const totalVulns = stats
    ? Object.values(stats.vulnerabilities_by_severity).reduce((a, b) => a + b, 0)
    : 0;
  const criticalCount = stats?.vulnerabilities_by_severity?.critical ?? 0;

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">Postura de segurança por alvo</p>
        </div>
        <Link
          href="/scans/new"
          className="flex items-center gap-2 px-4 py-2 bg-primary/20 border border-primary/30 rounded-lg text-primary text-sm font-medium hover:bg-primary/30 transition-colors"
        >
          <ScanIcon className="w-4 h-4" />
          Novo Scan
        </Link>
      </div>

      {/* Global stats */}
      {loadingStats ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-32 rounded-xl glass animate-pulse" />)}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <StatsCard title="Total Scans" value={stats?.total_scans ?? 0}
            subtitle={`${stats?.scans_by_status?.completed ?? 0} concluídos`}
            icon={ScanIcon} color="blue" index={0} />
          <StatsCard title="Vulnerabilidades" value={totalVulns}
            subtitle={`${criticalCount} críticas`}
            icon={AlertTriangle} color={criticalCount > 0 ? "red" : "green"} index={1} />
          <StatsCard title="Risk Score Médio" value={`${stats?.average_risk_score ?? 0}`}
            subtitle={riskScoreLabel(stats?.average_risk_score ?? 100)}
            icon={TrendingUp} color={stats?.average_risk_score && stats.average_risk_score < 60 ? "orange" : "green"} index={2} />
          <StatsCard title="Scans Ativos" value={(stats?.scans_by_status?.running ?? 0) + (stats?.scans_by_status?.pending ?? 0)}
            subtitle="Em andamento" icon={Activity} color="yellow" index={3} />
        </div>
      )}

      {/* Per-target view */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Alvos ({targets?.length ?? 0})
          </h2>
          <Link href="/targets" className="text-xs text-primary hover:underline">Gerenciar alvos →</Link>
        </div>

        {loadingTargets ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {[...Array(3)].map((_, i) => <div key={i} className="h-48 rounded-2xl glass animate-pulse" />)}
          </div>
        ) : !targets?.length ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground gap-4 glass rounded-2xl">
            <Globe className="w-10 h-10 opacity-30" />
            <p className="text-sm">Nenhum alvo cadastrado ainda.</p>
            <Link href="/targets" className="text-primary hover:underline text-sm">Adicionar primeiro alvo →</Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {targets.map((target, i) => (
              <TargetCard
                key={target.id}
                target={target}
                scans={scansByTarget[target.id] ?? []}
                index={i}
              />
            ))}
          </div>
        )}
      </div>

      {/* Severity distribution */}
      {stats && totalVulns > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="glass rounded-xl p-5 max-w-sm"
        >
          <h2 className="text-sm font-semibold text-foreground mb-4 uppercase tracking-wider">
            Distribuição por Severidade
          </h2>
          <SeverityChart data={stats.vulnerabilities_by_severity} />
        </motion.div>
      )}

      {/* Ethics notice */}
      <div className="flex items-start gap-3 p-4 rounded-xl border border-orange-400/20 bg-orange-400/5 text-xs text-orange-300/70">
        <Shield className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />
        <p>
          <span className="font-semibold text-orange-400">Lembrete de Uso Autorizado: </span>
          Todos os scans devem ser realizados em sistemas de sua propriedade ou com autorização
          explícita por escrito. Todas as ações são registradas para fins de auditoria.
        </p>
      </div>
    </div>
  );
}
