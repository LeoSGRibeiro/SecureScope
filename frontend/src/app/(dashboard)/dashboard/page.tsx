"use client";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield, Scan, AlertTriangle, CheckCircle, Target, TrendingUp,
  Activity, Clock
} from "lucide-react";
import { StatsCard } from "@/components/dashboard/stats-card";
import { SeverityChart } from "@/components/dashboard/severity-chart";
import { scansApi } from "@/lib/api";
import { cn, scanStatusColor, riskScoreColor, riskScoreLabel, timeAgo } from "@/lib/utils";
import Link from "next/link";

export default function DashboardPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["scan-stats"],
    queryFn: () => scansApi.stats().then((r) => r.data),
    refetchInterval: 15_000,
  });

  const totalVulns = stats
    ? Object.values(stats.vulnerabilities_by_severity).reduce((a, b) => a + b, 0)
    : 0;
  const criticalCount = stats?.vulnerabilities_by_severity?.critical ?? 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">Real-time view of your security posture</p>
        </div>
        <Link
          href="/scans/new"
          className="flex items-center gap-2 px-4 py-2 bg-primary/20 border border-primary/30 rounded-lg text-primary text-sm font-medium hover:bg-primary/30 transition-colors"
        >
          <Scan className="w-4 h-4" />
          New Scan
        </Link>
      </div>

      {/* Stats grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-32 rounded-xl glass animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <StatsCard
            title="Total Scans"
            value={stats?.total_scans ?? 0}
            subtitle={`${stats?.scans_by_status?.completed ?? 0} completed`}
            icon={Scan}
            color="blue"
            index={0}
          />
          <StatsCard
            title="Vulnerabilities"
            value={totalVulns}
            subtitle={`${criticalCount} critical`}
            icon={AlertTriangle}
            color={criticalCount > 0 ? "red" : "green"}
            index={1}
          />
          <StatsCard
            title="Avg Risk Score"
            value={`${stats?.average_risk_score ?? 0}`}
            subtitle={riskScoreLabel(stats?.average_risk_score ?? 100)}
            icon={TrendingUp}
            color={stats?.average_risk_score && stats.average_risk_score < 60 ? "orange" : "green"}
            index={2}
          />
          <StatsCard
            title="Active Scans"
            value={(stats?.scans_by_status?.running ?? 0) + (stats?.scans_by_status?.pending ?? 0)}
            subtitle="In progress"
            icon={Activity}
            color="yellow"
            index={3}
          />
        </div>
      )}

      {/* Charts + Recent scans */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Severity distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="glass rounded-xl p-5"
        >
          <h2 className="text-sm font-semibold text-foreground mb-4 uppercase tracking-wider">
            Vulnerabilities by Severity
          </h2>
          <SeverityChart data={stats?.vulnerabilities_by_severity ?? {}} />
        </motion.div>

        {/* Recent scans */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
          className="xl:col-span-2 glass rounded-xl p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider">Recent Scans</h2>
            <Link href="/scans" className="text-xs text-primary hover:underline">View all</Link>
          </div>

          {!stats?.recent_scans?.length ? (
            <div className="flex flex-col items-center justify-center h-40 text-muted-foreground gap-3">
              <Scan className="w-8 h-8 opacity-30" />
              <p className="text-sm">No scans yet. <Link href="/scans/new" className="text-primary hover:underline">Start your first scan</Link></p>
            </div>
          ) : (
            <div className="space-y-2">
              {stats.recent_scans.map((scan, i) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.4 + i * 0.05 }}
                >
                  <Link
                    href={`/scans/${scan.id}`}
                    className="flex items-center gap-4 p-3 rounded-lg hover:bg-accent/50 transition-colors group"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate group-hover:text-primary transition-colors">
                        Scan #{scan.id.slice(0, 8)}
                      </p>
                      <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5">
                        <Clock className="w-3 h-3" />
                        {timeAgo(scan.created_at)}
                      </p>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      {scan.risk_score != null && (
                        <span className={cn("text-sm font-bold tabular-nums", riskScoreColor(scan.risk_score))}>
                          {scan.risk_score}
                        </span>
                      )}
                      <span className={cn(
                        "text-[10px] font-semibold uppercase px-2 py-0.5 rounded border",
                        scanStatusColor(scan.status)
                      )}>
                        {scan.status}
                      </span>
                      <span className="text-xs text-muted-foreground">{scan.findings_count} findings</span>
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Ethics notice */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="flex items-start gap-3 p-4 rounded-xl border border-orange-400/20 bg-orange-400/5 text-xs text-orange-300/70"
      >
        <Shield className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />
        <p>
          <span className="font-semibold text-orange-400">Authorized Use Reminder: </span>
          All scans executed on this platform must be against systems you own or have explicit written
          authorization to test. All actions are logged for audit purposes.
        </p>
      </motion.div>
    </div>
  );
}
