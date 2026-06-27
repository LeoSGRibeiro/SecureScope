"use client";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  color?: "blue" | "red" | "orange" | "yellow" | "green" | "gray";
  index?: number;
}

const COLOR_MAP = {
  blue:   { icon: "text-blue-400",   bg: "bg-blue-400/10",   border: "border-blue-400/20",   glow: "from-blue-400/5" },
  red:    { icon: "text-red-400",    bg: "bg-red-400/10",    border: "border-red-400/20",    glow: "from-red-400/5" },
  orange: { icon: "text-orange-400", bg: "bg-orange-400/10", border: "border-orange-400/20", glow: "from-orange-400/5" },
  yellow: { icon: "text-yellow-400", bg: "bg-yellow-400/10", border: "border-yellow-400/20", glow: "from-yellow-400/5" },
  green:  { icon: "text-emerald-400",bg: "bg-emerald-400/10",border: "border-emerald-400/20",glow: "from-emerald-400/5" },
  gray:   { icon: "text-gray-400",   bg: "bg-gray-400/10",   border: "border-gray-400/20",   glow: "from-gray-400/5" },
};

export function StatsCard({
  title, value, subtitle, icon: Icon, trend, color = "blue", index = 0
}: StatsCardProps) {
  const c = COLOR_MAP[color];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.07, duration: 0.4 }}
      className={cn(
        "relative overflow-hidden rounded-xl border p-5 glass",
        c.border,
      )}
    >
      <div className={cn("absolute inset-0 bg-gradient-to-br opacity-50", c.glow, "to-transparent")} />

      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="mt-2 text-3xl font-bold text-foreground tabular-nums">{value}</p>
          {subtitle && <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>}
          {trend && (
            <div className={cn(
              "mt-2 inline-flex items-center gap-1 text-xs font-medium px-1.5 py-0.5 rounded",
              trend.value >= 0 ? "text-emerald-400 bg-emerald-400/10" : "text-red-400 bg-red-400/10"
            )}>
              {trend.value >= 0 ? "+" : ""}{trend.value}% {trend.label}
            </div>
          )}
        </div>
        <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0", c.bg)}>
          <Icon className={cn("w-5 h-5", c.icon)} />
        </div>
      </div>
    </motion.div>
  );
}
