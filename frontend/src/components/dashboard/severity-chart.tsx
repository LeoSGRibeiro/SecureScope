"use client";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend
} from "recharts";
import type { Severity } from "@/types";

const COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  informational: "#6b7280",
};

const LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

interface Props {
  data: Record<string, number>;
}

export function SeverityChart({ data }: Props) {
  const chartData = Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({ name: LABELS[key] || key, value, key }));

  if (chartData.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">
        No vulnerability data yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={3}
          dataKey="value"
        >
          {chartData.map((entry) => (
            <Cell key={entry.key} fill={COLORS[entry.key] || "#6b7280"} opacity={0.9} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "hsl(222 47% 7%)",
            border: "1px solid hsl(217 33% 15%)",
            borderRadius: "8px",
            color: "hsl(210 40% 92%)",
            fontSize: "12px",
          }}
        />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: "12px", color: "hsl(215 20% 55%)" }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
