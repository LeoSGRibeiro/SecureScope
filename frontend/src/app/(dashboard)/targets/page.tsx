"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Target, Search, Scan, Trash2, Globe, Server } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { targetsApi, scansApi } from "@/lib/api";
import { cn, timeAgo } from "@/lib/utils";
import type { TargetCriticality } from "@/types";
import toast from "react-hot-toast";
import { useRouter } from "next/navigation";

const CRITICALITY_COLORS: Record<TargetCriticality, string> = {
  critical: "text-red-400 bg-red-400/10 border-red-400/30",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/30",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
};

const schema = z.object({
  name: z.string().min(1, "Name required"),
  value: z.string().min(1, "URL/domain required"),
  type: z.enum(["url", "domain", "subdomain", "ip"]),
  criticality: z.enum(["low", "medium", "high", "critical"]),
  description: z.string().optional(),
  organization: z.string().optional(),
  authorization_confirmed: z.boolean().refine((v) => v, "Must confirm authorization"),
});

type FormData = z.infer<typeof schema>;

export default function TargetsPage() {
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const router = useRouter();
  const qc = useQueryClient();

  const { data: targets, isLoading } = useQuery({
    queryKey: ["targets", search],
    queryFn: () => targetsApi.list({ search: search || undefined }).then((r) => r.data),
  });

  const { register, handleSubmit, reset, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { type: "url", criticality: "medium", authorization_confirmed: false },
  });

  const createMutation = useMutation({
    mutationFn: (data: FormData) => targetsApi.create(data),
    onSuccess: () => {
      toast.success("Target added");
      reset();
      setShowForm(false);
      qc.invalidateQueries({ queryKey: ["targets"] });
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to add target"),
  });

  const scanMutation = useMutation({
    mutationFn: (targetId: string) => scansApi.create({ target_id: targetId }),
    onSuccess: (res) => {
      toast.success("Scan started");
      router.push(`/scans/${res.data.id}`);
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to start scan"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => targetsApi.delete(id),
    onSuccess: () => { toast.success("Target removed"); qc.invalidateQueries({ queryKey: ["targets"] }); },
  });

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Targets</h1>
          <p className="text-sm text-muted-foreground mt-1">Manage authorized scan targets</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Target
        </button>
      </div>

      {/* Add target form */}
      <AnimatePresence>
        {showForm && (
          <motion.form
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            onSubmit={handleSubmit((d) => createMutation.mutate(d))}
            className="glass rounded-xl p-6 space-y-4 overflow-hidden"
          >
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">New Target</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">Name</label>
                <input {...register("name")} className="w-full px-3 py-2 bg-input border border-border rounded-lg text-sm focus:ring-2 focus:ring-primary/50 focus:border-primary/50 outline-none transition" placeholder="My website" />
                {errors.name && <p className="text-xs text-red-400 mt-1">{errors.name.message}</p>}
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">URL / Domain</label>
                <input {...register("value")} className="w-full px-3 py-2 bg-input border border-border rounded-lg text-sm focus:ring-2 focus:ring-primary/50 focus:border-primary/50 outline-none transition" placeholder="https://example.com" />
                {errors.value && <p className="text-xs text-red-400 mt-1">{errors.value.message}</p>}
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">Type</label>
                <select {...register("type")} className="w-full px-3 py-2 bg-input border border-border rounded-lg text-sm focus:ring-2 focus:ring-primary/50 focus:border-primary/50 outline-none transition">
                  <option value="url">URL</option>
                  <option value="domain">Domain</option>
                  <option value="subdomain">Subdomain</option>
                  <option value="ip">IP Address</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">Criticality</label>
                <select {...register("criticality")} className="w-full px-3 py-2 bg-input border border-border rounded-lg text-sm focus:ring-2 focus:ring-primary/50 focus:border-primary/50 outline-none transition">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">Description (optional)</label>
                <input {...register("description")} className="w-full px-3 py-2 bg-input border border-border rounded-lg text-sm focus:ring-2 focus:ring-primary/50 focus:border-primary/50 outline-none transition" placeholder="Production web application" />
              </div>
            </div>
            <div className="flex items-start gap-3 p-3 rounded-lg bg-orange-400/5 border border-orange-400/20">
              <input type="checkbox" id="auth_confirm" {...register("authorization_confirmed")} className="mt-0.5 w-4 h-4" />
              <label htmlFor="auth_confirm" className="text-xs text-orange-300/80 cursor-pointer">
                I confirm I have explicit written authorization to perform security testing on this target.
              </label>
            </div>
            {errors.authorization_confirmed && <p className="text-xs text-red-400">{errors.authorization_confirmed.message}</p>}
            <div className="flex gap-3 justify-end">
              <button type="button" onClick={() => setShowForm(false)} className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground border border-border rounded-lg hover:bg-accent/50 transition-colors">
                Cancel
              </button>
              <button type="submit" disabled={createMutation.isPending} className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors">
                {createMutation.isPending ? "Adding..." : "Add Target"}
              </button>
            </div>
          </motion.form>
        )}
      </AnimatePresence>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search targets..."
          className="w-full pl-9 pr-4 py-2.5 bg-input border border-border rounded-lg text-sm focus:ring-2 focus:ring-primary/50 focus:border-primary/50 outline-none transition"
        />
      </div>

      {/* Target list */}
      {isLoading ? (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => <div key={i} className="h-20 glass rounded-xl animate-pulse" />)}
        </div>
      ) : !targets?.length ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-3">
          <Target className="w-10 h-10 opacity-30" />
          <p className="text-sm">No targets yet. Add your first authorized target above.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {targets.map((target, i) => (
            <motion.div
              key={target.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              className="glass rounded-xl p-4 flex items-center gap-4"
            >
              <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                {target.type === "ip" ? <Server className="w-4 h-4 text-primary" /> : <Globe className="w-4 h-4 text-primary" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="font-medium text-sm text-foreground truncate">{target.name}</p>
                  <span className={cn("text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border", CRITICALITY_COLORS[target.criticality])}>
                    {target.criticality}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground font-mono truncate">{target.value}</p>
                <p className="text-xs text-muted-foreground mt-0.5">Added {timeAgo(target.created_at)}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={() => scanMutation.mutate(target.id)}
                  disabled={scanMutation.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-primary/20 border border-primary/30 text-primary rounded-lg hover:bg-primary/30 transition-colors disabled:opacity-50"
                >
                  <Scan className="w-3 h-3" />
                  Scan
                </button>
                <button
                  onClick={() => deleteMutation.mutate(target.id)}
                  className="p-1.5 text-muted-foreground hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
