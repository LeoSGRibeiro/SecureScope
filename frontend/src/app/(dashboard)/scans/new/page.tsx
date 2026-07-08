"use client";
import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowLeft, Scan, Plus, AlertTriangle } from "lucide-react";
import Link from "next/link";
import toast from "react-hot-toast";
import { scansApi, targetsApi } from "@/lib/api";
import { cn } from "@/lib/utils";

const PASSIVE_MODULES = [
  { id: "headers",     label: "HTTP Headers",      desc: "Analisa headers de segurança (CSP, HSTS, X-Frame…)" },
  { id: "tls",         label: "TLS / SSL",          desc: "Versão do protocolo, cipher suites, validade do certificado" },
  { id: "cookies",     label: "Cookies",            desc: "Flags HttpOnly, Secure, SameSite" },
  { id: "cors",        label: "CORS",               desc: "Políticas de Cross-Origin Resource Sharing" },
  { id: "fingerprint", label: "Fingerprint",        desc: "Detecção de tecnologias, versões e CDN" },
  { id: "subdomains",  label: "Subdomínios",        desc: "Enumeração via DNS" },
  { id: "owasp",       label: "OWASP Passivo",      desc: "Verificações passivas do OWASP Top 10" },
  { id: "port_scan",   label: "Port Scan",          desc: "Varredura de portas e serviços expostos" },
];

const INTRUSIVE_MODULES = [
  { id: "sqli_xss",        label: "SQLi / XSS Ativo",   desc: "Injeta payloads reais em parâmetros e formulários ⚠" },
  { id: "dirbuster",       label: "Dirbuster",           desc: "Força bruta de diretórios e arquivos sensíveis ⚠" },
  { id: "auth_bruteforce", label: "Brute-force de Login",desc: "Testa credenciais comuns em formulários de login ⚠" },
  { id: "port_scan_deep",  label: "Port Scan Profundo",  desc: "~100 portas com banner grabbing ⚠" },
];

export default function NewScanPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [targetId, setTargetId] = useState(searchParams.get("target") ?? "");
  const [selectedModules, setSelectedModules] = useState<string[]>(
    PASSIVE_MODULES.map((m) => m.id)
  );
  const [intrusiveMode, setIntrusiveMode] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const { data: targets, isLoading: loadingTargets } = useQuery({
    queryKey: ["targets"],
    queryFn: () => targetsApi.list({ limit: 100 }).then((r) => r.data),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      // Se há módulos intrusivos confirmados, libera o target primeiro
      if (hasIntrusive && confirmed) {
        await targetsApi.update(targetId, { intrusive_testing_confirmed: true } as any);
      }
      return scansApi.create({
        target_id: targetId,
        scan_type: "full",
        modules: selectedModules,
      });
    },
    onSuccess: (res) => {
      toast.success("Scan iniciado!");
      router.push(`/scans/${res.data.id}`);
    },
    onError: (err: any) => {
      const msg = err.response?.data?.detail || "Erro ao criar scan";
      toast.error(typeof msg === "string" ? msg : JSON.stringify(msg));
    },
  });

  const toggleModule = (id: string) => {
    setSelectedModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const hasIntrusive = selectedModules.some((m) =>
    INTRUSIVE_MODULES.map((i) => i.id).includes(m)
  );

  const handleSubmit = () => {
    if (!targetId) { toast.error("Selecione um alvo"); return; }
    if (selectedModules.length === 0) { toast.error("Selecione ao menos um módulo"); return; }
    if (hasIntrusive && !confirmed) { toast.error("Confirme que tem autorização para testes intrusivos"); return; }
    createMutation.mutate();
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/scans" className="p-2 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-foreground">Novo Scan</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Configure e inicie uma varredura de segurança</p>
        </div>
      </div>

      {/* Target selection */}
      <div className="glass rounded-2xl p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Scan className="w-4 h-4 text-primary" />
          <h2 className="font-semibold text-foreground">Alvo</h2>
        </div>

        {loadingTargets ? (
          <div className="h-10 rounded-lg bg-accent/50 animate-pulse" />
        ) : !targets?.length ? (
          <div className="flex items-center gap-3 p-4 rounded-lg border border-dashed border-border text-muted-foreground">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span className="text-sm">Nenhum alvo cadastrado. </span>
            <Link href="/targets" className="text-primary hover:underline text-sm">Cadastrar alvo →</Link>
          </div>
        ) : (
          <select
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="w-full px-3 py-2.5 bg-input border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
          >
            <option value="">Selecione um alvo...</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} — {t.value}
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Module selection */}
      <div className="glass rounded-2xl p-6 space-y-4">
        <h2 className="font-semibold text-foreground">Módulos de scan</h2>

        {/* Mode toggle */}
        <div className="flex gap-2">
          <button
            onClick={() => { setIntrusiveMode(false); setSelectedModules(PASSIVE_MODULES.map((m) => m.id)); }}
            className={cn(
              "flex-1 py-2 rounded-lg text-sm font-medium border transition-colors",
              !intrusiveMode
                ? "bg-primary/20 border-primary/40 text-primary"
                : "border-border text-muted-foreground hover:bg-accent/50"
            )}
          >
            Padrão (Passivo)
          </button>
          <button
            onClick={() => setIntrusiveMode(true)}
            className={cn(
              "flex-1 py-2 rounded-lg text-sm font-medium border transition-colors",
              intrusiveMode
                ? "bg-red-500/20 border-red-500/40 text-red-400"
                : "border-border text-muted-foreground hover:bg-accent/50"
            )}
          >
            Profundo (Intrusivo) ⚠
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {PASSIVE_MODULES.map((m) => (
            <label
              key={m.id}
              className={cn(
                "flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors",
                selectedModules.includes(m.id)
                  ? "border-primary/40 bg-primary/5"
                  : "border-border hover:bg-accent/30"
              )}
            >
              <input
                type="checkbox"
                checked={selectedModules.includes(m.id)}
                onChange={() => toggleModule(m.id)}
                className="mt-0.5 w-4 h-4 rounded border-border text-primary focus:ring-primary/50"
              />
              <div>
                <p className="text-sm font-medium text-foreground">{m.label}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{m.desc}</p>
              </div>
            </label>
          ))}
        </div>

        {/* Intrusive modules */}
        {intrusiveMode && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-3 pt-2 border-t border-red-500/20"
          >
            <p className="text-xs font-semibold text-red-400 uppercase tracking-wider">Módulos Intrusivos ⚠</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {INTRUSIVE_MODULES.map((m) => (
                <label
                  key={m.id}
                  className={cn(
                    "flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors",
                    selectedModules.includes(m.id)
                      ? "border-red-400/40 bg-red-500/5"
                      : "border-border hover:bg-accent/30"
                  )}
                >
                  <input
                    type="checkbox"
                    checked={selectedModules.includes(m.id)}
                    onChange={() => toggleModule(m.id)}
                    className="mt-0.5 w-4 h-4 rounded border-border text-red-400 focus:ring-red-400/50"
                  />
                  <div>
                    <p className="text-sm font-medium text-foreground">{m.label}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{m.desc}</p>
                  </div>
                </label>
              ))}
            </div>

            <label className="flex items-start gap-3 p-3 rounded-lg border border-red-400/30 bg-red-500/5 cursor-pointer">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-red-400 text-red-400 focus:ring-red-400/50"
              />
              <p className="text-xs text-red-300/80 leading-relaxed">
                Confirmo que tenho autorização explícita e por escrito para realizar testes intrusivos
                neste alvo. Entendo que uso não autorizado é ilegal.
              </p>
            </label>
          </motion.div>
        )}
      </div>

      {/* Submit */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {selectedModules.length} módulo{selectedModules.length !== 1 ? "s" : ""} selecionado{selectedModules.length !== 1 ? "s" : ""}
        </p>
        <button
          onClick={handleSubmit}
          disabled={createMutation.isPending || !targetId}
          className="flex items-center gap-2 px-6 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-semibold hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {createMutation.isPending ? (
            <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
          ) : (
            <Plus className="w-4 h-4" />
          )}
          {createMutation.isPending ? "Iniciando..." : "Iniciar Scan"}
        </button>
      </div>
    </div>
  );
}
