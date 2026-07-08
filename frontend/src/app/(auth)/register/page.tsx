"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Shield, Eye, EyeOff, AlertTriangle } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import toast from "react-hot-toast";
import { authApi } from "@/lib/api";
import { APP_VERSION, APP_AUTHOR } from "@/lib/version";
import { ThemeToggle } from "@/components/theme-toggle";

const schema = z.object({
  email: z.string().email("E-mail inválido"),
  username: z.string().min(3, "Mínimo 3 caracteres").regex(/^[a-zA-Z0-9_-]+$/, "Apenas letras, números, _ e -"),
  full_name: z.string().optional(),
  password: z.string().min(8, "Mínimo 8 caracteres"),
  confirm_password: z.string(),
}).refine((d) => d.password === d.confirm_password, {
  message: "As senhas não coincidem",
  path: ["confirm_password"],
});

type FormData = z.infer<typeof schema>;

export default function RegisterPage() {
  const router = useRouter();
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (data: FormData) => {
    setLoading(true);
    try {
      await authApi.register({
        email: data.email,
        username: data.username,
        password: data.password,
        full_name: data.full_name || undefined,
      });
      toast.success("Conta criada! Faça login para continuar.");
      router.push("/login");
    } catch (err: any) {
      const msg = err.response?.data?.detail || "Erro ao criar conta";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="fixed inset-0 bg-grid-pattern bg-[size:40px_40px] opacity-100 pointer-events-none" />

      <div className="fixed top-4 right-4 z-10">
        <ThemeToggle />
      </div>

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.3 }}
        className="relative w-full max-w-md"
      >
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 p-4 rounded-xl border border-orange-400/30 bg-orange-400/5"
        >
          <div className="flex gap-3">
            <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-orange-400">Uso Autorizado Apenas</p>
              <p className="text-xs text-orange-300/70 mt-1">
                Esta plataforma é exclusiva para testes de segurança em sistemas que você possui
                ou tem autorização explícita por escrito para testar.
              </p>
            </div>
          </div>
        </motion.div>

        <div className="glass rounded-2xl p-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-xl bg-primary/20 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="font-bold text-lg text-foreground tracking-wider">THREATLENS</h1>
              <p className="text-xs text-muted-foreground">Criar nova conta</p>
            </div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                E-mail
              </label>
              <input
                {...register("email")}
                type="email"
                autoComplete="email"
                className="w-full px-3 py-2.5 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                placeholder="analista@empresa.com"
              />
              {errors.email && <p className="mt-1 text-xs text-red-400">{errors.email.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                {...register("username")}
                autoComplete="username"
                className="w-full px-3 py-2.5 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                placeholder="analista"
              />
              {errors.username && <p className="mt-1 text-xs text-red-400">{errors.username.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                Nome completo <span className="text-muted-foreground/50 normal-case">(opcional)</span>
              </label>
              <input
                {...register("full_name")}
                autoComplete="name"
                className="w-full px-3 py-2.5 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                placeholder="João Silva"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                Senha
              </label>
              <div className="relative">
                <input
                  {...register("password")}
                  type={showPw ? "text" : "password"}
                  autoComplete="new-password"
                  className="w-full px-3 py-2.5 pr-10 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                  placeholder="Mínimo 8 caracteres"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.password && <p className="mt-1 text-xs text-red-400">{errors.password.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                Confirmar senha
              </label>
              <input
                {...register("confirm_password")}
                type={showPw ? "text" : "password"}
                autoComplete="new-password"
                className="w-full px-3 py-2.5 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                placeholder="Repita a senha"
              />
              {errors.confirm_password && <p className="mt-1 text-xs text-red-400">{errors.confirm_password.message}</p>}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-primary text-primary-foreground font-semibold text-sm hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
              ) : null}
              {loading ? "Criando conta..." : "Criar conta"}
            </button>
          </form>

          <p className="mt-4 text-center text-xs text-muted-foreground">
            Já tem conta?{" "}
            <a href="/login" className="text-primary hover:underline">Entrar</a>
          </p>
          <p className="mt-3 text-center text-[10px] text-muted-foreground/60">
            ThreatLens v{APP_VERSION} — desenvolvido por {APP_AUTHOR}
          </p>
        </div>
      </motion.div>
    </div>
  );
}
