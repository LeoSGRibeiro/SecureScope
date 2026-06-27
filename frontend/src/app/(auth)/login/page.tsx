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
import { useAuthStore } from "@/store/auth";

const schema = z.object({
  username: z.string().min(1, "Username required"),
  password: z.string().min(1, "Password required"),
  ethics_accepted: z.boolean().refine((v) => v, "You must accept the authorized use agreement"),
});

type FormData = z.infer<typeof schema>;

export default function LoginPage() {
  const router = useRouter();
  const { setAuth } = useAuthStore();
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { ethics_accepted: false },
  });

  const onSubmit = async (data: FormData) => {
    setLoading(true);
    try {
      const res = await authApi.login(data);
      const { access_token, refresh_token, user } = res.data;
      setAuth(user, access_token, refresh_token);
      router.push("/dashboard");
      toast.success(`Welcome back, ${user.username}`);
    } catch (err: any) {
      const msg = err.response?.data?.detail || "Login failed";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      {/* Background grid */}
      <div className="fixed inset-0 bg-grid-pattern bg-[size:40px_40px] opacity-100 pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.3 }}
        className="relative w-full max-w-md"
      >
        {/* Ethics banner */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 p-4 rounded-xl border border-orange-400/30 bg-orange-400/5"
        >
          <div className="flex gap-3">
            <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-orange-400">Authorized Use Only</p>
              <p className="text-xs text-orange-300/70 mt-1">
                This platform is exclusively for security testing of systems you own or have explicit
                written authorization to test. Unauthorized use is illegal and may result in criminal prosecution.
              </p>
            </div>
          </div>
        </motion.div>

        <div className="glass rounded-2xl p-8">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-xl bg-primary/20 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="font-bold text-lg text-foreground tracking-wider">THREATLENS</h1>
              <p className="text-xs text-muted-foreground">Enxergando ameaças antes que elas virem incidentes</p>
            </div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                {...register("username")}
                autoComplete="username"
                className="w-full px-3 py-2.5 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                placeholder="analyst"
              />
              {errors.username && <p className="mt-1 text-xs text-red-400">{errors.username.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <input
                  {...register("password")}
                  type={showPw ? "text" : "password"}
                  autoComplete="current-password"
                  className="w-full px-3 py-2.5 pr-10 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition"
                  placeholder="••••••••"
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

            <div className="flex items-start gap-3 p-3 rounded-lg bg-accent/50 border border-border/50">
              <input
                type="checkbox"
                id="ethics"
                {...register("ethics_accepted")}
                className="mt-0.5 w-4 h-4 rounded border-border text-primary focus:ring-primary/50"
              />
              <label htmlFor="ethics" className="text-xs text-muted-foreground cursor-pointer leading-relaxed">
                I confirm I have explicit authorization to test the targets I will add to this platform.
                I understand that unauthorized testing is illegal.
              </label>
            </div>
            {errors.ethics_accepted && (
              <p className="text-xs text-red-400">{errors.ethics_accepted.message}</p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-primary text-primary-foreground font-semibold text-sm hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
              ) : null}
              {loading ? "Authenticating..." : "Sign In"}
            </button>
          </form>

          <p className="mt-4 text-center text-xs text-muted-foreground">
            No account?{" "}
            <a href="/register" className="text-primary hover:underline">Register</a>
          </p>
        </div>
      </motion.div>
    </div>
  );
}
