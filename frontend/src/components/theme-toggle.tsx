"use client";
import { Sun, Moon } from "lucide-react";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  return (
    <button
      onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
      aria-label="Alternar tema claro/escuro"
      className={
        className ??
        "w-9 h-9 rounded-lg border border-border/50 bg-card/60 flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
      }
    >
      {mounted && theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
    </button>
  );
}
