"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { useAuthStore } from "@/store/auth";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { user, accessToken } = useAuthStore();

  useEffect(() => {
    if (!accessToken || !user) {
      router.replace("/login");
    }
  }, [accessToken, user, router]);

  if (!user) return null;

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="p-6 min-h-full">{children}</div>
      </main>
    </div>
  );
}
