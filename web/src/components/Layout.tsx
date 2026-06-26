import React from "react";
import { Flag, Globe, Users, Key, Lock, ScrollText, LogOut, Menu } from "lucide-react";
import { cn } from "@/lib/utils";

interface LayoutProps {
  current: string;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  children: React.ReactNode;
}

const navItems = [
  { page: "flags", path: "/flags", label: "Flags", icon: Flag },
  { page: "environments", path: "/environments", label: "Environments", icon: Globe },
  { page: "segments", path: "/segments", label: "Segments", icon: Users },
  { page: "secrets", path: "/secrets", label: "Secrets", icon: Lock },
  { page: "api-keys", path: "/api-keys", label: "API Keys", icon: Key },
  { page: "audit", path: "/audit", label: "Audit", icon: ScrollText },
];

export function Layout({ current, onNavigate, onLogout, children }: LayoutProps) {
  return (
    <div className="min-h-screen flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex w-60 flex-col bg-[var(--color-sidebar)] border-r border-[var(--color-sidebar-border)]">
        <div className="p-4 border-b border-[var(--color-sidebar-border)]">
          <h1 className="text-lg font-bold text-[var(--color-foreground)]">🚩 Reflag</h1>
          <p className="text-xs text-[var(--color-muted-foreground)]">Feature Flags & Config</p>
        </div>
        <nav className="flex-1 p-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = current === item.page;
            return (
              <button
                key={item.page}
                onClick={() => onNavigate(item.path)}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                  active
                    ? "bg-[var(--color-sidebar-accent)] text-[var(--color-sidebar-accent-foreground)]"
                    : "text-[var(--color-muted-foreground)] hover:bg-[var(--color-sidebar-accent)] hover:text-[var(--color-sidebar-accent-foreground)]"
                )}
              >
                <Icon className="size-4" />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="p-2 border-t border-[var(--color-sidebar-border)]">
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-[var(--color-muted-foreground)] hover:bg-[var(--color-destructive)] hover:text-[var(--color-destructive-foreground)] transition-colors"
          >
            <LogOut className="size-4" />
            Logout
          </button>
        </div>
      </aside>

      {/* Mobile Header */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-[var(--color-sidebar)] border-b border-[var(--color-sidebar-border)] h-14 flex items-center justify-between px-4">
        <h1 className="text-lg font-bold">🚩 Reflag</h1>
        <MobileNav current={current} onNavigate={onNavigate} onLogout={onLogout} />
      </div>

      {/* Main Content */}
      <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-6xl mx-auto w-full pt-16 lg:pt-8 pb-20 lg:pb-8">
        {children}
      </main>

      {/* Mobile Bottom Nav */}
      <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-50 bg-[var(--color-sidebar)] border-t border-[var(--color-sidebar-border)] h-14 flex items-center justify-around">
        {navItems.slice(0, 5).map((item) => {
          const Icon = item.icon;
          const active = current === item.page;
          return (
            <button
              key={item.page}
              onClick={() => onNavigate(item.path)}
              className={cn(
                "flex flex-col items-center gap-0.5 px-2 py-1 text-xs",
                active ? "text-[var(--color-foreground)]" : "text-[var(--color-muted-foreground)]"
              )}
            >
              <Icon className="size-5" />
              <span className="text-[10px]">{item.label}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
}

function MobileNav({ current, onNavigate, onLogout }: { current: string; onNavigate: (p: string) => void; onLogout: () => void }) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <button onClick={() => setOpen(!open)} className="p-2">
        <Menu className="size-5" />
      </button>
      {open && (
        <div className="absolute top-14 right-0 w-48 bg-[var(--color-popover)] border border-[var(--color-border)] rounded-md shadow-lg py-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = current === item.page;
            return (
              <button
                key={item.page}
                onClick={() => { onNavigate(item.path); setOpen(false); }}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-2 text-sm",
                  active ? "bg-[var(--color-accent)]" : ""
                )}
              >
                <Icon className="size-4" />
                {item.label}
              </button>
            );
          })}
          <div className="border-t border-[var(--color-border)] mt-1 pt-1">
            <button
              onClick={onLogout}
              className="w-full flex items-center gap-3 px-3 py-2 text-sm text-[var(--color-destructive)]"
            >
              <LogOut className="size-4" />
              Logout
            </button>
          </div>
        </div>
      )}
    </>
  );
}
