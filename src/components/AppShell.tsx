import React, { useState } from "react";
import {
  BookOpen,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  Globe,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Plus,
  Settings,
  Shield,
  Sun,
  X,
} from "lucide-react";
import { ThemeMode, UserProfile } from "../types";

export type AppRoute = "dashboard" | "scan" | "report" | "history" | "rules" | "settings";

interface AppShellProps {
  user: UserProfile;
  theme: ThemeMode;
  activeRoute: AppRoute;
  breadcrumb: string;
  onNavigate: (route: AppRoute) => void;
  onToggleTheme: () => void;
  onLogout: () => void;
  onBackToLanding: () => void;
  children: React.ReactNode;
}

const WORKSPACE_NAV: Array<{
  id: AppRoute;
  label: string;
  Icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { id: "scan", label: "Code Scanner", Icon: Plus },
  { id: "report", label: "Scan Report", Icon: FileSearch },
  { id: "history", label: "Scan History", Icon: History },
];

const REFERENCE_NAV: Array<{
  id: AppRoute;
  label: string;
  Icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "rules", label: "Rule Catalog", Icon: BookOpen },
  { id: "settings", label: "Settings", Icon: Settings },
];

export function AppShell({
  user,
  theme,
  activeRoute,
  breadcrumb,
  onNavigate,
  onToggleTheme,
  onLogout,
  onBackToLanding,
  children,
}: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [avatarFailed, setAvatarFailed] = useState(false);

  const renderNavGroup = (
    title: string,
    items: Array<{ id: AppRoute; label: string; Icon: React.ComponentType<{ className?: string }> }>
  ) => (
    <div className="space-y-1">
      {!collapsed && (
        <p className="px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-[#617565] dark:text-[#98AD94]">
          {title}
        </p>
      )}
      {items.map(({ id, label, Icon }) => {
        const active = activeRoute === id;
        return (
          <button
            key={id}
            type="button"
            onClick={() => {
              onNavigate(id);
              setMobileOpen(false);
            }}
            title={collapsed ? label : undefined}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap cursor-pointer ${
              active
                ? "bg-[#9BC585] text-[#142617] font-semibold"
                : "text-[#4A5E4E] dark:text-[#C4D3BF] hover:bg-[#EEF5E6] dark:hover:bg-[#223326] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
            }`}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {!collapsed && <span>{label}</span>}
          </button>
        );
      })}
    </div>
  );

  return (
    <div className="min-h-screen flex bg-[#FAF6ED] text-[#1B2B20] dark:bg-[#101712] dark:text-[#F5F1E6]">
      {/* Mobile Drawer Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Collapsible Sidebar */}
      <aside
        className={`fixed lg:sticky top-0 left-0 z-50 h-screen flex flex-col border-r border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#141E17] transition-transform duration-200 ${
          collapsed ? "w-[72px]" : "w-[248px]"
        } ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}
      >
        <div className="h-16 px-4 flex items-center justify-between border-b border-[#D5E2C8] dark:border-[#2A3D30]">
          <button
            type="button"
            onClick={onBackToLanding}
            className="flex items-center gap-2.5 overflow-hidden cursor-pointer text-left"
          >
            <div className="w-8 h-8 rounded-lg bg-[#9BC585] flex items-center justify-center text-[#142617] shrink-0">
              <Shield className="w-4 h-4" />
            </div>
            {!collapsed && (
              <span className="font-display font-bold text-base tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] whitespace-nowrap">
                SecureScan AI
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="hidden lg:flex w-7 h-7 items-center justify-center rounded-md text-[#617565] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6] hover:bg-[#EEF5E6] dark:hover:bg-[#223326] cursor-pointer"
          >
            {collapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>

          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation menu"
            className="lg:hidden p-1.5 text-[#617565] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6] cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 px-3 py-3 space-y-4 overflow-y-auto">
          {renderNavGroup("Security Console", WORKSPACE_NAV)}
          {renderNavGroup("Reference & Account", REFERENCE_NAV)}

          <div className="pt-2 border-t border-[#D5E2C8] dark:border-[#2A3D30]">
            <button
              type="button"
              onClick={onBackToLanding}
              title={collapsed ? "Public Website" : undefined}
              className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium text-[#617565] dark:text-[#98AD94] hover:text-[#2F592C] dark:hover:text-[#A5D190] hover:bg-[#EEF5E6] dark:hover:bg-[#223326] transition-colors cursor-pointer"
            >
              <Globe className="w-4 h-4 shrink-0" />
              {!collapsed && <span>Public Website</span>}
            </button>
          </div>
        </nav>

        {/* User Footer */}
        <div className="p-3 border-t border-[#D5E2C8] dark:border-[#2A3D30] space-y-2">
          <div className="flex items-center gap-3 px-2 py-1.5">
            {!avatarFailed ? (
              <img
                src="/src/assets/images/avatar_security_lead_1795584995373.jpg"
                alt={user.name}
                referrerPolicy="no-referrer"
                onError={() => setAvatarFailed(true)}
                className="w-8 h-8 rounded-full object-cover border border-[#C3D6B1] dark:border-[#2A3D30] shrink-0"
              />
            ) : (
              <div className="w-8 h-8 rounded-full bg-[#9BC585] text-[#142617] text-xs font-bold flex items-center justify-center shrink-0">
                {user.name.slice(0, 2).toUpperCase()}
              </div>
            )}
            {!collapsed && (
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] truncate">
                  {user.name}
                </p>
                <p className="text-[11px] text-[#617565] dark:text-[#98AD94] truncate">
                  {user.organization}
                </p>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onLogout}
            title={collapsed ? "Sign Out" : undefined}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium text-[#4A5E4E] dark:text-[#98AD94] hover:text-red-600 dark:hover:text-red-400 hover:bg-[#EEF5E6] dark:hover:bg-[#223326] transition-colors cursor-pointer"
          >
            <LogOut className="w-4 h-4 shrink-0" />
            {!collapsed && <span>Sign Out</span>}
          </button>
        </div>
      </aside>

      {/* Main Content Column */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="sticky top-0 z-20 h-16 px-4 sm:px-8 border-b border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7]/95 dark:bg-[#101712]/95 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-2 rounded-lg text-[#4A5E4E] dark:text-[#C4D3BF] hover:bg-[#EEF5E6] dark:hover:bg-[#223326] cursor-pointer"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-sm text-[#617565] dark:text-[#98AD94] truncate">
              <span className="hidden sm:inline">Workspace</span>
              <span className="hidden sm:inline" aria-hidden="true">
                /
              </span>
              <span className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6] truncate">
                {breadcrumb}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate("rules")}
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#17221B] text-xs font-medium text-[#1B2B20] dark:text-[#F5F1E6] hover:border-[#7FB16B] transition-colors cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-[#3D6A39] dark:text-[#A5D190]" />
              <span>Rule Catalog</span>
            </button>

            <button
              type="button"
              onClick={onToggleTheme}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              className="p-2 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] text-[#4A5E4E] dark:text-[#C4D3BF] hover:bg-[#EEF5E6] dark:hover:bg-[#223326] transition-colors cursor-pointer"
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            <button
              type="button"
              onClick={() => onNavigate("scan")}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs sm:text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Quick Scan</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-8 max-w-7xl w-full mx-auto min-w-0">{children}</main>
      </div>
    </div>
  );
}
