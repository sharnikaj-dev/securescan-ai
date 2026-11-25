import React, { useEffect, useState } from "react";
import { api, setAuthToken } from "./lib/api";
import { AppRoute, AppShell } from "./components/AppShell";
import { AuthView } from "./components/AuthView";
import { DashboardView } from "./components/DashboardView";
import { HistoryView } from "./components/HistoryView";
import { LandingPage } from "./components/LandingPage";
import { RuleCatalogView } from "./components/RuleCatalogView";
import { ScanReportView } from "./components/ScanReportView";
import { ScannerView } from "./components/ScannerView";
import { SettingsView } from "./components/SettingsView";
import { ThemeMode, UserProfile } from "./types";

type Surface = "landing" | "auth" | "console";

export default function App() {
  const [surface, setSurface] = useState<Surface>("landing");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [user, setUser] = useState<UserProfile | null>(null);
  const [theme, setTheme] = useState<ThemeMode>("light");
  const [route, setRoute] = useState<AppRoute>("dashboard");
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [focusVulnId, setFocusVulnId] = useState<number | null>(null);
  const [demoRunning, setDemoRunning] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "dark") {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
  }, [theme]);

  const handleOpenAuth = (mode: "login" | "register") => {
    setAuthMode(mode);
    setSurface("auth");
  };

  const handleAuthenticated = (loggedUser: UserProfile) => {
    setUser(loggedUser);
    setTheme(loggedUser.themePreference);
    setRoute("dashboard");
    setSurface("console");
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {
      // ignore session cleanup error
    }
    setAuthToken(null);
    setUser(null);
    setActiveScanId(null);
    setFocusVulnId(null);
    setSurface("landing");
  };

  const handleToggleTheme = async () => {
    const next: ThemeMode = theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (user) {
      try {
        const res = await api.updateProfile({ themePreference: next });
        setUser(res.user);
      } catch {
        // local theme still updates smoothly
      }
    }
  };

  const handleOpenScan = (scanId: number, vulnId?: number) => {
    setActiveScanId(scanId);
    setFocusVulnId(vulnId ?? null);
    setRoute("report");
  };

  const handleRunDemoScan = async () => {
    setDemoRunning(true);
    try {
      const res = await api.runDemoScan();
      setActiveScanId(res.scanId);
      setFocusVulnId(null);
      setRoute("report");
    } finally {
      setDemoRunning(false);
    }
  };

  if (surface === "landing") {
    return (
      <LandingPage
        onOpenAuth={handleOpenAuth}
        isAuthenticated={Boolean(user)}
        onEnterConsole={() => setSurface("console")}
      />
    );
  }

  if (surface === "auth" || !user) {
    return (
      <AuthView
        initialMode={authMode}
        onBackToLanding={() => setSurface("landing")}
        onAuthenticated={handleAuthenticated}
      />
    );
  }

  const breadcrumbMap: Record<AppRoute, string> = {
    dashboard: "Security Dashboard",
    scan: "Static Code Scanner",
    report: activeScanId ? `Audit Report #${activeScanId}` : "Vulnerability Report",
    history: "Scan History & Comparison",
    rules: "OWASP & CWE Rule Catalog",
    settings: "Settings & Profile",
  };

  return (
    <AppShell
      user={user}
      theme={theme}
      activeRoute={route}
      breadcrumb={breadcrumbMap[route]}
      onNavigate={(nextRoute) => {
        setRoute(nextRoute);
        if (nextRoute !== "report") {
          setFocusVulnId(null);
        }
      }}
      onToggleTheme={handleToggleTheme}
      onLogout={handleLogout}
      onBackToLanding={() => setSurface("landing")}
    >
      {route === "dashboard" && (
        <DashboardView
          onStartNewScan={() => setRoute("scan")}
          onOpenScan={handleOpenScan}
          onRunDemoScan={handleRunDemoScan}
          demoRunning={demoRunning}
        />
      )}

      {route === "scan" && (
        <ScannerView
          defaultLanguage={user.scanPreferences.defaultLanguage}
          onScanComplete={(scanId) => handleOpenScan(scanId)}
          onRunDemoScan={handleRunDemoScan}
          demoRunning={demoRunning}
        />
      )}

      {route === "report" && (
        <ScanReportView
          scanId={activeScanId}
          focusVulnId={focusVulnId}
          onBackToHistory={() => setRoute("history")}
          onStartNewScan={() => setRoute("scan")}
        />
      )}

      {route === "history" && (
        <HistoryView
          onOpenScan={(scanId) => handleOpenScan(scanId)}
          onStartNewScan={() => setRoute("scan")}
        />
      )}

      {route === "rules" && (
        <RuleCatalogView onTryScanner={() => setRoute("scan")} />
      )}

      {route === "settings" && (
        <SettingsView
          user={user}
          theme={theme}
          onUserUpdated={setUser}
          onThemeChange={(nextTheme) => setTheme(nextTheme)}
          onAccountDeleted={() => {
            setAuthToken(null);
            setUser(null);
            setSurface("landing");
          }}
        />
      )}
    </AppShell>
  );
}
