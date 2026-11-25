import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  FileCode2,
  FlaskConical,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../lib/api";
import { DashboardPayload } from "../types";
import { SecurityShield3D } from "./SecurityShield3D";
import { TiltCard3D } from "./TiltCard3D";
import { VulnerabilityOrbit3D } from "./VulnerabilityOrbit3D";
import { getScoreColorClass, SeverityLabel } from "./SeverityLabel";

interface DashboardViewProps {
  onStartNewScan: () => void;
  onOpenScan: (scanId: number, focusVulnId?: number) => void;
  onRunDemoScan: () => Promise<void>;
  demoRunning: boolean;
}

export function DashboardView({
  onStartNewScan,
  onOpenScan,
  onRunDemoScan,
  demoRunning,
}: DashboardViewProps) {
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const payload = await api.getDashboard();
      setData(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard metrics.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadDashboard();
  }, []);

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((n) => (
            <div
              key={n}
              className="h-28 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]"
            />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 h-72 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]" />
          <div className="lg:col-span-5 h-72 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-8 rounded-xl border border-red-300 dark:border-red-500/30 bg-[#FFFDF7] dark:bg-[#17221B] text-center space-y-4">
        <AlertTriangle className="w-8 h-8 text-red-500 mx-auto" />
        <div>
          <h2 className="text-base font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
            Unable to load security overview
          </h2>
          <p className="text-sm text-[#617565] dark:text-[#98AD94] mt-1">{error}</p>
        </div>
        <button
          type="button"
          onClick={loadDashboard}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry</span>
        </button>
      </div>
    );
  }

  const { stats, categoryDistribution, trend, recentScans, securityAlerts } = data;
  const isEmpty = stats.totalScans === 0;

  if (isEmpty) {
    return (
      <div className="space-y-6">
        <div className="p-8 sm:p-10 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] max-w-4xl mx-auto mt-4 grid md:grid-cols-12 gap-8 items-center">
          <div className="md:col-span-5 h-60 rounded-xl overflow-hidden border border-[#CBE0B9] dark:border-[#2A3D30] bg-[#EDF3E5] min-w-0">
            <SecurityShield3D variant="compact" score={90} />
          </div>
          <div className="md:col-span-7 space-y-4">
            <div className="inline-flex items-center gap-2 text-xs font-medium text-[#3D6A39] dark:text-[#A5D190]">
              <ShieldCheck className="w-4 h-4" />
              <span>Workspace Ready</span>
            </div>
            <h1 className="text-xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
              No security scans recorded yet
            </h1>
            <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
              Upload a source file, submit a ZIP repository, or paste code to run static analysis
              and populate your security posture metrics, severity trends, and remediation insights.
            </p>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                type="button"
                onClick={onStartNewScan}
                className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Start First Code Scan</span>
              </button>
              <button
                type="button"
                onClick={onRunDemoScan}
                disabled={demoRunning}
                className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] border border-[#C3D6B1] dark:border-[#2A3D30] hover:border-[#7FB16B] rounded-lg transition-colors disabled:opacity-60 cursor-pointer"
              >
                <FlaskConical className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
                <span>{demoRunning ? "Running Demo Scan..." : "Run Demo Mode Scan"}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const severityChartData = [
    { name: "Critical", count: stats.severityCounts.critical, color: "#DC2626" },
    { name: "High", count: stats.severityCounts.high, color: "#F59E0B" },
    { name: "Medium", count: stats.severityCounts.medium, color: "#0EA5E9" },
    { name: "Low", count: stats.severityCounts.low, color: "#10B981" },
  ];

  return (
    <div className="space-y-6">
      {/* Header Row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
            Security Posture Overview
          </h1>
          <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
            Aggregated static-analysis metrics across your scanned repositories · Application-defined risk indicator
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onRunDemoScan}
            disabled={demoRunning}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-[#1B2B20] dark:text-[#F5F1E6] hover:border-[#7FB16B] rounded-lg transition-colors disabled:opacity-60 whitespace-nowrap cursor-pointer"
          >
            <FlaskConical className="w-3.5 h-3.5 text-[#3D6A39] dark:text-[#A5D190]" />
            <span>{demoRunning ? "Running Demo..." : "Run Demo Mode"}</span>
          </button>
          <button
            type="button"
            onClick={onStartNewScan}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Code Scan</span>
          </button>
        </div>
      </div>

      {/* KPI Strip + Live 3D Posture Core */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch">
        <div className="lg:col-span-9 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <TiltCard3D className="p-5 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
            <div className="flex items-center justify-between text-xs text-[#617565] dark:text-[#98AD94] mb-2">
              <span>Total Code Scans</span>
              <FileCode2 className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
            </div>
            <p className="text-2xl font-bold font-mono tabular-nums text-[#1B2B20] dark:text-[#F5F1E6]">
              {stats.totalScans}
            </p>
            <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
              Persisted in SQLite store
            </p>
          </TiltCard3D>

          <TiltCard3D className="p-5 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#EEF5E6] dark:bg-[#17221B]">
            <div className="flex items-center justify-between text-xs text-[#4A5E4E] dark:text-[#98AD94] mb-2">
              <span>Total Vulnerabilities</span>
              <ShieldAlert className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
            </div>
            <p className="text-2xl font-bold font-mono tabular-nums text-[#1B2B20] dark:text-[#F5F1E6]">
              {stats.totalVulnerabilities}
            </p>
            <p className="text-xs text-[#4A5E4E] dark:text-[#98AD94] mt-1 tabular-nums">
              {stats.severityCounts.critical} Critical · {stats.severityCounts.high} High
            </p>
          </TiltCard3D>

          <TiltCard3D className="p-5 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
            <div className="flex items-center justify-between text-xs text-[#617565] dark:text-[#98AD94] mb-2">
              <span>Average Security Score</span>
              <Activity className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
            </div>
            <p
              className={`text-2xl font-bold font-mono tabular-nums ${
                stats.averageSecurityScore !== null
                  ? getScoreColorClass(stats.averageSecurityScore)
                  : "text-[#617565]"
              }`}
            >
              {stats.averageSecurityScore !== null ? `${stats.averageSecurityScore}/100` : "—"}
            </p>
            <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
              Weighted static indicator
            </p>
          </TiltCard3D>

          <TiltCard3D className="p-5 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
            <div className="flex items-center justify-between text-xs text-[#617565] dark:text-[#98AD94] mb-2">
              <span>Severity Breakdown</span>
            </div>
            <div className="grid grid-cols-4 gap-2 pt-1">
              <div>
                <p className="text-lg font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
                  {stats.severityCounts.critical}
                </p>
                <p className="text-[11px] text-[#617565] dark:text-[#98AD94]">Crit</p>
              </div>
              <div>
                <p className="text-lg font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
                  {stats.severityCounts.high}
                </p>
                <p className="text-[11px] text-[#617565] dark:text-[#98AD94]">High</p>
              </div>
              <div>
                <p className="text-lg font-bold font-mono tabular-nums text-sky-600 dark:text-sky-400">
                  {stats.severityCounts.medium}
                </p>
                <p className="text-[11px] text-[#617565] dark:text-[#98AD94]">Med</p>
              </div>
              <div>
                <p className="text-lg font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
                  {stats.severityCounts.low}
                </p>
                <p className="text-[11px] text-[#617565] dark:text-[#98AD94]">Low</p>
              </div>
            </div>
          </TiltCard3D>
        </div>

        {/* Live 3D Posture Core Widget */}
        <div className="lg:col-span-3 h-40 lg:h-auto min-w-0 rounded-xl overflow-hidden border border-[#CBE0B9] dark:border-[#2A3D30] bg-[#EDF3E5] relative">
          <SecurityShield3D variant="compact" score={stats.averageSecurityScore ?? 85} />
          <div className="pointer-events-none absolute bottom-2 left-3 text-[10px] font-mono text-[#2F4534] bg-[#FFFDF7]/95 px-2 py-0.5 rounded border border-[#CBE0B9]">
            3D Posture Core
          </div>
        </div>
      </div>

      {/* Charts + 3D Threat Orbit Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 min-w-0 p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                Security Score Trend
              </h2>
              <p className="text-xs text-[#617565] dark:text-[#98AD94]">
                Chronological posture across recent scans (0–100)
              </p>
            </div>
          </div>
          <div className="h-64 min-w-0">
            <ResponsiveContainer width="100%" height="100%" debounce={60}>
              <AreaChart data={trend} margin={{ top: 10, right: 12, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#85B86D" stopOpacity={0.48} />
                    <stop offset="95%" stopColor="#85B86D" stopOpacity={0.04} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(107, 134, 96, 0.2)" />
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 11, fill: "#6B806B" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 11, fill: "#6B806B" }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#17221B",
                    borderColor: "#334C38",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#FAF6ED",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  name="Security Score"
                  stroke="#5F9A4E"
                  strokeWidth={2}
                  fill="url(#scoreGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-4 min-w-0 p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
              Severity Distribution
            </h2>
            <p className="text-xs text-[#617565] dark:text-[#98AD94]">
              Total static findings grouped by severity level
            </p>
          </div>
          <div className="h-64 min-w-0">
            <ResponsiveContainer width="100%" height="100%" debounce={60}>
              <BarChart data={severityChartData} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(107, 134, 96, 0.2)" />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 11, fill: "#6B806B" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "#6B806B" }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#17221B",
                    borderColor: "#334C38",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#FAF6ED",
                  }}
                />
                <Bar dataKey="count" name="Findings" radius={[6, 6, 0, 0]}>
                  {severityChartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-3 min-w-0 rounded-xl overflow-hidden border border-[#CBE0B9] dark:border-[#2A3D30] bg-[#162119] flex flex-col">
          <div className="px-4 py-3 border-b border-[#2A3D30] flex items-center justify-between">
            <h2 className="text-xs font-semibold text-[#FAF6ED]">3D Threat Orbit</h2>
            <span className="text-[10px] font-mono text-[#B7CEAE]">Drag to rotate</span>
          </div>
          <div className="flex-1 min-h-[240px]">
            <VulnerabilityOrbit3D
              critical={stats.severityCounts.critical}
              high={stats.severityCounts.high}
              medium={stats.severityCounts.medium}
              low={stats.severityCounts.low}
            />
          </div>
        </div>
      </div>

      {/* Category Distribution + Recent Activity + Security Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] overflow-hidden">
          <div className="px-6 py-4 border-b border-[#D5E2C8] dark:border-[#2A3D30] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
              Recent Scan Activity
            </h2>
            <span className="text-xs text-[#617565] dark:text-[#98AD94]">
              Latest {recentScans.length} scans
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#D5E2C8] dark:border-[#2A3D30] text-[#617565] dark:text-[#98AD94]">
                <tr>
                  <th className="py-3 px-5 font-medium">Project</th>
                  <th className="py-3 px-4 font-medium">Language</th>
                  <th className="py-3 px-4 font-medium text-right">Findings</th>
                  <th className="py-3 px-4 font-medium text-right">Score</th>
                  <th className="py-3 px-5 font-medium text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E3ECD8] dark:divide-[#243629]">
                {recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="hover:bg-[#EEF5E6] dark:hover:bg-[#223326] transition-colors"
                  >
                    <td className="py-3 px-5">
                      <div className="font-medium text-[#1B2B20] dark:text-[#F5F1E6] truncate max-w-[200px]">
                        {scan.projectName}
                      </div>
                      <div className="text-[11px] text-[#617565] dark:text-[#98AD94]">
                        {new Date(scan.createdAt).toLocaleDateString()} · {scan.filesScanned} file(s)
                        {scan.isDemo ? " · Demo Mode" : ""}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-[#4A5E4E] dark:text-[#C4D3BF]">
                      {scan.language}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-[#1B2B20] dark:text-[#F5F1E6]">
                      {scan.totalVulnerabilities}
                    </td>
                    <td
                      className={`py-3 px-4 text-right font-mono tabular-nums font-semibold ${getScoreColorClass(
                        scan.securityScore
                      )}`}
                    >
                      {scan.securityScore}
                    </td>
                    <td className="py-3 px-5 text-right">
                      <button
                        type="button"
                        onClick={() => onOpenScan(scan.id)}
                        className="inline-flex items-center gap-1 text-[#3D6A39] dark:text-[#A5D190] hover:underline font-medium cursor-pointer"
                      >
                        <span>Inspect</span>
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="lg:col-span-5 space-y-6">
          <div className="rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] overflow-hidden">
            <div className="px-6 py-4 border-b border-[#D5E2C8] dark:border-[#2A3D30] flex items-center justify-between">
              <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                Priority Security Alerts
              </h2>
              <span className="text-xs text-[#617565] dark:text-[#98AD94]">
                Critical &amp; High
              </span>
            </div>
            {securityAlerts.length === 0 ? (
              <div className="p-6 text-xs text-[#617565] dark:text-[#98AD94]">
                No critical or high-severity alerts across your scanned projects.
              </div>
            ) : (
              <div className="divide-y divide-[#E3ECD8] dark:divide-[#243629]">
                {securityAlerts.slice(0, 5).map((alert) => (
                  <button
                    key={alert.id}
                    type="button"
                    onClick={() => onOpenScan(alert.scan_id, alert.id)}
                    className="w-full text-left px-6 py-3.5 hover:bg-[#EEF5E6] dark:hover:bg-[#223326] transition-colors flex items-start justify-between gap-3 cursor-pointer"
                  >
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] truncate">
                        {alert.title}
                      </p>
                      <p className="text-[11px] text-[#617565] dark:text-[#98AD94] font-mono truncate mt-0.5">
                        {alert.project_name} · {alert.file_path}:{alert.line_number}
                      </p>
                    </div>
                    <SeverityLabel severity={alert.severity} compact />
                  </button>
                ))}
              </div>
            )}
          </div>

          {categoryDistribution.length > 0 && (
            <div className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
              <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-3">
                Top Vulnerability Categories
              </h2>
              <div className="space-y-2.5">
                {categoryDistribution.slice(0, 5).map((cat) => (
                  <div key={cat.name} className="flex items-center justify-between text-xs">
                    <span className="text-[#4A5E4E] dark:text-[#C4D3BF] truncate pr-4">
                      {cat.name}
                    </span>
                    <span className="font-mono tabular-nums font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                      {cat.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
