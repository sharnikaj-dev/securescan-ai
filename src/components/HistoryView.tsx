import React, { useEffect, useState } from "react";
import {
  ArrowRight,
  GitCompare,
  History,
  Plus,
  Trash2,
} from "lucide-react";
import { api } from "../lib/api";
import { ScanComparisonPayload, ScanSummary } from "../types";
import { getScoreColorClass } from "./SeverityLabel";

interface HistoryViewProps {
  onOpenScan: (scanId: number) => void;
  onStartNewScan: () => void;
}

export function HistoryView({ onOpenScan, onStartNewScan }: HistoryViewProps) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const [baselineId, setBaselineId] = useState<string>("");
  const [compareId, setCompareId] = useState<string>("");
  const [comparison, setComparison] = useState<ScanComparisonPayload | null>(null);
  const [comparing, setComparing] = useState(false);

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listScans();
      setScans(res.scans);
      if (res.scans.length >= 2) {
        setBaselineId(String(res.scans[1].id));
        setCompareId(String(res.scans[0].id));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadScans();
  }, []);

  const handleDelete = async (scanId: number) => {
    try {
      await api.deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
      if (
        comparison &&
        (comparison.baseline.id === scanId || comparison.comparison.id === scanId)
      ) {
        setComparison(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete scan.");
    }
  };

  const handleCompare = async () => {
    if (!baselineId || !compareId || baselineId === compareId) {
      setError("Select two different scans to compare.");
      return;
    }
    setError(null);
    setComparing(true);
    try {
      const res = await api.compareScans(Number(baselineId), Number(compareId));
      setComparison(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan comparison failed.");
    } finally {
      setComparing(false);
    }
  };

  const filtered = scans.filter((s) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      s.projectName.toLowerCase().includes(q) ||
      s.language.toLowerCase().includes(q) ||
      s.riskClassification.toLowerCase().includes(q)
    );
  });

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-24 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]" />
        <div className="h-64 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
            Scan History &amp; Comparison
          </h1>
          <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
            Reopen historical security reports, track score changes, or compare two repository audits.
          </p>
        </div>

        <button
          type="button"
          onClick={onStartNewScan}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Scan</span>
        </button>
      </div>

      {error && (
        <div
          role="alert"
          className="p-3.5 rounded-lg border border-red-300 dark:border-red-500/40 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300"
        >
          {error}
        </div>
      )}

      {scans.length === 0 ? (
        <div className="p-10 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-center space-y-3">
          <History className="w-9 h-9 text-[#3D6A39] dark:text-[#A5D190] mx-auto" />
          <h2 className="text-base font-bold text-[#1B2B20] dark:text-[#F5F1E6]">
            Your scan history is empty
          </h2>
          <p className="text-xs text-[#617565] dark:text-[#98AD94] max-w-md mx-auto">
            Run a source code or ZIP archive scan to persist reports and unlock historical scan
            comparisons.
          </p>
          <button
            type="button"
            onClick={onStartNewScan}
            className="px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg cursor-pointer"
          >
            Run First Scan
          </button>
        </div>
      ) : (
        <>
          {/* Scan Comparison Module */}
          {scans.length >= 2 && (
            <div className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-4">
              <div className="flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
                <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                  Compare Two Scans
                </h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
                <div className="md:col-span-5">
                  <label className="block text-[11px] font-medium text-[#617565] dark:text-[#98AD94] mb-1">
                    Baseline Scan
                  </label>
                  <select
                    value={baselineId}
                    onChange={(e) => setBaselineId(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
                  >
                    {scans.map((s) => (
                      <option key={s.id} value={s.id}>
                        #{s.id} · {s.projectName} ({s.securityScore}/100)
                      </option>
                    ))}
                  </select>
                </div>

                <div className="md:col-span-5">
                  <label className="block text-[11px] font-medium text-[#617565] dark:text-[#98AD94] mb-1">
                    Comparison Scan
                  </label>
                  <select
                    value={compareId}
                    onChange={(e) => setCompareId(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
                  >
                    {scans.map((s) => (
                      <option key={s.id} value={s.id}>
                        #{s.id} · {s.projectName} ({s.securityScore}/100)
                      </option>
                    ))}
                  </select>
                </div>

                <div className="md:col-span-2">
                  <button
                    type="button"
                    onClick={handleCompare}
                    disabled={comparing}
                    className="w-full py-2 px-3 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors cursor-pointer"
                  >
                    {comparing ? "Comparing..." : "Compare"}
                  </button>
                </div>
              </div>

              {comparison && (
                <div className="pt-4 border-t border-[#D5E2C8] dark:border-[#2A3D30] grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs">
                  <div>
                    <p className="text-[#617565] dark:text-[#98AD94]">Score Change</p>
                    <p
                      className={`text-lg font-bold font-mono tabular-nums ${
                        comparison.deltas.scoreDelta >= 0
                          ? "text-emerald-600 dark:text-emerald-400"
                          : "text-red-600 dark:text-red-400"
                      }`}
                    >
                      {comparison.deltas.scoreDelta >= 0 ? "+" : ""}
                      {comparison.deltas.scoreDelta}
                    </p>
                  </div>
                  <div>
                    <p className="text-[#617565] dark:text-[#98AD94]">Total Findings</p>
                    <p className="text-lg font-bold font-mono tabular-nums text-[#1B2B20] dark:text-[#F5F1E6]">
                      {comparison.deltas.totalDelta >= 0 ? "+" : ""}
                      {comparison.deltas.totalDelta}
                    </p>
                  </div>
                  <div>
                    <p className="text-[#617565] dark:text-[#98AD94]">Critical Delta</p>
                    <p className="text-lg font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
                      {comparison.deltas.criticalDelta >= 0 ? "+" : ""}
                      {comparison.deltas.criticalDelta}
                    </p>
                  </div>
                  <div>
                    <p className="text-[#617565] dark:text-[#98AD94]">High Delta</p>
                    <p className="text-lg font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
                      {comparison.deltas.highDelta >= 0 ? "+" : ""}
                      {comparison.deltas.highDelta}
                    </p>
                  </div>
                  <div>
                    <p className="text-[#617565] dark:text-[#98AD94]">Medium Delta</p>
                    <p className="text-lg font-bold font-mono tabular-nums text-sky-600 dark:text-sky-400">
                      {comparison.deltas.mediumDelta >= 0 ? "+" : ""}
                      {comparison.deltas.mediumDelta}
                    </p>
                  </div>
                  <div>
                    <p className="text-[#617565] dark:text-[#98AD94]">Low Delta</p>
                    <p className="text-lg font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
                      {comparison.deltas.lowDelta >= 0 ? "+" : ""}
                      {comparison.deltas.lowDelta}
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Scans Table */}
          <div className="rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] overflow-hidden">
            <div className="px-6 py-4 border-b border-[#D5E2C8] dark:border-[#2A3D30] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <span className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                {filtered.length} Scan Record(s)
              </span>
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter by project or language..."
                className="px-3 py-1.5 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
              />
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-[#D5E2C8] dark:border-[#2A3D30] bg-[#EEF5E6]/60 dark:bg-[#141E17] text-[#617565] dark:text-[#98AD94]">
                  <tr>
                    <th className="py-3 px-6 font-medium">Project &amp; Timestamp</th>
                    <th className="py-3 px-4 font-medium">Languages</th>
                    <th className="py-3 px-4 font-medium text-right">Files</th>
                    <th className="py-3 px-4 font-medium text-right">Crit / High / Med / Low</th>
                    <th className="py-3 px-4 font-medium text-right">Score</th>
                    <th className="py-3 px-6 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#D5E2C8] dark:divide-[#2A3D30]">
                  {filtered.map((s) => (
                    <tr
                      key={s.id}
                      className="hover:bg-[#EEF5E6] dark:hover:bg-[#1C2A21] transition-colors"
                    >
                      <td className="py-3.5 px-6">
                        <div className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                          {s.projectName}
                        </div>
                        <div className="text-[11px] text-[#617565] dark:text-[#98AD94] mt-0.5">
                          {new Date(s.createdAt).toLocaleString()} · #{s.id}
                          {s.isDemo ? " · Demo Mode" : ""}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-[#4A5E4E] dark:text-[#C4D3BF]">
                        {s.language}
                      </td>
                      <td className="py-3.5 px-4 text-right font-mono tabular-nums text-[#4A5E4E] dark:text-[#C4D3BF]">
                        {s.filesScanned}
                      </td>
                      <td className="py-3.5 px-4 text-right font-mono tabular-nums text-[#4A5E4E] dark:text-[#C4D3BF]">
                        <span className="text-red-500">{s.severityCounts.critical}</span> /{" "}
                        <span className="text-amber-500">{s.severityCounts.high}</span> /{" "}
                        <span className="text-sky-500">{s.severityCounts.medium}</span> /{" "}
                        <span className="text-emerald-500">{s.severityCounts.low}</span>
                      </td>
                      <td
                        className={`py-3.5 px-4 text-right font-mono tabular-nums font-bold ${getScoreColorClass(
                          s.securityScore
                        )}`}
                      >
                        {s.securityScore}/100
                      </td>
                      <td className="py-3.5 px-6 text-right">
                        <div className="inline-flex items-center gap-3">
                          <button
                            type="button"
                            onClick={() => onOpenScan(s.id)}
                            className="inline-flex items-center gap-1 text-[#3D6A39] dark:text-[#A5D190] hover:underline font-semibold cursor-pointer"
                          >
                            <span>Open</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDelete(s.id)}
                            aria-label={`Delete scan ${s.projectName}`}
                            className="text-[#617565] hover:text-red-500 p-1 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
