import React, { useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  ArrowLeft,
  Check,
  Copy,
  Download,
  FileCode,
  Loader2,
  Search,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { api } from "../lib/api";
import { downloadSecurityPdfReport } from "../lib/pdfReport";
import { ScanSummary, SeverityLevel, VulnerabilityFinding } from "../types";
import { SecurityShield3D } from "./SecurityShield3D";
import { getScoreColorClass, SeverityLabel } from "./SeverityLabel";

interface ScanReportViewProps {
  scanId: number | null;
  focusVulnId?: number | null;
  onBackToHistory: () => void;
  onStartNewScan: () => void;
}

export function ScanReportView({
  scanId,
  focusVulnId,
  onBackToHistory,
  onStartNewScan,
}: ScanReportViewProps) {
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityFinding[]>([]);
  const [selectedVulnId, setSelectedVulnId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<"all" | SeverityLevel>("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");

  const [analyzingId, setAnalyzingId] = useState<number | null>(null);
  const [batchAnalyzing, setBatchAnalyzing] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  const loadScan = async (id: number) => {
    setLoading(true);
    setError(null);
    setAiError(null);
    try {
      const res = await api.getScan(id);
      setScan(res.scan);
      setVulnerabilities(res.vulnerabilities);
      if (focusVulnId && res.vulnerabilities.some((v) => v.id === focusVulnId)) {
        setSelectedVulnId(focusVulnId);
      } else if (res.vulnerabilities.length > 0) {
        setSelectedVulnId(res.vulnerabilities[0].id);
      } else {
        setSelectedVulnId(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan report.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (scanId !== null) {
      void loadScan(scanId);
    }
  }, [scanId, focusVulnId]);

  const categories = useMemo(() => {
    const set = new Set(vulnerabilities.map((v) => v.category));
    return Array.from(set).sort();
  }, [vulnerabilities]);

  const filteredVulns = useMemo(() => {
    return vulnerabilities.filter((v) => {
      if (severityFilter !== "all" && v.severity !== severityFilter) return false;
      if (categoryFilter !== "all" && v.category !== categoryFilter) return false;
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const hay = `${v.title} ${v.filePath} ${v.cweId} ${v.category}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [vulnerabilities, severityFilter, categoryFilter, searchTerm]);

  const selectedVuln =
    filteredVulns.find((v) => v.id === selectedVulnId) ||
    vulnerabilities.find((v) => v.id === selectedVulnId) ||
    filteredVulns[0] ||
    null;

  const handleAnalyzeFinding = async (vulnId: number, force = false) => {
    setAnalyzingId(vulnId);
    setAiError(null);
    try {
      const res = await api.analyzeVulnerability(vulnId, force);
      setVulnerabilities((prev) =>
        prev.map((item) => (item.id === vulnId ? res.vulnerability : item))
      );
    } catch (err) {
      setAiError(err instanceof Error ? err.message : "Gemini AI analysis failed.");
    } finally {
      setAnalyzingId(null);
    }
  };

  const handleBatchAnalyze = async () => {
    if (!scan) return;
    setBatchAnalyzing(true);
    setAiError(null);
    try {
      await api.analyzeScanBatch(scan.id);
      await loadScan(scan.id);
    } catch (err) {
      setAiError(err instanceof Error ? err.message : "Batch Gemini analysis failed.");
    } finally {
      setBatchAnalyzing(false);
    }
  };

  const handleCopyCode = async (vulnId: number, code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedId(vulnId);
      window.setTimeout(() => setCopiedId(null), 1800);
    } catch {
      // clipboard fallback ignored
    }
  };

  if (scanId === null) {
    return (
      <div className="p-10 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-center max-w-xl mx-auto mt-6 space-y-4">
        <FileCode className="w-9 h-9 text-[#3D6A39] dark:text-[#A5D190] mx-auto" />
        <h2 className="text-lg font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
          Select or run a scan to inspect findings
        </h2>
        <p className="text-sm text-[#617565] dark:text-[#98AD94]">
          Open any historical audit from Scan History or upload new source files to inspect
          vulnerabilities, risk scores, and AI remediations.
        </p>
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            type="button"
            onClick={onStartNewScan}
            className="px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg cursor-pointer"
          >
            New Code Scan
          </button>
          <button
            type="button"
            onClick={onBackToHistory}
            className="px-4 py-2 text-xs font-semibold border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] hover:border-[#7FB16B] rounded-lg cursor-pointer"
          >
            View Scan History
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-36 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]" />
        <div className="h-96 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="p-8 rounded-xl border border-red-300 dark:border-red-500/40 bg-[#FFFDF7] dark:bg-[#17221B] text-center space-y-3">
        <AlertCircle className="w-8 h-8 text-red-500 mx-auto" />
        <p className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">{error}</p>
        <button
          type="button"
          onClick={onBackToHistory}
          className="px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg cursor-pointer"
        >
          Return to History
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Action Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <button
            type="button"
            onClick={onBackToHistory}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-[#617565] dark:text-[#98AD94] hover:text-[#3D6A39] dark:hover:text-[#A5D190] mb-1 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Scan History</span>
          </button>
          <h1 className="text-2xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
            {scan.projectName}
          </h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#617565] dark:text-[#98AD94]">
            <span>{new Date(scan.createdAt).toLocaleString()}</span>
            <span aria-hidden="true">·</span>
            <span>{scan.language}</span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">
              {scan.filesScanned} file(s) ({scan.totalLines} lines)
            </span>
            <span aria-hidden="true">·</span>
            <span>Engines: {scan.enginesUsed.join(", ")}</span>
            {scan.isDemo && (
              <>
                <span aria-hidden="true">·</span>
                <span className="font-semibold text-[#3D6A39] dark:text-[#A5D190]">
                  Demo Mode Sample
                </span>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          {vulnerabilities.some((v) => !v.aiAnalysis) && (
            <button
              type="button"
              onClick={handleBatchAnalyze}
              disabled={batchAnalyzing}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold border border-[#7FB16B] dark:border-[#4D7843] bg-[#EEF5E6] dark:bg-[#223326] text-[#2E592C] dark:text-[#A5D190] hover:bg-[#E7F1DC] dark:hover:bg-[#2A3F2F] rounded-lg transition-colors disabled:opacity-60 cursor-pointer"
            >
              {batchAnalyzing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Sparkles className="w-3.5 h-3.5" />
              )}
              <span>
                {batchAnalyzing ? "Analyzing Top Findings..." : "Analyze Top Findings with Gemini"}
              </span>
            </button>
          )}
          <button
            type="button"
            onClick={() => downloadSecurityPdfReport(scan, vulnerabilities)}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF Report</span>
          </button>
        </div>
      </div>

      {/* Security Risk Scoring Card with Interactive 3D Risk Core */}
      <div className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-2 h-40 lg:h-auto rounded-lg overflow-hidden border border-[#CBE0B9] dark:border-[#2A3D30] bg-[#EDF3E5]">
          <SecurityShield3D variant="compact" score={scan.securityScore} />
        </div>

        <div className="lg:col-span-3 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-[#D5E2C8] dark:border-[#2A3D30] pb-5 lg:pb-0 lg:pr-6">
          <div>
            <p className="text-xs font-medium text-[#617565] dark:text-[#98AD94] mb-1">
              Security Posture Score
            </p>
            <div className="flex items-baseline gap-2">
              <span
                className={`text-4xl font-bold font-mono tabular-nums ${getScoreColorClass(
                  scan.securityScore
                )}`}
              >
                {scan.securityScore}
              </span>
              <span className="text-sm text-[#617565] dark:text-[#98AD94] font-mono">/ 100</span>
              <span className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] ml-auto">
                {scan.riskClassification}
              </span>
            </div>
            <div className="mt-3 h-2 rounded-full bg-[#E7F1DC] dark:bg-[#0D130F] overflow-hidden">
              <div
                className={`h-full transition-all ${
                  scan.securityScore >= 90
                    ? "bg-emerald-500"
                    : scan.securityScore >= 70
                    ? "bg-[#7FB16B]"
                    : scan.securityScore >= 45
                    ? "bg-amber-500"
                    : "bg-red-500"
                }`}
                style={{ width: `${scan.securityScore}%` }}
              />
            </div>
          </div>
          <p className="text-[11px] text-[#617565] dark:text-[#98AD94] mt-4 leading-relaxed">
            Application-defined risk indicator based on weighted static-analysis severity and
            category multipliers. Not a formal security certification.
          </p>
        </div>

        <div className="lg:col-span-3 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-2 gap-4 border-b lg:border-b-0 lg:border-r border-[#D5E2C8] dark:border-[#2A3D30] pb-5 lg:pb-0 lg:pr-6">
          <div>
            <p className="text-xs text-[#617565] dark:text-[#98AD94]">Critical</p>
            <p className="text-2xl font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
              {scan.severityCounts.critical}
            </p>
          </div>
          <div>
            <p className="text-xs text-[#617565] dark:text-[#98AD94]">High</p>
            <p className="text-2xl font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
              {scan.severityCounts.high}
            </p>
          </div>
          <div>
            <p className="text-xs text-[#617565] dark:text-[#98AD94]">Medium</p>
            <p className="text-2xl font-bold font-mono tabular-nums text-sky-600 dark:text-sky-400">
              {scan.severityCounts.medium}
            </p>
          </div>
          <div>
            <p className="text-xs text-[#617565] dark:text-[#98AD94]">Low</p>
            <p className="text-2xl font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
              {scan.severityCounts.low}
            </p>
          </div>
        </div>

        <div className="lg:col-span-4 space-y-2">
          <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
            Priority Improvement Suggestions
          </p>
          <ul className="space-y-1.5 text-xs text-[#4A5E4E] dark:text-[#C4D3BF]">
            {scan.improvementSuggestions.map((item, idx) => (
              <li key={idx} className="leading-relaxed">
                {idx + 1}. {item}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Findings Section */}
      {vulnerabilities.length === 0 ? (
        <div className="p-10 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-center space-y-3">
          <ShieldCheck className="w-10 h-10 text-emerald-600 dark:text-emerald-400 mx-auto" />
          <h2 className="text-lg font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
            Zero static vulnerabilities detected
          </h2>
          <p className="text-sm text-[#617565] dark:text-[#98AD94] max-w-lg mx-auto">
            Our Python AST and static rule engines scanned {scan.filesScanned} file(s) and found no
            matching vulnerability patterns.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Filter Controls */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-[#EEF5E6] dark:bg-[#141E17] border border-[#D5E2C8] dark:border-[#2A3D30]">
              {(["all", "critical", "high", "medium", "low"] as const).map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setSeverityFilter(lvl)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md capitalize transition-colors cursor-pointer ${
                    severityFilter === lvl
                      ? "bg-[#9BC585] text-[#142617]"
                      : "text-[#4A5E4E] dark:text-[#98AD94] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                aria-label="Filter by vulnerability category"
                className="px-3 py-2 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              >
                <option value="all">All Categories</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>

              <div className="relative">
                <Search className="w-3.5 h-3.5 text-[#617565] dark:text-[#98AD94] absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search file, CWE, or title..."
                  className="pl-8 pr-3 py-2 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
                />
              </div>
            </div>
          </div>

          {/* Master-Detail Vulnerability Inspector */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <div className="lg:col-span-5 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] divide-y divide-[#D5E2C8] dark:divide-[#2A3D30] max-h-[760px] overflow-y-auto">
              {filteredVulns.length === 0 ? (
                <div className="p-6 text-xs text-[#617565] dark:text-[#98AD94] text-center">
                  No findings match the current filter criteria.
                </div>
              ) : (
                filteredVulns.map((v) => {
                  const active = selectedVuln?.id === v.id;
                  return (
                    <button
                      key={v.id}
                      type="button"
                      onClick={() => {
                        setSelectedVulnId(v.id);
                        setAiError(null);
                      }}
                      className={`w-full text-left p-4 transition-colors cursor-pointer ${
                        active
                          ? "bg-[#E7F1DC] dark:bg-[#223326]"
                          : "hover:bg-[#EEF5E6] dark:hover:bg-[#1C2A21]"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <SeverityLabel severity={v.severity} compact />
                        <span className="text-[11px] font-mono text-[#617565] dark:text-[#98AD94]">
                          {v.cweId}
                        </span>
                      </div>
                      <p className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] leading-snug">
                        {v.title}
                      </p>
                      <div className="mt-1.5 flex items-center justify-between gap-2 text-[11px] text-[#617565] dark:text-[#98AD94]">
                        <span className="font-mono truncate">
                          {v.filePath}:{v.lineNumber}
                        </span>
                        {v.aiAnalysis && (
                          <span className="text-[#3D6A39] dark:text-[#A5D190] font-medium shrink-0">
                            AI Analyzed
                          </span>
                        )}
                      </div>
                    </button>
                  );
                })
              )}
            </div>

            <div className="lg:col-span-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] p-6 space-y-6">
              {selectedVuln ? (
                <>
                  <div className="pb-5 border-b border-[#D5E2C8] dark:border-[#2A3D30]">
                    <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
                      <SeverityLabel severity={selectedVuln.severity} />
                      <span className="text-xs font-mono text-[#617565] dark:text-[#98AD94]">
                        Static Source: {selectedVuln.scannerSource} · Rule {selectedVuln.ruleId}
                      </span>
                    </div>
                    <h2 className="text-xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                      {selectedVuln.title}
                    </h2>
                    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#617565] dark:text-[#98AD94]">
                      <span className="font-mono text-[#1B2B20] dark:text-[#F5F1E6]">
                        {selectedVuln.filePath} (Line {selectedVuln.lineNumber})
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{selectedVuln.cweId}</span>
                      <span aria-hidden="true">·</span>
                      <span>{selectedVuln.owaspCategory}</span>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <h3 className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                      Static Analysis Finding
                    </h3>
                    <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                      {selectedVuln.staticSummary}
                    </p>
                    <div>
                      <p className="text-xs font-medium text-[#617565] dark:text-[#98AD94] mb-1.5">
                        Vulnerable Code Context
                      </p>
                      <pre className="p-4 rounded-lg border border-[#2D4233] bg-[#162119] text-xs font-mono text-red-200 overflow-x-auto leading-relaxed">
                        {selectedVuln.codeSnippet}
                      </pre>
                    </div>
                    <div className="p-4 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
                      <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1">
                        Baseline Static Remediation Guidance
                      </p>
                      <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                        {selectedVuln.staticRemediation}
                      </p>
                    </div>
                  </div>

                  <div className="pt-5 border-t border-[#D5E2C8] dark:border-[#2A3D30] space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h3 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] flex items-center gap-2">
                          <Sparkles className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
                          <span>AI-Powered Vulnerability Analysis (Gemini)</span>
                        </h3>
                        <p className="text-xs text-[#617565] dark:text-[#98AD94]">
                          Contextual explanation and secure code rewrite generated strictly for this
                          verified static finding
                        </p>
                      </div>

                      <button
                        type="button"
                        onClick={() =>
                          handleAnalyzeFinding(selectedVuln.id, Boolean(selectedVuln.aiAnalysis))
                        }
                        disabled={analyzingId === selectedVuln.id}
                        className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] disabled:opacity-60 rounded-lg transition-colors cursor-pointer"
                      >
                        {analyzingId === selectedVuln.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Sparkles className="w-3.5 h-3.5" />
                        )}
                        <span>
                          {analyzingId === selectedVuln.id
                            ? "Analyzing with Gemini..."
                            : selectedVuln.aiAnalysis
                            ? "Regenerate AI Fix"
                            : "Analyze with Gemini"}
                        </span>
                      </button>
                    </div>

                    {aiError && (
                      <div
                        role="alert"
                        className="p-3.5 rounded-lg border border-red-300 dark:border-red-500/40 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300"
                      >
                        {aiError}
                      </div>
                    )}

                    {selectedVuln.aiAnalysis ? (
                      <div className="space-y-4">
                        <div className="grid sm:grid-cols-2 gap-4">
                          <div className="p-4 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
                            <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1.5">
                              Plain-Language Explanation
                            </p>
                            <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                              {selectedVuln.aiAnalysis.plainExplanation}
                            </p>
                          </div>

                          <div className="p-4 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
                            <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1.5">
                              Potential Security Impact
                            </p>
                            <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                              {selectedVuln.aiAnalysis.potentialImpact}
                            </p>
                          </div>
                        </div>

                        <div className="p-4 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
                          <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1.5">
                            Recommended Secure Coding Practices
                          </p>
                          <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                            {selectedVuln.aiAnalysis.recommendedFix}
                          </p>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-1.5">
                            <p className="text-xs font-semibold text-[#3D6A39] dark:text-[#A5D190]">
                              Corrected Secure Code Implementation
                            </p>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopyCode(
                                  selectedVuln.id,
                                  selectedVuln.aiAnalysis!.secureCodeExample
                                )
                              }
                              className="inline-flex items-center gap-1 text-xs text-[#617565] hover:text-[#1B2B20] dark:text-[#98AD94] dark:hover:text-[#F5F1E6] cursor-pointer"
                            >
                              {copiedId === selectedVuln.id ? (
                                <>
                                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                                  <span>Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5" />
                                  <span>Copy Code</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-4 rounded-lg border border-[#2D4233] bg-[#162119] text-xs font-mono text-[#D9ECCB] overflow-x-auto leading-relaxed">
                            {selectedVuln.aiAnalysis.secureCodeExample}
                          </pre>
                        </div>

                        <div className="p-4 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
                          <p className="text-xs font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1">
                            Vulnerable vs. Secure Implementation Difference
                          </p>
                          <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                            {selectedVuln.aiAnalysis.diffSummary}
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="p-5 rounded-lg border border-dashed border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED]/60 dark:bg-[#0D130F]/50 text-xs text-[#617565] dark:text-[#98AD94]">
                        Click <strong>Analyze with Gemini</strong> to generate an AI-assisted
                        explanation, exploit impact assessment, and secure code replacement for this
                        finding.
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <p className="text-sm text-[#617565] dark:text-[#98AD94]">
                  Select a vulnerability from the list to inspect its details.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
