import React, { useEffect, useRef, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Code2,
  FileArchive,
  FlaskConical,
  Loader2,
  Shield,
  Trash2,
  Upload,
} from "lucide-react";
import { api } from "../lib/api";
import { ScanJobStatus } from "../types";

interface ScannerViewProps {
  defaultLanguage: string;
  onScanComplete: (scanId: number) => void;
  onRunDemoScan: () => Promise<void>;
  demoRunning: boolean;
}

const SUPPORTED_LANGUAGES = [
  "Auto-Detect",
  "Python",
  "JavaScript",
  "TypeScript",
  "Java",
  "PHP",
  "C",
  "C++",
];

const ALLOWED_EXTENSIONS = [
  ".py",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".java",
  ".php",
  ".c",
  ".h",
  ".cpp",
  ".hpp",
  ".cc",
  ".cxx",
  ".zip",
];

export function ScannerView({
  defaultLanguage,
  onScanComplete,
  onRunDemoScan,
  demoRunning,
}: ScannerViewProps) {
  const [inputMode, setInputMode] = useState<"upload" | "paste">("upload");
  const [projectName, setProjectName] = useState("");
  const [language, setLanguage] = useState(defaultLanguage || "Auto-Detect");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [pastedFilename, setPastedFilename] = useState("app.py");
  const [pastedCode, setPastedCode] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [job, setJob] = useState<ScanJobStatus | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!job || job.stage === "completed" || job.stage === "failed") return;
    const timer = window.setInterval(async () => {
      try {
        const latest = await api.getJobStatus(job.jobId);
        setJob(latest);
        if (latest.stage === "completed" && latest.scanId) {
          window.clearInterval(timer);
          setSubmitting(false);
          onScanComplete(latest.scanId);
        } else if (latest.stage === "failed") {
          window.clearInterval(timer);
          setSubmitting(false);
          setError(latest.error || latest.message || "Static analysis failed.");
        }
      } catch (err) {
        window.clearInterval(timer);
        setSubmitting(false);
        setError(err instanceof Error ? err.message : "Lost connection while polling scan job.");
      }
    }, 500);

    return () => window.clearInterval(timer);
  }, [job, onScanComplete]);

  const validateAndAddFiles = (incoming: FileList | File[]) => {
    setError(null);
    const list = Array.from(incoming);
    const valid: File[] = [];
    for (const file of list) {
      const lower = file.name.toLowerCase();
      const hasValidExt = ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
      if (!hasValidExt) {
        setError(
          `Unsupported file '${file.name}'. Allowed: Python, JS, TS, Java, PHP, C, C++, or .zip.`
        );
        return;
      }
      const maxSize = lower.endsWith(".zip") ? 15 * 1024 * 1024 : 5 * 1024 * 1024;
      if (file.size > maxSize) {
        setError(`File '${file.name}' exceeds size limit (${lower.endsWith(".zip") ? "15 MB" : "5 MB"}).`);
        return;
      }
      valid.push(file);
    }
    setSelectedFiles((prev) => [...prev, ...valid]);
    if (!projectName && valid[0]) {
      setProjectName(valid[0].name.replace(/\.[^.]+$/, ""));
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files?.length) {
      validateAndAddFiles(e.dataTransfer.files);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanProject = projectName.trim() || "Security Audit";
    if (inputMode === "upload" && selectedFiles.length === 0) {
      setError("Please select at least one source file or a .zip repository archive.");
      return;
    }
    if (inputMode === "paste" && !pastedCode.trim()) {
      setError("Please paste source code to analyze.");
      return;
    }

    const formData = new FormData();
    formData.append("projectName", cleanProject);
    formData.append("language", language);

    if (inputMode === "upload") {
      for (const f of selectedFiles) {
        formData.append("files", f);
      }
    } else {
      formData.append("filename", pastedFilename.trim() || "snippet.py");
      formData.append("code", pastedCode);
    }

    setSubmitting(true);
    try {
      const initialJob = await api.uploadScan(formData);
      setJob(initialJob);
    } catch (err) {
      setSubmitting(false);
      setError(err instanceof Error ? err.message : "Failed to submit code scan.");
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
            Static Code Scanning Engine
          </h1>
          <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
            Upload individual files, ZIP archives, or paste source code for AST &amp; Semgrep-aligned static analysis.
          </p>
        </div>

        <button
          type="button"
          onClick={onRunDemoScan}
          disabled={demoRunning || submitting}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-[#1B2B20] dark:text-[#F5F1E6] hover:border-[#7FB16B] rounded-lg transition-colors disabled:opacity-60 whitespace-nowrap cursor-pointer"
        >
          <FlaskConical className="w-3.5 h-3.5 text-[#3D6A39] dark:text-[#A5D190]" />
          <span>{demoRunning ? "Running Demo Scan..." : "Run Demo Mode Sample"}</span>
        </button>
      </div>

      {/* Mode Switch */}
      <div className="inline-flex p-1 rounded-lg bg-[#EEF5E6] dark:bg-[#141E17] border border-[#D5E2C8] dark:border-[#2A3D30]">
        <button
          type="button"
          onClick={() => {
            setInputMode("upload");
            setError(null);
          }}
          className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
            inputMode === "upload"
              ? "bg-[#FFFDF7] dark:bg-[#223326] text-[#1B2B20] dark:text-[#F5F1E6] border border-[#D5E2C8] dark:border-[#2A3D30]"
              : "text-[#4A5E4E] dark:text-[#98AD94] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
          }`}
        >
          <FileArchive className="w-3.5 h-3.5" />
          <span>Upload Files or ZIP</span>
        </button>
        <button
          type="button"
          onClick={() => {
            setInputMode("paste");
            setError(null);
          }}
          className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
            inputMode === "paste"
              ? "bg-[#FFFDF7] dark:bg-[#223326] text-[#1B2B20] dark:text-[#F5F1E6] border border-[#D5E2C8] dark:border-[#2A3D30]"
              : "text-[#4A5E4E] dark:text-[#98AD94] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
          }`}
        >
          <Code2 className="w-3.5 h-3.5" />
          <span>Paste Source Code</span>
        </button>
      </div>

      {error && (
        <div
          role="alert"
          className="p-4 rounded-xl border border-red-300 dark:border-red-500/40 bg-red-50 dark:bg-red-950/30 flex items-start gap-3 text-xs text-red-700 dark:text-red-300"
        >
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Real-time Pipeline Progress Banner */}
      {job && job.stage !== "failed" && (
        <div className="p-6 rounded-xl border border-[#7FB16B] dark:border-[#4D7843] bg-[#FFFDF7] dark:bg-[#17221B] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              {job.stage === "completed" ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <Loader2 className="w-5 h-5 text-[#3D6A39] dark:text-[#A5D190] animate-spin" />
              )}
              <div>
                <p className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                  Scanning {job.projectName}
                </p>
                <p className="text-xs text-[#617565] dark:text-[#98AD94]">{job.message}</p>
              </div>
            </div>
            <span className="text-sm font-mono tabular-nums font-bold text-[#3D6A39] dark:text-[#A5D190]">
              {job.progress}%
            </span>
          </div>

          <div className="h-2 rounded-full bg-[#E7F1DC] dark:bg-[#0D130F] overflow-hidden">
            <div
              className="h-full bg-[#7FB16B] dark:bg-[#9BC585] transition-all duration-300"
              style={{ width: `${job.progress}%` }}
            />
          </div>

          <div className="grid grid-cols-4 gap-2 text-[11px] text-[#617565] dark:text-[#98AD94]">
            {["validating", "extracting", "scanning", "scoring"].map((st, idx) => {
              const stageOrder = ["validating", "extracting", "scanning", "scoring", "completed"];
              const currentIdx = stageOrder.indexOf(job.stage);
              const done = currentIdx > idx || job.stage === "completed";
              const active = currentIdx === idx;
              return (
                <div
                  key={st}
                  className={`capitalize ${
                    done
                      ? "text-[#3D6A39] dark:text-[#A5D190] font-semibold"
                      : active
                      ? "text-[#2E592C] dark:text-[#C9E7BA] font-semibold"
                      : ""
                  }`}
                >
                  {idx + 1}. {st}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-6"
      >
        <div className="grid sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
              Project / Audit Name
            </label>
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="payments-api-service"
              maxLength={100}
              className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
              Target Language
            </label>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
            >
              {SUPPORTED_LANGUAGES.map((lang) => (
                <option key={lang} value={lang}>
                  {lang}
                </option>
              ))}
            </select>
          </div>
        </div>

        {inputMode === "upload" ? (
          <div className="space-y-4">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
                dragActive
                  ? "border-[#6A9E58] bg-[#E7F1DC] dark:bg-[#223326]"
                  : "border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED]/70 dark:bg-[#0D130F]/60 hover:border-[#7FB16B]"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept={ALLOWED_EXTENSIONS.join(",")}
                onChange={(e) => {
                  if (e.target.files?.length) validateAndAddFiles(e.target.files);
                }}
                className="hidden"
              />
              <Upload className="w-8 h-8 text-[#3D6A39] dark:text-[#A5D190] mx-auto mb-3" />
              <p className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1">
                Drop source files or a .zip archive here, or click to browse
              </p>
              <p className="text-xs text-[#617565] dark:text-[#98AD94]">
                Supports .py, .js, .jsx, .ts, .tsx, .java, .php, .c, .cpp, .h, .hpp (max 5 MB/file) and .zip (max 15 MB)
              </p>
            </div>

            {selectedFiles.length > 0 && (
              <div className="divide-y divide-[#D5E2C8] dark:divide-[#2A3D30] border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] rounded-lg">
                {selectedFiles.map((file, idx) => (
                  <div
                    key={`${file.name}-${idx}`}
                    className="px-4 py-2.5 flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="font-mono text-[#1B2B20] dark:text-[#F5F1E6] truncate">
                        {file.name}
                      </span>
                      <span className="text-[#617565] dark:text-[#98AD94] tabular-nums shrink-0">
                        {(file.size / 1024).toFixed(1)} KB
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setSelectedFiles((prev) => prev.filter((_, i) => i !== idx))
                      }
                      aria-label={`Remove ${file.name}`}
                      className="text-[#617565] hover:text-red-500 p-1 cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Virtual Filename (determines extension routing)
              </label>
              <input
                type="text"
                value={pastedFilename}
                onChange={(e) => setPastedFilename(e.target.value)}
                placeholder="handler.py"
                className="w-full px-3.5 py-2 text-sm font-mono rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Source Code
              </label>
              <textarea
                rows={12}
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                placeholder="Paste Python, JavaScript, TypeScript, Java, PHP, C, or C++ source code..."
                className="w-full px-3.5 py-3 text-xs font-mono leading-relaxed rounded-lg border border-[#2D4233] bg-[#162119] text-[#D9ECCB] placeholder:text-[#98AD94]/70 focus:outline-none focus:border-[#7FB16B]"
              />
            </div>
          </div>
        )}

        <div className="pt-4 border-t border-[#D5E2C8] dark:border-[#2A3D30] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-xs text-[#617565] dark:text-[#98AD94]">
            <Shield className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
            <span>
              Uploaded source code is parsed strictly as untrusted text and never executed.
            </span>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="px-6 py-2.5 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {submitting ? "Analyzing Codebase..." : "Run Security Scan"}
          </button>
        </div>
      </form>
    </div>
  );
}
