import React, { useState } from "react";
import {
  ArrowRight,
  BookOpen,
  Check,
  CheckCircle2,
  Code2,
  Cpu,
  Database,
  FileArchive,
  FileText,
  Layers,
  Lock,
  Menu,
  ShieldAlert,
  Sparkles,
  Terminal,
  X,
} from "lucide-react";
import { SecurityShield3D } from "./SecurityShield3D";
import { TiltCard3D } from "./TiltCard3D";
import { PIPELINE_STAGES, Pipeline3DShowcase, PipelineStageId } from "./Pipeline3DShowcase";
import { RuleCatalogView } from "./RuleCatalogView";

type PublicPage = "platform" | "3d-lab" | "rules" | "plans" | "docs";

interface LandingPageProps {
  onOpenAuth: (mode: "login" | "register") => void;
  isAuthenticated: boolean;
  onEnterConsole: () => void;
}

const NAV_PAGES: Array<{ id: PublicPage; label: string }> = [
  { id: "platform", label: "Platform" },
  { id: "3d-lab", label: "3D Lab" },
  { id: "rules", label: "Rule Catalog" },
  { id: "plans", label: "Plans" },
  { id: "docs", label: "Docs" },
];

const LANGUAGES = [
  { name: "Python", detail: "AST + Semgrep rules for Flask, Django, sqlite3, subprocess, pickle" },
  { name: "JavaScript", detail: "DOM XSS sinks, eval/exec, SQL interpolation, weak crypto" },
  { name: "TypeScript", detail: "Strict server & client taint patterns, SSRF, path confinement" },
  { name: "Java", detail: "JDBC query building, ObjectInputStream, Runtime.exec, MessageDigest" },
  { name: "PHP", detail: "Superglobal output escaping, mysqli_query, unserialize, file uploads" },
  { name: "C", detail: "Unbounded buffer copies (strcpy, gets, sprintf) and shell calls" },
  { name: "C++", detail: "Memory-unsafe string primitives, command execution, file permissions" },
];

const SIMULATOR_SAMPLES = [
  {
    id: "python",
    lang: "Python",
    file: "auth_service.py",
    line: 14,
    rule: "SQL Injection · CWE-89 · OWASP A03:2021",
    severity: "Critical",
    vulnerable: `def find_user(db_conn, email):\n    cursor = db_conn.cursor()\n    query = f"SELECT id, role FROM users WHERE email = '{email}'"\n    return cursor.execute(query).fetchone()`,
    remediated: `def find_user(db_conn, email):\n    cursor = db_conn.cursor()\n    query = "SELECT id, role FROM users WHERE email = ?"\n    return cursor.execute(query, (email,)).fetchone()`,
    explanation:
      "Interpolating user-controlled email directly into SQL allows attackers to alter query logic. Parameterized placeholders bind input strictly as data.",
  },
  {
    id: "typescript",
    lang: "TypeScript",
    file: "webhookProxy.ts",
    line: 22,
    rule: "Server-Side Request Forgery · CWE-918 · OWASP A10:2021",
    severity: "High",
    vulnerable: `export async function fetchWebhook(req: Request) {\n  const targetUrl = new URL(req.url).searchParams.get("target")!;\n  const res = await fetch(targetUrl);\n  return res.text();\n}`,
    remediated: `export async function fetchWebhook(req: Request) {\n  const parsed = assertAllowedHttpsOrigin(new URL(req.url).searchParams.get("target"));\n  const res = await fetch(parsed.toString(), { redirect: "error" });\n  return res.text();\n}`,
    explanation:
      "Unvalidated outbound fetches permit requests to internal metadata endpoints (169.254.169.254). Enforce an explicit HTTPS host allowlist and disable redirects.",
  },
  {
    id: "java",
    lang: "Java",
    file: "SessionLoader.java",
    line: 31,
    rule: "Insecure Deserialization · CWE-502 · OWASP A08:2021",
    severity: "Critical",
    vulnerable: `ObjectInputStream ois = new ObjectInputStream(req.getInputStream());\nUserSession session = (UserSession) ois.readObject();`,
    remediated: `ObjectMapper mapper = new ObjectMapper();\nUserSession session = mapper.readValue(req.getInputStream(), UserSession.class);`,
    explanation:
      "Java ObjectInputStream instantiates arbitrary classes on the classpath during readObject(), enabling remote code execution gadgets. Parse strict JSON DTOs instead.",
  },
  {
    id: "cpp",
    lang: "C++",
    file: "archive_helper.cpp",
    line: 19,
    rule: "Command Injection · CWE-78 · OWASP A03:2021",
    severity: "Critical",
    vulnerable: `std::string cmd = "unzip -q " + userArchivePath + " -d /tmp/work";\nstd::system(cmd.c_str());`,
    remediated: `execve("/usr/bin/unzip", argvWithValidatedPath, safeEnv);`,
    explanation:
      "Passing concatenated filenames to std::system() invokes a shell interpreter where metacharacters like ';' execute arbitrary commands.",
  },
];

const DOC_SECTIONS = [
  {
    id: "quickstart",
    title: "Architecture & Quick Start",
    icon: Terminal,
    summary:
      "Run the full-stack SecureScan AI engine locally with Express + Vite, Python 3.11 AST inspection, SQLite persistence, and server-side Gemini remediation.",
    blocks: [
      {
        heading: "1. Environment Setup (.env)",
        code: `GEMINI_API_KEY="your-server-side-key"\nAPP_URL="http://localhost:3000"`,
      },
      {
        heading: "2. Run Development Server & Python SAST",
        code: `npm install\nnpm run dev\n# Express mounts Vite on port 3000 and spawns python3 backend/scanner/engine.py`,
      },
    ],
  },
  {
    id: "api",
    title: "REST API Endpoints",
    icon: Layers,
    summary:
      "Both the TypeScript Express backend and the standalone Python Flask service (backend/app.py) expose identical Bearer-authenticated endpoints.",
    blocks: [
      {
        heading: "Core Scan & Analysis Routes",
        code: `POST   /api/auth/register        # Scrypt password hashing + session token\nPOST   /api/auth/login           # Issue Bearer token\nPOST   /api/scans/upload         # Multipart file / ZIP / raw code submission\nGET    /api/scans/jobs/:jobId    # Poll real-time scan stage & progress\nGET    /api/scans/:id            # Fetch score, CWE mapping, & static findings\nPOST   /api/vulnerabilities/:id/analyze  # Server-side Gemini remediation\nGET    /api/scans/compare        # Side-by-side historical posture delta`,
      },
    ],
  },
  {
    id: "rules-yml",
    title: "Semgrep YAML & Python AST Engine",
    icon: Code2,
    summary:
      "Static rules reside in backend/rules/securescan_rules.yml alongside Python AST visitors in backend/scanner/engine.py. When the Semgrep CLI is present in PATH, both engines merge automatically.",
    blocks: [
      {
        heading: "Sample Custom Rule Definition",
        code: `- id: securescan.python.sql-injection\n  languages: [python]\n  severity: ERROR\n  metadata:\n    cwe: CWE-89\n    owasp: A03:2021\n  pattern-either:\n    - pattern: $CURSOR.execute(f"...")\n    - pattern: $CURSOR.execute("..." + $VAR)`,
      },
    ],
  },
  {
    id: "database",
    title: "SQLite & PostgreSQL Migration",
    icon: Database,
    summary:
      "Scans, findings, and AI analyses persist in SQLite (data/securescan.db) out of the box, with a ready-to-apply PostgreSQL DDL migration script in backend/schema.postgres.sql.",
    blocks: [
      {
        heading: "Apply PostgreSQL Schema",
        code: `psql "$DATABASE_URL" -f backend/schema.postgres.sql`,
      },
    ],
  },
];

export function LandingPage({
  onOpenAuth,
  isAuthenticated,
  onEnterConsole,
}: LandingPageProps) {
  const [activePage, setActivePage] = useState<PublicPage>("platform");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeSimId, setActiveSimId] = useState<string>("python");
  const [pipelineStage, setPipelineStage] = useState<PipelineStageId>("overview");
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annual">("annual");
  const [activeDocId, setActiveDocId] = useState<string>("quickstart");
  const [pipelineImgFailed, setPipelineImgFailed] = useState(false);

  const handlePrimaryCta = () => {
    if (isAuthenticated) {
      onEnterConsole();
    } else {
      onOpenAuth("register");
    }
  };

  const navigatePage = (page: PublicPage) => {
    setActivePage(page);
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const activeSim =
    SIMULATOR_SAMPLES.find((s) => s.id === activeSimId) ?? SIMULATOR_SAMPLES[0];
  const activeDoc =
    DOC_SECTIONS.find((d) => d.id === activeDocId) ?? DOC_SECTIONS[0];

  return (
    <div className="min-h-screen flex flex-col bg-[#FAF6ED] text-[#1B2B20] dark:bg-[#101712] dark:text-[#F5F1E6]">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="sticky top-0 z-30 border-b border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7]/95 dark:bg-[#101712]/95">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
          <button
            type="button"
            onClick={() => navigatePage("platform")}
            className="text-lg font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] whitespace-nowrap shrink-0 font-display cursor-pointer"
          >
            SecureScan AI
          </button>

          <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-[#4A5E4E] dark:text-[#C4D3BF]">
            {NAV_PAGES.map((item) => {
              const active = activePage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigatePage(item.id)}
                  className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer py-1 border-b-2 ${
                    active
                      ? "text-[#2F592C] dark:text-[#A5D190] border-[#7FB16B] font-semibold"
                      : "border-transparent hover:text-[#2F592C] dark:hover:text-[#A5D190]"
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handlePrimaryCta}
              className="px-4 py-2 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {isAuthenticated ? "Open Console" : "Start Code Audit"}
            </button>
            <button
              type="button"
              onClick={() => setMobileMenuOpen((v) => !v)}
              aria-label="Toggle site navigation"
              className="md:hidden p-2 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] text-[#1B2B20] dark:text-[#F5F1E6] cursor-pointer"
            >
              {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Mobile Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] px-6 py-3 space-y-1">
            {NAV_PAGES.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => navigatePage(item.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium cursor-pointer ${
                  activePage === item.id
                    ? "bg-[#9BC585] text-[#142617] font-semibold"
                    : "text-[#354B3A] dark:text-[#C4D3BF] hover:bg-[#EEF5E6] dark:hover:bg-[#223326]"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
      </header>

      <main className="flex-1">
        {/* ==================== PAGE 1: PLATFORM (HOME) ==================== */}
        {activePage === "platform" && (
          <>
            {/* Hero Section with Interactive 3D WebGL Security Core */}
            <section className="max-w-7xl mx-auto px-6 pt-12 pb-16 lg:pt-18 lg:pb-24">
              <div className="grid lg:grid-cols-12 gap-12 items-stretch">
                <div className="lg:col-span-6 flex flex-col justify-center">
                  <p className="text-sm font-medium text-[#3D6A39] dark:text-[#A5D190] mb-4 tracking-wide">
                    Static Application Security Testing · Gemini Remediation
                  </p>
                  <h1
                    className="font-display font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] mb-6"
                    style={{
                      fontSize: "clamp(2.25rem, 4vw, 3.5rem)",
                      lineHeight: 1.12,
                      textWrap: "balance",
                    }}
                  >
                    Detect real code vulnerabilities before they reach production.
                  </h1>
                  <p className="text-base sm:text-lg text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed max-w-2xl mb-8">
                    SecureScan AI combines deterministic Python AST inspection and Semgrep-aligned
                    static rules with Google Gemini remediation guidance. Upload source files or
                    ZIP projects to uncover injection, authentication, cryptographic, and SSRF
                    flaws with clear before-and-after fixes.
                  </p>

                  <div className="flex flex-wrap items-center gap-3.5">
                    <button
                      type="button"
                      onClick={handlePrimaryCta}
                      className="inline-flex items-center gap-2 px-6 py-3 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <span>{isAuthenticated ? "Launch Security Console" : "Create Free Account"}</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                    <button
                      type="button"
                      onClick={() => navigatePage("3d-lab")}
                      className="inline-flex items-center gap-2 px-5 py-3 text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] bg-[#FFFDF7] dark:bg-[#17221B] border border-[#C3D6B1] dark:border-[#2A3D30] hover:border-[#7FB16B] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <Cpu className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
                      <span>Explore 3D Pipeline Lab</span>
                    </button>
                    {!isAuthenticated && (
                      <button
                        type="button"
                        onClick={() => onOpenAuth("login")}
                        className="px-4 py-3 text-sm font-semibold text-[#4A5E4E] dark:text-[#C4D3BF] hover:text-[#2F592C] dark:hover:text-[#A5D190] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Sign In
                      </button>
                    )}
                  </div>

                  <div className="mt-10 pt-6 border-t border-[#D5E2C8] dark:border-[#2A3D30] flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-[#617565] dark:text-[#98AD94]">
                    <span>7 Supported Languages</span>
                    <span aria-hidden="true">·</span>
                    <span>12 OWASP &amp; CWE Rule Classes</span>
                    <span aria-hidden="true">·</span>
                    <span>Downloadable PDF Audit Reports</span>
                    <span aria-hidden="true">·</span>
                    <span>Zero Code Execution Policy</span>
                  </div>
                </div>

                <div className="lg:col-span-6 min-w-0">
                  <div className="h-[380px] lg:h-full lg:min-h-[440px] rounded-xl overflow-hidden border border-[#CBE0B9] dark:border-[#2A3D30] bg-[#EDF3E5] relative">
                    <SecurityShield3D variant="hero" score={94} />
                    <div className="pointer-events-none absolute bottom-3 right-4 text-[11px] font-mono text-[#2F4534] bg-[#FFFDF7]/95 px-2.5 py-1 rounded border border-[#CBE0B9]">
                      Interactive 3D Core · Drag to rotate
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* Interactive Live SAST Rule Preview Section */}
            <section className="border-t border-[#D5E2C8] dark:border-[#2A3D30] bg-[#EEF5E6] dark:bg-[#141E17] py-18">
              <div className="max-w-7xl mx-auto px-6">
                <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-8">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-[#3D6A39] dark:text-[#A5D190] mb-2">
                      Interactive Static Rule Preview
                    </p>
                    <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                      Inspect real detections &amp; Gemini fixes across languages
                    </h2>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-lg bg-[#FFFDF7] dark:bg-[#101712] border border-[#D5E2C8] dark:border-[#2A3D30]">
                    {SIMULATOR_SAMPLES.map((s) => (
                      <button
                        key={s.id}
                        type="button"
                        onClick={() => setActiveSimId(s.id)}
                        className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                          activeSim.id === s.id
                            ? "bg-[#9BC585] text-[#142617]"
                            : "text-[#4A5E4E] dark:text-[#C4D3BF] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
                        }`}
                      >
                        {s.lang}
                      </button>
                    ))}
                  </div>
                </div>

                <TiltCard3D maxTilt={3} className="rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] p-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 mb-5 border-b border-[#D5E2C8] dark:border-[#2A3D30]">
                    <div className="flex items-center gap-2.5 text-xs font-mono text-[#4A5E4E] dark:text-[#C4D3BF]">
                      <ShieldAlert className="w-4 h-4 text-red-500 shrink-0" />
                      <span className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                        {activeSim.file}:{activeSim.line}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{activeSim.rule}</span>
                    </div>
                    <span className="text-xs font-semibold text-red-600 dark:text-red-400 font-mono">
                      Severity: {activeSim.severity}
                    </span>
                  </div>

                  <div className="grid lg:grid-cols-2 gap-5">
                    <div>
                      <p className="text-xs font-semibold text-red-600 dark:text-red-400 mb-2">
                        1. Static Engine Match (Vulnerable Input)
                      </p>
                      <pre className="p-4 rounded-lg bg-[#162119] border border-red-950/60 text-xs font-mono text-red-200 overflow-x-auto leading-relaxed">
                        <code>{activeSim.vulnerable}</code>
                      </pre>
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-emerald-700 dark:text-emerald-400 mb-2">
                        2. Gemini Recommended Fix (Secure Pattern)
                      </p>
                      <pre className="p-4 rounded-lg bg-[#162119] border border-[#2D4233] text-xs font-mono text-[#D9ECCB] overflow-x-auto leading-relaxed">
                        <code>{activeSim.remediated}</code>
                      </pre>
                    </div>
                  </div>

                  <div className="mt-5 pt-4 border-t border-[#D5E2C8] dark:border-[#2A3D30] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <p className="text-xs sm:text-sm text-[#4A5E4E] dark:text-[#C4D3BF] max-w-3xl">
                      {activeSim.explanation}
                    </p>
                    <button
                      type="button"
                      onClick={() => navigatePage("rules")}
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#3D6A39] dark:text-[#A5D190] hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <span>Browse all 12 rules</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </TiltCard3D>
              </div>
            </section>

            {/* Core Capabilities Bento Section with Interactive Pointer-Tracked 3D Tilt Cards */}
            <section className="max-w-7xl mx-auto px-6 py-20">
              <div className="max-w-2xl mb-12">
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] mb-3 font-display">
                  Deterministic static scanning paired with verified AI remediation
                </h2>
                <p className="text-[#4A5E4E] dark:text-[#C4D3BF] text-base leading-relaxed">
                  Every vulnerability reported by SecureScan AI originates from concrete static
                  analysis rules. Gemini AI operates strictly on verified findings to explain risk
                  and draft secure fixes.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <TiltCard3D className="md:col-span-2 p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
                  <div className="flex items-center gap-3 mb-4">
                    <Code2 className="w-5 h-5 text-[#3D6A39] dark:text-[#A5D190]" />
                    <h3 className="text-lg font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                      01. Multi-Engine Static Code Inspection
                    </h3>
                  </div>
                  <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed mb-5">
                    Combines Python AST traversal with Semgrep-compatible YAML rules to catch SQL
                    injection, unsafe deserialization, hardcoded credentials, command injection, and
                    broken cryptography with line-level precision.
                  </p>
                  <div className="grid sm:grid-cols-3 gap-4 pt-4 border-t border-[#D5E2C8] dark:border-[#2A3D30] text-xs text-[#4A5E4E] dark:text-[#98AD94]">
                    <div>
                      <p className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1">
                        Static Ground Truth
                      </p>
                      <p>Distinguishes deterministic SAST matches from AI-generated explanations.</p>
                    </div>
                    <div>
                      <p className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1">
                        CWE &amp; OWASP Mapping
                      </p>
                      <p>Classifies every finding against CWE IDs and OWASP Top 10 categories.</p>
                    </div>
                    <div>
                      <p className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mb-1">
                        Zero Code Execution
                      </p>
                      <p>Uploaded files and ZIP archives are parsed strictly as untrusted text.</p>
                    </div>
                  </div>
                </TiltCard3D>

                <TiltCard3D className="p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#EEF5E6] dark:bg-[#17221B]">
                  <div className="flex items-center gap-3 mb-4">
                    <Sparkles className="w-5 h-5 text-[#3D6A39] dark:text-[#A5D190]" />
                    <h3 className="text-lg font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                      02. Gemini Remediation Synthesis
                    </h3>
                  </div>
                  <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                    Explains why the flagged snippet is vulnerable, outlines exploit impact, and
                    generates corrected code alongside a clear diff summary.
                  </p>
                </TiltCard3D>

                <TiltCard3D className="p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#EEF5E6] dark:bg-[#17221B]">
                  <div className="flex items-center gap-3 mb-4">
                    <FileArchive className="w-5 h-5 text-[#3D6A39] dark:text-[#A5D190]" />
                    <h3 className="text-lg font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                      03. Hardened ZIP &amp; File Upload
                    </h3>
                  </div>
                  <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                    Enforces extension allowlists, file-size limits, symlink rejection, and canonical
                    path-traversal confinement during archive extraction.
                  </p>
                </TiltCard3D>

                <TiltCard3D className="md:col-span-2 p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
                  <div className="flex items-center gap-3 mb-4">
                    <FileText className="w-5 h-5 text-[#3D6A39] dark:text-[#A5D190]" />
                    <h3 className="text-lg font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                      04. Weighted Risk Scoring &amp; Executive PDF Reports
                    </h3>
                  </div>
                  <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                    Generates an application-defined 0–100 security score, tracks remediation progress
                    across historical scans via side-by-side comparison, and exports full PDF reports
                    with severity breakdowns and code examples.
                  </p>
                </TiltCard3D>
              </div>
            </section>

            {/* Languages + 3D Lab Teaser */}
            <section className="border-t border-[#D5E2C8] dark:border-[#2A3D30] bg-[#EEF5E6] dark:bg-[#141E17] py-20">
              <div className="max-w-7xl mx-auto px-6 grid lg:grid-cols-12 gap-12 items-center">
                <div className="lg:col-span-5">
                  <div className="h-[320px] rounded-xl overflow-hidden border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]">
                    {!pipelineImgFailed ? (
                      <img
                        src="/src/assets/images/feature_sast_pipeline_1795584994649.jpg"
                        alt="Automated SAST code inspection pipeline"
                        referrerPolicy="no-referrer"
                        onError={() => setPipelineImgFailed(true)}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <div className="w-full h-full flex flex-col items-center justify-center p-8 bg-gradient-to-br from-[#FAF6ED] to-[#DFECD2]">
                        <Lock className="w-12 h-12 text-[#3D6A39] mb-3" />
                        <p className="text-sm text-[#1B2B20]">Four-Stage Security Analysis Pipeline</p>
                      </div>
                    )}
                  </div>
                </div>

                <div className="lg:col-span-7">
                  <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] mb-4 font-display">
                    Seven languages supported out of the box
                  </h2>
                  <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed mb-6">
                    Upload individual modules or mixed-language archives. Language detection routes
                    each file through tailored AST and structural pattern rules.
                  </p>
                  <div className="divide-y divide-[#D5E2C8] dark:divide-[#2A3D30] border-t border-b border-[#D5E2C8] dark:border-[#2A3D30]">
                    {LANGUAGES.map((lang) => (
                      <div key={lang.name} className="py-3 flex items-baseline justify-between gap-4">
                        <span className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] shrink-0 w-24">
                          {lang.name}
                        </span>
                        <span className="text-xs text-[#4A5E4E] dark:text-[#98AD94] text-right">
                          {lang.detail}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          </>
        )}

        {/* ==================== PAGE 2: 3D ARCHITECTURE LAB ==================== */}
        {activePage === "3d-lab" && (
          <section className="max-w-7xl mx-auto px-6 py-12 space-y-10">
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-[#3D6A39] dark:text-[#A5D190] mb-2">
                  Interactive WebGL Architecture Explorer
                </p>
                <h1 className="text-3xl font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                  Four-Stage Static Inspection &amp; Remediation Pipeline
                </h1>
                <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] mt-2 max-w-2xl">
                  Click any 3D stage node directly in the viewport or use the bottom camera dock to
                  inspect how SecureScan AI isolates archives, analyzes ASTs, computes scores, and
                  synthesizes Gemini fixes.
                </p>
              </div>
              <button
                type="button"
                onClick={handlePrimaryCta}
                className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>Run Live Scan</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            <Pipeline3DShowcase
              selectedStage={pipelineStage}
              onSelectStage={setPipelineStage}
            />

            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {PIPELINE_STAGES.map((stage) => {
                const active = pipelineStage === stage.id;
                return (
                  <TiltCard3D
                    key={stage.id}
                    onClick={() => setPipelineStage(stage.id)}
                    className={`p-5 rounded-xl border cursor-pointer ${
                      active
                        ? "border-[#7FB16B] bg-[#E7F1DC] dark:bg-[#223326]"
                        : "border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B]"
                    }`}
                  >
                    <p className="text-xs font-mono text-[#3D6A39] dark:text-[#A5D190] mb-1">
                      {stage.label}
                    </p>
                    <h3 className="text-sm font-bold text-[#1B2B20] dark:text-[#F5F1E6] mb-2">
                      {stage.shortTitle}
                    </h3>
                    <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed mb-3">
                      {stage.summary}
                    </p>
                    <p className="text-[11px] font-mono text-[#617565] dark:text-[#98AD94]">
                      {stage.techSpec}
                    </p>
                  </TiltCard3D>
                );
              })}
            </div>
          </section>
        )}

        {/* ==================== PAGE 3: RULE CATALOG ==================== */}
        {activePage === "rules" && (
          <section className="max-w-7xl mx-auto px-6 py-12">
            <RuleCatalogView onTryScanner={handlePrimaryCta} />
          </section>
        )}

        {/* ==================== PAGE 4: PLANS ==================== */}
        {activePage === "plans" && (
          <section className="max-w-7xl mx-auto px-6 py-14 space-y-12">
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
              <div className="max-w-2xl">
                <p className="text-xs font-semibold uppercase tracking-wider text-[#3D6A39] dark:text-[#A5D190] mb-2">
                  Deployment Tiers
                </p>
                <h1 className="text-3xl font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                  Built for solo developers, AppSec teams, and enterprise pipelines
                </h1>
                <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] mt-2">
                  Every tier runs deterministic Python AST and Semgrep-aligned static inspection
                  with zero arbitrary execution of uploaded code.
                </p>
              </div>

              <div className="inline-flex items-center p-1 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] self-start">
                <button
                  type="button"
                  onClick={() => setBillingCycle("monthly")}
                  className={`px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                    billingCycle === "monthly"
                      ? "bg-[#9BC585] text-[#142617]"
                      : "text-[#4A5E4E] dark:text-[#C4D3BF]"
                  }`}
                >
                  Monthly
                </button>
                <button
                  type="button"
                  onClick={() => setBillingCycle("annual")}
                  className={`px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                    billingCycle === "annual"
                      ? "bg-[#9BC585] text-[#142617]"
                      : "text-[#4A5E4E] dark:text-[#C4D3BF]"
                  }`}
                >
                  Annual (Save 20%)
                </button>
              </div>
            </div>

            <div className="grid md:grid-cols-3 gap-6">
              <TiltCard3D className="p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] flex flex-col justify-between">
                <div>
                  <h2 className="text-lg font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                    Community Developer
                  </h2>
                  <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
                    For individual engineers auditing personal or open-source repositories.
                  </p>
                  <p className="text-3xl font-bold font-mono text-[#1B2B20] dark:text-[#F5F1E6] mt-5">
                    $0
                    <span className="text-xs font-normal text-[#617565]"> / forever</span>
                  </p>
                  <ul className="mt-6 space-y-2.5 text-xs text-[#4A5E4E] dark:text-[#C4D3BF]">
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>All 7 languages &amp; 12 OWASP rule classes</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>ZIP archive &amp; multi-file uploads up to 25 MB</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>Gemini AI vulnerability explanations &amp; PDF exports</span>
                    </li>
                  </ul>
                </div>
                <button
                  type="button"
                  onClick={handlePrimaryCta}
                  className="mt-8 w-full py-2.5 text-xs font-semibold rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] text-[#1B2B20] dark:text-[#F5F1E6] hover:border-[#7FB16B] transition-colors cursor-pointer"
                >
                  {isAuthenticated ? "Open Console" : "Start Free Workspace"}
                </button>
              </TiltCard3D>

              <TiltCard3D className="p-7 rounded-xl border-2 border-[#7FB16B] bg-[#EEF5E6] dark:bg-[#1E2E22] flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <h2 className="text-lg font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                      AppSec Team
                    </h2>
                    <span className="text-[11px] font-mono font-semibold text-[#3D6A39] dark:text-[#A5D190]">
                      Recommended
                    </span>
                  </div>
                  <p className="text-xs text-[#4A5E4E] dark:text-[#98AD94] mt-1">
                    For security engineers managing CI posture trends and release gates.
                  </p>
                  <p className="text-3xl font-bold font-mono text-[#1B2B20] dark:text-[#F5F1E6] mt-5">
                    {billingCycle === "annual" ? "$39" : "$49"}
                    <span className="text-xs font-normal text-[#4A5E4E] dark:text-[#98AD94]"> / seat / mo</span>
                  </p>
                  <ul className="mt-6 space-y-2.5 text-xs text-[#354B3A] dark:text-[#C4D3BF]">
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>Unlimited historical scan comparison &amp; trend tracking</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>Custom Semgrep YAML rule packs per repository</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>Flask &amp; Express REST API tokens for CI webhooks</span>
                    </li>
                  </ul>
                </div>
                <button
                  type="button"
                  onClick={handlePrimaryCta}
                  className="mt-8 w-full py-2.5 text-xs font-semibold rounded-lg bg-[#9BC585] hover:bg-[#8AB773] text-[#142617] transition-colors cursor-pointer"
                >
                  Launch Team Console
                </button>
              </TiltCard3D>

              <TiltCard3D className="p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] flex flex-col justify-between">
                <div>
                  <h2 className="text-lg font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                    Enterprise Self-Hosted
                  </h2>
                  <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
                    Dedicated PostgreSQL deployment with air-gapped SAST workers.
                  </p>
                  <p className="text-3xl font-bold font-mono text-[#1B2B20] dark:text-[#F5F1E6] mt-5">
                    Custom
                  </p>
                  <ul className="mt-6 space-y-2.5 text-xs text-[#4A5E4E] dark:text-[#C4D3BF]">
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>PostgreSQL cluster migration (`schema.postgres.sql`)</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>Dedicated Gemini API project quotas &amp; audit trails</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <Check className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] shrink-0" />
                      <span>Org-wide executive compliance PDF exports</span>
                    </li>
                  </ul>
                </div>
                <button
                  type="button"
                  onClick={() => navigatePage("docs")}
                  className="mt-8 w-full py-2.5 text-xs font-semibold rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] text-[#1B2B20] dark:text-[#F5F1E6] hover:border-[#7FB16B] transition-colors cursor-pointer"
                >
                  Read Deployment Docs
                </button>
              </TiltCard3D>
            </div>
          </section>
        )}

        {/* ==================== PAGE 5: DEVELOPER DOCS ==================== */}
        {activePage === "docs" && (
          <section className="max-w-7xl mx-auto px-6 py-12">
            <div className="mb-8">
              <p className="text-xs font-semibold uppercase tracking-wider text-[#3D6A39] dark:text-[#A5D190] mb-2">
                Developer Documentation
              </p>
              <h1 className="text-3xl font-bold tracking-tight text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                Integrate &amp; Extend SecureScan AI
              </h1>
            </div>

            <div className="grid lg:grid-cols-12 gap-8 items-start">
              <div className="lg:col-span-4 space-y-2">
                {DOC_SECTIONS.map((doc) => {
                  const Icon = doc.icon;
                  const active = doc.id === activeDoc.id;
                  return (
                    <button
                      key={doc.id}
                      type="button"
                      onClick={() => setActiveDocId(doc.id)}
                      className={`w-full text-left p-4 rounded-xl border transition-colors flex items-start gap-3 cursor-pointer ${
                        active
                          ? "border-[#7FB16B] bg-[#E7F1DC] dark:bg-[#223326]"
                          : "border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] hover:border-[#7FB16B]/70"
                      }`}
                    >
                      <Icon className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190] mt-0.5 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
                          {doc.title}
                        </p>
                        <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-0.5 line-clamp-2">
                          {doc.summary}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>

              <div className="lg:col-span-8 p-7 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-6">
                <div className="flex items-center gap-3 pb-4 border-b border-[#D5E2C8] dark:border-[#2A3D30]">
                  <BookOpen className="w-5 h-5 text-[#3D6A39] dark:text-[#A5D190]" />
                  <h2 className="text-xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                    {activeDoc.title}
                  </h2>
                </div>
                <p className="text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
                  {activeDoc.summary}
                </p>
                <div className="space-y-5">
                  {activeDoc.blocks.map((b) => (
                    <div key={b.heading}>
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-[#617565] dark:text-[#98AD94] mb-2">
                        {b.heading}
                      </h3>
                      <pre className="p-4 rounded-lg bg-[#162119] border border-[#2D4233] text-xs font-mono text-[#D9ECCB] overflow-x-auto leading-relaxed">
                        <code>{b.code}</code>
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Bottom CTA */}
        <section className="max-w-7xl mx-auto px-6 py-16">
          <div className="p-8 sm:p-10 rounded-xl border border-[#CBE0B9] dark:border-[#2A3D30] bg-gradient-to-br from-[#DFECD2] via-[#EAF3DF] to-[#F7F3E6] dark:from-[#1A291E] dark:to-[#243628] text-[#1B2B20] dark:text-[#F5F1E6] flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
            <div className="max-w-xl">
              <h2 className="text-2xl font-bold tracking-tight mb-2 font-display">
                Ready to audit your source repository?
              </h2>
              <p className="text-sm text-[#354B3A] dark:text-[#C4D3BF] leading-relaxed">
                Upload your first source file or ZIP archive, inspect verified static findings, and
                generate Gemini-assisted remediation guidance.
              </p>
            </div>
            <button
              type="button"
              onClick={handlePrimaryCta}
              className="px-6 py-3 text-sm font-semibold bg-[#9BC585] hover:bg-[#8AB773] text-[#142617] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {isAuthenticated ? "Open Security Console" : "Start Free Security Scan"}
            </button>
          </div>
        </section>
      </main>

      {/* Quiet Enterprise Footer */}
      <footer className="border-t border-[#D5E2C8] dark:border-[#2A3D30] py-10">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-6 text-xs text-[#617565] dark:text-[#98AD94]">
          <div>
            <p className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">SecureScan AI</p>
            <p className="mt-1">
              Static Application Security Testing &amp; Automated Secure Code Analysis Framework
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-6">
            {NAV_PAGES.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => navigatePage(item.id)}
                className="hover:text-[#1B2B20] dark:hover:text-[#F5F1E6] cursor-pointer"
              >
                {item.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => onOpenAuth("login")}
              className="text-[#3D6A39] dark:text-[#A5D190] font-medium hover:underline cursor-pointer"
            >
              Console Sign In
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
