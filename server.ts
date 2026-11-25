import express, { NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import AdmZip from "adm-zip";
import { execFile } from "child_process";
import crypto from "crypto";
import fs from "fs";
import multer from "multer";
import os from "os";
import path from "path";
import { promisify } from "util";
import { createServer as createViteServer } from "vite";
import {
  createSession,
  db,
  deleteSession,
  getUserBySessionToken,
  hashPassword,
  sanitizeUser,
  UserRecord,
  verifyPassword,
} from "./backend/db.ts";
import { DEMO_PROJECT_NAME, DEMO_SAMPLE_FILES } from "./backend/demoSamples.ts";
import { analyzeVulnerabilityWithGemini } from "./backend/geminiService.ts";

dotenv.config();

const execFileAsync = promisify(execFile);

const PORT = Number(process.env.PORT || 3000);
const ENGINE_PATH = path.resolve(process.cwd(), "backend/scanner/engine.py");
const RULES_PATH = path.resolve(process.cwd(), "backend/rules/securescan_rules.yml");

const ALLOWED_SOURCE_EXTS = new Set([
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
]);

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB per source file
const MAX_ZIP_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB per archive
const MAX_ZIP_ENTRIES = 100;
const MAX_ZIP_UNCOMPRESSED_BYTES = 25 * 1024 * 1024; // 25 MB total extracted cap

interface AuthenticatedRequest extends Request {
  user?: UserRecord;
  sessionToken?: string;
}

interface ScanJobState {
  jobId: string;
  userId: number;
  projectName: string;
  stage: "validating" | "extracting" | "scanning" | "scoring" | "completed" | "failed";
  progress: number;
  message: string;
  scanId?: number;
  error?: string;
  createdAt: number;
}

const scanJobs = new Map<string, ScanJobState>();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_ZIP_SIZE_BYTES,
    files: 30,
  },
});

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  const token = authHeader.slice(7).trim();
  const user = getUserBySessionToken(token);
  if (!user) {
    res.status(401).json({ error: "Session expired or invalid" });
    return;
  }
  req.user = user;
  req.sessionToken = token;
  next();
}

function safeRelativeFilename(rawName: string): string {
  const normalized = rawName.replace(/\\/g, "/").replace(/^\/+/, "");
  const parts = normalized
    .split("/")
    .filter((segment) => segment && segment !== "." && segment !== "..");
  return parts.join("/") || "uploaded_file.txt";
}

function safeExtractZipBuffer(zipBuffer: Buffer, destDir: string): number {
  const zip = new AdmZip(zipBuffer);
  const entries = zip.getEntries();
  const destResolved = path.resolve(destDir);

  let fileCount = 0;
  let totalUncompressed = 0;

  for (const entry of entries) {
    if (entry.isDirectory) continue;

    // Reject symlinks based on Unix mode bits
    const unixMode = (entry.header.attr >>> 16) & 0o170000;
    if (unixMode === 0o120000) {
      continue;
    }

    if (entry.entryName.includes("..") || path.isAbsolute(entry.entryName)) {
      throw new Error(`Unsafe path detected in archive entry: ${entry.entryName}`);
    }

    fileCount += 1;
    if (fileCount > MAX_ZIP_ENTRIES) {
      throw new Error(`Archive exceeds maximum of ${MAX_ZIP_ENTRIES} files.`);
    }

    totalUncompressed += entry.header.size || 0;
    if (totalUncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) {
      throw new Error("Archive exceeds uncompressed size safety limit (25 MB).");
    }

    const relPath = safeRelativeFilename(entry.entryName);
    const ext = path.extname(relPath).toLowerCase();
    if (!ALLOWED_SOURCE_EXTS.has(ext)) {
      continue;
    }

    const targetPath = path.resolve(destResolved, relPath);
    if (!targetPath.startsWith(destResolved + path.sep)) {
      throw new Error(`Path traversal blocked for archive entry: ${entry.entryName}`);
    }

    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, entry.getData());
  }

  return fileCount;
}

interface PythonEngineOutput {
  engines_used: string[];
  semgrep_available: boolean;
  files_scanned: number;
  total_lines: number;
  languages_detected: string[];
  scanned_files: Array<{ file_path: string; language: string; lines: number; size_bytes: number }>;
  findings: Array<{
    rule_id: string;
    scanner_source: string;
    title: string;
    category: string;
    severity: string;
    cwe_id: string;
    owasp_category: string;
    file_path: string;
    language: string;
    line_number: number;
    matched_line: string;
    code_snippet: string;
    static_summary: string;
    static_remediation: string;
  }>;
  security_score: number;
  risk_classification: string;
  severity_counts: { critical: number; high: number; medium: number; low: number };
  category_counts: Record<string, number>;
  improvement_suggestions: string[];
  scoring_note: string;
}

async function runPythonSastEngine(
  targetDir: string,
  explicitLanguage: string
): Promise<PythonEngineOutput> {
  const { stdout } = await execFileAsync(
    "python3",
    [ENGINE_PATH, targetDir, explicitLanguage || "", RULES_PATH],
    {
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
    }
  );
  return JSON.parse(stdout) as PythonEngineOutput;
}

function persistScanResult(
  userId: number,
  projectName: string,
  sourceType: string,
  explicitLanguage: string,
  result: PythonEngineOutput,
  isDemo: boolean
): number {
  const insertScan = db.prepare(`
    INSERT INTO scans (
      user_id, project_name, source_type, language, files_scanned, total_lines,
      security_score, risk_classification, critical_count, high_count, medium_count, low_count,
      engines_used_json, category_counts_json, improvement_suggestions_json, scanned_files_json,
      status, is_demo
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
  `);

  const languageLabel =
    result.languages_detected.length > 0
      ? result.languages_detected.join(", ")
      : explicitLanguage || "Unknown";

  const tx = db.transaction(() => {
    const info = insertScan.run(
      userId,
      projectName,
      sourceType,
      languageLabel,
      result.files_scanned,
      result.total_lines,
      result.security_score,
      result.risk_classification,
      result.severity_counts.critical,
      result.severity_counts.high,
      result.severity_counts.medium,
      result.severity_counts.low,
      JSON.stringify(result.engines_used),
      JSON.stringify(result.category_counts),
      JSON.stringify(result.improvement_suggestions),
      JSON.stringify(result.scanned_files),
      isDemo ? 1 : 0
    );
    const scanId = Number(info.lastInsertRowid);

    const insertVuln = db.prepare(`
      INSERT INTO vulnerabilities (
        scan_id, rule_id, scanner_source, title, category, severity, cwe_id, owasp_category,
        file_path, language, line_number, matched_line, code_snippet, static_summary, static_remediation
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const f of result.findings) {
      insertVuln.run(
        scanId,
        f.rule_id,
        f.scanner_source,
        f.title,
        f.category,
        f.severity,
        f.cwe_id,
        f.owasp_category,
        f.file_path,
        f.language,
        f.line_number,
        f.matched_line,
        f.code_snippet,
        f.static_summary,
        f.static_remediation
      );
    }

    return scanId;
  });

  return tx();
}

function serializeScanRow(row: Record<string, unknown>) {
  return {
    id: row.id,
    projectName: row.project_name,
    sourceType: row.source_type,
    language: row.language,
    filesScanned: row.files_scanned,
    totalLines: row.total_lines,
    securityScore: row.security_score,
    riskClassification: row.risk_classification,
    severityCounts: {
      critical: row.critical_count,
      high: row.high_count,
      medium: row.medium_count,
      low: row.low_count,
    },
    totalVulnerabilities:
      Number(row.critical_count) +
      Number(row.high_count) +
      Number(row.medium_count) +
      Number(row.low_count),
    enginesUsed: JSON.parse(String(row.engines_used_json || "[]")),
    categoryCounts: JSON.parse(String(row.category_counts_json || "{}")),
    improvementSuggestions: JSON.parse(String(row.improvement_suggestions_json || "[]")),
    scannedFiles: JSON.parse(String(row.scanned_files_json || "[]")),
    status: row.status,
    isDemo: Boolean(row.is_demo),
    createdAt: row.created_at,
  };
}

function serializeVulnRow(row: Record<string, unknown>) {
  return {
    id: row.id,
    scanId: row.scan_id,
    ruleId: row.rule_id,
    scannerSource: row.scanner_source,
    title: row.title,
    category: row.category,
    severity: row.severity,
    cweId: row.cwe_id,
    owaspCategory: row.owasp_category,
    filePath: row.file_path,
    language: row.language,
    lineNumber: row.line_number,
    matchedLine: row.matched_line,
    codeSnippet: row.code_snippet,
    staticSummary: row.static_summary,
    staticRemediation: row.static_remediation,
    aiAnalysis: row.ai_explanation
      ? {
          plainExplanation: row.ai_explanation,
          potentialImpact: row.ai_impact,
          recommendedFix: row.ai_remediation,
          secureCodeExample: row.ai_secure_code,
          diffSummary: row.ai_diff_summary,
          analyzedAt: row.ai_analyzed_at,
        }
      : null,
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

  // Healthcheck
  app.get("/api/health", (_req, res) => {
    const geminiConfigured =
      Boolean(process.env.GEMINI_API_KEY) &&
      process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY";
    res.json({
      status: "ok",
      geminiConfigured,
      database: "sqlite",
      postgresMigrationReady: true,
    });
  });

  // 1. Authentication Routes
  app.post("/api/auth/register", (req, res) => {
    const { name, email, password, organization, role } = req.body ?? {};
    const cleanName = typeof name === "string" ? name.trim() : "";
    const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
    const cleanPassword = typeof password === "string" ? password : "";
    const cleanOrg =
      typeof organization === "string" && organization.trim()
        ? organization.trim().slice(0, 80)
        : "Independent";
    const cleanRole =
      typeof role === "string" && role.trim()
        ? role.trim().slice(0, 60)
        : "Security Engineer";

    if (cleanName.length < 2) {
      res.status(400).json({ error: "Name must be at least 2 characters." });
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ error: "Please enter a valid email address." });
      return;
    }
    if (cleanPassword.length < 8) {
      res.status(400).json({ error: "Password must be at least 8 characters long." });
      return;
    }

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(cleanEmail);
    if (existing) {
      res.status(409).json({ error: "An account with this email already exists." });
      return;
    }

    const pwHash = hashPassword(cleanPassword);
    const info = db
      .prepare(
        "INSERT INTO users (name, email, password_hash, role, organization, theme_preference) VALUES (?, ?, ?, ?, ?, 'light')"
      )
      .run(cleanName, cleanEmail, pwHash, cleanRole, cleanOrg);

    const userId = Number(info.lastInsertRowid);
    const token = createSession(userId);
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId) as UserRecord;
    res.status(201).json({ token, user: sanitizeUser(user) });
  });

  app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body ?? {};
    const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
    const cleanPassword = typeof password === "string" ? password : "";

    if (!cleanEmail || !cleanPassword) {
      res.status(400).json({ error: "Email and password are required." });
      return;
    }

    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(cleanEmail) as UserRecord | undefined;

    if (!user || !verifyPassword(cleanPassword, user.password_hash)) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    const token = createSession(user.id);
    res.json({ token, user: sanitizeUser(user) });
  });

  app.post("/api/auth/logout", requireAuth, (req: AuthenticatedRequest, res) => {
    if (req.sessionToken) {
      deleteSession(req.sessionToken);
    }
    res.json({ ok: true });
  });

  app.get("/api/auth/me", requireAuth, (req: AuthenticatedRequest, res) => {
    res.json({ user: sanitizeUser(req.user!) });
  });

  // 2. Profile & Settings Routes
  app.put("/api/profile", requireAuth, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const { name, organization, role, themePreference, scanPreferences, newPassword, currentPassword } =
      req.body ?? {};

    const nextName =
      typeof name === "string" && name.trim().length >= 2 ? name.trim().slice(0, 80) : user.name;
    const nextOrg =
      typeof organization === "string" && organization.trim()
        ? organization.trim().slice(0, 80)
        : user.organization;
    const nextRole =
      typeof role === "string" && role.trim() ? role.trim().slice(0, 60) : user.role;
    const nextTheme = themePreference === "light" ? "light" : "dark";

    let nextPrefsJson = user.scan_preferences_json;
    if (scanPreferences && typeof scanPreferences === "object") {
      nextPrefsJson = JSON.stringify({
        defaultLanguage: String(scanPreferences.defaultLanguage || "Auto-Detect"),
        autoAiSummary: Boolean(scanPreferences.autoAiSummary),
        minSeverity: ["low", "medium", "high", "critical"].includes(scanPreferences.minSeverity)
          ? scanPreferences.minSeverity
          : "low",
      });
    }

    let nextPasswordHash = user.password_hash;
    if (typeof newPassword === "string" && newPassword.length > 0) {
      if (newPassword.length < 8) {
        res.status(400).json({ error: "New password must be at least 8 characters." });
        return;
      }
      if (
        typeof currentPassword !== "string" ||
        !verifyPassword(currentPassword, user.password_hash)
      ) {
        res.status(400).json({ error: "Current password verification failed." });
        return;
      }
      nextPasswordHash = hashPassword(newPassword);
    }

    db.prepare(
      `UPDATE users
       SET name = ?, organization = ?, role = ?, theme_preference = ?, scan_preferences_json = ?, password_hash = ?
       WHERE id = ?`
    ).run(nextName, nextOrg, nextRole, nextTheme, nextPrefsJson, nextPasswordHash, user.id);

    const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id) as UserRecord;
    res.json({ user: sanitizeUser(updated) });
  });

  app.delete("/api/profile", requireAuth, (req: AuthenticatedRequest, res) => {
    db.prepare("DELETE FROM users WHERE id = ?").run(req.user!.id);
    res.json({ ok: true });
  });

  // 3. Dashboard Aggregation Route
  app.get("/api/dashboard", requireAuth, (req: AuthenticatedRequest, res) => {
    const userId = req.user!.id;
    const scans = db
      .prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY datetime(created_at) DESC, id DESC")
      .all(userId) as Array<Record<string, unknown>>;

    let totalVulnerabilities = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let scoreSum = 0;
    const categoryTotals: Record<string, number> = {};

    for (const s of scans) {
      const c = Number(s.critical_count);
      const h = Number(s.high_count);
      const m = Number(s.medium_count);
      const l = Number(s.low_count);
      critical += c;
      high += h;
      medium += m;
      low += l;
      totalVulnerabilities += c + h + m + l;
      scoreSum += Number(s.security_score);

      try {
        const cats = JSON.parse(String(s.category_counts_json || "{}")) as Record<string, number>;
        for (const [k, v] of Object.entries(cats)) {
          categoryTotals[k] = (categoryTotals[k] || 0) + Number(v);
        }
      } catch {
        // ignore malformed json
      }
    }

    const averageScore = scans.length > 0 ? Math.round(scoreSum / scans.length) : null;

    const trend = [...scans]
      .reverse()
      .slice(-12)
      .map((s) => ({
        id: s.id,
        label: String(s.project_name).slice(0, 18),
        date: String(s.created_at).slice(0, 10),
        score: Number(s.security_score),
        vulnerabilities:
          Number(s.critical_count) +
          Number(s.high_count) +
          Number(s.medium_count) +
          Number(s.low_count),
      }));

    const alerts = db
      .prepare(
        `SELECT v.id, v.scan_id, v.title, v.severity, v.category, v.file_path, v.line_number, s.project_name, s.created_at
         FROM vulnerabilities v
         INNER JOIN scans s ON s.id = v.scan_id
         WHERE s.user_id = ? AND v.severity IN ('critical', 'high')
         ORDER BY CASE v.severity WHEN 'critical' THEN 0 ELSE 1 END, v.id DESC
         LIMIT 8`
      )
      .all(userId);

    const geminiConfigured =
      Boolean(process.env.GEMINI_API_KEY) &&
      process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY";

    res.json({
      stats: {
        totalScans: scans.length,
        totalVulnerabilities,
        severityCounts: { critical, high, medium, low },
        averageSecurityScore: averageScore,
      },
      categoryDistribution: Object.entries(categoryTotals)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count),
      trend,
      recentScans: scans.slice(0, 6).map(serializeScanRow),
      securityAlerts: alerts,
      environment: {
        geminiConfigured,
        databaseEngine: "SQLite (PostgreSQL Migration Ready)",
      },
    });
  });

  // 4. Scans & History Routes
  app.get("/api/scans", requireAuth, (req: AuthenticatedRequest, res) => {
    const scans = db
      .prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY datetime(created_at) DESC, id DESC")
      .all(req.user!.id) as Array<Record<string, unknown>>;
    res.json({ scans: scans.map(serializeScanRow) });
  });

  app.get("/api/scans/compare", requireAuth, (req: AuthenticatedRequest, res) => {
    const idA = Number(req.query.a);
    const idB = Number(req.query.b);
    if (!Number.isInteger(idA) || !Number.isInteger(idB)) {
      res.status(400).json({ error: "Provide valid scan IDs ?a=...&b=..." });
      return;
    }

    const rowA = db
      .prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?")
      .get(idA, req.user!.id) as Record<string, unknown> | undefined;
    const rowB = db
      .prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?")
      .get(idB, req.user!.id) as Record<string, unknown> | undefined;

    if (!rowA || !rowB) {
      res.status(404).json({ error: "One or both scans were not found." });
      return;
    }

    const scanA = serializeScanRow(rowA);
    const scanB = serializeScanRow(rowB);

    res.json({
      baseline: scanA,
      comparison: scanB,
      deltas: {
        scoreDelta: Number(scanB.securityScore) - Number(scanA.securityScore),
        totalDelta: Number(scanB.totalVulnerabilities) - Number(scanA.totalVulnerabilities),
        criticalDelta:
          Number(scanB.severityCounts.critical) - Number(scanA.severityCounts.critical),
        highDelta: Number(scanB.severityCounts.high) - Number(scanA.severityCounts.high),
        mediumDelta: Number(scanB.severityCounts.medium) - Number(scanA.severityCounts.medium),
        lowDelta: Number(scanB.severityCounts.low) - Number(scanA.severityCounts.low),
      },
    });
  });

  app.get("/api/scans/jobs/:jobId", requireAuth, (req: AuthenticatedRequest, res) => {
    const job = scanJobs.get(String(req.params.jobId));
    if (!job || job.userId !== req.user!.id) {
      res.status(404).json({ error: "Scan job not found" });
      return;
    }
    res.json(job);
  });

  app.get("/api/scans/:id", requireAuth, (req: AuthenticatedRequest, res) => {
    const scanId = Number(req.params.id);
    const scanRow = db
      .prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?")
      .get(scanId, req.user!.id) as Record<string, unknown> | undefined;

    if (!scanRow) {
      res.status(404).json({ error: "Scan record not found" });
      return;
    }

    const vulns = db
      .prepare(
        `SELECT * FROM vulnerabilities
         WHERE scan_id = ?
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, file_path ASC, line_number ASC`
      )
      .all(scanId) as Array<Record<string, unknown>>;

    res.json({
      scan: serializeScanRow(scanRow),
      vulnerabilities: vulns.map(serializeVulnRow),
    });
  });

  app.delete("/api/scans/:id", requireAuth, (req: AuthenticatedRequest, res) => {
    const scanId = Number(req.params.id);
    const result = db
      .prepare("DELETE FROM scans WHERE id = ? AND user_id = ?")
      .run(scanId, req.user!.id);
    if (result.changes === 0) {
      res.status(404).json({ error: "Scan record not found" });
      return;
    }
    res.json({ ok: true });
  });

  // 5. Code Scanning Engine Endpoint (multipart upload OR raw pasted code)
  app.post(
    "/api/scans/upload",
    requireAuth,
    upload.array("files", 30),
    async (req: AuthenticatedRequest, res) => {
      const userId = req.user!.id;
      const projectName =
        typeof req.body?.projectName === "string" && req.body.projectName.trim()
          ? req.body.projectName.trim().slice(0, 100)
          : "Untitled Security Scan";
      const explicitLanguage =
        typeof req.body?.language === "string" ? req.body.language.trim() : "Auto-Detect";
      const pastedCode = typeof req.body?.code === "string" ? req.body.code : "";
      const pastedFilename =
        typeof req.body?.filename === "string" && req.body.filename.trim()
          ? safeRelativeFilename(req.body.filename.trim())
          : "";

      const uploadedFiles = (req.files as Express.Multer.File[]) || [];

      if (uploadedFiles.length === 0 && !pastedCode.trim()) {
        res.status(400).json({ error: "Upload source files, a ZIP archive, or paste source code." });
        return;
      }

      // Validate file types and sizes synchronously before launching background job
      let hasZip = false;
      for (const file of uploadedFiles) {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ext === ".zip") {
          hasZip = true;
          if (file.size > MAX_ZIP_SIZE_BYTES) {
            res.status(400).json({ error: `ZIP archive ${file.originalname} exceeds 15 MB limit.` });
            return;
          }
        } else if (ALLOWED_SOURCE_EXTS.has(ext)) {
          if (file.size > MAX_FILE_SIZE_BYTES) {
            res.status(400).json({ error: `Source file ${file.originalname} exceeds 5 MB limit.` });
            return;
          }
        } else {
          res.status(400).json({
            error: `Unsupported file type '${ext || file.originalname}'. Supported: Python, JS, TS, Java, PHP, C, C++, and .zip archives.`,
          });
          return;
        }
      }

      if (pastedCode.trim() && pastedFilename) {
        const ext = path.extname(pastedFilename).toLowerCase();
        if (!ALLOWED_SOURCE_EXTS.has(ext)) {
          res.status(400).json({ error: `Unsupported filename extension '${ext}'.` });
          return;
        }
      }

      const jobId = crypto.randomUUID();
      const job: ScanJobState = {
        jobId,
        userId,
        projectName,
        stage: "validating",
        progress: 15,
        message: "Validating uploaded files and isolating untrusted workspace...",
        createdAt: Date.now(),
      };
      scanJobs.set(jobId, job);

      // Process asynchronously so frontend displays real-time pipeline stages
      void (async () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "securescan-"));
        const tempResolved = path.resolve(tempDir);
        try {
          job.stage = "extracting";
          job.progress = 35;
          job.message = hasZip
            ? "Extracting ZIP archive with path-traversal confinement..."
            : "Preparing isolated source tree...";

          let filesPrepared = 0;

          for (const file of uploadedFiles) {
            const ext = path.extname(file.originalname).toLowerCase();
            if (ext === ".zip") {
              filesPrepared += safeExtractZipBuffer(file.buffer, tempResolved);
            } else {
              const safeName = safeRelativeFilename(file.originalname);
              const targetPath = path.resolve(tempResolved, safeName);
              if (!targetPath.startsWith(tempResolved + path.sep)) {
                throw new Error(`Invalid file path: ${file.originalname}`);
              }
              fs.mkdirSync(path.dirname(targetPath), { recursive: true });
              fs.writeFileSync(targetPath, file.buffer);
              filesPrepared += 1;
            }
          }

          if (pastedCode.trim()) {
            const extByLang: Record<string, string> = {
              Python: ".py",
              JavaScript: ".js",
              TypeScript: ".ts",
              Java: ".java",
              PHP: ".php",
              C: ".c",
              "C++": ".cpp",
            };
            const fallbackExt = extByLang[explicitLanguage] || ".py";
            const fileName = pastedFilename || `snippet${fallbackExt}`;
            const targetPath = path.resolve(tempResolved, fileName);
            if (!targetPath.startsWith(tempResolved + path.sep)) {
              throw new Error("Invalid snippet filename.");
            }
            fs.mkdirSync(path.dirname(targetPath), { recursive: true });
            fs.writeFileSync(targetPath, pastedCode, "utf8");
            filesPrepared += 1;
          }

          if (filesPrepared === 0) {
            throw new Error("No supported source code files were found in the upload.");
          }

          job.stage = "scanning";
          job.progress = 65;
          job.message = "Running Python AST analyzer and Semgrep-aligned static security rules...";

          const result = await runPythonSastEngine(tempResolved, explicitLanguage);
          if (result.files_scanned === 0) {
            throw new Error("No scannable source files matched supported languages.");
          }

          job.stage = "scoring";
          job.progress = 90;
          job.message = "Calculating weighted security score and persisting report...";

          const sourceType = hasZip ? "zip" : uploadedFiles.length > 0 ? "file" : "snippet";
          const scanId = persistScanResult(
            userId,
            projectName,
            sourceType,
            explicitLanguage,
            result,
            false
          );

          job.stage = "completed";
          job.progress = 100;
          job.scanId = scanId;
          job.message = `Scan complete: ${result.findings.length} static findings across ${result.files_scanned} file(s).`;
        } catch (err) {
          job.stage = "failed";
          job.progress = 100;
          job.error = err instanceof Error ? err.message : "Static analysis failed.";
          job.message = job.error;
        } finally {
          fs.rmSync(tempDir, { recursive: true, force: true });
        }
      })();

      res.status(202).json({ jobId, stage: job.stage, progress: job.progress, message: job.message });
    }
  );

  // Clearly Labeled Demo Mode Endpoint (runs real Python SAST engine on sample vulnerable files)
  app.post("/api/scans/demo", requireAuth, async (req: AuthenticatedRequest, res) => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "securescan-demo-"));
    try {
      for (const sample of DEMO_SAMPLE_FILES) {
        const target = path.resolve(tempDir, sample.filename);
        if (target.startsWith(path.resolve(tempDir) + path.sep)) {
          fs.writeFileSync(target, sample.content, "utf8");
        }
      }
      const result = await runPythonSastEngine(tempDir, "Auto-Detect");
      const scanId = persistScanResult(
        req.user!.id,
        DEMO_PROJECT_NAME,
        "demo",
        "Python, TypeScript, C",
        result,
        true
      );
      res.status(201).json({ scanId, isDemo: true });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : "Failed to run demonstration scan.",
      });
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // 6. Gemini AI Vulnerability Explanation & Remediation Routes
  app.post(
    "/api/vulnerabilities/:id/analyze",
    requireAuth,
    async (req: AuthenticatedRequest, res) => {
      const vulnId = Number(req.params.id);
      const force = Boolean(req.body?.force);

      const row = db
        .prepare(
          `SELECT v.* FROM vulnerabilities v
           INNER JOIN scans s ON s.id = v.scan_id
           WHERE v.id = ? AND s.user_id = ?`
        )
        .get(vulnId, req.user!.id) as Record<string, unknown> | undefined;

      if (!row) {
        res.status(404).json({ error: "Vulnerability finding not found." });
        return;
      }

      if (row.ai_explanation && !force) {
        res.json({ vulnerability: serializeVulnRow(row), cached: true });
        return;
      }

      try {
        const aiResult = await analyzeVulnerabilityWithGemini({
          title: String(row.title),
          category: String(row.category),
          severity: String(row.severity),
          cwe_id: String(row.cwe_id),
          owasp_category: String(row.owasp_category),
          file_path: String(row.file_path),
          language: String(row.language),
          line_number: Number(row.line_number),
          matched_line: String(row.matched_line),
          code_snippet: String(row.code_snippet),
          static_summary: String(row.static_summary),
          static_remediation: String(row.static_remediation),
        });

        const nowIso = new Date().toISOString();
        db.prepare(
          `UPDATE vulnerabilities
           SET ai_explanation = ?, ai_impact = ?, ai_remediation = ?, ai_secure_code = ?, ai_diff_summary = ?, ai_analyzed_at = ?
           WHERE id = ?`
        ).run(
          aiResult.plainExplanation,
          aiResult.potentialImpact,
          aiResult.recommendedFix,
          aiResult.secureCodeExample,
          aiResult.diffSummary,
          nowIso,
          vulnId
        );

        const updated = db
          .prepare("SELECT * FROM vulnerabilities WHERE id = ?")
          .get(vulnId) as Record<string, unknown>;
        res.json({ vulnerability: serializeVulnRow(updated), cached: false });
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Gemini AI analysis request failed.";
        res.status(502).json({ error: message });
      }
    }
  );

  // Batch analyze unanalyzed findings in a scan (up to 5 at a time for responsiveness)
  app.post("/api/scans/:id/analyze-all", requireAuth, async (req: AuthenticatedRequest, res) => {
    const scanId = Number(req.params.id);
    const scanRow = db
      .prepare("SELECT id FROM scans WHERE id = ? AND user_id = ?")
      .get(scanId, req.user!.id);

    if (!scanRow) {
      res.status(404).json({ error: "Scan not found." });
      return;
    }

    const pending = db
      .prepare(
        `SELECT * FROM vulnerabilities
         WHERE scan_id = ? AND ai_explanation IS NULL
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
         LIMIT 5`
      )
      .all(scanId) as Array<Record<string, unknown>>;

    if (pending.length === 0) {
      res.json({ analyzedCount: 0, message: "All findings already have AI analysis." });
      return;
    }

    let analyzedCount = 0;
    const errors: string[] = [];

    for (const row of pending) {
      try {
        const aiResult = await analyzeVulnerabilityWithGemini({
          title: String(row.title),
          category: String(row.category),
          severity: String(row.severity),
          cwe_id: String(row.cwe_id),
          owasp_category: String(row.owasp_category),
          file_path: String(row.file_path),
          language: String(row.language),
          line_number: Number(row.line_number),
          matched_line: String(row.matched_line),
          code_snippet: String(row.code_snippet),
          static_summary: String(row.static_summary),
          static_remediation: String(row.static_remediation),
        });

        db.prepare(
          `UPDATE vulnerabilities
           SET ai_explanation = ?, ai_impact = ?, ai_remediation = ?, ai_secure_code = ?, ai_diff_summary = ?, ai_analyzed_at = ?
           WHERE id = ?`
        ).run(
          aiResult.plainExplanation,
          aiResult.potentialImpact,
          aiResult.recommendedFix,
          aiResult.secureCodeExample,
          aiResult.diffSummary,
          new Date().toISOString(),
          row.id
        );
        analyzedCount += 1;
      } catch (err) {
        errors.push(err instanceof Error ? err.message : "AI analysis error");
        break;
      }
    }

    if (analyzedCount === 0 && errors.length > 0) {
      res.status(502).json({ error: errors[0] });
      return;
    }

    res.json({ analyzedCount, errors });
  });

  // Vite integration in development or static dist in production
  if (process.env.NODE_ENV === "production") {
    const distDir = path.resolve(process.cwd(), "dist");
    app.use(express.static(distDir));
    app.get("/{*splat}", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SecureScan AI listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start SecureScan AI server:", err);
  process.exit(1);
});
