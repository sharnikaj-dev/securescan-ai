import Database from "better-sqlite3";
import crypto from "crypto";
import fs from "fs";
import path from "path";

const DATA_DIR = path.resolve(process.cwd(), "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "securescan.db");
export const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Security Engineer',
    organization TEXT NOT NULL DEFAULT 'Independent',
    theme_preference TEXT NOT NULL DEFAULT 'light',
    scan_preferences_json TEXT NOT NULL DEFAULT '{"defaultLanguage":"Auto-Detect","autoAiSummary":false,"minSeverity":"low"}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    language TEXT NOT NULL,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    total_lines INTEGER NOT NULL DEFAULT 0,
    security_score INTEGER NOT NULL DEFAULT 100,
    risk_classification TEXT NOT NULL DEFAULT 'Low Risk',
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    engines_used_json TEXT NOT NULL DEFAULT '[]',
    category_counts_json TEXT NOT NULL DEFAULT '{}',
    improvement_suggestions_json TEXT NOT NULL DEFAULT '[]',
    scanned_files_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'completed',
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    scanner_source TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    owasp_category TEXT NOT NULL,
    file_path TEXT NOT NULL,
    language TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    matched_line TEXT NOT NULL,
    code_snippet TEXT NOT NULL,
    static_summary TEXT NOT NULL,
    static_remediation TEXT NOT NULL,
    ai_explanation TEXT,
    ai_impact TEXT,
    ai_remediation TEXT,
    ai_secure_code TEXT,
    ai_diff_summary TEXT,
    ai_analyzed_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
  CREATE INDEX IF NOT EXISTS idx_vuln_scan_id ON vulnerabilities(scan_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`);

export interface UserRecord {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  role: string;
  organization: string;
  theme_preference: string;
  scan_preferences_json: string;
  created_at: string;
}

export interface ScanPreferences {
  defaultLanguage: string;
  autoAiSummary: boolean;
  minSeverity: "low" | "medium" | "high" | "critical";
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(":");
  if (parts.length !== 2) return false;
  const [salt, originalHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const originalBuf = Buffer.from(originalHex, "hex");
  if (derived.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(derived, originalBuf);
}

export function createSession(userId: number): string {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").run(
    token,
    userId,
    expiresAt
  );
  return token;
}

export function getUserBySessionToken(token: string): UserRecord | null {
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.* FROM users u
       INNER JOIN sessions s ON s.user_id = u.id
       WHERE s.token = ? AND s.expires_at > ?`
    )
    .get(token, new Date().toISOString()) as UserRecord | undefined;
  return row ?? null;
}

export function deleteSession(token: string): void {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
}

export function sanitizeUser(user: UserRecord) {
  let prefs: ScanPreferences = {
    defaultLanguage: "Auto-Detect",
    autoAiSummary: false,
    minSeverity: "low",
  };
  try {
    prefs = { ...prefs, ...JSON.parse(user.scan_preferences_json) };
  } catch {
    // ignore invalid json
  }
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    organization: user.organization,
    themePreference: user.theme_preference === "light" ? "light" : "dark",
    scanPreferences: prefs,
    createdAt: user.created_at,
  };
}
