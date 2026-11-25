-- PostgreSQL Migration Schema for SecureScan AI
-- Mirrors the SQLite schema in backend/db.ts for production PostgreSQL deployments.

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'Security Engineer',
  organization TEXT NOT NULL DEFAULT 'Independent',
  theme_preference TEXT NOT NULL DEFAULT 'light',
  scan_preferences_json TEXT NOT NULL DEFAULT '{"defaultLanguage":"Auto-Detect","autoAiSummary":false,"minSeverity":"low"}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
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
  ai_analyzed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
