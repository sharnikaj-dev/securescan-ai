# SecureScan AI

**AI-Powered Software Vulnerability Detection and Automated Secure Code Analysis Framework**

SecureScan AI is an enterprise-grade static application security testing (SAST) and automated remediation platform. It combines deterministic Python AST inspection and Semgrep-compatible static rules with Google Gemini API remediation synthesis, weighted risk scoring, scan comparison, and downloadable PDF audit reports.

---

## Architecture Overview

- **Frontend (`src/`)**: React 19, TypeScript, Tailwind CSS v4, Lucide Icons, Recharts visualizations, and jsPDF report generation.
- **Full-Stack Server (`server.ts`)**: Express API + Vite dev middleware serving port `3000`, multipart file/ZIP ingestion, hardened archive extraction, real-time scan job status tracking, scrypt authentication, and server-side Gemini integration.
- **Static Analysis Engine (`backend/scanner/engine.py` & `backend/rules/securescan_rules.yml`)**:
  - Executes `semgrep` CLI automatically when installed, alongside a deep **Python AST security visitor** and multi-language static rule engine.
  - Supports **Python, JavaScript, TypeScript, Java, PHP, C, and C++**.
  - Covers 12 OWASP/CWE categories: SQL Injection, XSS, CSRF, Hardcoded Credentials, Insecure Authentication, Command Injection, Path Traversal, Insecure Deserialization, Weak Cryptography, Sensitive Information Exposure, Insecure File Handling, and SSRF.
- **Standalone Python Flask API (`backend/app.py`)**: Full Flask REST backend sharing the identical SQLite schema and Python SAST engine for standalone Python deployments.
- **Database (`backend/db.ts` & `backend/schema.postgres.sql`)**: SQLite persistence in `data/securescan.db` with an aligned PostgreSQL DDL migration schema.

---

## Security Controls

- Uploaded source code and ZIP archives are treated strictly as untrusted data and are **never executed**.
- File uploads enforce extension allowlists and size caps (5 MB per file, 15 MB per ZIP, 25 MB uncompressed limit, max 100 entries).
- ZIP extraction rejects symlinks, `..` traversal segments, and verifies canonical path prefix confinement (`path.resolve`).
- Passwords use per-user salted `scrypt` hashes with constant-time verification (`crypto.timingSafeEqual`).
- `GEMINI_API_KEY` is accessed strictly on the server and never bundled into frontend code.

---

## Local Installation & Running

### 1. Environment Configuration

Copy `.env.example` to `.env` and configure your server-side key:

```bash
cp .env.example .env
# Set GEMINI_API_KEY in .env
```

### 2. Full-Stack Web App (Node.js + Python SAST Engine)

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

### 3. Optional Standalone Python Flask Backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python backend/app.py
```

---

## Disclaimer

Security scores (`0–100`) are application-defined risk indicators derived from weighted static-analysis findings and are not formal security certifications.
