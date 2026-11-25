"""
SecureScan AI — Standalone Python Flask REST API Backend
Provides a full Python/Flask alternative entrypoint sharing the same SQLite schema,
Semgrep + Python AST scanner engine, and Gemini remediation workflow.

Run standalone:
  pip install -r requirements.txt
  python backend/app.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.utils import secure_filename

from scanner.engine import SUPPORTED_EXTENSIONS, scan_directory

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "securescan.db"
RULES_PATH = BASE_DIR / "backend" / "rules" / "securescan_rules.yml"

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ZIP_BYTES = 15 * 1024 * 1024
MAX_EXTRACTED_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_FILES = 100

app = Flask(__name__)
CORS(app, supports_credentials=False)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc: Optional[BaseException]) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1, dklen=64
    )
    return f"{salt}:{derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected_hex = stored_hash.split(":", 1)
    except ValueError:
        return False
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1, dklen=64
    )
    return hmac.compare_digest(derived, bytes.fromhex(expected_hex))


def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        conn = get_db()
        row = conn.execute(
            """
            SELECT u.* FROM users u
            INNER JOIN sessions s ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (token, datetime.now(timezone.utc).isoformat()),
        ).fetchone()
        if not row:
            return jsonify({"error": "Invalid or expired session"}), 401
        g.current_user = dict(row)
        return fn(*args, **kwargs)

    return wrapper


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    total_size = 0
    file_count = 0
    dest_resolved = dest_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Reject symlinks via Unix external_attr mode bits
            if (info.external_attr >> 16) & 0o120000 == 0o120000:
                continue
            file_count += 1
            if file_count > MAX_EXTRACTED_FILES:
                raise ValueError("ZIP archive exceeds maximum file count limit.")
            total_size += info.file_size
            if total_size > MAX_EXTRACTED_BYTES:
                raise ValueError("ZIP archive exceeds uncompressed size safety limit.")
            target_path = (dest_resolved / info.filename).resolve()
            if not str(target_path).startswith(str(dest_resolved) + os.sep):
                raise ValueError(f"Path traversal blocked in archive entry: {info.filename}")
            ext = target_path.suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)


@app.route("/api/health", methods=["GET"])
def health() -> Any:
    return jsonify({"status": "ok", "engine": "python-flask-sast"})


@app.route("/api/auth/register", methods=["POST"])
def register() -> Any:
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    organization = str(data.get("organization", "Independent")).strip() or "Independent"
    if len(name) < 2 or "@" not in email or len(password) < 8:
        return jsonify({"error": "Valid name, email, and 8+ character password required"}), 400

    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
        return jsonify({"error": "Email already registered"}), 409

    pw_hash = hash_password(password)
    cur = conn.execute(
        "INSERT INTO users (name, email, password_hash, organization) VALUES (?, ?, ?, ?)",
        (name, email, pw_hash, organization),
    )
    user_id = cur.lastrowid
    token = secrets.token_hex(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, expires))
    conn.commit()
    return jsonify({"token": token, "user": {"id": user_id, "name": name, "email": email, "organization": organization}}), 201


@app.route("/api/auth/login", methods=["POST"])
def login() -> Any:
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401
    token = secrets.token_hex(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user["id"], expires))
    conn.commit()
    return jsonify({"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"]}})


@app.route("/api/scans/upload", methods=["POST"])
@require_auth
def upload_scan() -> Any:
    project_name = str(request.form.get("projectName", "Untitled Project")).strip() or "Untitled Project"
    language = str(request.form.get("language", "Auto-Detect")).strip()
    uploaded_files = request.files.getlist("files")
    if not uploaded_files:
        return jsonify({"error": "No source files or archive uploaded"}), 400

    with tempfile.TemporaryDirectory(prefix="securescan_flask_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        for f in uploaded_files:
            fname = secure_filename(f.filename or "snippet.py")
            ext = Path(fname).suffix.lower()
            if ext == ".zip":
                zip_dest = tmp_path / "__upload.zip"
                f.save(zip_dest)
                if zip_dest.stat().st_size > MAX_ZIP_BYTES:
                    return jsonify({"error": "ZIP file exceeds 15MB limit"}), 400
                safe_extract_zip(zip_dest, tmp_path)
                zip_dest.unlink(missing_ok=True)
            elif ext in SUPPORTED_EXTENSIONS:
                dest = (tmp_path / fname).resolve()
                if str(dest).startswith(str(tmp_path.resolve()) + os.sep):
                    f.save(dest)
                    if dest.stat().st_size > MAX_FILE_BYTES:
                        return jsonify({"error": f"File {fname} exceeds 5MB limit"}), 400
            else:
                return jsonify({"error": f"Unsupported file extension: {ext}"}), 400

        result = scan_directory(str(tmp_path), None if language == "Auto-Detect" else language, str(RULES_PATH))
        conn = get_db()
        counts = result["severity_counts"]
        cur = conn.execute(
            """
            INSERT INTO scans (
              user_id, project_name, source_type, language, files_scanned, total_lines,
              security_score, risk_classification, critical_count, high_count, medium_count, low_count,
              engines_used_json, category_counts_json, improvement_suggestions_json, scanned_files_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                g.current_user["id"],
                project_name,
                "upload",
                ", ".join(result["languages_detected"]) or language,
                result["files_scanned"],
                result["total_lines"],
                result["security_score"],
                result["risk_classification"],
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                json.dumps(result["engines_used"]),
                json.dumps(result["category_counts"]),
                json.dumps(result["improvement_suggestions"]),
                json.dumps(result["scanned_files"]),
            ),
        )
        scan_id = cur.lastrowid
        for v in result["findings"]:
            conn.execute(
                """
                INSERT INTO vulnerabilities (
                  scan_id, rule_id, scanner_source, title, category, severity, cwe_id, owasp_category,
                  file_path, language, line_number, matched_line, code_snippet, static_summary, static_remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    v["rule_id"],
                    v["scanner_source"],
                    v["title"],
                    v["category"],
                    v["severity"],
                    v["cwe_id"],
                    v["owasp_category"],
                    v["file_path"],
                    v["language"],
                    v["line_number"],
                    v["matched_line"],
                    v["code_snippet"],
                    v["static_summary"],
                    v["static_remediation"],
                ),
            )
        conn.commit()
        return jsonify({"scanId": scan_id, **result}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("FLASK_PORT", "5001")), debug=False)
