#!/usr/bin/env python3
"""
SecureScan AI — Static Application Security Testing (SAST) Engine
Combines Semgrep CLI execution (when available), Python AST deep inspection,
and multi-language structural pattern rules across Python, JavaScript, TypeScript,
Java, PHP, C, and C++.

IMPORTANT SECURITY INVARIANT:
This module treats all uploaded source code as untrusted data and NEVER executes,
imports, or evaluates analyzed files.
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".php": "PHP",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
}

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 18.0,
    "high": 10.0,
    "medium": 4.0,
    "low": 1.5,
}

CATEGORY_MULTIPLIERS: Dict[str, float] = {
    "SQL Injection": 1.25,
    "Command Injection": 1.25,
    "Insecure Deserialization": 1.25,
    "Hardcoded Credentials": 1.2,
    "Insecure Authentication": 1.15,
    "Server-Side Request Forgery (SSRF)": 1.15,
    "Path Traversal": 1.15,
    "Cross-Site Scripting (XSS)": 1.05,
    "Cross-Site Request Forgery (CSRF)": 1.0,
    "Weak Cryptographic Practices": 1.0,
    "Insecure File Handling": 1.0,
    "Sensitive Information Exposure": 0.85,
}


@dataclass
class StaticFinding:
    rule_id: str
    scanner_source: str
    title: str
    category: str
    severity: str
    cwe_id: str
    owasp_category: str
    file_path: str
    language: str
    line_number: int
    matched_line: str
    code_snippet: str
    static_summary: str
    static_remediation: str
    confidence: str = "high"


def extract_code_snippet(lines: List[str], line_num: int, context: int = 3) -> str:
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    formatted: List[str] = []
    for idx in range(start, end):
        marker = ">" if (idx + 1) == line_num else " "
        formatted.append(f"{marker} {idx + 1:4d} | {lines[idx].rstrip()}")
    return "\n".join(formatted)


def detect_language(file_path: str, explicit_language: Optional[str] = None) -> str:
    ext = Path(file_path).suffix.lower()
    if ext in SUPPORTED_EXTENSIONS:
        return SUPPORTED_EXTENSIONS[ext]
    if explicit_language and explicit_language != "Auto-Detect":
        return explicit_language
    return "Unknown"


class PythonAstSecurityVisitor(ast.NodeVisitor):
    """Performs safe AST analysis on Python source code without executing it."""

    def __init__(self, file_path: str, lines: List[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: List[StaticFinding] = []

    def _add(
        self,
        rule_id: str,
        title: str,
        category: str,
        severity: str,
        cwe_id: str,
        owasp_category: str,
        lineno: int,
        summary: str,
        remediation: str,
        confidence: str = "high",
    ) -> None:
        matched = (
            self.lines[lineno - 1].strip()
            if 1 <= lineno <= len(self.lines)
            else ""
        )
        self.findings.append(
            StaticFinding(
                rule_id=rule_id,
                scanner_source="Python AST Analyzer",
                title=title,
                category=category,
                severity=severity,
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                file_path=self.file_path,
                language="Python",
                line_number=lineno,
                matched_line=matched,
                code_snippet=extract_code_snippet(self.lines, lineno),
                static_summary=summary,
                static_remediation=remediation,
                confidence=confidence,
            )
        )

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        parts: List[str] = []
        curr: ast.AST = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _is_dynamic_sql_arg(node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node)
        lower_name = call_name.lower()

        # 1. SQL Injection via cursor.execute / session.execute / raw
        if lower_name.endswith((".execute", ".executemany", ".raw")) or lower_name == "execute":
            if node.args and self._is_dynamic_sql_arg(node.args[0]):
                self._add(
                    rule_id="py-ast-sqli-dynamic-query",
                    title="SQL Injection via Dynamic Query Construction",
                    category="SQL Injection",
                    severity="critical",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                    lineno=node.lineno,
                    summary="Database execution call receives an interpolated or concatenated string instead of bound parameters.",
                    remediation="Pass a static SQL template with placeholders (?, %s) and supply user values as a tuple in the second argument.",
                )

        # 2. Command Injection
        if lower_name in {"os.system", "os.popen", "eval", "exec"}:
            self._add(
                rule_id=f"py-ast-cmdi-{lower_name.replace('.', '-')}",
                title=f"Dangerous Code or OS Command Execution ({call_name})",
                category="Command Injection",
                severity="critical",
                cwe_id="CWE-78" if "os." in lower_name else "CWE-94",
                owasp_category="A03:2021 - Injection",
                lineno=node.lineno,
                summary=f"Direct call to {call_name}() can execute arbitrary commands or expressions if influenced by untrusted input.",
                remediation="Avoid eval/exec and os.system; use subprocess.run with shell=False and explicit argument lists, or ast.literal_eval for data parsing.",
            )

        if lower_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(
                        rule_id="py-ast-subprocess-shell-true",
                        title="OS Command Injection Risk via subprocess(shell=True)",
                        category="Command Injection",
                        severity="critical",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 - Injection",
                        lineno=node.lineno,
                        summary="Invoking subprocess with shell=True spawns an OS shell, allowing metacharacter injection.",
                        remediation="Set shell=False and pass command and arguments as a list of strings.",
                    )

        # 3. Insecure Deserialization
        if lower_name in {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "shelve.open"}:
            self._add(
                rule_id="py-ast-deserialization-pickle",
                title=f"Insecure Deserialization via {call_name}",
                category="Insecure Deserialization",
                severity="critical",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                lineno=node.lineno,
                summary=f"{call_name} can execute arbitrary Python code during deserialization of untrusted payloads.",
                remediation="Use JSON (json.loads) or another data-only format with strict schema validation.",
            )

        if lower_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader"
                and (
                    (isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr)
                    or (isinstance(kw.value, ast.Name) and "Safe" in kw.value.id)
                )
                for kw in node.keywords
            )
            if not has_safe_loader:
                self._add(
                    rule_id="py-ast-yaml-unsafe-load",
                    title="Unsafe YAML Deserialization without SafeLoader",
                    category="Insecure Deserialization",
                    severity="high",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021 - Software and Data Integrity Failures",
                    lineno=node.lineno,
                    summary="yaml.load() without SafeLoader permits arbitrary Python object instantiation.",
                    remediation="Replace yaml.load(...) with yaml.safe_load(...).",
                )

        # 4. Weak Crypto
        if lower_name in {"hashlib.md5", "hashlib.sha1"}:
            self._add(
                rule_id="py-ast-weak-hash",
                title=f"Weak Cryptographic Hash Function ({call_name})",
                category="Weak Cryptographic Practices",
                severity="medium",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                lineno=node.lineno,
                summary=f"{call_name} is collision-prone and unsuitable for password hashing or integrity verification.",
                remediation="Use hashlib.sha256 for integrity digests and hashlib.scrypt or Argon2/bcrypt for passwords.",
            )

        # 5. XSS via render_template_string / Markup
        if lower_name in {"render_template_string", "flask.render_template_string", "markupsafe.markup", "markup"}:
            if node.args and not isinstance(node.args[0], ast.Constant):
                self._add(
                    rule_id="py-ast-xss-template-injection",
                    title="Server-Side Template Injection / XSS via Dynamic Template String",
                    category="Cross-Site Scripting (XSS)",
                    severity="high",
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 - Injection",
                    lineno=node.lineno,
                    summary="Rendering dynamically constructed template strings enables XSS and template injection.",
                    remediation="Use static template files with render_template() and auto-escaping enabled.",
                )

        # 6. SSRF / Disabled TLS verification
        if lower_name.startswith(("requests.", "urllib.request.urlopen", "httpx.")):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._add(
                        rule_id="py-ast-tls-verify-disabled",
                        title="TLS Certificate Verification Disabled (verify=False)",
                        category="Weak Cryptographic Practices",
                        severity="high",
                        cwe_id="CWE-295",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        lineno=node.lineno,
                        summary="Disabling TLS certificate validation exposes outbound requests to man-in-the-middle attacks.",
                        remediation="Remove verify=False and validate server certificates against trusted CA bundles.",
                    )
            if node.args and not isinstance(node.args[0], ast.Constant):
                self._add(
                    rule_id="py-ast-ssrf-dynamic-url",
                    title="Potential SSRF via Unvalidated Outbound Request URL",
                    category="Server-Side Request Forgery (SSRF)",
                    severity="high",
                    cwe_id="CWE-918",
                    owasp_category="A10:2021 - Server-Side Request Forgery",
                    lineno=node.lineno,
                    summary="Outbound HTTP client receives a dynamic URL variable without visible host allowlist validation.",
                    remediation="Validate scheme (http/https), resolve target IP, and reject loopback, private, and link-local ranges before sending requests.",
                    confidence="medium",
                )

        # 7. Insecure Temp File
        if lower_name in {"tempfile.mktemp", "mktemp"}:
            self._add(
                rule_id="py-ast-insecure-mktemp",
                title="Insecure Temporary File Creation (mktemp)",
                category="Insecure File Handling",
                severity="medium",
                cwe_id="CWE-377",
                owasp_category="A04:2021 - Insecure Design",
                lineno=node.lineno,
                summary="tempfile.mktemp() is vulnerable to race conditions (TOCTOU) between name generation and file creation.",
                remediation="Use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() instead.",
            )

        # 8. Flask debug=True
        if lower_name.endswith(".run") or lower_name == "app.run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(
                        rule_id="py-ast-flask-debug-true",
                        title="Sensitive Information Exposure via Debug Mode Enabled",
                        category="Sensitive Information Exposure",
                        severity="high",
                        cwe_id="CWE-489",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        lineno=node.lineno,
                        summary="Running web servers with debug=True can expose interactive debuggers and stack traces.",
                        remediation="Set debug=False in production and control development debugging via environment flags.",
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        secret_names = re.compile(
            r"(password|passwd|pwd|secret|api_key|apikey|token|private_key|auth_key|jwt_secret)",
            re.IGNORECASE,
        )
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            if len(val) >= 4 and val.lower() not in {"changeme", "none", "null", "test", "example", ""}:
                for target in node.targets:
                    if isinstance(target, ast.Name) and secret_names.search(target.id):
                        self._add(
                            rule_id="py-ast-hardcoded-secret",
                            title=f"Hardcoded Credential Assigned to '{target.id}'",
                            category="Hardcoded Credentials",
                            severity="high",
                            cwe_id="CWE-798",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            lineno=node.lineno,
                            summary=f"Literal string assigned to sensitive variable '{target.id}' exposes credentials in source control.",
                            remediation="Load secrets from environment variables (os.environ.get) or a dedicated secrets manager.",
                        )
        self.generic_visit(node)


# Multi-language static rule definitions covering all 12 categories and 7 languages
STATIC_RULES: List[Dict[str, Any]] = [
    # 1. SQL Injection
    {
        "id": "sast-sqli-interpolation",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
        "pattern": re.compile(
            r"""(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]*(?:\$\{[^}]+\}|['"]\s*\+\s*[a-zA-Z_$]|%s|\{\s*[a-zA-Z_]|['"]\s*\.\s*\$[a-zA-Z_])""",
            re.IGNORECASE,
        ),
        "title": "SQL Injection via Dynamic Query String",
        "category": "SQL Injection",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "summary": "SQL statement dynamically interpolates or concatenates variables directly into the query string.",
        "remediation": "Use parameterized queries / prepared statements (e.g., db.prepare, PDO prepared statements, PreparedStatement).",
    },
    {
        "id": "sast-sqli-query-call",
        "languages": ["JavaScript", "TypeScript", "PHP", "Java"],
        "pattern": re.compile(
            r"""\b(?:query|executeQuery|executeUpdate|mysqli_query|pg_query)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[^,)]*\$_(?:GET|POST|REQUEST))""",
            re.IGNORECASE,
        ),
        "title": "SQL Injection in Database Execution Call",
        "category": "SQL Injection",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "summary": "Database query API is invoked with an unparameterized template literal or concatenated request parameter.",
        "remediation": "Bind user parameters separately using placeholders (?, $1, :param) rather than string building.",
    },
    # 2. Cross-Site Scripting (XSS)
    {
        "id": "sast-xss-dom-sink",
        "languages": ["JavaScript", "TypeScript"],
        "pattern": re.compile(
            r"""(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML\s*[:=])"""
        ),
        "title": "Cross-Site Scripting (XSS) via Unsafe DOM HTML Sink",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "summary": "Direct HTML injection into the DOM without sanitization enables arbitrary script execution in user browsers.",
        "remediation": "Use textContent or React declarative JSX bindings; sanitize unavoidable HTML with DOMPurify.",
    },
    {
        "id": "sast-xss-php-echo",
        "languages": ["PHP"],
        "pattern": re.compile(r"""(?:echo|print)\s+[^\n]*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        "title": "Reflected XSS via Unescaped PHP Output",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "summary": "Superglobal user input is echoed directly into HTTP output without HTML encoding.",
        "remediation": "Wrap output in htmlspecialchars($input, ENT_QUOTES, 'UTF-8') before rendering.",
    },
    # 3. Cross-Site Request Forgery (CSRF)
    {
        "id": "sast-csrf-disabled",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
        "pattern": re.compile(
            r"""(?:WTF_CSRF_ENABLED\s*=\s*False|@csrf_exempt|csrf\.disable\(\)|sameSite\s*:\s*['"]?none['"]?(?!.*secure\s*:\s*true)|csrfProtection\s*:\s*false)""",
            re.IGNORECASE,
        ),
        "title": "Cross-Site Request Forgery (CSRF) Safeguard Disabled",
        "category": "Cross-Site Request Forgery (CSRF)",
        "severity": "medium",
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021 - Broken Access Control",
        "summary": "CSRF protection is explicitly disabled or session cookie policy weakens cross-origin request defenses.",
        "remediation": "Enable anti-CSRF token verification for state-changing endpoints and enforce SameSite=Lax or Strict cookies.",
    },
    # 4. Hardcoded Credentials
    {
        "id": "sast-hardcoded-credentials",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
        "pattern": re.compile(
            r"""(?:(?:password|passwd|secret|api_?key|jwt_?secret|private_?key|db_?pass|auth_?token)\s*[:=]\s*["'][^"'\s]{4,}["']|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|-----BEGIN\s+(?:RSA|EC|PRIVATE)\s+KEY-----)""",
            re.IGNORECASE,
        ),
        "title": "Hardcoded Credential or Private Key in Source Code",
        "category": "Hardcoded Credentials",
        "severity": "critical",
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "summary": "Embedded password, secret token, or cryptographic private key found directly in source file.",
        "remediation": "Move secrets into environment variables or a managed secrets manager and rotate exposed credentials immediately.",
    },
    # 5. Insecure Authentication
    {
        "id": "sast-auth-insecure-jwt-or-plaintext",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
        "pattern": re.compile(
            r"""(?:jwt\.decode\([^\n]*verify_signature\s*[:=]\s*False|algorithms\s*=\s*\[\s*['"]none['"]|password\s*===?\s*['"][^'"]+['"]|user\.password\s*===?\s*(?:req|request)\.)""",
            re.IGNORECASE,
        ),
        "title": "Insecure Authentication Check or Unverified JWT Decoding",
        "category": "Insecure Authentication",
        "severity": "high",
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "summary": "Authentication routine compares plaintext passwords or bypasses cryptographic JWT signature verification.",
        "remediation": "Verify credentials using bcrypt/scrypt/Argon2 and always enforce strict algorithm allowlists on JWT verification.",
    },
    # 6. Command Injection
    {
        "id": "sast-cmdi-js-exec",
        "languages": ["JavaScript", "TypeScript"],
        "pattern": re.compile(
            r"""\b(?:exec|execSync|eval|new\s+Function)\s*\([^\n]*(?:\$\{|\+|req\.|input|user|cmd)"""
        ),
        "title": "OS Command or Code Injection via Dynamic Execution",
        "category": "Command Injection",
        "severity": "critical",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 - Injection",
        "summary": "Shell command or dynamic code evaluation incorporates external input without strict sanitization.",
        "remediation": "Use execFile or spawn with shell: false and pass validated arguments as an array.",
    },
    {
        "id": "sast-cmdi-php-java-c",
        "languages": ["PHP", "Java", "C", "C++"],
        "pattern": re.compile(
            r"""(?:\b(?:system|popen|shell_exec|passthru)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\([^\n]*\+|\bexecl?p?\s*\()"""
        ),
        "title": "OS Command Injection Risk in Native / Runtime Process Call",
        "category": "Command Injection",
        "severity": "critical",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 - Injection",
        "summary": "Process execution primitive invokes an OS command that may permit shell metacharacter injection.",
        "remediation": "Replace shell commands with safe language APIs or pass fixed executable paths and validated argument arrays.",
    },
    # 7. Path Traversal
    {
        "id": "sast-path-traversal",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
        "pattern": re.compile(
            r"""(?:(?:readFile|readFileSync|createReadStream|sendFile|file_get_contents|fopen|new\s+File|open)\s*\([^\n]*(?:req\.|request\.|\$_GET|\$_POST|params\.|query\.|\+\s*[a-zA-Z_]|`[^`]*\$\{))"""
        ),
        "title": "Path Traversal via Unvalidated File System Path",
        "category": "Path Traversal",
        "severity": "high",
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021 - Broken Access Control",
        "summary": "File system operation accepts user-influenced path components without canonical base-directory confinement.",
        "remediation": "Canonicalize paths (path.resolve / realpath) and verify the result starts with the allowed base directory + separator.",
    },
    # 8. Insecure Deserialization
    {
        "id": "sast-deserialization-multi",
        "languages": ["JavaScript", "TypeScript", "Java", "PHP"],
        "pattern": re.compile(
            r"""(?:\bObjectInputStream\b|\.readObject\s*\(|\bunserialize\s*\(\s*\$|node-serialize|js-yaml[^\n]*\.load\s*\()"""
        ),
        "title": "Insecure Deserialization of Untrusted Data",
        "category": "Insecure Deserialization",
        "severity": "critical",
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "summary": "Deserializing untrusted serialized object graphs can allow remote code execution or gadget-chain abuse.",
        "remediation": "Use JSON parsing with strict type validation instead of native object deserialization.",
    },
    # 9. Weak Cryptographic Practices
    {
        "id": "sast-weak-crypto",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
        "pattern": re.compile(
            r"""(?:\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]|\bmd5\s*\(|\bsha1\s*\(|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1)['"]|AES/ECB|DES/|\bMath\.random\s*\(\)|rejectUnauthorized\s*:\s*false)""",
            re.IGNORECASE,
        ),
        "title": "Weak Cryptographic Algorithm or Insecure TLS Configuration",
        "category": "Weak Cryptographic Practices",
        "severity": "medium",
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "summary": "Deprecated hash/cipher algorithm (MD5/SHA1/ECB/DES), predictable PRNG, or disabled TLS verification detected.",
        "remediation": "Use SHA-256+, AES-GCM, crypto.randomBytes/secrets, and strict TLS certificate validation.",
    },
    # 10. Sensitive Information Exposure
    {
        "id": "sast-info-exposure",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
        "pattern": re.compile(
            r"""(?:console\.log\([^\n]*(?:password|secret|token|apiKey|privateKey)|printStackTrace\s*\(|display_errors\s*=\s*['"]?(?:1|On|true)|APP_DEBUG\s*=\s*true|res\.(?:send|json)\([^\n]*err\.stack)""",
            re.IGNORECASE,
        ),
        "title": "Sensitive Information Exposure via Logs or Verbose Error Output",
        "category": "Sensitive Information Exposure",
        "severity": "low",
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "summary": "Sensitive credentials, debug flags, or internal stack traces may be exposed in logs or HTTP responses.",
        "remediation": "Redact secrets before logging and return generic error payloads in production responses.",
    },
    # 11. Insecure File Handling & C/C++ Buffer Risks
    {
        "id": "sast-file-and-buffer",
        "languages": ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
        "pattern": re.compile(
            r"""(?:\b(?:strcpy|strcat|gets|sprintf|vsprintf)\s*\(|move_uploaded_file\s*\([^\n]*\$_FILES|chmod\s*\([^\n]*0o?777|umask\s*\(\s*0\s*\))"""
        ),
        "title": "Insecure File Permissions, Upload Handling, or Unbounded Buffer Copy",
        "category": "Insecure File Handling",
        "severity": "high",
        "cwe_id": "CWE-434",
        "owasp_category": "A04:2021 - Insecure Design",
        "summary": "World-writable file permissions, unvalidated file upload handling, or unbounded memory copy detected.",
        "remediation": "Restrict file permissions (0600/0640), validate upload MIME/extensions with random names, and use strncpy/snprintf in C/C++.",
    },
    # 12. Server-Side Request Forgery (SSRF)
    {
        "id": "sast-ssrf-outbound",
        "languages": ["JavaScript", "TypeScript", "Java", "PHP"],
        "pattern": re.compile(
            r"""(?:(?:fetch|axios\.(?:get|post|request)|http\.get|https\.get|curl_exec|new\s+URL)\s*\([^\n]*(?:req\.|request\.|\$_GET|\$_POST|query\.|params\.|url\b))"""
        ),
        "title": "Potential Server-Side Request Forgery (SSRF)",
        "category": "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "summary": "Server-side HTTP request uses a user-controlled URL without explicit host allowlisting or private-IP blocking.",
        "remediation": "Parse and validate URLs against a host allowlist and block loopback, private, and cloud metadata IPs (169.254.169.254).",
    },
]


def run_semgrep_if_installed(target_dir: str, rules_path: str) -> List[StaticFinding]:
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin or not os.path.exists(rules_path):
        return []

    findings: List[StaticFinding] = []
    try:
        proc = subprocess.run(
            [semgrep_bin, "--config", rules_path, "--json", "--no-git-ignore", target_dir],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
        if not proc.stdout:
            return []
        payload = json.loads(proc.stdout)
        for item in payload.get("results", []):
            extra = item.get("extra", {})
            meta = extra.get("metadata", {})
            sev_raw = str(extra.get("severity", "WARNING")).upper()
            sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
            severity = sev_map.get(sev_raw, "medium")
            file_p = str(item.get("path", ""))
            rel_path = os.path.relpath(file_p, target_dir) if file_p.startswith(target_dir) else file_p
            line_no = int(item.get("start", {}).get("line", 1))
            lines = Path(file_p).read_text(encoding="utf-8", errors="replace").splitlines() if os.path.exists(file_p) else []
            findings.append(
                StaticFinding(
                    rule_id=str(item.get("check_id", "semgrep-rule")),
                    scanner_source="Semgrep SAST",
                    title=meta.get("category", "Semgrep Security Finding"),
                    category=meta.get("category", "Sensitive Information Exposure"),
                    severity=severity,
                    cwe_id=meta.get("cwe", "CWE-200"),
                    owasp_category=meta.get("owasp", "A05:2021 - Security Misconfiguration"),
                    file_path=rel_path,
                    language=detect_language(rel_path),
                    line_number=line_no,
                    matched_line=lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else "",
                    code_snippet=extract_code_snippet(lines, line_no) if lines else str(extra.get("lines", "")),
                    static_summary=str(extra.get("message", "Static rule matched potentially insecure pattern.")),
                    static_remediation=meta.get("remediation", "Review and refactor following OWASP secure coding guidelines."),
                )
            )
    except Exception:
        return []
    return findings


def scan_file_content(
    rel_path: str,
    content: str,
    explicit_language: Optional[str] = None,
) -> List[StaticFinding]:
    language = detect_language(rel_path, explicit_language)
    lines = content.splitlines()
    findings: List[StaticFinding] = []
    seen_keys: set[Tuple[str, int, str]] = set()

    # 1. Python AST deep analysis (never executes code!)
    if language == "Python":
        try:
            tree = ast.parse(content, filename=rel_path)
            visitor = PythonAstSecurityVisitor(rel_path, lines)
            visitor.visit(tree)
            for f in visitor.findings:
                key = (f.file_path, f.line_number, f.category)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)
        except SyntaxError:
            pass

    # 2. Structural SAST pattern rules per language
    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        # Skip pure single-line comments
        if stripped.startswith(("#", "//", "/*", "*")):
            continue
        for rule in STATIC_RULES:
            if language != "Unknown" and language not in rule["languages"]:
                continue
            if rule["pattern"].search(raw_line):
                key = (rel_path, idx, rule["category"])
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    StaticFinding(
                        rule_id=rule["id"],
                        scanner_source="Static Rule Engine",
                        title=rule["title"],
                        category=rule["category"],
                        severity=rule["severity"],
                        cwe_id=rule["cwe_id"],
                        owasp_category=rule["owasp_category"],
                        file_path=rel_path,
                        language=language,
                        line_number=idx,
                        matched_line=stripped,
                        code_snippet=extract_code_snippet(lines, idx),
                        static_summary=rule["summary"],
                        static_remediation=rule["remediation"],
                    )
                )

    return findings


def calculate_security_score(findings: List[StaticFinding], file_count: int) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    raw_penalty = 0.0
    category_counts: Dict[str, int] = {}

    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
        base_w = SEVERITY_WEIGHTS.get(sev, 2.0)
        cat_mult = CATEGORY_MULTIPLIERS.get(f.category, 1.0)
        raw_penalty += base_w * cat_mult
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    # Normalize gently by project footprint while keeping critical issues impactful
    footprint_factor = 1.0 + math.log10(max(1, file_count)) * 0.35
    adjusted = raw_penalty / footprint_factor
    # Smooth asymptotic curve capped at 100 penalty points
    penalty = min(100.0, round(adjusted * 0.92, 1)) if adjusted <= 45 else min(
        100.0, round(41.4 + (100.0 - 41.4) * (1.0 - math.exp(-(adjusted - 45.0) / 55.0)), 1)
    )
    score = max(0, min(100, int(round(100.0 - penalty))))

    if score >= 90:
        classification = "Low Risk"
    elif score >= 70:
        classification = "Moderate Risk"
    elif score >= 45:
        classification = "Elevated Risk"
    else:
        classification = "Critical Risk"

    suggestions: List[str] = []
    if counts["critical"] > 0:
        suggestions.append("Prioritize immediate remediation of critical injection, deserialization, or credential findings before deployment.")
    if counts["high"] > 0:
        suggestions.append("Address high-severity access control, XSS, SSRF, or path-validation weaknesses in the next sprint.")
    if counts["medium"] > 0 or counts["low"] > 0:
        suggestions.append("Harden cryptographic primitives, CSRF protections, and error-handling configurations across modules.")
    if not findings:
        suggestions.append("No static-analysis rules matched in the scanned files. Continue pairing SAST with dependency auditing and dynamic tests.")

    return {
        "security_score": score,
        "risk_classification": classification,
        "severity_counts": counts,
        "category_counts": category_counts,
        "improvement_suggestions": suggestions,
        "scoring_note": "Application-defined risk indicator derived from weighted static-analysis findings; not a formal security certification.",
    }


def scan_directory(target_dir: str, explicit_language: Optional[str] = None, rules_path: Optional[str] = None) -> Dict[str, Any]:
    target = Path(target_dir).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target directory not found: {target_dir}")

    semgrep_findings: List[StaticFinding] = []
    if rules_path:
        semgrep_findings = run_semgrep_if_installed(str(target), rules_path)

    all_findings: List[StaticFinding] = list(semgrep_findings)
    seen = {(f.file_path, f.line_number, f.category) for f in semgrep_findings}

    scanned_files: List[Dict[str, Any]] = []
    total_lines = 0
    languages_detected: set[str] = set()

    for root, _, filenames in os.walk(target):
        for fname in sorted(filenames):
            fpath = Path(root).joinpath(fname).resolve()
            # Path confinement check
            if not str(fpath).startswith(str(target) + os.sep) and fpath != target:
                continue
            ext = fpath.suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS and (not explicit_language or explicit_language == "Auto-Detect"):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel_path = str(fpath.relative_to(target)).replace("\\", "/")
            lang = detect_language(rel_path, explicit_language)
            if lang != "Unknown":
                languages_detected.add(lang)
            line_count = len(content.splitlines())
            total_lines += line_count
            scanned_files.append({
                "file_path": rel_path,
                "language": lang,
                "lines": line_count,
                "size_bytes": len(content.encode("utf-8")),
            })

            file_findings = scan_file_content(rel_path, content, explicit_language)
            for f in file_findings:
                key = (f.file_path, f.line_number, f.category)
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number))

    scoring = calculate_security_score(all_findings, len(scanned_files))

    return {
        "engines_used": (["Semgrep SAST"] if semgrep_findings else []) + ["Python AST Analyzer", "Static Rule Engine"],
        "semgrep_available": shutil.which("semgrep") is not None,
        "files_scanned": len(scanned_files),
        "total_lines": total_lines,
        "languages_detected": sorted(languages_detected),
        "scanned_files": scanned_files,
        "findings": [asdict(f) for f in all_findings],
        **scoring,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: engine.py <target_dir> [explicit_language] [rules_path]"}))
        sys.exit(1)

    target_arg = sys.argv[1]
    lang_arg = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
    rules_arg = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None

    result = scan_directory(target_arg, lang_arg, rules_arg)
    print(json.dumps(result))
