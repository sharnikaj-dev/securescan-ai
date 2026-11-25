import React, { useMemo, useState } from "react";
import { CheckCircle2, Search, ShieldAlert } from "lucide-react";
import { TiltCard3D } from "./TiltCard3D";
import { SeverityLevel } from "../types";
import { SeverityLabel } from "./SeverityLabel";

export interface RuleEntry {
  id: string;
  name: string;
  cwe: string;
  owasp: string;
  severity: SeverityLevel;
  languages: string[];
  description: string;
  vulnerableExample: string;
  secureExample: string;
}

export const SECURITY_RULES: RuleEntry[] = [
  {
    id: "sql-injection",
    name: "SQL Injection",
    cwe: "CWE-89",
    owasp: "A03:2021",
    severity: "critical",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
    description:
      "Detects string formatting, f-strings, or concatenation of untrusted parameters into SQL execution APIs.",
    vulnerableExample: `cursor.execute(f"SELECT * FROM users WHERE email = '{user_email}'")`,
    secureExample: `cursor.execute("SELECT * FROM users WHERE email = ?", (user_email,))`,
  },
  {
    id: "command-injection",
    name: "Command Injection",
    cwe: "CWE-78",
    owasp: "A03:2021",
    severity: "critical",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
    description:
      "Flags shell=True subprocess calls, os.system(), exec(), Runtime.exec(), and system() calls with dynamic arguments.",
    vulnerableExample: `subprocess.run(f"tar -czf out.tgz {user_dir}", shell=True)`,
    secureExample: `subprocess.run(["tar", "-czf", "out.tgz", safe_dir], shell=False, check=True)`,
  },
  {
    id: "xss",
    name: "Cross-Site Scripting (XSS)",
    cwe: "CWE-79",
    owasp: "A03:2021",
    severity: "high",
    languages: ["JavaScript", "TypeScript", "PHP", "Python"],
    description:
      "Identifies unescaped HTML sinks including innerHTML, dangerouslySetInnerHTML, document.write, and raw template echoes.",
    vulnerableExample: `element.innerHTML = "<div>Welcome " + username + "</div>";`,
    secureExample: `element.textContent = "Welcome " + username;`,
  },
  {
    id: "hardcoded-creds",
    name: "Hardcoded Credentials",
    cwe: "CWE-798",
    owasp: "A07:2021",
    severity: "high",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
    description:
      "Catches literal API keys, database passwords, JWT secrets, and signing tokens committed directly in source code.",
    vulnerableExample: `const JWT_SECRET = "prod-signing-key-9918273";`,
    secureExample: `const JWT_SECRET = process.env.JWT_SECRET ?? throwMissing("JWT_SECRET");`,
  },
  {
    id: "insecure-deserialization",
    name: "Insecure Deserialization",
    cwe: "CWE-502",
    owasp: "A08:2021",
    severity: "critical",
    languages: ["Python", "Java", "PHP"],
    description:
      "Flags pickle.loads(), unsafe yaml.load(), ObjectInputStream.readObject(), and PHP unserialize() on untrusted payloads.",
    vulnerableExample: `payload = pickle.loads(request.data)`,
    secureExample: `payload = json.loads(request.data.decode("utf-8"))`,
  },
  {
    id: "path-traversal",
    name: "Path Traversal",
    cwe: "CWE-22",
    owasp: "A01:2021",
    severity: "high",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
    description:
      "Detects unvalidated user file paths passed into open(), fs.readFile(), send_file(), or archive extraction routines.",
    vulnerableExample: `return send_file(os.path.join("/srv/uploads", req.args["file"]))`,
    secureExample: `target = Path(BASE_DIR, safe_name).resolve(); assert target.is_relative_to(BASE_DIR)`,
  },
  {
    id: "ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    cwe: "CWE-918",
    owasp: "A10:2021",
    severity: "high",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
    description:
      "Highlights outbound HTTP requests (fetch, requests.get, axios, curl_exec) driven by unvalidated user URLs.",
    vulnerableExample: `resp = requests.get(request.args.get("webhook_url"))`,
    secureExample: `validate_public_https_allowlist(url); resp = requests.get(url, allow_redirects=False, timeout=5)`,
  },
  {
    id: "weak-crypto",
    name: "Weak Cryptographic Practices",
    cwe: "CWE-327",
    owasp: "A02:2021",
    severity: "medium",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"],
    description:
      "Flags MD5/SHA1 for password hashing, ECB cipher mode, Math.random() for security tokens, and deprecated TLS versions.",
    vulnerableExample: `digest = hashlib.md5(password.encode()).hexdigest()`,
    secureExample: `digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)`,
  },
  {
    id: "insecure-auth",
    name: "Insecure Authentication",
    cwe: "CWE-287",
    owasp: "A07:2021",
    severity: "high",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
    description:
      "Identifies missing signature verification (jwt.decode verify=False), plain password equality checks, and disabled session flags.",
    vulnerableExample: `claims = jwt.decode(token, options={"verify_signature": False})`,
    secureExample: `claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])`,
  },
  {
    id: "csrf",
    name: "Cross-Site Request Forgery (CSRF)",
    cwe: "CWE-352",
    owasp: "A01:2021",
    severity: "medium",
    languages: ["Python", "JavaScript", "TypeScript", "PHP", "Java"],
    description:
      "Detects explicit CSRF exemption decorators, disabled middleware protections, or permissive SameSite=None cookie settings.",
    vulnerableExample: `@csrf_exempt\ndef transfer_funds(request): ...`,
    secureExample: `app.config["SESSION_COOKIE_SAMESITE"] = "Lax"; csrf.protect()`,
  },
  {
    id: "info-exposure",
    name: "Sensitive Information Exposure",
    cwe: "CWE-200",
    owasp: "A05:2021",
    severity: "medium",
    languages: ["Python", "JavaScript", "TypeScript", "Java", "PHP"],
    description:
      "Flags production debug=True flags, stack-trace leakage in HTTP responses, and logging of secret tokens.",
    vulnerableExample: `app.run(host="0.0.0.0", debug=True)`,
    secureExample: `app.run(host="127.0.0.1", debug=os.getenv("FLASK_DEBUG") == "1")`,
  },
  {
    id: "insecure-file",
    name: "Insecure File Handling",
    cwe: "CWE-434",
    owasp: "A04:2021",
    severity: "medium",
    languages: ["Python", "JavaScript", "TypeScript", "PHP", "C", "C++"],
    description:
      "Detects unrestricted file uploads, world-writable permissions (0777), and unsafe buffer copies (strcpy, gets) in C/C++.",
    vulnerableExample: `os.chmod(upload_path, 0o777)`,
    secureExample: `os.chmod(upload_path, 0o600)`,
  },
];

interface RuleCatalogViewProps {
  compact?: boolean;
  onTryScanner?: () => void;
}

export function RuleCatalogView({ compact = false, onTryScanner }: RuleCatalogViewProps) {
  const [query, setQuery] = useState("");
  const [languageFilter, setLanguageFilter] = useState<string>("All");
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [selectedRuleId, setSelectedRuleId] = useState<string>(SECURITY_RULES[0].id);

  const languages = ["All", "Python", "JavaScript", "TypeScript", "Java", "PHP", "C", "C++"];
  const severities = ["All", "critical", "high", "medium"];

  const filteredRules = useMemo(() => {
    const q = query.trim().toLowerCase();
    return SECURITY_RULES.filter((r) => {
      if (languageFilter !== "All" && !r.languages.includes(languageFilter)) return false;
      if (severityFilter !== "All" && r.severity !== severityFilter) return false;
      if (!q) return true;
      return (
        r.name.toLowerCase().includes(q) ||
        r.cwe.toLowerCase().includes(q) ||
        r.owasp.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q)
      );
    });
  }, [query, languageFilter, severityFilter]);

  const activeRule =
    filteredRules.find((r) => r.id === selectedRuleId) ?? filteredRules[0] ?? SECURITY_RULES[0];

  return (
    <div className="space-y-6">
      {!compact && (
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
              OWASP &amp; CWE Static Rule Catalog
            </h1>
            <p className="text-xs sm:text-sm text-[#617565] dark:text-[#98AD94] mt-1">
              Inspect all 12 deterministic vulnerability categories enforced by our Python AST and Semgrep-compatible rule engine.
            </p>
          </div>
          {onTryScanner && (
            <button
              type="button"
              onClick={onTryScanner}
              className="px-4 py-2 text-xs font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Test Against Your Code
            </button>
          )}
        </div>
      )}

      {/* Filter Bar */}
      <div className="p-4 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] flex flex-col lg:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-[#617565] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search rule name, CWE-89, OWASP A03, or sink..."
            className="w-full pl-9 pr-3 py-2 text-xs sm:text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Filter by language"
            value={languageFilter}
            onChange={(e) => setLanguageFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
          >
            {languages.map((lang) => (
              <option key={lang} value={lang}>
                Language: {lang}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
          >
            {severities.map((sev) => (
              <option key={sev} value={sev}>
                Severity: {sev}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Master-Detail Rule Grid */}
      <div className="grid lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-7 grid sm:grid-cols-2 gap-3.5">
          {filteredRules.length === 0 ? (
            <div className="sm:col-span-2 p-8 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] text-center text-xs text-[#617565] dark:text-[#98AD94]">
              No static analysis rules match your current search filters.
            </div>
          ) : (
            filteredRules.map((rule) => {
              const selected = activeRule.id === rule.id;
              return (
                <TiltCard3D
                  key={rule.id}
                  onClick={() => setSelectedRuleId(rule.id)}
                  className={`p-4 rounded-xl border cursor-pointer ${
                    selected
                      ? "border-[#7FB16B] bg-[#E7F1DC] dark:bg-[#223326]"
                      : "border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] hover:border-[#7FB16B]/70"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <h3 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6] leading-snug">
                      {rule.name}
                    </h3>
                    <SeverityLabel severity={rule.severity} compact />
                  </div>
                  <p className="text-[11px] font-mono text-[#617565] dark:text-[#98AD94] mb-2">
                    {rule.cwe} · {rule.owasp}
                  </p>
                  <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] line-clamp-2 leading-relaxed">
                    {rule.description}
                  </p>
                </TiltCard3D>
              );
            })
          )}
        </div>

        {/* Selected Rule Inspector */}
        <div className="lg:col-span-5 lg:sticky lg:top-20 p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-mono text-[#3D6A39] dark:text-[#A5D190]">
                {activeRule.cwe} · {activeRule.owasp}
              </p>
              <h2 className="text-lg font-bold text-[#1B2B20] dark:text-[#F5F1E6] mt-0.5 font-display">
                {activeRule.name}
              </h2>
            </div>
            <SeverityLabel severity={activeRule.severity} />
          </div>

          <p className="text-xs sm:text-sm text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
            {activeRule.description}
          </p>

          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[#617565] dark:text-[#98AD94] mb-1.5">
              Supported Languages
            </p>
            <p className="text-xs font-mono text-[#1B2B20] dark:text-[#C4D3BF]">
              {activeRule.languages.join(" · ")}
            </p>
          </div>

          <div className="space-y-3 pt-2 border-t border-[#D5E2C8] dark:border-[#2A3D30]">
            <div>
              <div className="flex items-center gap-1.5 text-xs font-semibold text-red-600 dark:text-red-400 mb-1.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Vulnerable Pattern Flagged</span>
              </div>
              <pre className="p-3 rounded-lg bg-[#162119] border border-red-950/60 text-[11px] font-mono text-red-200 overflow-x-auto">
                <code>{activeRule.vulnerableExample}</code>
              </pre>
            </div>

            <div>
              <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400 mb-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Recommended Secure Pattern</span>
              </div>
              <pre className="p-3 rounded-lg bg-[#162119] border border-[#2D4233] text-[11px] font-mono text-[#D9ECCB] overflow-x-auto">
                <code>{activeRule.secureExample}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
