import { GoogleGenAI, Type } from "@google/genai";

export interface VulnerabilityInput {
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
}

export interface AiAnalysisResult {
  plainExplanation: string;
  potentialImpact: string;
  recommendedFix: string;
  secureCodeExample: string;
  diffSummary: string;
}

function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
    throw new Error(
      "GEMINI_API_KEY is not configured on the server. Add it in Settings > Secrets."
    );
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

export async function analyzeVulnerabilityWithGemini(
  vuln: VulnerabilityInput
): Promise<AiAnalysisResult> {
  const ai = getGeminiClient();

  const prompt = [
    "Analyze the following verified static-analysis (SAST) finding. Do NOT invent unrelated vulnerabilities; focus strictly on this exact finding and code snippet.",
    "",
    `Vulnerability: ${vuln.title}`,
    `Category: ${vuln.category} (${vuln.cwe_id} | ${vuln.owasp_category})`,
    `Severity: ${vuln.severity}`,
    `Language: ${vuln.language}`,
    `File: ${vuln.file_path} (Line ${vuln.line_number})`,
    `Static Rule Summary: ${vuln.static_summary}`,
    `Flagged Line: ${vuln.matched_line}`,
    "",
    "Code Context:",
    "```" + vuln.language.toLowerCase(),
    vuln.code_snippet,
    "```",
    "",
    "Provide:",
    "1. plainExplanation: Clear, accessible explanation of the issue in this specific code section.",
    "2. potentialImpact: Realistic security risks and how an attacker could exploit it.",
    "3. recommendedFix: Concrete, actionable remediation steps for the developer.",
    "4. secureCodeExample: Complete corrected code snippet in the same programming language.",
    "5. diffSummary: Concise comparison explaining the key security difference between the vulnerable code and the secure fix.",
  ].join("\n");

  const response = await ai.models.generateContent({
    model: "gemini-4-hydrogen",
    contents: prompt,
    config: {
      systemInstruction:
        "You are an enterprise application security engineer. Explain verified static-analysis findings clearly, accurately, and concisely without hallucinating findings outside the provided snippet.",
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          plainExplanation: {
            type: Type.STRING,
            description: "Simple-language explanation of the vulnerability in the affected code.",
          },
          potentialImpact: {
            type: Type.STRING,
            description: "Concrete security risks and exploit scenario.",
          },
          recommendedFix: {
            type: Type.STRING,
            description: "Actionable remediation practices and steps.",
          },
          secureCodeExample: {
            type: Type.STRING,
            description: "Corrected secure code implementation.",
          },
          diffSummary: {
            type: Type.STRING,
            description: "Key differences between the vulnerable and secure implementations.",
          },
        },
        required: [
          "plainExplanation",
          "potentialImpact",
          "recommendedFix",
          "secureCodeExample",
          "diffSummary",
        ],
      },
    },
  });

  const rawText = (response.text ?? "").trim();
  if (!rawText) {
    throw new Error("Empty response received from Gemini API.");
  }

  const parsed = JSON.parse(rawText) as AiAnalysisResult;
  return {
    plainExplanation: parsed.plainExplanation || vuln.static_summary,
    potentialImpact: parsed.potentialImpact || "Review exposure and privilege boundaries.",
    recommendedFix: parsed.recommendedFix || vuln.static_remediation,
    secureCodeExample: parsed.secureCodeExample || "// Refactor using parameterized/validated APIs",
    diffSummary: parsed.diffSummary || "Replaces unvalidated or unsafe operation with bounded/parameterized handling.",
  };
}
