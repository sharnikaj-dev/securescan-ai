import { jsPDF } from "jspdf";
import { ScanSummary, VulnerabilityFinding } from "../types";

export function downloadSecurityPdfReport(
  scan: ScanSummary,
  vulnerabilities: VulnerabilityFinding[]
): void {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 44;
  const maxLineWidth = pageWidth - margin * 2;
  let y = 52;

  const ensureSpace = (needed: number) => {
    if (y + needed > pageHeight - 48) {
      doc.addPage();
      y = 52;
    }
  };

  const addWrappedText = (
    text: string,
    x: number,
    fontSize: number,
    color: [number, number, number] = [30, 41, 59],
    fontStyle: "normal" | "bold" = "normal",
    fontName: "helvetica" | "courier" = "helvetica"
  ) => {
    doc.setFont(fontName, fontStyle);
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(text, maxLineWidth - (x - margin)) as string[];
    const lineHeight = fontSize * 1.38;
    for (const line of lines) {
      ensureSpace(lineHeight + 4);
      doc.text(line, x, y);
      y += lineHeight;
    }
  };

  // Header Banner
  doc.setFillColor(10, 19, 15);
  doc.rect(0, 0, pageWidth, 92, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.setTextColor(255, 255, 255);
  doc.text("SecureScan AI — Security Assessment Report", margin, 40);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(161, 161, 170);
  const subtitle = `${scan.projectName}${scan.isDemo ? " [DEMO MODE]" : ""}  |  Generated ${new Date(
    scan.createdAt
  ).toLocaleString()}`;
  doc.text(subtitle, margin, 62);

  y = 116;

  // Executive Summary & Score Box
  doc.setFillColor(246, 248, 247);
  doc.setDrawColor(212, 212, 216);
  doc.roundedRect(margin, y, maxLineWidth, 96, 6, 6, "FD");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(24, 24, 27);
  doc.text("Executive Risk Summary", margin + 16, y + 24);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  const scoreColor: [number, number, number] =
    scan.securityScore >= 85
      ? [16, 185, 129]
      : scan.securityScore >= 60
      ? [245, 158, 11]
      : [220, 38, 38];
  doc.setTextColor(...scoreColor);
  doc.text(`${scan.securityScore}/100`, margin + 16, y + 58);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text(`Classification: ${scan.riskClassification}`, margin + 16, y + 78);

  const col2X = margin + 210;
  doc.text(`Languages: ${scan.language}`, col2X, y + 40);
  doc.text(`Files Scanned: ${scan.filesScanned} (${scan.totalLines} lines)`, col2X, y + 56);
  doc.text(`Engines: ${scan.enginesUsed.join(", ")}`, col2X, y + 72);

  y += 116;

  addWrappedText(
    "Note: Security score is an application-defined risk indicator based on weighted static-analysis findings and is not a formal security certification.",
    margin,
    8.5,
    [100, 116, 139]
  );
  y += 8;

  // Severity Breakdown
  addWrappedText("Vulnerability Breakdown", margin, 13, [15, 23, 42], "bold");
  y += 4;
  addWrappedText(
    `Total Findings: ${scan.totalVulnerabilities}   |   Critical: ${scan.severityCounts.critical}   |   High: ${scan.severityCounts.high}   |   Medium: ${scan.severityCounts.medium}   |   Low: ${scan.severityCounts.low}`,
    margin,
    10,
    [51, 65, 85]
  );
  y += 10;

  if (scan.improvementSuggestions.length > 0) {
    addWrappedText("Priority Improvement Recommendations", margin, 12, [15, 23, 42], "bold");
    y += 2;
    for (const sug of scan.improvementSuggestions) {
      addWrappedText(`- ${sug}`, margin + 8, 9.5, [51, 65, 85]);
    }
    y += 10;
  }

  // Detailed Findings
  addWrappedText("Detailed Static Analysis & AI Findings", margin, 13, [15, 23, 42], "bold");
  y += 6;

  if (vulnerabilities.length === 0) {
    addWrappedText(
      "No static-analysis vulnerabilities were detected across the scanned source files.",
      margin,
      10,
      [13, 148, 136]
    );
  } else {
    vulnerabilities.forEach((v, idx) => {
      ensureSpace(120);
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, y, pageWidth - margin, y);
      y += 14;

      addWrappedText(
        `${idx + 1}. [${v.severity.toUpperCase()}] ${v.title}`,
        margin,
        11,
        [15, 23, 42],
        "bold"
      );
      addWrappedText(
        `${v.filePath}:${v.lineNumber}  |  ${v.cweId}  |  ${v.owaspCategory}  |  Source: ${v.scannerSource}`,
        margin,
        9,
        [71, 85, 105]
      );
      y += 4;

      addWrappedText("Static Finding Summary:", margin, 9.5, [15, 23, 42], "bold");
      addWrappedText(v.staticSummary, margin + 8, 9.5, [51, 65, 85]);

      addWrappedText("Vulnerable Code Snippet:", margin, 9.5, [15, 23, 42], "bold");
      addWrappedText(v.codeSnippet, margin + 8, 8, [30, 41, 59], "normal", "courier");

      if (v.aiAnalysis) {
        addWrappedText("Gemini AI Explanation:", margin, 9.5, [37, 99, 235], "bold");
        addWrappedText(v.aiAnalysis.plainExplanation, margin + 8, 9.5, [51, 65, 85]);

        addWrappedText("Recommended Remediation:", margin, 9.5, [13, 148, 136], "bold");
        addWrappedText(v.aiAnalysis.recommendedFix, margin + 8, 9.5, [51, 65, 85]);

        addWrappedText("Secure Code Example:", margin, 9.5, [13, 148, 136], "bold");
        addWrappedText(
          v.aiAnalysis.secureCodeExample,
          margin + 8,
          8,
          [15, 23, 42],
          "normal",
          "courier"
        );
      } else {
        addWrappedText("Recommended Remediation:", margin, 9.5, [13, 148, 136], "bold");
        addWrappedText(v.staticRemediation, margin + 8, 9.5, [51, 65, 85]);
      }

      y += 8;
    });
  }

  const safeSlug = scan.projectName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  doc.save(`securescan-report-${safeSlug || scan.id}.pdf`);
}
