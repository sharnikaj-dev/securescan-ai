export type ThemeMode = "dark" | "light";

export type SeverityLevel = "critical" | "high" | "medium" | "low";

export interface ScanPreferences {
  defaultLanguage: string;
  autoAiSummary: boolean;
  minSeverity: SeverityLevel;
}

export interface UserProfile {
  id: number;
  name: string;
  email: string;
  role: string;
  organization: string;
  themePreference: ThemeMode;
  scanPreferences: ScanPreferences;
  createdAt: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScannedFileMeta {
  file_path: string;
  language: string;
  lines: number;
  size_bytes: number;
}

export interface ScanSummary {
  id: number;
  projectName: string;
  sourceType: string;
  language: string;
  filesScanned: number;
  totalLines: number;
  securityScore: number;
  riskClassification: string;
  severityCounts: SeverityCounts;
  totalVulnerabilities: number;
  enginesUsed: string[];
  categoryCounts: Record<string, number>;
  improvementSuggestions: string[];
  scannedFiles: ScannedFileMeta[];
  status: string;
  isDemo: boolean;
  createdAt: string;
}

export interface AiAnalysis {
  plainExplanation: string;
  potentialImpact: string;
  recommendedFix: string;
  secureCodeExample: string;
  diffSummary: string;
  analyzedAt: string;
}

export interface VulnerabilityFinding {
  id: number;
  scanId: number;
  ruleId: string;
  scannerSource: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  cweId: string;
  owaspCategory: string;
  filePath: string;
  language: string;
  lineNumber: number;
  matchedLine: string;
  codeSnippet: string;
  staticSummary: string;
  staticRemediation: string;
  aiAnalysis: AiAnalysis | null;
}

export interface SecurityAlertItem {
  id: number;
  scan_id: number;
  title: string;
  severity: SeverityLevel;
  category: string;
  file_path: string;
  line_number: number;
  project_name: string;
  created_at: string;
}

export interface DashboardPayload {
  stats: {
    totalScans: number;
    totalVulnerabilities: number;
    severityCounts: SeverityCounts;
    averageSecurityScore: number | null;
  };
  categoryDistribution: Array<{ name: string; count: number }>;
  trend: Array<{
    id: number;
    label: string;
    date: string;
    score: number;
    vulnerabilities: number;
  }>;
  recentScans: ScanSummary[];
  securityAlerts: SecurityAlertItem[];
  environment: {
    geminiConfigured: boolean;
    databaseEngine: string;
  };
}

export interface ScanJobStatus {
  jobId: string;
  projectName: string;
  stage: "validating" | "extracting" | "scanning" | "scoring" | "completed" | "failed";
  progress: number;
  message: string;
  scanId?: number;
  error?: string;
}

export interface ScanComparisonPayload {
  baseline: ScanSummary;
  comparison: ScanSummary;
  deltas: {
    scoreDelta: number;
    totalDelta: number;
    criticalDelta: number;
    highDelta: number;
    mediumDelta: number;
    lowDelta: number;
  };
}
