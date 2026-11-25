import React from "react";
import { AlertOctagon, AlertTriangle, Info, ShieldAlert } from "lucide-react";
import { SeverityLevel } from "../types";

interface SeverityLabelProps {
  severity: SeverityLevel | string;
  compact?: boolean;
}

const SEVERITY_META: Record<
  string,
  { label: string; textClass: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  critical: {
    label: "Critical",
    textClass: "text-red-600 dark:text-red-400",
    Icon: AlertOctagon,
  },
  high: {
    label: "High",
    textClass: "text-amber-600 dark:text-amber-400",
    Icon: ShieldAlert,
  },
  medium: {
    label: "Medium",
    textClass: "text-sky-600 dark:text-sky-400",
    Icon: AlertTriangle,
  },
  low: {
    label: "Low",
    textClass: "text-emerald-600 dark:text-emerald-400",
    Icon: Info,
  },
};

export function SeverityLabel({ severity, compact = false }: SeverityLabelProps) {
  const key = severity.toLowerCase();
  const meta = SEVERITY_META[key] || SEVERITY_META.low;
  const Icon = meta.Icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium whitespace-nowrap ${
        compact ? "text-xs" : "text-sm"
      } ${meta.textClass}`}
    >
      <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>{meta.label}</span>
    </span>
  );
}

export function getScoreColorClass(score: number): string {
  if (score >= 90) return "text-emerald-600 dark:text-emerald-400";
  if (score >= 70) return "text-teal-600 dark:text-teal-400";
  if (score >= 45) return "text-amber-600 dark:text-amber-400";
  return "text-red-600 dark:text-red-400";
}
